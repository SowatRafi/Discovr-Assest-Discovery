"""Validate the actual USB archive after relocation, with an empty PATH.

Uses only the standard library. Run on each build platform before uploading a binary.
The only active scan targets a TCP listener created by this test on loopback.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import struct
import sys
import tarfile
import tempfile
import time
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="discovr-smoke-") as temporary:
        folder = Path(temporary) / "USB drive with spaces"
        folder.mkdir()
        archive = args.archive.resolve()
        if sys.platform == "darwin":
            subprocess.run(["/usr/bin/ditto", "-x", "-k", str(archive), str(folder)], check=True)
            binary = folder / "Discovr/Discovr.app/Contents/Resources/runtime/Discovr"
        elif os.name == "nt":
            with zipfile.ZipFile(archive) as package:
                package.extractall(folder)
            binary = folder / "Discovr/Discovr.exe"
            # Check the Windows PE subsystem: this must be a GUI app, not a console app.
            data = binary.read_bytes()
            pe = struct.unpack_from("<I", data, 0x3c)[0]
            assert struct.unpack_from("<H", data, pe + 24 + 68)[0] == 2
        else:
            with tarfile.open(archive) as package:
                package.extractall(folder, filter="data")
            binary = folder / "Discovr/Discovr"
        environment = dict(os.environ, PATH="", PYTHONPATH="", PYTHONHOME="")
        assert not any(path.is_symlink() for path in folder.rglob("*")), "USB archive requires symlink support"
        diagnostics = folder / "diagnostics.json"
        result = subprocess.run([str(binary), "--diagnostics-file", str(diagnostics)], cwd=folder, env=environment,
                                text=True, capture_output=True, timeout=90)
        assert result.returncode == 0, f"Packaged diagnostics failed:\n{result.stdout}\n{result.stderr}"
        assert json.loads(diagnostics.read_text())["ok"], diagnostics.read_text()
        licence_file = folder / "notices.txt"
        notices = subprocess.run([str(binary), "--licenses-file", str(licence_file)], cwd=folder, env=environment,
                                 capture_output=True, timeout=30)
        assert notices.returncode == 0 and "boto3" in licence_file.read_text(encoding="utf-8").lower(), notices.stderr
        handoff = folder / "startup.json"
        environment.update(DISCOVR_TEST_STARTUP_FILE=str(handoff), DISCOVR_TEST_NO_BROWSER="1")
        with (folder / "server.log").open("w+", encoding="utf-8") as output:
            arguments = [str(binary)]  # exercise the same zero-argument path as a double click
            if sys.platform == "darwin":
                # Exercise LaunchServices (Finder's app-bundle path), not only the inner binary.
                arguments = ["/usr/bin/open", "-W", "-n", str(folder / "Discovr/Discovr.app"), "--args",
                             "--no-browser", "--startup-file", str(handoff)]
            started = time.monotonic()
            process = subprocess.Popen(arguments, cwd=folder, env=environment,
                                       stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 60
                match = None
                while time.monotonic() < deadline:
                    try:
                        startup = json.loads(handoff.read_text())
                        match = re.search(r"http://127\.0\.0\.1:(\d+)/#token=([\w-]+)", startup["url"])
                    except (FileNotFoundError, json.JSONDecodeError):
                        match = None
                    if match:
                        break
                    if process.poll() is not None:
                        output.seek(0)
                        raise AssertionError("Dashboard exited before startup: " + output.read())
                    time.sleep(0.1)
                if not match:
                    output.seek(0)
                    safe_log = re.sub(r"#token=[\w-]+", "#token=[redacted]", output.read())
                    raise AssertionError("Dashboard did not start: " + safe_log)
                elapsed = time.monotonic() - started
                assert Path(startup["runtime"]).resolve().is_relative_to(folder.resolve()), "Runtime was extracted elsewhere"
                assert elapsed < 15, f"Dashboard startup exceeded the 15-second CI budget: {elapsed:.2f}s"
                print(f"Dashboard ready in {elapsed:.2f}s from the USB app")
                port, token = int(match[1]), match[2]

                def request(method, path, body=None, authenticated=True):
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                    headers = {"Content-Type": "application/json"}
                    if authenticated:
                        headers["X-Discovr-Token"] = token
                    connection.request(method, path, json.dumps(body) if body is not None else None, headers)
                    response = connection.getresponse()
                    payload = response.read().decode()
                    status = response.status
                    connection.close()
                    return status, payload

                assert request("GET", "/")[0] == 200
                assert request("GET", "/api/state", authenticated=False)[0] == 401
                status, info = request("GET", "/api/info")
                assert status == 200 and all(json.loads(info)["providers"].values())
                assert "nmap" not in json.loads(info) and "captureWarning" not in json.loads(info)
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(8)
                    status, job = request("POST", "/api/scans", {"kind": "network", "target": "127.0.0.1",
                                                               "ports": str(listener.getsockname()[1])})
                    assert status == 202, job
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        state = json.loads(request("GET", "/api/state")[1])
                        if state["jobs"][0]["status"] != "running":
                            break
                        time.sleep(0.1)
                    assert state["jobs"][0]["status"] == "done", state
                assets = json.loads(request("GET", "/api/assets")[1])["assets"]
                assert len(assets) == 1 and assets[0]["IP"] == "127.0.0.1"
                for fmt in ("csv", "json", "html"):
                    status, report = request("POST", "/api/export", {"format": fmt})
                    assert status == 200 and "127.0.0.1" in report
                assert request("DELETE", "/api/assets")[0] == 200
                assert request("POST", "/api/assets/import", [{"Hostname": "offline-import", "OS": "Linux"}])[0] == 200
                assert request("POST", "/api/shutdown", {})[0] == 202
                assert process.wait(timeout=15) == 0
                deadline = time.monotonic() + 15
                while handoff.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert not handoff.exists(), "Private startup handoff was not cleaned up"
                print("PASS: relocated USB archive, empty PATH, GUI, provider diagnostics, authenticated API, scan, exports, import, Quit")
            finally:
                if process.poll() is None and os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                   capture_output=True, timeout=15)
                elif process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=15)


if __name__ == "__main__":
    main()
