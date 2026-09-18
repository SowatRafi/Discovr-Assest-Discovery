"""Validate a relocated executable with an empty PATH and no source-tree working directory.

Uses only the standard library. Run on each build platform before uploading a binary.
The only active scan targets a TCP listener created by this test on loopback.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="discovr-smoke-") as temporary:
        folder = Path(temporary)
        binary = folder / args.binary.name
        shutil.copy2(args.binary.resolve(), binary)
        environment = dict(os.environ, PATH="", PYTHONPATH="", PYTHONHOME="")
        result = subprocess.run([str(binary), "--diagnostics"], cwd=folder, env=environment,
                                text=True, capture_output=True, timeout=90)
        assert result.returncode == 0, f"Packaged diagnostics failed:\n{result.stdout}\n{result.stderr}"
        assert json.loads(result.stdout)["ok"], result.stdout
        notices = subprocess.run([str(binary), "--licenses"], cwd=folder, env=environment,
                                 capture_output=True, timeout=30)
        assert notices.returncode == 0 and b"scapy" in notices.stdout.lower(), notices.stderr
        with (folder / "server.log").open("w+", encoding="utf-8") as output:
            process = subprocess.Popen([str(binary), "--no-browser"], cwd=folder, env=environment,
                                       stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 60
                match = None
                while time.monotonic() < deadline:
                    output.seek(0)
                    match = re.search(r"http://127\.0\.0\.1:(\d+)/#token=([\w-]+)", output.read())
                    if match:
                        break
                    if process.poll() is not None:
                        raise AssertionError("Dashboard exited before startup")
                    time.sleep(0.1)
                assert match, "Dashboard did not start"
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
                print("PASS: relocated binary, empty PATH, provider diagnostics, dashboard, authenticated API, scan, exports, import")
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
