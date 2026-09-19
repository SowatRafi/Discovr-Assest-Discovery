"""Validate the actual USB archive after relocation, with an empty PATH.

Uses only the standard library. Run on each build platform before uploading a binary.
The only active scan targets a TCP listener created by this test on loopback.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import struct
import shutil
import sys
import tarfile
import tempfile
import time
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--single-file", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="discovr-smoke-") as temporary:
        folder = Path(temporary) / "USB drive with spaces"
        folder.mkdir()
        archive = args.archive.resolve()
        if args.single_file:
            binary = folder / archive.name
            shutil.copy2(archive, binary)
        elif sys.platform == "darwin":
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
        result_file = folder / "native-result.json"
        environment.update(DISCOVR_TEST_STARTUP_FILE=str(handoff), DISCOVR_TEST_RESULT_FILE=str(result_file))
        with (folder / "desktop.log").open("w+", encoding="utf-8") as output:
            arguments = [str(binary)]  # exercise the same zero-argument path as a double click
            if sys.platform == "darwin":
                # Exercise LaunchServices (Finder's app-bundle path), not only the inner binary.
                arguments = ["/usr/bin/open", "-W", "-n", str(folder / "Discovr/Discovr.app"), "--args",
                             "--self-test", str(result_file), "--startup-file", str(handoff)]
            started = time.monotonic()
            process = subprocess.Popen(arguments, cwd=folder, env=environment,
                                       stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 60
                startup = None
                while time.monotonic() < deadline:
                    try:
                        startup = json.loads(handoff.read_text())
                    except (FileNotFoundError, json.JSONDecodeError):
                        pass
                    if startup:
                        break
                    if process.poll() is not None:
                        output.seek(0)
                        raise AssertionError("Desktop exited before startup: " + output.read())
                    time.sleep(0.05)
                assert startup, "Native desktop did not start"
                elapsed = time.monotonic() - started
                assert startup["ui"] == "native-qt-widgets" and "url" not in startup
                runtime = Path(startup["runtime"]).resolve()
                if args.single_file:
                    assert not runtime.is_relative_to(folder.resolve()), "Single-file runtime was not isolated"
                else:
                    assert runtime.is_relative_to(folder.resolve()), "Runtime was extracted elsewhere"
                budget = 45 if args.single_file else 15
                assert elapsed < budget, f"Desktop startup exceeded the {budget}-second CI budget: {elapsed:.2f}s"
                print(f"Native desktop ready in {elapsed:.2f}s ({'single file' if args.single_file else 'USB folder'})")
                code = process.wait(timeout=90)
                output.seek(0)
                assert result_file.is_file(), f"No native acceptance result (exit {code}): {output.read()}"
                result = json.loads(result_file.read_text(encoding="utf-8"))
                assert result["ok"], result
                assert code == 0, f"Desktop exit {code}: {output.read()}"
                assert result["platform"] in ("windows", "cocoa", "xcb", "wayland"), result
                deadline = time.monotonic() + 15
                while handoff.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert not handoff.exists(), "Private startup handoff was not cleaned up"
                if args.single_file:
                    assert not runtime.exists(), "Single-file temporary runtime was not cleaned up"
                print("PASS: relocated USB folder, empty PATH, native desktop, provider diagnostics, scan, stop, search, exports, import, close")
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
