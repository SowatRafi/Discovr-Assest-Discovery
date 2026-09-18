"""Double-click entry point for the USB app; no terminal or installed runtime needed."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import webbrowser


def open_default_browser(url, new=2):
    """Keep bundled libraries out of the system browser's process environment."""
    if not getattr(sys, "frozen", False):
        return webbrowser.open(url, new=new)
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.kernel32.SetDllDirectoryW(None)
        try:
            return webbrowser.open(url, new=new)
        finally:
            ctypes.windll.kernel32.SetDllDirectoryW(sys._MEIPASS)
    if sys.platform.startswith("linux"):
        previous = os.environ.pop("LD_LIBRARY_PATH", None)
        if "LD_LIBRARY_PATH_ORIG" in os.environ:
            os.environ["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH_ORIG"]
        try:
            return webbrowser.open(url, new=new)
        finally:
            os.environ.pop("LD_LIBRARY_PATH", None)
            if previous is not None:
                os.environ["LD_LIBRARY_PATH"] = previous
    return webbrowser.open(url, new=new)


def write_private_json(path, payload):
    """Create a private automation handoff without overwriting an existing file.

    This is only used by packaging checks, never by a normal double-click launch.
    The temporary file can contain the session token and is removed on shutdown.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(payload, output)


def show_error(message):
    """Report startup failure when a windowed application has no console."""
    message = f"Discovr could not start.\n\n{message}"
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, message, "Discovr", 0x10)
    elif sys.platform == "darwin":
        # Pass text as data, never interpolate it into AppleScript source.
        subprocess.run(["/usr/bin/osascript", "-e",
                        'on run argv\n display alert "Discovr" message (item 1 of argv)\nend run', message],
                       timeout=60, check=False)
    else:
        # Desktop Linux has no universal native dialog API. Leave a readable report
        # next to the launcher and ask the configured browser to show it.
        report = Path(sys.executable).with_name("STARTUP_ERROR.txt")
        try:
            report.write_text(message, encoding="utf-8")
            webbrowser.open(report.as_uri())
        except OSError:
            pass
        print(message, file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Open the portable Discovr dashboard")
    # Test/support switches let CI exercise this exact GUI executable, not a different CLI build.
    parser.add_argument("--no-browser", action="store_true",
                        default=os.environ.get("DISCOVR_TEST_NO_BROWSER") == "1", help=argparse.SUPPRESS)
    parser.add_argument("--startup-file", type=Path,
                        default=os.environ.get("DISCOVR_TEST_STARTUP_FILE"), help=argparse.SUPPRESS)
    parser.add_argument("--diagnostics-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--licenses-file", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    ready_written = False

    def ready(url):
        nonlocal ready_written
        if args.startup_file:
            write_private_json(args.startup_file, {"url": url,
                               "runtime": str(getattr(sys, "_MEIPASS", Path(__file__).parent)),
                               "pid": os.getpid()})
            ready_written = True

    # PyInstaller windowed builds supply None streams on Windows. Some SDKs expect
    # real file objects even though progress is shown in the dashboard activity panel.
    with ExitStack() as resources:
        original = {name: getattr(sys, name) for name in ("stdin", "stdout", "stderr")}
        for name, stream in original.items():
            if stream is None:
                setattr(sys, name, resources.enter_context(open(os.devnull, "r" if name == "stdin" else "w")))
        try:
            if args.diagnostics_file:
                from discovr.diagnostics import check_runtime
                result = check_runtime()
                write_private_json(args.diagnostics_file, result)
                return 0 if result["ok"] else 1
            if args.licenses_file:
                import discovr
                # The frozen entry script lives at the bundle root, outside the package.
                args.licenses_file.write_bytes(Path(discovr.__file__).with_name("THIRD_PARTY_NOTICES.txt").read_bytes())
                return 0
            from discovr.server import serve
            serve(open_browser=not args.no_browser, on_ready=ready, browser_opener=open_default_browser)
            return 0
        except Exception as exc:
            if not (args.startup_file or args.diagnostics_file or args.licenses_file):
                show_error(str(exc))
            return 1
        finally:
            if ready_written:
                args.startup_file.unlink(missing_ok=True)
            for name, stream in original.items():
                setattr(sys, name, stream)


if __name__ == "__main__":
    sys.exit(main())
