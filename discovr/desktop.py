"""Double-click entry point for the USB app; no terminal or installed runtime needed."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys


def write_private_json(path, payload):
    """Create a private automation handoff without overwriting an existing file.

    This is only used by packaging checks, never by a normal double-click launch.
    The temporary file contains readiness metadata and is removed on shutdown.
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
        report = Path(sys.executable).with_name("STARTUP_ERROR.txt")
        try:
            report.write_text(message, encoding="utf-8")
        except OSError:
            pass
        print(message, file=sys.stderr)


def run_native(on_ready, test_result=None):
    """Create a real desktop window; never launch a browser or bind an HTTP port."""
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
    from discovr.native import MainWindow

    app = QApplication.instance() or QApplication(["Discovr"])
    app.setApplicationName("Discovr")
    app.setOrganizationName("Discovr")
    window = MainWindow()
    window.show()
    # Record readiness from the event loop, after showing the native window.
    QTimer.singleShot(0, lambda: on_ready(window))
    if test_result:
        from discovr.native_smoke import exercise
        QTimer.singleShot(100, lambda: exercise(window, test_result))
    return app.exec()


def main():
    # Both source and packaged launches always open the desktop. CI opts into GUI
    # acceptance through its private environment; there are no command-line modes.
    testing = os.environ.get("DISCOVR_TEST_MODE") == "1"
    startup_file = os.environ.get("DISCOVR_TEST_STARTUP_FILE") if testing else None
    startup_file = Path(startup_file) if startup_file else None
    test_result = os.environ.get("DISCOVR_TEST_RESULT_FILE") if testing else None
    ready_written = False

    def ready(window):
        nonlocal ready_written
        if startup_file:
            write_private_json(startup_file, {"ui": "native-qt-widgets",
                               "runtime": str(getattr(sys, "_MEIPASS", Path(__file__).parent)),
                               "pid": os.getpid()})
            ready_written = True

    # PyInstaller windowed builds supply None streams on Windows. Some SDKs expect
    # real file objects even though progress is shown in the desktop activity panel.
    with ExitStack() as resources:
        original = {name: getattr(sys, name) for name in ("stdin", "stdout", "stderr")}
        for name, stream in original.items():
            if stream is None:
                setattr(sys, name, resources.enter_context(open(os.devnull, "r" if name == "stdin" else "w")))
        try:
            return run_native(ready, test_result)
        except Exception as exc:
            if not testing:
                show_error(str(exc))
            return 1
        finally:
            if ready_written:
                startup_file.unlink(missing_ok=True)
            for name, stream in original.items():
                setattr(sys, name, stream)


if __name__ == "__main__":
    sys.exit(main())
