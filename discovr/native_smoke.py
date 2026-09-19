"""Opt-in packaged GUI acceptance check. Only the test's own loopback listener is scanned."""
import json
from pathlib import Path
import socket
import sys
import time
import traceback

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication


def require(condition, message):
    # PyInstaller optimises Python; ordinary assert statements would disappear.
    if not condition:
        raise RuntimeError(message)


def wait_until(predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        QApplication.processEvents()
        if predicate():
            return
        QTest.qWait(50)
    raise TimeoutError("Native UI operation did not finish")


def exercise(window, result_file):
    result_file = Path(result_file)
    result = {"ok": False, "checks": []}
    try:
        require(window.isVisible(), "Desktop window is not visible")
        require("discovr.server" not in sys.modules, "Desktop loaded the legacy HTTP server")
        require(not any("QtWeb" in name for name in sys.modules), "Desktop loaded a webview")
        result["platform"] = QApplication.platformName()
        result["checks"].append("native-window-without-web-server")
        window.fields["network"]["target"].setText("invalid target")
        QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
        wait_until(lambda: not window._preparing)
        require(window.form_error.text() and not window.session.jobs, "Invalid input was not rejected")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(8)
            port = listener.getsockname()[1]
            window.fields["network"]["target"].setText("127.0.0.1")
            window.fields["network"]["ports"].setText(str(port))
            QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
            wait_until(lambda: bool(window.session.jobs) and not window.session.cancels and not window._preparing)
        window.refresh()
        job = next(iter(window.session.jobs.values()))
        require(job["status"] == "done", str(job))
        require(any(a.get("IP") == "127.0.0.1" and str(port) in a.get("Ports", "") for a in window.model.assets), "Loopback scan absent from table")
        result["checks"].append("validation-and-real-loopback-scan")
        fixture = result_file.with_name("input.json")
        fixture.write_text(json.dumps([{"Hostname": "portable-desktop-check", "OS": "Linux", "Source": "Network"}]), encoding="utf-8")
        window.import_path(fixture)
        window.search.setText("portable-desktop-check")
        wait_until(lambda: window.proxy.rowCount() == 1)
        require(window.proxy.rowCount() == 1, "Search did not filter imported assets")
        for fmt in ("csv", "json", "html"):
            report = result_file.with_name(f"filtered.{fmt}")
            window.export_path(report, fmt)
            body = report.read_text(encoding="utf-8")
            require("portable-desktop-check" in body and "127.0.0.1" not in body, f"{fmt} ignored filters")
        complete = result_file.with_name("complete.json")
        window.export_path(complete, "json", all_assets=True)
        require(len(json.loads(complete.read_text(encoding="utf-8"))) == 2, "Save inventory lost filtered-out assets")
        window.reset_filters()
        window.source.setCurrentIndex(window.source.findData("passive"))
        window.fields["passive"]["duration"].setValue(10)
        QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
        wait_until(lambda: not window._preparing and bool(window.session.cancels))
        QTest.mouseClick(window.stop_button, Qt.MouseButton.LeftButton)
        wait_until(lambda: not window.session.cancels, seconds=15)
        require(list(window.session.jobs.values())[-1]["status"] == "cancelled", "Stop did not cancel the selected scan")
        result["checks"].extend(["import-search-filtered-exports-complete-save", "cooperative-stop"])
        demo = window.show_demo()
        require(demo.session is not window.session and len(demo.model.assets) == 10, "Demo was not isolated")
        require(not demo.start_button.isEnabled(), "Demo enabled real scanning")
        demo.search.setText("192.0.2.0/24")
        wait_until(lambda: demo.proxy.rowCount() == 6)
        demo.export_path(result_file.with_name("demo.csv"), "csv")
        require(all(a.get("Demo") is True for a in demo.visible_assets()), "Sample assets lack demo markers")
        demo._allow_close = True
        demo.close()
        # The optional API is enabled explicitly and shares the desktop inventory.
        window.show_integration()
        window.integration.start()
        import http.client
        api = window.integration.server
        conn = http.client.HTTPConnection("127.0.0.1", api.server_address[1], timeout=5)
        conn.request("GET", "/api/assets", headers={"X-Discovr-Token": api.token})
        response = conn.getresponse()
        require(response.status == 200 and json.loads(response.read())["assets"], "Packaged API unavailable")
        conn.close()
        window.integration.stop()
        wait_until(lambda: window.integration.server is None)
        window.integration.hide()
        result["checks"].extend(["isolated-offline-demo-and-cidr-filter", "opt-in-authenticated-api"])
        window.refresh()
        window.grab().save(str(result_file.with_suffix(".png")))
        result["ok"] = True
    except Exception:
        result["error"] = traceback.format_exc()
    finally:
        result_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        window._allow_close = True
        window.close()
        QApplication.exit(0 if result["ok"] else 1)
