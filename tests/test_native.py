"""Real Qt widgets: validation, filters, disk failures and desktop lifecycle."""
import json
import os
import sys
import time

if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

from discovr.native import MainWindow, write_report
from discovr.scan import ScanCancelled
from discovr.session import BadRequest, Session


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication(["Discovr tests"])


@pytest.fixture
def window(app):
    widget = MainWindow()
    widget.show()
    app.processEvents()
    yield widget
    widget._allow_close = True
    widget.close()
    app.processEvents()


def pump(predicate, timeout=5):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        QApplication.processEvents()
        if predicate():
            return
        QTest.qWait(10)
    pytest.fail("Desktop operation timed out")


def test_form_validation_and_secret_clearing(window, monkeypatch):
    observed = []
    class Scanner:
        runtime_credentials = {"secretKey": "private"}
        def run(self, **kwargs):
            return []
    def build(kind, params):
        observed.append((kind, dict(params)))
        return Scanner(), "AWS test"
    window.source.setCurrentIndex(window.source.findData("aws"))
    fields = window.fields["aws"]
    fields["accessKey"].setText("key")
    QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
    pump(lambda: not window._preparing)
    assert not window.session.jobs and "required" in window.form_error.text()
    monkeypatch.setattr("discovr.session.build_scanner", build)
    fields["secretKey"].setText("private")
    QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
    pump(lambda: not window._preparing and not window.session.cancels)
    assert observed[0][1]["secretKey"] == "private"
    assert not fields["secretKey"].text() and not fields["accessKey"].text()
    assert "private" not in json.dumps(window.session.snapshot())


def test_filters_sorting_and_save_all_preserves_hidden_assets(window, tmp_path, monkeypatch):
    window.session.merge([{"IP": "10.0.0.20", "Hostname": "printer", "Ports": "9100", "Source": "Network"},
                          {"IP": "10.0.0.2", "Hostname": "server", "OS": "Linux", "Source": "Network,AD"}])
    window.refresh()
    assert window.visible_assets()[0]["IP"] == "10.0.0.2"
    window.filters["Source"].setCurrentIndex(window.filters["Source"].findData("AD"))
    assert len(window.visible_assets()) == 1
    window.filters["AgentCapable"].setCurrentIndex(1)
    assert window.proxy.rowCount() == 1
    filtered = tmp_path / "filtered.json"
    window.export_path(filtered, "json")
    assert len(json.loads(filtered.read_text())) == 1
    full = tmp_path / "all.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(full), "JSON reports (*.json)"))
    assert window.save_inventory()
    assert len(json.loads(full.read_text())) == 2
    assert window.saved_version == window.session.version
    window.reset_filters()
    window.search.setText("not found")
    pump(lambda: window.proxy.rowCount() == 0)
    assert window.proxy.rowCount() == 0 and window.empty.isVisible()


def test_malformed_import_is_atomic_and_file_dialog_works(window, tmp_path, monkeypatch):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps([{"IP": "10.0.0.1"}, {"IP": {"bad": "data"}}]))
    with pytest.raises(BadRequest):
        window.import_path(path)
    assert not window.model.assets
    path.write_text(json.dumps([{"Hostname": "<script>alert(1)</script>", "OS": "Linux"}]))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(path), ""))
    window.import_dialog()
    pump(lambda: not window._importing)
    assert len(window.model.assets) == 1
    assert "<script>" in window.model.data(window.model.index(0, 1))


def test_atomic_export_failure_keeps_old_report(tmp_path, monkeypatch):
    path = tmp_path / "inventory.json"
    path.write_text("original")
    def fail(*args):
        raise OSError("USB drive removed")
    monkeypatch.setattr("discovr.native.os.replace", fail)
    with pytest.raises(OSError, match="USB drive removed"):
        write_report(path, [{"IP": "127.0.0.1"}], "json")
    assert path.read_text() == "original"
    assert list(tmp_path.iterdir()) == [path]


def test_close_cancel_and_failed_save_preserve_inventory(window, monkeypatch):
    window.session.merge([{"Hostname": "keep-me"}])
    window.refresh()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Cancel)
    assert not window.close() and window.isVisible()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Save)
    monkeypatch.setattr(window, "save_inventory", lambda: False)
    assert not window.close() and window.isVisible()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Discard)
    assert window.close()


def test_cancel_preserves_streamed_results_and_warnings(window, monkeypatch):
    class Scanner:
        warnings = ["Optional firewall metadata unavailable"]
        def run(self, on_asset, cancel, **kwargs):
            on_asset({"Hostname": "already-found", "OS": "Linux"})
            cancel.wait(3)
            raise ScanCancelled()
    monkeypatch.setattr("discovr.session.build_scanner", lambda *a: (Scanner(), "Test directory"))
    window.fields["network"]["target"].setText("127.0.0.1")
    QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
    pump(lambda: bool(window.session.inventory) and not window._preparing)
    QTest.mouseClick(window.stop_button, Qt.MouseButton.LeftButton)
    pump(lambda: not window.session.cancels)
    window.refresh()
    assert window.model.assets[0]["Hostname"] == "already-found"
    assert window.jobs.item(0, 1).text() == "Cancelled"
    assert "firewall" in window.jobs.item(0, 1).toolTip()


def test_snapshot_does_not_share_worker_data():
    session = Session()
    session.merge([{"Hostname": "original", "Tags": {"environment": "test"}}])
    data = session.snapshot()
    data["assets"][0]["Tags"]["environment"] = "changed"
    assert session.snapshot()["assets"][0]["Tags"]["environment"] == "test"


def test_slow_preparation_keeps_ui_responsive_and_close_prevents_scan(window, monkeypatch):
    import threading
    entered, release = threading.Event(), threading.Event()
    ran = []
    class Scanner:
        def run(self, **kwargs):
            ran.append(True)
            return []
    def build(*args):
        entered.set()
        release.wait(3)
        return Scanner(), "Delayed preparation"
    monkeypatch.setattr("discovr.session.build_scanner", build)
    window.start_scan()
    try:
        pump(entered.is_set)
        QTest.keyClicks(window.search, "still responsive")
        assert window.search.text() == "still responsive" and window._preparing
        window._allow_close = True
        window.close()
    finally:
        release.set()
    pump(lambda: not window._preparing)
    assert not ran and not window.session.jobs


def test_demo_isolated_searchable_and_exports_marked(window, tmp_path):
    window.session.merge([{"Hostname": "real-asset"}])
    demo = window.show_demo()
    try:
        assert len(demo.model.assets) == 10 and not demo.start_button.isEnabled()
        demo.start_scan()
        assert not demo.session.jobs
        demo.search.setText("192.0.2.0/24")
        pump(lambda: demo.proxy.rowCount() == 6)
        demo.filters["Environment"].setCurrentIndex(demo.filters["Environment"].findData("Example production"))
        assert demo.proxy.rowCount() == 0
        demo.search.clear()
        path = tmp_path / "sample.json"
        demo.export_path(path, "json")  # Applies a pending search before exporting.
        assets = json.loads(path.read_text())
        assert len(assets) == 2 and all(a["Demo"] is True for a in assets)
        assert [a["Hostname"] for a in window.session.snapshot()["assets"]] == ["real-asset"]
    finally:
        demo._allow_close = True
        demo.close()


def test_streaming_preserves_selection_and_saved_indicator(window, tmp_path):
    window.session.merge([{"IP": "10.0.0.2", "Hostname": "keep-selected"}])
    window.refresh()
    window.table.selectRow(0)
    window.session.merge([{"IP": "10.0.0.1", "Hostname": "new"}])
    window.session.merge([{"IP": "10.0.0.2", "OS": "Linux"}])
    window.refresh()
    selected = window.proxy.mapToSource(window.table.currentIndex()).row()
    assert window.model.assets[selected]["Hostname"] == "keep-selected"
    assert window.isWindowModified()
    window.export_path(tmp_path / "all.json", "json", all_assets=True)
    assert not window.isWindowModified()


def test_environment_and_scope_survive_stream_and_completion(window, monkeypatch):
    class Scanner:
        def run(self, on_asset, **kwargs):
            row = {"IP": "10.2.0.7", "OS": "Linux"}
            on_asset(row)
            return [row]
    monkeypatch.setattr("discovr.session.build_scanner", lambda *a: (Scanner(), "Metadata"))
    window.fields["network"]["target"].setText("10.2.0.0/24")
    window.environment.setText("Production, west")
    window.start_scan()
    pump(lambda: not window._preparing and not window.session.cancels)
    window.refresh()
    assert window.model.assets[0]["Environment"] == "Production, west"
    assert window.model.assets[0]["ScanScope"] == "10.2.0.0/24"
    assert window.filters["Environment"].findData("Production, west") > 0


def test_api_opt_in_and_shutdown_leave_inventory_and_scan_intact(window):
    import threading
    from tests.test_server import request
    assert window.integration is None
    window.show_integration()
    integration = window.integration
    assert integration.server is None
    window.session.merge([{"Hostname": "shared-with-api"}])
    # A cancellation token stands in for a job already owned by the desktop.
    cancel = threading.Event()
    window.session.cancels["existing"] = cancel
    window.session.jobs["existing"] = {"stage": "Working"}
    try:
        integration.start()
        server = integration.server
        port, token = server.server_address[1], server.token
        assert request(port, "GET", "/api/assets")[0] == 401
        assert request(port, "GET", "/")[0] == 404
        result = request(port, "GET", "/api/assets", token=token)[2]
        assert result["assets"][0]["Hostname"] == "shared-with-api"
        assert request(port, "POST", "/api/shutdown", token=token)[0] == 202
        integration.worker.join(timeout=2)
        integration.refresh()
        assert integration.server is None and not cancel.is_set()
        assert not integration.token.text()
    finally:
        window.session.cancels.clear()
        window.session.jobs.clear()


def test_disabling_api_revokes_existing_keepalive_clients(window):
    import http.client
    window.show_integration()
    integration = window.integration
    integration.start()
    server = integration.server
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
    headers = {"X-Discovr-Token": server.token}
    try:
        conn.request("GET", "/api/assets", headers=headers)
        response = conn.getresponse()
        assert response.status == 200
        response.read()
        integration.stop()
        conn.request("GET", "/api/assets", headers=headers)
        response = conn.getresponse()
        assert response.status == 503
        response.read()
    finally:
        conn.close()
        integration.worker.join(timeout=2)
        integration.refresh()


def test_second_scan_can_be_stopped_immediately_after_preparation(window, monkeypatch):
    class Scanner:
        def __init__(self, first):
            self.first = first
        def run(self, cancel, **kwargs):
            if not self.first:
                cancel.wait(3)
            return []
    calls = []
    def build(*args):
        calls.append(True)
        return Scanner(len(calls) == 1), "Selection test"
    monkeypatch.setattr("discovr.session.build_scanner", build)
    window.start_scan()
    pump(lambda: not window._preparing and not window.session.cancels)
    window.start_scan()
    pump(lambda: not window._preparing)
    assert window.stop_button.isEnabled()
    QTest.mouseClick(window.stop_button, Qt.MouseButton.LeftButton)
    pump(lambda: not window.session.cancels)
    assert list(window.session.jobs.values())[-1]["status"] == "cancelled"
