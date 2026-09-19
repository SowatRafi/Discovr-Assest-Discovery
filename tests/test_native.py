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
    assert not window.session.jobs and "required" in window.form_error.text()
    monkeypatch.setattr("discovr.session.build_scanner", build)
    fields["secretKey"].setText("private")
    QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
    pump(lambda: not window.session.cancels)
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
    pump(lambda: bool(window.session.inventory))
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
