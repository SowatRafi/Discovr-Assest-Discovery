"""The GUI launcher must work without a console and clean up on every exit path."""
import json
from pathlib import Path
import sys

import pytest

from discovr.desktop import main, write_private_json


def test_double_click_opens_browser_without_stdio(monkeypatch):
    calls = []
    monkeypatch.setattr("discovr.server.serve", lambda **kwargs: calls.append(kwargs))
    for name in ("stdin", "stdout", "stderr"):
        monkeypatch.setattr(sys, name, None)
    assert main([]) == 0
    assert calls[0]["open_browser"] is True
    assert sys.stdout is None and sys.stderr is None


def test_startup_handoff_is_private_and_removed_when_app_stops(monkeypatch, tmp_path):
    handoff = tmp_path / "ready.json"
    def serve(**kwargs):
        kwargs["on_ready"]("http://127.0.0.1:12345/#token=private")
        payload = json.loads(handoff.read_text())
        assert payload["url"].endswith("token=private") and payload["pid"] > 0
        assert kwargs["open_browser"] is False
    monkeypatch.setattr("discovr.server.serve", serve)
    assert main(["--startup-file", str(handoff), "--no-browser"]) == 0
    assert not handoff.exists()


def test_handoff_never_overwrites_an_existing_file(tmp_path):
    handoff = tmp_path / "existing.json"
    handoff.write_text("keep me")
    with pytest.raises(FileExistsError):
        write_private_json(handoff, {"url": "private"})
    assert handoff.read_text() == "keep me"


def test_failed_start_shows_a_gui_error(monkeypatch):
    messages = []
    def fail(**kwargs):
        raise OSError("No default browser")
    monkeypatch.setattr("discovr.server.serve", fail)
    monkeypatch.setattr("discovr.desktop.show_error", messages.append)
    assert main([]) == 1 and messages == ["No default browser"]


def test_browser_failure_releases_listener(monkeypatch):
    import discovr.server as server_module
    server, _ = server_module.create_server()
    monkeypatch.setattr(server_module, "create_server", lambda port: (server, "http://127.0.0.1/"))
    monkeypatch.setattr(server_module.webbrowser, "open", lambda *args, **kwargs: False)
    with pytest.raises(OSError, match="default browser"):
        server_module.serve()
    assert server.socket.fileno() == -1
