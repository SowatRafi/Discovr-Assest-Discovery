"""Zero-argument GUI launcher: no website, no console, private readiness metadata."""
import json
import sys
import pytest
from discovr.desktop import main, write_private_json

def test_double_click_native_without_stdio(monkeypatch):
    calls = []
    monkeypatch.setattr('discovr.desktop.run_native', lambda *args: calls.append(args) or 0)
    for name in ('stdin', 'stdout', 'stderr'):
        monkeypatch.setattr(sys, name, None)
    assert main([]) == 0 and len(calls) == 1
    assert sys.stdout is None and sys.stderr is None

def test_startup_handoff_private_and_removed(monkeypatch, tmp_path):
    handoff = tmp_path / 'ready.json'
    def run(args, ready):
        ready(None)
        payload = json.loads(handoff.read_text())
        assert payload['ui'] == 'native-qt-widgets' and payload['pid'] > 0
        assert 'url' not in payload
        return 0
    monkeypatch.setattr('discovr.desktop.run_native', run)
    assert main(['--startup-file', str(handoff)]) == 0
    assert not handoff.exists()

def test_handoff_never_overwrites(tmp_path):
    handoff = tmp_path / 'existing.json'
    handoff.write_text('keep me')
    with pytest.raises(FileExistsError):
        write_private_json(handoff, {'pid': 123})
    assert handoff.read_text() == 'keep me'

def test_failed_start_native_error(monkeypatch):
    messages = []
    def fail(*args):
        raise OSError('Native runtime could not load')
    monkeypatch.setattr('discovr.desktop.run_native', fail)
    monkeypatch.setattr('discovr.desktop.show_error', messages.append)
    assert main([]) == 1 and messages == ['Native runtime could not load']
