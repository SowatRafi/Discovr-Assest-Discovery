"""Zero-argument GUI launcher: no website, no console, private readiness metadata."""
import json
import runpy
import sys
import pytest
from discovr.desktop import main, write_private_json

def test_double_click_native_without_stdio(monkeypatch):
    calls = []
    monkeypatch.setattr('discovr.desktop.run_native', lambda *args: calls.append(args) or 0)
    for name in ('stdin', 'stdout', 'stderr'):
        monkeypatch.setattr(sys, name, None)
    assert main() == 0 and len(calls) == 1
    assert sys.stdout is None and sys.stderr is None

def test_startup_handoff_private_and_removed(monkeypatch, tmp_path):
    handoff = tmp_path / 'ready.json'
    def run(ready, test_result):
        ready(None)
        payload = json.loads(handoff.read_text())
        assert payload['ui'] == 'native-qt-widgets' and payload['pid'] > 0
        assert 'url' not in payload
        return 0
    monkeypatch.setattr('discovr.desktop.run_native', run)
    monkeypatch.setenv('DISCOVR_TEST_MODE', '1')
    monkeypatch.setenv('DISCOVR_TEST_STARTUP_FILE', str(handoff))
    assert main() == 0
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
    assert main() == 1 and messages == ['Native runtime could not load']


@pytest.mark.parametrize('arguments', [[], ['--help'], ['--version'],
                                      ['--scan-network', '192.0.2.0/24', '--save', 'yes'],
                                      ['--demo', '--import-file', 'old-inventory.json']])
def test_module_launch_always_opens_desktop(monkeypatch, arguments, tmp_path):
    """Old shortcuts cannot trigger scans, file imports or headless output."""
    calls = []
    monkeypatch.setattr(sys, 'argv', ['discovr', *arguments])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('discovr.desktop.run_native', lambda *args: calls.append(args) or 7)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module('discovr', run_name='__main__')
    assert exit_info.value.code == 7 and len(calls) == 1
    assert not list(tmp_path.iterdir())


def test_test_handoff_requires_explicit_test_mode(monkeypatch, tmp_path):
    """A leftover handoff variable alone must not start automated GUI work."""
    handoff = tmp_path / 'ready.json'
    monkeypatch.delenv('DISCOVR_TEST_MODE', raising=False)
    monkeypatch.setenv('DISCOVR_TEST_STARTUP_FILE', str(handoff))
    monkeypatch.setenv('DISCOVR_TEST_RESULT_FILE', str(tmp_path / 'result.json'))
    def run(ready, test_result):
        assert test_result is None
        ready(None)
        return 0
    monkeypatch.setattr('discovr.desktop.run_native', run)
    assert main() == 0 and not list(tmp_path.iterdir())
