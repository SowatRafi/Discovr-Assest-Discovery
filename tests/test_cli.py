"""Tests for the command line (discovr.cli): argument handling, headless scans and reports."""
import logging
import socket

import pytest

from discovr import __version__
from discovr.cli import build_parser, main, selected_feature


@pytest.fixture(autouse=True)
def close_log_files():
    """Logger.setup() opens a log file; close it so Windows can delete the temp folder."""
    yield
    for handler in logging.getLogger().handlers[:]:
        handler.close()
        logging.getLogger().removeHandler(handler)


def test_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0 and __version__ in capsys.readouterr().out


def test_selected_feature():
    parse = build_parser().parse_args
    assert selected_feature(parse([])) is None                                   # -> web UI
    assert selected_feature(parse(["--scan-network", "10.0.0.0/24"])) == "network"
    assert selected_feature(parse(["--autoipaddr"])) == "network"
    assert selected_feature(parse(["--cloud", "gcp"])) == "cloud"
    assert selected_feature(parse(["--ad", "--domain", "d"])) == "ad"
    assert selected_feature(parse(["--passive"])) == "passive"


def test_headless_scan_writes_every_report_format(tmp_path, capsys):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        main(["--scan-network", "127.0.0.1", "--ports", str(port), "--save", "yes", "--format", "all",
              "--out", str(tmp_path)])
    out = capsys.readouterr().out
    assert "127.0.0.1" in out and "1 active assets" in out
    for folder, suffix in (("csv", ".csv"), ("json", ".json"), ("html", ".html"), ("logs", ".log")):
        files = list((tmp_path / folder).glob(f"discovr_*{suffix}"))
        assert len(files) == 1, folder


def test_save_no_writes_nothing(tmp_path, capsys):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        main(["--scan-network", "127.0.0.1", "--ports", str(listener.getsockname()[1]), "--save", "no",
              "--out", str(tmp_path)])
    assert "Results not saved" in capsys.readouterr().out
    assert not (tmp_path / "csv").exists()


def test_bad_input_is_one_readable_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--scan-network", "10.0.0.0/8", "--out", str(tmp_path)])
    assert exit_info.value.code == 1
    assert "Fatal error: target is larger than a /16" in capsys.readouterr().out


@pytest.mark.parametrize("args", [["--ui", "--cloud", "aws"], ["--ad", "--passive"],
                                  ["--autoipaddr", "--scan-network", "127.0.0.1"],
                                  ["--port", "-1"], ["--packet-capture"], ["--timeout", "0"]])
def test_conflicting_or_invalid_modes_fail_before_work(args):
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
