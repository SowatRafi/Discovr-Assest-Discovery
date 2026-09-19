"""Reports convert offline without running embedded HTML or losing boolean meaning."""
import pytest

from discovr.core import to_csv, to_html, to_json
from discovr.reports import read_report
from discovr.session import BadRequest, Session


@pytest.mark.parametrize("fmt,writer", [("json", to_json), ("csv", to_csv), ("html", to_html)])
def test_report_roundtrip(fmt, writer, tmp_path):
    asset = {"IP": "192.0.2.1", "Hostname": "</script><img src=x onerror=alert(1)>",
             "OS": "Linux", "Ports": "22,443", "InternetExposed": False, "Demo": True}
    path = tmp_path / ("report." + fmt)
    path.write_text(writer([asset]), encoding="utf-8")
    report = read_report(path)
    assert report == [asset]
    session = Session()
    assert session.import_report(report) == 1
    assert session.snapshot()["assets"][0]["InternetExposed"] is False
    if fmt == "html":
        assert asset["Hostname"] not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("fmt,body", [("html", "<script>alert(1)</script>"),
                                     ("csv", "IP,IP\n192.0.2.1,x"),
                                     ("csv", "IP,OS\n192.0.2.1,Linux,unexpected"),
                                     ("csv", "IP,InternetExposed\n192.0.2.1,maybe")])
def test_malformed_conversion_is_rejected(fmt, body, tmp_path):
    path = tmp_path / ("invalid." + fmt)
    path.write_text(body)
    with pytest.raises(BadRequest):
        read_report(path)
