"""Offline report conversion: JSON, CSV and Discovr's self-contained HTML reports."""
import csv
from html.parser import HTMLParser
import io
import json
from pathlib import Path

from discovr.session import BadRequest


class _ReportData(HTMLParser):
    """Read only the inert data island; never render HTML or execute its scripts."""
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.inside = False
        self.blocks = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and attrs.get("id") == "discovr-data" and attrs.get("type") == "application/json":
            self.inside = True
            self.blocks.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self.inside = False

    def handle_data(self, data):
        if self.inside:
            self.blocks[-1] += data


def read_report(path):
    """Bound disk input before parsing. Session validates every row before merging."""
    path = Path(path)
    with path.open("rb") as source:
        raw = source.read(32 * 1024 * 1024 + 1)
    if len(raw) > 32 * 1024 * 1024:
        raise BadRequest("Report exceeds the 32 MB import limit")
    text = raw.decode("utf-8-sig")
    if path.suffix.lower() in (".html", ".htm"):
        parser = _ReportData()
        parser.feed(text)
        if len(parser.blocks) != 1:
            raise BadRequest("This HTML file has no Discovr conversion data. Import its original JSON/CSV report, or export HTML again with this version.")
        return json.loads(parser.blocks[0])
    if path.suffix.lower() == ".csv":
        reader = csv.DictReader(io.StringIO(text, newline=""))
        headers = reader.fieldnames or []
        if not headers or len(headers) != len(set(headers)) or any(not h for h in headers):
            raise BadRequest("CSV requires unique, non-empty column names")
        if not set(headers) & {"IP", "Hostname", "InstanceID", "MAC"}:
            raise BadRequest("CSV needs an IP, Hostname, InstanceID or MAC column")
        booleans = {"InternetExposed", "Enabled", "Stale", "DomainController", "Demo", "LocalHost", "AgentCapable"}
        rows = []
        for row in reader:
            if None in row or any(v is None for v in row.values()):
                raise BadRequest("CSV row does not match its column headers")
            for key in booleans & row.keys():
                value = row[key].strip().lower()
                if value in ("yes", "true", "1"):
                    row[key] = True
                elif value in ("no", "false", "0"):
                    row[key] = False
                elif not value:
                    row[key] = None
                else:
                    raise BadRequest(f"{key} must be Yes/No or true/false")
            for key in {"PortsChecked", "TCPResponses"} & row.keys():
                # A CSV "0" is truthy in Python. Preserve numerical meaning so
                # a silent device cannot turn into a responding host on import.
                value = row[key].strip()
                if not value:
                    row[key] = None
                elif value.isdecimal() and len(value) <= 5 and int(value) <= 65535:
                    row[key] = int(value)
                else:
                    raise BadRequest(f"{key} must be a number from 0 to 65535")
            rows.append(row)
            if len(rows) > 65536:
                raise BadRequest("Import is limited to 65,536 assets")
        return rows
    return json.loads(text)
