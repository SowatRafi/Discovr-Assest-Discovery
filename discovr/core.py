"""Shared plumbing for every discovery mode: logging, enrichment, merging, export and reporting.

Every discovery module returns plain dicts ("assets") carrying at least IP / Hostname /
OS / Ports / Source. Keeping assets as dicts lets each provider attach extra metadata
(cloud region, AD OU, MAC address...) without schema changes; exporters simply add a
column for every key they see.
"""
import csv
import ctypes
import html
import io
import ipaddress
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from string import Template

from tabulate import tabulate

from discovr import __version__
from discovr.risk import RISK_ORDER, RiskAssessor
from discovr.tagger import Tagger, port_sort_key

# Columns shown first in tables and exports; provider-specific fields follow alphabetically.
CORE_FIELDS = ["IP", "Hostname", "OS", "Ports", "Tag", "Risk", "AgentCapable", "Source", "MAC"]
# Fields computed from the others - never merged, always recomputed.
DERIVED_FIELDS = {"Tag", "Risk", "AgentCapable"}
# Placeholder values that carry no information and may be overwritten by a better source.
BLANK_VALUES = {"", "n/a", "unknown", "none", "null"}
# Leading characters that make spreadsheet apps evaluate a cell as a formula (OWASP CSV injection).
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- helpers

def reports_dir(out_dir=None) -> Path:
    """Folder for logs and reports: --out when given, else ~/Documents/discovr_reports."""
    return Path(out_dir) if out_dir else Path.home() / "Documents" / "discovr_reports"


def is_elevated() -> bool:
    """True when running as root (macOS/Linux) or as Administrator (Windows)."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def is_blank(value) -> bool:
    """True for None, empty containers and placeholder strings such as "N/A" or "Unknown"."""
    if value is None or (isinstance(value, (list, tuple, set, dict)) and not value):
        return True
    return isinstance(value, str) and value.strip().lower() in BLANK_VALUES


def enrich(assets):
    """Add Tag, AgentCapable and Risk to every asset in place (safe to call repeatedly)."""
    assets = list(assets)
    Tagger.tag_assets(assets)
    RiskAssessor.add_risks(assets)
    return assets


def columns_for(assets) -> list:
    """Stable column order: core fields first (if present), then everything else A-Z."""
    keys = {k for a in assets for k in a}
    return [c for c in CORE_FIELDS if c in keys] + sorted(keys - set(CORE_FIELDS))


def _ip_sort_key(asset):
    """Sort numerically by IP; assets without a valid IP go last, ordered by hostname."""
    try:
        return (0, int(ipaddress.ip_address(str(asset.get("IP", "")).strip())), "")
    except ValueError:
        return (1, 0, str(asset.get("Hostname", "")).lower())


def _cell_text(value) -> str:
    """Render any field value as human-readable text (lists joined, dicts as compact JSON)."""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple, set)):
        return "; ".join(_cell_text(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, default=str, separators=(",", ":"))
    return "" if value is None else str(value)


def _clip(value, width=38) -> str:
    """Shorten long text for the terminal table so rows stay on one line."""
    text = _cell_text(value)
    return text if len(text) <= width else text[: width - 1] + "…"


def csv_safe(value) -> str:
    """Cell text with spreadsheet formulas neutralised.

    Hostnames, AD descriptions and cloud tags are attacker-controllable; a name such as
    "=HYPERLINK(...)" would otherwise execute when an analyst opens the CSV in Excel.
    """
    text = _cell_text(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


# --------------------------------------------------------------------------- merging

def _short_name(asset) -> str:
    """Lower-case host label without the domain part ("PC01.corp.local" -> "pc01")."""
    name = str(asset.get("Hostname") or "").strip().lower()
    return "" if is_blank(name) else name.split(".")[0]


def asset_key(asset) -> str:
    """Stable inventory key for a new record: IP, else MAC, else short hostname."""
    return next((f"{kind}:{value}" for kind, value in _identities(asset)), f"id:{id(asset)}")


def _identities(asset, for_matching=False) -> list:
    """Ways to recognise the same machine: ("ip", ...), ("mac", ...), ("host", ...).

    When matching an incoming record, the hostname is only used if it has no IP:
    two different devices can share a name ("raspberrypi"), but an AD computer whose
    DNS record is missing should still join the host the network scan found.
    """
    ip = str(asset.get("IP") or "").strip()
    mac = str(asset.get("MAC") or "").strip().lower()
    found = [("ip", ip)] if not is_blank(ip) else []
    if not is_blank(mac):
        found.append(("mac", mac))
    if _short_name(asset) and not (for_matching and found):
        found.append(("host", _short_name(asset)))
    return found


def _merge_tokens(first, second) -> str:
    """Union two comma/semicolon separated lists (ports or sources), numbers sorted first."""
    tokens = set()
    for value in (first, second):
        if not is_blank(value):
            tokens.update(t.strip() for t in str(value).replace(";", ",").split(",") if t.strip())
    ordered = sorted(tokens, key=port_sort_key)
    return ",".join(ordered) if ordered else str(first or second or "")


def merge_assets(inventory: dict, assets, source=None, index=None) -> dict:
    """Merge newly discovered assets into ``inventory`` (key -> asset) in place.

    The same machine is often seen by several sources - AD knows its exact OS, the
    network scan knows its open ports, the cloud API knows its instance ID. Records are
    matched by IP or MAC (hostname only when the newcomer has no IP); each field keeps
    the most informative value, port and source lists are unioned, and derived fields
    (Tag/Risk/AgentCapable) are recomputed for the touched records only.

    :param index: identity -> key lookup to reuse across calls. Long-lived callers (the
        UI streams one host at a time) pass their own dict so each merge stays O(1).
    """
    if index is None:
        index = {ident: key for key, asset in inventory.items() for ident in _identities(asset)}
    touched = set()
    for incoming in assets:
        incoming = dict(incoming)
        if source:
            incoming.setdefault("Source", source)
        key = next((index[i] for i in _identities(incoming, for_matching=True) if i in index), None) \
            or asset_key(incoming)
        current = inventory.setdefault(key, {})
        for field, value in incoming.items():
            if field in DERIVED_FIELDS:
                continue
            if field == "Ports":
                current["Ports"] = _merge_tokens(current.get("Ports"), value)
            elif field == "Source":
                current["Source"] = _merge_tokens(current.get("Source"), value).replace(",", ", ")
            elif is_blank(current.get(field)) and not is_blank(value):
                current[field] = value
            elif field == "OS" and "guessed" in str(current.get("OS", "")).lower() and not is_blank(value) \
                    and "guessed" not in str(value).lower():
                current[field] = value  # a real OS name beats a port-based guess
            elif field not in current:
                current[field] = value
        for ident in _identities(current):
            index[ident] = key
        touched.add(key)
    enrich(inventory[key] for key in touched)
    return inventory


# --------------------------------------------------------------------------- export

def to_csv(assets) -> str:
    """Serialise assets as CSV text with one column per field seen (formula-safe)."""
    buffer = io.StringIO()
    fields = columns_for(assets)
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(fields)
    for asset in assets:
        writer.writerow(csv_safe(asset.get(f)) for f in fields)
    return buffer.getvalue()


def to_json(assets) -> str:
    """Serialise assets as pretty JSON (datetimes and other objects become strings)."""
    return json.dumps(list(assets), indent=2, default=str)


_REPORT = Template("""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<style>
  /* Self-contained report: no external fonts, scripts or images, so it opens offline. */
  :root { color-scheme: light dark; --bg:#ffffff; --fg:#0f172a; --muted:#475569; --line:#e2e8f0;
          --card:#f8fafc; --crit:#b91c1c; --high:#c2410c; --med:#a16207; --low:#15803d; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0b1015; --fg:#e6edf3; --muted:#9fb0bf; --line:#1f2a33; --card:#11181f;
            --crit:#f87171; --high:#fb923c; --med:#facc15; --low:#4ade80; } }
  body { margin:0; padding:24px; background:var(--bg); color:var(--fg);
         font:14px/1.5 "Fira Sans", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  h1 { font:600 22px/1.2 "Fira Code", ui-monospace, "Cascadia Code", Menlo, Consolas, monospace; margin:0 0 4px; }
  p.meta { color:var(--muted); margin:0 0 20px; }
  .tiles { display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:12px; margin-bottom:20px; }
  .tile { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 16px; }
  .tile b { display:block; font-size:24px; font-variant-numeric:tabular-nums; }
  .tile span { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { position:sticky; top:0; background:var(--card); font-size:12px; text-transform:uppercase; color:var(--muted); }
  td.mono { font-family:"Fira Code", ui-monospace, Menlo, Consolas, monospace; font-variant-numeric:tabular-nums; }
  .risk { font-weight:600; }
  .Critical { color:var(--crit); } .High { color:var(--high); } .Medium { color:var(--med); } .Low { color:var(--low); }
  details summary { cursor:pointer; color:var(--muted); }
  dl { display:grid; grid-template-columns:max-content 1fr; gap:2px 12px; margin:6px 0 0; font-size:12px; }
  dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; }
  @media print { th { position:static; } details { display:block; } }
</style></head>
<body>
<h1>Discovr asset report</h1>
<p class="meta">Generated $generated by Discovr $version &middot; $count assets</p>
<section class="tiles" aria-label="Summary">$tiles</section>
<table>
<thead><tr><th scope="col">IP</th><th scope="col">Hostname</th><th scope="col">OS</th><th scope="col">Ports</th>
<th scope="col">Tag</th><th scope="col">Risk</th><th scope="col">Agent</th><th scope="col">Source</th><th scope="col">Details</th></tr></thead>
<tbody>
$rows
</tbody></table>
</body></html>
""")


def to_html(assets, title="Discovr asset report") -> str:
    """Render a self-contained, printable HTML report; every value is HTML-escaped.

    Escaping matters: hostnames and mDNS names come from the network and are attacker
    controlled, so an unescaped "<script>" hostname would run in the analyst's browser.
    """
    assets = sorted(assets, key=_ip_sort_key)

    def esc(value):
        """Field value as escaped HTML text."""
        return html.escape(_cell_text(value))

    risk_counts = {level: sum(a.get("Risk") == level for a in assets) for level in RISK_ORDER}
    tiles = [("Assets", len(assets)), ("Agent-capable", sum(bool(a.get("AgentCapable")) for a in assets))]
    tiles += [(level, risk_counts[level]) for level in RISK_ORDER]
    tile_html = "".join(f'<div class="tile"><b>{n}</b><span>{html.escape(label)}</span></div>' for label, n in tiles)

    rows = []
    for a in assets:
        extras = {k: v for k, v in a.items() if k not in CORE_FIELDS and not is_blank(v)}
        # Provider metadata goes in a native <details> disclosure: readable without any JavaScript.
        details = ""
        if extras:
            items = "".join(f"<dt>{html.escape(k)}</dt><dd>{esc(v)}</dd>" for k, v in sorted(extras.items()))
            details = f"<details><summary>{len(extras)} fields</summary><dl>{items}</dl></details>"
        risk = html.escape(str(a.get("Risk", "")))
        rows.append(
            f'<tr><td class="mono">{esc(a.get("IP"))}</td><td>{esc(a.get("Hostname"))}</td>'
            f'<td>{esc(a.get("OS"))}</td><td class="mono">{esc(a.get("Ports"))}</td><td>{esc(a.get("Tag"))}</td>'
            f'<td class="risk {risk}">{risk}</td><td>{esc(a.get("AgentCapable", ""))}</td>'
            f'<td>{esc(a.get("Source"))}</td><td>{details}</td></tr>'
        )
    return _REPORT.substitute(
        title=html.escape(title), generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        version=__version__, count=len(assets), tiles=tile_html, rows="\n".join(rows),
    )


class Logger:
    """Per-run log file under <reports>/logs plus console output for Discovr's own messages."""

    @staticmethod
    def setup(feature: str, out_dir=None):
        """Create the log file for this run and return (log_file, timestamp)."""
        log_dir = reports_dir(out_dir) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"discovr_{feature}_log_{timestamp}.log"

        # Root logger -> file at WARNING, so chatty SDKs (botocore, azure, urllib3) stay quiet...
        logging.basicConfig(filename=str(log_file), level=logging.WARNING, encoding="utf-8",
                            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", force=True)
        # ...while Discovr's own INFO messages go to both the file and the console.
        app = logging.getLogger("discovr")
        app.setLevel(logging.INFO)
        if not any(type(h) is logging.StreamHandler for h in app.handlers):
            console = logging.StreamHandler()
            console.setFormatter(logging.Formatter("%(message)s"))
            app.addHandler(console)

        print(f"[+] Logs saved at {log_file}")
        return log_file, timestamp


class Exporter:
    """Writes CSV / JSON / HTML reports to <reports>/{csv,json,html}/discovr_<feature>_<ts>.*"""

    WRITERS = {"csv": to_csv, "json": to_json, "html": to_html}

    @staticmethod
    def save_results(assets, formats, feature: str, timestamp: str, out_dir=None) -> list:
        """Save ``assets`` in each requested format and return the written paths."""
        assets = enrich(assets)
        written = []
        for fmt in formats:
            folder = reports_dir(out_dir) / fmt
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / f"discovr_{feature}_{timestamp}.{fmt}"
            path.write_text(Exporter.WRITERS[fmt](assets), encoding="utf-8", newline="")
            print(f"[+] {fmt.upper()} saved: {path}")
            written.append(path)
        return written


class Reporter:
    """Terminal summary table shown at the end of every CLI run."""

    @staticmethod
    def print_results(assets, total_hosts, context="assets"):
        """Tag + risk-rate ``assets`` in place and print them as a grid table with a summary line."""
        if not assets:
            print("\n[!] No assets discovered.")
            return
        enrich(assets)
        table = [
            [_clip(a.get("IP", "N/A")), _clip(a.get("Hostname", "Unknown")), _clip(a.get("OS", "Unknown")),
             _clip(a.get("Ports", "N/A"), 24), a.get("Tag"), a.get("Risk"),
             "Yes" if a.get("AgentCapable") else "No", _clip(a.get("Source", ""), 16)]
            for a in sorted(assets, key=_ip_sort_key)
        ]
        print("\nDiscovered Assets (final report):")
        print(tabulate(table, headers=["IP", "Hostname", "OS", "Ports", "Tag", "Risk", "Agent", "Source"],
                       tablefmt="grid"))
        agents = sum(bool(a.get("AgentCapable")) for a in assets)
        urgent = sum(a.get("Risk") in ("Critical", "High") for a in assets)
        print(f"\n[+] {len(assets)} {context} ({agents} agent-capable, {urgent} critical/high risk) "
              f"discovered out of {total_hosts} scanned.")
