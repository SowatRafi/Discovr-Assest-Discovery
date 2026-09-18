"""Tests for tagging, risk rating, inventory merging and report export (discovr.core)."""
import csv
import io
import json

from discovr.core import Exporter, csv_safe, enrich, merge_assets, to_csv, to_html
from discovr.risk import RiskAssessor
from discovr.tagger import Tagger, port_set


def tag(**fields):
    """Shortcut: tag a single asset built from keyword fields."""
    return Tagger.assign_tag(fields)


def risk(**fields):
    """Shortcut: enrich a single asset and return its risk level."""
    return enrich([fields])[0]["Risk"]


def test_port_set_parses_numbers_not_substrings():
    assert port_set("22,80,443") == {22, 80, 443}
    assert 80 not in port_set("8080")          # old code: "80" in "8080" -> True
    assert port_set(["22", 3389]) == {22, 3389}
    assert port_set("N/A") == set() and port_set(None) == set()
    assert port_set("1000-1002") == {1000, 1001, 1002}
    assert 3389 in port_set("*")               # cloud rule "allow any port"


def test_tags_cover_common_device_roles():
    assert tag(Hostname="router", OS="Linux/Unix", Ports="80,443") == "[Network]"
    assert tag(Hostname="edge01", OS="Cisco IOS 15.2") == "[Network]"          # not Apple iOS
    assert tag(Hostname="laptop01", OS="Windows 10 Pro", Ports="135,445") == "[Workstation]"
    assert tag(Hostname="dc01", OS="Windows (guessed)", Ports="53,88,389,445") == "[Server]"
    assert tag(Hostname="srv", OS="Linux 5.x kernel", Ports="22") == "[Server]"
    assert tag(Hostname="unknown", OS="Unknown", Ports="9100") == "[Printer]"
    assert tag(Hostname="unknown", OS="Unknown", Ports="554") == "[IoT]"
    assert tag(Hostname="unknown", OS="Unknown", Ports="62078") == "[Mobile]"
    assert tag(Hostname="vm1", OS="Windows", Cloud="Azure") == "[Server]"
    assert tag(Hostname="box", OS="Unknown", Ports="8080") == "[WebHost]"


def test_agent_capable_only_for_workstations_and_servers():
    assets = Tagger.tag_assets([{"OS": "Windows 11 Pro"}, {"OS": "Ubuntu 22.04"}, {"Ports": "9100"}])
    assert [a["AgentCapable"] for a in assets] == [True, True, False]


def test_risk_rules():
    assert risk(OS="Windows 7 Professional") == "Critical"
    assert risk(OS="Windows Server 2012 R2") == "Critical"
    assert risk(OS="Windows 10 Enterprise") == "High"                 # end of support Oct 2025
    assert risk(OS="Windows 11 Pro") == "Low"
    assert risk(OS="Ubuntu", Ports="22,3389", InternetExposed=True, Cloud="AWS") == "Critical"
    assert risk(OS="Ubuntu", Ports="443", InternetExposed=True, Cloud="AWS") == "High"
    assert risk(OS="Unknown", Ports="23") == "High"                   # telnet
    assert risk(OS="Unknown", Ports="9100") == "High"                 # printer
    assert risk(OS="Linux", Ports="22") == "Medium"                   # server baseline
    assert risk(OS="Linux", Ports="8021") == "Medium"                 # old bug: "21" in "8021" -> FTP


def test_csv_neutralises_formulas_and_keeps_every_field():
    assert csv_safe("=HYPERLINK(\"http://evil\")").startswith("'=")
    assert csv_safe("@SUM(A1)") == "'@SUM(A1)" and csv_safe("pc01") == "pc01"
    text = to_csv(enrich([{"IP": "10.0.0.1", "Hostname": "+cmd|' /C calc'!A0", "OS": "Linux",
                           "Ports": "22", "InstanceID": "i-1", "Tags": {"env": "prod"}}]))
    row = next(csv.DictReader(io.StringIO(text)))
    assert row["Hostname"].startswith("'+")
    assert row["InstanceID"] == "i-1" and row["Tags"] == '{"env":"prod"}'
    assert row["AgentCapable"] == "Yes"


def test_html_report_escapes_hostile_values():
    page = to_html(enrich([{"IP": "10.0.0.9", "Hostname": "<script>alert(1)</script>", "OS": "x"}]))
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page


def test_merge_combines_sources_for_the_same_machine():
    inventory = {}
    merge_assets(inventory, [{"IP": "10.0.0.5", "Hostname": "pc01", "OS": "Windows (guessed)",
                              "Ports": "445,3389"}], source="Network")
    merge_assets(inventory, [{"IP": "10.0.0.5", "Hostname": "PC01.corp.local", "OS": "Windows 11 Enterprise",
                              "Ports": "N/A", "OU": "Workstations"}], source="AD")
    assert len(inventory) == 1
    asset = next(iter(inventory.values()))
    assert asset["OS"] == "Windows 11 Enterprise"          # real OS replaces the port-based guess
    assert asset["Ports"] == "445,3389" and asset["OU"] == "Workstations"
    assert asset["Source"] == "AD, Network"
    assert asset["Tag"] == "[Workstation]" and asset["Risk"] == "High"   # RDP on an endpoint


def test_merge_matches_by_hostname_when_ip_is_unknown():
    inventory = {}
    merge_assets(inventory, [{"IP": "10.0.0.7", "Hostname": "srv02.corp.local", "OS": "Unknown"}], source="Network")
    merge_assets(inventory, [{"IP": "N/A", "Hostname": "SRV02.corp.local", "OS": "Windows Server 2022"}], source="AD")
    assert len(inventory) == 1 and next(iter(inventory.values()))["OS"] == "Windows Server 2022"


def test_merge_identity_rules():
    inventory = {}
    # A passive device is first seen by MAC only, later with its IP: still one machine.
    merge_assets(inventory, [{"IP": "N/A", "MAC": "AA:BB:CC:00:00:01", "Hostname": "Unknown"}], source="Passive")
    merge_assets(inventory, [{"IP": "10.0.0.8", "MAC": "aa:bb:cc:00:00:01", "OS": "Linux"}], source="Network")
    # Two different devices sharing a default hostname must NOT be merged.
    merge_assets(inventory, [{"IP": "10.0.0.20", "Hostname": "raspberrypi"},
                             {"IP": "10.0.0.21", "Hostname": "raspberrypi"}], source="Network")
    assert len(inventory) == 3
    assert {a["IP"] for a in inventory.values()} == {"10.0.0.8", "10.0.0.20", "10.0.0.21"}


def test_streaming_merge_stays_fast():
    """The UI merges hosts one at a time; with a shared index that must stay linear."""
    import time

    inventory, index = {}, {}
    start = time.perf_counter()
    for i in range(5000):
        merge_assets(inventory, [{"IP": f"10.{i // 250}.{i % 250}.1", "Ports": "22"}], "Network", index=index)
    assert len(inventory) == 5000 and time.perf_counter() - start < 5


def test_exporter_writes_all_formats_to_out_dir(tmp_path):
    paths = Exporter.save_results([{"IP": "1.2.3.4", "Hostname": "vm", "OS": "Linux", "Ports": "22"}],
                                  ["csv", "json", "html"], "network", "20260101_000000", out_dir=tmp_path)
    assert [p.suffix for p in paths] == [".csv", ".json", ".html"]
    assert all(p.is_relative_to(tmp_path) and p.stat().st_size for p in paths)
    assert json.loads(paths[1].read_text(encoding="utf-8"))[0]["Tag"] == "[Server]"


def test_legacy_classes_still_work_standalone():
    assets = RiskAssessor.add_risks(Tagger.tag_assets([{"Hostname": "printer01", "OS": "Unknown", "Ports": "N/A"}]))
    assert assets[0]["Tag"] == "[Printer]" and assets[0]["Risk"] == "High"
