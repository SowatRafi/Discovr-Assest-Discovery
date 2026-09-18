"""Tests for Active Directory discovery (discovr.active_directory) using ldap3's offline mock."""
from datetime import datetime, timezone

from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

import discovr.active_directory as ad
from discovr.active_directory import ADDiscovery, computer_to_asset, filetime_to_datetime, ou_path

NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
# 2026-08-20 as AD FILETIME (100 ns ticks since 1601-01-01).
RECENT = str(int((datetime(2026, 8, 20, tzinfo=timezone.utc) - datetime(1601, 1, 1, tzinfo=timezone.utc))
                 .total_seconds() * 10_000_000))


def test_filetime_conversion():
    assert filetime_to_datetime(RECENT).date().isoformat() == "2026-08-20"
    assert filetime_to_datetime(["0"]) is None and filetime_to_datetime(None) is None


def test_ou_path_is_top_down_and_handles_escaped_commas():
    assert ou_path("CN=PC\\,01,OU=Laptops,OU=HQ,DC=corp,DC=local") == "HQ/Laptops"
    assert ou_path("CN=DC01,CN=Computers,DC=corp,DC=local") == ""


def test_computer_entry_to_asset():
    workstation = computer_to_asset("CN=PC01,OU=Laptops,DC=corp,DC=local", {
        "dNSHostName": ["pc01.corp.local"], "operatingSystem": ["Windows 11 Enterprise"],
        "operatingSystemVersion": ["10.0 (22631)"], "userAccountControl": ["4096"],
        "lastLogonTimestamp": [RECENT]}, now=NOW)
    assert workstation["Hostname"] == "pc01.corp.local" and workstation["OU"] == "Laptops"
    assert workstation["OS"] == "Windows 11 Enterprise 10.0 (22631)"
    assert workstation["Enabled"] and not workstation["DomainController"] and not workstation["Stale"]

    dc = computer_to_asset("CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
                           {"cn": "DC01", "userAccountControl": 532480}, now=NOW)   # SERVER_TRUST | DELEGATION
    assert dc["DomainController"] and dc["Hostname"] == "DC01" and dc["LastLogon"] == "Never" and dc["Stale"]

    disabled = computer_to_asset("CN=OLD,DC=corp,DC=local", {"cn": ["OLD"], "userAccountControl": ["4098"]}, now=NOW)
    assert not disabled["Enabled"] and disabled["OS"] == "Unknown"


def test_ntlm_username_forms():
    assert ADDiscovery("corp.local", "alice@corp.local", "x")._ntlm_user() == "corp.local\\alice"
    assert ADDiscovery("corp.local", "CORP\\alice", "x")._ntlm_user() == "CORP\\alice"
    assert ADDiscovery("corp.local", "alice", "x")._ntlm_user() == "corp.local\\alice"


def test_run_pages_through_directory(monkeypatch):
    """End-to-end over ldap3's in-memory directory: 1,205 computers > AD's 1,000 unpaged cap."""
    server = Server("fake-dc", get_info=OFFLINE_AD_2012_R2)
    conn = Connection(server, user="cn=reader,dc=corp,dc=local", password="pw", client_strategy=MOCK_SYNC)
    conn.strategy.add_entry("cn=reader,dc=corp,dc=local", {"userPassword": "pw", "sn": "reader"})
    for i in range(1205):
        conn.strategy.add_entry(f"cn=pc{i},ou=Workstations,dc=corp,dc=local", {
            "objectClass": "computer", "cn": f"pc{i}", "dNSHostName": f"pc{i}.corp.local",
            "operatingSystem": "Windows 11 Pro", "userAccountControl": 4098 if i == 0 else 4096})
    conn.bind()

    monkeypatch.setattr(ADDiscovery, "_connect", lambda self: (conn, "MOCK"))
    monkeypatch.setattr(ad, "_resolve", lambda fqdn: "10.0.0.1" if fqdn == "pc1.corp.local" else "N/A")
    assets = ADDiscovery("corp.local", "reader", "pw").run()

    assert len(assets) == 1205
    by_name = {a["Hostname"]: a for a in assets}
    assert by_name["pc1.corp.local"]["IP"] == "10.0.0.1" and by_name["pc1.corp.local"]["OU"] == "Workstations"
    assert not by_name["pc0.corp.local"]["Enabled"] and by_name["pc0.corp.local"]["IP"] == "N/A"
