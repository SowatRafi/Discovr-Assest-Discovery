"""Tests for the asyncio network engine (discovr.network) - no real network access needed."""
import socket
import threading

import pytest

from discovr.network import (NetworkDiscovery, guess_os, parse_arp_table,
                             parse_port_spec, parse_targets)

WINDOWS_ARP = """
Interface: 192.168.1.161 --- 0x15
  Internet Address      Physical Address      Type
  192.168.1.1           60-95-f8-79-61-20     dynamic
  192.168.1.40          a4-83-e7-0b-1c-02     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
MACOS_ARP = """? (192.168.1.1) at 60:95:f8:79:61:20 on en0 ifscope [ethernet]
? (192.168.1.7) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.50) at 0:c:29:a:b:c on en0 ifscope [ethernet]
"""
LINUX_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         60:95:f8:79:61:20     *        eth0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0
"""


def test_parse_targets_expands_and_validates():
    assert parse_targets("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]   # no network/broadcast
    assert parse_targets("10.0.0.5") == ["10.0.0.5"]
    assert parse_targets("10.0.0.5, 10.0.0.4/31") == ["10.0.0.5", "10.0.0.4"]    # merged, de-duplicated
    for bad in ("", "10.0.0.300/24", "fe80::/64", "10.0.0.0/15", "not-an-ip"):
        with pytest.raises(ValueError):
            parse_targets(bad)


def test_parse_port_spec():
    assert parse_port_spec("443, 22,8000-8002") == [22, 443, 8000, 8001, 8002]
    for bad in ("", "0", "70000", "80-20", "http"):
        with pytest.raises(ValueError):
            parse_port_spec(bad)


def test_arp_tables_from_every_os():
    assert parse_arp_table(WINDOWS_ARP) == {"192.168.1.1": "60:95:f8:79:61:20",
                                            "192.168.1.40": "a4:83:e7:0b:1c:02"}
    assert parse_arp_table(MACOS_ARP) == {"192.168.1.1": "60:95:f8:79:61:20",
                                          "192.168.1.50": "00:0c:29:0a:0b:0c"}
    assert parse_arp_table(LINUX_ARP) == {"192.168.1.1": "60:95:f8:79:61:20"}


def test_guess_os_from_ports_and_banners():
    assert guess_os({22}, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13") == "Linux (Ubuntu) (guessed)"
    assert guess_os({22}, "SSH-2.0-OpenSSH_for_Windows_9.5") == "Windows (guessed)"
    assert guess_os({53, 88, 389, 445}) == "Windows Server (domain controller, guessed)"
    assert guess_os({135, 445}) == "Windows (guessed)"
    assert guess_os({22, 445}) == "Linux/Unix (guessed)"        # SMB + SSH = Samba/NAS, not Windows
    assert guess_os({62078}) == "iOS (guessed)"
    assert guess_os(set()) == "Unknown"



def test_scan_finds_listening_port_on_localhost():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        port = server.getsockname()[1]
        progress, streamed = [], []
        assets, scanned, elapsed = NetworkDiscovery("127.0.0.1/32", ports=str(port)).run(
            on_progress=lambda done, total, stage: progress.append((done, total)), on_asset=streamed.append)
    assert scanned == 1 and elapsed < 10
    assert [a["IP"] for a in assets] == ["127.0.0.1"] and assets[0]["Ports"] == str(port)
    assert assets[0]["Source"] == "Network" and streamed and progress[-1][0] == progress[-1][1]


def test_cancel_stops_before_probing():
    cancel = threading.Event()
    cancel.set()
    assets, scanned, _ = NetworkDiscovery("10.255.255.0/24", intensity="gentle").run(cancel=cancel)
    assert scanned == 254 and assets == []


def test_rejects_bad_intensity():
    with pytest.raises(ValueError):
        NetworkDiscovery("127.0.0.1", intensity="ludicrous")
