"""Startup address detection uses OS facts, including isolated LANs and VPNs."""
import socket
from types import SimpleNamespace

import pytest

from discovr.network import local_network_info, local_subnet


def address(ip, netmask="255.255.255.0"):
    return SimpleNamespace(family=socket.AF_INET, address=ip, netmask=netmask)


def environment(monkeypatch, interfaces, primary=None, down=()):
    monkeypatch.setattr("psutil.net_if_addrs", lambda: interfaces)
    monkeypatch.setattr("psutil.net_if_stats", lambda: {
        name: SimpleNamespace(isup=name not in down) for name in interfaces})
    def route():
        if primary is None:
            raise OSError("No default route")
        return primary
    monkeypatch.setattr("discovr.network.primary_ip", route)


def test_default_route_selects_vpn_and_preserves_actual_netmask(monkeypatch):
    environment(monkeypatch, {"Wi-Fi": [address("192.168.3.8")],
                "VPN": [address("10.20.4.9", "255.255.252.0")]}, primary="10.20.4.9")
    info = local_network_info()
    chosen = info["connections"][info["selected"]]
    assert chosen["interface"] == "VPN" and chosen["subnet"] == "10.20.4.0/22"
    assert len(info["connections"]) == 2
    assert local_subnet() == "10.20.4.0/22"


def test_single_isolated_lan_works_without_default_route(monkeypatch):
    environment(monkeypatch, {"Ethernet": [address("192.168.3.8")]})
    assert local_subnet() == "192.168.3.0/24"


def test_multiple_connections_without_route_require_choice(monkeypatch):
    environment(monkeypatch, {"Ethernet": [address("192.168.3.8")], "VPN": [address("10.0.0.3")]})
    assert local_network_info()["selected"] is None
    with pytest.raises(OSError, match="choose a connection"):
        local_subnet()


@pytest.mark.parametrize("mask", [None, "", "invalid", "255.0.255.0"])
def test_missing_or_invalid_mask_does_not_guess_a_subnet(monkeypatch, mask):
    environment(monkeypatch, {"Ethernet": [address("192.168.3.8", mask)]})
    info = local_network_info()
    assert info["connections"][0]["netmask_known"] is False
    assert local_subnet() == "192.168.3.8/32"


def test_filters_down_loopback_and_invalid_addresses(monkeypatch):
    environment(monkeypatch, {"Down": [address("192.168.3.8")],
        "Loopback": [address("127.0.0.1")], "Other": [address("0.0.0.0"), address("224.0.0.1"),
        address("not-an-ip"), address("255.255.255.255"),
        SimpleNamespace(family=socket.AF_INET6, address="::1", netmask=None)]}, down=["Down"])
    assert local_network_info() == {"connections": [], "selected": None}


def test_link_local_address_and_restricted_status_still_display(monkeypatch):
    environment(monkeypatch, {"Ethernet": [address("169.254.8.9", "255.255.0.0")]})
    def restricted():
        raise OSError("Interface status unavailable")
    monkeypatch.setattr("psutil.net_if_stats", restricted)
    assert local_subnet() == "169.254.0.0/16"
