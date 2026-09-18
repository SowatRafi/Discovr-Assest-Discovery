"""Tests for passive discovery (discovr.passive) with crafted packets - no capture needed."""
import threading
import warnings

import pytest

warnings.filterwarnings("ignore")  # scapy warns when no libpcap/Npcap is installed
from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, IP, UDP, Ether  # noqa: E402

import scapy.all  # noqa: E402
from discovr.core import enrich  # noqa: E402
from discovr.passive import PassiveDiscovery, dhcp_os  # noqa: E402

LAPTOP = "aa:bb:cc:00:00:01"


def feed(*packets):
    """Run packets through a fresh PassiveDiscovery (bytes round-trip = what the wire delivers)."""
    discovery, streamed = PassiveDiscovery(), []
    discovery.on_asset = streamed.append
    for packet in packets:
        discovery._process_packet(Ether(bytes(packet)))
    return discovery.devices, streamed


def test_dns_queries_do_not_become_assets():
    query = Ether(src=LAPTOP) / IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=51000, dport=53) / \
        DNS(rd=1, qd=DNSQR(qname="google.com"))
    devices, _ = feed(query)
    assert list(devices) == [LAPTOP]                               # the laptop, not "google.com"
    assert devices[LAPTOP]["IP"] == "192.168.1.10" and devices[LAPTOP]["Hostname"] == "Unknown"


def test_mdns_answer_names_the_sender():
    answer = Ether(src="aa:bb:cc:00:00:02") / IP(src="192.168.1.40", dst="224.0.0.251") / \
        UDP(sport=5353, dport=5353) / DNS(qr=1, an=[DNSRR(rrname="Johns-MacBook.local.", type="A", rdata="192.168.1.40")])
    devices, _ = feed(answer)
    assert devices["aa:bb:cc:00:00:02"]["Hostname"] == "Johns-MacBook.local"
    assert devices["aa:bb:cc:00:00:02"]["SeenVia"] == "mDNS"


def test_dhcp_request_and_ack_fingerprint_the_client():
    client = "de:ad:be:ef:00:01"
    request = Ether(src=client, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / \
        UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=bytes.fromhex("deadbeef0001")) / \
        DHCP(options=[("message-type", "request"), ("requested_addr", "192.168.1.77"),
                      ("hostname", b"DESKTOP-7Q2"), ("vendor_class_id", b"MSFT 5.0"), "end"])
    ack = Ether(src="11:22:33:44:55:66") / IP(src="192.168.1.1", dst="192.168.1.77") / UDP(sport=67, dport=68) / \
        BOOTP(op=2, yiaddr="192.168.1.77", chaddr=bytes.fromhex("deadbeef0001")) / \
        DHCP(options=[("message-type", "ack"), "end"])
    devices, streamed = feed(request, ack)
    pc = enrich([devices[client]])[0]
    assert (pc["IP"], pc["Hostname"], pc["OS"]) == ("192.168.1.77", "DESKTOP-7Q2", "Windows (DHCP fingerprint)")
    assert pc["Tag"] == "[Workstation]" and pc["DHCPVendor"] == "MSFT 5.0"
    assert devices["11:22:33:44:55:66"]["IP"] == "192.168.1.1"  # the DHCP server is recorded too
    assert streamed and streamed[0]["MAC"] == client


def test_arp_maps_ip_to_mac_and_ignores_probes():
    reply = Ether(src="aa:bb:cc:00:00:03") / ARP(op=2, hwsrc="aa:bb:cc:00:00:03", psrc="192.168.1.20")
    probe = Ether(src="aa:bb:cc:00:00:04") / ARP(op=1, hwsrc="aa:bb:cc:00:00:04", psrc="0.0.0.0")
    devices, _ = feed(reply, probe)
    assert devices["aa:bb:cc:00:00:03"]["IP"] == "192.168.1.20"
    assert devices["aa:bb:cc:00:00:04"]["IP"] == "N/A"             # address probe: MAC only


def test_dhcp_vendor_fingerprints():
    assert dhcp_os("android-dhcp-14") == "Android (DHCP fingerprint)"
    assert dhcp_os("dhcpcd-9.4.1:Linux-6.1") == "Linux (DHCP fingerprint)" and dhcp_os("") == ""


class DeadSniffer:
    """Stands in for scapy's AsyncSniffer when capture fails (e.g. Npcap missing)."""

    def __init__(self, **kwargs):
        self.thread = threading.Thread(target=lambda: None)
        self.exception = OSError("Npcap is not installed")

    def start(self):
        self.thread.start()
        self.thread.join()

    def stop(self):
        raise RuntimeError("Not running")


def test_capture_failure_is_reported_clearly(monkeypatch):
    monkeypatch.setattr(scapy.all, "AsyncSniffer", DeadSniffer)
    with pytest.raises(RuntimeError, match="Npcap is not installed"):
        PassiveDiscovery(iface="Wi-Fi", timeout=5).run(cancel=threading.Event())
