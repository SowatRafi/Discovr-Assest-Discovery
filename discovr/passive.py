"""Passive discovery: build an inventory by listening only - Discovr sends no packets.

For sensitive networks where active scanning is not allowed. On a switched LAN a
listener mostly sees broadcast/multicast chatter, which is exactly what devices use
to announce themselves:

  * ARP     - hosts asking for / announcing addresses (IP <-> MAC)
  * DHCP    - client hostname (option 12) and vendor class (option 60), which
              fingerprints the OS: "MSFT 5.0" = Windows, "android-dhcp-14" = Android
  * mDNS    - ".local" names devices publish for themselves (Macs, printers, IoT)
  * NBNS / LLMNR / SSDP - Windows name service and UPnP devices; the sender is alive

Each device is keyed by MAC address (its identity on the local segment), with its IP
filled in once any packet ties the two together.

Fixes over the previous version: DNS *queries* were recorded as assets (a laptop
resolving "google.com" became a bogus "google.com" device), the mDNS branch was
unreachable, DHCP names/vendors were ignored, and capture could not be cancelled.

Needs capture rights (Administrator/root, or configured capture permissions) plus Npcap
on Windows or libpcap on macOS/Linux.
"""
import ipaddress
import logging
import os
import sys
import time
from pathlib import Path

log = logging.getLogger(__name__)

# Kernel-side filter: only the self-announcing protocols listed above reach Python.
BPF_FILTER = "arp or udp port 67 or udp port 68 or udp port 137 or udp port 1900 or udp port 5353 or udp port 5355"
# DHCP option 60 (vendor class) fragments -> operating system.
DHCP_VENDOR_OS = (("msft", "Windows"), ("android", "Android"), ("dhcpcd", "Linux"),
                  ("udhcp", "Embedded Linux"), ("jetdirect", "HP JetDirect (printer)"), ("cisco", "Cisco IOS"))


def _text(value) -> str:
    """Decode a DHCP/DNS byte string safely (names come from the network: never trust them)."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value or "").strip().strip("\x00").rstrip(".")[:255]


def _usable_ip(value) -> str:
    """The IP if it is a real unicast private/link-local address, else ""."""
    try:
        ip = ipaddress.IPv4Address(str(value))
    except ValueError:
        return ""
    ok = (ip.is_private or ip.is_link_local) and not (ip.is_unspecified or ip.is_multicast or ip.is_loopback)
    return str(ip) if ok else ""


def dhcp_os(vendor_class: str) -> str:
    """OS hint from a DHCP vendor class id; "" when unknown."""
    lowered = vendor_class.lower()
    return next((f"{name} (DHCP fingerprint)" for key, name in DHCP_VENDOR_OS if key in lowered), "")


def list_interfaces() -> list:
    """Capture-capable interfaces with an IPv4 address: [{"name", "address"}] (psutil; no scapy import)."""
    import psutil
    import socket

    result = []
    for name, addresses in psutil.net_if_addrs().items():
        ipv4 = next((a.address for a in addresses if a.family == socket.AF_INET), None)
        if ipv4 and not ipv4.startswith("127."):
            result.append({"name": name, "address": ipv4})
    return result


def capture_warning() -> str:
    """Why passive capture probably cannot work here ("" if it probably can)."""
    from discovr.core import is_elevated

    if sys.platform == "win32" and not (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap").exists():
        return "Npcap is not installed - get it from https://npcap.com to enable passive discovery"
    if not is_elevated():
        return "Packet capture usually needs Administrator/root rights"
    return ""


class PassiveDiscovery:
    """Listens on one interface and turns self-announcing traffic into assets."""

    def __init__(self, iface=None, count=0, timeout=180):
        """
        :param iface: interface name ("Wi-Fi", "Ethernet", "eth0", "en0"); prompted for if missing
        :param count: stop after this many packets (0 = no limit)
        :param timeout: listening time in seconds (default 180)
        """
        self.iface = iface
        self.count = count
        self.timeout = timeout
        self.devices = {}   # MAC -> asset
        self.on_asset = None

    def _select_iface(self):
        """Interactive interface picker for the CLI."""
        interfaces = list_interfaces()
        print("[+] Available interfaces:")
        for idx, iface in enumerate(interfaces, start=1):
            print(f"    [{idx}] {iface['name']} ({iface['address']})")
        choice = input("\nSelect interface by number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            return interfaces[int(choice) - 1]["name"]
        print("[!] Invalid choice.")
        return None

    def _seen(self, mac, ip="", name="", os_name="", vendor="", via=""):
        """Record evidence about a device; stream it to the UI when something new was learned."""
        mac = str(mac or "").lower()
        if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return
        device = self.devices.setdefault(mac, {"IP": "N/A", "Hostname": "Unknown", "OS": "Unknown",
                                               "Ports": "N/A", "MAC": mac, "Source": "Passive", "SeenVia": ""})
        before = dict(device)
        if ip:
            device["IP"] = ip
        if name and device["Hostname"] == "Unknown":
            device["Hostname"] = name
        if os_name and device["OS"] == "Unknown":
            device["OS"] = os_name
        if vendor:
            device["DHCPVendor"] = vendor
        if via and via not in device["SeenVia"].split(", "):
            device["SeenVia"] = ", ".join(filter(None, [device["SeenVia"], via]))
        if device != before:
            if (before["IP"] == "N/A" and device["IP"] != "N/A") or before["Hostname"] != device["Hostname"]:
                log.info(f"    [+] Passive: {device['IP']} ({device['Hostname']}) | MAC {mac} | via {device['SeenVia']}")
            if self.on_asset:
                self.on_asset(dict(device))

    def _process_packet(self, packet):
        """Extract device evidence from one captured packet (called by scapy per packet)."""
        from scapy.all import ARP, BOOTP, DHCP, DNS, IP, UDP, Ether

        mac = packet[Ether].src if packet.haslayer(Ether) else ""
        if packet.haslayer(ARP):
            arp = packet[ARP]
            self._seen(arp.hwsrc, ip=_usable_ip(arp.psrc), via="ARP")
            return
        if packet.haslayer(DHCP) and packet.haslayer(BOOTP):
            bootp = packet[BOOTP]
            options = {o[0]: o[1] for o in packet[DHCP].options if isinstance(o, tuple) and len(o) > 1}
            client_mac = ":".join(f"{b:02x}" for b in bytes(bootp.chaddr)[:6])
            ip = _usable_ip(options.get("requested_addr")) or _usable_ip(bootp.ciaddr) or _usable_ip(bootp.yiaddr)
            vendor = _text(options.get("vendor_class_id"))
            self._seen(client_mac, ip=ip, name=_text(options.get("hostname")), os_name=dhcp_os(vendor),
                       vendor=vendor, via="DHCP")
            if bootp.op == 2 and packet.haslayer(IP):  # reply: the sender is the DHCP server itself
                self._seen(mac, ip=_usable_ip(packet[IP].src), via="DHCP server")
            return
        if not packet.haslayer(IP):
            return
        src = _usable_ip(packet[IP].src)
        port = packet[UDP].sport if packet.haslayer(UDP) else 0
        name = ""
        if port == 5353 and packet.haslayer(DNS) and packet[DNS].qr == 1:
            # mDNS answer: an A record for a ".local" name that points at the sender is its own name.
            for record in list(packet[DNS].an or []) + list(packet[DNS].ar or []):
                if getattr(record, "type", 0) == 1 and str(getattr(record, "rdata", "")) == src:
                    name = _text(record.rrname)
                    break
        via = {5353: "mDNS", 137: "NetBIOS", 5355: "LLMNR", 1900: "SSDP"}.get(port, "IP")
        if src:
            self._seen(mac, ip=src, name=name, via=via)

    def run(self, on_progress=None, on_asset=None, cancel=None):
        """Listen for ``timeout`` seconds (or until cancelled); returns (assets, count).

        :param on_progress: callback(elapsed_seconds, timeout, stage)
        :param on_asset: callback(asset) whenever a device is new or better identified
        :param cancel: threading.Event that stops listening early
        """
        from scapy.all import AsyncSniffer  # lazy: importing scapy costs ~1 s

        self.on_asset = on_asset
        if not self.iface:
            self.iface = self._select_iface()
            if not self.iface:
                return [], 0
        log.info(f"[+] Listening on {self.iface} for ARP, DHCP, mDNS, NetBIOS, LLMNR and SSDP "
                 f"(stops after {self.timeout}s or Ctrl+C)")
        sniffer = AsyncSniffer(iface=self.iface, filter=BPF_FILTER, prn=self._process_packet,
                               store=False, count=self.count)
        def failure(exc):
            """Capture error with the likely fix appended (missing Npcap, no admin rights)."""
            hint = capture_warning()
            return RuntimeError(f"Packet capture on '{self.iface}' failed: {exc}" + (f" - {hint}" if hint else ""))

        try:
            sniffer.start()
        except Exception as exc:  # scapy raises many types here (OSError, Scapy_Exception...)
            raise failure(exc) from exc
        start = time.monotonic()
        try:
            while time.monotonic() - start < self.timeout and not (cancel is not None and cancel.is_set()):
                # scapy sets .running inside its thread (racy right after start), so watch the thread.
                if not sniffer.thread.is_alive():
                    if sniffer.exception:  # permissions, missing Npcap/libpcap, unknown interface
                        raise failure(sniffer.exception)
                    break  # packet count reached
                if on_progress:
                    on_progress(int(time.monotonic() - start), self.timeout, f"Listening on {self.iface}")
                time.sleep(0.5)
        except KeyboardInterrupt:
            log.info("[+] Stopping passive discovery...")
        finally:
            try:
                sniffer.stop()
            except Exception:  # already finished (count reached or capture failed)
                pass
        if on_progress:
            on_progress(self.timeout, self.timeout, f"Listening on {self.iface}")  # marks the stage complete
        assets = list(self.devices.values())
        return assets, len(assets)
