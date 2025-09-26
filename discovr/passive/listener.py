import logging
import platform
from scapy.all import sniff, ARP, DNS, DNSQR, BOOTP, DHCP, UDP, get_if_list

try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:  # pragma: no cover - optional dependency
    get_windows_if_list = None


class PassiveDiscovery:
    """Passive packet capture for network asset discovery."""

    def __init__(self, iface=None, count=0, timeout=180):
        self.iface = iface
        self.count = count
        self.timeout = timeout
        self.assets = {}

    def _list_interfaces(self):
        if platform.system() == "Windows" and get_windows_if_list:
            return get_windows_if_list()
        return get_if_list()

    def _select_iface(self):
        ifaces = self._list_interfaces()
        print("[+] Available interfaces:")

        if platform.system() == "Windows" and get_windows_if_list:
            for idx, iface in enumerate(ifaces, start=1):
                print(f"    [{idx}] {iface['name']} ({iface['description']})")
            choice = input("\nSelect interface by number: ").strip()
            try:
                idx = int(choice)
                if 1 <= idx <= len(ifaces):
                    return ifaces[idx - 1]["name"]
            except ValueError:
                pass
        else:
            for idx, iface in enumerate(ifaces, start=1):
                print(f"    [{idx}] {iface}")
            choice = input("\nSelect interface by number: ").strip()
            try:
                idx = int(choice)
                if 1 <= idx <= len(ifaces):
                    return ifaces[idx - 1]
            except ValueError:
                pass

        print("[!] Invalid choice.")
        return None

    def _process_packet(self, packet):
        ip, hostname = None, None

        if packet.haslayer(ARP) and packet[ARP].psrc:
            ip = packet[ARP].psrc
            hostname = f"MAC-{packet[ARP].hwsrc}"
        elif packet.haslayer(DNS) and packet.haslayer(DNSQR):
            hostname = packet[DNSQR].qname.decode("utf-8") if packet[DNSQR].qname else None
        elif packet.haslayer(BOOTP) and packet.haslayer(DHCP):
            ip = packet[BOOTP].yiaddr if packet[BOOTP].yiaddr != "0.0.0.0" else None
            hostname = f"DHCP-{packet[BOOTP].chaddr.hex()}"
        elif packet.haslayer(UDP) and packet[UDP].dport == 5353 and packet.haslayer(DNSQR):
            hostname = packet[DNSQR].qname.decode("utf-8") if packet[DNSQR].qname else "mDNS-device"

        if ip or hostname:
            key = ip or hostname
            if key not in self.assets:
                self.assets[key] = {
                    "IP": ip or "N/A",
                    "Hostname": hostname or "Unknown",
                    "OS": "Unknown",
                    "Ports": "N/A",
                }
                logging.info(
                    f"    [+] Passive Discovery Found: {self.assets[key]['IP']} ({self.assets[key]['Hostname']})"
                )

    def run(self):
        if not self.iface:
            self.iface = self._select_iface()
            if not self.iface:
                return [], 0

        print(f"[+] Starting passive discovery on interface: {self.iface}")
        print(
            f"[+] Listening for ARP, DNS, DHCP, and mDNS traffic (auto-stop after {self.timeout} seconds or Ctrl+C)...\n"
        )

        try:
            sniff(
                prn=self._process_packet,
                iface=self.iface,
                count=self.count,
                timeout=self.timeout,
                store=0,
            )
        except KeyboardInterrupt:
            print("\n[+] Stopping passive discovery...")

        return list(self.assets.values()), len(self.assets)
