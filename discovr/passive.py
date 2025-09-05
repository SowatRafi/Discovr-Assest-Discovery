import logging
import platform
from scapy.all import sniff, ARP, DNS, DNSQR, BOOTP, DHCP, UDP, get_if_list

class PassiveDiscovery:
    def __init__(self, iface=None, count=0):
        """
        :param iface: Network interface
                       - Linux/Mac: 'eth0', 'wlan0', 'en0'
                       - Windows: raw GUID like '{782C6688-...}'
        :param count: Number of packets to capture (0 = unlimited until Ctrl+C)
        """
        self.iface = iface
        self.count = count
        self.assets = {}

    def _normalize_iface(self, iface):
        """Normalize interface name for Windows GUIDs and keep Linux/Mac unchanged."""
        if platform.system() == "Windows":
            if iface and iface.startswith("{") and iface.endswith("}"):
                # Correct: keep braces in Npcap path
                return f"\\\\Device\\\\NPF_{iface}"
        return iface

    def _process_packet(self, packet):
        ip, hostname = None, None

        # ARP packets (discover IP ↔ MAC mappings)
        if packet.haslayer(ARP) and packet[ARP].psrc:
            ip = packet[ARP].psrc
            hostname = f"MAC-{packet[ARP].hwsrc}"

        # DNS queries
        elif packet.haslayer(DNS) and packet.haslayer(DNSQR):
            hostname = packet[DNSQR].qname.decode("utf-8") if packet[DNSQR].qname else None

        # DHCP traffic (devices asking for IPs)
        elif packet.haslayer(BOOTP) and packet.haslayer(DHCP):
            ip = packet[BOOTP].yiaddr if packet[BOOTP].yiaddr != "0.0.0.0" else None
            hostname = f"DHCP-{packet[BOOTP].chaddr.hex()}"  # client MAC

        # mDNS traffic (multicast DNS — often IoT devices)
        elif packet.haslayer(UDP) and packet[UDP].dport == 5353 and packet.haslayer(DNSQR):
            hostname = packet[DNSQR].qname.decode("utf-8") if packet[DNSQR].qname else "mDNS-device"

        if ip or hostname:
            key = ip or hostname
            if key not in self.assets:
                self.assets[key] = {
                    "IP": ip or "N/A",
                    "Hostname": hostname or "Unknown",
                    "OS": "Unknown",
                    "Ports": "N/A"
                }
                logging.info(
                    f"    [+] Passive Discovery Found: {self.assets[key]['IP']} ({self.assets[key]['Hostname']})"
                )

    def _select_iface(self):
        """Interactive interface selection if none is provided"""
        available_ifaces = get_if_list()
        print("[+] Available interfaces:")
        for idx, iface in enumerate(available_ifaces, start=1):
            print(f"    [{idx}] {iface}")

        choice = input("\nSelect interface by number: ").strip()
        try:
            idx = int(choice)
            if 1 <= idx <= len(available_ifaces):
                return available_ifaces[idx - 1]
        except ValueError:
            pass

        print("[!] Invalid choice.")
        return None

    def run(self):
        if not self.iface:
            self.iface = self._select_iface()
            if not self.iface:
                return [], 0

        normalized_iface = self._normalize_iface(self.iface)
        available_ifaces = get_if_list()

        # Add expanded versions for Windows (Npcap device paths with braces)
        if platform.system() == "Windows":
            expanded = []
            for i in available_ifaces:
                if i.startswith("{") and i.endswith("}"):
                    expanded.append(f"\\\\Device\\\\NPF_{i}")
            available_ifaces.extend(expanded)

        if normalized_iface not in available_ifaces:
            print(f"[!] Invalid interface: {self.iface}")
            return [], 0

        print(f"[+] Starting passive discovery on interface: {normalized_iface}")
        print("[+] Listening for ARP, DNS, DHCP, and mDNS traffic (Ctrl+C to stop)...\n")

        try:
            sniff(prn=self._process_packet, iface=normalized_iface, count=self.count, store=0)
        except KeyboardInterrupt:
            print("\n[+] Stopping passive discovery...")

        return list(self.assets.values()), len(self.assets)
