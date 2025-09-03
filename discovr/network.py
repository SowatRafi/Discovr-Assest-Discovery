import time
import logging

try:
    import nmap
    nmap_available = True
except ImportError:
    nmap_available = False


class NetworkDiscovery:
    def __init__(self, network_range, ports=None):
        self.network_range = network_range
        self.ports = ports

    def run(self):
        if not nmap_available:
            print("[!] python-nmap not installed. Run: pip install python-nmap")
            return [], 0

        nm = nmap.PortScanner()
        print(f"[+] Scanning network: {self.network_range}")

        if self.ports:
            print(f"[+] Scanning ports: {self.ports}")
            arguments = f"-p {self.ports} -T4"
        else:
            print("[+] Running OS detection scan (requires admin privileges)")
            arguments = "-O -p 1-1024 -T4"

        start_time = time.time()

        try:
            nm.scan(hosts=self.network_range, arguments=arguments)
        except Exception as e:
            print(f"[!] Nmap scan failed: {e}")
            return [], 0

        total_hosts = len(nm.all_hosts())
        print(f"[+] {total_hosts} hosts scanned, processing results...\n")

        assets = []
        for host in nm.all_hosts():
            ip = host
            hostname = nm[host].hostname() or "Unknown"
            os_name = "Unknown"

            if not self.ports and "osmatch" in nm[host] and nm[host]["osmatch"]:
                os_name = nm[host]["osmatch"][0]["name"]

            open_ports = []
            if "tcp" in nm[host]:
                for port, port_data in nm[host]["tcp"].items():
                    if port_data["state"] == "open":
                        open_ports.append(str(port))

            if os_name == "Unknown" and open_ports:
                if "445" in open_ports or "3389" in open_ports:
                    os_name = "Windows (guessed)"
                elif "22" in open_ports:
                    os_name = "Linux/Unix (guessed)"

            asset = {
                "IP": ip,
                "Hostname": hostname,
                "OS": os_name,
                "Ports": ",".join(open_ports) if open_ports else "None",
            }

            print(f"    [+] Found: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']} | Ports: {asset['Ports']}")
            assets.append(asset)

        elapsed_time = time.time() - start_time
        return assets, total_hosts, elapsed_time
