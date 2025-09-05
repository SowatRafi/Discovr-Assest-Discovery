import logging
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import nmap
    nmap_available = True
except ImportError:
    nmap_available = False


class NetworkDiscovery:
    def __init__(self, network_range, ports=None, parallel=1):
        self.network_range = network_range
        self.ports = ports
        self.parallel = max(1, parallel)

    def _scan_host(self, host):
        """Scan a single host with Nmap"""
        nm = nmap.PortScanner()
        arguments = "-O -T4"
        if self.ports:
            arguments = f"-p {self.ports} -T4"

        try:
            nm.scan(hosts=host, arguments=arguments)
        except Exception as e:
            logging.error(f"[!] Nmap scan failed for {host}: {e}")
            return None

        assets = []
        for scanned_host in nm.all_hosts():
            hostname = nm[scanned_host].hostname() or "Unknown"
            os_name = "Unknown"

            if not self.ports and 'osmatch' in nm[scanned_host] and nm[scanned_host]['osmatch']:
                os_name = nm[scanned_host]['osmatch'][0]['name']

            open_ports = []
            if 'tcp' in nm[scanned_host]:
                for port, port_data in nm[scanned_host]['tcp'].items():
                    if port_data['state'] == 'open':
                        open_ports.append(str(port))

            if os_name == "Unknown" and open_ports:
                if "445" in open_ports or "3389" in open_ports:
                    os_name = "Windows (guessed)"
                elif "22" in open_ports:
                    os_name = "Linux/Unix (guessed)"

            asset = {
                "IP": scanned_host,
                "Hostname": hostname,
                "OS": os_name,
                "Ports": ",".join(open_ports) if open_ports else "None"
            }
            logging.info(
                f"    [+] Found: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']} | Ports: {asset['Ports']}"
            )
            assets.append(asset)
        return assets

    def run(self):
        if not nmap_available:
            print("[!] python-nmap not installed. Run: pip install python-nmap")
            return [], 0, 0

        print(f"[+] Scanning network: {self.network_range} with {self.parallel} parallel workers")
        print("[+] Running OS detection scan (requires admin privileges)")

        try:
            all_hosts = [str(ip) for ip in ipaddress.IPv4Network(self.network_range, strict=False)]
        except Exception as e:
            print(f"[!] Invalid network range: {e}")
            return [], 0, 0

        assets = []
        total_hosts = len(all_hosts)

        with ThreadPoolExecutor(max_workers=self.parallel) as executor:
            future_to_host = {executor.submit(self._scan_host, host): host for host in all_hosts}
            for future in as_completed(future_to_host):
                result = future.result()
                if result:
                    assets.extend(result)

        return assets, total_hosts, 0
