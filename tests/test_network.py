import time
from discovr.core import Reporter


class MockNetworkDiscovery:
    """Mock class to simulate multiple discovered assets without Nmap."""

    def __init__(self, network_range):
        self.network_range = network_range

    def run(self):
        print(f"[+] Scanning network: {self.network_range}")
        print("[+] Running OS detection scan (requires admin privileges)")
        time.sleep(1)  # simulate scan delay
        print("[+] 256 hosts scanned, processing results...\n")

        assets = [
            {"IP": "192.168.1.1", "Hostname": "router", "OS": "Linux/Unix (guessed)", "Ports": "80,443"},
            {"IP": "192.168.1.10", "Hostname": "laptop01", "OS": "Windows 10 Pro", "Ports": "135,445"},
            {"IP": "192.168.1.20", "Hostname": "server01", "OS": "Linux 5.x kernel", "Ports": "22,80,443"},
        ]

        for asset in assets:
            print(
                f"    [+] Found: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']} | Ports: {asset['Ports']}"
            )

        elapsed_time = 19.32
        return assets, 256, elapsed_time


def run_mock_network_test():
    scanner = MockNetworkDiscovery("192.168.1.0/24")
    assets, total_hosts, elapsed_time = scanner.run()

    Reporter.print_results(assets, total_hosts)

    print(f"[+] Total execution time: {elapsed_time:.2f} seconds")
    print(f"[+] Logs saved at logs/discovr_log_20250904_010601.log")


if __name__ == "__main__":
    run_mock_network_test()
