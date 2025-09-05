from discovr.core import Reporter

class MockADDiscovery:
    """Simulates AD results without connecting to real AD"""
    def run(self):
        assets = [
            {"IP": "192.168.1.25", "Hostname": "HR-PC01.mydomain.local", "OS": "Windows 10 Pro", "Ports": "N/A"},
            {"IP": "192.168.1.30", "Hostname": "DB-SERVER01.mydomain.local", "OS": "Windows Server 2019", "Ports": "N/A"},
            {"IP": "192.168.1.40", "Hostname": "DEV-LAPTOP.mydomain.local", "OS": "Windows 11 Pro", "Ports": "N/A"}
        ]
        for asset in assets:
            print(f"    [+] Simulated AD Computer: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']}")
        return assets


def run_mock_ad_test():
    print("[+] Running Active Directory Discovery Test (Simulated)")
    scanner = MockADDiscovery()
    assets = scanner.run()
    Reporter.print_results(assets, len(assets))


if __name__ == "__main__":
    run_mock_ad_test()
