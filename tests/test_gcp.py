from discovr.core import Reporter

class MockGCPDiscovery:
    def run(self):
        assets = [
            {"IP": "34.122.12.34", "Hostname": "gcp-web01", "OS": "Ubuntu 22.04", "Ports": "N/A"},
            {"IP": "10.128.0.5", "Hostname": "gcp-db01", "OS": "Windows Server 2019", "Ports": "N/A"},
        ]
        for asset in assets:
            print(f"    [+] Simulated GCP Instance: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']}")
        return assets


def run_mock_gcp_test():
    print("[+] Running GCP Discovery Test (Simulated)")
    scanner = MockGCPDiscovery()
    assets = scanner.run()
    Reporter.print_results(assets, len(assets), "cloud assets")


if __name__ == "__main__":
    run_mock_gcp_test()
