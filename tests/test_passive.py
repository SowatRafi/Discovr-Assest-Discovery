from discovr.core import Reporter

class MockPassiveDiscovery:
    """Simulates passive discovery without real packet sniffing"""
    def run(self):
        assets = [
            {"IP": "192.168.1.50", "Hostname": "printer.local", "OS": "Unknown", "Ports": "N/A"},
            {"IP": "192.168.1.60", "Hostname": "iot-camera.local", "OS": "Unknown", "Ports": "N/A"},
        ]
        for asset in assets:
            print(f"    [+] Simulated Passive Asset: {asset['IP']} ({asset['Hostname']})")
        return assets, len(assets)


def run_mock_passive_test():
    print("[+] Running Passive Discovery Test (Simulated)")
    scanner = MockPassiveDiscovery()
    assets, total = scanner.run()
    Reporter.print_results(assets, total)


if __name__ == "__main__":
    run_mock_passive_test()
