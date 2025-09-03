from discovr.core import Reporter

class MockCloudDiscovery:
    def __init__(self, provider):
        self.provider = provider

    def run(self):
        if self.provider == "aws":
            assets = [
                {"IP": "54.12.34.56", "Hostname": "aws-web01", "OS": "Amazon Linux", "Ports": "N/A"},
                {"IP": "10.0.0.12", "Hostname": "aws-db01", "OS": "Windows Server 2019", "Ports": "N/A"}
            ]
        elif self.provider == "azure":
            assets = [
                {"IP": "20.50.30.10", "Hostname": "azure-app01", "OS": "Ubuntu 20.04", "Ports": "N/A"},
                {"IP": "10.0.0.5", "Hostname": "azure-sql01", "OS": "Windows Server 2022", "Ports": "N/A"}
            ]
        else:
            assets = []

        for asset in assets:
            print(f"    [+] Simulated {self.provider.upper()} VM: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']}")
        return assets


def run_mock_cloud_test():
    print("[+] Running Cloud Discovery Tests")

    aws_scanner = MockCloudDiscovery("aws")
    aws_assets = aws_scanner.run()

    azure_scanner = MockCloudDiscovery("azure")
    azure_assets = azure_scanner.run()

    all_assets = aws_assets + azure_assets
    Reporter.print_results(all_assets, len(all_assets))


if __name__ == "__main__":
    run_mock_cloud_test()
