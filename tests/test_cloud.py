from discovr.core import Reporter
from discovr.tagger import Tagger
from discovr.risk import RiskAssessor

def run_mock_cloud_test():
    print("[+] Running Cloud Discovery Test (Simulated)")
    assets = [
        {"IP": "54.12.34.56", "Hostname": "aws-web01", "OS": "Amazon Linux", "Ports": "N/A"},
        {"IP": "10.0.0.12", "Hostname": "aws-db01", "OS": "Windows Server 2019", "Ports": "N/A"},
        {"IP": "20.50.30.10", "Hostname": "azure-app01", "OS": "Ubuntu 20.04", "Ports": "N/A"},
        {"IP": "10.0.0.5", "Hostname": "azure-sql01", "OS": "Windows Server 2022", "Ports": "N/A"},
    ]
    tagged_assets = Tagger.tag_assets(assets)
    risked_assets = RiskAssessor.add_risks(tagged_assets)
    Reporter.print_results(risked_assets, len(risked_assets), "cloud assets")

if __name__ == "__main__":
    run_mock_cloud_test()
