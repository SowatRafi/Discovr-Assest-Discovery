from discovr.core import Reporter
from discovr.tagger import Tagger
from discovr.risk import RiskAssessor

def run_mock_ad_test():
    print("[+] Running Active Directory Discovery Test (Simulated)")
    assets = [
        {"IP": "192.168.1.25", "Hostname": "HR-PC01.mydomain.local", "OS": "Windows 10 Pro", "Ports": "N/A"},
        {"IP": "192.168.1.30", "Hostname": "DB-SERVER01.mydomain.local", "OS": "Windows Server 2019", "Ports": "N/A"},
        {"IP": "192.168.1.40", "Hostname": "DEV-LAPTOP.mydomain.local", "OS": "Windows 11 Pro", "Ports": "N/A"}
    ]
    tagged_assets = Tagger.tag_assets(assets)
    risked_assets = RiskAssessor.add_risks(tagged_assets)
    Reporter.print_results(risked_assets, len(risked_assets), "AD assets")

if __name__ == "__main__":
    run_mock_ad_test()
