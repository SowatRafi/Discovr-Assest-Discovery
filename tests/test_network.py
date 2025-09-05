from discovr.core import Reporter
from discovr.tagger import Tagger
from discovr.risk import RiskAssessor

def run_mock_network_test():
    print("[+] Running Network Discovery Test (Simulated)")
    assets = [
        {"IP": "192.168.1.1", "Hostname": "router", "OS": "Linux/Unix", "Ports": "80,443"},
        {"IP": "192.168.1.10", "Hostname": "laptop01", "OS": "Windows 10 Pro", "Ports": "135,445"},
        {"IP": "192.168.1.20", "Hostname": "server01", "OS": "Linux 5.x kernel", "Ports": "22,80,443"}
    ]
    tagged_assets = Tagger.tag_assets(assets)
    risked_assets = RiskAssessor.add_risks(tagged_assets)
    Reporter.print_results(risked_assets, len(risked_assets), "active assets")

if __name__ == "__main__":
    run_mock_network_test()
