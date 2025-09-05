from discovr.core import Reporter
from discovr.tagger import Tagger
from discovr.risk import RiskAssessor

def run_mock_passive_test():
    print("[+] Running Passive Discovery Test (Simulated)")
    assets = [
        {"IP": "192.168.1.50", "Hostname": "printer.local", "OS": "Unknown", "Ports": "N/A"},
        {"IP": "192.168.1.60", "Hostname": "iot-camera.local", "OS": "Unknown", "Ports": "N/A"}
    ]
    tagged_assets = Tagger.tag_assets(assets)
    risked_assets = RiskAssessor.add_risks(tagged_assets)
    Reporter.print_results(risked_assets, len(risked_assets), "assets")

if __name__ == "__main__":
    run_mock_passive_test()
