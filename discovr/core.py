from pathlib import Path
import logging
import csv
import json
from datetime import datetime
from tabulate import tabulate
from discovr.tagger import Tagger
from discovr.risk import RiskAssessor


class Logger:
    @staticmethod
    def setup(feature: str):
        """
        Set up logging to save logs in the OS default Documents/discovr_reports/logs folder.
        """
        docs_path = Path.home() / "Documents" / "discovr_reports" / "logs"
        docs_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = docs_path / f"discovr_{feature}_log_{timestamp}.log"

        logging.basicConfig(
            filename=str(log_file),
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            force=True,
        )
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger().addHandler(console)

        # Always print the absolute path of the log file
        print(f"[+] Logs saved at {log_file}")
        return log_file, timestamp


class Exporter:
    @staticmethod
    def save_results(assets, formats, feature: str, timestamp: str):
        """
        Save discovered assets into CSV and/or JSON in Documents/discovr_reports folders.
        """
        base_path = Path.home() / "Documents" / "discovr_reports"
        csv_dir = base_path / "csv"
        json_dir = base_path / "json"
        csv_dir.mkdir(parents=True, exist_ok=True)
        json_dir.mkdir(parents=True, exist_ok=True)

        if "csv" in formats:
            csv_file = csv_dir / f"discovr_{feature}_{timestamp}.csv"
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["IP", "Hostname", "OS", "Ports", "Tag", "Risk"]
                )
                writer.writeheader()
                writer.writerows(assets)
            print(f"[+] CSV saved: {csv_file}")

        if "json" in formats:
            json_file = json_dir / f"discovr_{feature}_{timestamp}.json"
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(assets, f, indent=4)
            print(f"[+] JSON saved: {json_file}")


class Reporter:
    @staticmethod
    def print_results(assets, total_hosts, context="assets"):
        """
        Print discovered assets in tabular form with tags and risk assessment.
        """
        if assets:
            tagged_assets = Tagger.tag_assets(assets)
            risked_assets = RiskAssessor.add_risks(tagged_assets)
            table = [
                [a["IP"], a["Hostname"], a["OS"], a["Ports"], a["Tag"], a["Risk"]]
                for a in risked_assets
            ]
            print("\nDiscovered Assets (final report):")
            print(
                tabulate(
                    table,
                    headers=["IP", "Hostname", "OS", "Ports", "Tag", "Risk"],
                    tablefmt="grid",
                )
            )
            print(
                f"\n[+] {len(risked_assets)} {context} discovered out of {total_hosts} scanned hosts."
            )
        else:
            print("\n[!] No assets discovered.")
