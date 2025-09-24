from pathlib import Path
import logging
import csv
import json
from datetime import datetime
from tabulate import tabulate
from discovr.tagger import Tagger
from discovr.risk import RiskAssessor
from discovr.azure.exporter import AzureExporter
from discovr.azure.reporter import AzureReporter


class Logger:
    @staticmethod
    def setup(feature: str):
        docs_path = Path.home() / "Documents" / "discovr_reports" / "logs"
        docs_path.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = docs_path / f"discovr_{feature}_log_{timestamp}.log"
        logging.basicConfig(filename=str(log_file), level=logging.INFO,
                            format="%(asctime)s [%(levelname)s] %(message)s", force=True)
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger().addHandler(console)
        print(f"[+] Logs saved at {log_file}")
        return log_file, timestamp


class Exporter:
    @staticmethod
    def save_results(assets, formats, feature: str, timestamp: str):
        base_path = Path.home() / "Documents" / "discovr_reports"
        csv_dir = base_path / "csv"
        json_dir = base_path / "json"
        csv_dir.mkdir(parents=True, exist_ok=True)
        json_dir.mkdir(parents=True, exist_ok=True)

        if "json" in formats:
            json_file = json_dir / f"discovr_{feature}_{timestamp}.json"
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(assets, f, indent=4, default=str)
            print(f"[+] JSON saved: {json_file}")

        if "csv" in formats:
            if feature == "cloud":
                AzureExporter.export(assets, timestamp, csv_dir)
            else:
                csv_file = csv_dir / f"discovr_{feature}_{timestamp}.csv"

                def flatten_dict(d, parent_key="", sep="."):
                    items = []
                    for k, v in d.items():
                        new_key = f"{parent_key}{sep}{k}" if parent_key else k
                        if isinstance(v, dict):
                            items.extend(flatten_dict(v, new_key, sep=sep).items())
                        elif isinstance(v, list):
                            items.append((new_key, ";".join(map(str, v))))
                        else:
                            items.append((new_key, v))
                    return dict(items)

                flat_assets = [flatten_dict(a) for a in assets]
                if flat_assets:
                    headers = sorted({key for a in flat_assets for key in a.keys()})
                    with open(csv_file, "w", newline="", encoding="utf-8") as f:
                        writer = csv.DictWriter(f, fieldnames=headers)
                        writer.writeheader()
                        for a in flat_assets:
                            writer.writerow(a)
                    print(f"[+] CSV saved: {csv_file}")


class Reporter:
    @staticmethod
    def print_results(assets, total_hosts, context="assets", feature: str = None):
        if not assets:
            print("\n[!] No assets discovered.")
            return
        tagged_assets = Tagger.tag_assets(assets)
        risked_assets = RiskAssessor.add_risks(tagged_assets)
        if feature == "cloud":
            groups = {}
            for a in risked_assets:
                if a.get("ResourceGroup"):
                    a["ResourceGroup"] = a["ResourceGroup"].lower()
                rg = a.get("ResourceGroup", a.get("Name", "unknownrg")).lower()
                groups.setdefault(rg, []).append(a)
            AzureReporter.print_summary(groups)
        else:
            Reporter._print_tabular(risked_assets, total_hosts, context)

    @staticmethod
    def _print_tabular(assets, total_hosts, context):
        table = [
            [
                a.get("IP", "N/A"),
                a.get("Hostname", "Unknown"),
                a.get("OS", "Unknown"),
                ",".join(a.get("Ports", [])) if isinstance(a.get("Ports"), list) else a.get("Ports", "N/A"),
                a.get("Tag", "[Unknown]"),
                a.get("Risk", "Unknown"),
            ]
            for a in assets
        ]
        print("\nDiscovered Assets (final report):")
        print(tabulate(table, headers=["IP", "Hostname", "OS", "Ports", "Tag", "Risk"], tablefmt="grid"))
        print(f"\n[+] {len(assets)} assets discovered during {context}.")
