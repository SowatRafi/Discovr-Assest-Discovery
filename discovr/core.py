import os
import logging
from datetime import datetime
import csv
import json
from tabulate import tabulate


class Logger:
    @staticmethod
    def setup(feature: str):
        """Setup logger with feature-based log filename"""
        os.makedirs("logs", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join("logs", f"discovr_{feature}_log_{timestamp}.log")

        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            force=True,  # reset handlers
        )
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger().addHandler(console)

        print(f"[+] Logs saved at {log_file}")
        return log_file, timestamp


class Exporter:
    @staticmethod
    def save_results(assets, formats, feature: str, timestamp: str):
        """Save results with feature-based filenames"""
        os.makedirs("csv_report", exist_ok=True)
        os.makedirs("json_report", exist_ok=True)

        if "csv" in formats:
            csv_file = os.path.join("csv_report", f"discovr_{feature}_{timestamp}.csv")
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["IP", "Hostname", "OS", "Ports"])
                writer.writeheader()
                writer.writerows(assets)
            print(f"[+] CSV saved: {csv_file}")

        if "json" in formats:
            json_file = os.path.join("json_report", f"discovr_{feature}_{timestamp}.json")
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(assets, f, indent=4)
            print(f"[+] JSON saved: {json_file}")


class Reporter:
    @staticmethod
    def print_results(assets, total_hosts, context="assets"):
        """Print results in tabular form with summary (for active scans)"""
        if assets:
            table = [[a["IP"], a["Hostname"], a["OS"], a["Ports"]] for a in assets]
            print("\nDiscovered Assets (final report):")
            print(tabulate(table, headers=["IP", "Hostname", "OS", "Ports"], tablefmt="grid"))
            print(f"\n[+] {len(assets)} {context} discovered out of {total_hosts} scanned hosts.")
        else:
            print("\n[!] No assets discovered.")
