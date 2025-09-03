import argparse
import sys
import time
from discovr.core import Logger, Exporter, Reporter
from discovr.network import NetworkDiscovery


def main():
    parser = argparse.ArgumentParser(description="Discovr - Asset Discovery Tool")
    parser.add_argument("--scan-network", help="Network range, e.g. 192.168.1.0/24")
    parser.add_argument("--ports", help="Ports to scan, e.g. 22,80,443")

    args = parser.parse_args()
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    Logger.setup()

    assets = []
    total_hosts = 0
    elapsed_time = 0

    try:
        if args.scan_network:
            scanner = NetworkDiscovery(args.scan_network, args.ports)
            assets, total_hosts, elapsed_time = scanner.run()
        else:
            parser.print_help()
            return
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

    Reporter.print_results(assets, total_hosts)

    print(f"[+] Total execution time: {elapsed_time:.2f} seconds")
    print(f"[+] Logs saved at logs/discovr_log_{timestamp}.log")

    if assets:
        choice = input("\nDo you want to save results? (yes/no): ").strip().lower()
        if choice in ["yes", "y"]:
            format_choice = input("Choose format (csv/json/both): ").strip().lower()
            if format_choice == "csv":
                Exporter.save_results(assets, ["csv"], timestamp)
            elif format_choice == "json":
                Exporter.save_results(assets, ["json"], timestamp)
            elif format_choice == "both":
                Exporter.save_results(assets, ["csv", "json"], timestamp)
            else:
                print("[!] Invalid choice, not saving.")
        else:
            print("[+] Results not saved.")


if __name__ == "__main__":
    main()
