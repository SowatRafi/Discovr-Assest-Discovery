import argparse
import sys
import time
import warnings

# Suppress Scapy warnings (Wireshark manuf + TripleDES deprecation)
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)

from discovr.core import Logger, Exporter, Reporter
from discovr.network import NetworkDiscovery
from discovr.cloud import CloudDiscovery
from discovr.active_directory import ADDiscovery
from discovr.passive import PassiveDiscovery
from discovr.tagger import Tagger
from tabulate import tabulate


def main():
    parser = argparse.ArgumentParser(description="Discovr - Asset Discovery Tool")

    # Network
    parser.add_argument("--scan-network", help="Network range, e.g. 192.168.1.0/24")
    parser.add_argument("--ports", help="Ports to scan, e.g. 22,80,443")

    # Cloud
    parser.add_argument("--cloud", choices=["aws", "azure"], help="Cloud provider to scan")
    parser.add_argument("--profile", default="default", help="AWS profile (default: default)")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--subscription", help="Azure subscription ID")

    # Active Directory
    parser.add_argument("--ad", action="store_true", help="Run Active Directory discovery")
    parser.add_argument("--domain", help="Active Directory domain, e.g. mydomain.local")
    parser.add_argument("--username", help="AD username, e.g. user@mydomain.local")
    parser.add_argument("--password", help="AD password")

    # Passive
    parser.add_argument("--passive", action="store_true", help="Run passive discovery")
    parser.add_argument("--iface", help="Network interface (optional, choose interactively if missing)")
    parser.add_argument("--timeout", type=int, default=180, help="Passive discovery timeout in seconds (default: 180)")

    args = parser.parse_args()

    assets = []
    total_hosts = 0
    elapsed_time = 0
    feature = None
    timestamp = None

    try:
        # Network Discovery
        if args.scan_network:
            feature = "network"
            log_file, timestamp = Logger.setup(feature)
            scanner = NetworkDiscovery(args.scan_network, args.ports)
            assets, total_hosts, elapsed_time = scanner.run()
            Reporter.print_results(assets, total_hosts, "active assets")

        # Cloud Discovery
        elif args.cloud:
            feature = "cloud"
            log_file, timestamp = Logger.setup(feature)
            cloud_scanner = CloudDiscovery(
                provider=args.cloud,
                profile=args.profile,
                region=args.region,
                subscription=args.subscription,
            )
            print(f"[+] Discovering {args.cloud.upper()} assets...")
            start_time = time.time()
            assets = cloud_scanner.run()
            elapsed_time = time.time() - start_time
            Reporter.print_results(assets, len(assets), "cloud assets")

        # Active Directory Discovery
        elif args.ad:
            feature = "ad"
            log_file, timestamp = Logger.setup(feature)
            if not args.domain or not args.username or not args.password:
                print("[!] AD discovery requires --domain, --username, and --password")
                sys.exit(1)
            print(f"[+] Discovering Active Directory assets in {args.domain}")
            start_time = time.time()
            ad_scanner = ADDiscovery(args.domain, args.username, args.password)
            assets = ad_scanner.run()
            elapsed_time = time.time() - start_time
            Reporter.print_results(assets, len(assets), "AD assets")

        # Passive Discovery
        elif args.passive:
            feature = "passive"
            log_file, timestamp = Logger.setup(feature)
            print("[+] Running passive discovery")
            scanner = PassiveDiscovery(iface=args.iface, timeout=args.timeout)
            assets, total_assets = scanner.run()
            elapsed_time = args.timeout

            if assets:
                tagged_assets = Tagger.tag_assets(assets)
                table = [[a["IP"], a["Hostname"], a["OS"], a["Ports"], a["Tag"]] for a in tagged_assets]
                print("\nDiscovered Assets (final report):")
                print(tabulate(table, headers=["IP", "Hostname", "OS", "Ports", "Tag"], tablefmt="grid"))
                print(f"\n[+] {len(tagged_assets)} assets discovered during passive monitoring.")
            else:
                print("\n[!] No assets discovered during passive monitoring.")

        else:
            parser.print_help()
            return

    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

    if elapsed_time:
        print(f"[+] Total execution time: {elapsed_time:.2f} seconds")

    if feature and timestamp:
        print(f"[+] Logs saved at logs/discovr_{feature}_log_{timestamp}.log")

    # Export prompt
    if assets:
        choice = input("\nDo you want to save results? (yes/no): ").strip().lower()
        if choice in ["yes", "y"]:
            format_choice = input("Choose format (csv/json/both): ").strip().lower()
            if format_choice == "csv":
                Exporter.save_results(assets, ["csv"], feature, timestamp)
            elif format_choice == "json":
                Exporter.save_results(assets, ["json"], feature, timestamp)
            elif format_choice == "both":
                Exporter.save_results(assets, ["csv", "json"], feature, timestamp)
            else:
                print("[!] Invalid choice, not saving.")
        else:
            print("[+] Results not saved.")


if __name__ == "__main__":
    main()
