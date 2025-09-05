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
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    Logger.setup()

    assets = []
    total_hosts = 0
    elapsed_time = 0

    try:
        # Network Discovery
        if args.scan_network:
            scanner = NetworkDiscovery(args.scan_network, args.ports)
            assets, total_hosts, elapsed_time = scanner.run()
            Reporter.print_results(assets, total_hosts)

        # Cloud Discovery
        elif args.cloud:
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
            Reporter.print_results(assets, len(assets))

        # Active Directory Discovery
        elif args.ad:
            if not args.domain or not args.username or not args.password:
                print("[!] AD discovery requires --domain, --username, and --password")
                sys.exit(1)
            print(f"[+] Discovering Active Directory assets in {args.domain}")
            start_time = time.time()
            ad_scanner = ADDiscovery(args.domain, args.username, args.password)
            assets = ad_scanner.run()
            elapsed_time = time.time() - start_time
            Reporter.print_results(assets, len(assets))

        # Passive Discovery
        elif args.passive:
            print("[+] Running passive discovery")
            scanner = PassiveDiscovery(iface=args.iface, timeout=args.timeout)
            assets, total_assets = scanner.run()
            elapsed_time = args.timeout

            # Print passive results in the same table format
            if assets:
                from tabulate import tabulate
                table = [[a["IP"], a["Hostname"], a["OS"], a["Ports"]] for a in assets]
                print("\nDiscovered Assets (final report):")
                print(tabulate(table, headers=["IP", "Hostname", "OS", "Ports"], tablefmt="grid"))
                print(f"\n[+] {len(assets)} assets discovered during passive monitoring.")
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

    print(f"[+] Logs saved at logs/discovr_log_{timestamp}.log")

    # Export prompt (common across all modules)
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
