import argparse
import sys
import time
from discovr.core import Logger, Exporter, Reporter
from discovr.network import NetworkDiscovery
from discovr.cloud import CloudDiscovery
from discovr.active_directory import ADDiscovery


def main():
    parser = argparse.ArgumentParser(description="Discovr - Asset Discovery Tool")
    parser.add_argument("--scan-network", help="Network range, e.g. 192.168.1.0/24")
    parser.add_argument("--ports", help="Ports to scan, e.g. 22,80,443")
    parser.add_argument("--cloud", choices=["aws", "azure"], help="Cloud provider to scan")
    parser.add_argument("--profile", default="default", help="AWS profile (default: default)")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--subscription", help="Azure subscription ID")
    parser.add_argument("--ad", action="store_true", help="Run Active Directory discovery")
    parser.add_argument("--domain", help="Active Directory domain, e.g. mydomain.local")
    parser.add_argument("--username", help="AD username, e.g. user@mydomain.local")
    parser.add_argument("--password", help="AD password")

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
            Reporter.print_results(assets, total_hosts)

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

        else:
            parser.print_help()
            return
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

    if elapsed_time:
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
