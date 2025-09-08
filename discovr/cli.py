import argparse
import sys
import time
import warnings
import ipaddress
import platform
import signal
import os
import ctypes

# Suppress Scapy warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)

from discovr.core import Logger, Exporter, Reporter
from discovr.network import NetworkDiscovery
from discovr.cloud import CloudDiscovery
from discovr.active_directory import ADDiscovery
from discovr.passive import PassiveDiscovery
from discovr.gcp import GCPDiscovery
from discovr.tagger import Tagger
from discovr.risk import RiskAssessor
from tabulate import tabulate

try:
    import netifaces
except ImportError:
    print("[!] Please install netifaces: pip install netifaces")
    sys.exit(1)


def detect_local_subnet():
    """Detect local subnet using default gateway interface"""
    try:
        gateways = netifaces.gateways()
        default_iface = gateways['default'][netifaces.AF_INET][1]
        addrs = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
        ip = addrs['addr']
        netmask = addrs['netmask']
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except Exception as e:
        print(f"[!] Failed to auto-detect local subnet: {e}")
        sys.exit(1)


def is_admin_windows():
    """Check if Windows process is running with Administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def show_privilege_hint(system, assets):
    """Give OS-specific privilege hints only if not running elevated"""
    if not assets:
        if system == "Windows" and not is_admin_windows():
            print("[!] No assets discovered. Please try running again as Administrator on Windows for full functionality.")
        elif system in ["Linux", "Darwin"] and os.geteuid() != 0:
            print("[!] No assets discovered. Please try running again with sudo on macOS/Linux for full functionality.")
        return

    if system in ["Linux", "Darwin"] and os.geteuid() != 0:
        print("[!] Please try running again with sudo on macOS/Linux for OS detection and full functionality.")

    if system == "Windows" and not is_admin_windows():
        failed_os = any("Unknown" in str(a.get("OS", "")) for a in assets)
        if failed_os:
            print("[!] Please try running again as Administrator on Windows for OS detection and full functionality.")


def handle_export(assets, feature, timestamp, args):
    """Handle saving results based on OS behavior"""
    if not assets:
        return

    system = platform.system()

    # Linux / macOS behavior
    if system in ["Linux", "Darwin"]:
        if args.save or args.format:
            choice = args.save if args.save else "yes"
            fmt = args.format if args.format else "both"
        else:
            if os.geteuid() != 0:  # only show alert if not sudo
                print("[!] Please run with sudo and use --save and --format")
                print("    ; otherwise, results will be automatically saved in both CSV and JSON formats.")
            choice = "yes"
            fmt = "both"

        if choice in ["yes", "y"]:
            if fmt == "csv":
                Exporter.save_results(assets, ["csv"], feature, timestamp)
            elif fmt == "json":
                Exporter.save_results(assets, ["json"], feature, timestamp)
            else:
                Exporter.save_results(assets, ["csv", "json"], feature, timestamp)
        else:
            print("[+] Results not saved.")
        return

    # Windows behavior
    if system == "Windows":
        def timeout_handler(signum, frame):
            raise TimeoutError

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(15)

        try:
            choice = input("\nDo you want to save results? (yes/no): ").strip().lower()
            signal.alarm(0)
        except TimeoutError:
            print("\n[!] No response after 15 seconds. Automatically saving results in both formats.")
            choice = "yes"
            fmt = "both"
        except EOFError:
            choice = "no"
            fmt = "csv"

        if choice in ["yes", "y"]:
            fmt = args.format if args.format else input("Choose format (csv/json/both): ").strip().lower()
            if fmt == "csv":
                Exporter.save_results(assets, ["csv"], feature, timestamp)
            elif fmt == "json":
                Exporter.save_results(assets, ["json"], feature, timestamp)
            else:
                Exporter.save_results(assets, ["csv", "json"], feature, timestamp)
        else:
            print("[+] Results not saved.")


def main():
    parser = argparse.ArgumentParser(description="Discovr - Asset Discovery Tool")

    # Network
    parser.add_argument("--scan-network", help="Network range, e.g. 192.168.1.0/24")
    parser.add_argument("--ports", help="Ports to scan, e.g. 22,80,443")
    parser.add_argument("--parallel", type=int, default=1, help="Number of parallel workers for network scan (default: 1)")
    parser.add_argument("--autoipaddr", action="store_true", help="Auto-detect local IP and subnet for scanning")

    # Cloud
    parser.add_argument("--cloud", choices=["aws", "azure", "gcp"], help="Cloud provider to scan")
    parser.add_argument("--profile", default="default", help="AWS profile (default: default)")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--subscription", help="Azure subscription ID")
    parser.add_argument("--project", help="GCP project ID for discovery")
    parser.add_argument("--zone", help="GCP zone for discovery (e.g., us-central1-a)")

    # Active Directory
    parser.add_argument("--ad", action="store_true", help="Run Active Directory discovery")
    parser.add_argument("--domain", help="Active Directory domain, e.g. mydomain.local")
    parser.add_argument("--username", help="AD username, e.g. user@mydomain.local")
    parser.add_argument("--password", help="AD password")

    # Passive
    parser.add_argument("--passive", action="store_true", help="Run passive discovery")
    parser.add_argument("--iface", help="Network interface (optional, choose interactively if missing)")
    parser.add_argument("--timeout", type=int, default=180, help="Passive discovery timeout in seconds (default: 180)")

    # Export
    parser.add_argument("--save", choices=["yes", "no"], help="Auto-save results without prompt")
    parser.add_argument("--format", choices=["csv", "json", "both"], help="Export format if saving is enabled")

    args = parser.parse_args()

    assets = []
    total_hosts = 0
    elapsed_time = 0
    feature = None
    timestamp = None

    try:
        if args.autoipaddr:
            feature = "network"
            log_file, timestamp = Logger.setup(feature)
            auto_network = detect_local_subnet()
            print(f"[+] Auto-detected local subnet: {auto_network}")
            start_time = time.time()
            scanner = NetworkDiscovery(auto_network, args.ports, args.parallel)
            assets, total_hosts, _ = scanner.run()
            elapsed_time = time.time() - start_time
            Reporter.print_results(assets, total_hosts, "active assets")

        elif args.scan_network:
            feature = "network"
            log_file, timestamp = Logger.setup(feature)
            start_time = time.time()
            scanner = NetworkDiscovery(args.scan_network, args.ports, args.parallel)
            assets, total_hosts, _ = scanner.run()
            elapsed_time = time.time() - start_time
            Reporter.print_results(assets, total_hosts, "active assets")

        elif args.cloud:
            feature = "cloud"
            log_file, timestamp = Logger.setup(feature)

            if args.cloud == "aws":
                print(f"[+] Discovering AWS assets...")
                scanner = CloudDiscovery(args.cloud, args.profile, args.region, args.subscription)
            elif args.cloud == "azure":
                print(f"[+] Discovering Azure assets...")
                scanner = CloudDiscovery(args.cloud, args.profile, args.region, args.subscription)
            elif args.cloud == "gcp":
                if not args.project or not args.zone:
                    print("[!] GCP discovery requires --project and --zone")
                    sys.exit(1)
                print(f"[+] Discovering GCP assets in project {args.project}, zone {args.zone}")
                scanner = GCPDiscovery(args.project, args.zone)

            start_time = time.time()
            assets = scanner.run()
            elapsed_time = time.time() - start_time
            Reporter.print_results(assets, len(assets), "cloud assets")

        elif args.ad:
            feature = "ad"
            log_file, timestamp = Logger.setup(feature)
            if not args.domain or not args.username or not args.password:
                print("[!] AD discovery requires --domain, --username, and --password")
                sys.exit(1)
            print(f"[+] Discovering Active Directory assets in {args.domain}")
            start_time = time.time()
            scanner = ADDiscovery(args.domain, args.username, args.password)
            assets = scanner.run()
            elapsed_time = time.time() - start_time
            Reporter.print_results(assets, len(assets), "AD assets")

        elif args.passive:
            feature = "passive"
            log_file, timestamp = Logger.setup(feature)
            print("[+] Running passive discovery")
            try:
                scanner = PassiveDiscovery(iface=args.iface, timeout=args.timeout)
                assets, total_assets = scanner.run()
                elapsed_time = args.timeout

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
                    print(f"\n[+] {len(risked_assets)} assets discovered during passive monitoring.")
                else:
                    print("\n[!] No assets discovered during passive monitoring.")
                    show_privilege_hint(platform.system(), assets)

                handle_export(assets, feature, timestamp, args)

            except Exception as e:
                print(f"[!] Fatal error: {e}")
                system = platform.system()
                if system in ["Linux", "Darwin"] and os.geteuid() != 0:
                    print("[!] Passive discovery failed. Please try running again with sudo on macOS/Linux.")
                elif system == "Windows" and not is_admin_windows():
                    print("[!] Passive discovery failed. Please try running again as Administrator on Windows.")
                sys.exit(1)

        else:
            parser.print_help()
            return

    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

    if elapsed_time:
        print(f"[+] Total execution time: {elapsed_time:.2f} seconds")

    if feature and timestamp:
        print(f"[+] Logs saved at Documents/discovr_reports/logs/discovr_{feature}_log_{timestamp}.log")

    if feature in ["network", "cloud", "ad"]:
        system = platform.system()
        show_privilege_hint(system, assets)

    if feature != "passive":
        handle_export(assets, feature, timestamp, args)


if __name__ == "__main__":
    main()
