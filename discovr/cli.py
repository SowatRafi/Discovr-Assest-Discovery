import argparse
import sys
import time
import ipaddress
import platform
import os
import ctypes
import warnings
import logging

# --------------------------
# Suppress noisy warnings/logs
# --------------------------
warnings.filterwarnings("ignore")
logging.getLogger("azure").setLevel(logging.WARNING)
logging.getLogger("azure.identity").setLevel(logging.WARNING)
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Windows-specific for non-blocking input
if platform.system() == "Windows":
    import msvcrt

from discovr.core import Logger, Exporter, Reporter
from discovr.network import NetworkDiscovery
from discovr.cloud import CloudDiscovery
from discovr.active_directory import ADDiscovery
from discovr.passive import PassiveDiscovery
from discovr.gcp import GCPDiscovery


def is_admin_windows():
    """Check if Windows process is running with Administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def detect_local_subnet():
    """Detect local subnet using default gateway interface"""
    try:
        import netifaces
        gateways = netifaces.gateways()
        default_iface = gateways["default"][netifaces.AF_INET][1]
        addrs = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
        ip = addrs["addr"]
        netmask = addrs["netmask"]
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except Exception as e:
        print(f"[!] Failed to auto-detect local subnet: {e}")
        sys.exit(1)


def show_privilege_hint(system, assets):
    """Give OS-specific privilege hints only if not elevated"""
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


def handle_export(assets, feature, timestamp, args, provider=None):
    """Handle saving results across platforms"""
    if not assets:
        return

    system = platform.system()

    # Linux / macOS
    if system in ["Linux", "Darwin"]:
        if args.save or args.format:
            choice = args.save if args.save else "yes"
            fmt = args.format if args.format else "both"
        else:
            if os.geteuid() != 0:
                print("[!] Please run with sudo and use --save and --format")
                print("    ; otherwise, results will be automatically saved in both CSV and JSON formats.")
            choice = "yes"
            fmt = "both"

        if choice in ["yes", "y"]:
            if fmt == "csv":
                Exporter.save_results(assets, ["csv"], feature, timestamp, provider)
            elif fmt == "json":
                Exporter.save_results(assets, ["json"], feature, timestamp, provider)
            else:
                Exporter.save_results(assets, ["csv", "json"], feature, timestamp, provider)
        else:
            print("[+] Results not saved.")
        return

    # Windows
    if system == "Windows":
        if args.save == "no":
            print("[+] Results not saved.")
            return
        elif args.save == "yes":
            fmt = args.format if args.format else "both"
            if fmt == "csv":
                Exporter.save_results(assets, ["csv"], feature, timestamp, provider)
            elif fmt == "json":
                Exporter.save_results(assets, ["json"], feature, timestamp, provider)
            else:
                Exporter.save_results(assets, ["csv", "json"], feature, timestamp, provider)
            return

        # Interactive + timeout
        print("\nDo you want to save results? (yes/no): ", end="", flush=True)
        start = time.time()
        buffer = ""
        warned10, warned5 = False, False

        while True:
            elapsed = time.time() - start
            remaining = 15 - int(elapsed)

            if msvcrt.kbhit():
                char = msvcrt.getwch()
                if char == "\r":  # Enter pressed
                    print()
                    break
                elif char == "\b":
                    buffer = buffer[:-1]
                    sys.stdout.write("\b \b")
                else:
                    buffer += char
                    sys.stdout.write(char)
                    sys.stdout.flush()

            if remaining <= 0:
                print("\n[!] No response received. Automatically saving results in both formats.")
                buffer = "yes"
                break
            elif remaining == 10 and not warned10:
                print(f"\n[!] Auto-saving results in 10 seconds...", flush=True)
                warned10 = True
            elif remaining == 5 and not warned5:
                print(f"\n[!] Auto-saving results in 5 seconds...", flush=True)
                warned5 = True

            time.sleep(0.1)

        choice = buffer.strip().lower()
        if choice in ["yes", "y"]:
            fmt = args.format if args.format else "both"
            if fmt == "csv":
                Exporter.save_results(assets, ["csv"], feature, timestamp, provider)
            elif fmt == "json":
                Exporter.save_results(assets, ["json"], feature, timestamp, provider)
            else:
                Exporter.save_results(assets, ["csv", "json"], feature, timestamp, provider)
        else:
            print("[+] Results not saved.")


def main():
    parser = argparse.ArgumentParser(description="Discovr - Asset Discovery Tool")

    # Network
    parser.add_argument("--scan-network", help="Network range (CIDR)")
    parser.add_argument("--ports", help="Ports to scan (22,80,443)")
    parser.add_argument("--parallel", type=int, default=1, help="Parallel workers")
    parser.add_argument("--autoipaddr", action="store_true", help="Auto-detect subnet")

    # Cloud
    parser.add_argument("--cloud", choices=["aws", "azure", "gcp"], help="Cloud provider")
    parser.add_argument("--profile", default="default", help="AWS profile name")
    parser.add_argument("--region", default="us-east-1", help="Cloud region (e.g. us-east-1)")
    parser.add_argument("--subscription", help="Azure subscription ID")
    parser.add_argument("--project", help="GCP project ID")
    parser.add_argument("--zone", help="GCP zone")
    parser.add_argument(
        "--gcp-credentials",
        help="Path to a GCP Application Default Credentials JSON file",
    )
    parser.add_argument(
        "--gcp-disable-python-protobuf",
        action="store_true",
        help="Opt-out of forcing the pure Python protobuf implementation for GCP discovery",
    )

    # Active Directory
    parser.add_argument("--ad", action="store_true", help="Active Directory discovery")
    parser.add_argument("--domain", help="AD domain")
    parser.add_argument("--username", help="AD username")
    parser.add_argument("--password", help="AD password")

    # Passive
    parser.add_argument("--passive", action="store_true", help="Passive discovery")
    parser.add_argument("--iface", help="Network interface")
    parser.add_argument("--timeout", type=int, default=180, help="Passive timeout (seconds)")

    # Export
    parser.add_argument("--save", choices=["yes", "no"], help="Auto-save results")
    parser.add_argument("--format", choices=["csv", "json", "both"], help="Export format")

    args = parser.parse_args()

    assets, feature, timestamp = [], None, None
    provider = None

    try:
        if args.autoipaddr:
            feature = "network"
            log_file, timestamp = Logger.setup(feature)
            network = detect_local_subnet()
            print(f"[+] Auto-detected local subnet: {network}")
            start = time.time()
            scanner = NetworkDiscovery(network, args.ports, args.parallel)
            assets, total_hosts, _ = scanner.run()
            print(f"[+] Total execution time: {time.time() - start:.2f} seconds")
            Reporter.print_results(assets, total_hosts, "active assets")

        elif args.scan_network:
            feature = "network"
            log_file, timestamp = Logger.setup(feature)
            start = time.time()
            scanner = NetworkDiscovery(args.scan_network, args.ports, args.parallel)
            assets, total_hosts, _ = scanner.run()
            print(f"[+] Total execution time: {time.time() - start:.2f} seconds")
            Reporter.print_results(assets, total_hosts, "active assets")

        elif args.cloud:
            feature = "cloud"
            provider = args.cloud
            log_file, timestamp = Logger.setup(feature)
            if args.cloud == "azure":
                if not args.subscription:
                    print("[!] Azure discovery requires --subscription <id>")
                    sys.exit(1)
                print(f"[+] Discovering Azure assets in subscription {args.subscription}")
                scanner = CloudDiscovery("azure", subscription=args.subscription)
                assets = scanner.run()
            elif args.cloud == "gcp":
                if not args.project or not args.zone:
                    print("[!] GCP requires --project and --zone")
                    sys.exit(1)
                print(f"[+] Discovering GCP assets in project {args.project}, zone {args.zone}")
                scanner = CloudDiscovery(
                    "gcp",
                    project=args.project,
                    zone=args.zone,
                    gcp_credentials=args.gcp_credentials,
                    force_python_proto=not args.gcp_disable_python_protobuf,
                )
                assets = scanner.run()
            elif args.cloud == "aws":
                print(
                    f"[+] Discovering AWS assets in region {args.region} "
                    f"using profile {args.profile}"
                )
                scanner = CloudDiscovery("aws", profile=args.profile, region=args.region)
                assets = scanner.run()
            Reporter.print_results(assets, len(assets), "cloud assets")

        elif args.ad:
            feature = "ad"
            log_file, timestamp = Logger.setup(feature)
            if not (args.domain and args.username and args.password):
                print("[!] AD discovery requires --domain, --username, --password")
                sys.exit(1)
            print(f"[+] Discovering Active Directory assets in {args.domain}")
            scanner = ADDiscovery(args.domain, args.username, args.password)
            assets = scanner.run()
            Reporter.print_results(assets, len(assets), "AD assets")

        elif args.passive:
            feature = "passive"
            log_file, timestamp = Logger.setup(feature)
            print("[+] Running passive discovery")
            scanner = PassiveDiscovery(iface=args.iface, timeout=args.timeout)
            assets, total_assets = scanner.run()
            Reporter.print_results(assets, len(assets), "passive assets")

        else:
            parser.print_help()
            return

    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

    if feature and timestamp:
        handle_export(assets, feature, timestamp, args, provider)


if __name__ == "__main__":
    main()
