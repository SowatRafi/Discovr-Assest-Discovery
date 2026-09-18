import argparse
import getpass
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
# Cloud, AD and passive modules pull in heavy SDKs (boto3, azure, scapy); they are
# imported inside their branches below so startup stays fast for everything else.


def is_admin_windows():
    """Check if Windows process is running with Administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def detect_local_subnet():
    """Detect the subnet of the interface carrying the default route (psutil based)."""
    from discovr.network import local_subnet

    try:
        return local_subnet()
    except OSError as e:
        print(f"[!] Failed to auto-detect local subnet (no network connection?): {e}")
        sys.exit(1)


def print_progress(done, total, stage):
    """Self-updating progress line on stderr (keeps stdout clean for piping).

    Counted stages redraw one line and finish it with a newline at 100%; stages without
    a count (total == 0) print once. Later log lines therefore always start on a fresh line.
    """
    if total:
        end = "\n" if done >= total else ""
        sys.stderr.write(f"\r[~] {stage}: {done}/{total} ({done * 100 // total}%){end}")
    else:
        sys.stderr.write(f"[~] {stage}...\n")
    sys.stderr.flush()


def run_network_scan(target, args):
    """Run the async network engine with CLI options; returns (assets, hosts_scanned)."""
    scanner = NetworkDiscovery(target, args.ports, args.parallel, args.intensity, args.os_detect)
    assets, total_hosts, elapsed = scanner.run(on_progress=print_progress)
    print(f"[+] Total execution time: {elapsed:.2f} seconds")
    return assets, total_hosts


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


def handle_export(assets, feature, timestamp, args):
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
                Exporter.save_results(assets, ["csv"], feature, timestamp)
            elif fmt == "json":
                Exporter.save_results(assets, ["json"], feature, timestamp)
            else:
                Exporter.save_results(assets, ["csv", "json"], feature, timestamp)
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
                Exporter.save_results(assets, ["csv"], feature, timestamp)
            elif fmt == "json":
                Exporter.save_results(assets, ["json"], feature, timestamp)
            else:
                Exporter.save_results(assets, ["csv", "json"], feature, timestamp)
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
    parser.add_argument("--scan-network", help="Network range (CIDR)")
    parser.add_argument("--ports", help="Only scan these ports, e.g. 22,80,443 or 8000-8100")
    parser.add_argument("--parallel", type=int, help="Max probes in flight (overrides --intensity)")
    parser.add_argument("--intensity", choices=["gentle", "normal", "aggressive"], default="normal",
                        help="Scan speed/load profile (default: normal); use gentle on sensitive networks")
    parser.add_argument("--os-detect", action="store_true",
                        help="Also fingerprint OS with nmap -O (needs nmap + admin/root)")
    parser.add_argument("--autoipaddr", action="store_true", help="Auto-detect subnet")

    # Cloud
    parser.add_argument("--cloud", choices=["aws", "azure", "gcp"], help="Cloud provider")
    parser.add_argument("--subscription", help="Azure subscription ID")
    parser.add_argument("--project", help="GCP project ID")
    parser.add_argument("--zone", help="GCP zone")

    # Active Directory
    parser.add_argument("--ad", action="store_true", help="Active Directory discovery")
    parser.add_argument("--domain", help="AD domain")
    parser.add_argument("--username", help="AD username, e.g. user@corp.local or CORP\\user")
    parser.add_argument("--password", help="AD password (omit to be prompted securely; "
                                           "or set DISCOVR_AD_PASSWORD) - avoid: visible in shell history")
    parser.add_argument("--dc", help="Domain controller host/IP (default: resolve the domain name)")
    parser.add_argument("--ldaps", action="store_true",
                        help="Bind over LDAPS/636 (default: StartTLS, falling back to NTLM)")

    # Passive
    parser.add_argument("--passive", action="store_true", help="Passive discovery")
    parser.add_argument("--iface", help="Network interface")
    parser.add_argument("--timeout", type=int, default=180, help="Passive timeout (seconds)")

    # Export
    parser.add_argument("--save", choices=["yes", "no"], help="Auto-save results")
    parser.add_argument("--format", choices=["csv", "json", "both"], help="Export format")

    args = parser.parse_args()

    assets, feature, timestamp = [], None, None

    try:
        if args.autoipaddr:
            feature = "network"
            log_file, timestamp = Logger.setup(feature)
            network = detect_local_subnet()
            print(f"[+] Auto-detected local subnet: {network}")
            assets, total_hosts = run_network_scan(network, args)
            Reporter.print_results(assets, total_hosts, "active assets")

        elif args.scan_network:
            feature = "network"
            log_file, timestamp = Logger.setup(feature)
            assets, total_hosts = run_network_scan(args.scan_network, args)
            Reporter.print_results(assets, total_hosts, "active assets")

        elif args.cloud:
            from discovr.cloud import CloudDiscovery

            feature = "cloud"
            log_file, timestamp = Logger.setup(feature)
            if args.cloud == "azure":
                print(f"[+] Discovering Azure assets in subscription {args.subscription}")
                scanner = CloudDiscovery("azure", subscription=args.subscription)
                assets = scanner.run()
            elif args.cloud == "gcp":
                if not args.project or not args.zone:
                    print("[!] GCP requires --project and --zone")
                    sys.exit(1)
                print(f"[+] Discovering GCP assets in project {args.project}, zone {args.zone}")
                scanner = CloudDiscovery("gcp", project=args.project, zone=args.zone)
                assets = scanner.run()
            elif args.cloud == "aws":
                print("[!] AWS discovery not yet implemented")
            Reporter.print_results(assets, len(assets), "cloud assets")

        elif args.ad:
            from discovr.active_directory import ADDiscovery

            feature = "ad"
            log_file, timestamp = Logger.setup(feature)
            if not (args.domain and args.username):
                print("[!] AD discovery requires --domain and --username")
                sys.exit(1)
            # Prefer the environment or an interactive prompt: CLI arguments leak into
            # shell history and are visible to other users in the process list.
            password = args.password or os.environ.get("DISCOVR_AD_PASSWORD") \
                or getpass.getpass(f"Password for {args.username}: ")
            print(f"[+] Discovering Active Directory assets in {args.domain}")
            scanner = ADDiscovery(args.domain, args.username, password, dc=args.dc, use_ldaps=args.ldaps)
            assets = scanner.run()
            Reporter.print_results(assets, len(assets), "AD assets")

        elif args.passive:
            from discovr.passive import PassiveDiscovery

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
        handle_export(assets, feature, timestamp, args)


if __name__ == "__main__":
    main()
