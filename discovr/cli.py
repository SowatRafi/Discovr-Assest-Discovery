"""Discovr command line: headless scans for scripts and servers, or the web UI by default.

    discovr                                   open the web interface (also on double-click)
    discovr --scan-network 10.0.0.0/24        active network sweep
    discovr --autoipaddr --intensity gentle   sweep the local subnet, gently
    discovr --ad --domain corp.local --username me@corp.local      (password is prompted)
    discovr --cloud aws|azure|gcp             cloud inventory with runtime credentials
    discovr --passive --iface eth0            listen-only discovery

Heavy optional modules (cloud SDKs, scapy, LDAP) are imported inside their branches so
startup stays fast for everything else.
"""
import argparse
import getpass
import logging
import os
import sys
import time
import warnings

from discovr import __version__
from discovr.core import Exporter, Logger, Reporter, is_elevated

# Third-party libraries are chatty; Discovr prints its own concise progress instead.
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

FORMATS = {"csv": ["csv"], "json": ["json"], "html": ["html"], "both": ["csv", "json"], "all": ["csv", "json", "html"]}
SAVE_PROMPT_SECONDS = 15   # Windows interactive prompt: auto-save after this long

_progress_open = False     # True while a "\r" progress line is waiting for its newline


def print_progress(done, total, stage):
    """Self-updating progress line on stderr (keeps stdout clean for piping).

    Counted stages redraw one line and finish it with a newline at 100%; stages without
    a count (total == 0) print once, so later log lines always start on a fresh line.
    """
    global _progress_open
    if total:
        finished = done >= total
        sys.stderr.write(f"\r[~] {stage}: {done}/{total} ({done * 100 // total}%)" + ("\n" if finished else ""))
        _progress_open = not finished
    else:
        sys.stderr.write(("\n" if _progress_open else "") + f"[~] {stage}...\n")
        _progress_open = False
    sys.stderr.flush()


def build_parser() -> argparse.ArgumentParser:
    """All command-line options (legacy flags kept so existing scripts keep working)."""
    parser = argparse.ArgumentParser(prog="discovr", description="Discovr - asset discovery for networks, "
                                     "Active Directory and cloud. Run without options to open the web interface.")
    parser.add_argument("--version", action="version", version=f"Discovr {__version__}")

    ui = parser.add_argument_group("web interface")
    ui.add_argument("--ui", action="store_true", help="open the web interface (the default with no scan options)")
    ui.add_argument("--port", type=int, default=0, help="web interface port (default: a random free port)")
    ui.add_argument("--no-browser", action="store_true", help="do not open a browser automatically")

    net = parser.add_argument_group("network discovery (no admin rights needed)")
    net.add_argument("--scan-network", metavar="RANGE", help="CIDR, IP or comma-separated list, e.g. 192.168.1.0/24")
    net.add_argument("--autoipaddr", action="store_true", help="scan the local subnet (auto-detected)")
    net.add_argument("--ports", help="only probe these ports, e.g. 22,80,443 or 8000-8100")
    net.add_argument("--intensity", choices=["gentle", "normal", "aggressive"], default="normal",
                     help="load profile (default: normal); use gentle on sensitive networks")
    net.add_argument("--parallel", type=int, metavar="N", help="max probes in flight (overrides --intensity)")
    net.add_argument("--os-detect", action="store_true", help="also fingerprint OS with nmap -O (needs nmap + admin/root)")

    cloud = parser.add_argument_group("cloud discovery (credentials resolved at runtime)")
    cloud.add_argument("--cloud", choices=["aws", "azure", "gcp"], help="cloud provider")
    cloud.add_argument("--profile", help="AWS profile (default: the standard AWS credential chain)")
    cloud.add_argument("--region", default="all", help="AWS region, or 'all' enabled regions (default: all)")
    cloud.add_argument("--subscription", help="Azure subscription ID (default: every enabled subscription)")
    cloud.add_argument("--project", help="GCP project ID (default: from the credentials)")
    cloud.add_argument("--zone", help="GCP zone filter (default: all zones)")
    cloud.add_argument("--gcp-credentials", metavar="KEY.json", help="GCP service-account key file (default: ADC)")

    ad = parser.add_argument_group("Active Directory discovery")
    ad.add_argument("--ad", action="store_true", help="enumerate computer accounts over LDAP")
    ad.add_argument("--domain", help="AD domain, e.g. corp.local")
    ad.add_argument("--username", help="e.g. user@corp.local or CORP\\user")
    ad.add_argument("--password", help="avoid: visible in shell history - omit it to be prompted, "
                                       "or set DISCOVR_AD_PASSWORD")
    ad.add_argument("--dc", help="domain controller host/IP (default: resolve the domain name)")
    ad.add_argument("--ldaps", action="store_true", help="bind over LDAPS/636 (default: StartTLS, else NTLM)")
    ad.add_argument("--ca-file", metavar="PEM", help="domain CA certificate to verify the DC (default: system "
                                                     "trust store; a DC that cannot be verified gets NTLM)")

    passive = parser.add_argument_group("passive discovery (listen only; needs capture rights)")
    passive.add_argument("--passive", action="store_true", help="learn devices from ARP/DHCP/mDNS/NetBIOS traffic")
    passive.add_argument("--iface", help="network interface (asked interactively if omitted)")
    passive.add_argument("--timeout", type=int, default=180, help="listening time in seconds (default: 180)")

    out = parser.add_argument_group("reports")
    out.add_argument("--save", choices=["yes", "no"], help="save results without asking")
    out.add_argument("--format", choices=list(FORMATS), help="report format (default: both = CSV + JSON)")
    out.add_argument("--out", metavar="DIR", help="report folder (default: Documents/discovr_reports) - "
                                                  "e.g. a folder next to the binary on a USB stick")
    return parser


def ask_to_save_windows():
    """Windows console prompt that auto-answers "yes" after 15 s (so unattended runs still save)."""
    import msvcrt

    print("\nDo you want to save results? (yes/no): ", end="", flush=True)
    start, buffer, warned = time.time(), "", set()
    while True:
        remaining = SAVE_PROMPT_SECONDS - int(time.time() - start)
        if msvcrt.kbhit():
            char = msvcrt.getwch()
            if char == "\r":
                print()
                return buffer.strip().lower() in ("yes", "y")
            if char == "\b":
                buffer = buffer[:-1]
                sys.stdout.write("\b \b")
            else:
                buffer += char
                sys.stdout.write(char)
            sys.stdout.flush()
        if remaining <= 0:
            print("\n[!] No response received. Automatically saving results.")
            return True
        if remaining in (10, 5) and remaining not in warned:
            print(f"\n[!] Auto-saving results in {remaining} seconds...", flush=True)
            warned.add(remaining)
        time.sleep(0.1)


def handle_export(assets, feature, timestamp, args):
    """Save reports: --save/--format decide; otherwise Windows asks (with a countdown), others auto-save."""
    if not assets:
        return
    if args.save == "no":
        print("[+] Results not saved.")
        return
    wants_prompt = args.save is None and os.name == "nt" and sys.stdin.isatty()
    if wants_prompt and not ask_to_save_windows():
        print("[+] Results not saved.")
        return
    Exporter.save_results(assets, FORMATS[args.format or "both"], feature, timestamp, args.out)


def selected_feature(args):
    """Which discovery the options ask for ("network", "cloud", "ad", "passive"), or None."""
    choices = (("network", args.autoipaddr or args.scan_network), ("cloud", args.cloud),
               ("ad", args.ad), ("passive", args.passive))
    return next((name for name, chosen in choices if chosen), None)


def run_scan(feature, args):
    """Run one discovery; returns (assets, hosts_scanned, context label for the summary)."""
    if feature == "network":
        from discovr.network import NetworkDiscovery, local_subnet

        target = args.scan_network
        if args.autoipaddr:
            try:
                target = local_subnet()
            except OSError as exc:
                raise RuntimeError(f"Could not detect the local subnet (no network connection?): {exc}")
            print(f"[+] Auto-detected local subnet: {target}")
        scanner = NetworkDiscovery(target, args.ports, args.parallel, args.intensity, args.os_detect)
        assets, scanned, elapsed = scanner.run(on_progress=print_progress)
        print(f"[+] Total execution time: {elapsed:.2f} seconds")
        if args.os_detect and not is_elevated():
            print("[!] nmap OS detection needs Administrator/root; OS names above are port-based guesses.")
        return assets, scanned, "active assets"

    if feature == "cloud":
        from discovr.cloud import CloudDiscovery

        print(f"[+] Discovering {args.cloud.upper()} assets...")
        scanner = CloudDiscovery(args.cloud, profile=args.profile, region=args.region, subscription=args.subscription,
                                 project=args.project, zone=args.zone, credentials_file=args.gcp_credentials)
        assets = scanner.run()
        return assets, len(assets), "cloud assets"

    if feature == "ad":
        from discovr.active_directory import ADDiscovery

        if not (args.domain and args.username):
            raise RuntimeError("AD discovery requires --domain and --username")
        if args.password:
            print("[!] --password is visible in shell history and the process list; omit it to be prompted.")
        # Environment variable or interactive prompt keep the secret off the command line.
        password = args.password or os.environ.get("DISCOVR_AD_PASSWORD") \
            or getpass.getpass(f"Password for {args.username}: ")
        print(f"[+] Discovering Active Directory assets in {args.domain}")
        assets = ADDiscovery(args.domain, args.username, password, dc=args.dc, use_ldaps=args.ldaps,
                             ca_file=args.ca_file).run()
        return assets, len(assets), "AD assets"

    from discovr.passive import PassiveDiscovery

    print("[+] Running passive discovery")
    assets, _ = PassiveDiscovery(iface=args.iface, timeout=args.timeout).run(on_progress=print_progress)
    return assets, len(assets), "passive assets"


def main(argv=None):
    """Parse arguments, run a scan (or the web UI) and save the report."""
    args = build_parser().parse_args(argv)
    feature = selected_feature(args)
    if feature is None:
        # No scan options (or --ui): the local web interface - also what a double-click starts.
        from discovr.server import serve

        serve(port=args.port, open_browser=not args.no_browser)
        return

    try:
        _, timestamp = Logger.setup(feature, args.out)
        assets, scanned, context = run_scan(feature, args)
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Cancelled.\n")
        sys.exit(130)
    except Exception as exc:  # every failure ends as one readable line, not a traceback
        if _progress_open:
            sys.stderr.write("\n")
        print(f"[!] Fatal error: {exc}")
        sys.exit(1)

    Reporter.print_results(assets, scanned, context)
    handle_export(assets, feature, timestamp, args)


if __name__ == "__main__":
    main()
