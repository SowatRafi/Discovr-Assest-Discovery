import argparse
import sys
import time
import ipaddress
import platform
import os
import ctypes
import warnings
import logging

warnings.filterwarnings("ignore")
logging.getLogger("azure").setLevel(logging.WARNING)
logging.getLogger("azure.identity").setLevel(logging.WARNING)
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if platform.system() == "Windows":
    import msvcrt

from discovr.core import Logger, Exporter, Reporter
from discovr.network import NetworkDiscovery
from discovr.cloud import CloudDiscovery
from discovr.active_directory import ADDiscovery
from discovr.passive import PassiveDiscovery


def is_admin_windows():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def detect_local_subnet():
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


def handle_export(assets, feature, timestamp, args, provider=None):
    if not assets:
        return
    system = platform.system()
    if system in ["Linux", "Darwin"]:
        choice = args.save if args.save else "yes"
        fmt = args.format if args.format else "both"
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


def main():
    parser = argparse.ArgumentParser(description="Discovr - Asset Discovery Tool")
    parser.add_argument("--scan-network", help="Network range (CIDR)")
    parser.add_argument("--ports", help="Ports to scan (22,80,443)")
    parser.add_argument("--parallel", type=int, default=1, help="Parallel workers")
    parser.add_argument("--autoipaddr", action="store_true", help="Auto-detect subnet")
    parser.add_argument("--cloud", choices=["aws", "azure", "gcp"], help="Cloud provider")
    parser.add_argument("--subscription", help="Azure subscription ID")
    parser.add_argument("--project", help="GCP project ID")
    parser.add_argument("--zone", help="GCP zone")
    parser.add_argument("--gcp-credentials", help="Path to GCP service account JSON")
    parser.add_argument("--profile", help="AWS profile name", default="default")
    parser.add_argument("--region", help="AWS region (e.g., us-east-1)")
    parser.add_argument("--aws-access-key", help="AWS access key ID")
    parser.add_argument("--aws-secret-key", help="AWS secret access key")
    parser.add_argument("--aws-session-token", help="AWS session token")
    parser.add_argument("--azure-tenant", help="Azure tenant ID")
    parser.add_argument("--azure-client-id", help="Azure client ID")
    parser.add_argument("--azure-client-secret", help="Azure client secret")
    parser.add_argument("--ad", action="store_true", help="Active Directory discovery")
    parser.add_argument("--domain", help="AD domain")
    parser.add_argument("--username", help="AD username")
    parser.add_argument("--password", help="AD password")
    parser.add_argument("--passive", action="store_true", help="Passive discovery")
    parser.add_argument("--iface", help="Network interface")
    parser.add_argument("--timeout", type=int, default=180, help="Passive timeout (seconds)")
    parser.add_argument("--save", choices=["yes", "no"], help="Auto-save results")
    parser.add_argument("--format", choices=["csv", "json", "both"], help="Export format")
    args = parser.parse_args()

    assets, feature, timestamp = [], None, None
    cloud_provider = None

    try:
        if args.autoipaddr:
            feature = "network"
            log_file, timestamp = Logger.setup(feature)
            network = detect_local_subnet()
            print(f"[+] Auto-detected local subnet: {network}")
            scanner = NetworkDiscovery(network, args.ports, args.parallel)
            assets, total_hosts, exec_time = scanner.run()
            print(f"[+] Total execution time: {exec_time:.2f} seconds")
            Reporter.print_results(assets, exec_time, "network scan", feature)

        elif args.scan_network:
            feature = "network"
            log_file, timestamp = Logger.setup(feature)
            scanner = NetworkDiscovery(args.scan_network, args.ports, args.parallel)
            assets, total_hosts, exec_time = scanner.run()
            print(f"[+] Total execution time: {exec_time:.2f} seconds")
            Reporter.print_results(assets, exec_time, "network scan", feature)

        elif args.cloud:
            feature = "cloud"
            cloud_provider = args.cloud
            log_file, timestamp = Logger.setup(feature)
            if args.cloud == "azure":
                from discovr.azure.discovery import AzureDiscovery

                credential, tenant_id, client_id, client_secret = AzureDiscovery.obtain_credential(
                    args.azure_tenant, args.azure_client_id, args.azure_client_secret
                )

                subscription_id = args.subscription
                if not subscription_id:
                    try:
                        from azure.mgmt.resource import SubscriptionClient

                        sub_client = SubscriptionClient(credential)
                        subscriptions = list(sub_client.subscriptions.list())
                    except Exception as exc:
                        print(f"[!] Failed to enumerate Azure subscriptions automatically: {exc}")
                        subscriptions = []

                    if not subscriptions:
                        subscription_id = input("Azure subscription ID: ").strip()
                        if not subscription_id:
                            print("[!] Azure discovery requires a subscription ID.")
                            sys.exit(1)
                    elif len(subscriptions) == 1:
                        subscription_id = subscriptions[0].subscription_id
                        print(f"[+] Using detected subscription {subscription_id}")
                    else:
                        print("[+] Multiple Azure subscriptions detected:")
                        for idx, sub in enumerate(subscriptions, start=1):
                            name = getattr(sub, "display_name", "unknown")
                            print(f"    [{idx}] {name} ({sub.subscription_id})")
                        choice = input(f"Select subscription [1-{len(subscriptions)}] (default 1): ").strip()
                        try:
                            index = int(choice) - 1 if choice else 0
                            if not (0 <= index < len(subscriptions)):
                                raise ValueError
                        except ValueError:
                            index = 0
                        subscription_id = subscriptions[index].subscription_id
                        print(f"[+] Using subscription {subscription_id}")

                print(f"[+] Discovering Azure assets in subscription {subscription_id}")
                scanner = AzureDiscovery(
                    subscription_id=subscription_id,
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret,
                    credential=credential,
                )
                assets = scanner.run()
            elif args.cloud == "gcp":
                if not args.project or not args.zone:
                    print("[!] GCP requires --project and --zone")
                    sys.exit(1)
                print(f"[+] Discovering GCP assets in project {args.project} (zone: {args.zone})")
                scanner = CloudDiscovery(
                    "gcp",
                    project=args.project,
                    zone=args.zone,
                    credentials_file=args.gcp_credentials,
                )
                assets = scanner.run()
            elif args.cloud == "aws":
                profile = args.profile or "default"
                region = args.region
                if region:
                    print(f"[+] Discovering AWS assets (profile: {profile}, region: {region})")
                else:
                    print(f"[+] Discovering AWS assets (profile: {profile})")
                scanner = CloudDiscovery(
                    "aws",
                    profile=profile,
                    region=region,
                    access_key=args.aws_access_key,
                    secret_key=args.aws_secret_key,
                    session_token=args.aws_session_token,
                )
                assets = scanner.run()
            else:
                print(f"[!] Unsupported cloud provider: {args.cloud}")
                sys.exit(1)
            Reporter.print_results(assets, len(assets), "cloud assets", feature, provider=cloud_provider)

        elif args.ad:
            feature = "ad"
            log_file, timestamp = Logger.setup(feature)
            if not (args.domain and args.username and args.password):
                print("[!] AD discovery requires --domain, --username, --password")
                sys.exit(1)
            print(f"[+] Discovering Active Directory assets in {args.domain}")
            scanner = ADDiscovery(args.domain, args.username, args.password)
            assets = scanner.run()
            Reporter.print_results(assets, len(assets), "Active Directory assets", feature)

        elif args.passive:
            feature = "passive"
            log_file, timestamp = Logger.setup(feature)
            print("[+] Running passive discovery")
            scanner = PassiveDiscovery(iface=args.iface, timeout=args.timeout)
            assets, total_assets = scanner.run()
            Reporter.print_results(assets, len(assets), "passive monitoring", feature)

        else:
            parser.print_help()
            return

    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

    if feature and timestamp:
        handle_export(assets, feature, timestamp, args, provider=cloud_provider)


if __name__ == "__main__":
    main()
