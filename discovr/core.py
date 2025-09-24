from pathlib import Path
import logging
import csv
import json
from datetime import datetime
from tabulate import tabulate
from discovr.tagger import Tagger
from discovr.risk import RiskAssessor


class Logger:
    @staticmethod
    def setup(feature: str):
        docs_path = Path.home() / "Documents" / "discovr_reports" / "logs"
        docs_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = docs_path / f"discovr_{feature}_log_{timestamp}.log"

        logging.basicConfig(
            filename=str(log_file),
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            force=True,
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
        """
        Save assets in JSON and/or CSV.
        Special case: Azure cloud scan exports 4 optimized CSVs inside azure_<timestamp> folder.
        """
        base_path = Path.home() / "Documents" / "discovr_reports"
        csv_dir = base_path / "csv"
        json_dir = base_path / "json"
        csv_dir.mkdir(parents=True, exist_ok=True)
        json_dir.mkdir(parents=True, exist_ok=True)

        # JSON Export
        if "json" in formats:
            json_file = json_dir / f"discovr_{feature}_{timestamp}.json"
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(assets, f, indent=4, default=str)
            print(f"[+] JSON saved: {json_file}")

        # CSV Export
        if "csv" in formats:
            # Special case: Azure Cloud Scan
            if feature == "cloud":
                azure_dir = csv_dir / f"azure_{timestamp}"
                azure_dir.mkdir(parents=True, exist_ok=True)

                vms = [a for a in assets if a.get("Type") == "VirtualMachine"]
                vnets = [a for a in assets if a.get("Type") == "VirtualNetwork"]
                nsgs = [a for a in assets if a.get("Type") == "NetworkSecurityGroup"]
                rgs = [a for a in assets if a.get("Type") == "ResourceGroup"]

                # VMs CSV
                vm_file = azure_dir / f"azure_vms_{timestamp}.csv"
                with open(vm_file, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "ResourceGroup", "Name", "OS", "Size", "PowerState",
                        "Risk", "OpenPorts", "PrivateIP", "PublicIP",
                        "NIC", "Subnet", "VNet", "AgentCompatible", "AgentVersion", "Tags"
                    ])
                    for vm in vms:
                        net = vm.get("Networking", {})
                        tags = vm.get("Tags") or {}
                        tags_str = ";".join([f"{k}={v}" for k, v in tags.items()]) if isinstance(tags, dict) else ""
                        writer.writerow([
                            vm.get("ResourceGroup", ""),
                            vm.get("Name", ""),
                            vm.get("OS", ""),
                            vm.get("Size", ""),
                            vm.get("PowerState", ""),
                            vm.get("Risk", ""),
                            ";".join(vm.get("OpenPorts", [])) if vm.get("OpenPorts") else "",
                            net.get("PrivateIP", ""),
                            net.get("PublicIP", ""),
                            net.get("NIC", ""),
                            net.get("Subnet", ""),
                            net.get("VNet", ""),
                            "Yes" if vm.get("AgentCompatible") else "No",
                            vm.get("AgentVersion", ""),
                            tags_str,
                        ])
                print(f"[+] Azure VMs CSV saved: {vm_file}")

                # VNets CSV
                vnet_file = azure_dir / f"azure_vnets_{timestamp}.csv"
                with open(vnet_file, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["ResourceGroup", "Name", "AddressSpace", "Subnets", "DNS", "Risk"])
                    for vn in vnets:
                        writer.writerow([
                            vn.get("ResourceGroup", ""),
                            vn.get("Name", ""),
                            ";".join(vn.get("AddressSpace", [])),
                            ";".join(vn.get("Subnets", [])),
                            ";".join(vn.get("DNS", [])) if vn.get("DNS") else "",
                            vn.get("Risk", "Low"),
                        ])
                print(f"[+] Azure VNets CSV saved: {vnet_file}")

                # NSGs CSV
                nsg_file = azure_dir / f"azure_nsgs_{timestamp}.csv"
                with open(nsg_file, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["ResourceGroup", "Name", "Risk", "RuleCount", "RuleSummary", "AssociatedSubnets", "AssociatedNICs"])
                    for n in nsgs:
                        summary = []
                        for rule in n.get("SecurityRules", []):
                            marker = "✅" if rule["Access"].lower() == "allow" else "❌"
                            summary.append(f"{marker} {rule['Name']}({rule['Ports']})")
                        writer.writerow([
                            n.get("ResourceGroup", ""),
                            n.get("Name", ""),
                            n.get("Risk", ""),
                            len(n.get("SecurityRules", [])),
                            "; ".join(summary),
                            ";".join(n.get("AssociatedSubnets", [])),
                            ";".join(n.get("AssociatedNICs", [])),
                        ])
                print(f"[+] Azure NSGs CSV saved: {nsg_file}")

                # Summary CSV
                summary_file = azure_dir / f"azure_summary_{timestamp}.csv"
                with open(summary_file, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["ResourceGroup", "VMCount", "VMHighRisk", "VNetCount", "NSGCount", "NSGHighRisk"])
                    for rg in rgs:
                        rg_name = rg.get("Name", "")
                        rg_vms = [v for v in vms if v.get("ResourceGroup") == rg_name]
                        rg_vnets = [v for v in vnets if v.get("ResourceGroup") == rg_name]
                        rg_nsgs = [n for n in nsgs if n.get("ResourceGroup") == rg_name]
                        high_vms = sum(1 for v in rg_vms if v.get("Risk") in ["High", "Critical"])
                        high_nsgs = sum(1 for n in rg_nsgs if n.get("Risk") in ["High", "Critical"])
                        writer.writerow([
                            rg_name, len(rg_vms), high_vms, len(rg_vnets), len(rg_nsgs), high_nsgs
                        ])
                print(f"[+] Azure Summary CSV saved: {summary_file}")

            else:
                # Default flat CSV for other scans
                csv_file = csv_dir / f"discovr_{feature}_{timestamp}.csv"

                def flatten_dict(d, parent_key="", sep="."):
                    items = []
                    for k, v in d.items():
                        new_key = f"{parent_key}{sep}{k}" if parent_key else k
                        if isinstance(v, dict):
                            items.extend(flatten_dict(v, new_key, sep=sep).items())
                        elif isinstance(v, list):
                            items.append((new_key, ";".join(map(str, v))))
                        else:
                            items.append((new_key, v))
                    return dict(items)

                flat_assets = [flatten_dict(a) for a in assets]

                if flat_assets:
                    headers = sorted({key for a in flat_assets for key in a.keys()})
                    with open(csv_file, "w", newline="", encoding="utf-8") as f:
                        writer = csv.DictWriter(f, fieldnames=headers)
                        writer.writeheader()
                        for a in flat_assets:
                            writer.writerow(a)
                    print(f"[+] CSV saved: {csv_file}")


class Reporter:
    @staticmethod
    def print_results(assets, total_hosts, context="assets"):
        if not assets:
            print("\n[!] No assets discovered.")
            return

        tagged_assets = Tagger.tag_assets(assets)
        risked_assets = RiskAssessor.add_risks(tagged_assets)

        # Normalize RG names
        for a in risked_assets:
            if a.get("ResourceGroup"):
                a["ResourceGroup"] = a["ResourceGroup"].lower()

        groups = {}
        for a in risked_assets:
            rg = a.get("ResourceGroup", a.get("Name", "unknownrg")).lower()
            groups.setdefault(rg, []).append(a)

        for rg, items in groups.items():
            Reporter._print_resource_group(rg, items)

    @staticmethod
    def _print_resource_group(rg_name, items):
        rg_info = next((i for i in items if i.get("Type") == "ResourceGroup"), None)
        header_line = "═" * 70
        if rg_info:
            print(f"\n{header_line}\nResource Group: {rg_info.get('Name')} "
                  f"(Location: {rg_info.get('Location')})\nTags: {rg_info.get('Tags')}\n{header_line}")
        else:
            print(f"\n{header_line}\nResource Group: {rg_name}\n{header_line}")

        vms = [i for i in items if i.get("Type") == "VirtualMachine"]
        if vms:
            print("\nAssociated Virtual Machines")
            print(tabulate(
                [
                    [
                        vm["Name"],
                        vm.get("OS", "Unknown"),
                        vm.get("Size", "Unknown"),
                        vm.get("PowerState", "Unknown"),
                        vm.get("Risk", "Unknown"),
                        ";".join(vm.get("OpenPorts", [])) if vm.get("OpenPorts") else "None",
                        vm.get("Networking", {}).get("PrivateIP", "N/A"),
                        vm.get("Networking", {}).get("PublicIP", "N/A"),
                        vm.get("Networking", {}).get("NIC", "N/A"),
                        f"{vm.get('Networking', {}).get('Subnet','N/A')}/{vm.get('Networking', {}).get('VNet','N/A')}",
                        "Yes" if vm.get("AgentCompatible") else "No",
                        vm.get("AgentVersion", "N/A"),
                        vm.get("Tags", {}),
                    ]
                    for vm in vms
                ],
                headers=["Name", "OS", "Size", "PowerState", "Risk", "OpenPorts",
                         "PrivateIP", "PublicIP", "NIC", "Subnet/VNet", "AgentCompatible", "AgentVersion", "Tags"],
                tablefmt="grid"
            ))

        vnets = [i for i in items if i.get("Type") == "VirtualNetwork"]
        if vnets:
            print("\nAssociated Virtual Networks")
            print(tabulate(
                [
                    [
                        vn["Name"],
                        ";".join(vn.get("AddressSpace", [])),
                        ";".join(vn.get("Subnets", [])),
                        ";".join(vn.get("DNS", [])) if vn.get("DNS") else "-",
                        vn.get("Risk", "Low"),
                    ]
                    for vn in vnets
                ],
                headers=["Name", "Address Space", "Subnets", "DNS", "Risk"],
                tablefmt="grid"
            ))

        nsgs = [i for i in items if i.get("Type") == "NetworkSecurityGroup"]
        if nsgs:
            print("\nAssociated Network Security Groups")
            for n in nsgs:
                print(f"\nNSG: {n['Name']} | Risk: {n.get('Risk', 'Unknown')} | Rules: {len(n.get('SecurityRules', []))}")
                rules_table = [
                    [
                        "✅" if rule["Access"].lower() == "allow" else "❌",
                        rule["Name"],
                        rule["Direction"],
                        rule["Access"],
                        rule["Protocol"],
                        rule["Ports"],
                    ]
                    for rule in n.get("SecurityRules", [])
                ]
                if rules_table:
                    print(tabulate(rules_table,
                                   headers=["", "Rule", "Direction", "Access", "Protocol", "Ports"],
                                   tablefmt="grid"))
                if n.get("AssociatedSubnets"):
                    print(f"Associated Subnets: {', '.join(n['AssociatedSubnets'])}")
                if n.get("AssociatedNICs"):
                    print(f"Associated NICs: {', '.join(n['AssociatedNICs'])}")

        vm_count = len(vms)
        vnet_count = len(vnets)
        nsg_count = len(nsgs)
        high_risk_vms = sum(1 for vm in vms if vm.get("Risk") in ["High", "Critical"])
        high_risk_nsgs = sum(1 for n in nsgs if n.get("Risk") in ["High", "Critical"])
        print("\n" + "-" * 70)
        print(f"Summary for Resource Group '{rg_name}':")
        print(f"- {vm_count} Virtual Machines ({high_risk_vms} High/Critical Risk)")
        print(f"- {vnet_count} Virtual Networks")
        print(f"- {nsg_count} Network Security Groups ({high_risk_nsgs} High/Critical Risk)")
        print("-" * 70)
