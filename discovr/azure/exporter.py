import csv
from pathlib import Path


class AzureExporter:
    @staticmethod
    def export(assets, timestamp, csv_dir):
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
