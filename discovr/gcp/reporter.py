from collections import defaultdict
from tabulate import tabulate


class GCPReporter:
    @staticmethod
    def print_summary(assets):
        projects = defaultdict(list)
        for asset in assets:
            project = asset.get("Project") or "unknown"
            projects[project].append(asset)

        header = "═" * 70
        for project, items in sorted(projects.items()):
            print(f"\n{header}\nGCP Project: {project}\n{header}")

            instances = [a for a in items if a.get("Type") == "ComputeInstance"]
            if instances:
                print("\nCompute Instances")
                print(
                    tabulate(
                        [
                            [
                                inst.get("Name", ""),
                                inst.get("Zone", ""),
                                inst.get("MachineType", ""),
                                inst.get("Status", ""),
                                inst.get("IP", ""),
                                GCPReporter._format_labels(inst.get("Labels")),
                            ]
                            for inst in instances
                        ],
                        headers=["Name", "Zone", "MachineType", "Status", "IP", "Labels"],
                        tablefmt="grid",
                    )
                )

            networks = [a for a in items if a.get("Type") == "VPCNetwork"]
            if networks:
                print("\nVPC Networks")
                print(
                    tabulate(
                        [
                            [
                                net.get("Name", ""),
                                "Yes" if net.get("AutoCreateSubnetworks") else "No",
                                ",".join(net.get("Subnets", [])),
                                net.get("RoutingMode", ""),
                            ]
                            for net in networks
                        ],
                        headers=["Name", "Auto Subnet", "Subnets", "RoutingMode"],
                        tablefmt="grid",
                    )
                )

            firewalls = [a for a in items if a.get("Type") == "FirewallRule"]
            if firewalls:
                print("\nFirewall Rules")
                print(
                    tabulate(
                        [
                            [
                                fw.get("Name", ""),
                                fw.get("Direction", ""),
                                fw.get("Priority", ""),
                                ";".join(fw.get("Allowed", [])),
                                ";".join(fw.get("Denied", [])),
                                ";".join(fw.get("SourceRanges", [])),
                            ]
                            for fw in firewalls
                        ],
                        headers=["Name", "Direction", "Priority", "Allowed", "Denied", "SourceRanges"],
                        tablefmt="grid",
                    )
                )

            addresses = [a for a in items if a.get("Type") in {"RegionalAddress", "GlobalAddress"}]
            if addresses:
                print("\nReserved Addresses")
                print(
                    tabulate(
                        [
                            [
                                addr.get("Name", ""),
                                "regional" if addr.get("Type") == "RegionalAddress" else "global",
                                addr.get("Address", ""),
                                addr.get("Status", ""),
                                addr.get("AddressType", ""),
                                addr.get("Region", ""),
                            ]
                            for addr in addresses
                        ],
                        headers=["Name", "Scope", "Address", "Status", "AddressType", "Region"],
                        tablefmt="grid",
                    )
                )

            forwarding = [a for a in items if a.get("Type") in {"ForwardingRule", "GlobalForwardingRule"}]
            if forwarding:
                print("\nForwarding Rules")
                print(
                    tabulate(
                        [
                            [
                                rule.get("Name", ""),
                                "regional" if rule.get("Type") == "ForwardingRule" else "global",
                                rule.get("IPAddress", ""),
                                rule.get("PortRange", ""),
                                rule.get("Target", ""),
                                rule.get("Region", ""),
                            ]
                            for rule in forwarding
                        ],
                        headers=["Name", "Scope", "IPAddress", "PortRange", "Target", "Region"],
                        tablefmt="grid",
                    )
                )

            summary = {
                "Instances": len(instances),
                "Networks": len(networks),
                "Firewalls": len(firewalls),
                "Addresses": len(addresses),
                "ForwardingRules": len(forwarding),
            }
            print("\n" + "-" * 70)
            print("Summary:")
            for label, count in summary.items():
                print(f"- {label}: {count}")
            print("-" * 70)

    @staticmethod
    def _format_labels(labels):
        if isinstance(labels, dict):
            return ";".join(f"{k}={v}" for k, v in labels.items())
        return ""
