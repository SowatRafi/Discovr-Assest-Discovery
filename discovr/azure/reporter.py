from tabulate import tabulate


class AzureReporter:
    @staticmethod
    def print_summary(groups):
        for rg, items in groups.items():
            rg_info = next((i for i in items if i.get("Type") == "ResourceGroup"), None)
            header_line = "═" * 70
            if rg_info:
                print(f"\n{header_line}\nResource Group: {rg_info.get('Name')} "
                      f"(Location: {rg_info.get('Location')})\nTags: {rg_info.get('Tags')}\n{header_line}")
            else:
                print(f"\n{header_line}\nResource Group: {rg}\n{header_line}")

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
            print(f"Summary for Resource Group '{rg}':")
            print(f"- {vm_count} Virtual Machines ({high_risk_vms} High/Critical Risk)")
            print(f"- {vnet_count} Virtual Networks")
            print(f"- {nsg_count} Network Security Groups ({high_risk_nsgs} High/Critical Risk)")
            print("-" * 70)
