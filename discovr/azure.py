from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient


class AzureDiscovery:
    def __init__(self, subscription_id: str):
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()
        self.network_client = NetworkManagementClient(self.credential, self.subscription_id)

    def run(self):
        assets = []

        # --------------------
        # Resource Groups
        # --------------------
        print("[+] Collecting Resource Groups...")
        resource_client = ResourceManagementClient(self.credential, self.subscription_id)
        for rg in resource_client.resource_groups.list():
            assets.append({
                "Type": "ResourceGroup",
                "Name": rg.name,
                "Location": rg.location,
                "Tags": rg.tags,
            })
            print(f"    [+] RG: {rg.name} | Location: {rg.location}")

        # --------------------
        # Virtual Machines
        # --------------------
        print("[+] Collecting Virtual Machines...")
        compute_client = ComputeManagementClient(self.credential, self.subscription_id)
        for vm in compute_client.virtual_machines.list_all():
            rg_name = vm.id.split("/")[4]
            vm_details = compute_client.virtual_machines.instance_view(rg_name, vm.name)
            os_type = vm.storage_profile.os_disk.os_type if vm.storage_profile else "Unknown"
            power_state = [
                s.code for s in vm_details.statuses if "PowerState" in s.code
            ][0] if vm_details and vm_details.statuses else "Unknown"

            nic_info = {}
            open_ports = set()
            nsg_name = None

            if vm.network_profile and vm.network_profile.network_interfaces:
                for nic_ref in vm.network_profile.network_interfaces:
                    nic_name = nic_ref.id.split("/")[-1]
                    nic = self.network_client.network_interfaces.get(rg_name, nic_name)
                    private_ip = None
                    public_ip = None
                    subnet_name = None
                    vnet_name = None

                    if nic.ip_configurations:
                        ipconf = nic.ip_configurations[0]
                        private_ip = ipconf.private_ip_address
                        if ipconf.public_ip_address:
                            pub_id = ipconf.public_ip_address.id
                            pub_name = pub_id.split("/")[-1]
                            pub_rg = pub_id.split("/")[4]
                            pub_ip_obj = self.network_client.public_ip_addresses.get(pub_rg, pub_name)
                            public_ip = pub_ip_obj.ip_address
                        if ipconf.subnet:
                            subnet_name = ipconf.subnet.id.split("/")[-1]
                            vnet_name = ipconf.subnet.id.split("/")[8]

                        if nic.network_security_group:
                            nsg_name = nic.network_security_group.id.split("/")[-1]
                            nsg_rg = nic.network_security_group.id.split("/")[4]
                            nsg = self.network_client.network_security_groups.get(nsg_rg, nsg_name)
                            for rule in nsg.security_rules:
                                if rule.direction.lower() == "inbound" and rule.access.lower() == "allow":
                                    if rule.destination_port_range:
                                        open_ports.add(str(rule.destination_port_range))

                    nic_info = {
                        "NIC": nic_name,
                        "PrivateIP": private_ip,
                        "PublicIP": public_ip,
                        "VNet": vnet_name,
                        "Subnet": subnet_name,
                    }

            assets.append({
                "Type": "VirtualMachine",
                "Name": vm.name,
                "ResourceGroup": rg_name,
                "Location": vm.location,
                "OS": os_type,
                "Size": vm.hardware_profile.vm_size if vm.hardware_profile else "Unknown",
                "PowerState": power_state,
                "Disks": {
                    "OSDisk": vm.storage_profile.os_disk.name if vm.storage_profile and vm.storage_profile.os_disk else None,
                    "DataDisks": len(vm.storage_profile.data_disks) if vm.storage_profile else 0,
                },
                "Networking": nic_info,
                "NSG": nsg_name,
                "OpenPorts": sorted(list(open_ports)),
                "Tags": vm.tags,
            })

            print(
                f"    [+] VM: {vm.name} | OS: {os_type} | Size: {vm.hardware_profile.vm_size} "
                f"| PrivateIP: {nic_info.get('PrivateIP')} | PublicIP: {nic_info.get('PublicIP')} "
                f"| OpenPorts: {','.join(open_ports) if open_ports else 'None'}"
            )

        # --------------------
        # Virtual Networks
        # --------------------
        print("[+] Collecting Virtual Networks...")
        for vnet in self.network_client.virtual_networks.list_all():
            rg_name = vnet.id.split("/")[4]
            subnets = [subnet.name for subnet in vnet.subnets] if vnet.subnets else []
            assets.append({
                "Type": "VirtualNetwork",
                "Name": vnet.name,
                "ResourceGroup": rg_name,
                "Location": vnet.location,
                "AddressSpace": vnet.address_space.address_prefixes,
                "Subnets": subnets,
                "DNS": vnet.dhcp_options.dns_servers if vnet.dhcp_options else [],
            })
            print(f"    [+] VNet: {vnet.name} | Subnets: {subnets}")

        # --------------------
        # Network Security Groups
        # --------------------
        print("[+] Collecting Network Security Groups...")
        for nsg in self.network_client.network_security_groups.list_all():
            rg_name = nsg.id.split("/")[4]
            rules = []
            for rule in nsg.security_rules:
                rules.append({
                    "Name": rule.name,
                    "Priority": rule.priority,
                    "Direction": rule.direction,
                    "Access": rule.access,
                    "Protocol": rule.protocol,
                    "Source": rule.source_address_prefix,
                    "Destination": rule.destination_address_prefix,
                    "Ports": rule.destination_port_range,
                })

            assets.append({
                "Type": "NetworkSecurityGroup",
                "Name": nsg.name,
                "ResourceGroup": rg_name,
                "Location": nsg.location,
                "SecurityRules": rules,
                "AssociatedSubnets": [s.id.split("/")[-1] for s in nsg.subnets] if nsg.subnets else [],
                "AssociatedNICs": [nic.id.split("/")[-1] for nic in nsg.network_interfaces] if nsg.network_interfaces else [],
            })
            print(f"    [+] NSG: {nsg.name} | Group: {rg_name} | Rules: {len(rules)}")

        return assets
