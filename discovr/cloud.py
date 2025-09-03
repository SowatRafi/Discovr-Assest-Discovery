import logging
import boto3
from botocore.exceptions import NoCredentialsError, ProfileNotFound, ClientError

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    azure_available = True
except ImportError:
    azure_available = False


class CloudDiscovery:
    def __init__(self, provider, profile="default", region="us-east-1", subscription=None):
        self.provider = provider
        self.profile = profile
        self.region = region
        self.subscription = subscription

    def run(self):
        if self.provider == "aws":
            return self._discover_aws()
        elif self.provider == "azure":
            return self._discover_azure()
        else:
            logging.error("[!] Unsupported cloud provider. Choose 'aws' or 'azure'.")
            return []

    def _discover_aws(self):
        assets = []
        try:
            session = boto3.session.Session(profile_name=self.profile, region_name=self.region)
            ec2 = session.client("ec2")
            response = ec2.describe_instances()
        except ProfileNotFound:
            logging.error(f"[!] AWS profile '{self.profile}' not found. Run 'aws configure'.")
            return []
        except NoCredentialsError:
            logging.error("[!] No AWS credentials found. Run 'aws configure'.")
            return []
        except ClientError as e:
            logging.error(f"[!] AWS API error: {e}")
            return []
        except Exception as e:
            logging.error(f"[!] AWS discovery failed: {e}")
            return []

        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                private_ip = instance.get("PrivateIpAddress", "N/A")
                public_ip = instance.get("PublicIpAddress", "N/A")
                tags = instance.get("Tags", [])
                name = next((t["Value"] for t in tags if t["Key"] == "Name"), instance.get("InstanceId", "Unknown"))
                os_name = instance.get("PlatformDetails", "Unknown")

                asset = {
                    "IP": public_ip if public_ip != "N/A" else private_ip,
                    "Hostname": name,
                    "OS": os_name,
                    "Ports": "N/A"
                }
                logging.info(f"    [+] AWS Instance: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']}")
                assets.append(asset)
        return assets

    def _discover_azure(self):
        if not azure_available:
            logging.error("[!] Azure SDK not installed. Run: pip install azure-identity azure-mgmt-compute azure-mgmt-network")
            return []

        assets = []
        try:
            credential = DefaultAzureCredential()
            compute_client = ComputeManagementClient(credential, self.subscription)
            network_client = NetworkManagementClient(credential, self.subscription)

            for vm in compute_client.virtual_machines.list_all():
                name = vm.name
                os_type = str(vm.storage_profile.os_disk.os_type) if vm.storage_profile.os_disk.os_type else "Unknown"

                private_ip, public_ip = "N/A", "N/A"
                try:
                    nic_id = vm.network_profile.network_interfaces[0].id
                    nic_name = nic_id.split("/")[-1]
                    rg_name = nic_id.split("/")[4]
                    nic = network_client.network_interfaces.get(rg_name, nic_name)
                    if nic.ip_configurations:
                        private_ip = nic.ip_configurations[0].private_ip_address or "N/A"
                        if nic.ip_configurations[0].public_ip_address:
                            pub_id = nic.ip_configurations[0].public_ip_address.id
                            pub_name = pub_id.split("/")[-1]
                            pub_ip = network_client.public_ip_addresses.get(rg_name, pub_name)
                            public_ip = pub_ip.ip_address or "N/A"
                except Exception as e:
                    logging.error(f"[!] NIC fetch failed for VM {name}: {e}")

                asset = {
                    "IP": public_ip if public_ip != "N/A" else private_ip,
                    "Hostname": name,
                    "OS": os_type,
                    "Ports": "N/A"
                }
                logging.info(f"    [+] Azure VM: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']}")
                assets.append(asset)
        except Exception as e:
            logging.error(f"[!] Azure discovery failed: {e}")

        return assets
