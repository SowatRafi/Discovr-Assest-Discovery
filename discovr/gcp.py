import logging
import os
from pathlib import Path


class GCPDiscovery:
    def __init__(self, project, zone, credentials_path=None, force_python_proto=True):
        self.project = project
        self.zone = zone
        self.credentials_path = credentials_path
        self.force_python_proto = force_python_proto

    def run(self):
        print(f"[+] Discovering GCP assets in project: {self.project} (zone: {self.zone})")

        env_overrides = {}
        previous_env = {}

        if self.credentials_path:
            creds_path = Path(self.credentials_path).expanduser()
            if not creds_path.exists():
                logging.error(f"[!] Provided GCP credentials file not found: {creds_path}")
                return []
            env_overrides["GOOGLE_APPLICATION_CREDENTIALS"] = str(creds_path)

        if self.force_python_proto:
            env_overrides.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

        assets: list[dict] = []
        try:
            for key, value in env_overrides.items():
                previous_env[key] = os.environ.get(key)
                os.environ[key] = value

            try:
                from google.cloud import compute_v1  # type: ignore import-not-found
            except ImportError:
                print("[!] google-cloud-compute library not installed. Run: pip install google-cloud-compute")
                return []

            collectors = [
                (self._discover_instances, compute_v1),
                (self._discover_disks, compute_v1),
                (self._discover_images, compute_v1),
                (self._discover_networks, compute_v1),
                (self._discover_firewalls, compute_v1),
                (self._discover_addresses, compute_v1),
                (self._discover_forwarding_rules, compute_v1),
            ]

            for collector, arg in collectors:
                try:
                    assets.extend(collector(arg))
                except Exception as exc:
                    logging.error(f"[!] Failed to collect {collector.__name__}: {exc}")

            try:
                assets.extend(self._discover_storage_buckets())
            except Exception as exc:
                logging.error(f"[!] Unexpected storage discovery error: {exc}")

            try:
                assets.extend(self._discover_service_accounts())
            except Exception as exc:
                logging.error(f"[!] Unexpected IAM discovery error: {exc}")
            project_asset = self._discover_project()
            if project_asset:
                assets.append(project_asset)

        except Exception as e:
            logging.error(f"[!] Failed to discover GCP assets: {e}")
            return []
        finally:
            for key in env_overrides.keys():
                previous = previous_env.get(key)
                if previous is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = previous

        return assets

    def _base_asset(self, asset_type: str, name: str | None = None) -> dict:
        return {
            "Type": asset_type,
            "Name": name or "",
            "CloudProvider": "gcp",
            "Hostname": name or "",
            "OS": "Unknown",
            "Ports": "N/A",
        }

    def _region_from_zone(self) -> str:
        return "-".join(self.zone.split("-")[:-1]) if "-" in self.zone else self.zone

    def _discover_instances(self, compute_v1):
        assets = []
        client = compute_v1.InstancesClient()
        request = compute_v1.ListInstancesRequest(project=self.project, zone=self.zone)
        for instance in client.list(request=request):
            ip = None
            if instance.network_interfaces:
                ip = instance.network_interfaces[0].network_i_p

            hostname = instance.name or "Unknown"
            os_name = "Unknown"

            if instance.labels and "os" in instance.labels:
                os_name = instance.labels["os"]

            asset = self._base_asset("ComputeInstance", hostname)
            asset.update(
                {
                    "IP": ip or "N/A",
                    "Zone": instance.zone.split("/")[-1] if instance.zone else self.zone,
                    "MachineType": instance.machine_type.split("/")[-1] if instance.machine_type else "Unknown",
                    "Status": instance.status or "Unknown",
                    "OS": os_name,
                    "Labels": dict(instance.labels) if instance.labels else {},
                    "Tags": list(instance.tags.items) if getattr(instance, "tags", None) and instance.tags.items else [],
                    "CreationTimestamp": instance.creation_timestamp,
                }
            )
            logging.info(f"    [+] GCP Instance: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']}")
            assets.append(asset)
        return assets

    def _discover_disks(self, compute_v1):
        assets = []
        client = compute_v1.DisksClient()
        request = compute_v1.ListDisksRequest(project=self.project, zone=self.zone)
        for disk in client.list(request=request):
            asset = self._base_asset("Disk", disk.name)
            asset.update(
                {
                    "SizeGb": disk.size_gb,
                    "TypeUrl": disk.type_,
                    "Status": disk.status,
                    "Zone": disk.zone.split("/")[-1] if disk.zone else self.zone,
                    "Users": list(disk.users) if disk.users else [],
                    "Encrypted": disk.disk_encryption_key is not None,
                }
            )
            assets.append(asset)
        return assets

    def _discover_images(self, compute_v1):
        assets = []
        client = compute_v1.ImagesClient()
        request = compute_v1.ListImagesRequest(project=self.project)
        for image in client.list(request=request):
            asset = self._base_asset("Image", image.name)
            asset.update(
                {
                    "Status": image.status,
                    "DiskSizeGb": image.disk_size_gb,
                    "SourceType": image.source_type,
                    "Family": image.family or "",
                    "CreationTimestamp": image.creation_timestamp,
                }
            )
            assets.append(asset)
        return assets

    def _discover_networks(self, compute_v1):
        assets = []
        client = compute_v1.NetworksClient()
        request = compute_v1.ListNetworksRequest(project=self.project)
        for network in client.list(request=request):
            asset = self._base_asset("VPCNetwork", network.name)
            asset.update(
                {
                    "AutoCreateSubnetworks": network.auto_create_subnetworks,
                    "Subnets": [sub.split("/")[-1] for sub in network.subnetworks] if network.subnetworks else [],
                    "RoutingMode": network.routing_config.routing_mode if network.routing_config else "Unknown",
                    "Peerings": [p.name for p in network.peerings] if network.peerings else [],
                }
            )
            assets.append(asset)
        return assets

    def _discover_firewalls(self, compute_v1):
        assets = []
        client = compute_v1.FirewallsClient()
        request = compute_v1.ListFirewallsRequest(project=self.project)
        for fw in client.list(request=request):
            allowed = []
            for rule in fw.allowed or []:
                ports = ",".join(rule.ports) if rule.ports else "*"
                protocol = getattr(rule, "IPProtocol", getattr(rule, "ip_protocol", "*"))
                allowed.append(f"allow {protocol}:{ports}")
            denied = []
            for rule in fw.denied or []:
                ports = ",".join(rule.ports) if rule.ports else "*"
                protocol = getattr(rule, "IPProtocol", getattr(rule, "ip_protocol", "*"))
                denied.append(f"deny {protocol}:{ports}")
            asset = self._base_asset("FirewallRule", fw.name)
            asset.update(
                {
                    "Direction": fw.direction,
                    "Priority": fw.priority,
                    "SourceRanges": list(fw.source_ranges) if fw.source_ranges else [],
                    "TargetTags": list(fw.target_tags) if fw.target_tags else [],
                    "Allowed": allowed,
                    "Denied": denied,
                }
            )
            assets.append(asset)
        return assets

    def _discover_addresses(self, compute_v1):
        assets = []
        region = self._region_from_zone()
        regional_client = compute_v1.AddressesClient()
        regional_request = compute_v1.ListAddressesRequest(project=self.project, region=region)
        for address in regional_client.list(request=regional_request):
            asset = self._base_asset("IPAddress", address.name)
            asset.update(
                {
                    "Address": address.address,
                    "AddressType": address.address_type,
                    "Status": address.status,
                    "Region": region,
                }
            )
            assets.append(asset)

        try:
            global_client = compute_v1.GlobalAddressesClient()
            global_request = compute_v1.ListGlobalAddressesRequest(project=self.project)
            for address in global_client.list(request=global_request):
                asset = self._base_asset("GlobalIPAddress", address.name)
                asset.update(
                    {
                        "Address": address.address,
                        "AddressType": address.address_type,
                        "Status": address.status,
                    }
                )
                assets.append(asset)
        except AttributeError:
            logging.warning("[!] Global address enumeration is not supported in this client version.")

        return assets

    def _discover_forwarding_rules(self, compute_v1):
        assets = []
        region = self._region_from_zone()
        regional_client = compute_v1.ForwardingRulesClient()
        regional_request = compute_v1.ListForwardingRulesRequest(project=self.project, region=region)
        for rule in regional_client.list(request=regional_request):
            asset = self._base_asset("ForwardingRule", rule.name)
            asset.update(
                {
                    "IPAddress": rule.i_p_address,
                    "PortRange": rule.port_range,
                    "LoadBalancingScheme": rule.load_balancing_scheme,
                    "Network": rule.network.split("/")[-1] if rule.network else "",
                    "Target": rule.target.split("/")[-1] if rule.target else "",
                    "Region": region,
                }
            )
            assets.append(asset)

        try:
            global_client = compute_v1.GlobalForwardingRulesClient()
            global_request = compute_v1.ListGlobalForwardingRulesRequest(project=self.project)
            for rule in global_client.list(request=global_request):
                asset = self._base_asset("GlobalForwardingRule", rule.name)
                asset.update(
                    {
                        "IPAddress": rule.i_p_address,
                        "PortRange": rule.port_range,
                        "LoadBalancingScheme": rule.load_balancing_scheme,
                        "Target": rule.target.split("/")[-1] if rule.target else "",
                    }
                )
                assets.append(asset)
        except AttributeError:
            logging.warning("[!] Global forwarding rule enumeration is not supported in this client version.")

        return assets

    def _discover_storage_buckets(self):
        try:
            from google.cloud import storage  # type: ignore import-not-found
        except ImportError:
            logging.warning("[!] google-cloud-storage not installed. Skipping Cloud Storage discovery.")
            return []

        assets = []
        try:
            client = storage.Client(project=self.project)
            for bucket in client.list_buckets(project=self.project):
                asset = self._base_asset("StorageBucket", bucket.name)
                asset.update(
                    {
                        "Location": bucket.location,
                        "Class": bucket.storage_class,
                        "Created": bucket.time_created,
                        "Versioning": bucket.versioning_enabled,
                    }
                )
                assets.append(asset)
        except Exception as exc:
            logging.error(f"[!] Failed to list Cloud Storage buckets: {exc}")
        return assets

    def _discover_service_accounts(self):
        try:
            from googleapiclient import discovery  # type: ignore import-not-found
            from googleapiclient.errors import HttpError  # type: ignore import-not-found
        except ImportError:
            logging.warning(
                "[!] google-api-python-client not installed. Skipping IAM service account discovery."
            )
            return []

        assets = []
        try:
            iam = discovery.build("iam", "v1", cache_discovery=False)
            name = f"projects/{self.project}"
            request = iam.projects().serviceAccounts().list(name=name)
            while request is not None:
                response = request.execute()
                for account in response.get("accounts", []):
                    asset = self._base_asset("ServiceAccount", account.get("displayName") or account.get("name"))
                    asset.update(
                        {
                            "Email": account.get("email"),
                            "UniqueId": account.get("uniqueId"),
                            "Disabled": account.get("disabled", False),
                            "ProjectId": account.get("projectId"),
                            "Oauth2ClientId": account.get("oauth2ClientId"),
                        }
                    )
                    assets.append(asset)
                request = iam.projects().serviceAccounts().list_next(
                    previous_request=request, previous_response=response
                )
        except HttpError as http_exc:
            logging.error(f"[!] IAM service account discovery failed: {http_exc}")
        except Exception as exc:
            logging.error(f"[!] Unexpected error during IAM service account discovery: {exc}")

        return assets

    def _discover_project(self):
        try:
            from google.cloud import resourcemanager_v3  # type: ignore import-not-found
        except ImportError:
            logging.warning(
                "[!] google-cloud-resourcemanager not installed. Skipping project metadata discovery."
            )
            return None

        try:
            client = resourcemanager_v3.ProjectsClient()
            project_name = f"projects/{self.project}"
            project = client.get_project(name=project_name)
            asset = self._base_asset("Project", project.display_name or project.project_id)
            asset.update(
                {
                    "ProjectId": project.project_id,
                    "ProjectNumber": project.name.split("/")[-1],
                    "State": project.state.name if project.state else "STATE_UNSPECIFIED",
                    "CreateTime": project.create_time,
                    "Labels": dict(project.labels),
                }
            )
            return asset
        except Exception as exc:
            logging.error(f"[!] Failed to retrieve project metadata: {exc}")
            return None
