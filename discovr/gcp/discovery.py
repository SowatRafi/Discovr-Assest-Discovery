import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    from google.cloud import compute_v1
    from google.auth import default as google_auth_default
    from google.auth.exceptions import DefaultCredentialsError
    from google.oauth2 import service_account
    gcp_available = True
except ImportError:
    gcp_available = False
    google_auth_default = None  # type: ignore
    service_account = None  # type: ignore
    DefaultCredentialsError = Exception  # type: ignore

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class GCPDiscovery:
    def __init__(self, project: str, zone: str, credentials_file: Optional[str] = None):
        self.project = project
        self.zone = zone
        self.credentials_file = credentials_file
        self._credentials = None
        self._client_kwargs: Optional[dict] = None

    def run(self) -> List[Dict[str, Any]]:
        if not gcp_available:
            print("[!] google-cloud-compute library not installed. Run: pip install google-cloud-compute")
            return []

        if not self._prepare_credentials():
            return []

        print(f"[+] Discovering GCP assets in project: {self.project} (zone: {self.zone})")
        assets: List[Dict[str, Any]] = []

        assets.extend(self._discover_instances())
        assets.extend(self._discover_networks())
        assets.extend(self._discover_firewalls())
        assets.extend(self._discover_addresses())
        assets.extend(self._discover_forwarding_rules())
        assets.extend(self._discover_disks())
        assets.extend(self._discover_images())
        return assets

    def _discover_instances(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            client = compute_v1.InstancesClient(**self._client_kwargs)
            request = compute_v1.ListInstancesRequest(project=self.project, zone=self.zone)
            for inst in client.list(request=request):
                ip = "N/A"
                if inst.network_interfaces:
                    iface = inst.network_interfaces[0]
                    if iface.network_i_p:
                        ip = iface.network_i_p
                    if iface.access_configs:
                        ip = iface.access_configs[0].nat_i_p or ip
                os_name = inst.labels.get("os") if inst.labels else "Unknown"
                results.append({
                    "Type": "ComputeInstance",
                    "CloudProvider": "gcp",
                    "Project": self.project,
                    "Name": inst.name,
                    "Hostname": inst.name,
                    "IP": ip,
                    "Zone": inst.zone.split("/")[-1] if inst.zone else self.zone,
                    "MachineType": inst.machine_type.split("/")[-1] if inst.machine_type else "Unknown",
                    "Status": inst.status,
                    "Labels": inst.labels or {},
                })
        except Exception as exc:
            logging.error(f"[!] Failed to enumerate GCP instances: {exc}")
        return results

    def _discover_networks(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            client = compute_v1.NetworksClient(**self._client_kwargs)
            request = compute_v1.ListNetworksRequest(project=self.project)
            for net in client.list(request=request):
                subnets = [s.split("/")[-1] for s in net.subnetworks] if net.subnetworks else []
                results.append({
                    "Type": "VPCNetwork",
                    "CloudProvider": "gcp",
                    "Project": self.project,
                    "Name": net.name,
                    "AutoCreateSubnetworks": net.auto_create_subnetworks,
                    "Subnets": subnets,
                    "RoutingMode": net.routing_config.routing_mode if net.routing_config else "UNKNOWN",
                })
        except Exception as exc:
            logging.error(f"[!] Failed to enumerate GCP networks: {exc}")
        return results

    def _discover_firewalls(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            client = compute_v1.FirewallsClient(**self._client_kwargs)
            request = compute_v1.ListFirewallsRequest(project=self.project)
            for fw in client.list(request=request):
                allowed = [
                    f"allow {rule.ip_protocol}:{','.join(rule.ports) if rule.ports else '*'}"
                    for rule in fw.allowed
                ] if fw.allowed else []
                denied = [
                    f"deny {rule.ip_protocol}:{','.join(rule.ports) if rule.ports else '*'}"
                    for rule in fw.denied
                ] if fw.denied else []
                results.append({
                    "Type": "FirewallRule",
                    "CloudProvider": "gcp",
                    "Project": self.project,
                    "Name": fw.name,
                    "Direction": fw.direction,
                    "Priority": fw.priority,
                    "SourceRanges": list(fw.source_ranges),
                    "TargetTags": list(fw.target_tags),
                    "Allowed": allowed,
                    "Denied": denied,
                })
        except Exception as exc:
            logging.error(f"[!] Failed to enumerate GCP firewalls: {exc}")
        return results

    def _discover_addresses(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        region = "-".join(self.zone.split("-")[:-1]) if "-" in self.zone else self.zone
        try:
            regional_client = compute_v1.AddressesClient(**self._client_kwargs)
            request = compute_v1.ListAddressesRequest(project=self.project, region=region)
            for addr in regional_client.list(request=request):
                results.append({
                    "Type": "RegionalAddress",
                    "CloudProvider": "gcp",
                    "Project": self.project,
                    "Name": addr.name,
                    "Address": addr.address,
                    "Status": addr.status,
                    "AddressType": addr.address_type,
                    "Region": region,
                })
        except Exception as exc:
            logging.error(f"[!] Failed to enumerate regional addresses: {exc}")

        try:
            global_client = compute_v1.GlobalAddressesClient(**self._client_kwargs)
            request = compute_v1.ListGlobalAddressesRequest(project=self.project)
            for addr in global_client.list(request=request):
                results.append({
                    "Type": "GlobalAddress",
                    "CloudProvider": "gcp",
                    "Project": self.project,
                    "Name": addr.name,
                    "Address": addr.address,
                    "Status": addr.status,
                    "AddressType": addr.address_type,
                })
        except Exception as exc:
            logging.error(f"[!] Failed to enumerate global addresses: {exc}")
        return results

    def _discover_forwarding_rules(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        region = "-".join(self.zone.split("-")[:-1]) if "-" in self.zone else self.zone
        try:
            regional_client = compute_v1.ForwardingRulesClient(**self._client_kwargs)
            request = compute_v1.ListForwardingRulesRequest(project=self.project, region=region)
            for rule in regional_client.list(request=request):
                results.append({
                    "Type": "ForwardingRule",
                    "CloudProvider": "gcp",
                    "Project": self.project,
                    "Name": rule.name,
                    "IPAddress": rule.i_p_address,
                    "PortRange": rule.port_range,
                    "Target": rule.target,
                    "Region": region,
                })
        except Exception as exc:
            logging.error(f"[!] Failed to enumerate regional forwarding rules: {exc}")

        try:
            global_client = compute_v1.GlobalForwardingRulesClient(**self._client_kwargs)
            request = compute_v1.ListGlobalForwardingRulesRequest(project=self.project)
            for rule in global_client.list(request=request):
                results.append({
                    "Type": "GlobalForwardingRule",
                    "CloudProvider": "gcp",
                    "Project": self.project,
                    "Name": rule.name,
                    "IPAddress": rule.i_p_address,
                    "PortRange": rule.port_range,
                    "Target": rule.target,
                })
        except Exception as exc:
            logging.error(f"[!] Failed to enumerate global forwarding rules: {exc}")
        return results

    def _discover_disks(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            client = compute_v1.DisksClient(**self._client_kwargs)
            request = compute_v1.ListDisksRequest(project=self.project, zone=self.zone)
            for disk in client.list(request=request):
                disk_type = getattr(disk, "type_", "") or ""
                users = [self._last_segment(u) for u in disk.users]
                results.append(
                    {
                        "Type": "PersistentDisk",
                        "CloudProvider": "gcp",
                        "Project": self.project,
                        "Zone": self.zone,
                        "Name": disk.name,
                        "SizeGb": disk.size_gb,
                        "DiskType": self._last_segment(disk_type),
                        "Status": disk.status,
                        "Users": users,
                    }
                )
        except Exception as exc:
            logging.error(f"[!] Failed to enumerate GCP disks: {exc}")
        return results

    def _discover_images(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            client = compute_v1.ImagesClient(**self._client_kwargs)
            request = compute_v1.ListImagesRequest(project=self.project)
            for image in client.list(request=request):
                results.append(
                    {
                        "Type": "Image",
                        "CloudProvider": "gcp",
                        "Project": self.project,
                        "Name": image.name,
                        "Status": image.status,
                        "DiskSizeGb": image.disk_size_gb,
                        "Family": image.family or "",
                    }
                )
        except Exception as exc:
            logging.error(f"[!] Failed to enumerate GCP images: {exc}")
        return results

    def _prepare_credentials(self) -> bool:
        if self._client_kwargs is not None:
            return True

        credentials = None

        if self.credentials_file:
            cred_path = Path(self.credentials_file)
            if not cred_path.exists():
                logging.error(f"[!] GCP credentials file not found: {self.credentials_file}")
                return False
            if service_account is None:
                logging.error("[!] google-auth package missing. Run: pip install google-auth")
                return False
            try:
                credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_file,
                    scopes=SCOPES,
                )
            except Exception as exc:
                logging.error(f"[!] Failed to load GCP service account credentials: {exc}")
                return False
        else:
            if google_auth_default is None:
                logging.error("[!] google-auth package missing. Run: pip install google-auth")
                return False
            try:
                credentials, detected_project = google_auth_default(scopes=SCOPES)
                if not self.project and detected_project:
                    self.project = detected_project
            except DefaultCredentialsError as exc:  # type: ignore[arg-type]
                logging.error(
                    "[!] Unable to locate GCP Application Default Credentials. Provide a service "
                    "account JSON with --gcp-credentials, set GOOGLE_APPLICATION_CREDENTIALS, or "
                    "run `gcloud auth application-default login`."
                )
                logging.debug(f"GCP credential resolution error: {exc}")
                return False

        self._credentials = credentials
        self._client_kwargs = {"credentials": self._credentials} if self._credentials else {}
        return True

    @staticmethod
    def _last_segment(value: Optional[str]) -> str:
        if not value:
            return ""
        return value.split("/")[-1]
