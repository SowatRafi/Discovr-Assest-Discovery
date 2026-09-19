"""GCP discovery: Compute Engine VMs across every zone of a project via the REST API.

google-cloud-compute (plus gRPC and protobuf) was replaced by two paginated REST calls:
one *aggregated* instance list covering all zones - the old code only saw the single
zone it was given - and one VPC firewall list used to work out exposed ports.

Credentials resolve at runtime: a service-account key file chosen in the desktop, or
Application Default Credentials (`gcloud auth application-default login`,
GOOGLE_APPLICATION_CREDENTIALS, or the metadata server on GCP).
"""
import logging

from discovr.tagger import port_sort_key
from discovr.scan import ScanControl

log = logging.getLogger(__name__)

COMPUTE = "https://compute.googleapis.com/compute/v1"
SCOPES = ["https://www.googleapis.com/auth/compute.readonly"]
INTERNET = {"0.0.0.0/0", "::/0"}


def _name(url) -> str:
    """Last path segment of a GCP resource URL ("…/zones/us-central1-a" -> "us-central1-a")."""
    return str(url or "").rstrip("/").rsplit("/", 1)[-1] or "N/A"


def license_os(instance) -> str:
    """OS from the boot disk licence, e.g. "…/licenses/windows-server-2022-dc" -> "Windows Server 2022 Dc"."""
    for disk in instance.get("disks", []):
        if disk.get("boot"):
            if disk.get("licenses"):
                return _name(disk["licenses"][0]).replace("-", " ").title()
            if any(f.get("type") == "WINDOWS" for f in disk.get("guestOsFeatures", [])):
                return "Windows"
    return "Unknown"


def firewall_ports(instance, firewalls) -> tuple:
    """(allowed, internet-exposed) inbound port tokens from VPC firewall rules targeting this VM.

    A rule applies when it is enabled, ingress, on the VM's network, and either targets
    every instance or matches one of the VM's network tags / service accounts.
    Unions Allow rules; Deny rules and priorities are not evaluated.
    """
    networks = {nic.get("network") for nic in instance.get("networkInterfaces", [])}
    tags = set(instance.get("tags", {}).get("items", []))
    accounts = {sa.get("email") for sa in instance.get("serviceAccounts", [])}
    allowed, exposed = set(), set()
    for rule in firewalls:
        if rule.get("disabled") or rule.get("direction", "INGRESS") != "INGRESS" or rule.get("network") not in networks:
            continue
        target_tags, target_accounts = set(rule.get("targetTags", [])), set(rule.get("targetServiceAccounts", []))
        if (target_tags or target_accounts) and not (target_tags & tags or target_accounts & accounts):
            continue
        ranges = rule.get("sourceRanges", [])
        # An ingress rule without any source selector defaults to all IPv4 sources.
        if not ranges and not rule.get("sourceTags") and not rule.get("sourceServiceAccounts"):
            ranges = ["0.0.0.0/0"]
        public = bool(INTERNET & set(ranges))
        for entry in rule.get("allowed", []):
            if entry.get("IPProtocol") not in ("tcp", "udp", "all", "6", "17"):
                continue
            ports = entry.get("ports") or ["*"]  # no port list = every port for that protocol
            allowed.update(ports)
            if public:
                exposed.update(ports)
    return allowed, exposed


def instance_to_asset(instance, project, firewalls) -> dict:
    """Convert one Compute Engine instance into a Discovr asset."""
    nic = (instance.get("networkInterfaces") or [{}])[0]
    private_ip = nic.get("networkIP")
    public = [c["natIP"] for n in instance.get("networkInterfaces", [])
              for c in n.get("accessConfigs", []) if c.get("natIP")]
    public_v6 = [c["externalIpv6"] for n in instance.get("networkInterfaces", [])
                 for c in n.get("ipv6AccessConfigs", []) if c.get("externalIpv6")]
    public_ip = public[0] if public else None
    allowed, exposed = firewall_ports(instance, firewalls)
    zone = _name(instance.get("zone"))
    scheduling = instance.get("scheduling", {})
    return {
        "IP": private_ip or public_ip or "N/A",
        "Hostname": instance.get("hostname") or instance.get("name", "Unknown"),
        "OS": license_os(instance),
        "Ports": ",".join(sorted(allowed, key=port_sort_key)) or "None",
        "ExposedPorts": ",".join(sorted(exposed, key=port_sort_key)) or "None",
        "InternetExposed": bool((public or public_v6) and exposed),
        "ExposureAssessment": "Potential exposure from allow rules; priorities, routing and deny rules not evaluated",
        "Source": "GCP",
        "Cloud": "GCP",
        "ProjectID": project,
        "Zone": zone,
        "Region": zone.rsplit("-", 1)[0],
        "InstanceID": str(instance.get("id", "Unknown")),
        "Name": instance.get("name", "Unknown"),
        "MachineType": _name(instance.get("machineType")),
        "Status": instance.get("status", "Unknown"),
        "Preemptible": bool(scheduling.get("preemptible")) or scheduling.get("provisioningModel") == "SPOT",
        "PublicIP": public_ip or "N/A",
        "PublicIPv6": public_v6,
        "Network": _name(nic.get("network")),
        "Subnet": _name(nic.get("subnetwork")),
        "NetworkTags": instance.get("tags", {}).get("items", []),
        "Labels": instance.get("labels", {}),
        "ServiceAccount": next((sa.get("email") for sa in instance.get("serviceAccounts", [])), "N/A"),
        "Disks": [{"Name": d.get("deviceName"), "SizeGB": d.get("diskSizeGb"), "Boot": d.get("boot", False)}
                  for d in instance.get("disks", [])],
        "ShieldedVM": bool(instance.get("shieldedInstanceConfig", {}).get("enableSecureBoot")),
        "Created": instance.get("creationTimestamp", "Unknown"),
    }


def _gcp_list(session, url, aggregated=False, control=None, on_items=None) -> list:
    """GET a Compute API collection, following nextPageToken; flattens aggregated (per-zone) lists."""
    control = control or ScanControl()
    params, items, tokens = {"maxResults": 500}, [], set()
    if aggregated:
        params["returnPartialSuccess"] = "true"  # one unreachable zone must not fail the whole list
    while True:
        control.check()
        import requests
        try:
            resp = session.get(url, params=params, timeout=(5, 15))
        except requests.RequestException as exc:
            raise RuntimeError(f"GCP request failed: {exc.__class__.__name__}") from exc
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("error", {}).get("message") or resp.text[:200]
            except ValueError:
                detail = resp.text[:200]
            raise RuntimeError(f"GCP API {resp.status_code} on {url}: {detail}")
        data = resp.json()
        if aggregated:
            for block in data.get("items", {}).values():
                if block.get("warning", {}).get("code") not in (None, "NO_RESULTS_ON_PAGE"):
                    control.warn(f"GCP returned partial results: {block['warning'].get('message', 'zone unavailable')}")
                items.extend(block.get("instances", []))
                if on_items:
                    on_items(block.get("instances", []))
        else:
            items.extend(data.get("items", []))
        if not data.get("nextPageToken"):
            return items
        if data["nextPageToken"] in tokens:
            raise RuntimeError("GCP returned a repeated pagination token")
        tokens.add(data["nextPageToken"])
        params["pageToken"] = data["nextPageToken"]


class GCPDiscovery:
    """Lists Compute Engine VMs in a project (all zones, or only the chosen zone)."""

    def __init__(self, project=None, zone=None, credentials_file=None):
        """
        :param project: project ID (default: the one attached to the credentials / gcloud config)
        :param zone: optional zone filter, e.g. "us-central1-a"
        :param credentials_file: optional service-account JSON key path
        """
        self.project = project
        self.zone = zone
        self.credentials_file = credentials_file

    def _session(self):
        """Authorised HTTP session plus the credentials' default project; validates credentials early."""
        import google.auth
        from google.auth.exceptions import DefaultCredentialsError, RefreshError
        from google.auth.transport.requests import AuthorizedSession, Request

        try:
            if self.credentials_file:
                from google.oauth2 import service_account

                creds = service_account.Credentials.from_service_account_file(self.credentials_file, scopes=SCOPES)
                default_project = creds.project_id
            else:
                creds, default_project = google.auth.default(scopes=SCOPES)
            creds.refresh(Request())  # fail fast with a clear message instead of on the first list call
        except (DefaultCredentialsError, FileNotFoundError, ValueError) as exc:
            raise RuntimeError("No usable GCP credentials. Choose a valid service-account JSON key in the "
                               "Google Cloud form, or use existing application-default credentials. "
                               "The account needs Compute Viewer access.") from exc
        except RefreshError as exc:
            raise RuntimeError(f"GCP authentication failed: {exc}")
        return AuthorizedSession(creds), default_project

    def run(self, on_progress=None, on_asset=None, cancel=None):
        """Return VM assets for the project; raises on credential or API errors."""
        control = ScanControl(on_progress, on_asset, cancel)
        self.warnings = control.warnings
        control.progress(0, 0, "Authenticating with GCP")
        session, default_project = self._session()
        try:
            return self._scan_project(session, default_project, control)
        finally:
            session.close()

    def _scan_project(self, session, default_project, control):
        """Read project inventory; the caller owns and closes the authorised session."""
        project = self.project or default_project
        if not project:
            raise RuntimeError("No GCP project given. Enter a Project ID in the GCP form, "
                               "or choose a service-account key file that includes its project.")
        control.progress(0, 0, "Listing GCP instances")
        def discovered(instances):
            for instance in instances:
                if not self.zone or _name(instance.get("zone")) == self.zone:
                    asset = instance_to_asset(instance, project, [])
                    asset.update(Ports="Unknown", ExposedPorts="Unknown", InternetExposed=None,
                                 ExposureAssessment="Unknown: firewall metadata pending")
                    control.emit(asset)

        instances = _gcp_list(session, f"{COMPUTE}/projects/{project}/aggregated/instances", aggregated=True,
                              control=control, on_items=discovered)
        if self.zone:
            instances = [i for i in instances if _name(i.get("zone")) == self.zone]
        unavailable = False
        try:
            firewalls = _gcp_list(session, f"{COMPUTE}/projects/{project}/global/firewalls", control=control)
        except RuntimeError as exc:  # exposure is context; missing permission must not hide the VMs
            control.warn(f"Firewall rules unavailable ({exc}); exposure is unknown")
            firewalls = []
            unavailable = True
        assets = [instance_to_asset(i, project, firewalls) for i in instances]
        for a in assets:
            if unavailable:
                a.update(Ports="Unknown", ExposedPorts="Unknown", InternetExposed=None,
                         ExposureAssessment="Unknown: firewall rules unavailable")
            control.emit(a)
            log.info(f"    [+] GCP {a['Zone']}: {a['IP']} ({a['Hostname']}) | OS: {a['OS']} | {a['Status']}")
        return assets
