"""Azure discovery: virtual machines across one or all subscriptions via the ARM REST API.

The azure-mgmt-* SDKs were replaced by plain REST calls: they are hundreds of MB
installed, slow to import, and bloated the portable binary. Each subscription now costs
five paginated list calls (VMs, VM run-time status, NICs, public IPs, NSGs) joined in
memory - the previous code made 3-4 extra calls *per VM*, so big subscriptions crawled.

Kept from the original deep-Azure work: power state, VM agent detection (can a security
agent be pushed as a VM extension?), NIC/VNet/subnet details and NSG-derived open ports.

Authentication is azure-identity's DefaultAzureCredential, resolved at runtime:
`az login`, AZURE_CLIENT_ID/AZURE_TENANT_ID/AZURE_CLIENT_SECRET, managed identity, ...
"""
import logging
from concurrent.futures import ThreadPoolExecutor

from discovr.tagger import port_sort_key

log = logging.getLogger(__name__)

ARM = "https://management.azure.com"
COMPUTE_API = "2024-07-01"
NETWORK_API = "2024-05-01"
INTERNET_SOURCES = {"*", "internet", "any", "0.0.0.0/0", "::/0"}


def _key(resource_id) -> str:
    """Azure resource IDs are case-insensitive; normalise them before joining on them."""
    return str(resource_id or "").lower()


def _name(resource_id) -> str:
    """Last segment of a resource ID ("/.../networkInterfaces/nic1" -> "nic1")."""
    return str(resource_id or "").rstrip("/").rsplit("/", 1)[-1] or "N/A"


def _segment(resource_id, key) -> str:
    """Segment following ``key`` in a resource ID, e.g. the resource group name."""
    parts = str(resource_id or "").split("/")
    lowered = [p.lower() for p in parts]
    return parts[lowered.index(key.lower()) + 1] if key.lower() in lowered[:-1] else "N/A"


def nsg_ports(nsg) -> tuple:
    """(allowed, internet-exposed) inbound TCP/UDP port tokens from an NSG's custom rules.

    ponytail: unions Allow rules and ignores Deny rules and priorities, so exposure can be
    over-reported (the safe direction for triage). Upgrade: evaluate rules in priority order.
    """
    allowed, exposed = set(), set()
    for rule in nsg.get("properties", {}).get("securityRules", []):
        p = rule.get("properties", {})
        if p.get("direction") != "Inbound" or p.get("access") != "Allow":
            continue
        if str(p.get("protocol", "*")).lower() not in ("tcp", "udp", "*"):
            continue  # ICMP rules say "*" for ports but open no TCP/UDP service
        ports = [p["destinationPortRange"]] if p.get("destinationPortRange") else p.get("destinationPortRanges", [])
        sources = [p["sourceAddressPrefix"]] if p.get("sourceAddressPrefix") else p.get("sourceAddressPrefixes", [])
        allowed.update(ports)
        if any(str(s).lower() in INTERNET_SOURCES for s in sources):
            exposed.update(ports)
    return allowed, exposed


def _os_name(props, view) -> str:
    """Most precise OS string available: agent-reported name, else image, else disk OS type."""
    if view.get("osName"):
        return f"{view['osName']} {view.get('osVersion', '')}".strip()
    storage = props.get("storageProfile", {})
    os_type = storage.get("osDisk", {}).get("osType", "Unknown")
    image = storage.get("imageReference", {})
    return f"{os_type} ({image['offer']} {image.get('sku', '')})".strip() if image.get("offer") else os_type


def build_assets(subscription, vms, statuses, nics, public_ips, nsgs) -> list:
    """Join one subscription's list results into VM assets (pure function - no network)."""
    view_by_vm = {_key(s["id"]): s.get("properties", {}).get("instanceView", {}) for s in statuses}
    nic_by_id = {_key(n["id"]): n for n in nics}
    pip_by_id = {_key(p["id"]): p for p in public_ips}
    nsg_by_target = {}  # an NSG may be attached to a NIC, a subnet, or both
    for nsg in nsgs:
        for ref in nsg.get("properties", {}).get("networkInterfaces", []) + nsg.get("properties", {}).get("subnets", []):
            nsg_by_target[_key(ref.get("id"))] = nsg

    assets = []
    for vm in vms:
        props = vm.get("properties", {})
        view = view_by_vm.get(_key(vm["id"]), {})
        private_ips, public, vnet, subnet, nsg_names = [], [], "N/A", "N/A", set()
        allowed, exposed = set(), set()
        for ref in props.get("networkProfile", {}).get("networkInterfaces", []):
            nic = nic_by_id.get(_key(ref.get("id")), {})
            attached = [nsg_by_target.get(_key(nic.get("id")))]
            for ipconf in nic.get("properties", {}).get("ipConfigurations", []):
                ip_props = ipconf.get("properties", {})
                if ip_props.get("privateIPAddress"):
                    private_ips.append(ip_props["privateIPAddress"])
                pip = pip_by_id.get(_key(ip_props.get("publicIPAddress", {}).get("id")), {})
                if pip.get("properties", {}).get("ipAddress"):
                    public.append(pip["properties"]["ipAddress"])
                subnet_id = ip_props.get("subnet", {}).get("id")
                if subnet_id:
                    vnet, subnet = _segment(subnet_id, "virtualNetworks"), _name(subnet_id)
                    attached.append(nsg_by_target.get(_key(subnet_id)))
            for nsg in filter(None, attached):
                nsg_allowed, nsg_exposed = nsg_ports(nsg)
                allowed |= nsg_allowed
                exposed |= nsg_exposed
                nsg_names.add(nsg.get("name", "N/A"))

        power = next((s["code"].split("/", 1)[1] for s in view.get("statuses", [])
                      if str(s.get("code", "")).startswith("PowerState/")), "Unknown")
        agent = view.get("vmAgent", {})
        agent_state = (agent.get("statuses") or [{}])[0].get("displayStatus", "Unknown")
        storage = props.get("storageProfile", {})
        asset = {
            "IP": private_ips[0] if private_ips else (public[0] if public else "N/A"),
            "Hostname": props.get("osProfile", {}).get("computerName") or vm.get("name", "Unknown"),
            "OS": _os_name(props, view),
            "Ports": ",".join(sorted(allowed, key=port_sort_key)) or "None",
            "ExposedPorts": ",".join(sorted(exposed, key=port_sort_key)) or "None",
            "InternetExposed": bool(public and exposed),
            "Source": "Azure",
            "Cloud": "Azure",
            "SubscriptionID": subscription,
            "ResourceGroup": _segment(vm["id"], "resourceGroups"),
            "Location": vm.get("location", "Unknown"),
            "InstanceID": vm["id"],
            "Name": vm.get("name", "Unknown"),
            "Size": props.get("hardwareProfile", {}).get("vmSize", "Unknown"),
            "PowerState": power,
            # A running VM agent means a security agent can be deployed as a VM extension.
            "VMAgent": f"Azure VM Agent {agent['vmAgentVersion']} ({agent_state})"
                       if agent.get("vmAgentVersion") else "Not reporting",
            "PublicIP": ", ".join(public) or "N/A",
            "PrivateIPs": private_ips,
            "VNet": vnet,
            "Subnet": subnet,
            "NSG": sorted(nsg_names),
            "Disks": {"OSDisk": storage.get("osDisk", {}).get("name"), "DataDisks": len(storage.get("dataDisks", []))},
            "Tags": vm.get("tags") or {},
        }
        assets.append(asset)
    return assets


def _arm_list(token, url) -> list:
    """GET an ARM collection, following nextLink pagination; raises RuntimeError on API errors."""
    import requests

    items = []
    while url:
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=60)
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("error", {}).get("message") or resp.text[:200]
            except ValueError:
                detail = resp.text[:200]
            raise RuntimeError(f"Azure API {resp.status_code} on {url.split('?')[0]}: {detail}")
        data = resp.json()
        items.extend(data.get("value", []))
        url = data.get("nextLink")
    return items


class AzureDiscovery:
    """Lists virtual machines in one subscription, or in every enabled subscription."""

    def __init__(self, subscription=None, credential=None):
        """
        :param subscription: subscription ID; None scans every subscription the identity can see
        :param credential: optional azure-identity credential (default: DefaultAzureCredential)
        """
        self.subscription = subscription
        self.credential = credential

    def _token(self) -> str:
        """ARM access token from the runtime credential chain."""
        from azure.core.exceptions import ClientAuthenticationError
        from azure.identity import DefaultAzureCredential

        credential = self.credential or DefaultAzureCredential()
        try:
            return credential.get_token(f"{ARM}/.default").token
        except ClientAuthenticationError as exc:
            raise RuntimeError("No usable Azure credentials - run `az login`, or set AZURE_TENANT_ID, "
                               f"AZURE_CLIENT_ID and AZURE_CLIENT_SECRET ({str(exc).splitlines()[0]})")

    @staticmethod
    def _scan_subscription(token, subscription) -> list:
        """The five list calls for one subscription, fetched concurrently, then joined."""
        base = f"{ARM}/subscriptions/{subscription}/providers"
        urls = {
            "vms": f"{base}/Microsoft.Compute/virtualMachines?api-version={COMPUTE_API}",
            "statuses": f"{base}/Microsoft.Compute/virtualMachines?api-version={COMPUTE_API}&statusOnly=true",
            "nics": f"{base}/Microsoft.Network/networkInterfaces?api-version={NETWORK_API}",
            "public_ips": f"{base}/Microsoft.Network/publicIPAddresses?api-version={NETWORK_API}",
            "nsgs": f"{base}/Microsoft.Network/networkSecurityGroups?api-version={NETWORK_API}",
        }
        with ThreadPoolExecutor(max_workers=len(urls)) as pool:
            lists = dict(zip(urls, pool.map(lambda url: _arm_list(token, url), urls.values())))
        return build_assets(subscription, **lists)

    def run(self):
        """Return VM assets; subscriptions that fail are reported, the rest still returned."""
        token = self._token()
        if self.subscription:
            subscriptions = [self.subscription]
        else:
            subscriptions = [s["subscriptionId"] for s in _arm_list(token, f"{ARM}/subscriptions?api-version=2022-12-01")
                             if s.get("state") == "Enabled"]
            if not subscriptions:
                raise RuntimeError("This Azure identity cannot see any enabled subscription")
        log.info(f"[+] Azure: scanning {len(subscriptions)} subscription(s)")

        assets, errors = [], []
        with ThreadPoolExecutor(max_workers=min(8, len(subscriptions))) as pool:
            futures = [(sub, pool.submit(self._scan_subscription, token, sub)) for sub in subscriptions]
            for sub, future in futures:
                try:
                    assets.extend(future.result())
                except RuntimeError as exc:
                    errors.append(str(exc))
                    log.warning(f"[!] Subscription {sub}: {exc}")
        if errors and not assets:
            raise RuntimeError(errors[0])
        for a in assets:
            log.info(f"    [+] Azure VM: {a['IP']} ({a['Hostname']}) | OS: {a['OS']} | {a['PowerState']}")
        return assets
