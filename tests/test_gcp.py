"""Tests for GCP discovery (discovr.gcp) - pure functions and pagination, no GCP access needed."""
from discovr.core import enrich
from discovr.gcp import _gcp_list, firewall_ports, instance_to_asset, license_os

API = "https://www.googleapis.com/compute/v1/projects/p1"
NETWORK = f"{API}/global/networks/default"

INSTANCE = {
    "id": "123", "name": "web-1", "zone": f"{API}/zones/us-central1-a", "status": "RUNNING",
    "machineType": f"{API}/zones/us-central1-a/machineTypes/e2-medium",
    "networkInterfaces": [{"network": NETWORK, "subnetwork": f"{API}/regions/us-central1/subnetworks/default",
                           "networkIP": "10.128.0.2", "accessConfigs": [{"natIP": "34.1.2.3"}]}],
    "tags": {"items": ["web"]}, "serviceAccounts": [{"email": "sa@p1.iam.gserviceaccount.com"}],
    "disks": [{"boot": True, "deviceName": "boot", "diskSizeGb": "10",
               "licenses": [f"{API}/global/licenses/ubuntu-2204-lts"]}],
    "scheduling": {"provisioningModel": "SPOT"}, "labels": {"env": "dev"},
}
FIREWALLS = [
    {"network": NETWORK, "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
     "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},                                    # all VMs, public
    {"network": NETWORK, "direction": "INGRESS", "sourceRanges": ["10.0.0.0/8"], "targetTags": ["web"],
     "allowed": [{"IPProtocol": "tcp", "ports": ["80", "443"]}]},                             # tag match, private
    {"network": NETWORK, "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"], "targetTags": ["db"],
     "allowed": [{"IPProtocol": "tcp", "ports": ["5432"]}]},                                  # other tag
    {"network": f"{API}/global/networks/other", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "all"}]},
    {"network": NETWORK, "disabled": True, "sourceRanges": ["0.0.0.0/0"],
     "allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}]},
]


def test_firewall_rules_apply_by_network_tag_and_state():
    assert firewall_ports(INSTANCE, FIREWALLS) == ({"22", "80", "443"}, {"22"})


def test_instance_to_asset():
    [vm] = enrich([instance_to_asset(INSTANCE, "p1", FIREWALLS)])
    assert (vm["IP"], vm["PublicIP"], vm["Hostname"]) == ("10.128.0.2", "34.1.2.3", "web-1")
    assert vm["OS"] == "Ubuntu 2204 Lts" and vm["Tag"] == "[Server]"
    assert (vm["Zone"], vm["Region"], vm["MachineType"]) == ("us-central1-a", "us-central1", "e2-medium")
    assert vm["Ports"] == "22,80,443" and vm["ExposedPorts"] == "22" and vm["InternetExposed"]
    assert vm["Preemptible"] and vm["Risk"] == "High"                  # SSH open to the internet


def test_license_os_fallbacks():
    windows = {"disks": [{"boot": True, "guestOsFeatures": [{"type": "WINDOWS"}]}]}
    assert license_os(windows) == "Windows" and license_os({"disks": []}) == "Unknown"
    legacy = {"disks": [{"boot": True, "licenses": [f"{API}/global/licenses/windows-server-2012-r2-dc"]}]}
    assert enrich([{"OS": license_os(legacy), "Cloud": "GCP"}])[0]["Risk"] == "Critical"   # EOL server


class FakeSession:
    """Serves two pages of an aggregated instance list, checking the page token is sent."""

    def get(self, url, params, timeout):
        page_two = params.get("pageToken") == "next"
        payload = {"items": {"zones/b": {"instances": [{"name": "b"}]}}} if page_two else \
            {"items": {"zones/a": {"instances": [{"name": "a"}]}, "zones/empty": {"warning": {}}},
             "nextPageToken": "next"}
        return type("Resp", (), {"status_code": 200, "json": lambda self: payload, "text": ""})()


def test_aggregated_list_pagination():
    assert [i["name"] for i in _gcp_list(FakeSession(), "url", aggregated=True)] == ["a", "b"]
