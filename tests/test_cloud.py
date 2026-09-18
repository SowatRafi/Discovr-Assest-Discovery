"""Tests for AWS and Azure discovery (discovr.aws, discovr.azure) - no cloud access needed."""
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import boto3
import pytest
import requests
from botocore.stub import Stubber

import discovr.azure as azure
from discovr.aws import AWSDiscovery, group_exposure
from discovr.cloud import CloudDiscovery
from discovr.core import enrich

# ----------------------------------------------------------------------------- AWS

WEB_SG = {"GroupId": "sg-1", "GroupName": "web", "IpPermissions": [
    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
    {"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
]}


def test_security_group_exposure():
    assert group_exposure([WEB_SG]) == (["22", "443"], ["443"])
    anything = {"IpPermissions": [{"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}
    assert group_exposure([anything]) == (["*"], ["*"])


def test_aws_run_joins_groups_instances_and_ssm(monkeypatch):
    session = boto3.session.Session(aws_access_key_id="AKIDEXAMPLE", aws_secret_access_key="x",
                                    region_name="eu-west-1")
    clients = {name: session.client(name, region_name="eu-west-1") for name in ("sts", "ec2", "ssm")}
    stubs = {name: Stubber(client) for name, client in clients.items()}
    stubs["sts"].add_response("get_caller_identity", {"Account": "123456789012", "Arn": "arn:aws:iam::1:user/a",
                                                      "UserId": "AIDA"})
    stubs["ec2"].add_response("describe_security_groups", {"SecurityGroups": [WEB_SG]})
    stubs["ssm"].add_response("describe_instance_information", {"InstanceInformationList": [
        {"InstanceId": "i-1", "PingStatus": "Online", "AgentVersion": "3.3.0",
         "PlatformName": "Ubuntu", "PlatformVersion": "22.04"}]})
    stubs["ec2"].add_response("describe_instances", {"Reservations": [{"Instances": [
        {"InstanceId": "i-1", "InstanceType": "t3.micro", "PrivateIpAddress": "10.0.1.5",
         "PublicIpAddress": "54.1.2.3", "PlatformDetails": "Linux/UNIX", "State": {"Name": "running", "Code": 16},
         "SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web"}], "Tags": [{"Key": "Name", "Value": "web01"}],
         "LaunchTime": datetime(2026, 1, 1, tzinfo=timezone.utc), "VpcId": "vpc-1", "SubnetId": "subnet-1"},
        {"InstanceId": "i-2", "PrivateIpAddress": "10.0.1.6", "PlatformDetails": "Windows",
         "State": {"Name": "stopped", "Code": 80}}]}]})
    for stub in stubs.values():
        stub.activate()
    monkeypatch.setattr(session, "client", lambda name, region_name=None: clients[name])

    web, win = enrich(AWSDiscovery(region="eu-west-1", session=session).run())

    assert (web["IP"], web["Hostname"], web["OS"]) == ("10.0.1.5", "web01", "Ubuntu 22.04")  # SSM distro
    assert web["Ports"] == "22,443" and web["ExposedPorts"] == "443" and web["InternetExposed"]
    assert web["VMAgent"] == "SSM 3.3.0 (Online)" and web["AccountID"] == "123456789012"
    assert web["Tag"] == "[Server]" and web["Risk"] == "High"          # public HTTPS, admin ports private
    assert win["Hostname"] == "i-2" and win["VMAgent"] == "Not reporting" and not win["InternetExposed"]
    for stub in stubs.values():
        stub.assert_no_pending_responses()


def test_aws_all_regions_lists_enabled_regions(monkeypatch):
    session = boto3.session.Session(aws_access_key_id="a", aws_secret_access_key="b", region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    with Stubber(ec2) as stub:
        stub.add_response("describe_regions", {"Regions": [{"RegionName": "us-east-1"}, {"RegionName": "ap-south-1"}]})
        monkeypatch.setattr(session, "client", lambda name, region_name=None: ec2)
        assert AWSDiscovery(region="all", session=session)._regions(session) == ["ap-south-1", "us-east-1"]


# ----------------------------------------------------------------------------- Azure

SUB = "00000000-0000-0000-0000-000000000001"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-prod/providers"
VM_ID = f"/subscriptions/{SUB}/resourceGroups/RG-Prod/providers/Microsoft.Compute/virtualMachines/web01"
NIC_ID = f"{RG}/Microsoft.Network/networkInterfaces/web01-nic"
SUBNET_ID = f"{RG}/Microsoft.Network/virtualNetworks/vnet1/subnets/default"
PIP_ID = f"{RG}/Microsoft.Network/publicIPAddresses/web01-ip"


def rule(port, source, access="Allow", protocol="Tcp"):
    """One NSG security rule in ARM JSON shape."""
    return {"properties": {"direction": "Inbound", "access": access, "protocol": protocol,
                           "destinationPortRange": port, "sourceAddressPrefix": source}}


AZURE_LISTS = {
    "vms": [{"id": VM_ID, "name": "web01", "location": "eastus", "tags": {"env": "prod"}, "properties": {
        "hardwareProfile": {"vmSize": "Standard_B2s"}, "osProfile": {"computerName": "WEB01"},
        "storageProfile": {"osDisk": {"osType": "Windows", "name": "web01-os"}, "dataDisks": [{}],
                           "imageReference": {"offer": "WindowsServer", "sku": "2019-Datacenter"}},
        "networkProfile": {"networkInterfaces": [{"id": NIC_ID.upper()}]}}}],  # IDs differ only in case
    "statuses": [{"id": VM_ID, "properties": {"instanceView": {
        "statuses": [{"code": "ProvisioningState/succeeded"}, {"code": "PowerState/running"}],
        "vmAgent": {"vmAgentVersion": "2.7.41491.1102", "statuses": [{"displayStatus": "Ready"}]}}}}],
    "nics": [{"id": NIC_ID, "properties": {"ipConfigurations": [{"properties": {
        "privateIPAddress": "10.1.0.4", "publicIPAddress": {"id": PIP_ID}, "subnet": {"id": SUBNET_ID}}}]}}],
    "public_ips": [{"id": PIP_ID, "properties": {"ipAddress": "20.1.2.3"}}],
    "nsgs": [{"id": f"{RG}/Microsoft.Network/networkSecurityGroups/web-nsg", "name": "web-nsg", "properties": {
        "subnets": [{"id": SUBNET_ID}],
        "securityRules": [rule("3389", "Internet"), rule("443", "10.0.0.0/8"), rule("*", "*", access="Deny"),
                          rule("*", "*", protocol="Icmp")]}}],
}


def test_azure_joins_vm_nic_ip_and_subnet_nsg():
    [vm] = enrich(azure.build_assets(SUB, **AZURE_LISTS))
    assert (vm["IP"], vm["Hostname"], vm["PublicIP"]) == ("10.1.0.4", "WEB01", "20.1.2.3")
    assert vm["OS"] == "Windows (WindowsServer 2019-Datacenter)" and vm["Tag"] == "[Server]"
    assert vm["Ports"] == "443,3389" and vm["ExposedPorts"] == "3389"   # Deny and ICMP rules ignored
    assert vm["PowerState"] == "running" and vm["VMAgent"] == "Azure VM Agent 2.7.41491.1102 (Ready)"
    assert (vm["ResourceGroup"], vm["VNet"], vm["Subnet"], vm["NSG"]) == ("RG-Prod", "vnet1", "default", ["web-nsg"])
    assert vm["Risk"] == "Critical"                                     # RDP open to the internet


class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, payload, status=200):
        self.payload, self.status_code, self.text = payload, status, json.dumps(payload)

    def json(self):
        return self.payload


def test_arm_list_follows_next_link_and_reports_errors(monkeypatch):
    pages = {"https://arm/a": FakeResponse({"value": [1, 2], "nextLink": "https://arm/b"}),
             "https://arm/b": FakeResponse({"value": [3]}),
             "https://arm/denied": FakeResponse({"error": {"message": "AuthorizationFailed"}}, 403)}
    monkeypatch.setattr(requests, "get", lambda url, headers, timeout: pages[url])
    assert azure._arm_list("token", "https://arm/a") == [1, 2, 3]
    with pytest.raises(RuntimeError, match="AuthorizationFailed"):
        azure._arm_list("token", "https://arm/denied")


def test_azure_scans_all_subscriptions_and_survives_one_failure(monkeypatch):
    def fake_list(token, url):
        """Route ARM URLs to canned data; the second subscription is forbidden."""
        if "/subscriptions?" in url:
            return [{"subscriptionId": SUB, "state": "Enabled"}, {"subscriptionId": "bad", "state": "Enabled"},
                    {"subscriptionId": "off", "state": "Disabled"}]
        if "/subscriptions/bad/" in url:
            raise RuntimeError("Azure API 403")
        kind = ("statuses" if "statusOnly" in url else "vms" if "virtualMachines" in url
                else "nics" if "networkInterfaces" in url else "public_ips" if "publicIP" in url else "nsgs")
        return AZURE_LISTS[kind]

    monkeypatch.setattr(azure, "_arm_list", fake_list)
    credential = SimpleNamespace(get_token=lambda scope: SimpleNamespace(token="t"))
    assets = azure.AzureDiscovery(credential=credential).run()
    assert [a["Hostname"] for a in assets] == ["WEB01"]


def test_cloud_dispatcher():
    assert type(CloudDiscovery("aws")).__name__ == "AWSDiscovery"
    assert CloudDiscovery("azure", subscription="s").subscription == "s"
    assert CloudDiscovery("gcp", project="p", zone="z").zone == "z"
    with pytest.raises(ValueError):
        CloudDiscovery("oracle")
