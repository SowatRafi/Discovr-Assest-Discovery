"""AWS discovery: EC2 instances in one or every enabled region, with firewall exposure.

Per region Discovr makes three paginated list calls (security groups, instances, SSM
agents) and joins them in memory, and all regions run in parallel - so a full-account
sweep costs seconds regardless of instance count.

Credentials are only ever taken from the standard AWS chain at runtime (environment,
`aws configure` profiles, `aws sso login`, instance roles) - never from CLI arguments.
"""
import logging
from concurrent.futures import ThreadPoolExecutor

from discovr.tagger import port_sort_key
from discovr.scan import ScanControl, ScanCancelled

log = logging.getLogger(__name__)

INTERNET = {"0.0.0.0/0", "::/0"}
LIVE_STATES = ["pending", "running", "stopping", "stopped", "shutting-down"]  # skip terminated


def rule_ports(permission) -> str:
    """Port token for one security-group permission: "22", "1000-2000", "*" (any); "" for ICMP."""
    protocol = str(permission.get("IpProtocol"))
    if protocol == "-1":
        return "*"
    if protocol not in ("tcp", "udp", "6", "17"):
        return ""
    low, high = permission.get("FromPort"), permission.get("ToPort")
    return str(low) if low == high else f"{low}-{high}"


def group_exposure(groups) -> tuple:
    """(allowed ports, internet-exposed ports) as sorted token lists for a set of security groups."""
    allowed, exposed = set(), set()
    for group in groups:
        for perm in group.get("IpPermissions", []):
            token = rule_ports(perm)
            if not token:
                continue
            allowed.add(token)
            sources = {r.get("CidrIp") for r in perm.get("IpRanges", [])}
            sources |= {r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])}
            if sources & INTERNET:
                exposed.add(token)
    return sorted(allowed, key=port_sort_key), sorted(exposed, key=port_sort_key)


def instance_to_asset(instance, region, account, groups_by_id, ssm_by_id) -> dict:
    """Convert one EC2 instance (+ its security groups and SSM record) into a Discovr asset."""
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    private_ip = instance.get("PrivateIpAddress")
    public_ip = instance.get("PublicIpAddress")
    public_v6 = [a["Ipv6Address"] for nic in instance.get("NetworkInterfaces", [])
                 for a in nic.get("Ipv6Addresses", []) if a.get("Ipv6Address")]
    groups = [groups_by_id.get(g["GroupId"], {}) for g in instance.get("SecurityGroups", [])]
    allowed, exposed = group_exposure(groups)
    ssm = ssm_by_id.get(instance["InstanceId"], {})
    # SSM reports the real distro ("Ubuntu 22.04"); PlatformDetails only says "Linux/UNIX".
    ssm_os = f"{ssm.get('PlatformName', '')} {ssm.get('PlatformVersion', '')}".strip()
    launched = instance.get("LaunchTime")
    return {
        "IP": private_ip or public_ip or "N/A",
        "Hostname": tags.get("Name") or instance.get("PrivateDnsName") or instance["InstanceId"],
        "OS": ssm_os or instance.get("PlatformDetails") or "Unknown",
        "Ports": ",".join(allowed) or "None",
        "ExposedPorts": ",".join(exposed) or "None",
        "InternetExposed": bool((public_ip or public_v6) and exposed),
        "ExposureAssessment": "Potential exposure from allow rules; routing and deny controls not evaluated",
        "Source": "AWS",
        "Cloud": "AWS",
        "AccountID": account,
        "Region": region,
        "InstanceID": instance["InstanceId"],
        "InstanceType": instance.get("InstanceType", "Unknown"),
        "State": instance.get("State", {}).get("Name", "Unknown"),
        "PublicIP": public_ip or "N/A",
        "PublicIPv6": public_v6,
        "VPC": instance.get("VpcId", "N/A"),
        "Subnet": instance.get("SubnetId", "N/A"),
        "SecurityGroups": [g.get("GroupName", g["GroupId"]) for g in instance.get("SecurityGroups", [])],
        "IAMRole": instance.get("IamInstanceProfile", {}).get("Arn", "N/A"),
        # SSM agent online => a security agent can be pushed with SSM Run Command.
        "VMAgent": f"SSM {ssm.get('AgentVersion', '')} ({ssm.get('PingStatus')})" if ssm else "Not reporting",
        "Tags": tags,
        "Created": launched.isoformat() if hasattr(launched, "isoformat") else str(launched or "Unknown"),
    }


class AWSDiscovery:
    """Lists EC2 instances for the account behind the active AWS credentials."""

    def __init__(self, profile=None, region="all", session=None, runtime_credentials=None):
        """
        :param profile: named profile from ~/.aws/config (default: the standard credential chain)
        :param region: a region name, or "all" for every region enabled on the account
        :param session: pre-built boto3 Session (tests)
        """
        self.profile = profile
        self.region = region or "all"
        self.session = session
        self.runtime_credentials = runtime_credentials or {}
        self.control = ScanControl()
        self.warnings = self.control.warnings

    def _session(self):
        """boto3 session, converting missing-credential errors into actionable messages."""
        import boto3
        from botocore.exceptions import ProfileNotFound

        try:
            if self.session:
                return self.session
            from botocore.config import Config
            credentials = self.runtime_credentials
            if credentials:
                session = boto3.session.Session(aws_access_key_id=credentials["accessKey"],
                                                aws_secret_access_key=credentials["secretKey"],
                                                aws_session_token=credentials.get("sessionToken"))
            else:
                session = boto3.session.Session(profile_name=self.profile or None)
            session._session.set_default_client_config(Config(
                connect_timeout=5, read_timeout=15, retries={"mode": "standard", "total_max_attempts": 2}))
            return session
        except ProfileNotFound:
            raise RuntimeError(f"AWS profile '{self.profile}' was not found. Choose an existing profile, "
                               "or clear Profile and enter an access key and secret in the AWS form.")

    def _regions(self, session):
        """The requested region, or every enabled region (falls back to the default one)."""
        if self.region != "all":
            return [self.region]
        home = session.region_name or "us-east-1"
        try:
            return sorted(r["RegionName"] for r in session.client("ec2", region_name=home).describe_regions()["Regions"])
        except Exception as exc:  # e.g. AccessDenied on ec2:DescribeRegions
            self.control.warn(f"Could not list AWS regions ({exc}); scanning {home} only")
            return [home]

    @staticmethod
    def _scan_region(region, account, ec2, ssm, control=None):
        """Security groups + instances + SSM agents for one region, joined into assets."""
        control = control or ScanControl()
        try:
            groups = {g["GroupId"]: g for page in control.pages(ec2.get_paginator("describe_security_groups").paginate())
                      for g in page["SecurityGroups"]}
        except ScanCancelled:
            raise
        except Exception as exc:
            control.warn(f"{region}: security groups unavailable ({exc.__class__.__name__}); exposure unknown")
            groups = None
        try:
            ssm_by_id = {i["InstanceId"]: i for page in control.pages(ssm.get_paginator("describe_instance_information").paginate())
                         for i in page["InstanceInformationList"]}
        except ScanCancelled:
            raise
        except Exception as exc:  # SSM is optional context; missing permission must not fail the scan
            control.warn(f"{region}: SSM agent status unavailable ({exc.__class__.__name__})")
            ssm_by_id = {}
        pages = ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": LIVE_STATES}])
        assets = []
        for page in control.pages(pages):
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    asset = instance_to_asset(inst, region, account, groups or {}, ssm_by_id)
                    if groups is None:
                        asset.update(Ports="Unknown", ExposedPorts="Unknown", InternetExposed=None,
                                     ExposureAssessment="Unknown: security groups unavailable")
                    assets.append(control.emit(asset))
        return assets

    def run(self, on_progress=None, on_asset=None, cancel=None):
        """Return EC2 assets from every requested region; raises on credential problems."""
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

        self.control = control = ScanControl(on_progress, on_asset, cancel)
        self.warnings = control.warnings
        control.progress(0, 0, "Authenticating with AWS")
        session = self._session()
        try:
            account = session.client("sts", region_name=session.region_name or "us-east-1") \
                .get_caller_identity()["Account"]
        except NoCredentialsError:
            raise RuntimeError("No AWS credentials found. Enter an access key and secret in the AWS form, "
                               "including a session token for temporary credentials, or choose an existing profile.")
        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(f"AWS authentication failed: {exc}")

        regions = self._regions(session)
        if not regions:
            raise RuntimeError("No enabled AWS regions were returned")
        control.check()
        log.info(f"[+] AWS account {account}: scanning {len(regions)} region(s)")
        # boto3 sessions are not thread-safe, so clients are created here, then used in threads.
        clients = {r: (session.client("ec2", region_name=r), session.client("ssm", region_name=r)) for r in regions}
        assets, errors = [], []
        with ThreadPoolExecutor(max_workers=min(16, len(regions))) as pool:
            futures = {r: pool.submit(self._scan_region, r, account, *clients[r], control) for r in regions}
            for done, (region, future) in enumerate(futures.items(), 1):
                try:
                    assets.extend(future.result())
                except (ClientError, BotoCoreError) as exc:  # one broken region must not hide the others
                    errors.append(f"{region}: {exc}")
                    control.warn(f"{region}: {exc}")
                control.progress(done, len(regions), "Scanning AWS regions")
        if errors and not assets and len(errors) == len(regions):
            raise RuntimeError(f"AWS discovery failed in every region - {errors[0]}")
        for a in assets:
            log.info(f"    [+] AWS {a['Region']}: {a['IP']} ({a['Hostname']}) | OS: {a['OS']} | {a['State']}")
        return assets
