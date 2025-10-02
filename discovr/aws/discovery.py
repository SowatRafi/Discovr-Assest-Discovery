import logging
from getpass import getpass
from typing import Dict, Iterable, Optional, Set, List

try:
    import boto3
    from botocore.exceptions import (  # type: ignore
        BotoCoreError,
        ClientError,
        EndpointConnectionError,
        NoCredentialsError,
        NoRegionError,
        ProfileNotFound,
    )
    boto3_available = True
except ImportError:  # pragma: no cover - handled at runtime
    boto3 = None  # type: ignore
    BotoCoreError = ClientError = EndpointConnectionError = NoCredentialsError = NoRegionError = ProfileNotFound = Exception  # type: ignore
    boto3_available = False


class AWSDiscovery:
    """Discover AWS EC2 assets for a given profile and region."""

    def __init__(
        self,
        profile: Optional[str] = None,
        region: Optional[str] = None,
        session=None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        session_token: Optional[str] = None,
    ) -> None:
        self.profile = profile
        self.region = region
        self._provided_session = session
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self._sg_cache: Dict[str, dict] = {}

    def _create_session(self):
        if self._provided_session:
            return self._provided_session

        if not boto3_available:
            raise RuntimeError("boto3 library not installed")

        session_kwargs = {}
        if self.access_key and self.secret_key:
            session_kwargs.update(
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
            )
            if self.session_token:
                session_kwargs["aws_session_token"] = self.session_token
        elif self.profile:
            session_kwargs["profile_name"] = self.profile

        session = boto3.Session(**session_kwargs)  # type: ignore[arg-type]

        if not session.get_credentials():
            print("[!] No AWS credentials detected. Please provide them now.")
            access = input("AWS access key ID: ").strip()
            secret = getpass("AWS secret access key: ").strip()
            token = input("AWS session token (optional): ").strip()
            if not access or not secret:
                raise RuntimeError("AWS credentials are required to continue")
            session = boto3.Session(  # type: ignore[arg-type]
                aws_access_key_id=access,
                aws_secret_access_key=secret,
                aws_session_token=token or None,
            )

        return session

    @staticmethod
    def _normalize_region(region: str) -> str:
        if (
            len(region) >= 2
            and region[-1].isalpha()
            and region[-2].isdigit()
            and "-" in region
        ):
            return region[:-1]
        return region

    def _resolve_region(self, session) -> tuple[str, str]:
        raw_region = self.region or getattr(session, "region_name", None) or "us-east-1"
        normalized = self._normalize_region(raw_region)
        return normalized, raw_region

    def _ensure_security_groups(self, ec2_client, group_ids: Iterable[str]) -> None:
        missing = [gid for gid in group_ids if gid and gid not in self._sg_cache]
        if not missing:
            return

        try:
            response = ec2_client.describe_security_groups(GroupIds=missing)
        except ClientError as exc:
            logging.debug(f"[!] Failed to describe security groups {missing}: {exc}")
            return

        for sg in response.get("SecurityGroups", []):
            gid = sg.get("GroupId")
            if gid:
                self._sg_cache[gid] = sg

    @staticmethod
    def _permissions_to_ports(permissions: Iterable[dict]) -> Set[str]:
        ports: Set[str] = set()
        for permission in permissions:
            ip_protocol = permission.get("IpProtocol")
            if ip_protocol == "-1":
                ports.add("Any")
                continue

            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            if from_port is None and to_port is None:
                continue

            if from_port == to_port or to_port is None:
                ports.add(str(from_port))
            else:
                ports.add(f"{from_port}-{to_port}")

        return ports

    def _summarize_ports(self, group_ids: Iterable[str]) -> str:
        ports: Set[str] = set()

        for gid in group_ids:
            sg = self._sg_cache.get(gid)
            if not sg:
                continue

            ports.update(self._permissions_to_ports(sg.get("IpPermissions", [])))

        if not ports:
            return "N/A"

        return ",".join(sorted(ports, key=lambda value: (value == "Any", value)))

    @staticmethod
    def _extract_hostname(instance: dict) -> str:
        tags = instance.get("Tags", []) or []
        for tag in tags:
            if tag.get("Key", "").lower() == "name" and tag.get("Value"):
                return tag["Value"]
        return instance.get("InstanceId", "unknown-instance")

    @staticmethod
    def _extract_os(instance: dict) -> str:
        if instance.get("PlatformDetails"):
            return instance["PlatformDetails"]
        if instance.get("Platform"):
            platform = instance["Platform"]
            return "Windows" if platform.lower() == "windows" else platform
        if instance.get("ImageId"):
            return instance["ImageId"]
        return "Unknown"

    def _populate_security_group_cache(self, ec2_client):
        if self._sg_cache:
            return list(self._sg_cache.values())

        groups = []
        try:
            paginator = ec2_client.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    gid = sg.get("GroupId")
                    if gid:
                        self._sg_cache[gid] = sg
                        groups.append(sg)
        except (ClientError, BotoCoreError, EndpointConnectionError) as exc:
            print(f"[!] Failed to enumerate AWS security groups: {exc}")
            return []

        return groups

    def _discover_instances(self, ec2_client, region: str) -> list:
        assets = []
        try:
            paginator = ec2_client.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        state = instance.get("State", {}).get("Name")
                        if state in {"terminated", "shutting-down"}:
                            continue

                        public_ip = instance.get("PublicIpAddress")
                        private_ip = instance.get("PrivateIpAddress")
                        primary_ip = public_ip or private_ip or "N/A"

                        group_ids = [sg.get("GroupId") for sg in instance.get("SecurityGroups", [])]
                        self._ensure_security_groups(ec2_client, group_ids)
                        port_summary = self._summarize_ports(group_ids)

                        hostname = self._extract_hostname(instance)
                        os_name = self._extract_os(instance)

                        asset = {
                            "Type": "EC2Instance",
                            "CloudProvider": "aws",
                            "InstanceId": instance.get("InstanceId"),
                            "Hostname": hostname,
                            "IP": primary_ip,
                            "PublicIP": public_ip or "N/A",
                            "PrivateIP": private_ip or "N/A",
                            "OS": os_name,
                            "Ports": port_summary,
                            "State": state,
                            "InstanceType": instance.get("InstanceType"),
                            "AvailabilityZone": instance.get("Placement", {}).get("AvailabilityZone"),
                            "Tags": instance.get("Tags", []),
                            "ResourceGroup": region,
                        }

                        logging.info(
                            f"    [+] AWS Instance: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']}"
                        )

                        assets.append(asset)

        except (ClientError, BotoCoreError, EndpointConnectionError, NoCredentialsError) as exc:
            print(f"[!] Failed to discover AWS instances: {exc}")

        return assets

    def _discover_security_groups(self, region: str) -> list:
        assets = []
        if not self._sg_cache:
            return assets

        for sg in self._sg_cache.values():
            inbound_ports = self._permissions_to_ports(sg.get("IpPermissions", []))
            outbound_ports = self._permissions_to_ports(sg.get("IpPermissionsEgress", []))

            assets.append(
                {
                    "Type": "EC2SecurityGroup",
                    "CloudProvider": "aws",
                    "ResourceGroup": region,
                    "GroupId": sg.get("GroupId"),
                    "GroupName": sg.get("GroupName"),
                    "Description": sg.get("Description"),
                    "VpcId": sg.get("VpcId", "N/A"),
                    "InboundPorts": ",".join(sorted(inbound_ports)) if inbound_ports else "N/A",
                    "OutboundPorts": ",".join(sorted(outbound_ports)) if outbound_ports else "N/A",
                    "InboundRuleCount": len(sg.get("IpPermissions", [])),
                    "OutboundRuleCount": len(sg.get("IpPermissionsEgress", [])),
                    "Ports": ",".join(sorted(inbound_ports)) if inbound_ports else "N/A",
                    "Tags": sg.get("Tags", []),
                }
            )

        return assets

    def _discover_volumes(self, ec2_client, region: str) -> list:
        assets = []
        try:
            paginator = ec2_client.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page.get("Volumes", []):
                    attachments = [att.get("InstanceId") for att in volume.get("Attachments", []) if att.get("InstanceId")]
                    assets.append(
                        {
                            "Type": "EBSVolume",
                            "CloudProvider": "aws",
                            "ResourceGroup": region,
                            "VolumeId": volume.get("VolumeId"),
                            "State": volume.get("State"),
                            "SizeGiB": volume.get("Size"),
                            "Encrypted": volume.get("Encrypted"),
                            "VolumeType": volume.get("VolumeType"),
                            "AvailabilityZone": volume.get("AvailabilityZone"),
                            "AttachedInstances": ",".join(attachments) if attachments else "None",
                            "Iops": volume.get("Iops"),
                            "Throughput": volume.get("Throughput"),
                            "SnapshotId": volume.get("SnapshotId"),
                            "Tags": volume.get("Tags", []),
                            "Ports": "N/A",
                        }
                    )
        except (ClientError, BotoCoreError, EndpointConnectionError) as exc:
            print(f"[!] Failed to discover EBS volumes: {exc}")

        return assets

    def _discover_rds_instances(self, session, region: str) -> list:
        assets = []

        try:
            rds_client = session.client("rds", region_name=region)
        except (BotoCoreError, ClientError, EndpointConnectionError) as exc:
            print(f"[!] Failed to initialize RDS client: {exc}")
            return assets

        try:
            paginator = rds_client.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    endpoint = db.get("Endpoint", {})
                    assets.append(
                        {
                            "Type": "RDSInstance",
                            "CloudProvider": "aws",
                            "ResourceGroup": region,
                            "DBInstanceIdentifier": db.get("DBInstanceIdentifier"),
                            "DBInstanceClass": db.get("DBInstanceClass"),
                            "Engine": db.get("Engine"),
                            "EngineVersion": db.get("EngineVersion"),
                            "Status": db.get("DBInstanceStatus"),
                            "Endpoint": endpoint.get("Address"),
                            "Port": endpoint.get("Port"),
                            "MultiAZ": db.get("MultiAZ"),
                            "StorageType": db.get("StorageType"),
                            "AllocatedStorage": db.get("AllocatedStorage"),
                            "PubliclyAccessible": db.get("PubliclyAccessible"),
                            "IAMDatabaseAuthenticationEnabled": db.get("IAMDatabaseAuthenticationEnabled"),
                            "MasterUsername": db.get("MasterUsername"),
                            "AvailabilityZone": db.get("AvailabilityZone"),
                            "InstanceCreateTime": str(db.get("InstanceCreateTime")),
                            "BackupRetentionPeriod": db.get("BackupRetentionPeriod"),
                            "Tags": db.get("TagList", []),
                            "Ports": str(endpoint.get("Port")) if endpoint.get("Port") else "N/A",
                        }
                    )
                    arn = db.get("DBInstanceArn")
                    if arn:
                        try:
                            tags_resp = rds_client.list_tags_for_resource(ResourceName=arn)
                            assets[-1]["Tags"] = tags_resp.get("TagList", [])
                        except (ClientError, BotoCoreError, EndpointConnectionError):
                            pass
        except (ClientError, BotoCoreError, EndpointConnectionError) as exc:
            print(f"[!] Failed to discover RDS instances: {exc}")

        return assets

    def _discover_iam(self, session) -> list:
        assets = []
        try:
            iam_client = session.client("iam")
        except (BotoCoreError, ClientError) as exc:
            print(f"[!] Failed to initialize IAM client: {exc}")
            return assets

        try:
            user_paginator = iam_client.get_paginator("list_users")
            for page in user_paginator.paginate():
                for user in page.get("Users", []):
                    assets.append(
                        {
                            "Type": "IAMUser",
                            "CloudProvider": "aws",
                            "ResourceGroup": "iam",
                            "UserName": user.get("UserName"),
                            "Arn": user.get("Arn"),
                            "CreateDate": str(user.get("CreateDate")),
                            "PasswordLastUsed": str(user.get("PasswordLastUsed")) if user.get("PasswordLastUsed") else "Never",
                            "Tags": user.get("Tags", []),
                            "Ports": "N/A",
                        }
                    )

            role_paginator = iam_client.get_paginator("list_roles")
            for page in role_paginator.paginate():
                for role in page.get("Roles", []):
                    assets.append(
                        {
                            "Type": "IAMRole",
                            "CloudProvider": "aws",
                            "ResourceGroup": "iam",
                            "RoleName": role.get("RoleName"),
                            "Arn": role.get("Arn"),
                            "CreateDate": str(role.get("CreateDate")),
                            "Path": role.get("Path"),
                            "Description": role.get("Description", ""),
                            "Tags": role.get("Tags", []),
                            "Ports": "N/A",
                        }
                    )

        except (ClientError, BotoCoreError) as exc:
            print(f"[!] Failed to discover IAM entities: {exc}")

        return assets

    def _discover_eks_clusters(self, session, region: str) -> list:
        assets = []

        try:
            eks_client = session.client("eks", region_name=region)
        except (BotoCoreError, ClientError, EndpointConnectionError) as exc:
            print(f"[!] Failed to initialize EKS client: {exc}")
            return assets

        try:
            cluster_names: List[str] = []

            try:
                paginator = eks_client.get_paginator("list_clusters")
                for page in paginator.paginate():
                    cluster_names.extend(page.get("clusters", []))
            except Exception:
                # Some stubs or partitions may not support pagination
                response = eks_client.list_clusters()
                cluster_names.extend(response.get("clusters", []))

            for cluster_name in cluster_names:
                if not cluster_name:
                    continue
                try:
                    details = eks_client.describe_cluster(name=cluster_name).get("cluster", {})
                except (ClientError, BotoCoreError, EndpointConnectionError) as exc:
                    logging.debug(f"[!] Failed to describe EKS cluster {cluster_name}: {exc}")
                    continue

                resources = details.get("resourcesVpcConfig", {})
                assets.append(
                    {
                        "Type": "EKSCluster",
                        "CloudProvider": "aws",
                        "ResourceGroup": region,
                        "Name": details.get("name", cluster_name),
                        "Arn": details.get("arn"),
                        "Status": details.get("status"),
                        "Version": details.get("version"),
                        "Endpoint": details.get("endpoint"),
                        "RoleArn": details.get("roleArn"),
                        "PlatformVersion": details.get("platformVersion"),
                        "VpcId": resources.get("vpcId"),
                        "SubnetIds": ",".join(resources.get("subnetIds", [])) or "N/A",
                        "SecurityGroupIds": ",".join(resources.get("securityGroupIds", [])) or "N/A",
                        "Logging": details.get("logging", {}),
                        "Tags": details.get("tags", {}),
                        "CreatedAt": str(details.get("createdAt")),
                        "Ports": "N/A",
                    }
                )
        except (ClientError, BotoCoreError, EndpointConnectionError) as exc:
            print(f"[!] Failed to discover EKS clusters: {exc}")

        return assets

    def _discover_s3_buckets(self, session, region: str) -> list:
        assets = []

        try:
            s3_client = session.client("s3")
        except (BotoCoreError, ClientError, EndpointConnectionError) as exc:
            print(f"[!] Failed to initialize S3 client: {exc}")
            return assets

        try:
            buckets = s3_client.list_buckets().get("Buckets", [])
        except (ClientError, BotoCoreError, EndpointConnectionError) as exc:
            print(f"[!] Failed to list S3 buckets: {exc}")
            return assets

        for bucket in buckets:
            name = bucket.get("Name")
            if not name:
                continue

            try:
                location_resp = s3_client.get_bucket_location(Bucket=name)
                location = location_resp.get("LocationConstraint") or "us-east-1"
            except (ClientError, BotoCoreError, EndpointConnectionError):
                location = "Unknown"

            bucket_region = "us-east-1" if location in (None, "", "US") else location
            if region and region != bucket_region:
                continue

            # Optional enrichment – best-effort and tolerant to permission issues
            versioning = "Unknown"
            encryption = "Unknown"
            public_access = "Unknown"

            try:
                versioning_status = s3_client.get_bucket_versioning(Bucket=name)
                versioning = versioning_status.get("Status", "Disabled") or "Disabled"
            except (ClientError, BotoCoreError, EndpointConnectionError):
                pass

            try:
                encryption_resp = s3_client.get_bucket_encryption(Bucket=name)
                rules = encryption_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                    encryption = algo or "Enabled"
                else:
                    encryption = "Enabled"
            except (ClientError, BotoCoreError, EndpointConnectionError):
                pass

            try:
                pab = s3_client.get_public_access_block(Bucket=name)
                config = pab.get("PublicAccessBlockConfiguration", {})
                public_access = "Blocked" if all(config.values()) else "PartiallyBlocked"
            except (ClientError, BotoCoreError, EndpointConnectionError):
                pass

            assets.append(
                {
                    "Type": "S3Bucket",
                    "CloudProvider": "aws",
                    "ResourceGroup": bucket_region,
                    "Name": name,
                    "CreationDate": str(bucket.get("CreationDate")),
                    "Region": bucket_region,
                    "PublicAccess": public_access,
                    "Versioning": versioning,
                    "Encryption": encryption,
                    "Ports": "N/A",
                }
            )

        return assets

    def run(self) -> list:
        if not boto3_available and not self._provided_session:
            print("[!] boto3 library not installed. Run: pip install boto3")
            return []

        try:
            session = self._create_session()
        except ProfileNotFound:
            print(f"[!] AWS profile '{self.profile}' not found.")
            return []
        except Exception as exc:  # pragma: no cover - unforeseen boto3 issues
            print(f"[!] Failed to create AWS session: {exc}")
            return []

        try:
            region, raw_region = self._resolve_region(session)
            if region != raw_region:
                print(f"[!] Normalizing AWS region '{raw_region}' to '{region}'")
            ec2_client = session.client("ec2", region_name=region)
        except (NoRegionError, BotoCoreError, ClientError, EndpointConnectionError) as exc:
            print(f"[!] Failed to initialize EC2 client: {exc}")
            return []

        print(
            f"[+] Discovering AWS assets in region {region} "
            f"using profile {self.profile or 'default'}"
        )

        # Populate SG cache upfront (best-effort)
        self._populate_security_group_cache(ec2_client)

        assets = []
        assets.extend(self._discover_instances(ec2_client, region))
        assets.extend(self._discover_security_groups(region))
        assets.extend(self._discover_volumes(ec2_client, region))
        assets.extend(self._discover_eks_clusters(session, region))
        assets.extend(self._discover_s3_buckets(session, region))
        assets.extend(self._discover_rds_instances(session, region))
        assets.extend(self._discover_iam(session))

        return assets
