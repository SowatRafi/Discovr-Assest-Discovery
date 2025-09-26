import csv
from pathlib import Path
from typing import Iterable, Dict, Any, List


class AWSExporter:
    @staticmethod
    def export(assets: Iterable[Dict[str, Any]], timestamp: str, csv_dir: Path):
        aws_dir = csv_dir / f"aws_{timestamp}"
        aws_dir.mkdir(parents=True, exist_ok=True)

        grouped: Dict[str, List[Dict[str, Any]]] = {
            "instances": [],
            "security_groups": [],
            "volumes": [],
            "iam_users": [],
            "iam_roles": [],
            "rds": [],
            "s3": [],
            "eks": [],
        }
        for asset in assets:
            asset_type = asset.get("Type", "")
            if asset_type == "EC2Instance":
                grouped["instances"].append(asset)
            elif asset_type == "EC2SecurityGroup":
                grouped["security_groups"].append(asset)
            elif asset_type == "EBSVolume":
                grouped["volumes"].append(asset)
            elif asset_type == "IAMUser":
                grouped["iam_users"].append(asset)
            elif asset_type == "IAMRole":
                grouped["iam_roles"].append(asset)
            elif asset_type == "RDSInstance":
                grouped["rds"].append(asset)
            elif asset_type == "S3Bucket":
                grouped["s3"].append(asset)
            elif asset_type == "EKSCluster":
                grouped["eks"].append(asset)

        # Instances
        if grouped["instances"]:
            path = aws_dir / f"aws_instances_{timestamp}.csv"
            AWSExporter._write_csv(
                path,
                [
                    "Region",
                    "InstanceId",
                    "Hostname",
                    "IP",
                    "PublicIP",
                    "PrivateIP",
                    "OS",
                    "Ports",
                    "State",
                    "InstanceType",
                    "AvailabilityZone",
                    "Tags",
                ],
                [
                    [
                        inst.get("ResourceGroup", ""),
                        inst.get("InstanceId", ""),
                        inst.get("Hostname", ""),
                        inst.get("IP", ""),
                        inst.get("PublicIP", ""),
                        inst.get("PrivateIP", ""),
                        inst.get("OS", ""),
                        inst.get("Ports", ""),
                        inst.get("State", ""),
                        inst.get("InstanceType", ""),
                        inst.get("AvailabilityZone", ""),
                        AWSExporter._format_tags(inst.get("Tags")),
                    ]
                    for inst in grouped["instances"]
                ],
            )
            print(f"[+] AWS Instances CSV saved: {path}")

        # Security groups
        if grouped["security_groups"]:
            path = aws_dir / f"aws_security_groups_{timestamp}.csv"
            AWSExporter._write_csv(
                path,
                [
                    "Region",
                    "GroupId",
                    "GroupName",
                    "Description",
                    "VpcId",
                    "InboundPorts",
                    "OutboundPorts",
                    "InboundRuleCount",
                    "OutboundRuleCount",
                    "Tags",
                ],
                [
                    [
                        sg.get("ResourceGroup", ""),
                        sg.get("GroupId", ""),
                        sg.get("GroupName", ""),
                        sg.get("Description", ""),
                        sg.get("VpcId", ""),
                        sg.get("InboundPorts", ""),
                        sg.get("OutboundPorts", ""),
                        sg.get("InboundRuleCount", ""),
                        sg.get("OutboundRuleCount", ""),
                        AWSExporter._format_tags(sg.get("Tags")),
                    ]
                    for sg in grouped["security_groups"]
                ],
            )
            print(f"[+] AWS Security Groups CSV saved: {path}")

        # Volumes
        if grouped["volumes"]:
            path = aws_dir / f"aws_volumes_{timestamp}.csv"
            AWSExporter._write_csv(
                path,
                [
                    "Region",
                    "VolumeId",
                    "State",
                    "SizeGiB",
                    "Encrypted",
                    "VolumeType",
                    "AvailabilityZone",
                    "AttachedInstances",
                    "Iops",
                    "Throughput",
                    "SnapshotId",
                    "Tags",
                ],
                [
                    [
                        vol.get("ResourceGroup", ""),
                        vol.get("VolumeId", ""),
                        vol.get("State", ""),
                        vol.get("SizeGiB", ""),
                        vol.get("Encrypted", ""),
                        vol.get("VolumeType", ""),
                        vol.get("AvailabilityZone", ""),
                        vol.get("AttachedInstances", ""),
                        vol.get("Iops", ""),
                        vol.get("Throughput", ""),
                        vol.get("SnapshotId", ""),
                        AWSExporter._format_tags(vol.get("Tags")),
                    ]
                    for vol in grouped["volumes"]
                ],
            )
            print(f"[+] AWS Volumes CSV saved: {path}")

        # IAM users
        if grouped["iam_users"]:
            path = aws_dir / f"aws_iam_users_{timestamp}.csv"
            AWSExporter._write_csv(
                path,
                ["UserName", "Arn", "CreateDate", "PasswordLastUsed", "Tags"],
                [
                    [
                        user.get("UserName", ""),
                        user.get("Arn", ""),
                        user.get("CreateDate", ""),
                        user.get("PasswordLastUsed", ""),
                        AWSExporter._format_tags(user.get("Tags")),
                    ]
                    for user in grouped["iam_users"]
                ],
            )
            print(f"[+] AWS IAM Users CSV saved: {path}")

        # IAM roles
        if grouped["iam_roles"]:
            path = aws_dir / f"aws_iam_roles_{timestamp}.csv"
            AWSExporter._write_csv(
                path,
                ["RoleName", "Arn", "CreateDate", "Path", "Description", "Tags"],
                [
                    [
                        role.get("RoleName", ""),
                        role.get("Arn", ""),
                        role.get("CreateDate", ""),
                        role.get("Path", ""),
                        role.get("Description", ""),
                        AWSExporter._format_tags(role.get("Tags")),
                    ]
                    for role in grouped["iam_roles"]
                ],
            )
            print(f"[+] AWS IAM Roles CSV saved: {path}")

        # RDS
        if grouped["rds"]:
            path = aws_dir / f"aws_rds_{timestamp}.csv"
            AWSExporter._write_csv(
                path,
                [
                    "Region",
                    "Identifier",
                    "Class",
                    "Engine",
                    "EngineVersion",
                    "Status",
                    "Endpoint",
                    "Port",
                    "MultiAZ",
                    "StorageType",
                    "AllocatedStorage",
                    "PubliclyAccessible",
                ],
                [
                    [
                        rds.get("ResourceGroup", ""),
                        rds.get("DBInstanceIdentifier", ""),
                        rds.get("DBInstanceClass", ""),
                        rds.get("Engine", ""),
                        rds.get("EngineVersion", ""),
                        rds.get("Status", ""),
                        rds.get("Endpoint", ""),
                        rds.get("Port", ""),
                        rds.get("MultiAZ", ""),
                        rds.get("StorageType", ""),
                        rds.get("AllocatedStorage", ""),
                        rds.get("PubliclyAccessible", ""),
                    ]
                    for rds in grouped["rds"]
                ],
            )
            print(f"[+] AWS RDS CSV saved: {path}")

        # S3 buckets
        if grouped["s3"]:
            path = aws_dir / f"aws_s3_{timestamp}.csv"
            AWSExporter._write_csv(
                path,
                ["Name", "Region", "CreationDate", "PublicAccess", "Versioning", "Encryption"],
                [
                    [
                        s3.get("Name", ""),
                        s3.get("Region", ""),
                        s3.get("CreationDate", ""),
                        s3.get("PublicAccess", ""),
                        s3.get("Versioning", ""),
                        s3.get("Encryption", ""),
                    ]
                    for s3 in grouped["s3"]
                ],
            )
            print(f"[+] AWS S3 CSV saved: {path}")

        # EKS
        if grouped["eks"]:
            path = aws_dir / f"aws_eks_{timestamp}.csv"
            AWSExporter._write_csv(
                path,
                ["Name", "Status", "Version", "Endpoint", "Ports", "Tags"],
                [
                    [
                        eks.get("Name", ""),
                        eks.get("Status", ""),
                        eks.get("Version", ""),
                        eks.get("Endpoint", ""),
                        eks.get("Ports", ""),
                        AWSExporter._format_tags(eks.get("Tags")),
                    ]
                    for eks in grouped["eks"]
                ],
            )
            print(f"[+] AWS EKS CSV saved: {path}")

        # Summary
        summary_rows = AWSExporter._build_summary(grouped)
        summary_path = aws_dir / f"aws_summary_{timestamp}.csv"
        AWSExporter._write_csv(
            summary_path,
            ["Region", "Instances", "SecurityGroups", "Volumes", "IAMUsers", "IAMRoles", "RDS", "S3", "EKS"],
            summary_rows,
        )
        print(f"[+] AWS Summary CSV saved: {summary_path}")

    @staticmethod
    def _write_csv(path: Path, header: List[str], rows: List[List[Any]]):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)

    @staticmethod
    def _format_tags(tags: Any) -> str:
        if isinstance(tags, list):
            pairs = []
            for item in tags:
                if isinstance(item, dict):
                    k = item.get("Key")
                    v = item.get("Value")
                    if k:
                        pairs.append(f"{k}={v}")
            return ";".join(pairs)
        if isinstance(tags, dict):
            return ";".join(f"{k}={v}" for k, v in tags.items())
        return ""

    @staticmethod
    def _build_summary(grouped: Dict[str, List[Dict[str, Any]]]) -> List[List[Any]]:
        region_counts: Dict[str, Dict[str, int]] = {}
        def inc(region: str, key: str):
            region_counts.setdefault(region, {}).setdefault(key, 0)
            region_counts[region][key] += 1

        for inst in grouped["instances"]:
            inc(inst.get("ResourceGroup", "unknown"), "instances")
        for sg in grouped["security_groups"]:
            inc(sg.get("ResourceGroup", "unknown"), "security_groups")
        for vol in grouped["volumes"]:
            inc(vol.get("ResourceGroup", "unknown"), "volumes")
        for user in grouped["iam_users"]:
            inc("global", "iam_users")
        for role in grouped["iam_roles"]:
            inc("global", "iam_roles")
        for rds in grouped["rds"]:
            inc(rds.get("ResourceGroup", "unknown"), "rds")
        for s3 in grouped["s3"]:
            inc(s3.get("Region", "unknown"), "s3")
        for eks in grouped["eks"]:
            inc("global", "eks")

        rows = []
        for region, counts in sorted(region_counts.items()):
            rows.append([
                region,
                counts.get("instances", 0),
                counts.get("security_groups", 0),
                counts.get("volumes", 0),
                counts.get("iam_users", 0),
                counts.get("iam_roles", 0),
                counts.get("rds", 0),
                counts.get("s3", 0),
                counts.get("eks", 0),
            ])
        return rows
