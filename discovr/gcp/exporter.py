import csv
from pathlib import Path
from typing import Iterable, Dict, Any, List


class GCPExporter:
    @staticmethod
    def export(assets: Iterable[Dict[str, Any]], timestamp: str, csv_dir: Path):
        gcp_dir = csv_dir / f"gcp_{timestamp}"
        gcp_dir.mkdir(parents=True, exist_ok=True)

        instances: List[Dict[str, Any]] = []
        networks: List[Dict[str, Any]] = []
        firewalls: List[Dict[str, Any]] = []
        regional_addresses: List[Dict[str, Any]] = []
        global_addresses: List[Dict[str, Any]] = []
        regional_forwarding: List[Dict[str, Any]] = []
        global_forwarding: List[Dict[str, Any]] = []
        disks: List[Dict[str, Any]] = []
        images: List[Dict[str, Any]] = []

        for asset in assets:
            asset_type = asset.get("Type")
            if asset_type == "ComputeInstance":
                instances.append(asset)
            elif asset_type == "VPCNetwork":
                networks.append(asset)
            elif asset_type == "FirewallRule":
                firewalls.append(asset)
            elif asset_type == "RegionalAddress":
                regional_addresses.append(asset)
            elif asset_type == "GlobalAddress":
                global_addresses.append(asset)
            elif asset_type == "ForwardingRule":
                regional_forwarding.append(asset)
            elif asset_type == "GlobalForwardingRule":
                global_forwarding.append(asset)
            elif asset_type == "PersistentDisk":
                disks.append(asset)
            elif asset_type == "Image":
                images.append(asset)

        if instances:
            path = gcp_dir / f"gcp_instances_{timestamp}.csv"
            GCPExporter._write_csv(
                path,
                ["Project", "Name", "Zone", "MachineType", "Status", "IP", "Labels"],
                [
                    [
                        inst.get("Project", ""),
                        inst.get("Name", ""),
                        inst.get("Zone", ""),
                        inst.get("MachineType", ""),
                        inst.get("Status", ""),
                        inst.get("IP", ""),
                        GCPExporter._format_labels(inst.get("Labels")),
                    ]
                    for inst in instances
                ],
            )
            print(f"[+] GCP Instances CSV saved: {path}")

        if networks:
            path = gcp_dir / f"gcp_networks_{timestamp}.csv"
            GCPExporter._write_csv(
                path,
                ["Project", "Name", "AutoCreateSubnetworks", "Subnets", "RoutingMode"],
                [
                    [
                        net.get("Project", ""),
                        net.get("Name", ""),
                        net.get("AutoCreateSubnetworks", ""),
                        ";".join(net.get("Subnets", [])),
                        net.get("RoutingMode", ""),
                    ]
                    for net in networks
                ],
            )
            print(f"[+] GCP Networks CSV saved: {path}")

        if firewalls:
            path = gcp_dir / f"gcp_firewalls_{timestamp}.csv"
            GCPExporter._write_csv(
                path,
                ["Project", "Name", "Direction", "Priority", "SourceRanges", "TargetTags", "Allowed", "Denied"],
                [
                    [
                        fw.get("Project", ""),
                        fw.get("Name", ""),
                        fw.get("Direction", ""),
                        fw.get("Priority", ""),
                        ";".join(fw.get("SourceRanges", [])),
                        ";".join(fw.get("TargetTags", [])),
                        ";".join(fw.get("Allowed", [])),
                        ";".join(fw.get("Denied", [])),
                    ]
                    for fw in firewalls
                ],
            )
            print(f"[+] GCP Firewalls CSV saved: {path}")

        if regional_addresses or global_addresses:
            path = gcp_dir / f"gcp_addresses_{timestamp}.csv"
            rows: List[List[Any]] = []
            for addr in regional_addresses:
                rows.append([
                    addr.get("Project", ""),
                    "regional",
                    addr.get("Name", ""),
                    addr.get("Address", ""),
                    addr.get("Status", ""),
                    addr.get("AddressType", ""),
                    addr.get("Region", ""),
                ])
            for addr in global_addresses:
                rows.append([
                    addr.get("Project", ""),
                    "global",
                    addr.get("Name", ""),
                    addr.get("Address", ""),
                    addr.get("Status", ""),
                    addr.get("AddressType", ""),
                    "",
                ])
            GCPExporter._write_csv(
                path,
                ["Project", "Scope", "Name", "Address", "Status", "AddressType", "Region"],
                rows,
            )
            print(f"[+] GCP Addresses CSV saved: {path}")

        if regional_forwarding or global_forwarding:
            path = gcp_dir / f"gcp_forwarding_rules_{timestamp}.csv"
            rows: List[List[Any]] = []
            for rule in regional_forwarding:
                rows.append([
                    rule.get("Project", ""),
                    "regional",
                    rule.get("Name", ""),
                    rule.get("IPAddress", ""),
                    rule.get("PortRange", ""),
                    rule.get("Target", ""),
                    rule.get("Region", ""),
                ])
            for rule in global_forwarding:
                rows.append([
                    rule.get("Project", ""),
                    "global",
                    rule.get("Name", ""),
                    rule.get("IPAddress", ""),
                    rule.get("PortRange", ""),
                    rule.get("Target", ""),
                    "",
                ])
            GCPExporter._write_csv(
                path,
                ["Project", "Scope", "Name", "IPAddress", "PortRange", "Target", "Region"],
                rows,
            )
            print(f"[+] GCP Forwarding Rules CSV saved: {path}")

        if disks:
            path = gcp_dir / f"gcp_disks_{timestamp}.csv"
            GCPExporter._write_csv(
                path,
                ["Project", "Zone", "Name", "SizeGb", "DiskType", "Status", "Users"],
                [
                    [
                        disk.get("Project", ""),
                        disk.get("Zone", ""),
                        disk.get("Name", ""),
                        disk.get("SizeGb", ""),
                        disk.get("DiskType", ""),
                        disk.get("Status", ""),
                        ";".join(disk.get("Users", [])),
                    ]
                    for disk in disks
                ],
            )
            print(f"[+] GCP Disks CSV saved: {path}")

        if images:
            path = gcp_dir / f"gcp_images_{timestamp}.csv"
            GCPExporter._write_csv(
                path,
                ["Project", "Name", "Status", "DiskSizeGb", "Family"],
                [
                    [
                        image.get("Project", ""),
                        image.get("Name", ""),
                        image.get("Status", ""),
                        image.get("DiskSizeGb", ""),
                        image.get("Family", ""),
                    ]
                    for image in images
                ],
            )
            print(f"[+] GCP Images CSV saved: {path}")

        summary_path = gcp_dir / f"gcp_summary_{timestamp}.csv"
        summary_rows = GCPExporter._build_summary(
            instances,
            networks,
            firewalls,
            regional_addresses,
            global_addresses,
            regional_forwarding,
            global_forwarding,
            disks,
            images,
        )
        GCPExporter._write_csv(
            summary_path,
            [
                "Project",
                "Instances",
                "Networks",
                "Firewalls",
                "Disks",
                "Images",
                "RegionalAddresses",
                "GlobalAddresses",
                "RegionalForwarding",
                "GlobalForwarding",
            ],
            summary_rows,
        )
        print(f"[+] GCP Summary CSV saved: {summary_path}")

    @staticmethod
    def _write_csv(path: Path, header: List[str], rows: List[List[Any]]):
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(header)
            writer.writerows(rows)

    @staticmethod
    def _format_labels(labels: Any) -> str:
        if isinstance(labels, dict):
            return ";".join(f"{k}={v}" for k, v in labels.items())
        return ""

    @staticmethod
    def _build_summary(
        instances: List[Dict[str, Any]],
        networks: List[Dict[str, Any]],
        firewalls: List[Dict[str, Any]],
        regional_addresses: List[Dict[str, Any]],
        global_addresses: List[Dict[str, Any]],
        regional_forwarding: List[Dict[str, Any]],
        global_forwarding: List[Dict[str, Any]],
        disks: List[Dict[str, Any]],
        images: List[Dict[str, Any]],
    ) -> List[List[Any]]:
        projects: Dict[str, Dict[str, int]] = {}

        def inc(project: str, key: str):
            projects.setdefault(project, {}).setdefault(key, 0)
            projects[project][key] += 1

        for inst in instances:
            inc(inst.get("Project", "unknown"), "Instances")
        for net in networks:
            inc(net.get("Project", "unknown"), "Networks")
        for fw in firewalls:
            inc(fw.get("Project", "unknown"), "Firewalls")
        for addr in regional_addresses:
            inc(addr.get("Project", "unknown"), "RegionalAddresses")
        for addr in global_addresses:
            inc(addr.get("Project", "unknown"), "GlobalAddresses")
        for rule in regional_forwarding:
            inc(rule.get("Project", "unknown"), "RegionalForwarding")
        for rule in global_forwarding:
            inc(rule.get("Project", "unknown"), "GlobalForwarding")
        for disk in disks:
            inc(disk.get("Project", "unknown"), "Disks")
        for image in images:
            inc(image.get("Project", "unknown"), "Images")

        rows: List[List[Any]] = []
        for project, counters in sorted(projects.items()):
            rows.append([
                project,
                counters.get("Instances", 0),
                counters.get("Networks", 0),
                counters.get("Firewalls", 0),
                counters.get("Disks", 0),
                counters.get("Images", 0),
                counters.get("RegionalAddresses", 0),
                counters.get("GlobalAddresses", 0),
                counters.get("RegionalForwarding", 0),
                counters.get("GlobalForwarding", 0),
            ])
        return rows
