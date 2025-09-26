from collections import defaultdict
from tabulate import tabulate


class AWSReporter:
    @staticmethod
    def print_summary(assets):
        regions = defaultdict(list)
        for asset in assets:
            region = asset.get("ResourceGroup") or asset.get("Region") or "global"
            regions[region].append(asset)

        header = "═" * 70
        for region, items in sorted(regions.items()):
            print(f"\n{header}\nAWS Region: {region}\n{header}")

            instances = [i for i in items if i.get("Type") == "EC2Instance"]
            if instances:
                print("\nEC2 Instances")
                print(tabulate(
                    [
                        [
                            inst.get("InstanceId", ""),
                            inst.get("Hostname", ""),
                            inst.get("OS", ""),
                            inst.get("IP", ""),
                            inst.get("PublicIP", ""),
                            inst.get("State", ""),
                            inst.get("InstanceType", ""),
                        ]
                        for inst in instances
                    ],
                    headers=["InstanceId", "Hostname", "OS", "IP", "PublicIP", "State", "Type"],
                    tablefmt="grid",
                ))

            security_groups = [i for i in items if i.get("Type") == "EC2SecurityGroup"]
            if security_groups:
                print("\nSecurity Groups")
                print(tabulate(
                    [
                        [
                            sg.get("GroupId", ""),
                            sg.get("GroupName", ""),
                            sg.get("InboundPorts", ""),
                            sg.get("OutboundPorts", ""),
                        ]
                        for sg in security_groups
                    ],
                    headers=["GroupId", "Name", "Inbound Ports", "Outbound Ports"],
                    tablefmt="grid",
                ))

            iam = [i for i in items if i.get("Type") in ("IAMUser", "IAMRole")]
            if iam:
                print("\nIAM Resources")
                print(tabulate(
                    [
                        [
                            res.get("Type"),
                            res.get("UserName") or res.get("RoleName"),
                            res.get("Arn", ""),
                        ]
                        for res in iam
                    ],
                    headers=["Type", "Name", "Arn"],
                    tablefmt="grid",
                ))

            other_counts = {
                "EBS Volumes": len([i for i in items if i.get("Type") == "EBSVolume"]),
                "RDS Instances": len([i for i in items if i.get("Type") == "RDSInstance"]),
                "S3 Buckets": len([i for i in items if i.get("Type") == "S3Bucket"]),
                "EKS Clusters": len([i for i in items if i.get("Type") == "EKSCluster"]),
            }
            if any(other_counts.values()):
                print("\nAdditional Resources:")
                for label, count in other_counts.items():
                    print(f"- {label}: {count}")
