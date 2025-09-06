import logging

try:
    from google.cloud import compute_v1
    gcp_available = True
except ImportError:
    gcp_available = False


class GCPDiscovery:
    def __init__(self, project, zone):
        self.project = project
        self.zone = zone

    def run(self):
        if not gcp_available:
            print("[!] google-cloud-compute library not installed. Run: pip install google-cloud-compute")
            return []

        print(f"[+] Discovering GCP assets in project: {self.project} (zone: {self.zone})")

        assets = []
        try:
            client = compute_v1.InstancesClient()
            request = compute_v1.ListInstancesRequest(project=self.project, zone=self.zone)
            response = client.list(request=request)

            for instance in response:
                ip = None
                if instance.network_interfaces:
                    ip = instance.network_interfaces[0].network_i_p

                hostname = instance.name or "Unknown"
                os_name = "Unknown"

                if instance.labels and "os" in instance.labels:
                    os_name = instance.labels["os"]

                asset = {
                    "IP": ip or "N/A",
                    "Hostname": hostname,
                    "OS": os_name,
                    "Ports": "N/A"
                }
                logging.info(
                    f"    [+] GCP Instance: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']}"
                )
                assets.append(asset)

        except Exception as e:
            logging.error(f"[!] Failed to discover GCP assets: {e}")
            return []

        return assets
