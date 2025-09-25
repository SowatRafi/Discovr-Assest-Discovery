import logging
import os
from pathlib import Path


class GCPDiscovery:
    def __init__(self, project, zone, credentials_path=None, force_python_proto=True):
        self.project = project
        self.zone = zone
        self.credentials_path = credentials_path
        self.force_python_proto = force_python_proto

    def run(self):
        print(f"[+] Discovering GCP assets in project: {self.project} (zone: {self.zone})")

        env_overrides = {}
        previous_env = {}

        if self.credentials_path:
            creds_path = Path(self.credentials_path).expanduser()
            if not creds_path.exists():
                logging.error(f"[!] Provided GCP credentials file not found: {creds_path}")
                return []
            env_overrides["GOOGLE_APPLICATION_CREDENTIALS"] = str(creds_path)

        if self.force_python_proto:
            env_overrides.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

        assets = []
        try:
            for key, value in env_overrides.items():
                previous_env[key] = os.environ.get(key)
                os.environ[key] = value

            try:
                from google.cloud import compute_v1  # type: ignore import-not-found
            except ImportError:
                print("[!] google-cloud-compute library not installed. Run: pip install google-cloud-compute")
                return []

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
        finally:
            for key in env_overrides.keys():
                previous = previous_env.get(key)
                if previous is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = previous

        return assets
