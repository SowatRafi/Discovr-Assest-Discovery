from discovr.azure import AzureDiscovery
from discovr.gcp import GCPDiscovery
# from discovr.aws import AWSDiscovery  # Placeholder if AWS logic is split into its own module


class CloudDiscovery:
    def __init__(self, provider, profile=None, region=None, subscription=None, project=None, zone=None):
        """
        Initialize the Cloud Discovery dispatcher.
        :param provider: "aws", "azure", "gcp"
        :param profile: AWS profile name
        :param region: AWS region
        :param subscription: Azure subscription ID
        :param project: GCP project ID
        :param zone: GCP zone
        """
        self.provider = provider
        self.profile = profile
        self.region = region
        self.subscription = subscription
        self.project = project
        self.zone = zone

    def run(self):
        """
        Dispatch to the correct cloud provider discovery.
        """
        if self.provider == "azure":
            if not self.subscription:
                raise Exception("Azure discovery requires --subscription <id>")
            azure_scanner = AzureDiscovery(self.subscription)
            return azure_scanner.run()

        elif self.provider == "gcp":
            if not self.project or not self.zone:
                raise Exception("GCP discovery requires --project and --zone")
            gcp_scanner = GCPDiscovery(self.project, self.zone)
            return gcp_scanner.run()

        elif self.provider == "aws":
            # Future expansion: move AWS-specific discovery here
            raise NotImplementedError("AWS discovery not yet separated into its own module")

        else:
            raise Exception(f"Unsupported cloud provider: {self.provider}")
