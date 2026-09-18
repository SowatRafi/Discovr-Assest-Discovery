"""Cloud dispatcher: one entry point for AWS, Azure and GCP discovery.

Provider modules are imported only when selected, so a network-only run never pays
the import cost of boto3 or azure-identity.
"""


def CloudDiscovery(provider, profile=None, region=None, subscription=None, project=None, zone=None,
                   credentials_file=None):
    """Return the discovery object (with a .run() method) for "aws", "azure" or "gcp".

    Kept as a CamelCase factory so existing `CloudDiscovery(...).run()` callers keep working.
    """
    if provider == "aws":
        from discovr.aws import AWSDiscovery

        return AWSDiscovery(profile=profile, region=region or "all")
    if provider == "azure":
        from discovr.azure import AzureDiscovery

        return AzureDiscovery(subscription=subscription)
    if provider == "gcp":
        from discovr.gcp import GCPDiscovery

        return GCPDiscovery(project=project, zone=zone, credentials_file=credentials_file)
    raise ValueError(f"Unsupported cloud provider: {provider}")
