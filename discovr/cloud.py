"""
Cloud dispatcher for Discovr

This module handles dispatching cloud discovery logic to the correct
provider. Azure is handled in the separate `discovr.azure` package.
"""

def CloudDiscovery(provider, **kwargs):
    """
    Dispatcher function for non-Azure cloud providers.

    Args:
        provider (str): Cloud provider ("gcp", "aws").
        kwargs: Additional arguments required by each provider.

    Returns:
        Cloud discovery object (GCPDiscovery, AWSDiscovery, etc.)
    """
    if provider == "gcp":
        from discovr.gcp import GCPDiscovery

        return GCPDiscovery(kwargs.get("project"), kwargs.get("zone"))

    if provider == "aws":
        from discovr.aws import AWSDiscovery

        return AWSDiscovery(
            profile=kwargs.get("profile"),
            region=kwargs.get("region"),
            session=kwargs.get("session"),
        )

    else:
        raise ValueError(f"Unsupported cloud provider: {provider}")
