"""Offline examples, deliberately using reserved documentation addresses and fake IDs."""


def demo_assets():
    """Return fresh sample records; every exported row carries an explicit demo marker."""
    rows = [
        {"IP": "192.0.2.10", "Hostname": "demo-dc.example", "OS": "Windows Server 2022", "Ports": "88,135,389,445,636,3389", "Source": "AD, Network", "Environment": "Example office", "DomainController": True},
        {"IP": "192.0.2.20", "Hostname": "demo-laptop.example", "OS": "Windows 11", "Ports": "135,445", "Source": "AD", "Environment": "Example office"},
        {"IP": "192.0.2.30", "Hostname": "demo-mac.example", "OS": "macOS", "Ports": "22,3283", "Source": "Network", "Environment": "Example office"},
        {"IP": "192.0.2.40", "Hostname": "demo-printer.example", "OS": "Unknown", "Ports": "80,631,9100", "Source": "Network", "Environment": "Example office"},
        {"IP": "192.0.2.50", "Hostname": "demo-camera.example", "OS": "Embedded Linux (guessed)", "Ports": "80,554", "Source": "Network", "Environment": "Example office"},
        {"IP": "192.0.2.60", "Hostname": "demo-router.example", "OS": "Cisco IOS (guessed)", "Ports": "22,23,80", "Source": "Network", "Environment": "Example office"},
        {"IP": "198.51.100.10", "Hostname": "demo-web.example", "OS": "Linux (Ubuntu)", "Ports": "22,443", "Source": "AWS", "Cloud": "AWS", "AccountID": "000000000000", "InstanceID": "i-demo-web", "Region": "ap-southeast-2", "InternetExposed": True, "ExposedPorts": "22,443", "Environment": "Example production"},
        {"IP": "198.51.100.20", "Hostname": "demo-db.example", "OS": "Windows Server 2019", "Ports": "1433,3389", "Source": "Azure", "Cloud": "Azure", "SubscriptionID": "demo-subscription", "InstanceID": "demo-database", "InternetExposed": None, "Environment": "Example production"},
        {"IP": "203.0.113.10", "Hostname": "demo-worker.example", "OS": "Debian Linux", "Ports": "22", "Source": "GCP", "Cloud": "GCP", "ProjectID": "demo-project", "Zone": "australia-southeast1-a", "InstanceID": "demo-worker", "InternetExposed": False, "Environment": "Example development"},
        {"IP": "203.0.113.20", "Hostname": "Unknown", "OS": "Unknown", "Ports": "Unknown", "Source": "Passive", "SeenVia": "OS neighbour cache (may be stale)", "Environment": "Example development"},
    ]
    for row in rows:
        row["Demo"] = True
        row["Evidence"] = "Fictional sample only; not a real scan or verified exposure assessment."
    return rows
