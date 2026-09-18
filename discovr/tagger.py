"""Role tagging: classify each asset from its OS string, hostname, open ports and cloud metadata.

The tag answers "what kind of device is this?" and drives two downstream decisions:
the risk rating (discovr.risk) and the AgentCapable flag - whether the host can run a
security agent, which is Discovr's primary purpose. Rules are ordered most-specific
first and the first match wins.
"""
import re

# Hosts that can run an EDR / security agent (the tool's primary target).
AGENT_CAPABLE_TAGS = {"[Workstation]", "[Server]"}

PRINTER_PORTS = {515, 631, 9100}          # LPD, IPP, JetDirect raw printing
IOT_PORTS = {554, 1883, 8883, 37777}      # RTSP cameras, MQTT brokers/devices, Dahua DVRs
DC_PORTS = {88, 389}                      # Kerberos + LDAP together => domain controller
WEB_PORTS = {80, 443, 8080, 8443}

NETWORK_OS_HINTS = ("cisco", "junos", "fortios", "routeros", "mikrotik", "pan-os", "arista")
NETWORK_HOST_HINTS = ("router", "switch", "firewall", "gateway")
IOT_HOST_HINTS = ("camera", "iot", "chromecast", "sonos", "roku")
SERVER_OS_HINTS = ("server", "linux", "unix", "ubuntu", "debian", "centos", "red hat", "rhel",
                   "suse", "freebsd", "amazon", "rocky", "alma")


def port_set(value) -> set:
    """Normalise a Ports field ("22,80", [22, "80"], "1000-1010", "*", "N/A") into a set of ints.

    Parsing into integers fixes the old substring matching, where "80" matched "8080"
    and "21" matched "8021". Cloud firewall rules may contain ranges or "*" (any port).
    """
    items = value if isinstance(value, (list, tuple, set)) else str(value or "").replace(";", ",").split(",")
    ports = set()
    for item in items:
        token = str(item).strip().lower()
        if token in ("*", "any", "all"):
            # ponytail: expands to 65k ints; fine for the rare "allow any" cloud rule.
            return set(range(1, 65536))
        low, _, high = token.partition("-")
        if low.isdigit() and (high.isdigit() or not high):
            ports.update(range(int(low), int(high or low) + 1))
    return ports


def port_sort_key(token):
    """Sort key for port tokens: numbers ascending, then ranges and "*" alphabetically."""
    token = str(token)
    return (not token.isdigit(), int(token) if token.isdigit() else 0, token)


class Tagger:
    """Assigns a role tag such as [Workstation], [Server] or [Printer] to discovered assets."""

    @staticmethod
    def assign_tag(asset: dict) -> str:
        """Return the role tag for a single asset (does not modify it)."""
        host = str(asset.get("Hostname", "")).lower()
        os_name = str(asset.get("OS", "")).lower()
        ports = port_set(asset.get("Ports"))

        # Network gear first: "Cisco IOS" must not be mistaken for Apple iOS below.
        if any(k in os_name for k in NETWORK_OS_HINTS) or any(k in host for k in NETWORK_HOST_HINTS):
            return "[Network]"

        # Phones and tablets (62078 = Apple lockdownd, only exposed by iPhones/iPads).
        if "ipad" in host or "tablet" in host or "ipados" in os_name:
            return "[Tablet]"
        if (any(k in host for k in ("iphone", "android", "pixel", "galaxy")) or "android" in os_name
                or re.search(r"\bios\b", os_name) or 62078 in ports):
            return "[Mobile]"

        # Desktop operating systems.
        if any(k in os_name for k in ("macos", "mac os", "os x", "darwin")):
            return "[Workstation]"
        if "windows" in os_name:
            # Server editions, domain controllers and cloud VMs are servers; the rest are endpoints.
            if "server" in os_name or DC_PORTS <= ports or asset.get("Cloud"):
                return "[Server]"
            return "[Workstation]"

        # Devices that cannot run agents - identified mostly by the services they expose.
        if ports & PRINTER_PORTS or "printer" in host:
            return "[Printer]"
        if ports & IOT_PORTS or any(k in host for k in IOT_HOST_HINTS) or "embedded" in os_name:
            return "[IoT]"

        # Cloud VMs and Unix-like systems.
        if asset.get("Cloud") or any(k in os_name for k in SERVER_OS_HINTS):
            return "[Server]"

        if ports & WEB_PORTS:
            return "[WebHost]"
        return "[Unknown]"

    @staticmethod
    def tag_assets(assets: list) -> list:
        """Tag every asset in place, add the AgentCapable flag, and return the same list."""
        for asset in assets:
            asset["Tag"] = Tagger.assign_tag(asset)
            asset["AgentCapable"] = asset["Tag"] in AGENT_CAPABLE_TAGS
        return assets
