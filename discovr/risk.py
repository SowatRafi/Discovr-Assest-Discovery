"""Preliminary risk rating (Critical / High / Medium / Low) for discovered assets.

This is a triage heuristic, not a vulnerability scan: it combines operating-system
support status, exposed services and device role so the riskiest hosts surface first.
Rules run from most to least severe and the first match wins.
"""
from discovr.tagger import Tagger, port_set

# Past vendor end-of-support: no security patches at all.
UNSUPPORTED_OS = ("windows xp", "windows vista", "windows 7", "windows 8", "server 2003",
                  "server 2008", "server 2012", "centos linux", "centos 7", "centos-7",
                  "centos 8", "centos-8")
# Out of mainstream support; patched only with paid ESU (Windows 10 ended 14 Oct 2025).
ENDING_OS = ("windows 10",)
# Desktop OSes that are current and receive security updates.
CURRENT_DESKTOP_OS = ("windows 11", "macos", "mac os", "darwin")

CLEARTEXT_PORTS = {21, 23}                          # FTP, Telnet: credentials sent in cleartext
REMOTE_ADMIN_PORTS = {3389, 5900, 5985, 5986}       # RDP, VNC, WinRM
DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 27017}
FILE_SHARE_PORTS = {139, 445, 2049}                 # SMB/NetBIOS, NFS
SENSITIVE_PORTS = CLEARTEXT_PORTS | REMOTE_ADMIN_PORTS | DATABASE_PORTS | FILE_SHARE_PORTS

RISK_ORDER = ("Critical", "High", "Medium", "Low")


class RiskAssessor:
    """Rates assets so unsupported, exposed or unmanageable devices are triaged first."""

    @staticmethod
    def assess(asset: dict) -> str:
        """Return the risk level for one asset (uses its Tag, computing it if missing)."""
        os_name = str(asset.get("OS", "")).lower()
        tag = asset.get("Tag") or Tagger.assign_tag(asset)
        ports = port_set(asset.get("Ports"))
        # Cloud discovery sets InternetExposed when a public IP meets a firewall rule allowing
        # inbound traffic from anywhere; ExposedPorts lists just those ports (default: all ports).
        exposed = bool(asset.get("InternetExposed"))
        exposed_ports = port_set(asset.get("ExposedPorts", asset.get("Ports"))) if exposed else set()

        if any(k in os_name for k in UNSUPPORTED_OS):
            return "Critical"
        if exposed_ports & SENSITIVE_PORTS:
            return "Critical"  # admin, database or file-share service reachable from the internet
        if exposed or ports & CLEARTEXT_PORTS or any(k in os_name for k in ENDING_OS):
            return "High"
        if tag in ("[IoT]", "[Printer]"):
            return "High"  # rarely patched and cannot host a security agent
        if tag in ("[Workstation]", "[Mobile]", "[Tablet]", "[Network]") and ports & REMOTE_ADMIN_PORTS:
            return "High"  # remote admin on endpoints/network gear is a common initial-access path
        if tag == "[Workstation]":
            return "Low" if any(k in os_name for k in CURRENT_DESKTOP_OS) else "Medium"
        if tag in ("[Server]", "[Network]", "[WebHost]", "[Mobile]", "[Tablet]", "[Unknown]"):
            return "Medium"  # high-value, externally facing, or simply not identifiable
        return "Low"

    @staticmethod
    def add_risks(assets: list) -> list:
        """Add the Risk field to every asset in place and return the same list."""
        for asset in assets:
            asset["Risk"] = RiskAssessor.assess(asset)
        return assets
