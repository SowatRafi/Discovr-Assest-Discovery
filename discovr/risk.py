class RiskAssessor:
    @staticmethod
    def assess(asset: dict) -> str:
        """Assign a refined risk level based on OS, open ports, and tag"""
        os_name = asset.get("OS", "").lower()
        ports = asset.get("Ports", "").lower()
        tag = asset.get("Tag", "[Unknown]")

        # --- Helper: risky ports ---
        risky_ports = ["3389", "23", "445", "21"]  # RDP, Telnet, SMB, FTP
        medium_ports = ["80", "443", "3306"]       # HTTP, HTTPS, MySQL

        # --- Critical OS ---
        if any(old in os_name for old in ["windows xp", "windows vista", "windows 7", "server 2003", "server 2008"]):
            return "Critical"

        # --- IoT / Printer ---
        if tag in ["[IoT]", "[Printer]"]:
            return "High"

        # --- Mobile / Tablet ---
        if tag in ["[Mobile]", "[Tablet]"]:
            if any(p in ports for p in risky_ports):
                return "High"
            return "Medium"

        # --- Workstations ---
        if tag == "[Workstation]":
            # Old Windows workstations
            if "windows 7" in os_name or "vista" in os_name:
                return "Critical"
            # Windows 10 baseline
            if "windows 10" in os_name:
                return "Medium"
            # Windows 11 or macOS modern versions
            if "windows 11" in os_name or "macos" in os_name or "darwin" in os_name:
                return "Low"
            # Escalate if risky ports
            if any(p in ports for p in risky_ports):
                return "High"

        # --- Servers ---
        if tag == "[Server]":
            if "server 2008" in os_name or "server 2003" in os_name:
                return "Critical"
            if any(p in ports for p in risky_ports):
                return "High"
            return "Medium"

        # --- Network devices ---
        if tag == "[Network]":
            if any(p in ports for p in risky_ports):
                return "High"
            return "Medium"

        # --- Web hosts ---
        if tag == "[WebHost]":
            if any(p in ports for p in medium_ports):
                return "Medium"

        # --- Unknown ---
        if os_name == "unknown" or tag == "[Unknown]":
            return "Medium"

        # --- Default ---
        return "Low"

    @staticmethod
    def add_risks(assets: list) -> list:
        """Add Risk field to assets"""
        for asset in assets:
            asset["Risk"] = RiskAssessor.assess(asset)
        return assets
