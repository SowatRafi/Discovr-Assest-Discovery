class RiskAssessor:
    @staticmethod
    def assess(asset: dict) -> str:
        """
        Assign a refined risk level based on:
        - OS
        - Open ports (Ports or OpenPorts)
        - Tag
        - NSG rules (for NetworkSecurityGroup assets)
        """

        asset_type = asset.get("Type", "").lower()
        os_name = str(asset.get("OS", "")).lower()
        tag = asset.get("Tag", "[Unknown]")
        ports_field = asset.get("Ports") or asset.get("OpenPorts") or []

        # Normalize ports into a list of strings
        if isinstance(ports_field, str):
            ports = [p.strip() for p in ports_field.split(",") if p.strip()]
        elif isinstance(ports_field, list):
            ports = [str(p).strip() for p in ports_field if p]
        else:
            ports = []

        # --- Helper categories ---
        risky_ports = ["3389", "23", "445", "21"]   # RDP, Telnet, SMB, FTP
        medium_ports = ["80", "443", "3306"]        # HTTP, HTTPS, MySQL

        # --------------------------
        # Network Security Group assessment
        # --------------------------
        if asset_type in ["networksecuritygroup", "nsg"]:
            rules = asset.get("SecurityRules", [])
            for rule in rules:
                if rule.get("Direction", "").lower() == "inbound" and rule.get("Access", "").lower() == "allow":
                    rule_ports = str(rule.get("Ports", ""))
                    if rule_ports == "*" or rule.get("Source") in ["*", "Any"]:
                        return "Critical"
                    elif any(p in rule_ports for p in risky_ports):
                        return "High"
                    elif any(p in rule_ports for p in medium_ports):
                        return "Medium"
            return "Low"

        # --------------------------
        # VM / Host / Workstation / Server assessment
        # --------------------------

        # --- Critical OS versions ---
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
            if "windows 7" in os_name or "vista" in os_name:
                return "Critical"
            if "windows 10" in os_name:
                return "Medium"
            if "windows 11" in os_name or "macos" in os_name or "darwin" in os_name:
                return "Low"
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

        # --- Unknown assets ---
        if os_name == "unknown" or tag == "[Unknown]":
            return "Medium"

        # --- Escalate risk for ports if no other rule matched ---
        if any(p in ports for p in risky_ports):
            return "High"
        elif any(p in ports for p in medium_ports):
            return "Medium"

        # --- Default fallback ---
        return "Low"

    @staticmethod
    def add_risks(assets: list) -> list:
        """Add Risk field to all assets"""
        for asset in assets:
            asset["Risk"] = RiskAssessor.assess(asset)
        return assets
