class Tagger:
    @staticmethod
    def assign_tag(asset: dict) -> str:
        """Assigns a role tag to an asset based on hostname, OS, or IP clues"""
        hostname = asset.get("Hostname", "").lower()
        os_name = asset.get("OS", "").lower()
        ports = asset.get("Ports", "").lower()

        # --- Mobile ---
        if any(mobile in hostname for mobile in ["iphone", "android", "pixel", "galaxy"]):
            return "[Mobile]"
        if "ios" in os_name and "macos" not in os_name:
            return "[Mobile]"
        if "android" in os_name:
            return "[Mobile]"

        # --- Tablet ---
        if "ipad" in hostname or "tablet" in hostname:
            return "[Tablet]"
        if "ipad" in os_name or "ipad os" in os_name:
            return "[Tablet]"

        # --- macOS ---
        if "macos" in os_name or "os x" in os_name or ("darwin" in os_name and "ios" not in os_name):
            return "[Workstation]"

        # --- Windows Workstation ---
        if "windows 10" in os_name or "windows 11" in os_name:
            return "[Workstation]"

        # --- Servers ---
        if "server" in os_name or "linux" in os_name:
            return "[Server]"

        # --- Printers ---
        if "printer" in hostname:
            return "[Printer]"

        # --- IoT ---
        if "camera" in hostname or "iot" in hostname or "chromecast" in hostname:
            return "[IoT]"

        # --- Network Devices ---
        if "router" in hostname or "switch" in hostname or "firewall" in hostname:
            return "[Network]"

        # --- Web Hosts ---
        if "80" in ports or "443" in ports:
            return "[WebHost]"

        return "[Unknown]"

    @staticmethod
    def tag_assets(assets: list) -> list:
        """Tag a list of assets and add 'Tag' key"""
        for asset in assets:
            asset["Tag"] = Tagger.assign_tag(asset)
        return assets
