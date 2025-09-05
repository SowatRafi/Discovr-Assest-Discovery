class Tagger:
    @staticmethod
    def assign_tag(asset: dict) -> str:
        """Assigns a role tag to an asset based on hostname, OS, or IP clues"""
        hostname = asset.get("Hostname", "").lower()
        os_name = asset.get("OS", "").lower()
        ports = asset.get("Ports", "").lower()

        # Workstations
        if "windows 10" in os_name or "windows 11" in os_name:
            return "[Workstation]"

        # Servers
        if "server" in os_name or "linux" in os_name:
            return "[Server]"

        # Printers
        if "printer" in hostname:
            return "[Printer]"

        # IoT
        if "camera" in hostname or "iot" in hostname or "chromecast" in hostname:
            return "[IoT]"

        # Mobile Phones
        if any(word in os_name for word in ["android", "ios", "iphone", "ipad"]):
            return "[Mobile]"
        if any(word in hostname for word in ["iphone", "ipad", "android", "samsung", "oneplus", "pixel"]):
            return "[Mobile]"

        # Network Devices
        if "router" in hostname or "switch" in hostname or "firewall" in hostname:
            return "[Network]"

        # Web hosts
        if "80" in ports or "443" in ports:
            return "[WebHost]"

        return "[Unknown]"

    @staticmethod
    def tag_assets(assets: list) -> list:
        """Tag a list of assets and add 'Tag' key"""
        for asset in assets:
            asset["Tag"] = Tagger.assign_tag(asset)
        return assets
