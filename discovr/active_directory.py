import logging
import socket

try:
    from ldap3 import Server, Connection, ALL
    ad_available = True
except ImportError:
    ad_available = False


class ADDiscovery:
    def __init__(self, domain, username, password):
        self.domain = domain
        self.username = username
        self.password = password

    def run(self):
        if not ad_available:
            logging.error("[!] ldap3 not installed. Run: pip install ldap3")
            return []

        assets = []
        try:
            server = Server(self.domain, get_info=ALL)
            conn = Connection(server, user=self.username, password=self.password, auto_bind=True)
            logging.info(f"[+] Connected to AD domain: {self.domain}")

            conn.search(
                search_base=f"DC={self.domain.replace('.', ',DC=')}",
                search_filter="(objectClass=computer)",
                attributes=["cn", "dNSHostName", "operatingSystem", "operatingSystemVersion"]
            )

            for entry in conn.entries:
                fqdn = str(entry.dNSHostName) if entry.dNSHostName else str(entry.cn)
                os_name = str(entry.operatingSystem) if entry.operatingSystem else "Unknown"
                os_version = str(entry.operatingSystemVersion) if entry.operatingSystemVersion else ""

                try:
                    ip = socket.gethostbyname(fqdn)
                except Exception:
                    ip = "N/A"

                asset = {
                    "IP": ip,
                    "Hostname": fqdn,
                    "OS": f"{os_name} {os_version}".strip(),
                    "Ports": "N/A"
                }
                logging.info(f"    [+] AD Computer: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']}")
                assets.append(asset)

            conn.unbind()
        except Exception as e:
            logging.error(f"[!] Active Directory discovery failed: {e}")

        return assets