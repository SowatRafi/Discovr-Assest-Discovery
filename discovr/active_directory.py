"""Active Directory discovery: enumerate computer accounts over LDAP.

AD is often the most complete list of domain-joined machines - it includes hosts that
are powered off or on another subnet during a network scan. Security and privacy choices:

* A simple bind (which
  carries the password) only happens inside a TLS channel whose certificate *verified*
  (system trust store, or --ca-file for an internal CA); otherwise Discovr uses NTLM
  challenge-response. The previous code used a plain LDAP simple bind, exposing the domain
  password to anyone sniffing the LAN.
* Only one bind attempt is made per mechanism; repeated retries can trigger account lockout.
* Paged searches: AD caps unpaged results at 1,000 entries, which silently truncated
  larger domains before.
* Data minimisation: free-text attributes such as `description` are not collected -
  admins sometimes store passwords there, and reports get shared widely.
"""
import logging
import asyncio
import socket
import ssl
from datetime import datetime, timedelta, timezone
from discovr.lookup import lookup_many
from discovr.scan import ScanControl

log = logging.getLogger(__name__)

UAC_ACCOUNTDISABLE = 0x2         # userAccountControl flag: computer account disabled
UAC_SERVER_TRUST = 0x2000        # userAccountControl flag: domain controller
STALE_AFTER_DAYS = 90            # no logon for this long => machine is probably gone
ATTRIBUTES = ["cn", "dNSHostName", "operatingSystem", "operatingSystemVersion",
              "lastLogonTimestamp", "userAccountControl"]


def _first(value):
    """LDAP values arrive as lists without a schema, scalars with one; return the first/only item."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def filetime_to_datetime(value):
    """AD FILETIME (100 ns ticks since 1601, as int, str or datetime) -> aware datetime or None."""
    value = _first(value)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None  # 0 = never logged on
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)


def ou_path(dn) -> str:
    """Organisational-unit path, top-down: "CN=PC1,OU=Laptops,OU=HQ,DC=corp" -> "HQ/Laptops"."""
    from ldap3.utils.dn import parse_dn  # handles escaped commas in names

    try:
        return "/".join(reversed([value for attr, value, _ in parse_dn(dn) if attr.upper() == "OU"]))
    except Exception:  # malformed DN from a broken directory - the OU is only context
        return ""


def computer_to_asset(dn, attrs, now=None) -> dict:
    """Turn one LDAP computer entry into a Discovr asset (IP is resolved later)."""
    now = now or datetime.now(timezone.utc)
    fqdn = str(_first(attrs.get("dNSHostName")) or _first(attrs.get("cn")) or "Unknown")
    os_name = " ".join(str(_first(attrs.get(k)) or "") for k in ("operatingSystem", "operatingSystemVersion"))
    uac = int(_first(attrs.get("userAccountControl")) or 0)
    last_logon = filetime_to_datetime(attrs.get("lastLogonTimestamp"))
    return {
        "IP": "N/A",
        "Hostname": fqdn,
        "OS": os_name.strip() or "Unknown",
        "Ports": "N/A",
        "Source": "AD",
        "OU": ou_path(dn),
        "Enabled": not uac & UAC_ACCOUNTDISABLE,
        "DomainController": bool(uac & UAC_SERVER_TRUST),
        "LastLogon": last_logon.date().isoformat() if last_logon else "Never",
        "Stale": last_logon is None or (now - last_logon).days > STALE_AFTER_DAYS,
    }


def _resolve(fqdn) -> str:
    """Forward DNS lookup for an AD computer; "N/A" when the record is missing."""
    try:
        return socket.gethostbyname(fqdn)
    except (OSError, UnicodeError):
        return "N/A"


class ADDiscovery:
    """Lists every computer object in a domain, with OS, OU, logon age and resolved IP."""

    def __init__(self, domain, username, password, dc=None, use_ldaps=False, ca_file=None):
        """
        :param domain: DNS domain, e.g. "corp.local" (also used to build the search base)
        :param username: "user@corp.local" or "CORP\\user"
        :param password: account password (never logged)
        :param dc: domain controller host/IP when the domain name does not resolve to one
        :param use_ldaps: bind over LDAPS (636) instead of StartTLS/NTLM on 389
        :param ca_file: PEM file of the domain CA used to verify the DC certificate
                        (default: the operating system's trust store)
        """
        self.domain = domain
        self.username = username
        self.password = password
        self.server_host = dc or domain
        self.use_ldaps = use_ldaps
        self.ca_file = ca_file
        self.base_dn = ",".join(f"DC={part}" for part in domain.split("."))

    def _tls(self):
        """TLS settings that verify the DC certificate and hostname (never CERT_NONE)."""
        from ldap3 import Tls

        return Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=self.ca_file)

    def _ntlm_user(self) -> str:
        """NTLM wants DOMAIN\\user; derive it from a UPN (user@corp.local) when needed."""
        if "\\" in self.username:
            return self.username
        user, _, realm = self.username.partition("@")
        return f"{realm or self.domain}\\{user}"

    def _connect(self):
        """Open an authenticated connection that never exposes the password; returns (connection, method).

        Simple binds send the password, so they only ever run inside a TLS channel whose
        certificate verified. If the DC has no certificate, or it cannot be verified (internal
        CA not trusted, name mismatch, attacker in the middle), Discovr falls back to NTLM
        challenge-response, which never transmits the password.
        """
        from ldap3 import NTLM, SIMPLE, Connection, Server
        from ldap3.core.exceptions import LDAPException

        options = {"receive_timeout": 30, "read_only": True}

        if self.use_ldaps:
            server = Server(self.server_host, port=636, use_ssl=True, tls=self._tls(), connect_timeout=10)
            conn = Connection(server, self.username, self.password, authentication=SIMPLE, **options)
            try:
                conn.open()  # TLS handshake + certificate verification happen here, before any password
            except LDAPException as exc:
                raise RuntimeError(f"Could not verify the LDAPS certificate of {self.server_host} ({exc}) - "
                                   "pass your domain CA with --ca-file, or omit --ldaps to use NTLM")
            if not conn.bind():
                raise PermissionError(f"LDAPS bind failed: {conn.result.get('description')}")
            return conn, "LDAPS (verified certificate)"

        server = Server(self.server_host, port=389, tls=self._tls(), connect_timeout=10)
        conn = Connection(server, self.username, self.password, authentication=SIMPLE, **options)
        conn.open()  # raises LDAPSocketOpenError if the DC is unreachable
        try:
            tls_ok = conn.start_tls()  # raises if the certificate is missing or does not verify
        except LDAPException:
            tls_ok = False
        if tls_ok:
            if not conn.bind():  # verified channel: a failure here is a real credential error
                raise PermissionError(f"LDAP bind failed: {conn.result.get('description')}")
            return conn, "StartTLS (verified certificate)"
        try:
            conn.unbind()
        except LDAPException:
            pass  # a half-upgraded socket may already be closed

        conn = Connection(server, self._ntlm_user(), self.password, authentication=NTLM, **options)
        if not conn.bind():
            raise PermissionError(f"NTLM bind failed: {conn.result.get('description')} "
                                  "(if the DC requires LDAP signing, use --ldaps with --ca-file)")
        return conn, "NTLM (challenge-response)"

    def run(self, on_progress=None, on_asset=None, cancel=None):
        """Return a list of computer assets; raises on connection or credential errors."""
        control = ScanControl(on_progress, on_asset, cancel)
        self.warnings = control.warnings
        control.progress(0, 0, "Connecting to Active Directory")
        conn, method = self._connect()
        log.info(f"[+] Connected to {self.server_host} via {method}")
        try:
            results = conn.extend.standard.paged_search(
                self.base_dn, "(objectClass=computer)", attributes=ATTRIBUTES, paged_size=500, generator=True)
            assets = []
            for result in control.pages(results):
                if result.get("type") == "searchResEntry":
                    asset = computer_to_asset(result["dn"], result["attributes"])
                    assets.append(control.emit(asset))
                    control.progress(len(assets), 0, "Reading directory computers")
            if conn.result and conn.result.get("result", 0) != 0:
                control.warn(f"Directory search incomplete: {conn.result.get('description', 'search failed')}")
        finally:
            conn.unbind()

        # Resolve IPs in parallel; disabled accounts are skipped to save time.
        enabled = [a for a in assets if a["Enabled"]]
        control.progress(0, len(enabled), "Resolving directory computer names")
        addresses = asyncio.run(lookup_many([a["Hostname"] for a in enabled], _resolve, "N/A", cancel))
        for done, (asset, ip) in enumerate(zip(enabled, addresses), 1):
            asset["IP"] = ip
            control.emit(asset)
            control.progress(done, len(enabled), "Resolving directory computer names")

        for asset in assets:
            log.info(f"    [+] AD Computer: {asset['IP']} ({asset['Hostname']}) | OS: {asset['OS']}")
        log.info(f"[+] {len(assets)} computer accounts ({len(enabled)} enabled)")
        return assets
