"""Offline checks for the actual packaged application; no account or network access."""
import platform

from discovr import __version__


def check_runtime():
    """Exercise bundled providers and AWS service models, not just import discovery."""
    results = {"version": __version__, "platform": platform.system(), "architecture": platform.machine(), "checks": {}}

    def check(name, fn):
        try:
            fn()
            results["checks"][name] = {"ok": True}
        except Exception as exc:
            results["checks"][name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def aws():
        import boto3
        # Explicit dummy credentials prevent consulting instance metadata or SSO.
        session = boto3.Session(aws_access_key_id="diagnostic", aws_secret_access_key="diagnostic", region_name="us-east-1")
        for service in ("ec2", "sts", "ssm", "sso", "sso-oidc"):
            session.client(service).close()

    def azure():
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
        with ClientSecretCredential("tenant", "client", "diagnostic"):
            pass

    def gcp():
        from google.auth.transport.requests import AuthorizedSession
        from google.oauth2 import service_account

    def directory():
        from ldap3 import Tls
        from Crypto.Hash import MD4
        MD4.new(b"diagnostic").digest()
        Tls()

    def passive():
        from discovr.network import parse_arp_table
        from discovr.passive import PassiveDiscovery
        assert isinstance(parse_arp_table(""), dict)
        PassiveDiscovery(timeout=1)

    def ui():
        from discovr.server import STATIC, UI_DIR
        for name, _ in STATIC.values():
            if not (UI_DIR / name).read_bytes():
                raise RuntimeError(f"Empty UI asset: {name}")

    for name, fn in (("aws", aws), ("azure", azure), ("gcp", gcp), ("ad", directory), ("passive", passive), ("ui", ui)):
        check(name, fn)
    results["ok"] = all(item["ok"] for item in results["checks"].values())
    return results
