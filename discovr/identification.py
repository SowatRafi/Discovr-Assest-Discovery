"""Bounded, unauthenticated identification using the OS and ordinary HTTP responses.

No separately installed programs, raw sockets, logins or redirected requests are used.
Remote descriptions are evidence for hints, not an authoritative operating system.
"""
import asyncio
from html.parser import HTMLParser
import ipaddress
import os
from pathlib import Path
import platform
import re
import socket
import ssl
import subprocess
import sys


class _Title(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inside = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.inside = True

    def handle_endtag(self, tag):
        if tag == "title":
            self.inside = False

    def handle_data(self, data):
        if self.inside:
            self.parts.append(data)


def local_identity():
    """Return only this computer's interface addresses and facts reported by its OS."""
    import psutil

    addresses = {}
    for entries in psutil.net_if_addrs().values():
        mac = next((a.address for a in entries if a.family == psutil.AF_LINK), "N/A")
        for addr in entries:
            if addr.family == socket.AF_INET:
                addresses[addr.address] = mac
    system = platform.system()
    if system == "Windows":
        os_name = f"Windows {platform.release()} {platform.win32_edition()}"
    elif system == "Darwin":
        os_name = f"macOS {platform.mac_ver()[0]}"
    else:
        try:
            os_name = platform.freedesktop_os_release().get("PRETTY_NAME", system)
        except OSError:
            os_name = system
        os_name += f" (kernel {platform.release()})"
    return addresses, {"Hostname": socket.gethostname(), "OS": os_name.strip(),
                       "LocalHost": True, "OSEvidence": "Reported by this computer's operating system",
                       "OSConfidence": "Local OS", "DeviceHint": "Computer",
                       "DeviceEvidence": "Address belongs to this computer"}


def local_listener_ports(addresses):
    """Find extra local TCP candidates; a subsequent connect still verifies each port.

    Some OS configurations hide socket tables from ordinary users. That must never
    trigger an elevation/install prompt or prevent the normal network scan.
    """
    import psutil

    result = {ip: set() for ip in addresses}
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                continue
            for ip in result:
                if conn.laddr.ip in (ip, "0.0.0.0", "::"):
                    result[ip].add(conn.laddr.port)
    except (psutil.Error, OSError):
        pass
    return result


def is_local(ip, addresses):
    return ip in addresses or ipaddress.ip_address(ip).is_loopback


def parse_gateways(text, system):
    """Extract default next hops, never treating an on-link route as a router."""
    gateways = set()
    for line in text.splitlines():
        fields = line.split()
        candidate = None
        if system.startswith("linux") and len(fields) >= 8 and fields[1] == "00000000" and fields[7] == "00000000":
            try:
                if int(fields[3], 16) & 3 == 3:  # route UP and GATEWAY flags
                    candidate = socket.inet_ntoa(int(fields[2], 16).to_bytes(4, "little"))
            except (ValueError, OverflowError):
                pass
        elif system == "win32" and len(fields) == 5 and fields[:2] == ["0.0.0.0", "0.0.0.0"]:
            candidate = fields[2]
        elif system == "darwin" and len(fields) == 2 and fields[0] == "gateway:":
            candidate = fields[1]
        try:
            if candidate and not ipaddress.IPv4Address(candidate).is_unspecified:
                gateways.add(candidate)
        except ValueError:
            pass
    return gateways


def default_gateways():
    """Read OS route information using bundled OS facilities, with a hard timeout."""
    try:
        if sys.platform.startswith("linux"):
            text = Path("/proc/net/route").read_text()
        else:
            args = ([str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "route.exe"), "print", "-4"]
                    if sys.platform == "win32" else ["/sbin/route", "-n", "get", "default"])
            options = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
            text = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  errors="replace", timeout=2, **options).stdout
        return parse_gateways(text, sys.platform)
    except (OSError, subprocess.SubprocessError):
        return set()


async def ssdp_identity(ip, timeout=1.1, port=1900):
    """One unicast M-SEARCH to an in-scope host; read only its advertised server token.

    UPnP Device Architecture 1.1 §1.3 permits a unicast search and a one-second
    response window. No multicast, port mapping, XML fetching or control calls.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        async with asyncio.timeout(timeout):
            await loop.sock_connect(sock, (ip, port))
            message = f'M-SEARCH * HTTP/1.1\r\nHOST: {ip}:{port}\r\nMAN: "ssdp:discover"\r\nST: upnp:rootdevice\r\n\r\n'
            await loop.sock_sendall(sock, message.encode("ascii"))
            data = await loop.sock_recv(sock, 4096)
        lines = data.decode("utf-8", "replace").split("\r\n")
        if not lines or lines[0] != "HTTP/1.1 200 OK":
            return ""
        for line in lines[1:]:
            key, sep, value = line.partition(":")
            if sep and key.lower() == "server":
                return " ".join(value.split())[:300]
    except (OSError, TimeoutError):
        pass
    finally:
        sock.close()
    return ""


async def http_identity(ip, port, timeout=1.5):
    """Read at most 32 KiB from GET /; never follow redirects or send credentials.

    Device consoles often use self-signed TLS. This anonymous discovery connection
    accepts those certificates; it does not certify identity or TLS security.
    The deadline covers connect, handshake, headers and body together.
    """
    writer = None
    raw = bytearray()
    try:
        async with asyncio.timeout(timeout):
            context = None
            if port in (443, 8443):
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.open_connection(ip, port, ssl=context)
            writer.write(f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Discovr\r\nAccept: text/html\r\nConnection: close\r\n\r\n".encode("ascii"))
            await writer.drain()
            while len(raw) < 32768:
                chunk = await reader.read(min(4096, 32768 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                if b"</title>" in raw.lower():
                    break
    except (OSError, ValueError, TimeoutError):
        # Useful headers may have arrived before a slow/streaming body timed out.
        pass
    finally:
        if writer is not None:
            writer.close()
    raw = bytes(raw)
    header, separator, body = raw.partition(b"\r\n\r\n")
    if not separator or not header.startswith(b"HTTP/"):
        return ""
    fields = {}
    for line in header.decode("iso-8859-1", "replace").split("\r\n")[1:]:
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip().lower()] = value.strip()
    title = _Title()
    if "html" in fields.get("content-type", "").lower():
        title.feed(body.decode("utf-8", "replace"))
    # Do not retain cookies, authentication tokens, page bodies or private URLs.
    values = [fields.get("server", ""), " ".join(title.parts)]
    return " | ".join(" ".join(v.split())[:200] for v in values if v.strip())[:400]


def device_hint(evidence):
    """Conservative product hints; generic web servers don't identify device hardware."""
    text = evidence.lower()
    rules = (
        ("Network", r"\b(router|routeros|openwrt|dd-wrt|asuswrt|fortigate|junos|tp-link|netgear|ubiquiti)\b"),
        ("Printer", r"\b(printer|jetdirect|laserjet|officejet|cups)\b"),
        ("Storage", r"\b(synology|diskstation|qnap|truenas|freenas)\b"),
        ("IoT", r"\b(camera|hikvision|dahua|chromecast|roku|sonos)\b"),
    )
    return next((name for name, pattern in rules if re.search(pattern, text)), "")
