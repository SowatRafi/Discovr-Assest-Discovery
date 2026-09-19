"""Active network discovery: a fast, dependency-free asyncio TCP sweep.

The previous engine launched one `nmap -O` process per IP address. That needed nmap
installed, admin rights and Npcap on Windows, and took minutes to hours for a /24.
This engine needs none of those:

  1. Sweep every address on a few common ports. A host counts as alive when any probe
     is answered - an accepted connection (open port) *or* an immediate refusal (RST
     from a closed port). Plain TCP connects need no raw sockets, so no admin rights.
  2. Read the OS ARP cache: our connection attempts made the OS ARP for every local
     address, so hosts whose firewall drops all TCP still show up (with their MAC).
  3. Probe live hosts on the extended port list, resolve names and grab SSH banners,
     then guess the OS from what the host exposes.

Intensity profiles bound concurrency and timeouts so sensitive networks can be
scanned gently (brief: "configurable to avoid causing disruptions").
"""
import asyncio
import ipaddress
import logging
import os
import re
import socket
import struct
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from discovr.lookup import lookup_many

log = logging.getLogger(__name__)

# Phase 1 - probed on every address: cheap liveness plus strong role hints
# (SSH, web, Windows RPC/SMB, RDP, JetDirect printers, Apple iPhone sync).
SWEEP_PORTS = (22, 80, 135, 139, 443, 445, 3389, 8080, 9100, 62078)
# Phase 2 - probed on live hosts only: admin, directory, database, printing, IoT, Apple.
TOP_PORTS = (21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 515, 548, 554,
             631, 636, 993, 995, 1433, 1521, 1883, 2049, 3268, 3283, 3306, 3389, 5000, 5432, 5900,
             5985, 5986, 6379, 8000, 8080, 8443, 8883, 9100, 9200, 27017, 62078)

# name -> (probes in flight, seconds to wait per probe)
INTENSITY = {"gentle": (64, 2.0), "normal": (512, 1.0), "aggressive": (2048, 0.5)}
MAX_ADDRESSES = 65536  # one /16 per scan keeps runtime and memory predictable

# SSH banner fragments that reveal the operating system (checked in order).
BANNER_OS = (("windows", "Windows"), ("ubuntu", "Linux (Ubuntu)"), ("debian", "Linux (Debian)"),
             ("raspbian", "Linux (Raspberry Pi OS)"), ("freebsd", "FreeBSD"), ("cisco", "Cisco IOS"),
             ("mikrotik", "MikroTik RouterOS"), ("dropbear", "Embedded Linux"))

# ARP table lines: Linux /proc/net/arp (flags 0x0 = incomplete) and Windows `arp -a` / BSD `arp -an`.
_ARP_LINUX = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+0x\w+\s+0x[1-9a-f]\w*\s+([0-9a-f:]{17})", re.I | re.M)
_ARP_OTHER = re.compile(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2}){5})\b", re.I)


# --------------------------------------------------------------------------- input parsing

def parse_targets(spec) -> list:
    """Expand "10.0.0.0/24", "10.0.0.5" or a comma-separated mix into IPv4 host addresses.

    Raises ValueError for malformed input, IPv6 (a /64 cannot be swept) or more than
    MAX_ADDRESSES addresses.
    """
    networks = [ipaddress.IPv4Network(t.strip(), strict=False) for t in str(spec).split(",") if t.strip()]
    if not networks:
        raise ValueError("no target network given")
    if sum(n.num_addresses for n in networks) > MAX_ADDRESSES:
        raise ValueError(f"target is larger than a /16 ({MAX_ADDRESSES} addresses); split it into smaller ranges")
    hosts = []
    for net in networks:
        # .hosts() skips network/broadcast addresses; a /32 has no "hosts", so keep the address.
        hosts.extend(str(ip) for ip in (list(net.hosts()) or [net.network_address]))
    return list(dict.fromkeys(hosts))  # de-duplicate overlapping ranges, keep order


def parse_port_spec(spec) -> list:
    """Parse "22,80,8000-8010" into sorted unique port numbers (ValueError if invalid)."""
    ports = set()
    for token in str(spec).split(","):
        token = token.strip()
        if not token:
            continue
        low, _, high = token.partition("-")
        low, high = int(low), int(high or low)
        if not 1 <= low <= high <= 65535:
            raise ValueError(f"invalid port range: {token}")
        ports.update(range(low, high + 1))
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def _ip_key(ip):
    """Numeric sort key for IPv4 strings."""
    return int(ipaddress.IPv4Address(ip))


# --------------------------------------------------------------------------- local environment

def primary_ip() -> str:
    """Local IPv4 address used for outbound traffic (a UDP connect sends no packets)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("192.0.2.1", 9))  # TEST-NET-1: only used to ask the OS for its route
        return sock.getsockname()[0]


def local_subnet() -> str:
    """CIDR of the interface carrying the default route, e.g. "192.168.1.0/24"."""
    import psutil  # lazy: only needed for auto-detection

    ip = primary_ip()
    for addresses in psutil.net_if_addrs().values():
        for addr in addresses:
            if addr.family == socket.AF_INET and addr.address == ip and addr.netmask:
                return str(ipaddress.IPv4Network(f"{ip}/{addr.netmask}", strict=False))
    # Fall back to a /24 when the OS hides the netmask; the user can edit the range.
    return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))


def parse_arp_table(text) -> dict:
    """IP -> MAC ("aa:bb:cc:dd:ee:ff") from any OS's ARP table text; drops incomplete/multicast."""
    table = {}
    for pattern in (_ARP_LINUX, _ARP_OTHER):
        for ip, mac in pattern.findall(text):
            mac = ":".join(part.zfill(2) for part in re.split("[:-]", mac)).lower()
            # First-octet bit 0 set = multicast/broadcast; all zeros = unresolved entry.
            if int(mac[:2], 16) & 1 or mac == "00:00:00:00:00:00":
                continue
            table.setdefault(ip, mac)
    return table


def read_arp_cache() -> dict:
    """Read the OS neighbour (ARP) table without privileges; empty dict if unavailable."""
    try:
        if sys.platform.startswith("linux"):
            return parse_arp_table(Path("/proc/net/arp").read_text())
        if sys.platform == "win32":
            system = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            args = [str(system / "System32" / "arp.exe"), "-a"]
        else:
            args = ["/usr/sbin/arp", "-an"]
        # A GUI launch must not flash a console each time the neighbour cache is read.
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
        out = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                             errors="replace", timeout=3, **options)
        return parse_arp_table(out.stdout)
    except (OSError, subprocess.SubprocessError):
        return {}


def _raise_fd_limit(wanted: int) -> int:
    """Let this process open ``wanted`` sockets at once; return how many it actually may.

    macOS defaults to 256 open files, which would cap the sweep. Windows has no
    per-process descriptor limit for sockets, so it just returns ``wanted``.
    """
    try:
        import resource
    except ImportError:
        return wanted
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = wanted + 256 if hard == resource.RLIM_INFINITY else min(hard, wanted + 256)
    if soft < target:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            soft = target
        except (ValueError, OSError):
            pass
    return max(16, min(wanted, soft - 128))


# --------------------------------------------------------------------------- probing

def _abort_on_close(sock):
    """Close with RST instead of FIN so large scans do not pile up TIME_WAIT sockets."""
    fmt = "HH" if sys.platform == "win32" else "ii"  # Windows' linger struct uses u_short fields
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack(fmt, 1, 0))
    except OSError:
        pass


async def probe(ip, port, timeout):
    """TCP connect probe: True = open, False = closed but host alive (RST), None = no answer.

    Windows may retry a refused SYN, so a short timeout on a closed port
    can look like "no answer"; the ARP cache provides additional local-segment evidence.
    """
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout)
        _abort_on_close(sock)
        return True
    except (ConnectionRefusedError, ConnectionResetError):
        return False
    except (OSError, asyncio.TimeoutError):  # filtered, host down, or network unreachable
        return None
    finally:
        sock.close()


async def ssh_banner(ip, timeout=2.0) -> str:
    """First line an SSH server sends ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"), or ""."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 22), timeout)
    except (OSError, asyncio.TimeoutError):
        return ""
    try:
        line = await asyncio.wait_for(reader.readline(), timeout)
        return line.decode("ascii", "replace").strip()[:200]
    except (OSError, ValueError, asyncio.TimeoutError):  # ValueError: over-long line
        return ""
    finally:
        writer.close()


def guess_os(ports: set, banner: str = "") -> str:
    """Best-effort OS guess from open ports and an SSH banner; always labelled "(guessed)"."""
    text = banner.lower()
    for keyword, name in BANNER_OS:
        if keyword in text:
            return f"{name} (guessed)"
    if {88, 389} <= ports:
        return "Windows Server (domain controller, guessed)"
    # 135/3389/WinRM are Windows-only; bare SMB with SSH is usually Samba on Linux/NAS.
    if ports & {135, 3389, 5985, 5986} or (ports & {139, 445} and 22 not in ports):
        return "Windows (guessed)"
    if 62078 in ports:
        return "iOS (guessed)"
    if 3283 in ports:
        return "macOS (guessed)"  # Apple Remote Desktop
    if 22 in ports:
        return "Linux/Unix (guessed)"
    return "Unknown"


# --------------------------------------------------------------------------- engine

class NetworkDiscovery:
    """Discovers live hosts in one or more IPv4 ranges; see the module docstring for phases."""

    def __init__(self, network_range, ports=None, parallel=None, intensity="normal", depth="standard"):
        """Validate inputs up front so bad ranges or ports fail before any packet is sent.

        :param network_range: CIDR, IP, or comma-separated list of them
        :param ports: optional port spec ("22,80,8000-8100"); replaces the two built-in phases
        :param parallel: max probes in flight (overrides the intensity profile)
        :param intensity: "gentle" | "normal" | "aggressive"
        """
        if intensity not in INTENSITY:
            raise ValueError(f"intensity must be one of {', '.join(INTENSITY)}")
        if depth not in ("quick", "standard"):
            raise ValueError("depth must be quick or standard")
        self.depth = depth
        self.hosts = parse_targets(network_range)
        self.ports = parse_port_spec(ports) if ports else None
        self.intensity = intensity
        self.concurrency, self.timeout = INTENSITY[intensity]
        if parallel is not None:
            if not 1 <= parallel <= 4096:
                raise ValueError("parallel must be between 1 and 4096")
            self.concurrency = max(1, int(parallel))

    def run(self, on_progress=None, on_asset=None, cancel=None):
        """Scan and return (assets, hosts_scanned, elapsed_seconds).

        :param on_progress: callback(done, total, stage) for live progress
        :param on_asset: callback(asset) as hosts are found (the UI streams these)
        :param cancel: threading.Event; when set, the scan stops early with partial results
        """
        start = time.perf_counter()
        noop = lambda *args: None  # noqa: E731 - default no-op callback
        assets = asyncio.run(self._scan(on_progress or noop, on_asset or noop, cancel))
        return assets, len(self.hosts), time.perf_counter() - start

    async def _probe_many(self, pairs, total, stage, results, progress, cancel):
        """Run TCP probes over (ip, port) pairs with bounded concurrency, recording answers."""
        done, last = 0, 0.0
        pairs = iter(pairs)  # shared by all workers: each pair is taken exactly once

        async def worker():
            nonlocal done, last
            for ip, port in pairs:
                if cancel is not None and cancel.is_set():
                    return
                results(ip, port, await probe(ip, port, self.timeout))
                done += 1
                if done == total or time.monotonic() - last > 0.1:  # throttle UI updates
                    last = time.monotonic()
                    progress(done, total, stage)

        workers = min(_raise_fd_limit(self.concurrency), total) or 1
        await asyncio.gather(*(worker() for _ in range(workers)))

    async def _scan(self, progress, emit, cancel):
        """The four scan phases; returns the final asset list."""
        alive, open_ports, macs = set(), defaultdict(set), {}
        last_emit = {}

        def partial(ip):
            # Never wait for a silent address to time out before showing a responsive one.
            # Limit updates per host while its ports are still being probed.
            now = time.monotonic()
            if now - last_emit.get(ip, -1) >= 0.2:
                last_emit[ip] = now
                emit({"IP": ip, "Hostname": "Unknown", "OS": guess_os(open_ports[ip]),
                      "MAC": macs.get(ip, "N/A"), "Source": "Network",
                      "SeenVia": "TCP response",
                      "Ports": ",".join(map(str, sorted(open_ports[ip]))) or "None",
                      "DiscoveryStatus": "Scanning", "ScanDepth": self.depth})

        def record(ip, port, state):
            """Store one probe result: any answer (open or refused) proves the host is up."""
            if state is not None:
                alive.add(ip)
                if state:
                    open_ports[ip].add(port)
                partial(ip)

        # Phase 1: sweep all addresses (or the user's explicit port list).
        first = self.ports or SWEEP_PORTS
        total = len(self.hosts) * len(first)
        log.info(f"[+] Sweeping {len(self.hosts)} hosts x {len(first)} ports "
                 f"({self.intensity}: {self.concurrency} in flight, {self.timeout}s timeout)")
        await self._probe_many(((h, p) for h in self.hosts for p in first), total,
                               "Sweeping for live hosts", record, progress, cancel)

        # Phase 2: the ARP cache reveals firewalled hosts on the local segment.
        targets = set(self.hosts)
        for ip, mac in read_arp_cache().items():
            if ip in targets:
                alive.add(ip)
                macs[ip] = mac
        live = sorted(alive, key=_ip_key)
        for ip in live:  # early, partial rows so the UI fills up immediately
            emit({"IP": ip, "Hostname": "Unknown", "OS": "Unknown", "MAC": macs.get(ip, "N/A"),
                  "Ports": ",".join(map(str, sorted(open_ports[ip]))) or "None", "Source": "Network",
                  "DiscoveryStatus": "Scanning", "ScanDepth": self.depth})

        # Phase 3: extended ports on live hosts, with name lookups running alongside.
        names = asyncio.create_task(lookup_many(live, lambda ip: socket.gethostbyaddr(ip)[0], "Unknown", cancel))
        if self.depth == "standard" and not self.ports and live and not (cancel is not None and cancel.is_set()):
            extra = [p for p in TOP_PORTS if p not in SWEEP_PORTS]
            await self._probe_many(((h, p) for h in live for p in extra), len(live) * len(extra),
                                   f"Fingerprinting {len(live)} live hosts", record, progress, cancel)
        progress(0, 0, "Resolving names")
        hostnames = dict(zip(live, await names))
        banners = {}
        ssh_hosts = iter(ip for ip in live if 22 in open_ports[ip] and self.depth == "standard")

        async def read_banners():
            for ip in ssh_hosts:
                if cancel is not None and cancel.is_set():
                    return
                banners[ip] = await ssh_banner(ip)

        # Fingerprinting must obey a concurrency bound too, even for a full /16.
        await asyncio.gather(*(read_banners() for _ in range(min(32, self.concurrency))))

        assets = []
        for ip in live:
            ports = open_ports[ip]
            asset = {
                "IP": ip,
                "Hostname": hostnames.get(ip, "Unknown"),
                "OS": guess_os(ports, banners.get(ip, "")),
                "Ports": ",".join(map(str, sorted(ports))) or "None",
                "MAC": macs.get(ip, "N/A"),
                "Source": "Network",
                "ScanDepth": self.depth,
                "SeenVia": "TCP response" if ip in last_emit else "OS neighbour cache (may be stale)",
                "DiscoveryStatus": "Stopped early" if cancel is not None and cancel.is_set() else "Finished",
            }
            if banners.get(ip):
                asset["SSHBanner"] = banners[ip]
            log.info(f"    [+] Found: {ip} ({asset['Hostname']}) | OS: {asset['OS']} | Ports: {asset['Ports']}")
            emit(asset)
            assets.append(asset)
        return assets
