"""Observe existing OS neighbour entries without sending packets or loading drivers.

Cached entries may be stale. Devices absent from the cache cannot be found here.
"""
import logging
import time

log = logging.getLogger(__name__)


class PassiveDiscovery:
    """Stream IP/MAC observations using only facilities supplied by the OS."""

    def __init__(self, timeout=180):
        self.timeout = timeout
        self.devices = {}

    def run(self, on_progress=None, on_asset=None, cancel=None):
        """Return (assets, count); Stop interrupts the delay between cache reads."""
        from discovr.network import read_arp_cache

        start = time.monotonic()
        try:
            while time.monotonic() - start < self.timeout:
                if cancel is not None and cancel.is_set():
                    break
                for ip, mac in read_arp_cache().items():
                    asset = {"IP": ip, "MAC": mac, "Hostname": "Unknown", "OS": "Unknown",
                             "Ports": "N/A", "Source": "Passive",
                             "SeenVia": "OS neighbour cache (may be stale)"}
                    # Preserve multiple IPs observed for the same hardware address.
                    key = (mac, ip)
                    if self.devices.get(key) != asset:
                        self.devices[key] = asset
                        if on_asset:
                            on_asset(dict(asset))
                if on_progress:
                    on_progress(int(time.monotonic() - start), self.timeout, "Watching OS neighbour cache")
                delay = min(1, max(0, self.timeout - (time.monotonic() - start)))
                if cancel is not None:
                    cancel.wait(delay)
                else:
                    time.sleep(delay)
        except KeyboardInterrupt:
            log.info("[+] Stopped watching the neighbour cache")
        assets = list(self.devices.values())
        return assets, len(assets)
