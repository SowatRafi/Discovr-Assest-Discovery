"""Driver-free observations and cancellation; no real network probes."""
import threading
import time

from discovr.passive import PassiveDiscovery


def test_cache_observations_are_streamed_without_duplicate_events(monkeypatch):
    cancel = threading.Event()
    reads = []
    def cache():
        reads.append(True)
        if len(reads) == 2:
            cancel.set()
        return {"10.0.0.7": "aa:bb:cc:dd:ee:ff"}
    monkeypatch.setattr("discovr.network.read_arp_cache", cache)
    streamed = []
    assets, count = PassiveDiscovery(timeout=10).run(on_asset=streamed.append, cancel=cancel)
    assert count == 1 and len(streamed) == 1
    assert assets[0]["IP"] == "10.0.0.7"
    assert "may be stale" in assets[0]["SeenVia"]
    assert assets[0]["OS"] == "Unknown"  # never invent details the cache cannot provide


def test_stop_interrupts_passive_wait(monkeypatch):
    cancel = threading.Event()
    monkeypatch.setattr("discovr.network.read_arp_cache", lambda: {"10.0.0.7": "aa:bb:cc:dd:ee:ff"})
    start = time.monotonic()
    assets, count = PassiveDiscovery(timeout=3600).run(on_asset=lambda _: cancel.set(), cancel=cancel)
    assert time.monotonic() - start < 1 and count == 1


def test_cancelled_scan_does_not_read_cache(monkeypatch):
    def unexpected():
        raise AssertionError("Cancelled observation should not read the OS cache")
    monkeypatch.setattr("discovr.network.read_arp_cache", unexpected)
    cancel = threading.Event()
    cancel.set()
    assert PassiveDiscovery().run(cancel=cancel) == ([], 0)


def test_same_mac_with_multiple_addresses_preserves_both(monkeypatch):
    cancel = threading.Event()
    monkeypatch.setattr("discovr.network.read_arp_cache", lambda: {
        "10.0.0.7": "aa:bb:cc:dd:ee:ff", "10.0.0.8": "aa:bb:cc:dd:ee:ff"})
    assets, count = PassiveDiscovery().run(on_progress=lambda *args: cancel.set(), cancel=cancel)
    assert count == 2 and {a["IP"] for a in assets} == {"10.0.0.7", "10.0.0.8"}
