"""Regressions for portable operation, inventory accuracy and interrupted discovery."""
import asyncio
import threading
import time
from types import SimpleNamespace

import pytest

from discovr.core import enrich, merge_assets
from discovr.lookup import lookup_many
from discovr.scan import ScanCancelled, ScanControl
from discovr.session import Session, build_scanner


def test_cloud_private_ip_collisions_do_not_hide_machines():
    inventory, index = {}, {}
    common = {"IP": "10.0.0.4", "Hostname": "web", "OS": "Linux", "InstanceID": "i-1", "Cloud": "AWS"}
    for account, region, instance in [("a", "r1", "i-1"), ("b", "r1", "i-1"), ("a", "r2", "i-1"), ("a", "r1", "i-2")]:
        merge_assets(inventory, [{**common, "AccountID": account, "Region": region, "InstanceID": instance}], index=index)
    merge_assets(inventory, [{"IP": "10.0.0.4", "Hostname": "web", "Source": "Network"}], index=index)
    assert len(inventory) == 5


def test_repeat_cloud_scan_refreshes_state_ip_and_exposure():
    inventory, index = {}, {}
    vm = {"Cloud": "AWS", "Source": "AWS", "AccountID": "a", "Region": "r", "InstanceID": "i-1",
          "IP": "10.0.0.1", "State": "running", "InternetExposed": True, "ExposedPorts": "22", "Ports": "22"}
    merge_assets(inventory, [vm], index=index)
    key = next(iter(inventory))
    merge_assets(inventory, [{**vm, "IP": "10.0.0.2", "State": "stopped", "Ports": "None",
                              "InternetExposed": False, "ExposedPorts": "None"}], index=index)
    assert list(inventory) == [key]
    assert inventory[key]["IP"] == "10.0.0.2" and inventory[key]["State"] == "stopped"
    assert not inventory[key]["InternetExposed"] and inventory[key]["Ports"] == "None"


def test_full_dns_names_and_ambiguous_short_names_stay_separate():
    inventory = {}
    merge_assets(inventory, [{"Hostname": "pc1.east.example"}, {"Hostname": "pc1.west.example"},
                             {"Hostname": "nas", "IP": "10.0.0.1"}, {"Hostname": "nas", "IP": "10.0.0.2"}])
    merge_assets(inventory, [{"Hostname": "nas", "OS": "Linux"}])
    assert len(inventory) == 5


def test_directory_first_then_network_merges_without_duplicate():
    inventory, index = {}, {}
    merge_assets(inventory, [{"Hostname": "pc1.example", "OS": "Windows 11", "Source": "AD"}], index=index)
    merge_assets(inventory, [{"IP": "10.0.0.1", "Hostname": "PC1.EXAMPLE.", "Ports": "445",
                              "Source": "Network"}], index=index)
    assert len(inventory) == 1 and next(iter(inventory.values()))["IP"] == "10.0.0.1"


def test_cloud_firewall_ports_do_not_turn_vm_into_printer():
    for ports in ("*", "9100", "62078", "1883"):
        [asset] = enrich([{"Cloud": "AWS", "OS": "Unknown", "Hostname": "printer-server", "Ports": ports}])
        assert asset["AgentCapable"] and asset["Tag"] == "[Server]"


def test_cancel_prevents_fetching_next_page():
    cancel = threading.Event()
    calls = []

    def pages():
        calls.append(1)
        yield {"value": 1}
        calls.append(2)
        yield {"value": 2}

    iterator = ScanControl(cancel=cancel).pages(pages())
    assert next(iterator) == {"value": 1}
    cancel.set()
    with pytest.raises(ScanCancelled):
        next(iterator)
    assert calls == [1]


def test_stalled_dns_has_a_deadline():
    release = threading.Event()
    start = time.monotonic()
    try:
        result = asyncio.run(lookup_many([1, 2], lambda _: release.wait(5), "Unknown", timeout=0.05))
        assert result == ["Unknown", "Unknown"]
        assert time.monotonic() - start < 1
    finally:
        release.set()


def wait_finished(session, job):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        with session.lock:
            if session.jobs[job["id"]]["finished"] is not None:
                return session.jobs[job["id"]]
        time.sleep(0.01)
    pytest.fail("scan did not finish")


def test_all_provider_jobs_can_stop_and_keep_partial_results(monkeypatch):
    ready = threading.Event()

    class Scanner:
        def run(self, on_progress, on_asset, cancel):
            on_asset({"IP": "10.0.0.1", "Source": "AD"})
            ready.set()
            assert cancel.wait(2)
            ScanControl(cancel=cancel).check()

    monkeypatch.setattr("discovr.session.build_scanner", lambda *args: (Scanner(), "Directory"))
    session = Session()
    job = session.start("ad", {})
    assert ready.wait(2)
    session.cancel(job["id"])
    assert wait_finished(session, job)["status"] == "cancelled"
    assert len(session.inventory) == 1


def test_partial_scan_is_distinguished_from_success_and_secrets_are_released(monkeypatch):
    class Scanner:
        warnings = ["Region r2 is unavailable"]
        runtime_credentials = {"secretKey": "private-test-value"}

        def run(self, **kwargs):
            return [{"IP": "10.0.0.1"}]

    scanner = Scanner()
    monkeypatch.setattr("discovr.session.build_scanner", lambda *args: (scanner, "Cloud"))
    session = Session()
    result = wait_finished(session, session.start("aws", {}))
    assert result["status"] == "partial" and result["warnings"] == scanner.warnings
    assert scanner.runtime_credentials == {}


def test_passive_default_needs_neither_interface_nor_capture_driver(monkeypatch):
    cancel = threading.Event()
    monkeypatch.setattr("discovr.network.read_arp_cache", lambda: {"10.0.0.7": "aa:bb:cc:dd:ee:ff"})
    scanner, _ = build_scanner("passive", {"duration": "10"})
    result, found = scanner.run(on_asset=lambda _: cancel.set(), cancel=cancel)
    assert found == 1 and result[0]["IP"] == "10.0.0.7"
    assert "may be stale" in result[0]["SeenVia"]


def test_cloud_credentials_are_accepted_without_cli():
    aws, _ = build_scanner("aws", {"accessKey": "key", "secretKey": "secret", "sessionToken": "token"})
    assert aws.runtime_credentials == {"accessKey": "key", "secretKey": "secret", "sessionToken": "token"}
    azure, _ = build_scanner("azure", {"tenantId": "tenant", "clientId": "client", "clientSecret": "secret"})
    assert azure.runtime_credentials["tenantId"] == "tenant"


def test_clear_rejected_while_scan_can_still_emit():
    from discovr.session import BadRequest
    session = Session()
    session.cancels["running"] = threading.Event()
    with pytest.raises(BadRequest, match="Stop running"):
        session.clear()


def test_job_count_uses_stable_inventory_identity_when_ip_is_learned(monkeypatch):
    class Scanner:
        def run(self, on_asset, **kwargs):
            on_asset({"Hostname": "pc1.example", "IP": "N/A", "Source": "AD"})
            asset = {"Hostname": "pc1.example", "IP": "10.0.0.1", "Source": "AD"}
            on_asset(asset)
            return [asset]

    monkeypatch.setattr("discovr.session.build_scanner", lambda *args: (Scanner(), "Directory"))
    session = Session()
    job = wait_finished(session, session.start("ad", {}))
    assert job["found"] == len(session.inventory) == 1


def test_repeated_passive_updates_preserve_network_service_evidence():
    inventory, index = {}, {}
    network = {"IP": "10.0.0.1", "Source": "Network", "Ports": "22,443"}
    passive = {"IP": "10.0.0.1", "Source": "Passive", "Ports": "N/A"}
    for asset in (network, passive, passive):
        merge_assets(inventory, [asset], index=index)
    assert next(iter(inventory.values()))["Ports"] == "22,443"
    merge_assets(inventory, [{**network, "Ports": "22"}], index=index)
    assert next(iter(inventory.values()))["Ports"] == "22"
