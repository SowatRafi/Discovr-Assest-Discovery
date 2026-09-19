"""Desktop-independent discovery controller; no web server or UI dependencies."""
from copy import deepcopy
import importlib.util
import logging
import platform
import re
import socket
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from discovr import __version__
from discovr.core import is_elevated, merge_assets
from discovr.scan import ScanCancelled

log = logging.getLogger(__name__)
MAX_RUNNING = 4


class BadRequest(ValueError):
    """Client error; ``field`` names the form input the UI should highlight."""

    def __init__(self, message, field=None):
        super().__init__(message)
        self.field = field


def _text(params, name, required=False, label=None):
    """Trimmed string parameter; raises BadRequest naming the field when a required one is empty."""
    value = params.get(name)
    if value is not None and not isinstance(value, str):
        raise BadRequest(f"{label or name} must be text", field=name)
    value = (value or "").strip()
    if required and not value:
        raise BadRequest(f"{label or name} is required", field=name)
    return value or None


def _file(params, name, label):
    """Optional path parameter that must point to an existing file (checked before the scan starts)."""
    path = _text(params, name)
    if path and not Path(path).is_file():
        raise BadRequest(f"{label} not found: {path}", field=name)
    return path


def build_scanner(kind, params):
    """Validate UI parameters and return (scanner, human label). Imports providers lazily."""
    for name in ("osDetect", "ldaps", "capturePackets"):
        if name in params and not isinstance(params[name], bool):
            raise BadRequest(f"{name} must be true or false", field=name)
    # Reject obsolete clients explicitly; never start an external-tool mode silently.
    for name in ("osDetect", "capturePackets"):
        if params.get(name):
            raise BadRequest("This portable app uses built-in discovery only", field=name)
    if kind == "network":
        from discovr.network import NetworkDiscovery, parse_port_spec, parse_targets

        target = _text(params, "target", True, "Target range")
        ports = _text(params, "ports")
        try:
            parse_targets(target)
        except ValueError as exc:
            message = str(exc) if "larger than" in str(exc) else "Enter an IPv4 address or range, e.g. 192.168.1.0/24."
            raise BadRequest(message, field="target")
        try:
            ports and parse_port_spec(ports)
        except ValueError as exc:
            raise BadRequest("Use TCP ports from 1 to 65535, e.g. 22,443 or 8000-8010.", field="ports") from exc
        intensity = params.get("intensity") or "normal"
        if intensity not in ("gentle", "normal", "aggressive"):
            raise BadRequest("Choose gentle, normal or aggressive", field="intensity")
        depth = _text(params, "depth") or "standard"
        if depth not in ("quick", "standard"):
            raise BadRequest("Choose quick or standard discovery", field="depth")
        return (NetworkDiscovery(target, ports, None, intensity, depth),
                f"Network {target}")
    if kind == "passive":
        from discovr.passive import PassiveDiscovery

        try:
            seconds = int(params.get("duration") or 120)
        except (TypeError, ValueError):
            raise BadRequest("Duration must be a number of seconds", field="duration")
        if not 10 <= seconds <= 3600:
            raise BadRequest("Duration must be between 10 and 3600 seconds", field="duration")
        return PassiveDiscovery(timeout=seconds), f"OS neighbour cache ({seconds}s)"
    if kind == "ad":
        from discovr.active_directory import ADDiscovery

        domain = _text(params, "domain", True, "Domain")
        username = _text(params, "username", True, "Username")
        password = params.get("password") or ""
        if not isinstance(password, str):
            raise BadRequest("Password must be text", field="password")
        if not password:
            raise BadRequest("Password is required", field="password")
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", domain) or ".." in domain:
            raise BadRequest("Enter a DNS domain name", field="domain")
        return (ADDiscovery(domain, username, password, dc=_text(params, "dc"), use_ldaps=bool(params.get("ldaps")),
                            ca_file=_file(params, "caFile", "CA certificate file")),
                f"Active Directory {domain}")
    if kind in ("aws", "azure", "gcp"):
        from discovr.cloud import CloudDiscovery

        credentials = {}
        fields = ("accessKey", "secretKey") if kind == "aws" else ("tenantId", "clientId", "clientSecret") if kind == "azure" else ()
        if any(params.get(f) for f in fields):
            credentials = {f: _text(params, f, True) for f in fields}
            if kind == "aws":
                credentials["sessionToken"] = _text(params, "sessionToken")
        scanner = CloudDiscovery(kind, profile=_text(params, "profile"), region=_text(params, "region") or "all",
                                 subscription=_text(params, "subscription"), project=_text(params, "project"),
                                 zone=_text(params, "zone"),
                                 credentials_file=_file(params, "credentialsFile", "Service-account key file"),
                                 runtime_credentials=credentials)
        scope = _text(params, "project") or _text(params, "subscription") or _text(params, "region") or "all"
        return scanner, f"{kind.upper() if kind != 'azure' else 'Azure'} ({scope})"
    raise BadRequest(f"Unknown scan type: {kind}")


def host_info() -> dict:
    """What this machine can do - drives defaults and capability hints in the UI."""
    from discovr.network import local_subnet

    try:
        subnet = local_subnet()
    except OSError:
        subnet = ""  # offline: the user types a range

    def installed(module):
        """True when an optional provider library is bundled/installed."""
        try:
            return importlib.util.find_spec(module) is not None
        except (ImportError, ModuleNotFoundError):
            return False

    return {
        "version": __version__,
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "elevated": is_elevated(),
        "subnet": subnet,
        "providers": {"aws": installed("boto3"), "azure": installed("azure.identity"),
                      "gcp": installed("google.auth"), "ad": installed("ldap3"), "passive": True},
    }


class Session:
    """In-memory state for one UI session: scan jobs, the merged inventory and an activity log."""

    def __init__(self):
        self.lock = threading.RLock()
        self.jobs = {}          # id -> public job dict
        self.cancels = {}       # id -> threading.Event (kept out of the public dict)
        self.inventory = {}     # key -> asset
        self.index = {}         # identity -> key, so streaming merges stay O(1)
        self.version = 0        # bumped on every inventory change; the UI polls it cheaply
        self.activity = deque(maxlen=500)
        self.seq = 0
        self.closed = False

    def note(self, level, message):
        """Append one line to the activity log shown in the UI."""
        with self.lock:
            self.seq += 1
            self.activity.append({"seq": self.seq, "time": time.time(), "level": level, "message": message})

    def merge(self, assets, source=None):
        """Merge assets into the inventory and bump the version."""
        with self.lock:
            keys = []
            merge_assets(self.inventory, assets, source, index=self.index, keys=keys)
            self.version += 1
            return keys

    def clear(self, stop_running=False):
        """Forget every asset (jobs and the activity log stay)."""
        with self.lock:
            if self.cancels and not stop_running:
                raise BadRequest("Stop running scans before clearing the inventory")
            if stop_running:
                # A late callback/final result from a cancelled scan must never
                # repopulate an inventory the operator explicitly cleared.
                for job_id in self.cancels:
                    self.jobs[job_id]["discard_results"] = True
                self.stop_all()
            self.inventory.clear()
            self.index.clear()
            self.version += 1

    def snapshot(self, previous_version=-1, since=0):
        """Copy mutable data under the lock; GUI models must never read a worker's dicts."""
        with self.lock:
            return {"version": self.version,
                    "assets": deepcopy(list(self.inventory.values())) if previous_version != self.version else None,
                    "keys": list(self.inventory) if previous_version != self.version else None,
                    "jobs": deepcopy(list(self.jobs.values())),
                    "activity": [dict(a) for a in self.activity if a["seq"] > since]}

    def stop_all(self):
        """Request cooperative cancellation without blocking the desktop event loop."""
        with self.lock:
            for key, event in self.cancels.items():
                event.set()
                self.jobs[key]["stage"] = "Stopping"

    def import_report(self, body):
        """Validate the whole report before merging anything, including imported identities."""
        raw = body.get("assets") if isinstance(body, dict) else body
        if not isinstance(raw, list) or not all(isinstance(a, dict) for a in raw):
            raise BadRequest("Expected a Discovr JSON report (a list of assets)")
        if len(raw) > 65536:
            raise BadRequest("Import is limited to 65,536 assets")
        scalars = {"IP", "MAC", "Hostname", "OS", "Source", "Cloud", "InstanceID", "AccountID",
                   "SubscriptionID", "ProjectID", "Region", "Zone", "Ports", "ExposedPorts"}
        booleans = {"InternetExposed", "Enabled", "Stale", "DomainController"}
        for asset in raw:
            for key, value in asset.items():
                if key in scalars and value is not None and not isinstance(value, str):
                    raise BadRequest(f"{key} must be text")
                if key in booleans and value is not None and not isinstance(value, bool):
                    raise BadRequest(f"{key} must be true or false")
        clean = [{str(k)[:100]: v for k, v in a.items() if not str(k).startswith("_")} for a in raw]
        with self.lock:
            if self.closed:
                raise BadRequest("This discovery session is closed")
            self.merge(clean, source="Import")
        self.note("info", f"Imported {len(clean)} assets")
        return len(clean)

    def start(self, kind, params):
        """Validate, register and launch a scan in a background thread; returns the job."""
        environment = _text(params, "environment")
        if environment and len(environment) > 80:
            raise BadRequest("Environment must be 80 characters or fewer", field="environment")
        scope = _text(params, "target") if kind == "network" else None
        scanner, label = build_scanner(kind, params)
        with self.lock:
            # SDK preparation can finish after a user closes the desktop. Never launch
            # new discovery work once that session has been closed.
            if self.closed:
                raise BadRequest("This discovery session is closed")
            if sum(j["status"] == "running" for j in self.jobs.values()) >= MAX_RUNNING:
                raise BadRequest("Too many scans running - wait for one to finish")
            finished = [key for key, old in self.jobs.items() if old["finished"] is not None]
            while len(self.jobs) >= 100 and finished:
                self.jobs.pop(finished.pop(0))
            job = {"id": uuid.uuid4().hex[:8], "kind": kind, "label": label, "status": "running",
                   "stage": "Starting", "done": 0, "total": 0, "found": 0, "error": None,
                   "started": time.time(), "finished": None}
            job["warnings"] = []
            self.jobs[job["id"]] = job
            self.cancels[job["id"]] = threading.Event()
        threading.Thread(target=self._run, args=(job, kind, scanner, environment, scope), daemon=True,
                         name=f"discovr-job-{job['id']}").start()
        return dict(job)

    def cancel(self, job_id):
        """Ask a running scan to stop; it finishes with the results gathered so far."""
        with self.lock:
            event = self.cancels.get(job_id)
            if event is None:
                raise BadRequest("No running scan with that id")
            event.set()
            self.jobs[job_id]["stage"] = "Stopping"

    def close(self):
        with self.lock:
            self.closed = True
            self.stop_all()

    def _run(self, job, kind, scanner, environment=None, scope=None):
        """Body of a scan thread: run, stream progress/assets, record the outcome."""
        cancel, seen = self.cancels[job["id"]], set()

        def progress(done, total, stage):
            with self.lock:
                job.update(done=done, total=total, stage="Stopping" if cancel.is_set() else stage)

        def found(asset):
            with self.lock:
                if job.get("discard_results"):
                    return
                keys = self.merge([decorate(asset)])
                seen.update(keys)
                job["found"] = len(seen)

        def decorate(asset):
            # Operator labels are inventory metadata, never credentials or provider tags.
            result = dict(asset)
            if environment:
                result["Environment"] = environment
            if scope:
                result["ScanScope"] = scope
            return result

        self.note("info", f"Started {job['label']}")
        try:
            result = scanner.run(on_progress=progress, on_asset=found, cancel=cancel)
            assets = result[0] if isinstance(result, tuple) else result
            with self.lock:
                keys = [] if job.get("discard_results") else self.merge([decorate(asset) for asset in assets])
                seen.update(keys)
                warnings = list(getattr(scanner, "warnings", []))
                status = "cancelled" if cancel.is_set() else "partial" if warnings else "done"
                job.update(status=status, found=len(seen), stage="Stopped" if cancel.is_set() else "Finished",
                           warnings=warnings)
            self.note("info", f"Finished {job['label']}: {len(seen)} asset{'' if len(seen) == 1 else 's'}")
        except ScanCancelled:
            with self.lock:
                job.update(status="cancelled", stage="Stopped")
            self.note("info", f"Stopped {job['label']}: kept {len(seen)} assets")
        except Exception as exc:  # any scanner failure becomes a readable job error, never a crash
            message = str(exc) or exc.__class__.__name__
            log.warning(f"[!] {job['label']} failed: {message}")
            with self.lock:
                job.update(status="error", error=message, stage="Failed")
        finally:
            if hasattr(scanner, "password"):
                scanner.password = None
            if hasattr(scanner, "runtime_credentials"):
                scanner.runtime_credentials.clear()
            with self.lock:
                job["warnings"] = list(getattr(scanner, "warnings", []))
                job["finished"] = time.time()
                self.cancels.pop(job["id"], None)


class _ActivityHandler(logging.Handler):
    """Mirrors Discovr's own log lines into the UI activity panel."""

    def __init__(self, session):
        super().__init__(logging.INFO)
        self.session = session

    def emit(self, record):
        try:
            self.session.note(record.levelname.lower(), record.getMessage().strip())
        except Exception:
            self.handleError(record)
