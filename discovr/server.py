"""Local web UI and REST API, served by Discovr itself - no web framework, no internet access.

Security model (the UI can start scans and receives AD passwords):
  * Listens on 127.0.0.1 only - nothing else on the network can connect.
  * Every /api call must carry the per-launch random token in an X-Discovr-Token header.
    The token reaches the browser in the URL *fragment*, which browsers never send to a
    server or leak through Referer headers.
  * Requiring that custom header (and a JSON body) also defeats CSRF: other websites
    cannot add it without a CORS preflight, and this server never sends CORS headers.
  * The Host header must be 127.0.0.1/localhost, which blocks DNS-rebinding attacks.
  * A strict Content-Security-Policy lets only this server's own script and styles run.
  * Credentials are used for the scan in memory and never stored, logged or returned.
"""
import hmac
import importlib.util
import json
import logging
import platform
import re
import secrets
import shutil
import socket
import threading
import time
import uuid
import webbrowser
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from discovr import __version__
from discovr.core import asset_key, is_elevated, merge_assets, to_csv, to_html, to_json

log = logging.getLogger(__name__)

UI_DIR = Path(__file__).with_name("ui")
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/favicon.svg": ("favicon.svg", "image/svg+xml")}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
MAX_BODY = 32 * 1024 * 1024      # large enough to import big JSON reports
MAX_RUNNING = 4                  # concurrent scans per session
EXPORTS = {"csv": (to_csv, "text/csv; charset=utf-8"),
           "json": (to_json, "application/json; charset=utf-8"),
           "html": (to_html, "text/html; charset=utf-8")}


class BadRequest(ValueError):
    """Client error; ``field`` names the form input the UI should highlight."""

    def __init__(self, message, field=None):
        super().__init__(message)
        self.field = field


def _text(params, name, required=False, label=None):
    """Trimmed string parameter; raises BadRequest naming the field when a required one is empty."""
    value = str(params.get(name) or "").strip()
    if required and not value:
        raise BadRequest(f"{label or name} is required", field=name)
    return value or None


def build_scanner(kind, params):
    """Validate UI parameters and return (scanner, human label). Imports providers lazily."""
    if kind == "network":
        from discovr.network import NetworkDiscovery, parse_port_spec, parse_targets

        target = _text(params, "target", True, "Target range")
        ports = _text(params, "ports")
        try:
            parse_targets(target)
        except ValueError as exc:
            raise BadRequest(str(exc), field="target")
        try:
            ports and parse_port_spec(ports)
        except ValueError as exc:
            raise BadRequest(str(exc), field="ports")
        intensity = params.get("intensity") or "normal"
        return (NetworkDiscovery(target, ports, None, intensity, bool(params.get("osDetect"))),
                f"Network {target}")
    if kind == "passive":
        from discovr.passive import PassiveDiscovery

        iface = _text(params, "iface", True, "Interface")
        try:
            seconds = int(params.get("duration") or 120)
        except (TypeError, ValueError):
            raise BadRequest("Duration must be a number of seconds", field="duration")
        if not 10 <= seconds <= 3600:
            raise BadRequest("Duration must be between 10 and 3600 seconds", field="duration")
        return PassiveDiscovery(iface=iface, timeout=seconds), f"Passive on {iface} ({seconds}s)"
    if kind == "ad":
        from discovr.active_directory import ADDiscovery

        domain = _text(params, "domain", True, "Domain")
        username = _text(params, "username", True, "Username")
        password = params.get("password") or ""
        if not password:
            raise BadRequest("Password is required", field="password")
        return (ADDiscovery(domain, username, password, dc=_text(params, "dc"), use_ldaps=bool(params.get("ldaps"))),
                f"Active Directory {domain}")
    if kind in ("aws", "azure", "gcp"):
        from discovr.cloud import CloudDiscovery

        scanner = CloudDiscovery(kind, profile=_text(params, "profile"), region=_text(params, "region") or "all",
                                 subscription=_text(params, "subscription"), project=_text(params, "project"),
                                 zone=_text(params, "zone"), credentials_file=_text(params, "credentialsFile"))
        scope = _text(params, "project") or _text(params, "subscription") or _text(params, "region") or "all"
        return scanner, f"{kind.upper() if kind != 'azure' else 'Azure'} ({scope})"
    raise BadRequest(f"Unknown scan type: {kind}")


def host_info() -> dict:
    """What this machine can do - drives defaults and capability hints in the UI."""
    from discovr.network import local_subnet
    from discovr.passive import capture_warning, list_interfaces

    try:
        subnet = local_subnet()
    except OSError:
        subnet = ""  # offline: the user types a range

    def installed(module):
        """True when an optional provider library is bundled/installed."""
        return importlib.util.find_spec(module) is not None

    return {
        "version": __version__,
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "elevated": is_elevated(),
        "nmap": bool(shutil.which("nmap")),
        "subnet": subnet,
        "interfaces": list_interfaces(),
        "captureWarning": capture_warning(),
        "providers": {"aws": installed("boto3"), "azure": installed("azure.identity"),
                      "gcp": installed("google.auth"), "ad": installed("ldap3"), "passive": installed("scapy")},
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

    def note(self, level, message):
        """Append one line to the activity log shown in the UI."""
        with self.lock:
            self.seq += 1
            self.activity.append({"seq": self.seq, "time": time.time(), "level": level, "message": message})

    def merge(self, assets, source=None):
        """Merge assets into the inventory and bump the version."""
        with self.lock:
            merge_assets(self.inventory, assets, source, index=self.index)
            self.version += 1

    def clear(self):
        """Forget every asset (jobs and the activity log stay)."""
        with self.lock:
            self.inventory.clear()
            self.index.clear()
            self.version += 1

    def start(self, kind, params):
        """Validate, register and launch a scan in a background thread; returns the job."""
        scanner, label = build_scanner(kind, params)
        with self.lock:
            if sum(j["status"] == "running" for j in self.jobs.values()) >= MAX_RUNNING:
                raise BadRequest("Too many scans running - wait for one to finish")
            job = {"id": uuid.uuid4().hex[:8], "kind": kind, "label": label, "status": "running",
                   "stage": "Starting", "done": 0, "total": 0, "found": 0, "error": None,
                   "started": time.time(), "finished": None}
            self.jobs[job["id"]] = job
            self.cancels[job["id"]] = threading.Event()
        threading.Thread(target=self._run, args=(job, kind, scanner), daemon=True,
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

    def _run(self, job, kind, scanner):
        """Body of a scan thread: run, stream progress/assets, record the outcome."""
        cancel, seen = self.cancels[job["id"]], set()

        def progress(done, total, stage):
            with self.lock:
                job.update(done=done, total=total, stage=stage)

        def found(asset):
            self.merge([asset])
            with self.lock:
                seen.add(asset_key(asset))
                job["found"] = len(seen)

        self.note("info", f"Started {job['label']}")
        try:
            if kind in ("network", "passive"):  # these report progress and stream assets live
                result = scanner.run(on_progress=progress, on_asset=found, cancel=cancel)
            else:
                result = scanner.run()
            assets = result[0] if isinstance(result, tuple) else result
            self.merge(assets)
            with self.lock:
                seen.update(asset_key(a) for a in assets)
                job.update(status="cancelled" if cancel.is_set() else "done", found=len(seen), stage="Finished")
            self.note("info", f"Finished {job['label']}: {len(seen)} asset{'' if len(seen) == 1 else 's'}")
        except Exception as exc:  # any scanner failure becomes a readable job error, never a crash
            message = str(exc) or exc.__class__.__name__
            log.warning(f"[!] {job['label']} failed: {message}")
            with self.lock:
                job.update(status="error", error=message, stage="Failed")
        finally:
            with self.lock:
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


class Handler(BaseHTTPRequestHandler):
    """Routes static UI files and the JSON API; every response carries security headers."""

    server_version = "Discovr"   # do not advertise the Python version
    sys_version = ""
    protocol_version = "HTTP/1.1"  # keep-alive makes UI polling cheap

    def log_message(self, fmt, *args):
        """Silence per-request logging (the UI polls every second)."""

    # ------------------------------------------------------------------ plumbing
    def _send(self, status, payload=None, body=None, content_type="application/json; charset=utf-8", headers=()):
        """Write a complete response with security headers; ``payload`` is JSON-encoded."""
        data = body if body is not None else json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", CSP)
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        """Parsed JSON request body (size-capped; JSON content type required)."""
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise BadRequest("Request body too large")
        if self.headers.get_content_type() != "application/json":
            raise BadRequest("Expected an application/json body")
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise BadRequest("Malformed JSON")

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        """Check Host and token, then route; errors become JSON responses."""
        try:
            if self.headers.get("Host", "") not in self.server.allowed_hosts:
                return self._send(403, {"error": "Unexpected Host header"})  # DNS rebinding guard
            url = urlsplit(self.path)
            if method == "GET" and url.path in STATIC:
                name, content_type = STATIC[url.path]
                return self._send(200, body=self.server.static[name], content_type=content_type)
            if not url.path.startswith("/api/"):
                return self._send(404, {"error": "Not found"})
            token = self.headers.get("X-Discovr-Token", "")
            if not hmac.compare_digest(token.encode(), self.server.token.encode()):
                return self._send(401, {"error": "Missing or invalid session token - open the link shown in the terminal"})
            self._route(method, url.path, parse_qs(url.query))
        except BadRequest as exc:
            self._send(400, {"error": str(exc), "field": exc.field})
        except Exception as exc:  # never leak a traceback to the client
            log.exception("UI request failed")
            self._send(500, {"error": f"Internal error ({exc.__class__.__name__})"})

    # ------------------------------------------------------------------ API
    def _route(self, method, path, query):
        """The REST API (also usable by scripts and integrations with the session token)."""
        session = self.server.session
        if method == "GET" and path == "/api/info":
            return self._send(200, host_info())
        if method == "GET" and path == "/api/state":
            since = int((query.get("since") or ["0"])[0] or 0)
            with session.lock:
                return self._send(200, {"version": session.version, "count": len(session.inventory),
                                        "jobs": list(session.jobs.values()),
                                        "activity": [a for a in session.activity if a["seq"] > since]})
        if method == "GET" and path == "/api/assets":
            with session.lock:
                assets = [{**asset, "_id": key} for key, asset in session.inventory.items()]
                return self._send(200, {"version": session.version, "assets": assets})
        if method == "DELETE" and path == "/api/assets":
            session.clear()
            return self._send(200, {"ok": True})
        if method == "POST" and path == "/api/assets/import":
            body = self._body()
            raw = body.get("assets") if isinstance(body, dict) else body
            if not isinstance(raw, list) or not all(isinstance(a, dict) for a in raw):
                raise BadRequest("Expected a Discovr JSON report (a list of assets)")
            clean = [{str(k)[:100]: v for k, v in a.items() if not str(k).startswith("_")} for a in raw]
            session.merge(clean, source="Import")
            session.note("info", f"Imported {len(clean)} assets")
            return self._send(200, {"imported": len(clean)})
        if method == "POST" and path == "/api/scans":
            body = self._body()
            return self._send(202, session.start(str(body.get("kind")), body))
        cancel = re.fullmatch(r"/api/scans/([0-9a-f]{8})/cancel", path)
        if method == "POST" and cancel:
            session.cancel(cancel.group(1))
            return self._send(200, {"ok": True})
        if method == "POST" and path == "/api/export":
            body = self._body()
            fmt = body.get("format")
            if fmt not in EXPORTS:
                raise BadRequest("format must be csv, json or html")
            ids = body.get("ids")
            with session.lock:
                keys = ids if isinstance(ids, list) else list(session.inventory)
                assets = [dict(session.inventory[k]) for k in keys if k in session.inventory]
            render, content_type = EXPORTS[fmt]
            filename = f"discovr_{datetime.now():%Y%m%d_%H%M%S}.{fmt}"
            return self._send(200, body=render(assets).encode("utf-8"), content_type=content_type,
                              headers=[("Content-Disposition", f'attachment; filename="{filename}"')])
        self._send(404, {"error": "Unknown API endpoint"})


def create_server(port=0):
    """Build (but do not start) the UI server on 127.0.0.1; returns (server, url)."""
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    actual = server.server_address[1]
    server.token = secrets.token_urlsafe(24)
    server.session = Session()
    server.allowed_hosts = {f"127.0.0.1:{actual}", f"localhost:{actual}"}
    server.static = {name: (UI_DIR / name).read_bytes() for name, _ in STATIC.values()}
    return server, f"http://127.0.0.1:{actual}/#token={server.token}"


def serve(port=0, open_browser=True):
    """Run the UI until Ctrl+C: prints the private URL and opens it in the default browser."""
    server, url = create_server(port)
    app_log = logging.getLogger("discovr")
    app_log.setLevel(logging.INFO)
    app_log.addHandler(_ActivityHandler(server.session))

    # flush: when stdout is a pipe (launchers, services) Python would otherwise hold the URL back.
    print(f"\n  Discovr {__version__} is running at:\n\n    {url}\n", flush=True)
    print("  This link contains a private session token - do not share it.", flush=True)
    print("  Press Ctrl+C to stop.\n", flush=True)
    if open_browser and not webbrowser.open(url, new=2):
        print("  (Could not open a browser automatically - copy the link above.)")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\n[+] Discovr stopped.")
    finally:
        with server.session.lock:
            for event in server.session.cancels.values():
                event.set()  # stop running scans so the process can exit promptly
        server.server_close()
