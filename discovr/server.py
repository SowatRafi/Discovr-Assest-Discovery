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
from discovr.core import is_elevated, merge_assets, to_csv, to_html, to_json
from discovr.scan import ScanCancelled

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


from discovr.session import BadRequest, Session, build_scanner, host_info, _ActivityHandler


class Handler(BaseHTTPRequestHandler):
    """Routes static UI files and the JSON API; every response carries security headers."""

    server_version = "Discovr"   # do not advertise the Python version
    sys_version = ""
    protocol_version = "HTTP/1.1"  # keep-alive makes UI polling cheap
    timeout = 30                   # seconds per socket read: idle or trickling (slowloris) clients are dropped

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

    def _read_body(self):
        """Consume the request body up front, size-capped.

        Every route reads it (even ones that ignore it): unread bytes would be parsed as the
        start of the next request on the same keep-alive connection. Invalid lengths
        (negative, non-numeric, over MAX_BODY) and chunked uploads, which this server cannot
        decode, close the connection instead.
        """
        if "Transfer-Encoding" in self.headers:
            self.close_connection = True
            raise BadRequest("Chunked request bodies are not supported")
        raw_length = self.headers.get("Content-Length")
        if len(self.headers.get_all("Content-Length", [])) > 1:
            self.close_connection = True
            raise BadRequest("Duplicate Content-Length headers are not supported")
        if raw_length is None:
            return b""
        length = int(raw_length) if len(raw_length) <= 10 and raw_length.strip().isdigit() else -1
        if not 0 <= length <= MAX_BODY:
            self.close_connection = True
            raise BadRequest("Invalid or too large Content-Length")
        return self.rfile.read(length)

    def _body(self):
        """The request body parsed as JSON (an application/json content type is required)."""
        if self.headers.get_content_type() != "application/json":
            raise BadRequest("Expected an application/json body")
        try:
            return json.loads(self._raw or b"{}")
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise BadRequest("Malformed JSON")

    def _object_body(self):
        body = self._body()
        if not isinstance(body, dict):
            raise BadRequest("Expected a JSON object")
        return body

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        """Drain the body, check Host and token, then route; errors become JSON responses."""
        try:
            self._raw = self._read_body()
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
                return self._send(401, {"error": "Missing or invalid session token - reopen Discovr from its app icon"})
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
        if method == "POST" and path == "/api/shutdown":
            self._send(202, {"ok": True})
            with session.lock:
                for event in session.cancels.values():
                    event.set()
            # shutdown must run outside the serve_forever thread to avoid deadlock.
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if method == "GET" and path == "/api/info":
            return self._send(200, host_info())
        if method == "GET" and path == "/api/state":
            try:
                since = int((query.get("since") or ["0"])[0] or 0)
            except ValueError:
                raise BadRequest("since must be an integer")
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
            count = session.import_report(body)
            return self._send(200, {"imported": count})
        if method == "POST" and path == "/api/scans":
            body = self._object_body()
            return self._send(202, session.start(str(body.get("kind")), body))
        cancel = re.fullmatch(r"/api/scans/([0-9a-f]{8})/cancel", path)
        if method == "POST" and cancel:
            session.cancel(cancel.group(1))
            return self._send(200, {"ok": True})
        if method == "POST" and path == "/api/export":
            body = self._object_body()
            fmt = body.get("format")
            if fmt not in EXPORTS:
                raise BadRequest("format must be csv, json or html")
            ids = body.get("ids")
            if ids is not None and (not isinstance(ids, list) or not all(isinstance(k, str) for k in ids)):
                raise BadRequest("ids must be a list of asset IDs")
            with session.lock:
                keys = ids if isinstance(ids, list) else list(session.inventory)
                assets = [dict(session.inventory[k]) for k in keys if k in session.inventory]
            render, content_type = EXPORTS[fmt]
            filename = f"discovr_{datetime.now():%Y%m%d_%H%M%S}.{fmt}"
            return self._send(200, body=render(assets).encode("utf-8"), content_type=content_type,
                              headers=[("Content-Disposition", f'attachment; filename="{filename}"')])
        self._send(404, {"error": "Unknown API endpoint"})


class LocalHTTPServer(ThreadingHTTPServer):
    """Bound concurrent connections, including idle browser keep-alive sockets."""

    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def create_server(port=0):
    """Build (but do not start) the UI server on 127.0.0.1; returns (server, url)."""
    server = LocalHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    actual = server.server_address[1]
    server.token = secrets.token_urlsafe(24)
    server.session = Session()
    server.allowed_hosts = {f"127.0.0.1:{actual}", f"localhost:{actual}"}
    server.static = {name: (UI_DIR / name).read_bytes() for name, _ in STATIC.values()}
    return server, f"http://127.0.0.1:{actual}/#token={server.token}"


def serve(port=0, open_browser=True, on_ready=None, browser_opener=None):
    """Run until Quit or Ctrl+C; on_ready supplies the launcher with the private URL."""
    server, url = create_server(port)
    app_log = logging.getLogger("discovr")
    app_log.setLevel(logging.INFO)
    activity_handler = _ActivityHandler(server.session)
    app_log.addHandler(activity_handler)

    # flush: when stdout is a pipe (launchers, services) Python would otherwise hold the URL back.
    print(f"\n  Discovr {__version__} is running at:\n\n    {url}\n", flush=True)
    print("  This link contains a private session token - do not share it.", flush=True)
    print("  Press Ctrl+C to stop.\n", flush=True)
    try:
        if on_ready:
            on_ready(url)
        if open_browser and not (browser_opener or webbrowser.open)(url, new=2):
            raise OSError("No default browser could be opened. Set a default browser in your computer's settings.")
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\n[+] Discovr stopped.")
    finally:
        with server.session.lock:
            for event in server.session.cancels.values():
                event.set()  # stop running scans so the process can exit promptly
        server.server_close()
        app_log.removeHandler(activity_handler)
        activity_handler.close()
