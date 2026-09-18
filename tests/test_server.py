"""Tests for the local web UI server (discovr.server): security guards and the scan API."""
import http.client
import json
import socket
import threading
import time

import pytest

from discovr.server import create_server


@pytest.fixture()
def ui():
    """A running UI server on a random localhost port; yields (port, token)."""
    server, url = create_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1], server.token
    server.shutdown()
    server.server_close()


def request(port, method, path, token=None, body=None, host=None, content_type="application/json"):
    """Send one request; returns (status, headers, decoded body)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    if token:
        headers["X-Discovr-Token"] = token
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = content_type
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    is_json = resp.getheader("Content-Type", "").startswith("application/json")
    return resp.status, resp, json.loads(raw) if is_json else raw.decode()


def test_static_ui_has_strict_security_headers(ui):
    port, _ = ui
    status, resp, page = request(port, "GET", "/")
    assert status == 200 and "<title>Discovr</title>" in page
    assert "script-src 'self'" in resp.getheader("Content-Security-Policy")
    assert resp.getheader("X-Content-Type-Options") == "nosniff"
    assert resp.getheader("Server").startswith("Discovr")          # no Python version banner


def test_api_requires_token_and_localhost_host_header(ui):
    port, token = ui
    assert request(port, "GET", "/api/info")[0] == 401
    assert request(port, "GET", "/api/info", token="wrong")[0] == 401
    assert request(port, "GET", "/api/info", token=token, host="evil.example:80")[0] == 403   # DNS rebinding
    status, _, info = request(port, "GET", "/api/info", token=token)
    assert status == 200 and info["version"] and "providers" in info


def test_json_body_required_and_validation_names_the_field(ui):
    port, token = ui
    status, _, err = request(port, "POST", "/api/scans", token, {"kind": "network", "target": "10.0.0.0/8"})
    assert status == 400 and err["field"] == "target"
    status, _, err = request(port, "POST", "/api/scans", token, {"kind": "network", "target": "127.0.0.1",
                                                                  "ports": "99999"})
    assert status == 400 and err["field"] == "ports"
    status, _, err = request(port, "POST", "/api/scans", token, {"kind": "ad", "domain": "corp.local",
                                                                  "username": "u"})
    assert status == 400 and err["field"] == "password"
    # A form-encoded body (what a cross-site <form> could send) is rejected.
    assert request(port, "POST", "/api/scans", token, {"kind": "network"}, content_type="text/plain")[0] == 400


def test_network_scan_end_to_end_then_export_import_and_clear(ui):
    port, token = ui
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        open_port = listener.getsockname()[1]
        status, _, job = request(port, "POST", "/api/scans", token,
                                 {"kind": "network", "target": "127.0.0.1", "ports": str(open_port)})
        assert status == 202 and job["status"] == "running"
        deadline = time.time() + 20
        while time.time() < deadline:
            state = request(port, "GET", "/api/state", token)[2]
            if state["jobs"][0]["status"] != "running":
                break
            time.sleep(0.2)
    assert state["jobs"][0]["status"] == "done" and state["jobs"][0]["found"] == 1
    assert any("Finished" in line["message"] for line in state["activity"])

    assets = request(port, "GET", "/api/assets", token)[2]["assets"]
    assert [a["IP"] for a in assets] == ["127.0.0.1"] and assets[0]["Tag"] and assets[0]["_id"]

    status, resp, csv_text = request(port, "POST", "/api/export", token, {"format": "csv", "ids": [assets[0]["_id"]]})
    assert status == 200 and "attachment" in resp.getheader("Content-Disposition")
    assert csv_text.splitlines()[0].startswith("IP,Hostname,OS,Ports")

    status, _, result = request(port, "POST", "/api/assets/import", token,
                                [{"IP": "10.9.9.9", "Hostname": "imported", "OS": "Linux"}])
    assert status == 200 and result["imported"] == 1
    assert len(request(port, "GET", "/api/assets", token)[2]["assets"]) == 2

    assert request(port, "DELETE", "/api/assets", token)[0] == 200
    assert request(port, "GET", "/api/assets", token)[2]["assets"] == []


def test_cancel_unknown_job(ui):
    port, token = ui
    assert request(port, "POST", "/api/scans/deadbeef/cancel", token, {})[0] == 400
