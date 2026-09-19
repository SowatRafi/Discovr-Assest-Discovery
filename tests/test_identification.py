"""Protocol evidence and negative results must remain accurate without extra tools."""
import asyncio
import threading

from discovr.identification import device_hint, http_identity, parse_gateways, ssdp_identity
from discovr.network import NetworkDiscovery
from discovr.core import enrich


def test_http_reads_bounded_product_description_without_following_redirects():
    async def run():
        requests = []
        async def serve(reader, writer):
            requests.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b'HTTP/1.1 200 OK\r\nServer: Linux/6.1\r\nContent-Type: text/html\r\nSet-Cookie: secret\r\n\r\n<title>TP-Link Router</title>')
            await writer.drain()
            writer.close()
        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server:
            result = await http_identity("127.0.0.1", server.sockets[0].getsockname()[1])
        assert result == "Linux/6.1 | TP-Link Router" and "secret" not in result
        assert requests[0].startswith(b"GET / HTTP/1.1") and len(requests) == 1
    asyncio.run(run())


def test_http_slow_or_hostile_responses_are_bounded():
    async def run():
        async def serve(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 302 Found\r\nLocation: http://192.0.2.9/\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n" + b"x" * 40000)
            await writer.drain()
            writer.close()
        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server:
            assert await http_identity("127.0.0.1", server.sockets[0].getsockname()[1]) == "nginx"
    asyncio.run(run())


def test_standard_scan_enriches_cache_device_and_explains_silent_ports(monkeypatch):
    async def probe(ip, port, timeout):
        return (port == 80) if ip.endswith(".1") else None
    async def http(ip, port):
        return "Linux/6.1 | TP-Link Router"
    monkeypatch.setattr("discovr.network.probe", probe)
    monkeypatch.setattr("discovr.network.http_identity", http)
    async def ssdp(*args):
        return ""
    monkeypatch.setattr("discovr.network.ssdp_identity", ssdp)
    monkeypatch.setattr("discovr.network.read_arp_cache", lambda: {"192.0.2.2": "00:11:22:33:44:55"})
    monkeypatch.setattr("discovr.network.socket.gethostbyaddr", lambda ip: ("Unknown", [], []))
    rows, _, _ = NetworkDiscovery("192.0.2.1,192.0.2.2").run()
    router, silent = enrich(rows)
    assert router["Tag"] == "[Network]" and router["OS"] == "Linux (guessed)"
    assert router["Ports"] == "80" and router["OSConfidence"] == "Service hint"
    assert router["PortsChecked"] == 44
    assert silent["OS"] == "Unknown" and silent["Tag"] == "[Unknown]"
    assert "No TCP response" in silent["PortStatus"] and silent["TCPResponses"] == 0
    assert "stale" in silent["SeenVia"]


def test_local_firewalled_host_is_identified_and_additional_listeners_are_probed(monkeypatch):
    seen = []
    async def probe(ip, port, timeout):
        seen.append(port)
        return True if port == 45678 else None
    monkeypatch.setattr("discovr.network.probe", probe)
    monkeypatch.setattr("discovr.network.local_listener_ports", lambda ips: {"127.0.0.1": {45678}})
    rows, _, _ = NetworkDiscovery("127.0.0.1").run()
    assert rows[0]["Ports"] == "45678" and rows[0]["LocalHost"] is True
    assert rows[0]["OSConfidence"] == "Local OS" and 45678 in seen
    assert enrich(rows)[0]["Tag"] != "[Unknown]"


def test_quick_does_not_fetch_http_and_cancel_marks_incomplete(monkeypatch):
    event = threading.Event()
    async def probe(ip, port, timeout):
        event.set()
        return False
    async def http(*args):
        raise AssertionError("Quick scan must not request web pages")
    monkeypatch.setattr("discovr.network.probe", probe)
    monkeypatch.setattr("discovr.network.http_identity", http)
    rows, _, _ = NetworkDiscovery("192.0.2.1", depth="quick", parallel=1).run(cancel=event)
    assert rows[0]["DiscoveryStatus"] == "Stopped early" and rows[0]["PortsChecked"] == 1
    assert "Stopped" in rows[0]["PortStatus"]


def test_product_hints_do_not_turn_generic_web_servers_into_hardware():
    assert device_hint("nginx/1.24") == ""
    assert device_hint("HP LaserJet") == "Printer"
    assert device_hint("Synology DiskStation") == "Storage"


def test_gateway_parsing_across_platforms():
    assert parse_gateways("0.0.0.0 0.0.0.0 192.0.2.1 192.0.2.5 45\n0.0.0.0 0.0.0.0 On-link 192.0.2.5 4", "win32") == {"192.0.2.1"}
    assert parse_gateways("eth0 00000000 010200C0 0003 0 0 100 00000000 0 0 0", "linux") == {"192.0.2.1"}
    assert parse_gateways("route to: default\n gateway: 192.0.2.1\n interface: en0", "darwin") == {"192.0.2.1"}


def test_ssdp_proves_cached_host_is_present_even_when_tcp_is_silent(monkeypatch):
    async def probe(*args):
        return None
    async def ssdp(*args):
        return "OpenWrt/23.05 UPnP/1.1 router/1"
    monkeypatch.setattr("discovr.network.probe", probe)
    monkeypatch.setattr("discovr.network.ssdp_identity", ssdp)
    monkeypatch.setattr("discovr.network.read_arp_cache", lambda: {"192.0.2.9": "00:11:22:33:44:55"})
    monkeypatch.setattr("discovr.network.socket.gethostbyaddr", lambda ip: ("Unknown", [], []))
    rows, _, _ = NetworkDiscovery("192.0.2.9").run()
    assert rows[0]["SeenVia"] == "SSDP response" and rows[0]["OS"] == "OpenWrt Linux (guessed)"
    assert "offline" not in rows[0]["PortStatus"] and rows[0]["TCPResponses"] == 0


def test_ssdp_unicast_response_only_reads_server_metadata():
    async def run():
        loop = asyncio.get_running_loop()
        seen = []
        class Device(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
            def datagram_received(self, data, addr):
                seen.append(data)
                self.transport.sendto(b"HTTP/1.1 200 OK\r\nSERVER: Linux/5.4 UPnP/1.1 router/1\r\nLOCATION: http://192.0.2.9/never-fetch\r\n\r\n", addr)
        transport, _ = await loop.create_datagram_endpoint(Device, local_addr=("127.0.0.1", 0))
        try:
            result = await ssdp_identity("127.0.0.1", port=transport.get_extra_info("sockname")[1])
            assert result == "Linux/5.4 UPnP/1.1 router/1"
            assert len(seen) == 1 and b"M-SEARCH * HTTP/1.1" in seen[0]
            assert b"239.255.255.250" not in seen[0]
        finally:
            transport.close()
    asyncio.run(run())
