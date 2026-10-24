"""The SSRF-guarded clients refuse internal addresses on every connection,
redirect hops included, and connect to the address they vetted.

A real HTTP server on 127.0.0.1 stands in for both sides. Loopback is always
refused, so the redirect tests map test hostnames to it and refuse only the
"evil" one: that isolates "is every hop checked" from "is loopback refused".
"""

import ipaddress
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from app.core import safe_http
from app.services import transcript


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        port = self.server.server_port
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", f"http://evil.test:{port}/secret")
            self.end_headers()
            return
        if self.path == "/big.vtt":
            self.send_response(200)
            self.send_header("Content-Type", "text/vtt")
            self.end_headers()
            self.wfile.write(b"x" * (3 * 1024 * 1024))
            return
        if self.path == "/page.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>admin panel</html>")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"host=" + self.headers["Host"].encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv.server_port
    srv.shutdown()


@pytest.fixture
def names_point_at_server(monkeypatch):
    async def resolve(host):
        return [ipaddress.ip_address("127.0.0.1")]

    monkeypatch.setattr(safe_http, "resolve_host", resolve)
    monkeypatch.setattr(safe_http, "_refusal", lambda host, addr, allow: "refused" if host.startswith("evil") else None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/",
        "http://[fd00:ec2::254]/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.17.0.2:6379/",
        "http://100.64.0.1/",
    ],
)
async def test_internal_addresses_refused(url):
    async with safe_http.safe_async_client(follow_redirects=True) as client:
        with pytest.raises(safe_http.OutboundBlocked):
            await client.get(url)
    with pytest.raises(safe_http.OutboundBlocked):
        await safe_http.safe_curl_get(url)


@pytest.mark.asyncio
async def test_private_switch_opens_the_lan_but_not_loopback_or_metadata():
    with pytest.raises(safe_http.OutboundBlocked):
        await safe_http.vetted_address("169.254.169.254", allow_private=True)
    with pytest.raises(safe_http.OutboundBlocked):
        await safe_http.vetted_address("127.0.0.1", allow_private=True)
    assert str(await safe_http.vetted_address("192.168.1.1", allow_private=True)) == "192.168.1.1"


@pytest.mark.asyncio
async def test_connection_keeps_the_hostname_and_checks_every_redirect_hop(server, names_point_at_server):
    async with safe_http.safe_async_client(follow_redirects=True) as client:
        ok = await client.get(f"http://good.test:{server}/")
        assert ok.text == f"host=good.test:{server}"
        assert str(ok.url) == f"http://good.test:{server}/"
        with pytest.raises(safe_http.OutboundBlocked):
            await client.get(f"http://good.test:{server}/redir")

    ok = await safe_http.safe_curl_get(f"http://good.test:{server}/")
    assert ok.text == f"host=good.test:{server}"
    with pytest.raises(safe_http.OutboundBlocked):
        await safe_http.safe_curl_get(f"http://good.test:{server}/redir")


@pytest.mark.asyncio
async def test_transcript_fetch_refuses_the_metadata_service():
    assert await transcript.fetch_transcript("http://169.254.169.254/latest/meta-data/iam/") is None


@pytest.mark.asyncio
async def test_transcript_fetch_is_typed_and_capped(server, names_point_at_server):
    assert await transcript.fetch_transcript(f"http://good.test:{server}/big.vtt") is None
    assert await transcript.fetch_transcript(f"http://good.test:{server}/page.html") is not None  # text/* is text
    assert await transcript.fetch_transcript(f"http://good.test:{server}/redir") is None


@pytest.mark.asyncio
async def test_blocked_is_an_httpx_error():
    """Existing `except httpx.HTTPError` handling must treat a refusal as a failed fetch."""
    async with safe_http.safe_async_client() as client:
        with pytest.raises(httpx.HTTPError):
            await client.get("http://127.0.0.1/")
