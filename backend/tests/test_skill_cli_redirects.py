"""The skill CLIs must not follow redirects.

urllib's default redirect handler re-sends every request header, Authorization
included, to whatever host a redirect names, even over plain http. A redirect
from (or on the way to) the API would hand the caller's bearer token to that
host, so the CLIs refuse redirects and report the 3xx instead.
"""

import importlib.util
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

# Same locations test_tool_registry_sync.py checks: mounted in the api container
# (docker-compose.dev.yml), or at the repo root on a host checkout.
_REPO = Path(__file__).resolve().parents[2]
_CLI_PATHS = {
    "full": (Path("/app/skill-clis/full_cli.py"), _REPO / "intelfeed-skill" / "scripts" / "intelfeed_cli.py"),
    "lite": (Path("/app/skill-clis/lite_cli.py"), _REPO / "intelfeed-lite-skill" / "scripts" / "intelfeed_cli.py"),
}


def _load_cli(flavor: str):
    path = next((p for p in _CLI_PATHS[flavor] if p.is_file()), None)
    if path is None:
        pytest.skip(f"{flavor} skill CLI not available")
    spec = importlib.util.spec_from_file_location(f"skill_cli_{flavor}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("flavor", ["full", "lite"])
def test_cli_does_not_forward_the_token_on_redirect(flavor):
    cli = _load_cli(flavor)
    seen = {}

    class Elsewhere(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen["authorization"] = self.headers.get("Authorization")
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    class Api(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{elsewhere.server_port}/collect")
            self.send_header("Content-Length", "0")
            self.end_headers()

    elsewhere = ThreadingHTTPServer(("127.0.0.1", 0), Elsewhere)
    api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    for server in (elsewhere, api):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = cli.IntelFeedClient(f"http://127.0.0.1:{api.server_port}")
        status, _ = client._post(
            "/api/tools/execute", {"tool_name": "get_dashboard_stats", "args": {}}, {"Authorization": "Bearer t0ken"}
        )
    finally:
        elsewhere.shutdown()
        api.shutdown()
    assert status == 302
    assert "authorization" not in seen, "the bearer token was sent to the redirect target"
