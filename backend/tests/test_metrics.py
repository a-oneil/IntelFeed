"""Tests for the Prometheus metrics endpoint."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_metrics_returns_prometheus_format(client: AsyncClient):
    """Metrics endpoint returns Prometheus text format for allowed IPs."""
    response = await client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    # Prometheus output should contain at least one HELP or TYPE comment
    body = response.text
    assert body  # non-empty
    # Standard prometheus_client output includes HELP/TYPE lines
    assert "# HELP" in body or "# TYPE" in body


def _client_from(host: str) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app, client=(host, 50000)), base_url="http://test")


@pytest.mark.asyncio
async def test_metrics_forbidden_for_disallowed_ip():
    """Metrics endpoint returns 403 for peers outside loopback/RFC 1918."""
    async with _client_from("203.0.113.7") as c:
        response = await c.get("/metrics")
    assert response.status_code == 403
    assert response.text == "Forbidden"


@pytest.mark.asyncio
async def test_metrics_ignores_a_forged_real_ip_header():
    """A public caller can't get in by claiming a private address in X-Real-IP."""
    async with _client_from("203.0.113.7") as c:
        response = await c.get("/metrics", headers={"X-Real-IP": "127.0.0.1"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_metrics_forbidden_for_unparseable_ip():
    """A peer address that isn't an IP is denied rather than crashing the endpoint."""
    async with _client_from("not-an-ip") as c:
        response = await c.get("/metrics")
    assert response.status_code == 403
