"""Tests for the Prometheus metrics endpoint."""

import pytest
from httpx import AsyncClient


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


@pytest.mark.asyncio
async def test_metrics_forbidden_for_disallowed_ip(client: AsyncClient):
    """Metrics endpoint returns 403 for IPs outside loopback/RFC 1918."""
    response = await client.get("/metrics", headers={"X-Real-IP": "203.0.113.7"})
    assert response.status_code == 403
    assert response.text == "Forbidden"


@pytest.mark.asyncio
async def test_metrics_forbidden_for_unparseable_ip(client: AsyncClient):
    """A malformed forwarded IP is denied rather than crashing the endpoint."""
    response = await client.get("/metrics", headers={"X-Real-IP": "not-an-ip"})
    assert response.status_code == 403
