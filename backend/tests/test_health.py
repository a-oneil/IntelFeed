from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.build_info import build_stamp
from app.main import app


def _local_client() -> AsyncClient:
    """A caller on the api host itself (the container healthcheck)."""
    return AsyncClient(transport=ASGITransport(app=app, client=("127.0.0.1", 50000)), base_url="http://test")


@pytest.mark.asyncio
async def test_health_returns_200(client: AsyncClient):
    """GET /api/health returns 200 even without authentication."""
    with (
        patch("app.api.health._check_database", new_callable=AsyncMock) as mock_db,
        patch("app.api.health._check_redis", new_callable=AsyncMock) as mock_redis,
        patch("app.api.health._check_meilisearch", new_callable=AsyncMock) as mock_meili,
    ):
        mock_db.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_redis.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_meili.return_value = {"status": "ok", "latency_ms": 1.0}

        resp = await client.get("/api/health")

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_health_response_has_expected_fields():
    """A local caller gets status, version, and each component's status and latency."""
    with (
        patch("app.api.health._check_database", new_callable=AsyncMock) as mock_db,
        patch("app.api.health._check_redis", new_callable=AsyncMock) as mock_redis,
        patch("app.api.health._check_meilisearch", new_callable=AsyncMock) as mock_meili,
    ):
        mock_db.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_redis.return_value = {"status": "ok", "latency_ms": 2.0}
        mock_meili.return_value = {"status": "ok", "latency_ms": 3.0}

        async with _local_client() as local:
            resp = await local.get("/api/health")
        data = resp.json()

    assert "status" in data
    assert "version" in data
    assert "components" in data

    components = data["components"]
    assert "database" in components
    assert "redis" in components
    assert "meilisearch" in components

    for name in ("database", "redis", "meilisearch"):
        assert "status" in components[name]
        assert "latency_ms" in components[name]


@pytest.mark.asyncio
async def test_health_no_auth_required(client: AsyncClient):
    """The health endpoint must be accessible without any Authorization header."""
    with (
        patch("app.api.health._check_database", new_callable=AsyncMock) as mock_db,
        patch("app.api.health._check_redis", new_callable=AsyncMock) as mock_redis,
        patch("app.api.health._check_meilisearch", new_callable=AsyncMock) as mock_meili,
    ):
        mock_db.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_redis.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_meili.return_value = {"status": "ok", "latency_ms": 1.0}

        # Explicitly send no auth header
        resp = await client.get("/api/health", headers={})

    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_health_all_ok_returns_healthy(client: AsyncClient):
    """When all components are ok, status is 'healthy'."""
    with (
        patch("app.api.health._check_database", new_callable=AsyncMock) as mock_db,
        patch("app.api.health._check_redis", new_callable=AsyncMock) as mock_redis,
        patch("app.api.health._check_meilisearch", new_callable=AsyncMock) as mock_meili,
    ):
        mock_db.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_redis.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_meili.return_value = {"status": "ok", "latency_ms": 1.0}

        resp = await client.get("/api/health")
        data = resp.json()

    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_health_degraded_when_non_critical_down():
    """When database is ok but a non-critical service fails, status is 'degraded'."""
    with (
        patch("app.api.health._check_database", new_callable=AsyncMock) as mock_db,
        patch("app.api.health._check_redis", new_callable=AsyncMock) as mock_redis,
        patch("app.api.health._check_meilisearch", new_callable=AsyncMock) as mock_meili,
    ):
        mock_db.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_redis.return_value = {"status": "error", "error": "Connection refused"}
        mock_meili.return_value = {"status": "ok", "latency_ms": 1.0}

        async with _local_client() as local:
            resp = await local.get("/api/health")
        data = resp.json()

    assert data["status"] == "degraded"
    assert data["components"]["redis"]["status"] == "error"
    assert "error" in data["components"]["redis"]


@pytest.mark.asyncio
async def test_health_unhealthy_when_database_down(client: AsyncClient):
    """When the database is down, status is 'unhealthy' regardless of other services."""
    with (
        patch("app.api.health._check_database", new_callable=AsyncMock) as mock_db,
        patch("app.api.health._check_redis", new_callable=AsyncMock) as mock_redis,
        patch("app.api.health._check_meilisearch", new_callable=AsyncMock) as mock_meili,
    ):
        mock_db.return_value = {"status": "error", "error": "Connection refused"}
        mock_redis.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_meili.return_value = {"status": "ok", "latency_ms": 1.0}

        resp = await client.get("/api/health")
        data = resp.json()

    assert data["status"] == "unhealthy"
    assert data["components"]["database"]["status"] == "error"


@pytest.mark.asyncio
async def test_health_unhealthy_when_all_services_down(client: AsyncClient):
    """When all services are down, status is 'unhealthy'."""
    with (
        patch("app.api.health._check_database", new_callable=AsyncMock) as mock_db,
        patch("app.api.health._check_redis", new_callable=AsyncMock) as mock_redis,
        patch("app.api.health._check_meilisearch", new_callable=AsyncMock) as mock_meili,
    ):
        mock_db.return_value = {"status": "error", "error": "DB down"}
        mock_redis.return_value = {"status": "error", "error": "Redis down"}
        mock_meili.return_value = {"status": "error", "error": "Meili down"}

        resp = await client.get("/api/health")
        data = resp.json()

    assert data["status"] == "unhealthy"
    for name in ("database", "redis", "meilisearch"):
        assert data["components"][name]["status"] == "error"


@pytest.mark.asyncio
async def test_health_includes_version(client: AsyncClient):
    """Response includes a version string."""
    with (
        patch("app.api.health._check_database", new_callable=AsyncMock) as mock_db,
        patch("app.api.health._check_redis", new_callable=AsyncMock) as mock_redis,
        patch("app.api.health._check_meilisearch", new_callable=AsyncMock) as mock_meili,
    ):
        mock_db.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_redis.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_meili.return_value = {"status": "ok", "latency_ms": 1.0}

        resp = await client.get("/api/health")
        data = resp.json()

    # The build stamp, not a literal: it comes from the APP_VERSION build arg and
    # falls back to "dev" in an unstamped image (which is what tests run against).
    assert data["version"] == build_stamp()["version"]
    assert "git_sha" in data
    assert "built_at" in data


@pytest.mark.asyncio
async def test_version_endpoint_needs_no_backing_services(client: AsyncClient):
    """/api/version reports the build stamp without touching db/redis/meili."""
    with (
        patch("app.api.health._check_database", new_callable=AsyncMock) as mock_db,
        patch("app.api.health._check_redis", new_callable=AsyncMock) as mock_redis,
        patch("app.api.health._check_meilisearch", new_callable=AsyncMock) as mock_meili,
    ):
        resp = await client.get("/api/version")

        # The point of the endpoint: cheap enough to poll.
        mock_db.assert_not_called()
        mock_redis.assert_not_called()
        mock_meili.assert_not_called()

    assert resp.status_code == 200
    assert resp.json() == build_stamp()


@pytest.mark.asyncio
async def test_health_degraded_when_meilisearch_down(client: AsyncClient):
    """Meilisearch failure alone results in 'degraded', not 'unhealthy'."""
    with (
        patch("app.api.health._check_database", new_callable=AsyncMock) as mock_db,
        patch("app.api.health._check_redis", new_callable=AsyncMock) as mock_redis,
        patch("app.api.health._check_meilisearch", new_callable=AsyncMock) as mock_meili,
    ):
        mock_db.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_redis.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_meili.return_value = {"status": "error", "error": "HTTP 503"}

        resp = await client.get("/api/health")
        data = resp.json()

    assert data["status"] == "degraded"
    assert data["components"]["meilisearch"]["status"] == "error"


@pytest.mark.asyncio
async def test_health_hides_component_detail_from_remote_callers(client: AsyncClient):
    """Over the network a caller gets each component's status, never latency or error text."""
    with (
        patch("app.api.health._check_database", new_callable=AsyncMock) as mock_db,
        patch("app.api.health._check_redis", new_callable=AsyncMock) as mock_redis,
        patch("app.api.health._check_meilisearch", new_callable=AsyncMock) as mock_meili,
    ):
        mock_db.return_value = {"status": "ok", "latency_ms": 1.0}
        mock_redis.return_value = {"status": "error", "error": "Error connecting to redis-internal:6379"}
        mock_meili.return_value = {"status": "ok", "latency_ms": 1.0}

        remote = await client.get("/api/health")
        # Through the proxy the peer is local but the request was forwarded.
        async with _local_client() as local:
            forwarded = await local.get("/api/health", headers={"X-Forwarded-For": "203.0.113.9"})

    for resp in (remote, forwarded):
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["components"] == {
            "database": {"status": "ok"},
            "redis": {"status": "error"},
            "meilisearch": {"status": "ok"},
        }
