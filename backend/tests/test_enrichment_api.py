"""Tests for enrichment API endpoints, pipeline, and rate limiter."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.base import EnrichmentData
from app.models.enrichment import EnrichmentResult, EnrichmentSource, UserEnrichmentOverride
from app.models.threat_actor import ThreatActor
from app.models.user import User

# --- Fixtures ---


@pytest_asyncio.fixture
async def enrichment_source(db_session: AsyncSession) -> EnrichmentSource:
    source = EnrichmentSource(
        source_type="nvd",
        display_name="NVD API 2.0",
        is_enabled=True,
        trigger_mode="auto",
        rate_limit_config={"requests_per_period": 50, "period_seconds": 30},
        health_status="unknown",
        config={},
    )
    db_session.add(source)
    await db_session.flush()
    return source


@pytest_asyncio.fixture
async def disabled_source(db_session: AsyncSession) -> EnrichmentSource:
    source = EnrichmentSource(
        source_type="vulncheck",
        display_name="VulnCheck KEV",
        is_enabled=False,
        trigger_mode="scheduled",
        rate_limit_config={"requests_per_period": 1000, "period_seconds": 60},
        health_status="unknown",
        config={},
    )
    db_session.add(source)
    await db_session.flush()
    return source


@pytest_asyncio.fixture
async def test_actor(db_session: AsyncSession) -> ThreatActor:
    actor = ThreatActor(
        name="EnrichTestActor",
        aliases=["ETA"],
        country="Unknown",
    )
    db_session.add(actor)
    await db_session.flush()
    return actor


@pytest_asyncio.fixture
async def enrichment_result(
    db_session: AsyncSession, test_actor: ThreatActor, enrichment_source: EnrichmentSource
) -> EnrichmentResult:
    result = EnrichmentResult(
        entity_type="threat_actor",
        entity_id=test_actor.id,
        source_type="nvd",
        raw_response={"name": "EnrichTestActor", "data": {}},
        parsed_data={"name": "EnrichTestActor", "data": {}},
        enriched_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=168),
        status="success",
    )
    db_session.add(result)
    await db_session.flush()
    return result


# --- API Endpoint Tests ---


class TestListSources:
    async def test_list_sources(self, client: AsyncClient, auth_headers: dict, enrichment_source: EnrichmentSource):
        resp = await client.get("/api/enrichment/sources", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        source = next(s for s in data if s["source_type"] == "nvd")
        assert source["display_name"] == "NVD API 2.0"
        assert source["is_enabled"] is True
        assert "has_api_key" in source

    async def test_list_sources_unauthenticated(self, client: AsyncClient):
        resp = await client.get("/api/enrichment/sources")
        assert resp.status_code in (401, 403)


class TestUpdateSource:
    async def test_update_source_admin(
        self, client: AsyncClient, admin_headers: dict, enrichment_source: EnrichmentSource
    ):
        resp = await client.put(
            f"/api/enrichment/sources/{enrichment_source.id}",
            json={"is_enabled": False, "trigger_mode": "manual"},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_enabled"] is False
        assert data["trigger_mode"] == "manual"

    async def test_update_source_non_admin_rejected(
        self, client: AsyncClient, auth_headers: dict, enrichment_source: EnrichmentSource
    ):
        resp = await client.put(
            f"/api/enrichment/sources/{enrichment_source.id}",
            json={"is_enabled": False},
            headers=auth_headers,
        )
        assert resp.status_code == 403

    async def test_update_source_not_found(self, client: AsyncClient, admin_headers: dict):
        fake_id = str(uuid.uuid4())
        resp = await client.put(
            f"/api/enrichment/sources/{fake_id}",
            json={"is_enabled": True},
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_update_source_api_key(
        self, client: AsyncClient, admin_headers: dict, enrichment_source: EnrichmentSource
    ):
        resp = await client.put(
            f"/api/enrichment/sources/{enrichment_source.id}",
            json={"api_key": "test-secret-key"},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["has_api_key"] is True

    async def test_update_source_clear_api_key(
        self, client: AsyncClient, admin_headers: dict, enrichment_source: EnrichmentSource
    ):
        # Set then clear
        await client.put(
            f"/api/enrichment/sources/{enrichment_source.id}",
            json={"api_key": "temp-key"},
            headers=admin_headers,
        )
        resp = await client.put(
            f"/api/enrichment/sources/{enrichment_source.id}",
            json={"api_key": ""},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["has_api_key"] is False


class TestTestSource:
    async def test_test_source(self, client: AsyncClient, admin_headers: dict, enrichment_source: EnrichmentSource):
        resp = await client.post(
            f"/api/enrichment/sources/{enrichment_source.id}/test",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "health_status" in data

    async def test_test_source_non_admin_rejected(
        self, client: AsyncClient, auth_headers: dict, enrichment_source: EnrichmentSource
    ):
        resp = await client.post(
            f"/api/enrichment/sources/{enrichment_source.id}/test",
            headers=auth_headers,
        )
        assert resp.status_code == 403


class TestGetHealth:
    async def test_get_health(self, client: AsyncClient, auth_headers: dict, enrichment_source: EnrichmentSource):
        resp = await client.get(
            f"/api/enrichment/sources/{enrichment_source.id}/health",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["source_type"] == "nvd"
        assert "health_status" in data


class TestUserOverrides:
    async def test_list_user_overrides_empty(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/enrichment/user-overrides", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_create_user_override(
        self, client: AsyncClient, auth_headers: dict, enrichment_source: EnrichmentSource
    ):
        resp = await client.put(
            f"/api/enrichment/user-overrides/{enrichment_source.id}",
            json={"api_key": "my-personal-key"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

        # Verify it shows up in the list
        list_resp = await client.get("/api/enrichment/user-overrides", headers=auth_headers)
        overrides = list_resp.json()
        assert len(overrides) == 1
        assert overrides[0]["has_api_key"] is True

    async def test_two_users_can_each_override_the_same_source(
        self, client: AsyncClient, auth_headers: dict, admin_headers: dict, enrichment_source: EnrichmentSource
    ):
        for headers in (auth_headers, admin_headers):
            resp = await client.put(
                f"/api/enrichment/user-overrides/{enrichment_source.id}",
                json={"api_key": "personal-key"},
                headers=headers,
            )
            assert resp.status_code == 200
        for headers in (auth_headers, admin_headers):
            list_resp = await client.get("/api/enrichment/user-overrides", headers=headers)
            assert len(list_resp.json()) == 1

    async def test_delete_user_override(
        self, client: AsyncClient, auth_headers: dict, enrichment_source: EnrichmentSource
    ):
        # Create then delete
        await client.put(
            f"/api/enrichment/user-overrides/{enrichment_source.id}",
            json={"api_key": "temp"},
            headers=auth_headers,
        )
        resp = await client.delete(
            f"/api/enrichment/user-overrides/{enrichment_source.id}",
            headers=auth_headers,
        )
        assert resp.status_code == 204

        # Verify it's gone
        list_resp = await client.get("/api/enrichment/user-overrides", headers=auth_headers)
        assert list_resp.json() == []


class TestGetResults:
    async def test_get_results(
        self, client: AsyncClient, auth_headers: dict, enrichment_result: EnrichmentResult, test_actor: ThreatActor
    ):
        resp = await client.get(
            "/api/enrichment/results",
            params={"entity_type": "threat_actor", "entity_id": str(test_actor.id)},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        assert data[0]["source_type"] == "nvd"
        assert data[0]["status"] == "success"
        assert "parsed_data" in data[0]

    async def test_get_results_empty(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get(
            "/api/enrichment/results",
            params={"entity_type": "threat_actor", "entity_id": str(uuid.uuid4())},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json() == []


class TestEnrichmentStatus:
    async def test_get_status(self, client: AsyncClient, auth_headers: dict, enrichment_source: EnrichmentSource):
        resp = await client.get("/api/enrichment/status", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_sources" in data
        assert "enabled_sources" in data
        assert "healthy_sources" in data
        assert "enrichments_today" in data


class TestEnrichEntity:
    @patch("app.enrichment.pipeline.RedisRateLimiter")
    async def test_enrich_entity(
        self,
        mock_limiter_cls,
        client: AsyncClient,
        auth_headers: dict,
        enrichment_source: EnrichmentSource,
        test_actor: ThreatActor,
    ):
        # Mock rate limiter to always allow
        mock_limiter = MagicMock()
        mock_limiter.check = AsyncMock(return_value=True)
        mock_limiter_cls.return_value = mock_limiter

        # Mock the adapter's enrich method
        # Patch where it is used, not where it is defined: pipeline.py does
        # `from ...registry import get_adapter`, so patching the registry
        # module leaves the pipeline's own binding untouched.
        with patch("app.enrichment.pipeline.get_adapter") as mock_get_adapter:
            mock_adapter = MagicMock()
            mock_adapter.supports_entity.return_value = True
            mock_adapter.enrich = AsyncMock(
                return_value=EnrichmentData(
                    raw_response={"test": True},
                    parsed_data={"name": "EnrichTestActor"},
                    ttl_hours=24,
                )
            )
            mock_get_adapter.return_value = mock_adapter

            resp = await client.post(
                "/api/enrichment/enrich",
                json={
                    "entity_type": "threat_actor",
                    "entity_id": str(test_actor.id),
                    "source_types": ["nvd"],
                },
                headers=auth_headers,
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["entity_type"] == "threat_actor"
            assert len(data["results"]) >= 1

    async def test_enrich_not_found(self, client: AsyncClient, auth_headers: dict):
        resp = await client.post(
            "/api/enrichment/enrich",
            json={
                "entity_type": "threat_actor",
                "entity_id": str(uuid.uuid4()),
            },
            headers=auth_headers,
        )
        assert resp.status_code == 404


# --- Pipeline Unit Tests ---


class TestPipeline:
    async def test_resolve_api_key_global(self, db_session: AsyncSession, enrichment_source: EnrichmentSource):
        from app.core.encryption import encrypt_value
        from app.enrichment.pipeline import resolve_api_key

        enrichment_source.api_key_encrypted = encrypt_value("global-key")
        db_session.add(enrichment_source)
        await db_session.flush()

        key = await resolve_api_key(enrichment_source, None, db_session)
        assert key == "global-key"

    async def test_resolve_api_key_user_override(
        self, db_session: AsyncSession, enrichment_source: EnrichmentSource, test_user: User
    ):
        from app.core.encryption import encrypt_value
        from app.enrichment.pipeline import resolve_api_key

        enrichment_source.api_key_encrypted = encrypt_value("global-key")
        db_session.add(enrichment_source)

        override = UserEnrichmentOverride(
            created_by=test_user.id,
            source_id=enrichment_source.id,
            api_key_encrypted=encrypt_value("user-key"),
        )
        db_session.add(override)
        await db_session.flush()

        key = await resolve_api_key(enrichment_source, test_user.id, db_session)
        assert key == "user-key"

    async def test_resolve_api_key_no_key(self, db_session: AsyncSession, enrichment_source: EnrichmentSource):
        from app.enrichment.pipeline import resolve_api_key

        key = await resolve_api_key(enrichment_source, None, db_session)
        assert key is None

    async def test_get_cached_result_fresh(
        self, db_session: AsyncSession, test_actor: ThreatActor, enrichment_result: EnrichmentResult
    ):
        from app.enrichment.pipeline import get_cached_result

        cached = await get_cached_result(db_session, "threat_actor", test_actor.id, "nvd")
        assert cached is not None
        assert cached.status == "success"

    async def test_get_cached_result_expired(self, db_session: AsyncSession, test_actor: ThreatActor):
        from app.enrichment.pipeline import get_cached_result

        expired = EnrichmentResult(
            entity_type="threat_actor",
            entity_id=test_actor.id,
            source_type="cvedetails",
            raw_response={},
            parsed_data={},
            enriched_at=datetime.now(UTC) - timedelta(hours=200),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
            status="success",
        )
        db_session.add(expired)
        await db_session.flush()

        # The cache function returns the result, but the pipeline checks expires_at
        cached = await get_cached_result(db_session, "threat_actor", test_actor.id, "cvedetails")
        assert cached is not None
        # Verify it IS expired so the pipeline would re-enrich
        assert cached.expires_at < datetime.now(UTC)

    async def test_get_cached_result_none(self, db_session: AsyncSession, test_actor: ThreatActor):
        from app.enrichment.pipeline import get_cached_result

        cached = await get_cached_result(db_session, "threat_actor", test_actor.id, "nonexistent")
        assert cached is None


# --- Rate Limiter Unit Tests ---


class TestRateLimiter:
    @patch("app.enrichment.rate_limiter.redis.from_url")
    async def test_check_allowed(self, mock_redis_from_url):
        from app.enrichment.rate_limiter import RedisRateLimiter

        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.zremrangebyscore = MagicMock()
        mock_pipe.zcard = MagicMock()
        mock_pipe.zadd = MagicMock()
        mock_pipe.expire = MagicMock()
        mock_pipe.execute = AsyncMock(return_value=[None, 5, None, None])
        mock_redis.pipeline.return_value = mock_pipe
        mock_redis_from_url.return_value = mock_redis

        limiter = RedisRateLimiter("test_source", {"requests_per_period": 100, "period_seconds": 60})
        allowed = await limiter.check()
        assert allowed is True

    @patch("app.enrichment.rate_limiter.redis.from_url")
    async def test_check_rate_limited(self, mock_redis_from_url):
        from app.enrichment.rate_limiter import RedisRateLimiter

        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.zremrangebyscore = MagicMock()
        mock_pipe.zcard = MagicMock()
        mock_pipe.zadd = MagicMock()
        mock_pipe.expire = MagicMock()
        mock_pipe.execute = AsyncMock(return_value=[None, 100, None, None])
        mock_redis.pipeline.return_value = mock_pipe
        mock_redis_from_url.return_value = mock_redis

        limiter = RedisRateLimiter("test_source", {"requests_per_period": 100, "period_seconds": 60})
        allowed = await limiter.check()
        assert allowed is False

    @patch("app.enrichment.rate_limiter.redis.from_url")
    async def test_get_remaining(self, mock_redis_from_url):
        from app.enrichment.rate_limiter import RedisRateLimiter

        mock_redis = MagicMock()
        mock_redis.zremrangebyscore = AsyncMock()
        mock_redis.zcard = AsyncMock(return_value=30)
        mock_redis_from_url.return_value = mock_redis

        limiter = RedisRateLimiter("test_source", {"requests_per_period": 100, "period_seconds": 60})
        remaining = await limiter.get_remaining()
        assert remaining == 70
