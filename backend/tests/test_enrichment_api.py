"""Tests for enrichment API endpoints and the pipeline."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
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
        trigger_mode="manual",
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
        assert data["rate_limit_remaining"] == 50  # a full bucket

    async def test_remaining_reads_the_gateway_bucket(
        self, client: AsyncClient, auth_headers: dict, enrichment_source: EnrichmentSource
    ):
        from app.enrichment.registry import source_gateway

        await source_gateway(enrichment_source, None).acquire()
        resp = await client.get(f"/api/enrichment/sources/{enrichment_source.id}/health", headers=auth_headers)
        assert resp.json()["rate_limit_remaining"] == 49


class TestBudgetUsage:
    async def test_list_reads_the_gateway(
        self, client: AsyncClient, auth_headers: dict, db_session: AsyncSession, enrichment_source: EnrichmentSource
    ):
        from app.enrichment.registry import source_gateway

        enrichment_source.daily_budget = 10
        await db_session.flush()
        gateway = source_gateway(enrichment_source, None)
        for _ in range(3):
            await gateway.acquire()

        resp = await client.get("/api/enrichment/sources", headers=auth_headers)
        (row,) = [s for s in resp.json() if s["source_type"] == "nvd"]
        assert row["daily_budget_used"] == 3


class TestTestSourceThroughGateway:
    async def test_probe_goes_through_the_gateway(
        self, client: AsyncClient, admin_headers: dict, enrichment_source: EnrichmentSource
    ):
        from app.enrichment.gateway import USER_AGENT, SourceGateway

        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"vulnerabilities": []})

        real_init = SourceGateway.__init__

        def init(self, *args, **kwargs):
            real_init(self, *args, **kwargs, inner=httpx.MockTransport(handler))

        with patch.object(SourceGateway, "__init__", init):
            resp = await client.post(f"/api/enrichment/sources/{enrichment_source.id}/test", headers=admin_headers)

        assert resp.status_code == 200
        assert resp.json()["health_status"] == "healthy"
        assert seen[0].headers["User-Agent"] == USER_AGENT

    async def test_refused_probe_keeps_the_status(
        self, client: AsyncClient, admin_headers: dict, enrichment_source: EnrichmentSource
    ):
        from app.enrichment.gateway import BreakerOpen

        adapter = MagicMock()
        adapter.check_health = AsyncMock(side_effect=BreakerOpen("nvd", 120))
        with patch("app.enrichment.registry.adapter_for_source", return_value=adapter):
            resp = await client.post(f"/api/enrichment/sources/{enrichment_source.id}/test", headers=admin_headers)

        assert resp.status_code == 429
        assert resp.json()["error"]["code"] == "breaker_open"
        assert enrichment_source.health_status == "unknown"


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


class TestEnrichEntity:
    async def test_enrich_entity(
        self,
        client: AsyncClient,
        auth_headers: dict,
        enrichment_source: EnrichmentSource,
        test_actor: ThreatActor,
    ):
        # Mock the adapter's enrich method
        # Patch where it is used, not where it is defined: pipeline.py does
        # `from ...registry import adapter_for_source`, so patching the
        # registry module leaves the pipeline's own binding untouched.
        with patch("app.enrichment.pipeline.adapter_for_source") as mock_get_adapter:
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

    async def test_enrich_any_modelled_type_and_write_its_columns(
        self, client: AsyncClient, auth_headers: dict, db_session: AsyncSession
    ):
        """The profile's Enrich now is on every entity type: a vendor is looked
        up by name, and what comes back reaches the entity's columns, as a
        queued lookup's does."""
        from app.models.vendor import Vendor

        vendor = Vendor(name="Palo Alto Networks")
        db_session.add(vendor)
        await db_session.flush()

        answer = [
            {
                "source_type": "wikipedia",
                "status": "success",
                "parsed_data": {
                    "wikipedia_url": "https://en.wikipedia.org/wiki/Palo_Alto_Networks",
                    "first_paragraph": "Palo Alto Networks is a cybersecurity company.",
                },
            }
        ]
        with patch("app.enrichment.pipeline.enrich_entity", AsyncMock(return_value=answer)) as pipeline:
            resp = await client.post(
                "/api/enrichment/enrich",
                json={"entity_type": "vendor", "entity_id": str(vendor.id)},
                headers=auth_headers,
            )
        assert resp.status_code == 200
        assert pipeline.await_args.kwargs["entity_value"] == "Palo Alto Networks"
        await db_session.refresh(vendor)
        assert vendor.wikipedia_url == "https://en.wikipedia.org/wiki/Palo_Alto_Networks"
        assert vendor.description == "Palo Alto Networks is a cybersecurity company."

    async def test_refresh_asks_the_source_again_past_a_fresh_result(
        self, db_session: AsyncSession, enrichment_result: EnrichmentResult, test_actor: ThreatActor
    ):
        """A fresh stored result answers a lookup; Refresh asks the source again."""
        from app.enrichment.pipeline import enrich_entity

        with patch("app.enrichment.pipeline.adapter_for_source") as adapter_for:
            adapter = MagicMock()
            adapter.supports_entity.return_value = True
            adapter.enrich = AsyncMock(
                return_value=EnrichmentData(raw_response={}, parsed_data={"name": "fresher"}, ttl_hours=24)
            )
            adapter_for.return_value = adapter
            args = dict(
                entity_type="threat_actor",
                entity_id=test_actor.id,
                entity_value=test_actor.name,
                db=db_session,
                trigger="manual",
                source_types=["nvd"],
            )

            cached = await enrich_entity(**args)
            assert [r["status"] for r in cached] == ["cached"]
            adapter.enrich.assert_not_awaited()

            fresh = await enrich_entity(**args, refresh=True)
            assert [r["status"] for r in fresh] == ["success"]
            adapter.enrich.assert_awaited_once()

    async def test_enrich_rejects_types_with_no_entity_model(self, client: AsyncClient, auth_headers: dict):
        resp = await client.post(
            "/api/enrichment/enrich",
            json={"entity_type": "campaign", "entity_id": str(uuid.uuid4())},
            headers=auth_headers,
        )
        assert resp.status_code == 400  # request validation (the app's validation handler)


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
