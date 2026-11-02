"""Tests for enrichment API endpoints and the pipeline."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import encrypt_value
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

    async def test_update_source_takes_no_key(
        self, client: AsyncClient, admin_headers: dict, db_session: AsyncSession, enrichment_source: EnrichmentSource
    ):
        """Keys are set under /enrichment/keys: an ``api_key`` in the source's
        PUT neither sets one nor clears the stored one."""
        from app.core.encryption import decrypt_value

        resp = await client.put(
            f"/api/enrichment/sources/{enrichment_source.id}",
            json={"api_key": "test-secret-key"},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["has_api_key"] is False

        enrichment_source.api_key_encrypted = encrypt_value("stored-key")
        await db_session.flush()
        resp = await client.put(
            f"/api/enrichment/sources/{enrichment_source.id}",
            json={"api_key": "", "is_enabled": True},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["has_api_key"] is True
        assert decrypt_value(enrichment_source.api_key_encrypted) == "stored-key"


@pytest.fixture
def no_env_keys(monkeypatch, db_session):
    """No instance-wide key from the environment, a settings row to store one
    in, and no settings cached from another test."""
    from app.config import settings as env_settings
    from app.models.system_setting import SystemSettings
    from app.services.system_settings import invalidate_cache

    monkeypatch.setattr(env_settings, "nvd_api_key", "")
    monkeypatch.setattr(env_settings, "github_token", "")
    invalidate_cache()
    db_session.add(SystemSettings(id=1, settings={}, secrets={}))
    yield
    invalidate_cache()


def _probe_transport(handler):
    """Patch every SourceGateway built inside the block to send to ``handler``."""
    from app.enrichment.gateway import SourceGateway

    real_init = SourceGateway.__init__

    def init(self, *args, **kwargs):
        kwargs.pop("inner", None)
        real_init(self, *args, **kwargs, inner=httpx.MockTransport(handler))

    return patch.object(SourceGateway, "__init__", init)


class TestTestKey:
    async def test_test_key(
        self, client: AsyncClient, admin_headers: dict, enrichment_source: EnrichmentSource, no_env_keys
    ):
        # No key yet: nothing to test, and nothing is sent.
        resp = await client.post("/api/enrichment/keys/nvd_api_key/test", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "missing"

        await client.put("/api/enrichment/keys/nvd_api_key", json={"api_key": "nvd-key"}, headers=admin_headers)
        with _probe_transport(lambda request: httpx.Response(200, json={"vulnerabilities": []})):
            resp = await client.post("/api/enrichment/keys/nvd_api_key/test", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "message": None}
        assert enrichment_source.health_status == "healthy"

    async def test_test_key_non_admin_rejected(
        self, client: AsyncClient, auth_headers: dict, enrichment_source: EnrichmentSource
    ):
        resp = await client.post("/api/enrichment/keys/nvd_api_key/test", headers=auth_headers)
        assert resp.status_code == 403

    async def test_test_unknown_key_is_404(self, client: AsyncClient, admin_headers: dict):
        resp = await client.post("/api/enrichment/keys/nope/test", headers=admin_headers)
        assert resp.status_code == 404

    async def test_the_old_source_routes_are_gone(
        self, client: AsyncClient, admin_headers: dict, enrichment_source: EnrichmentSource
    ):
        resp = await client.post(f"/api/enrichment/sources/{enrichment_source.id}/test", headers=admin_headers)
        assert resp.status_code == 404
        resp = await client.get("/api/enrichment/user-overrides", headers=admin_headers)
        assert resp.status_code == 404


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
        assert data["rate_limit_remaining"] == 5  # a full bucket, held to the keyless 5 per 30 s

    async def test_remaining_reads_the_gateway_bucket(
        self, client: AsyncClient, auth_headers: dict, enrichment_source: EnrichmentSource
    ):
        from app.enrichment.registry import source_gateway

        await source_gateway(enrichment_source, None).acquire()
        resp = await client.get(f"/api/enrichment/sources/{enrichment_source.id}/health", headers=auth_headers)
        assert resp.json()["rate_limit_remaining"] == 4


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


@pytest_asyncio.fixture
async def virustotal_source(db_session: AsyncSession) -> EnrichmentSource:
    source = EnrichmentSource(
        source_type="virustotal",
        display_name="VirusTotal",
        is_enabled=True,
        trigger_mode="manual",
        rate_limit_config={"requests_per_period": 4, "period_seconds": 60},
        health_status="unknown",
        config={},
    )
    db_session.add(source)
    await db_session.flush()
    return source


class TestTestKeyThroughGateway:
    async def test_probe_goes_through_the_gateway_with_the_key(
        self, client: AsyncClient, admin_headers: dict, virustotal_source: EnrichmentSource
    ):
        from app.enrichment.gateway import USER_AGENT

        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"data": {}})

        await client.put("/api/enrichment/keys/virustotal", json={"api_key": "vt-key"}, headers=admin_headers)
        with _probe_transport(handler):
            resp = await client.post("/api/enrichment/keys/virustotal/test", headers=admin_headers)

        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert seen[0].headers["User-Agent"] == USER_AGENT
        assert seen[0].headers["x-apikey"] == "vt-key"
        assert virustotal_source.health_status == "healthy"

    async def test_a_key_the_source_answers_401_reads_rejected(
        self, client: AsyncClient, admin_headers: dict, virustotal_source: EnrichmentSource
    ):
        """The commonest rejection: the source answers 401 to the key."""
        await client.put("/api/enrichment/keys/virustotal", json={"api_key": "bad-key"}, headers=admin_headers)
        with _probe_transport(lambda request: httpx.Response(401, json={"error": {"code": "WrongCredentialsError"}})):
            resp = await client.post("/api/enrichment/keys/virustotal/test", headers=admin_headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "rejected"

    async def test_the_nvd_probe_sends_the_key_it_tests(
        self, client: AsyncClient, admin_headers: dict, enrichment_source: EnrichmentSource, no_env_keys
    ):
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"vulnerabilities": []})

        await client.put("/api/enrichment/keys/nvd_api_key", json={"api_key": "nvd-key"}, headers=admin_headers)
        with _probe_transport(handler):
            await client.post("/api/enrichment/keys/nvd_api_key/test", headers=admin_headers)
        assert seen[0].headers.get("apiKey") == "nvd-key"

    async def test_a_rejected_key_reads_rejected(
        self, client: AsyncClient, admin_headers: dict, enrichment_source: EnrichmentSource, no_env_keys
    ):
        await client.put("/api/enrichment/keys/nvd_api_key", json={"api_key": "bad-key"}, headers=admin_headers)
        with _probe_transport(lambda request: httpx.Response(404)):
            resp = await client.post("/api/enrichment/keys/nvd_api_key/test", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "rejected"
        assert enrichment_source.health_status == "down"

    async def test_refused_probe_keeps_the_status(
        self, client: AsyncClient, admin_headers: dict, enrichment_source: EnrichmentSource, no_env_keys
    ):
        """A probe the gateway refuses says nothing about the key: 429 (or 503
        with Redis down), and the source's health is left as it was."""
        from app.enrichment.gateway import BreakerOpen, GatewayUnavailable

        await client.put("/api/enrichment/keys/nvd_api_key", json={"api_key": "nvd-key"}, headers=admin_headers)
        for error, status in ((BreakerOpen("nvd", 120), 429), (GatewayUnavailable("redis down"), 503)):
            adapter = MagicMock()
            adapter.check_health = AsyncMock(side_effect=error)
            with patch("app.enrichment.registry.adapter_for_source", return_value=adapter):
                resp = await client.post("/api/enrichment/keys/nvd_api_key/test", headers=admin_headers)
            assert resp.status_code == status
            assert resp.json()["error"]["code"] == error.status
        assert enrichment_source.health_status == "unknown"

    async def test_a_fresh_test_clears_a_recorded_auth_failure(
        self, client: AsyncClient, admin_headers: dict, enrichment_source: EnrichmentSource, no_env_keys, db_session
    ):
        """An admin who fixed the key upstream tests it: the recorded rejection
        goes first, so the probe actually leaves, and the key reads set again."""
        from app.enrichment.pipeline import resolve_api_key
        from app.enrichment.registry import source_gateway

        await client.put("/api/enrichment/keys/nvd_api_key", json={"api_key": "nvd-key"}, headers=admin_headers)
        gateway = source_gateway(enrichment_source, await resolve_api_key(enrichment_source, None, db_session))
        await gateway._mark_auth_failed(401, "NVD rejected the API key (401)")
        (row,) = (await client.get("/api/enrichment/keys", headers=admin_headers)).json()
        assert (row["status"], row["message"]) == ("rejected", "NVD rejected the API key (401)")

        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"vulnerabilities": []})

        with _probe_transport(handler):
            resp = await client.post("/api/enrichment/keys/nvd_api_key/test", headers=admin_headers)
        assert resp.json()["status"] == "ok"
        assert len(seen) == 1
        assert await gateway.auth_failure() is None
        (row,) = (await client.get("/api/enrichment/keys", headers=admin_headers)).json()
        assert row["status"] == "set"


async def _overrides(db: AsyncSession, user_id) -> list[UserEnrichmentOverride]:
    from sqlalchemy import select

    return list(
        (await db.execute(select(UserEnrichmentOverride).where(UserEnrichmentOverride.created_by == user_id)))
        .scalars()
        .all()
    )


class TestOwnKeys:
    async def test_keys_list_has_no_own_key_at_first(
        self, client: AsyncClient, admin_headers: dict, virustotal_source: EnrichmentSource
    ):
        resp = await client.get("/api/enrichment/keys", headers=admin_headers)
        assert resp.status_code == 200
        (row,) = resp.json()
        assert row["id"] == "virustotal"
        assert (row["status"], row["mine"], row["required"]) == ("missing", False, True)

    async def test_set_my_key(
        self,
        client: AsyncClient,
        admin_headers: dict,
        admin_user: User,
        db_session: AsyncSession,
        virustotal_source: EnrichmentSource,
    ):
        from app.enrichment.pipeline import resolve_api_key

        resp = await client.put(
            "/api/enrichment/keys/virustotal/mine", json={"api_key": "my-personal-key"}, headers=admin_headers
        )
        assert resp.status_code == 200
        assert resp.json() == {"id": "virustotal", "mine": True}

        (row,) = (await client.get("/api/enrichment/keys", headers=admin_headers)).json()
        assert row["mine"] is True
        # An own key isn't the shared one: the instance still has none.
        assert row["status"] == "missing"
        assert await resolve_api_key(virustotal_source, admin_user.id, db_session) == "my-personal-key"
        assert await resolve_api_key(virustotal_source, None, db_session) is None

    async def test_two_admins_each_keep_their_own_key(
        self,
        client: AsyncClient,
        admin_headers: dict,
        admin_user: User,
        db_session: AsyncSession,
        virustotal_source: EnrichmentSource,
    ):
        from app.core.security import create_access_token, hash_password
        from app.enrichment.pipeline import resolve_api_key

        other = User(username="otheradmin", password_hash=hash_password("x"), role="admin")
        db_session.add(other)
        await db_session.flush()
        other_headers = {"Authorization": f"Bearer {create_access_token(other.id, other.role)}"}

        for headers, key in ((admin_headers, "key-a"), (other_headers, "key-b")):
            resp = await client.put("/api/enrichment/keys/virustotal/mine", json={"api_key": key}, headers=headers)
            assert resp.status_code == 200
        for headers in (admin_headers, other_headers):
            (row,) = (await client.get("/api/enrichment/keys", headers=headers)).json()
            assert row["mine"] is True
        assert await resolve_api_key(virustotal_source, admin_user.id, db_session) == "key-a"
        assert await resolve_api_key(virustotal_source, other.id, db_session) == "key-b"

    async def test_remove_my_key(
        self,
        client: AsyncClient,
        admin_headers: dict,
        admin_user: User,
        db_session: AsyncSession,
        virustotal_source: EnrichmentSource,
    ):
        await client.put("/api/enrichment/keys/virustotal/mine", json={"api_key": "temp"}, headers=admin_headers)
        resp = await client.put("/api/enrichment/keys/virustotal/mine", json={"api_key": ""}, headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json() == {"id": "virustotal", "mine": False}

        (row,) = (await client.get("/api/enrichment/keys", headers=admin_headers)).json()
        assert row["mine"] is False
        assert await _overrides(db_session, admin_user.id) == []

    async def test_keys_routes_are_admin_only(
        self, client: AsyncClient, auth_headers: dict, virustotal_source: EnrichmentSource
    ):
        for method, path in (
            ("get", "/api/enrichment/keys"),
            ("put", "/api/enrichment/keys/virustotal"),
            ("put", "/api/enrichment/keys/virustotal/mine"),
        ):
            resp = await client.request(method, path, json={"api_key": "k"}, headers=auth_headers)
            assert resp.status_code == 403, path


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


async def test_enrich_refuses_an_entity_with_nothing_to_look_up(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession
):
    """A victim is looked up by its domain, else its name; one with neither is
    a 400, not a lookup for the value None."""
    from app.models.ransomware import RansomwareVictim

    victim = RansomwareVictim(name="", domain=None)
    db_session.add(victim)
    await db_session.flush()

    resp = await client.post(
        "/api/enrichment/enrich",
        json={"entity_type": "ransomware_victim", "entity_id": str(victim.id)},
        headers=auth_headers,
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"]["code"] == "no_lookup_value"
