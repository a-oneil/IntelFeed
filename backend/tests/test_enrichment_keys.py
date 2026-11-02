"""Enrichment's API keys (``app/enrichment/keys.py``): one row per credential,
set in one place.

A setting credential (``nvd_api_key``) keeps its key in the instance setting;
a group (``abuse_ch``) writes the same key to every member's row; an own key is
an override on every member's row. Real database and Redis (conftest gives
each test its own gateway key prefix).
"""

import pytest
from sqlalchemy import select

from app.core.encryption import decrypt_value, encrypt_value
from app.enrichment import keys
from app.enrichment.pipeline import resolve_api_key
from app.enrichment.registry import source_gateway
from app.models.enrichment import EnrichmentSource, UserEnrichmentOverride
from app.models.system_setting import SystemSettings

ABUSECH = ("threatfox", "urlhaus", "malwarebazaar")


@pytest.fixture(autouse=True)
async def _settings_row(db_session, monkeypatch):
    """A settings row to store setting credentials in, no key from the
    environment, and no settings cached from another test."""
    from app.config import settings as env_settings
    from app.services.system_settings import invalidate_cache

    monkeypatch.setattr(env_settings, "nvd_api_key", "")
    monkeypatch.setattr(env_settings, "github_token", "")
    invalidate_cache()
    if await db_session.get(SystemSettings, 1) is None:
        db_session.add(SystemSettings(id=1, settings={}, secrets={}))
    await db_session.execute(EnrichmentSource.__table__.delete())
    await db_session.flush()
    yield
    invalidate_cache()


async def _rows(db, *source_types, **fields) -> dict[str, EnrichmentSource]:
    rows = {}
    for st in source_types:
        row = EnrichmentSource(
            source_type=st,
            display_name=st,
            is_enabled=fields.get("is_enabled", True),
            trigger_mode="manual",
            config={},
            rate_limit_config={"requests_per_period": 100, "period_seconds": 60},
        )
        db.add(row)
        rows[st] = row
    await db.flush()
    return rows


async def _listed(db, user_id) -> dict[str, dict]:
    return {k["id"]: k for k in await keys.list_keys(db, user_id)}


def test_credentials_group_the_sources_that_share_a_key():
    creds = keys.credentials()
    assert creds["abuse_ch"].sources == ABUSECH and creds["abuse_ch"].setting is None
    assert creds["nvd_api_key"].sources == ("nvd",) and creds["nvd_api_key"].setting == "nvd_api_key"
    assert set(creds["github_token"].sources) == {"github_poc", "github_repo"}
    # An optional key (GreyNoise) is still a credential; a keyless source isn't.
    assert "greynoise" in creds
    assert keys.credential_for("shodan") is None and keys.credential_for("urlhaus") == "abuse_ch"
    # A source that takes no key at all, and one that isn't registered.
    assert keys.credential_for("cymru") is None
    assert keys.credential_for("no_such_source") is None


async def test_a_setting_credential_lives_in_the_setting_only(db_session, admin_user):
    from app.services.system_settings import get_setting

    (nvd,) = (await _rows(db_session, "nvd")).values()
    nvd.api_key_encrypted = encrypt_value("left-over-row-key")
    await db_session.flush()

    await keys.set_shared_key(db_session, "nvd_api_key", "nvd-key")
    assert await get_setting("nvd_api_key", db_session) == "nvd-key"
    assert nvd.api_key_encrypted is None
    assert await resolve_api_key(nvd, None, db_session) == "nvd-key"
    assert (await _listed(db_session, admin_user.id))["nvd_api_key"]["status"] == "set"

    await keys.set_shared_key(db_session, "nvd_api_key", "")
    assert not await get_setting("nvd_api_key", db_session)
    assert await resolve_api_key(nvd, None, db_session) is None
    # NVD runs keyless: a missing key is optional, not missing.
    assert (await _listed(db_session, admin_user.id))["nvd_api_key"]["status"] == "optional"


async def test_a_group_key_is_written_to_every_member(db_session, admin_user):
    rows = await _rows(db_session, *ABUSECH)

    await keys.set_shared_key(db_session, "abuse_ch", "auth-key")
    for row in rows.values():
        assert decrypt_value(row.api_key_encrypted) == "auth-key"
        assert await resolve_api_key(row, None, db_session) == "auth-key"
    listed = (await _listed(db_session, admin_user.id))["abuse_ch"]
    assert listed["status"] == "set" and listed["required"] is True
    assert [s["source_type"] for s in listed["sources"]] == list(ABUSECH)
    assert listed["label"] == "abuse.ch Auth-Key"

    await keys.set_shared_key(db_session, "abuse_ch", None)
    assert all(row.api_key_encrypted is None for row in rows.values())
    assert (await _listed(db_session, admin_user.id))["abuse_ch"]["status"] == "missing"


async def test_an_own_key_is_an_override_on_every_member(db_session, admin_user, test_user):
    rows = await _rows(db_session, *ABUSECH)

    await keys.set_my_key(db_session, "abuse_ch", admin_user.id, "mine")
    overrides = (
        (
            await db_session.execute(
                select(UserEnrichmentOverride).where(UserEnrichmentOverride.created_by == admin_user.id)
            )
        )
        .scalars()
        .all()
    )
    assert {o.source_id for o in overrides} == {r.id for r in rows.values()}
    for row in rows.values():
        assert await resolve_api_key(row, admin_user.id, db_session) == "mine"
        # The shared key is untouched: other people still have none.
        assert row.api_key_encrypted is None
        assert await resolve_api_key(row, test_user.id, db_session) is None
    assert (await _listed(db_session, admin_user.id))["abuse_ch"]["mine"] is True
    assert (await _listed(db_session, test_user.id))["abuse_ch"]["mine"] is False

    # Setting it again replaces it rather than adding a second override.
    await keys.set_my_key(db_session, "abuse_ch", admin_user.id, "mine-2")
    assert await resolve_api_key(rows["urlhaus"], admin_user.id, db_session) == "mine-2"
    await keys.set_my_key(db_session, "abuse_ch", admin_user.id, "")
    assert (await _listed(db_session, admin_user.id))["abuse_ch"]["mine"] is False


async def test_status_rejected_needs_an_enabled_member(db_session, admin_user):
    rows = await _rows(db_session, "virustotal")
    await keys.set_shared_key(db_session, "virustotal", "vt-key")
    gateway = source_gateway(rows["virustotal"], "vt-key")
    await gateway._mark_auth_failed(401, "virustotal rejected the API key (HTTP 401)")

    listed = (await _listed(db_session, admin_user.id))["virustotal"]
    assert (listed["status"], listed["message"]) == ("rejected", "virustotal rejected the API key (HTTP 401)")

    # A source that is off isn't using the key: its old rejection isn't a problem.
    rows["virustotal"].is_enabled = False
    await db_session.flush()
    assert (await _listed(db_session, admin_user.id))["virustotal"]["status"] == "set"


async def test_replacing_a_key_forgets_the_recorded_rejection(db_session, admin_user):
    rows = await _rows(db_session, "virustotal")
    await keys.set_shared_key(db_session, "virustotal", "vt-key")
    await source_gateway(rows["virustotal"], "vt-key")._mark_auth_failed(401, "rejected")

    await keys.set_shared_key(db_session, "virustotal", "vt-key")
    assert await source_gateway(rows["virustotal"], "vt-key").auth_failure() is None


async def test_problems_list_first(db_session, admin_user):
    await _rows(db_session, "virustotal", "greynoise", *ABUSECH)
    await keys.set_shared_key(db_session, "abuse_ch", "auth-key")
    listed = await keys.list_keys(db_session, admin_user.id)
    assert [(k["id"], k["status"]) for k in listed] == [
        ("virustotal", "missing"),
        ("abuse_ch", "set"),
        ("greynoise", "optional"),
    ]
    # A credential none of whose sources has a row isn't listed.
    assert "nvd_api_key" not in {k["id"] for k in listed}


async def test_an_unknown_key_is_refused(db_session, admin_user):
    for call in (
        keys.set_shared_key(db_session, "nope", "k"),
        keys.set_my_key(db_session, "nope", admin_user.id, "k"),
        keys.test_key(db_session, "nope"),
        # A real credential with no source row is unknown too.
        keys.set_shared_key(db_session, "virustotal", "k"),
    ):
        with pytest.raises(keys.UnknownKey):
            await call


async def test_the_routes_answer_404_for_an_unknown_key(client, admin_headers):
    for method, path in (
        ("put", "/api/enrichment/keys/nope"),
        ("put", "/api/enrichment/keys/nope/mine"),
        ("post", "/api/enrichment/keys/nope/test"),
    ):
        resp = await client.request(method, path, json={"api_key": "k"}, headers=admin_headers)
        assert resp.status_code == 404, path
        assert resp.json()["error"]["code"] == "not_found"


async def test_put_key_route_sets_and_removes(client, admin_headers, db_session):
    rows = await _rows(db_session, *ABUSECH)
    resp = await client.put("/api/enrichment/keys/abuse_ch", json={"api_key": "auth-key"}, headers=admin_headers)
    assert resp.json() == {"id": "abuse_ch", "set": True}
    assert all(decrypt_value(r.api_key_encrypted) == "auth-key" for r in rows.values())
    listed = (await client.get("/api/enrichment/keys", headers=admin_headers)).json()
    assert "auth-key" not in str(listed)  # keys are never returned
    resp = await client.put("/api/enrichment/keys/abuse_ch", json={"api_key": ""}, headers=admin_headers)
    assert resp.json() == {"id": "abuse_ch", "set": False}
    assert all(r.api_key_encrypted is None for r in rows.values())


# ── test_key ─────────────────────────────────────────────────────────


async def test_test_key_ok_rejected_and_missing(db_session, monkeypatch):
    from unittest.mock import AsyncMock, MagicMock

    import app.enrichment.registry as registry

    rows = await _rows(db_session, *ABUSECH)
    assert await keys.test_key(db_session, "abuse_ch") == {"status": "missing", "message": None}

    await keys.set_shared_key(db_session, "abuse_ch", "auth-key")
    probed: list[tuple[str, str]] = []

    def adapter_for(row, api_key):
        probed.append((row.source_type, api_key))
        adapter = MagicMock()
        adapter.check_health = AsyncMock(return_value=healthy)
        return adapter

    monkeypatch.setattr(registry, "adapter_for_source", adapter_for)
    healthy = True
    assert await keys.test_key(db_session, "abuse_ch") == {"status": "ok", "message": None}
    # Probed through the first member, with the shared key; every member's health moves.
    assert probed == [("threatfox", "auth-key")]
    assert {r.health_status for r in rows.values()} == {"healthy"}

    # No answer says nothing about the key: health is left alone.
    healthy = False
    result = await keys.test_key(db_session, "abuse_ch")
    assert result == {"status": "unreachable", "message": "Couldn't reach threatfox; try again in a moment"}
    assert {r.health_status for r in rows.values()} == {"healthy"}

    # The source answering 401/403 is the rejection.
    from app.enrichment.gateway import AuthFailed

    refused = MagicMock()
    refused.check_health = AsyncMock(side_effect=AuthFailed("threatfox: 401 Unauthorized"))
    monkeypatch.setattr(registry, "adapter_for_source", lambda row, api_key: refused)
    result = await keys.test_key(db_session, "abuse_ch")
    assert result == {"status": "rejected", "message": "threatfox: 401 Unauthorized"}


async def test_test_key_of_job_only_sources_is_untestable(db_session):
    await _rows(db_session, "github_repo")
    result = await keys.test_key(db_session, "github_token")
    assert result["status"] == "untestable"


# ── The settings page doesn't set enrichment keys ────────────────────


@pytest.mark.parametrize("key", ["nvd_api_key", "github_token"])
async def test_settings_routes_refuse_the_enrichment_keys(key, client, admin_headers):
    resp = await client.patch("/api/system-settings", json={"settings": {key: "k"}}, headers=admin_headers)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "set_in_enrichment_keys"
    resp = await client.delete(f"/api/system-settings/{key}", headers=admin_headers)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "set_in_enrichment_keys"


async def test_settings_routes_still_take_other_settings(client, admin_headers):
    resp = await client.patch(
        "/api/system-settings", json={"settings": {"registration_enabled": True}}, headers=admin_headers
    )
    assert resp.status_code == 200
    resp = await client.delete("/api/system-settings/registration_enabled", headers=admin_headers)
    assert resp.status_code == 200
