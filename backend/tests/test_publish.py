"""Outbound observable feeds: the token gate, the policy filter, and STIX shape."""

import pytest

from app.intelligence.observables import get_or_create_observable
from app.services.system_settings import invalidate_cache, update_settings


async def _seed(db_session):
    obs = await get_or_create_observable(db_session, "ipv4", "45.155.204.119", via="ioc_list", role="c2")
    dom = await get_or_create_observable(db_session, "domain", "bad-c2-domain.top", via="ai_extraction", evidence="s")
    denied = await get_or_create_observable(db_session, "ipv4", "193.149.176.201", via="manual")
    denied.is_denied = True
    low = await get_or_create_observable(db_session, "ipv4", "91.92.240.37", via="manual")
    low.current_confidence = 0.2  # below the publish floor
    # Dual-use infrastructure: a NordVPN exit on an EDL blocks customers.
    infra = await get_or_create_observable(db_session, "ipv4", "185.230.125.1", via="ioc_list", infra_tag="vpn")
    await db_session.flush()
    return obs, dom, denied, low, infra


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    """The settings cache is process-global — never leak 'publishing on'."""
    yield
    invalidate_cache()


async def _enable(db_session, **overrides):
    from sqlalchemy import text as sql

    # The singleton settings row is seeded at app startup, not by create_all.
    await db_session.execute(
        sql("INSERT INTO system_settings (id, settings, secrets) VALUES (1, '{}', '{}') ON CONFLICT (id) DO NOTHING")
    )
    await update_settings(
        db_session,
        {
            "observables_publish_enabled": True,
            "observables_publish_token": "test-token",
            **overrides,
        },
    )
    await db_session.commit()
    invalidate_cache()


@pytest.mark.asyncio
async def test_publish_disabled_is_404(client, db_session):
    resp = await client.get("/api/publish/edl/ipv4.txt")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_publish_requires_token(client, db_session):
    await _enable(db_session)
    assert (await client.get("/api/publish/edl/ipv4.txt")).status_code == 401
    assert (await client.get("/api/publish/edl/ipv4.txt", headers={"Authorization": "Bearer wrong"})).status_code == 401


@pytest.mark.asyncio
async def test_edl_applies_policy(client, db_session):
    await _seed(db_session)
    await _enable(db_session)
    resp = await client.get("/api/publish/edl/ipv4.txt", headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    body = resp.text
    assert "45.155.204.119" in body
    # Denied, below-floor, and infra-tagged values never publish.
    assert "193.149.176.201" not in body
    assert "91.92.240.37" not in body
    assert "185.230.125.1" not in body
    # Domains have their own file.
    assert "bad-c2-domain.top" not in body
    dom = await client.get("/api/publish/edl/domains.txt", headers={"Authorization": "Bearer test-token"})
    assert "bad-c2-domain.top" in dom.text


@pytest.mark.asyncio
async def test_query_token_accepted_for_appliances(client, db_session):
    await _seed(db_session)
    await _enable(db_session)
    resp = await client.get("/api/publish/edl/ipv4.txt?token=test-token")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_taxii_envelope_and_stix_shape(client, db_session):
    await _seed(db_session)
    await _enable(db_session)
    disc = await client.get("/api/taxii2/", headers={"Authorization": "Bearer test-token"})
    assert disc.status_code == 200
    assert "taxii" in disc.headers["content-type"]

    resp = await client.get(
        "/api/taxii2/api/collections/observables/objects/", headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    envelope = resp.json()
    patterns = {o["pattern"] for o in envelope["objects"]}
    assert "[ipv4-addr:value = '45.155.204.119']" in patterns
    assert "[domain-name:value = 'bad-c2-domain.top']" in patterns
    ip_obj = next(o for o in envelope["objects"] if "45.155" in o["pattern"])
    assert ip_obj["type"] == "indicator"
    assert ip_obj["confidence"] == 85
    assert "valid_until" in ip_obj  # IPs decay, so expiry ships downstream
    assert "c2" in ip_obj["labels"]
    dom_obj = next(o for o in envelope["objects"] if "domain-name" in o["pattern"])
    assert dom_obj["description"] == "s"  # evidence rides along


@pytest.mark.asyncio
async def test_publish_status_reports_counts(client, auth_headers, db_session):
    await _seed(db_session)
    await _enable(db_session)
    resp = await client.get("/api/publish/status", headers=auth_headers)
    assert resp.status_code == 200
    status = resp.json()
    assert status["enabled"] is True
    assert status["token_configured"] is True
    edl = {f["path"]: f["count"] for f in status["feeds"]["edl"]}
    assert edl["/api/publish/edl/ipv4.txt"] == 1
    assert edl["/api/publish/edl/domains.txt"] == 1
    assert status["never_publish_count"] == 1


@pytest.mark.asyncio
async def test_publish_excludes_shared_infra_and_never_suffixes(client, db_session):
    """A CDN-hosted stager and the org's own domain must never land on an EDL —
    they stay in the ledger, the publish boundary drops them."""
    await get_or_create_observable(db_session, "domain", "bad-c2-domain.top", via="ai_extraction")
    await get_or_create_observable(db_session, "domain", "evil-stager.workers.dev", via="ai_extraction")
    await get_or_create_observable(db_session, "domain", "portal.mycorp.com", via="ai_extraction")
    await get_or_create_observable(db_session, "url", "https://abc123.cloudfront.net/ldr.php", via="ai_extraction")
    await get_or_create_observable(db_session, "email", "hr@mycorp.com", via="ai_extraction")
    await db_session.flush()
    await _enable(db_session, observables_publish_never_suffixes="mycorp.com")

    domains = (await client.get("/api/publish/edl/domains.txt", headers={"Authorization": "Bearer test-token"})).text
    assert "bad-c2-domain.top" in domains
    assert "workers.dev" not in domains
    assert "mycorp.com" not in domains

    urls = (await client.get("/api/publish/edl/urls.txt", headers={"Authorization": "Bearer test-token"})).text
    assert "cloudfront.net" not in urls

    taxii = (
        await client.get(
            "/api/taxii2/api/collections/observables/objects/", headers={"Authorization": "Bearer test-token"}
        )
    ).json()
    published = {o["name"] for o in taxii["objects"]}
    assert published == {"bad-c2-domain.top"}


@pytest.mark.asyncio
async def test_taxii_next_param_paginates(client, db_session):
    """Real TAXII 2.1 clients paginate with ?next=<envelope.next>."""
    await _seed(db_session)
    await _enable(db_session)
    headers = {"Authorization": "Bearer test-token"}
    base = "/api/taxii2/api/collections/observables/objects/"

    first = await client.get(f"{base}?limit=1", headers=headers)
    env = first.json()
    assert env["more"] is True and "next" in env
    assert "X-TAXII-Date-Added-Last" in first.headers

    second = (await client.get(f"{base}?limit=50&next={env['next']}", headers=headers)).json()
    first_ids = {o["id"] for o in env["objects"]}
    assert first_ids.isdisjoint({o["id"] for o in second["objects"]})
    assert second["more"] is False
