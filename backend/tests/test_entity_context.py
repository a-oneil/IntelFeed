"""Source context: what lookups store in entity_context and what
GET /api/entities/{entity_type}/{entity_id}/context serves the profile."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text

from app.config import settings
from app.core.encryption import encrypt_value
from app.enrichment.base import EnrichmentData
from app.enrichment.context import prune_expired_context, shape, store_context
from app.enrichment.manifest import Context, Display, Egress
from app.enrichment.registry import SOURCE_REGISTRY
from app.models.cve import CVE
from app.models.enrichment import EnrichmentResult, EnrichmentSource, EntityContext
from app.models.entity_field_claim import EntityFieldClaim
from app.models.observable import Observable
from app.models.threat_actor import EntryThreatActor, ThreatActor

NOW = datetime.now(UTC)


def _source(source_type: str, **fields) -> EnrichmentSource:
    cls = SOURCE_REGISTRY[source_type]
    return EnrichmentSource(
        source_type=source_type,
        display_name=cls.display_name,
        rate_limit_config=cls.quota.rate_limit_config,
        daily_budget=cls.quota.daily_budget,
        is_enabled=fields.pop("is_enabled", True),
        trigger_mode=fields.pop("trigger_mode", "manual"),
        **fields,
    )


async def _context(db, entity_type, entity_id) -> dict:
    rows = (
        await db.execute(
            select(EntityContext).where(EntityContext.entity_type == entity_type, EntityContext.entity_id == entity_id)
        )
    ).scalars()
    return {(r.source_type, r.key): r.value for r in rows}


async def _store(db, entity_type, entity_id, source_type, data, observed=NOW, ttl=timedelta(hours=24)):
    await store_context(db, entity_type, entity_id, source_type, data, observed_at=observed, expires_at=observed + ttl)
    await db.flush()


def _ip(value="71.6.135.131", kind="ipv4") -> Observable:
    return Observable(kind=kind, value=value, base_confidence=0.8, current_confidence=0.8)


SHODAN = {"found": True, "ports": "22, 443, 22", "hostnames": None, "tags": "vpn", "vulns": None, "cpes": None}
GREYNOISE = {
    "found": True,
    "noise_class": "benign",
    "noise": True,
    "riot": False,
    "name": "Shodan.io",
    "last_seen": "2026-10-27",
    "link": "https://viz.greynoise.io/ip/71.6.135.131",
}
NVD = {
    "cve_id": "CVE-2024-3400",
    "description": "A command injection in PAN-OS GlobalProtect.",
    "cvss_score": 10.0,
    "cvss_severity": "CRITICAL",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "published": "2024-04-12T08:15:06.230",
    "last_modified": "2024-04-19T01:00:00.000",
    "references": [{"url": "https://security.paloaltonetworks.com/CVE-2024-3400", "source": "psirt", "tags": []}],
    "weaknesses": ["CWE-77", "CWE-20"],
}


# ── Shaping, one display at a time ───────────────────────────────────


@pytest.mark.parametrize(
    ("display", "item", "value", "stored"),
    [
        (Display.FACT, None, "  10439 · CARINET ", "10439 · CARINET"),
        (Display.FACT, None, 0.97, 0.97),
        (Display.FACT, None, False, "no"),
        (Display.FACT, None, ["CWE-77", "CWE-20"], "CWE-77, CWE-20"),
        (Display.FACT, None, {"nested": 1}, None),
        (Display.FACT, None, "  ", None),
        (Display.CHIPS, None, "22, 443, 22", ["22", "443"]),
        (Display.CHIPS, None, ["APT28", "", 7, {"x": 1}], ["APT28", "7"]),
        (Display.CHIPS, None, [], None),
        (
            Display.TABLE,
            {"Repository": "name", "Stars": "stars", "Ranges": "ranges"},
            [
                {"name": "poc", "stars": 12, "ranges": [{"type": "SEMVER", "fixed": ["2.15.0"]}]},
                {"name": None, "stars": None},
            ],
            {"columns": ["Repository", "Stars", "Ranges"], "rows": [["poc", 12, "type SEMVER, fixed 2.15.0"]]},
        ),
        (
            Display.TABLE,
            {"Link": None},
            ["https://malpedia.example/a", "https://malpedia.example/b"],
            {"columns": ["Link"], "rows": [["https://malpedia.example/a"], ["https://malpedia.example/b"]]},
        ),
        (Display.TABLE, {"Link": "url"}, "not a list", None),
        (
            Display.TIMELINE,
            {"date": "when", "text": "what"},
            [{"when": "2013-02", "what": "MiniDuke PDF exploit"}, {"when": "2014-01"}],
            [{"date": "2013-02", "text": "MiniDuke PDF exploit"}],
        ),
        (Display.LINK, None, "https://viz.greynoise.io/ip/1.2.3.4", {"url": "https://viz.greynoise.io/ip/1.2.3.4"}),
        (
            Display.LINK,
            None,
            {"url": "https://x.example/", "label": "Card"},
            {"url": "https://x.example/", "label": "Card"},
        ),
        (Display.LINK, None, "javascript:alert(1)", None),
        (Display.LINK, None, ["https://x.example/"], None),
        (Display.BADGE, None, "benign", "benign"),
        (Display.BADGE, None, True, True),
        (Display.BADGE, None, None, None),
    ],
)
def test_each_display_stores_its_shape(display, item, value, stored):
    assert shape(Context("k", "Label", display, item=item), value) == stored


# ── Writing context with a lookup's result ───────────────────────────


async def test_a_result_writes_every_declared_output_it_has(db_session):
    obs = _ip()
    db_session.add(obs)
    await db_session.flush()

    await _store(db_session, "observable", obs.id, "shodan", SHODAN)
    await _store(db_session, "observable", obs.id, "greynoise", GREYNOISE)

    assert await _context(db_session, "observable", obs.id) == {
        ("shodan", "ports"): ["22", "443"],
        ("shodan", "tags"): ["vpn"],
        ("greynoise", "noise_class"): "benign",
        ("greynoise", "riot"): "no",
        ("greynoise", "name"): "Shodan.io",
        ("greynoise", "last_seen"): "2026-10-27",
        ("greynoise", "link"): {"url": "https://viz.greynoise.io/ip/71.6.135.131"},
    }
    row = (await db_session.execute(select(EntityContext).where(EntityContext.key == "ports"))).scalar_one()
    assert row.observed_at == NOW and row.expires_at == NOW + timedelta(hours=24)


async def test_a_newer_result_drops_the_keys_it_no_longer_carries(db_session):
    obs_id = uuid.uuid4()
    await _store(db_session, "observable", obs_id, "shodan", SHODAN)
    later = NOW + timedelta(days=1)
    await _store(db_session, "observable", obs_id, "shodan", {**SHODAN, "tags": None}, observed=later)

    assert await _context(db_session, "observable", obs_id) == {("shodan", "ports"): ["22", "443"]}
    row = (await db_session.execute(select(EntityContext).where(EntityContext.entity_id == obs_id))).scalar_one()
    assert row.observed_at == later

    # Not found any more: the source has nothing left to say.
    await _store(db_session, "observable", obs_id, "shodan", {"found": False})
    assert await _context(db_session, "observable", obs_id) == {}


async def test_outputs_scoped_to_other_types_are_not_written(db_session):
    actor_id = uuid.uuid4()
    data = {"urls": ["https://malpedia.example/u"], "refs": ["https://malpedia.example/r"], "families": ["win.x"]}
    await _store(db_session, "threat_actor", actor_id, "malpedia", data)
    assert set(await _context(db_session, "threat_actor", actor_id)) == {("malpedia", "refs"), ("malpedia", "families")}


# ── The pipeline: context with each lookup, results only on change ───


async def _lookup(db, monkeypatch, obs, parsed: dict):
    from app.enrichment.adapters import shodan
    from app.enrichment.pipeline import enrich_entity

    async def fake_enrich(self, entity_type, value):
        return EnrichmentData(raw_response={"n": 1}, parsed_data=parsed, ttl_hours=24)

    monkeypatch.setattr(shodan.ShodanAdapter, "enrich", fake_enrich)
    results = await enrich_entity("observable", obs.id, obs.value, db, trigger="manual", source_types=["shodan"])
    await db.flush()
    return results


async def _results(db, entity_id) -> list[EnrichmentResult]:
    return (
        (
            await db.execute(
                select(EnrichmentResult)
                .where(EnrichmentResult.entity_id == entity_id)
                .order_by(EnrichmentResult.enriched_at)
            )
        )
        .scalars()
        .all()
    )


async def _expire(db, entity_id):
    for r in await _results(db, entity_id):
        r.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    await db.flush()


async def test_a_lookup_stores_a_result_only_when_it_changed(db_session, monkeypatch):
    obs = _ip()
    db_session.add_all([obs, _source("shodan")])
    await db_session.flush()

    await _lookup(db_session, monkeypatch, obs, SHODAN)
    first = await _results(db_session, obs.id)
    assert len(first) == 1
    stamped = first[0].enriched_at

    await _expire(db_session, obs.id)
    await _lookup(db_session, monkeypatch, obs, dict(SHODAN))
    same = await _results(db_session, obs.id)
    assert [r.id for r in same] == [first[0].id]
    assert same[0].enriched_at > stamped
    assert same[0].expires_at > datetime.now(UTC)

    await _expire(db_session, obs.id)
    await _lookup(db_session, monkeypatch, obs, {**SHODAN, "ports": "8443"})
    changed = await _results(db_session, obs.id)
    assert len(changed) == 2
    assert (await _context(db_session, "observable", obs.id))[("shodan", "ports")] == ["8443"]


async def test_a_cached_lookup_writes_context_dated_by_its_result(db_session):
    from app.enrichment.pipeline import enrich_entity

    obs = _ip()
    db_session.add_all([obs, _source("shodan")])
    await db_session.flush()
    observed = datetime.now(UTC) - timedelta(hours=3)
    db_session.add(
        EnrichmentResult(
            entity_type="observable",
            entity_id=obs.id,
            source_type="shodan",
            raw_response={},
            parsed_data=SHODAN,
            enriched_at=observed,
            expires_at=observed + timedelta(hours=24),
            status="success",
        )
    )
    await db_session.flush()

    results = await enrich_entity("observable", obs.id, obs.value, db_session, trigger="manual")
    assert [r["status"] for r in results] == ["cached"]
    row = (await db_session.execute(select(EntityContext).where(EntityContext.key == "ports"))).scalar_one()
    assert row.observed_at == observed


# ── GET …/context ────────────────────────────────────────────────────


async def _get(client, entity_type, entity_id, headers=None):
    return await client.get(f"/api/entities/{entity_type}/{entity_id}/context", headers=headers or {})


@pytest.fixture
async def observable_with_context(db_session):
    obs = _ip()
    db_session.add_all([obs, _source("shodan"), _source("greynoise"), _source("virustotal")])
    await db_session.flush()
    await _store(db_session, "observable", obs.id, "shodan", SHODAN)
    await _store(db_session, "observable", obs.id, "greynoise", GREYNOISE)
    return obs


async def test_a_signed_in_viewer_gets_each_applicable_source(client, auth_headers, observable_with_context):
    resp = await _get(client, "observable", observable_with_context.id, auth_headers)
    assert resp.status_code == 200
    body = resp.json()

    # VirusTotal has no key: not a source until it has data, and only admins
    # are told it needs one.
    assert [s["source_type"] for s in body["sources"]] == ["greynoise", "shodan"]
    assert body["unavailable"] == []
    assert body["can_enrich"] is True
    shodan = body["sources"][1]
    assert shodan["label"] == "Shodan InternetDB"
    assert shodan["license"] == {"name": "InternetDB, free for non-commercial use", "attribution": "Shodan"}
    assert shodan["stale"] is False
    assert datetime.fromisoformat(shodan["observed_at"]) == NOW
    assert shodan["items"] == [
        {"key": "ports", "label": "Open ports", "display": "chips", "value": ["22", "443"]},
        {"key": "tags", "label": "Tags", "display": "chips", "value": ["vpn"]},
    ]
    # The badge mirrors the column GreyNoise also writes.
    assert body["badges"] == [
        {
            "source_type": "greynoise",
            "key": "noise_class",
            "label": "noise · benign",
            "tone": "success",
            "field": "noise_class",
        }
    ]


async def test_admins_see_what_is_unavailable(client, admin_headers, observable_with_context):
    body = (await _get(client, "observable", observable_with_context.id, admin_headers)).json()
    assert body["unavailable"] == [{"source_type": "virustotal", "label": "VirusTotal v3", "needs": "api_key"}]


async def test_a_source_with_a_key_and_no_data_yet_is_listed_empty(client, auth_headers, db_session):
    obs = _ip("example.org", kind="domain")
    db_session.add_all([obs, _source("shodan"), _source("virustotal", api_key_encrypted=encrypt_value("k"))])
    await db_session.flush()

    body = (await _get(client, "observable", obs.id, auth_headers)).json()
    # Shodan covers IPv4 only, so a domain doesn't list it.
    assert body["sources"] == [
        {
            "source_type": "virustotal",
            "label": "VirusTotal v3",
            "license": {"name": "VirusTotal public API terms", "attribution": "VirusTotal"},
            "observed_at": None,
            "stale": False,
            "items": [],
        }
    ]


async def test_disabled_sources_and_expired_rows(client, auth_headers, db_session):
    obs = _ip()
    db_session.add_all([obs, _source("shodan"), _source("greynoise", is_enabled=False)])
    await db_session.flush()
    await _store(db_session, "observable", obs.id, "shodan", SHODAN, observed=NOW - timedelta(days=2))
    await _store(db_session, "observable", obs.id, "greynoise", GREYNOISE)

    body = (await _get(client, "observable", obs.id, auth_headers)).json()
    assert [s["source_type"] for s in body["sources"]] == ["shodan"]
    assert body["sources"][0]["stale"] is True
    assert body["badges"] == []


async def test_unknown_types_and_missing_entities(client, auth_headers):
    assert (await _get(client, "spaceship", uuid.uuid4(), auth_headers)).status_code == 400
    assert (await _get(client, "cve", uuid.uuid4(), auth_headers)).status_code == 404


@pytest.fixture
async def cve_with_context(db_session):
    cve = CVE(cve_id="CVE-2024-3400")
    db_session.add_all(
        [
            cve,
            _source("nvd"),
            _source("cvedetails", api_key_encrypted=encrypt_value("k")),
            _source("vulncheck", api_key_encrypted=encrypt_value("k")),
            _source("github_poc"),
        ]
    )
    await db_session.flush()
    await _store(db_session, "cve", cve.id, "nvd", NVD, ttl=timedelta(hours=168))
    await _store(db_session, "cve", cve.id, "cvedetails", {"cvedetails_url": "https://www.cvedetails.com/cve/X/"})
    await _store(db_session, "cve", cve.id, "vulncheck", {"found": True, "in_kev": True, "date_added": "2024-04-12"})
    await _store(db_session, "cve", cve.id, "github_poc", {"exploit_maturity": "weaponized", "poc_count": 4})
    return cve


@pytest.fixture
def public_mode(monkeypatch):
    monkeypatch.setattr(settings, "public_read_only_enabled", True)


async def test_visitors_never_see_non_commercial_or_ioc_sharing_sources(
    client, cve_with_context, public_mode, monkeypatch
):
    body = (await _get(client, "cve", cve_with_context.id)).json()
    assert [s["source_type"] for s in body["sources"]] == ["github_poc", "nvd", "vulncheck"]
    assert body["can_enrich"] is False
    assert body["unavailable"] == []

    # A source that sends the value off the box is hidden whatever its license.
    monkeypatch.setattr(SOURCE_REGISTRY["nvd"], "egress", Egress.SHARES_IOC)
    body = (await _get(client, "cve", cve_with_context.id)).json()
    assert [s["source_type"] for s in body["sources"]] == ["github_poc", "vulncheck"]


async def test_signed_in_viewers_see_non_commercial_sources(client, auth_headers, cve_with_context):
    body = (await _get(client, "cve", cve_with_context.id, auth_headers)).json()
    assert [s["source_type"] for s in body["sources"]] == ["cvedetails", "github_poc", "nvd", "vulncheck"]
    assert body["badges"] == [
        {"source_type": "github_poc", "key": "exploit_maturity", "label": "PoC · weaponized", "tone": "high"},
        {"source_type": "vulncheck", "key": "in_kev", "label": "VulnCheck KEV", "tone": "critical"},
    ]


async def test_visitors_get_a_404_for_entities_they_cant_see(
    client, auth_headers, db_session, test_entry, observable_with_context, public_mode
):
    # Known only from an article in a feed visitors don't see.
    actor = ThreatActor(name="Hidden Actor")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=test_entry.id, threat_actor_id=actor.id, matched_names=["Hidden Actor"]))
    await db_session.flush()

    assert (await _get(client, "threat_actor", actor.id)).status_code == 404
    assert (await _get(client, "observable", observable_with_context.id)).status_code == 404
    assert (await _get(client, "threat_actor", actor.id, auth_headers)).status_code == 200


# ── The frontend contract (frontend/src/hooks/useEntityContext.ts) ───

_TONES = {"critical", "high", "medium", "low", "info", "neutral", "success", "danger", "warning"}


def _is_cell(v) -> bool:
    return v is None or (isinstance(v, (str, int, float)) and not isinstance(v, bool))


def _check_item(item: dict) -> None:
    assert set(item) == {"key", "label", "display", "value"}
    assert isinstance(item["key"], str) and isinstance(item["label"], str)
    value = item["value"]
    match item["display"]:
        case "fact":
            assert isinstance(value, (str, int, float)) and not isinstance(value, bool)
        case "chips":
            assert isinstance(value, list) and all(isinstance(v, str) for v in value)
        case "timeline":
            assert all(set(e) == {"date", "text"} and all(isinstance(x, str) for x in e.values()) for e in value)
        case "table":
            assert set(value) == {"columns", "rows"}
            assert all(isinstance(c, str) for c in value["columns"])
            assert all(len(row) == len(value["columns"]) and all(map(_is_cell, row)) for row in value["rows"])
        case "link":
            assert isinstance(value, dict) and isinstance(value["url"], str)
            assert set(value) <= {"url", "label"}
        case "badge":
            pass
        case other:
            raise AssertionError(f"unknown display {other}")


def check_entity_context(body: dict) -> None:
    """A hand-written check of the EntityContext TypeScript type."""
    assert set(body) == {"sources", "unavailable", "badges", "can_enrich"}
    assert isinstance(body["can_enrich"], bool)
    for s in body["sources"]:
        assert set(s) == {"source_type", "label", "license", "observed_at", "stale", "items"}
        assert isinstance(s["source_type"], str) and isinstance(s["label"], str) and isinstance(s["stale"], bool)
        assert s["license"] is None or (
            set(s["license"]) == {"name", "attribution"} and isinstance(s["license"]["name"], str)
        )
        assert s["observed_at"] is None or datetime.fromisoformat(s["observed_at"])
        for item in s["items"]:
            _check_item(item)
    for u in body["unavailable"]:
        assert set(u) == {"source_type", "label", "needs"} and all(isinstance(v, str) for v in u.values())
    for b in body["badges"]:
        assert {"source_type", "key", "label", "tone"} <= set(b) <= {"source_type", "key", "label", "tone", "field"}
        assert b["tone"] in _TONES and all(isinstance(v, str) for v in b.values())


async def test_the_body_satisfies_the_frontend_type(
    client, admin_headers, db_session, observable_with_context, cve_with_context
):
    await _store(
        db_session,
        "cve",
        cve_with_context.id,
        "osv",
        {
            "aliases": ["GHSA-x"],
            "affected": [{"ecosystem": "PyPI", "package_name": "p", "ranges": [{"fixed": ["1.2"]}]}],
            "references": [{"type": "WEB", "url": "https://osv.dev/x"}],
        },
    )
    db_session.add(_source("osv"))
    await db_session.flush()
    for entity_type, entity in (("observable", observable_with_context), ("cve", cve_with_context)):
        body = (await _get(client, entity_type, entity.id, admin_headers)).json()
        assert body["sources"]
        check_entity_context(body)
    assert {i["display"] for s in body["sources"] for i in s["items"]} >= {"fact", "chips", "table", "link", "badge"}


# ── NVD lookups fill the CVE without fighting extraction ─────────────

_EXTRACTED = {
    "cvss_score": 9.8,
    "severity": "CRITICAL",
    "description": "From the extraction-time NVD call.",
    "affected_products": [],
    "references": [],
    "nvd_data": {},
}


async def _extract(db, monkeypatch, nvd_answer):
    from app.intelligence import cve as cve_module

    async def fake_gateway(db):
        return None, None

    async def fake_nvd(cve_id, gateway, api_key=None):
        return nvd_answer

    monkeypatch.setattr(cve_module, "nvd_gateway", fake_gateway)
    monkeypatch.setattr(cve_module, "enrich_from_nvd", fake_nvd)
    (stored,) = await cve_module.extract_and_store_cves(db, uuid.uuid4(), "Patch CVE-2024-3400 now.")
    return stored


async def _claims(db, entity_id) -> set[tuple[str, str]]:
    rows = await db.execute(
        select(EntityFieldClaim.field, EntityFieldClaim.source_ref).where(EntityFieldClaim.entity_id == entity_id)
    )
    return set(rows.all())


async def test_extraction_writes_nvd_columns_and_a_lookup_leaves_them(db_session, test_entry, monkeypatch):
    from app.enrichment.entity_updater import apply_enrichment_results_to_entity
    from app.intelligence import cve as cve_module

    async def fake_gateway(db):
        return None, None

    async def fake_nvd(cve_id, gateway, api_key=None):
        return _EXTRACTED

    monkeypatch.setattr(cve_module, "nvd_gateway", fake_gateway)
    monkeypatch.setattr(cve_module, "enrich_from_nvd", fake_nvd)
    (cve,) = await cve_module.extract_and_store_cves(db_session, test_entry.id, "Patch CVE-2024-3400 now.")
    # Today's extraction path: score, severity and description from its own call.
    assert (float(cve.cvss_score), cve.severity, cve.description) == (9.8, "CRITICAL", _EXTRACTED["description"])

    nvd = {"status": "success", "source_type": "nvd", "parsed_data": NVD}
    assert await apply_enrichment_results_to_entity(db_session, "cve", cve.id, [nvd]) is False
    await db_session.flush()
    assert (float(cve.cvss_score), cve.severity, cve.description) == (9.8, "CRITICAL", _EXTRACTED["description"])
    assert await _claims(db_session, cve.id) == set()


async def test_a_lookup_fills_a_cve_extraction_left_bare(db_session, test_entry, monkeypatch):
    from app.enrichment.entity_updater import apply_enrichment_results_to_entity
    from app.intelligence import cve as cve_module

    async def fake_gateway(db):
        return None, None

    async def throttled(cve_id, gateway, api_key=None):
        return None

    monkeypatch.setattr(cve_module, "nvd_gateway", fake_gateway)
    monkeypatch.setattr(cve_module, "enrich_from_nvd", throttled)
    (cve,) = await cve_module.extract_and_store_cves(db_session, test_entry.id, "Patch CVE-2024-3400 now.")
    assert (cve.cvss_score, cve.severity, cve.description) == (None, None, None)

    nvd = {"status": "success", "source_type": "nvd", "parsed_data": NVD}
    assert await apply_enrichment_results_to_entity(db_session, "cve", cve.id, [nvd]) is True
    await db_session.flush()
    assert (float(cve.cvss_score), cve.severity, cve.description) == (10.0, "CRITICAL", NVD["description"])
    assert await _claims(db_session, cve.id) == {("cvss_score", "nvd"), ("severity", "nvd"), ("description", "nvd")}


# ── Prune ────────────────────────────────────────────────────────────


async def test_the_nightly_prune_drops_rows_expired_over_30_days(db_session):
    from app.workers.job_registry import JOB_REGISTRY

    old, recent = uuid.uuid4(), uuid.uuid4()
    await _store(db_session, "observable", old, "shodan", SHODAN, observed=NOW - timedelta(days=32))
    await _store(db_session, "observable", recent, "shodan", SHODAN, observed=NOW - timedelta(days=29))

    assert await prune_expired_context(db_session) == 2
    left = {r for (r,) in await db_session.execute(select(EntityContext.entity_id))}
    assert left == {recent}

    job = JOB_REGISTRY["prune-entity-context"]
    assert job["task"] == "app.workers.maintenance.prune_entity_context"
    assert job["category"] == "maintenance" and "source" not in job


# ── Migration ────────────────────────────────────────────────────────


async def test_migration_creates_and_drops_the_table(db_session):
    import importlib.util
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = Path(__file__).parent.parent / "alembic" / "versions" / "e6c7t8x9a0b1_entity_context.py"
    spec = importlib.util.spec_from_file_location("entity_context_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    def run(step):
        def go(sync_conn):
            with Operations.context(MigrationContext.configure(sync_conn)):
                step()

        return go

    async def exists() -> bool:
        return bool((await db_session.execute(text("SELECT to_regclass('entity_context') IS NOT NULL"))).scalar())

    connection = await db_session.connection()
    await connection.run_sync(run(migration.downgrade))
    assert not await exists()
    await connection.run_sync(run(migration.upgrade))
    assert await exists()
    pk = (
        await db_session.execute(
            text(
                "SELECT array_agg(a.attname ORDER BY k.ord) FROM pg_index i "
                "CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) "
                "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum "
                "WHERE i.indrelid = 'entity_context'::regclass AND i.indisprimary"
            )
        )
    ).scalar()
    assert pk == ["entity_type", "entity_id", "source_type", "key"]
    assert (await db_session.execute(select(func.count()).select_from(EntityContext))).scalar() == 0
