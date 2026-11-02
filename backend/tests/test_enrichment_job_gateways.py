"""Scheduled enrichment jobs reach their sources only through a SourceGateway.

Each test runs the real gateway (Redis bucket, budget and breaker; conftest
gives every test its own key prefix) with ``httpx.MockTransport`` in place of
the network. A refusal (rate limited, breaker open, budget spent) stops a job
cleanly with a reason in its stats; an unreachable gateway fails the run.
"""

import gzip
import importlib.util
import io
import uuid
import zipfile
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import redis.asyncio as aioredis
from sqlalchemy import select

import app.workers.enrichment_tasks as tasks
from app.enrichment import gateway as gw
from app.enrichment.adapters.github_poc import GitHubPoCAdapter
from app.enrichment.adapters.nvd import NVDAdapter
from app.enrichment.gateway import USER_AGENT, BreakerOpen, GatewayUnavailable, SourceGateway
from app.models.cve import CVE
from app.models.enrichment import EnrichmentSource
from app.models.vendor import Vendor


class _Upstream:
    """Stands in for every source: answers by URL fragment, records requests."""

    def __init__(self):
        self.routes: dict[str, list[Callable[[], httpx.Response]]] = {}
        self.requests: list[httpx.Request] = []

    def route(self, fragment: str, *replies: Callable[[], httpx.Response]) -> None:
        """Answer URLs containing ``fragment`` with each reply in turn; the last repeats."""
        self.routes[fragment] = list(replies)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        for fragment, replies in self.routes.items():
            if fragment in str(request.url):
                reply = replies.pop(0) if len(replies) > 1 else replies[0]
                return reply()
        return httpx.Response(404)


def _json(body, status: int = 200) -> Callable[[], httpx.Response]:
    return lambda: httpx.Response(status, json=body)


def _status(status: int) -> Callable[[], httpx.Response]:
    return lambda: httpx.Response(status)


@pytest.fixture
def upstream(monkeypatch):
    """Every gateway built without an ``inner`` transport sends to this fake."""
    server = _Upstream()

    def transport(self):
        return gw._GatewayTransport(self, self._inner or httpx.MockTransport(server))

    monkeypatch.setattr(SourceGateway, "transport", transport)
    return server


@pytest.fixture
def worker_session(db_session, monkeypatch):
    import app.workers.maintenance as maintenance

    @asynccontextmanager
    async def fake_session():
        yield db_session

    monkeypatch.setattr(tasks, "_get_worker_session", fake_session)
    monkeypatch.setattr(maintenance, "_get_worker_session", fake_session)


@pytest.fixture
def no_settings(monkeypatch):
    """No instance-wide fallback keys (nvd_api_key, github_token)."""
    import app.services.system_settings as ss

    async def no_setting(key, db=None):
        return ""

    monkeypatch.setattr(ss, "get_setting", no_setting)
    monkeypatch.setattr(ss, "get_setting_cached", lambda key: "" if key == "github_token" else None)


@pytest.fixture
def broken_redis(monkeypatch):
    dead = aioredis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.5)

    async def broken():
        return dead

    monkeypatch.setattr(gw, "get_redis_bytes", broken)


async def _source_row(db_session, source_type: str, **fields) -> EnrichmentSource:
    row = EnrichmentSource(
        source_type=source_type,
        display_name=source_type,
        is_enabled=True,
        trigger_mode="manual",
        config={},
        rate_limit_config={"requests_per_period": 100, "period_seconds": 60},
    )
    for k, v in fields.items():
        setattr(row, k, v)
    db_session.add(row)
    await db_session.flush()
    return row


def _all_through_gateway(server: _Upstream) -> bool:
    return bool(server.requests) and all(r.headers["User-Agent"] == USER_AGENT for r in server.requests)


# ── Every job sends through its gateway ─────────────────────────────


def _epss_csv() -> httpx.Response:
    csv = "#model_version:v2023.03.01\ncve,epss,percentile\nCVE-2026-70001,0.42,0.9\n"
    return httpx.Response(200, content=gzip.compress(csv.encode()))


def _cwe_zip() -> httpx.Response:
    xml = '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"><Weaknesses/><Categories/></Weakness_Catalog>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("cwec_v4.20.xml", xml)
    return httpx.Response(200, content=buf.getvalue())


async def _run_kev(db_session):
    from app.intelligence.external_feeds import sync_kev_feed

    return await sync_kev_feed(db_session)


async def _run_cwe(db_session):
    from app.intelligence.cwe_catalog import refresh_cwe_catalog

    return await refresh_cwe_catalog(db_session)


async def _run_cybergeist(db_session):
    from app.intelligence.external_feeds import sync_cybergeist_threat_actors

    return await sync_cybergeist_threat_actors(db_session)


async def _run_ransomware(db_session):
    from app.intelligence.ransomware_sync import sync_ransomware_victims

    return await sync_ransomware_victims(db_session)


# (job, url fragment, reply, the gateway scope it charges)
SINGLE_DOWNLOAD_JOBS = [
    pytest.param(lambda db: tasks._run_epss_bulk_sync(), "epss_scores", _epss_csv, "epss", id="epss-bulk-sync"),
    pytest.param(
        lambda db: tasks._run_mitre_attack_sync(),
        "attack-stix-data",
        _json({"type": "bundle", "objects": []}),
        "mitre_attack",
        id="mitre-attack-sync",
    ),
    pytest.param(
        lambda db: tasks._run_misp_galaxy_sync(), "misp-galaxy", _json({"values": []}), "misp_galaxy", id="misp"
    ),
    pytest.param(
        lambda db: tasks._run_metasploit_sync(), "metasploit-framework", _json({}), "metasploit", id="metasploit"
    ),
    pytest.param(
        _run_kev, "known_exploited", _json({"catalogVersion": "t", "vulnerabilities": []}), "cisa_kev", id="kev"
    ),
    pytest.param(_run_cwe, "cwec_latest", _cwe_zip, "mitre_cwe", id="cwe-catalog"),
    pytest.param(_run_cybergeist, "cybergeist.io", _json([]), "cybergeist", id="cybergeist"),
    pytest.param(_run_ransomware, "ransomware.live", _json([]), "ransomware_live", id="ransomware-victims"),
]


@pytest.fixture
def private_kev_version(monkeypatch):
    from app.intelligence import external_feeds

    monkeypatch.setattr(external_feeds, "KEV_REDIS_KEY", f"intelfeed:test:{uuid.uuid4().hex}:kev")


@pytest.mark.parametrize(("job", "fragment", "reply", "scope"), SINGLE_DOWNLOAD_JOBS)
async def test_job_downloads_through_its_gateway(
    job, fragment, reply, scope, db_session, worker_session, upstream, private_kev_version
):
    upstream.route(fragment, reply)
    stats = await job(db_session)

    assert "stopped" not in stats or stats["stopped"] is None
    assert _all_through_gateway(upstream)
    assert await SourceGateway(scope).used_today() == len(upstream.requests)


@pytest.mark.parametrize(("job", "fragment", "reply", "scope"), SINGLE_DOWNLOAD_JOBS)
async def test_job_skips_cleanly_when_its_breaker_is_open(
    job, fragment, reply, scope, db_session, worker_session, upstream, private_kev_version
):
    upstream.route(fragment, reply)
    await SourceGateway(scope)._trip("throttle", 600)

    stats = await job(db_session)

    assert stats["stopped"] == "breaker_open"
    assert upstream.requests == []


@pytest.mark.parametrize(("job", "fragment", "reply", "scope"), SINGLE_DOWNLOAD_JOBS)
async def test_job_stops_while_enrichment_is_paused(
    job, fragment, reply, scope, db_session, worker_session, upstream, private_kev_version, pause_enrichment
):
    upstream.route(fragment, reply)
    await pause_enrichment()

    stats = await job(db_session)

    assert stats["stopped"] == "paused"
    assert upstream.requests == []


async def test_epss_uses_the_source_rows_budget(db_session, worker_session, upstream):
    await _source_row(db_session, "epss", daily_budget=0)
    upstream.route("epss_scores", _epss_csv)

    stats = await tasks._run_epss_bulk_sync()

    assert stats["stopped"] == "budget_exhausted"
    assert upstream.requests == []


async def test_single_download_job_fails_when_the_gateway_is_unavailable(
    db_session, worker_session, upstream, broken_redis
):
    upstream.route("epss_scores", _epss_csv)
    with pytest.raises(GatewayUnavailable):
        await tasks._run_epss_bulk_sync()
    assert upstream.requests == []


# ── GitHub PoC: a loop job keeps what it did ────────────────────────


def _poc_hit() -> httpx.Response:
    repo = {"name": "poc", "html_url": "https://github.com/x/poc", "stargazers_count": 3, "language": "Python"}
    return httpx.Response(200, json={"total_count": 1, "items": [repo]})


@pytest.fixture
async def poc_cves(db_session):
    rows = [CVE(cve_id=f"CVE-2026-7100{i}", is_kev=True, epss_score=0.9 - i / 10) for i in range(3)]
    db_session.add_all(rows)
    await db_session.flush()
    return rows


async def test_github_poc_scan_sends_the_fallback_token_through_its_bucket(
    db_session, worker_session, upstream, poc_cves, monkeypatch
):
    async def github_token(key, db=None):
        return "fallback-token" if key == "github_token" else ""

    monkeypatch.setattr("app.services.system_settings.get_setting", github_token)
    upstream.route("api.github.com", _poc_hit)

    stats = await tasks._run_github_poc_scan()

    assert stats == {"fetched": 3, "changed": 3, "written": 3, "scanned": 3, "pocs_found": 3, "stopped": None}
    assert _all_through_gateway(upstream)
    assert upstream.requests[0].headers["Authorization"] == "Bearer fallback-token"
    # The token has its own allowance, apart from the keyless one.
    assert await SourceGateway("github_poc", api_key="fallback-token").used_today() == 3
    assert await SourceGateway("github_poc").used_today() == 0


async def test_github_poc_scan_stops_on_a_403_and_commits_what_it_did(
    db_session, worker_session, upstream, poc_cves, no_settings
):
    upstream.route("api.github.com", _poc_hit, _status(403))

    stats = await tasks._run_github_poc_scan()

    assert stats["stopped"] == "rate_limited"
    assert stats["scanned"] == 1
    assert len(upstream.requests) == 2
    first, second, _ = poc_cves
    await db_session.refresh(first)
    await db_session.refresh(second)
    assert first.github_poc_count == 1
    assert second.github_poc_count is None  # tomorrow's run
    # GitHub's 403 opened the breaker for the whole source.
    gateway = SourceGateway("github_poc", throttle_statuses=GitHubPoCAdapter.throttle_statuses)
    with pytest.raises(BreakerOpen):
        await gateway.acquire()


async def test_github_poc_scan_stops_when_the_budget_is_spent(
    db_session, worker_session, upstream, poc_cves, no_settings
):
    await _source_row(db_session, "github_poc", daily_budget=2)
    upstream.route("api.github.com", _poc_hit)

    stats = await tasks._run_github_poc_scan()

    assert stats["stopped"] == "budget_exhausted"
    assert stats["scanned"] == 2


async def test_github_poc_scan_stops_when_the_breaker_is_open(
    db_session, worker_session, upstream, poc_cves, no_settings
):
    await SourceGateway("github_poc")._trip("throttle", 600)
    upstream.route("api.github.com", _poc_hit)

    stats = await tasks._run_github_poc_scan()

    assert stats == {"fetched": 0, "changed": 0, "written": 0, "scanned": 0, "pocs_found": 0, "stopped": "breaker_open"}
    assert upstream.requests == []


async def test_github_poc_scan_fails_when_the_gateway_is_unavailable(
    db_session, worker_session, upstream, poc_cves, no_settings, broken_redis
):
    upstream.route("api.github.com", _poc_hit)
    with pytest.raises(GatewayUnavailable):
        await tasks._run_github_poc_scan()
    assert upstream.requests == []


# ── NVD sweeps ──────────────────────────────────────────────────────


def _nvd_record(request_cve: str = "CVE-2026-72000") -> Callable[[], httpx.Response]:
    body = {
        "vulnerabilities": [
            {"cve": {"id": request_cve, "descriptions": [{"lang": "en", "value": "Described by NVD"}], "metrics": {}}}
        ]
    }
    return _json(body)


@pytest.fixture
def fast_nvd_pace(monkeypatch):
    from app.intelligence import cve as cve_mod

    monkeypatch.setattr(cve_mod, "NVD_PACE_UNKEYED", 0.01)
    monkeypatch.setattr(cve_mod, "NVD_PACE_KEYED", 0.01)


async def test_nvd_backfill_stops_on_a_403_without_spending_a_retry(
    db_session, worker_session, upstream, no_settings, fast_nvd_pace
):
    rows = [CVE(cve_id=f"CVE-2026-7200{i}", nvd_data={}) for i in range(3)]
    db_session.add_all(rows)
    await db_session.flush()
    upstream.route("services.nvd.nist.gov", _nvd_record(), _status(403))

    stats = await tasks._run_cve_nvd_backfill()

    assert stats["stopped"] == "rate_limited"
    assert stats["enriched"] == 1
    assert _all_through_gateway(upstream) and len(upstream.requests) == 2
    await db_session.refresh(rows[0])
    await db_session.refresh(rows[1])
    assert rows[0].description == "Described by NVD"
    assert "_enrich_attempts" not in (rows[1].nvd_data or {})
    # NVD's 403 opened the breaker: per-entity lookups back off too.
    with pytest.raises(BreakerOpen):
        await SourceGateway("nvd", throttle_statuses=NVDAdapter.throttle_statuses).acquire()


async def test_nvd_sweeps_use_the_source_rows_key(db_session, worker_session, upstream, fast_nvd_pace, monkeypatch):
    from app.core.encryption import encrypt_value

    await _source_row(db_session, "nvd", api_key_encrypted=encrypt_value("row-key"))
    monkeypatch.setattr("app.services.system_settings.get_setting", lambda key, db=None: _value("setting-key"))
    db_session.add(CVE(cve_id="CVE-2026-72100", nvd_data={"id": "CVE-2026-72100"}))
    await db_session.flush()
    upstream.route("services.nvd.nist.gov", _nvd_record("CVE-2026-72100"))

    stats = await tasks._run_cve_nvd_refresh()

    assert stats["checked"] == 1 and stats["stopped"] is None
    assert upstream.requests[0].headers["apiKey"] == "row-key"
    assert await SourceGateway("nvd", api_key="row-key").used_today() == 1


async def _value(v):
    return v


async def test_reenrich_cve_nvd_stops_cleanly_when_refused(
    db_session, worker_session, upstream, no_settings, fast_nvd_pace
):
    import app.workers.maintenance as maintenance

    await _source_row(db_session, "nvd", daily_budget=0)
    row = CVE(cve_id="CVE-2026-72200", nvd_data={})
    db_session.add(row)
    await db_session.flush()

    stats = await maintenance._reenrich_cve_nvd(batch_size=5)

    assert stats["stopped"] == "budget_exhausted"
    assert stats["attempted"] == 0
    assert upstream.requests == []
    await db_session.refresh(row)
    assert "_enrich_attempts" not in (row.nvd_data or {})


async def test_kev_sync_queues_new_cves_instead_of_calling_nvd(
    db_session, worker_session, upstream, no_settings, private_kev_version
):
    """A CVE the catalog adds goes on the enrichment queue; the sync itself
    never calls NVD, so a disabled NVD source stays silent."""
    from app.models.enrichment import EnrichmentJob, EntityContext

    await _source_row(db_session, "nvd", trigger_mode="auto")
    vulns = [{"cveID": f"CVE-2026-7230{i}", "dateAdded": "2026-10-01", "dueDate": "2026-10-22"} for i in range(2)]
    upstream.route("known_exploited", _json({"catalogVersion": "t2", "vulnerabilities": vulns}))

    stats = await _run_kev(db_session)

    assert stats["new"] == 2 and stats["fetched"] == 2
    assert _all_through_gateway(upstream)
    assert not any("nvd.nist.gov" in str(r.url) for r in upstream.requests)
    queued = (await db_session.execute(select(EnrichmentJob.entity_value, EnrichmentJob.source_type))).all()
    assert {("CVE-2026-72300", "nvd"), ("CVE-2026-72301", "nvd")} <= set(queued)
    context = (
        await db_session.execute(select(EntityContext.key).where(EntityContext.source_type == "cisa_kev"))
    ).scalars()
    assert "date_added" in set(context)


# ── Wikipedia ───────────────────────────────────────────────────────


async def test_wikipedia_bulk_sync_fetches_through_the_wikipedia_gateway(
    db_session, worker_session, upstream, monkeypatch
):
    import app.enrichment.wikipedia_helper as helper

    db_session.add_all([Vendor(name="Wikitest Alpha"), Vendor(name="Wikitest Beta")])
    await db_session.flush()
    upstream.route("wikipedia.org", _json({}), _status(429))
    transports = []

    async def fake_fetch(name, entity_type, aliases=None, *, transport):
        transports.append(transport)
        async with httpx.AsyncClient(transport=transport) as client:
            await client.get("https://en.wikipedia.org/w/api.php")
        return None

    monkeypatch.setattr(helper, "fetch_wikipedia", fake_fetch)

    stats = await tasks._run_wikipedia_bulk_sync()

    assert stats["stopped"] == "rate_limited"
    assert stats["skipped"] >= 1
    assert all(t._gateway.source_type == "wikipedia" for t in transports)
    assert _all_through_gateway(upstream)
    assert await SourceGateway("wikipedia").used_today() == 2


async def test_wikipedia_bulk_sync_stores_no_article_and_moves_on(db_session, worker_session, upstream, monkeypatch):
    """A name Wikipedia has no article for gets a "not found" answer, so the
    next run asks about other names instead of the same ones again."""
    import app.enrichment.wikipedia_helper as helper
    from app.models.enrichment import EnrichmentResult

    vendor = Vendor(name="Wikitest Nothing")
    db_session.add(vendor)
    await db_session.flush()
    asked: list[str] = []

    async def fake_fetch(name, entity_type, aliases=None, *, transport):
        asked.append(name)
        return None

    monkeypatch.setattr(helper, "fetch_wikipedia", fake_fetch)

    await tasks._run_wikipedia_bulk_sync()
    assert "Wikitest Nothing" in asked
    stored = (
        await db_session.execute(
            select(EnrichmentResult.parsed_data).where(
                EnrichmentResult.entity_id == vendor.id, EnrichmentResult.source_type == "wikipedia"
            )
        )
    ).scalar_one()
    assert stored == {"found": False}

    asked.clear()
    await tasks._run_wikipedia_bulk_sync()
    assert "Wikitest Nothing" not in asked


async def test_wikipedia_bulk_sync_stops_a_fetch_that_outlasts_the_run(
    db_session, worker_session, upstream, monkeypatch
):
    """The run's time left bounds a whole entity's fetch, so a slow one can't
    carry the job past Celery's limit."""
    import asyncio

    import app.enrichment.wikipedia_helper as helper

    db_session.add(Vendor(name="Wikitest Slow"))
    await db_session.flush()

    async def slow_fetch(name, entity_type, aliases=None, *, transport):
        await asyncio.sleep(5)

    monkeypatch.setattr(helper, "fetch_wikipedia", slow_fetch)
    monkeypatch.setattr(tasks, "_WIKIPEDIA_BULK_BUDGET_S", 0.05)

    stats = await tasks._run_wikipedia_bulk_sync()
    assert stats["stopped"] == "out_of_time"


async def test_wikipedia_profile_fetch_answers_429_when_refused(client, auth_headers, db_session):
    vendor = Vendor(name="Wikitest Gamma")
    db_session.add(vendor)
    await db_session.flush()
    await SourceGateway("wikipedia")._trip("throttle", 600)

    resp = await client.post(f"/api/entities/vendor/{vendor.id}/wikipedia", headers=auth_headers)

    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "breaker_open"


# ── Default budgets ─────────────────────────────────────────────────


def _budget_migration():
    path = Path(__file__).parents[1] / "alembic" / "versions" / "j7e8f9a0b1c2_enrichment_daily_budgets.py"
    spec = importlib.util.spec_from_file_location("budget_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_budget_migration_fills_only_missing_budgets(db_session):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    migration = _budget_migration()
    await _source_row(db_session, "nvd", daily_budget=None)
    await _source_row(db_session, "wikipedia", daily_budget=42)  # an admin's choice

    def run(step):
        def apply(sync_conn):
            with Operations.context(MigrationContext.configure(sync_conn)):
                step()

        return apply

    conn = await db_session.connection()
    await conn.run_sync(run(migration.upgrade))
    budgets = dict(
        (await db_session.execute(select(EnrichmentSource.source_type, EnrichmentSource.daily_budget))).all()
    )
    assert budgets == {"nvd": migration.DAILY_BUDGETS["nvd"], "wikipedia": 42}

    await conn.run_sync(run(migration.downgrade))
    budgets = dict(
        (await db_session.execute(select(EnrichmentSource.source_type, EnrichmentSource.daily_budget))).all()
    )
    assert budgets == {"nvd": None, "wikipedia": 42}


def test_new_installs_seed_the_same_budgets():
    from app.enrichment.registry import DEFAULT_SOURCES

    budgets = _budget_migration().DAILY_BUDGETS
    assert {
        s["source_type"]: s["default_daily_budget"] for s in DEFAULT_SOURCES if s["source_type"] in budgets
    } == budgets


async def test_job_gateway_without_a_source_row_uses_the_defaults(db_session, monkeypatch):
    from app.enrichment.pipeline import gateway_for

    async def nvd_key(key, db=None):
        return "k" if key == "nvd_api_key" else ""

    monkeypatch.setattr("app.services.system_settings.get_setting", nvd_key)
    gateway, key = await gateway_for(db_session, "nvd", max_wait=gw.JOB_TOKEN_WAIT)
    assert key == "k"
    assert (gateway.capacity, gateway.period, gateway.daily_budget) == (50, 30, 5000)
    assert gateway.throttle_statuses == NVDAdapter.throttle_statuses
    assert gateway.max_wait == gw.JOB_TOKEN_WAIT


async def test_jobs_and_lookups_resolve_one_key_so_they_share_one_bucket(db_session, monkeypatch):
    """With the key only in the nvd_api_key setting, the per-entity path and the
    jobs must land on the same credential bucket (two buckets would double the
    real request rate)."""
    from app.enrichment.pipeline import gateway_for, resolve_api_key
    from app.enrichment.registry import source_gateway
    from app.models.enrichment import EnrichmentSource

    async def nvd_key(key, db=None):
        return "setting-key" if key == "nvd_api_key" else ""

    monkeypatch.setattr("app.services.system_settings.get_setting", nvd_key)
    row = EnrichmentSource(
        source_type="nvd",
        display_name="NVD",
        is_enabled=True,
        trigger_mode="manual",
        rate_limit_config={"requests_per_period": 50, "period_seconds": 30},
        health_status="unknown",
        config={},
    )
    db_session.add(row)
    await db_session.flush()

    job_gateway, job_key = await gateway_for(db_session, "nvd")
    lookup_key = await resolve_api_key(row, None, db_session)
    assert job_key == lookup_key == "setting-key"
    assert job_gateway.scope == source_gateway(row, lookup_key).scope


# ── Jobs write through the shared writer ─────────────────────────────


async def _claims(db_session, entity_id, source_ref: str) -> dict[str, str]:
    from app.models.entity_field_claim import EntityFieldClaim

    rows = (
        await db_session.execute(
            select(EntityFieldClaim).where(
                EntityFieldClaim.entity_id == entity_id, EntityFieldClaim.source_ref == source_ref
            )
        )
    ).scalars()
    return {r.field: r.value_text for r in rows}


async def _context(db_session, entity_id, source_type: str) -> dict:
    from app.models.enrichment import EntityContext

    rows = (
        await db_session.execute(
            select(EntityContext).where(EntityContext.entity_id == entity_id, EntityContext.source_type == source_type)
        )
    ).scalars()
    return {r.key: r.value for r in rows}


def _misp_cluster() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "values": [
                {
                    "value": "APT28",
                    "description": "A Russian state-sponsored group.",
                    "meta": {
                        "country": "RU",
                        "synonyms": ["Fancy Bear", "Sofacy"],
                        "cfr-type-of-incident": "Espionage",
                        "cfr-target-category": ["Government", "Military"],
                    },
                },
                {
                    "value": "Kept Group",
                    "description": "Its profile already says where it's from.",
                    "meta": {"country": "CN", "motive": "nonsense words"},
                },
                {"value": "Untracked", "meta": {"country": "RU"}},
            ]
        },
    )


async def test_misp_galaxy_applies_matched_actors_through_the_field_map(db_session, worker_session, upstream):
    from app.intelligence.sectors import normalize_sectors, sector_uuid
    from app.models.country import Country
    from app.models.sector import ThreatActorTargetSector
    from app.models.threat_actor import ThreatActor

    db_session.add_all([Country(name="Russia", iso_code="RU"), Country(name="China", iso_code="CN")])
    fancy = ThreatActor(name="Fancy Bear")  # matched by a synonym
    kept = ThreatActor(name="Kept Group", country="Iran")
    db_session.add_all([fancy, kept])
    await db_session.flush()
    upstream.route("misp-galaxy", _misp_cluster)

    stats = await tasks._run_misp_galaxy_sync()

    assert stats["matched"] == 2
    await db_session.refresh(fancy)
    await db_session.refresh(kept)
    # The ISO code resolves to the country's name; the CFR incident type is a motive.
    assert fancy.country == "Russia"
    assert fancy.motivation == "espionage"
    assert fancy.description == "A Russian state-sponsored group."
    sectors = (
        (
            await db_session.execute(
                select(ThreatActorTargetSector.sector_id).where(ThreatActorTargetSector.threat_actor_id == fancy.id)
            )
        )
        .scalars()
        .all()
    )
    # The CFR categories land on the sector vocabulary ("Military" is defense).
    assert normalize_sectors(["Government", "Military"]) == ["government", "defense"]
    assert set(sectors) == {sector_uuid("government"), sector_uuid("defense")}
    # Claims name MISP Galaxy, not another catalog.
    claims = await _claims(db_session, fancy.id, "misp_galaxy")
    assert claims["country"] == "Russia" and claims["motivation"] == "espionage"
    assert "description" in claims
    assert await _claims(db_session, fancy.id, "cybergeist") == {}

    # Fill-blank: a country the profile has stands; a motive that matches
    # nothing in the vocabulary is dropped.
    assert kept.country == "Iran"
    assert kept.motivation is None
    assert kept.description == "Its profile already says where it's from."


async def test_misp_galaxy_description_yields_to_a_higher_ranked_source(db_session, worker_session, upstream):
    from app.enrichment.entity_updater import apply_enrichment_results_to_entity
    from app.models.threat_actor import ThreatActor

    actor = ThreatActor(name="APT28")
    db_session.add(actor)
    await db_session.flush()
    await apply_enrichment_results_to_entity(
        db_session,
        "threat_actor",
        actor.id,
        [{"source_type": "mitre_attack", "status": "success", "parsed_data": {"description": "ATT&CK's words."}}],
    )
    assert actor.description == "ATT&CK's words."
    upstream.route("misp-galaxy", _misp_cluster)

    await tasks._run_misp_galaxy_sync()

    await db_session.refresh(actor)
    assert actor.description == "ATT&CK's words."
    # Its value is still recorded, as a claim that lost.
    assert "description" in await _claims(db_session, actor.id, "misp_galaxy")


def _msf_metadata() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "exploit_windows_x": {"fullname": "exploit/windows/http/x_rce", "references": ["CVE-2026-70100", "URL-x"]},
            "aux_scanner_x": {"fullname": "auxiliary/scanner/http/x_check", "references": ["CVE-2026-70100"]},
            "exploit_kev": {"fullname": "exploit/linux/kev_rce", "references": ["CVE-2026-70101"]},
            "exploit_manual": {"fullname": "exploit/linux/manual", "references": ["CVE-2026-70102"]},
            "exploit_untracked": {"fullname": "exploit/linux/other", "references": ["CVE-2026-79999"]},
        },
    )


async def test_metasploit_applies_modules_and_escalates_with_a_claim(db_session, worker_session, upstream, monkeypatch):
    import app.workers.signal_tasks as signal_tasks

    rescored: list = []
    monkeypatch.setattr(signal_tasks, "dispatch_cve_rescore", rescored.append)
    poc = CVE(cve_id="CVE-2026-70100", exploit_availability="poc")
    kev = CVE(cve_id="CVE-2026-70101", is_kev=True, exploit_availability="active_exploitation")
    manual = CVE(cve_id="CVE-2026-70102", exploit_availability="poc", exploit_status_source="manual")
    db_session.add_all([poc, kev, manual])
    await db_session.flush()
    upstream.route("metasploit-framework", _msf_metadata)

    stats = await tasks._run_metasploit_sync()

    assert stats["cves_matched"] == 4 and stats["escalated"] == 1
    for cve in (poc, kev, manual):
        await db_session.refresh(cve)
    # The first module (sorted) goes on the column; the full list is context.
    assert poc.metasploit_module == "auxiliary/scanner/http/x_check"
    assert await _context(db_session, poc.id, "metasploit") == {
        "modules": ["auxiliary/scanner/http/x_check", "exploit/windows/http/x_rce"]
    }
    assert [s for s in poc.exploit_sources if s.get("source") == "metasploit"] == [
        {"source": "metasploit", "module": "auxiliary/scanner/http/x_check"}
    ]
    assert poc.exploit_availability == "weaponized"
    assert (await _claims(db_session, poc.id, "metasploit")).get("exploit_availability") == "weaponized"
    assert rescored == [poc.id]

    # KEV stays active exploitation and an analyst's verdict stands, with no claim.
    assert kev.exploit_availability == "active_exploitation" and kev.metasploit_module == "exploit/linux/kev_rce"
    assert manual.exploit_availability == "poc"
    assert "exploit_availability" not in await _claims(db_session, manual.id, "metasploit")

    # A second run adds nothing: metasploit is listed once, nothing escalates again.
    upstream.route("metasploit-framework", _msf_metadata)
    again = await tasks._run_metasploit_sync()
    await db_session.refresh(poc)
    assert again["escalated"] == 0
    assert sum(1 for s in poc.exploit_sources if s.get("source") == "metasploit") == 1


async def test_an_epss_lookup_writes_both_columns(client, auth_headers, db_session, upstream):
    await _source_row(db_session, "epss")
    cve = CVE(cve_id="CVE-2026-70200")
    db_session.add(cve)
    await db_session.flush()
    upstream.route(
        "api.first.org",
        _json({"data": [{"cve": "CVE-2026-70200", "epss": "0.42", "percentile": "0.97", "date": "2026-10-31"}]}),
    )

    resp = await client.post(
        "/api/enrichment/enrich",
        json={"entity_type": "cve", "entity_id": str(cve.id), "source_types": ["epss"]},
        headers=auth_headers,
    )

    assert resp.status_code == 200, resp.text
    assert [r["status"] for r in resp.json()["results"]] == ["success"]
    assert _all_through_gateway(upstream)
    await db_session.refresh(cve)
    assert (cve.epss_score, cve.epss_percentile) == (0.42, 0.97)


# ── OSV: records changed since the last run ─────────────────────────


def _osv_stamp(when) -> str:
    """OSV's format: nanoseconds and a Z."""
    return f"{when:%Y-%m-%dT%H:%M:%S}.{when.microsecond:06d}789Z"


def _osv_record(cve_id: str, ghsa: str):
    return _json({"id": cve_id, "aliases": [ghsa], "summary": f"{cve_id} in a package", "affected": []})


@pytest.fixture
def osv_changes(db_session):
    """A change list newest first, around a cursor an hour back."""
    from datetime import UTC, datetime, timedelta

    cursor = (datetime.now(UTC) - timedelta(hours=1)).replace(microsecond=123456)
    at = {m: cursor + timedelta(minutes=m) for m in (50, 40, 30, 20, 10, -10)}
    lines = [
        f"{_osv_stamp(at[50])},GIT/CVE-2026-70301",
        f"{_osv_stamp(at[40])},PyPI/GHSA-aaaa-bbbb-cccc",  # not a CVE record
        f"{_osv_stamp(at[30])},Linux/CVE-2026-70302",
        f"{_osv_stamp(at[20])},GIT/CVE-2026-79999",  # a CVE IntelFeed doesn't track
        f"{_osv_stamp(at[10])},GIT/CVE-2026-70301",  # an older change of one listed above
        f"{_osv_stamp(at[-10])},GIT/CVE-2026-70303",  # before the cursor: never read
    ]
    return cursor, at, "\n".join(lines) + "\n"


async def _osv_cves(db_session):
    rows = [CVE(cve_id=f"CVE-2026-7030{i}") for i in (1, 2, 3)]
    db_session.add_all(rows)
    await db_session.flush()
    return rows


def test_parse_osv_modified_line():
    from datetime import UTC, datetime

    assert tasks.parse_osv_modified_line("2026-11-01T02:50:35.123456789Z,GIT/CVE-2026-1\n") == (
        datetime(2026, 11, 1, 2, 50, 35, 123456, tzinfo=UTC),
        "GIT/CVE-2026-1",
    )
    assert tasks.parse_osv_modified_line("2026-11-01T02:50:35Z,Linux/CVE-2026-2") == (
        datetime(2026, 11, 1, 2, 50, 35, tzinfo=UTC),
        "Linux/CVE-2026-2",
    )
    assert tasks.parse_osv_modified_line("2026-11-01T02:50:35Z") is None
    assert tasks.parse_osv_modified_line("not a time,GIT/CVE-2026-3") is None
    assert tasks.parse_osv_modified_line("") is None


async def test_osv_delta_fetches_only_tracked_cves_back_to_the_cursor(
    db_session, worker_session, upstream, osv_changes
):
    from datetime import UTC, datetime

    cursor, at, csv = osv_changes
    row = await _source_row(db_session, "osv", last_synced_at=cursor)
    first, second, before_cursor = await _osv_cves(db_session)
    upstream.route("modified_id.csv", lambda: httpx.Response(200, text=csv))
    upstream.route("GIT/CVE-2026-70301.json", _osv_record("CVE-2026-70301", "GHSA-1111-1111-1111"))
    upstream.route("Linux/CVE-2026-70302.json", _osv_record("CVE-2026-70302", "GHSA-2222-2222-2222"))
    started = datetime.now(UTC)

    stats = await tasks._run_osv_delta_sync()

    assert (stats["listed"], stats["tracked"], stats["fetched"], stats["stopped"]) == (5, 2, 2, None)
    assert _all_through_gateway(upstream)
    # Oldest change first; the untracked CVE and the one before the cursor aren't asked for.
    fetched = [r.url.path.rsplit("/", 2)[-2:] for r in upstream.requests[1:]]
    assert fetched == [["Linux", "CVE-2026-70302.json"], ["GIT", "CVE-2026-70301.json"]]
    for cve in (first, second, before_cursor):
        await db_session.refresh(cve)
    assert "GHSA-1111-1111-1111" in (first.aliases or [])
    assert "GHSA-2222-2222-2222" in (second.aliases or [])
    assert not before_cursor.aliases
    # A run that went through reads up to now next time.
    await db_session.refresh(row)
    assert row.last_synced_at >= started


async def test_osv_delta_refusal_keeps_the_cursor_at_the_last_applied_record(
    db_session, worker_session, upstream, osv_changes
):
    cursor, at, csv = osv_changes
    row = await _source_row(db_session, "osv", last_synced_at=cursor)
    first, second, _ = await _osv_cves(db_session)
    upstream.route("modified_id.csv", lambda: httpx.Response(200, text=csv))
    upstream.route("Linux/CVE-2026-70302.json", _osv_record("CVE-2026-70302", "GHSA-2222-2222-2222"))
    upstream.route("GIT/CVE-2026-70301.json", _status(429))

    stats = await tasks._run_osv_delta_sync()

    assert stats["stopped"] == "rate_limited"
    assert stats["fetched"] == 1
    await db_session.refresh(row)
    await db_session.refresh(second)
    assert "GHSA-2222-2222-2222" in (second.aliases or [])
    # The next run starts after CVE-2026-70302's change, so 70301's is read again.
    assert row.last_synced_at == at[30]


async def test_osv_delta_holds_the_cursor_before_a_record_that_failed(
    db_session, worker_session, upstream, osv_changes
):
    cursor, at, csv = osv_changes
    row = await _source_row(db_session, "osv", last_synced_at=cursor)
    first, second, _ = await _osv_cves(db_session)
    upstream.route("modified_id.csv", lambda: httpx.Response(200, text=csv))
    upstream.route("Linux/CVE-2026-70302.json", _status(500))  # the older change
    upstream.route("GIT/CVE-2026-70301.json", _osv_record("CVE-2026-70301", "GHSA-1111-1111-1111"))

    stats = await tasks._run_osv_delta_sync()

    assert (stats["fetched"], stats["failed"], stats["stopped"]) == (1, 1, None)
    await db_session.refresh(first)
    assert "GHSA-1111-1111-1111" in (first.aliases or [])
    # Nothing before the failed record was applied, so the next run starts where this one did.
    await db_session.refresh(row)
    assert row.last_synced_at == cursor


async def test_osv_delta_first_run_reads_a_window_back(db_session, worker_session, upstream, osv_changes):
    _, _, csv = osv_changes
    await _source_row(db_session, "osv", last_synced_at=None)
    await _osv_cves(db_session)
    upstream.route("modified_id.csv", lambda: httpx.Response(200, text=csv))
    upstream.route("CVE-2026-7030", _osv_record("CVE-2026-70300", "GHSA-0000-0000-0000"))

    stats = await tasks._run_osv_delta_sync()

    # Two days back takes in the change an hour before the cursor too.
    assert (stats["listed"], stats["tracked"], stats["fetched"]) == (6, 3, 3)


async def test_osv_delta_runs_before_the_source_row_is_seeded(db_session, worker_session, upstream, osv_changes):
    """``source_job`` runs a job whose source has no row yet; the delta sync
    reads its cursor from that row."""
    _, _, csv = osv_changes
    upstream.route("modified_id.csv", lambda: httpx.Response(200, text=csv))
    stats = await tasks._run_osv_delta_sync()
    # No row, so the cursor is the first window (two days back): every change
    # is listed, none is a CVE IntelFeed tracks, and only the list was fetched.
    assert (stats["listed"], stats["tracked"], stats["fetched"], stats["stopped"]) == (6, 0, 0, None)
    assert [str(r.url) for r in upstream.requests] == [tasks.OSV_MODIFIED_URL]
