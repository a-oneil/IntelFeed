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
        trigger_mode="scheduled",
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
    pytest.param(_run_cwe, "cwec_latest", _cwe_zip, "cwe_catalog", id="cwe-catalog"),
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
    monkeypatch.setattr(
        "app.services.system_settings.get_setting_cached",
        lambda key: "fallback-token" if key == "github_token" else None,
    )
    upstream.route("api.github.com", _poc_hit)

    stats = await tasks._run_github_poc_scan()

    assert stats == {"scanned": 3, "pocs_found": 3, "stopped": None}
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

    assert stats == {"scanned": 0, "pocs_found": 0, "stopped": "breaker_open"}
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


async def test_kev_sync_paces_new_cves_through_the_nvd_gateway(
    db_session, worker_session, upstream, no_settings, fast_nvd_pace, private_kev_version
):
    vulns = [{"cveID": f"CVE-2026-7230{i}", "dateAdded": "2026-10-01"} for i in range(2)]
    upstream.route("known_exploited", _json({"catalogVersion": "t2", "vulnerabilities": vulns}))
    upstream.route("services.nvd.nist.gov", _nvd_record("CVE-2026-72300"), _status(429))

    stats = await _run_kev(db_session)

    assert stats["new"] == 2
    assert stats["stopped"] == "rate_limited"
    assert _all_through_gateway(upstream)
    assert await SourceGateway("nvd").used_today() == 2


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

    assert {s["source_type"]: s["default_daily_budget"] for s in DEFAULT_SOURCES} == _budget_migration().DAILY_BUDGETS


async def test_job_gateway_without_a_source_row_uses_the_defaults(db_session):
    from app.enrichment.pipeline import gateway_for

    gateway, key = await gateway_for(db_session, "nvd", fallback_key="k", max_wait=gw.JOB_TOKEN_WAIT)
    assert key == "k"
    assert (gateway.capacity, gateway.period, gateway.daily_budget) == (50, 30, 5000)
    assert gateway.throttle_statuses == NVDAdapter.throttle_statuses
    assert gateway.max_wait == gw.JOB_TOKEN_WAIT
