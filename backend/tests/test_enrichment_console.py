"""The Enrichment console API: status and attention, source detail, the
gateway's hourly counters, the global pause and backfill.

Real database and Redis (conftest gives each test its own gateway key prefix);
sources answer through ``httpx.MockTransport`` behind their real gateways.
"""

import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, update

from app.enrichment import gateway as gw
from app.enrichment import pipeline
from app.enrichment import queue as q
from app.enrichment.gateway import SOURCE_REFUSALS, Paused, SourceGateway
from app.enrichment.pause import SETTING, set_paused, sync_pause
from app.enrichment.registry import DEFAULT_SOURCES, get_adapter, source_gateway
from app.models.enrichment import EnrichmentJob, EnrichmentSource
from app.models.job_run import JobRun
from app.models.observable import Observable
from app.models.system_setting import SystemSettings
from app.services.redis_client import get_redis_bytes
from app.services.system_settings import CONFIGURABLE_KEYS, SETTING_METADATA

FRONTEND_HOOKS = Path(__file__).resolve().parents[2] / "frontend" / "src" / "hooks" / "useEnrichment.ts"


@pytest.fixture(autouse=True)
async def _quiet_sources(db_session):
    """Every source has its seeded row, as on a running install; only the
    ones a test switches on count as on."""
    have = set((await db_session.execute(select(EnrichmentSource.source_type))).scalars())
    for seed in DEFAULT_SOURCES:
        if seed["source_type"] not in have:
            db_session.add(
                EnrichmentSource(
                    source_type=seed["source_type"],
                    display_name=seed["display_name"],
                    trigger_mode=seed["default_trigger_mode"],
                    rate_limit_config=seed["default_rate_limit"],
                    daily_budget=seed["default_daily_budget"],
                    config={},
                )
            )
    await db_session.flush()
    await db_session.execute(update(EnrichmentSource).values(is_enabled=False, api_key_encrypted=None))
    if await db_session.get(SystemSettings, 1) is None:
        db_session.add(SystemSettings(id=1, settings={}, secrets={}))
    await db_session.flush()


async def _source(db, source_type, **fields) -> EnrichmentSource:
    row = (
        await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == source_type))
    ).scalar_one_or_none()
    if row is None:
        row = EnrichmentSource(source_type=source_type, display_name=source_type, config={})
        db.add(row)
    values = {
        "is_enabled": True,
        "trigger_mode": "auto",
        "daily_budget": None,
        "rate_limit_config": {"requests_per_period": 100, "period_seconds": 60},
        "min_confidence_threshold": "low",
        **fields,
    }
    for k, v in values.items():
        setattr(row, k, v)
    await db.flush()
    return row


def _run(job_key, status, minutes_ago, error=None, result=None) -> JobRun:
    at = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    return JobRun(
        task_name=f"task.{job_key}",
        job_key=job_key,
        status=status,
        started_at=at,
        finished_at=at,
        error=error,
        detail={"result": result} if result is not None else None,
    )


async def _send(gateway: SourceGateway, n: int = 1) -> None:
    gateway._inner = httpx.MockTransport(lambda r: httpx.Response(200, json={}))
    async with gateway.client() as client:
        for _ in range(n):
            await client.get("https://example.test/x")


async def _hour_count(source_type: str) -> int:
    r = await get_redis_bytes()
    value = await r.get(gw.stats_key(source_type, datetime.now(UTC)))
    return int(value) if value else 0


# ── Console ──────────────────────────────────────────────────────────


async def _scenario(db):
    nvd = await _source(db, "nvd")
    db.add_all(
        [
            _run("cve-nvd-backfill", "success", 120),
            _run("cve-nvd-backfill", "error", 5, error="TimeLimitExceeded(960)"),
            _run("cve-nvd-refresh", "success", 60),
        ]
    )
    await _source(db, "virustotal")  # on, but no key
    await _source(db, "vulncheck", is_enabled=False)  # off and no key: not attention
    await _source(db, "osv", is_enabled=False)
    epss = await _source(db, "epss")
    await source_gateway(epss, None)._trip("throttle", 600)
    shodan = await _source(db, "shodan")
    await _send(source_gateway(shodan, None), 2)
    await db.flush()
    return nvd


async def test_console_status_attention_and_sort(client, admin_headers, db_session):
    nvd = await _scenario(db_session)

    resp = await client.get("/api/enrichment/console", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    by_type = {s["source_type"]: s for s in data["sources"]}

    assert by_type["nvd"]["status"] == "failing"
    assert by_type["nvd"]["attention"] == "cve-nvd-backfill failed 1 of 2 runs in 30 days"
    assert by_type["nvd"]["id"] == str(nvd.id)
    assert by_type["epss"]["status"] == "failing"
    assert "back off" in by_type["epss"]["attention"]
    assert (by_type["virustotal"]["status"], by_type["virustotal"]["attention"]) == ("needs_key", "needs an API key")
    assert (by_type["vulncheck"]["status"], by_type["vulncheck"]["attention"]) == ("needs_key", None)
    assert (by_type["osv"]["status"], by_type["osv"]["attention"]) == ("off", None)
    assert (by_type["shodan"]["status"], by_type["shodan"]["attention"]) == ("ok", None)
    assert by_type["shodan"]["applies_to"] == ["observable"]
    assert by_type["nvd"]["kind"] == "lookup" and by_type["misp_galaxy"]["kind"] == "catalog"

    # Attention first, then on, then by label.
    keys = [(s["attention"] is None, not s["enabled"], s["label"].lower()) for s in data["sources"]]
    assert keys == sorted(keys)
    assert [s["source_type"] for s in data["sources"][:3]] == sorted(
        ["nvd", "epss", "virustotal"], key=lambda t: by_type[t]["label"].lower()
    )

    summary = data["summary"]
    assert summary["needs_attention"] == 3
    assert summary["sources_on"] == 4
    assert summary["sources_total"] == len(data["sources"])
    assert summary["paused"] is False and summary["redis_ok"] is True
    assert summary["activity_24h"]["requests"] == 2
    assert summary["activity_24h"]["iocs_sent_off_box"] == 2  # Shodan shares the IP


async def test_console_fills_reads_the_manifest(client, admin_headers, db_session):
    await _source(db_session, "shodan")
    data = (await client.get("/api/enrichment/console", headers=admin_headers)).json()
    by_type = {s["source_type"]: s for s in data["sources"]}
    assert by_type["shodan"]["fills"].startswith("reputation, infra tag, open ports")
    assert by_type["cisa_kev"]["fills"].startswith("in KEV, added to KEV")
    assert by_type["epss"]["fills"] == "EPSS score, EPSS percentile, scored on"
    # A catalog source with no outputs says what its job does.
    assert by_type["misp_galaxy"]["fills"].startswith("Refresh the reference alias")


async def test_console_filters_by_entity_type(client, admin_headers, db_session):
    await _scenario(db_session)
    everything = (await client.get("/api/enrichment/console", headers=admin_headers)).json()
    resp = await client.get("/api/enrichment/console", params={"entity_type": "observable"}, headers=admin_headers)
    data = resp.json()

    assert {s["source_type"] for s in data["sources"]} == {
        "virustotal",
        "greynoise",
        "shodan",
        "cymru",
        "rdap",
        "tranco",
        "threatfox",
        "urlhaus",
        "malwarebazaar",
    }
    # The summary and the tabs always count every source.
    assert data["summary"] == everything["summary"]
    assert data["entity_types"] == everything["entity_types"]
    tabs = {t["entity_type"]: t for t in data["entity_types"]}
    assert tabs["observable"] == {"entity_type": "observable", "label": "Observable", "source_count": 9}
    assert tabs["cve"]["label"] == "CVE"


async def test_console_reports_redis_down(client, admin_headers, db_session, monkeypatch):
    import redis.asyncio as aioredis

    await _source(db_session, "nvd")
    dead = aioredis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.5)

    async def broken():
        return dead

    monkeypatch.setattr(gw, "get_redis_bytes", broken)
    data = (await client.get("/api/enrichment/console", headers=admin_headers)).json()
    assert data["summary"]["redis_ok"] is False
    assert data["summary"]["activity_24h"]["requests"] == 0


async def test_console_routes_are_admin_only(client, auth_headers, db_session):
    for method, path, body in (
        ("get", "/api/enrichment/console", None),
        ("get", "/api/enrichment/sources/nvd/detail", None),
        ("post", "/api/enrichment/pause", {"paused": True}),
        ("post", "/api/enrichment/sources/nvd/backfill", {}),
    ):
        resp = await client.request(method, path, json=body, headers=auth_headers)
        assert resp.status_code == 403, path


# ── Detail ───────────────────────────────────────────────────────────


async def test_detail_limits_trend_queue_and_jobs(client, admin_headers, db_session, monkeypatch):
    import app.api.job_schedules as job_schedules

    nvd = await _source(
        db_session, "nvd", daily_budget=100, rate_limit_config={"requests_per_period": 40, "period_seconds": 30}
    )
    await _send(source_gateway(nvd, None), 3)
    db_session.add_all(
        [
            _run("cve-nvd-backfill", "success", 300, result={"enriched": 12}),
            _run("cve-nvd-backfill", "error", 5, error="TimeLimitExceeded(960)", result={"enriched": 0}),
            _run("cve-nvd-backfill", "error", 60 * 24 * 40),  # older than 30 days
        ]
    )
    now = datetime.now(UTC)
    for lane, status, attempts, last in (
        ("backfill", "queued", 0, None),
        ("backfill", "queued", 1, "error"),
        ("refresh", "queued", 0, "rate_limited"),
        ("manual", "running", 0, None),
        ("new", "failed", 5, "error"),
    ):
        db_session.add(
            EnrichmentJob(
                entity_type="cve",
                entity_id=uuid.uuid4(),
                entity_value="CVE-2026-0001",
                source_type="nvd",
                lane=lane,
                priority=q.LANES[lane],
                status=status,
                due_at=now,
                attempts=attempts,
                last_status=last,
            )
        )
    await db_session.flush()

    async def overrides(db):
        return {"cve-nvd-refresh": {"schedule": {"type": "interval", "seconds": 7200}}}

    monkeypatch.setattr(job_schedules, "_load_overrides", overrides)

    resp = await client.get("/api/enrichment/sources/nvd/detail", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["limits"] == {
        "requests_per_period": 40,
        "period_seconds": 30,
        "ceiling_per_period": 5,  # keyless: NVD allows 5 per 30 s without a key
        "daily_budget": 100,
        "used_today": 3,
        "backfill_share": q.BACKFILL_SHARE,
        "refresh_days": None,
        "key": "none",
        # NVD fills cvss_score through the field map, so it can backfill.
        "triggers": ["new", "manual", "backfill", "schedule"],
        "scope": "CVE with no CVSS score",
    }
    assert data["gap"]["entity_type"] == "cve" and data["gap"]["field"] == "cvss_score"
    assert len(data["trend_24h"]) == 24 and data["trend_24h"][-1] == 3 and sum(data["trend_24h"]) == 3
    assert data["queue"] == {
        "waiting": 4,
        "by_lane": {"manual": 1, "new": 0, "refresh": 1, "backfill": 2},
        "retrying": 2,
        "failed": 1,
    }
    jobs = {j["key"]: j for j in data["jobs"]}
    assert set(jobs) == {"cve-nvd-refresh", "cve-nvd-backfill", "reenrich-cve-nvd"}
    assert jobs["cve-nvd-backfill"] == {
        "key": "cve-nvd-backfill",
        "schedule": "Daily at 1:30 AM",
        "runs_30d": 2,
        "ok_30d": 1,
        "last_status": "error",
        "last_error": "TimeLimitExceeded(960)",
        "last_detail": {"enriched": 0},
    }
    # A schedule override, as the Jobs API applies it.
    assert jobs["cve-nvd-refresh"]["schedule"] == "Every 2 hours"
    assert jobs["reenrich-cve-nvd"]["runs_30d"] == 0 and jobs["reenrich-cve-nvd"]["last_status"] is None


async def _observables(db):
    """Three ipv4s with no Shodan ports, one with, and a domain Shodan can't look up."""
    rows = [
        Observable(kind="ipv4", value="198.51.100.1"),
        Observable(kind="ipv4", value="198.51.100.2"),
        Observable(kind="ipv4", value="198.51.100.3", reputation={"ports": []}),
        Observable(kind="ipv4", value="198.51.100.4", reputation={"ports": [22]}, infra_tag="vpn"),
        Observable(kind="domain", value="example.test"),
    ]
    db.add_all(rows)
    await db.flush()
    return rows


async def test_detail_outputs_and_gap(client, admin_headers, db_session):
    await _source(
        db_session, "shodan", daily_budget=1000, rate_limit_config={"requests_per_period": 30, "period_seconds": 60}
    )
    await _observables(db_session)
    already = (await db_session.execute(select(Observable).where(Observable.value == "198.51.100.1"))).scalar_one()
    await q.enqueue(db_session, "observable", already.id, already.value, lane="backfill", source_types=["shodan"])

    data = (await client.get("/api/enrichment/sources/shodan/detail", headers=admin_headers)).json()

    outputs = {o["target"]: o for o in data["outputs"] if o["kind"] == "column"}
    # Over the ipv4s Shodan can look up: one of four has ports, one an infra tag.
    assert outputs["observable.reputation.ports"]["filled_pct"] == 25.0
    assert outputs["observable.infra_tag"]["filled_pct"] == 25.0
    assert outputs["observable.reputation.ports"]["policy"] == "newer_wins"
    assert outputs["observable.infra_tag"]["rank"] == 1
    contexts = [o for o in data["outputs"] if o["kind"] == "context"]
    assert {
        "field": "ports",
        "target": "profile: Open ports",
        "kind": "context",
        "policy": None,
        "rank": None,
        "filled_pct": None,
    } in contexts

    # Missing counts every observable without ports (an empty list is none);
    # in scope are the ipv4s among them not already waiting in the queue.
    assert data["gap"] == {
        "entity_type": "observable",
        "field": "reputation.ports",
        "missing": 4,
        "in_scope": 2,
        "eta_days": 0.1,  # 2 lookups against 600 a day of backfill: under a day
    }
    assert data["limits"]["scope"] == "observable (ipv4) with no reputation ports"
    assert data["limits"]["triggers"] == ["new", "manual", "backfill"]


async def test_detail_unknown_source_is_404(client, admin_headers):
    resp = await client.get("/api/enrichment/sources/nope/detail", headers=admin_headers)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"


# ── Hourly counters ──────────────────────────────────────────────────


async def test_hourly_counter_moves_with_the_token(db_session):
    row = await _source(db_session, "osv", daily_budget=2)
    gateway = source_gateway(row, None)
    await _send(gateway, 2)
    assert await _hour_count("osv") == 2

    # A refused request takes no token and counts nothing.
    with pytest.raises(gw.BudgetExhausted):
        await _send(gateway)
    assert await _hour_count("osv") == 2
    assert await gateway.used_today() == 2

    r = await get_redis_bytes()
    assert 0 < await r.ttl(gw.stats_key("osv", datetime.now(UTC))) <= gw.STATS_TTL
    assert (await gw.hourly_requests(["osv"]))["osv"][-1] == 2


async def test_hourly_counter_is_per_source_not_per_key(db_session):
    row = await _source(db_session, "virustotal")
    await _send(source_gateway(row, "key-one"))
    await _send(source_gateway(row, "key-two"))
    assert await _hour_count("virustotal") == 2


# ── Pause ────────────────────────────────────────────────────────────


def test_pause_setting_is_registered():
    assert CONFIGURABLE_KEYS[SETTING] is bool
    assert SETTING_METADATA[SETTING]["group"] == "enrichment"


async def test_paused_gateway_refuses_and_sends_nothing(db_session):
    sent = []
    gateway = SourceGateway("osv", inner=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200)))
    await set_paused(db_session, True)
    with pytest.raises(Paused) as e:
        async with gateway.client() as client:
            await client.get("https://example.test/x")
    assert e.value.status == "paused"
    assert Paused in SOURCE_REFUSALS
    assert sent == [] and await gateway.used_today() == 0 and await _hour_count("osv") == 0

    await set_paused(db_session, False)
    async with gateway.client() as client:
        await client.get("https://example.test/x")
    assert len(sent) == 1


async def test_pause_endpoint_stores_the_setting(client, admin_headers, db_session):
    resp = await client.post("/api/enrichment/pause", json={"paused": True}, headers=admin_headers)
    assert resp.json() == {"paused": True}
    console = (await client.get("/api/enrichment/console", headers=admin_headers)).json()
    assert console["summary"]["paused"] is True
    r = await get_redis_bytes()
    assert await r.exists(gw.paused_key())

    resp = await client.post("/api/enrichment/pause", json={"paused": False}, headers=admin_headers)
    assert resp.json() == {"paused": False}
    assert not await r.exists(gw.paused_key())


async def test_settings_page_toggle_reaches_the_gateways(client, admin_headers, db_session):
    await client.patch("/api/system-settings", json={"settings": {SETTING: True}}, headers=admin_headers)
    r = await get_redis_bytes()
    assert await r.exists(gw.paused_key())
    await client.delete(f"/api/system-settings/{SETTING}", headers=admin_headers)
    assert not await r.exists(gw.paused_key())


def _wired(source, api_key):
    """pipeline.adapter_for_source, answering from a fake OSV."""
    g = source_gateway(source, api_key)
    g._inner = httpx.MockTransport(lambda r: httpx.Response(200, json={"id": "CVE-2021-44228", "aliases": []}))
    return get_adapter(source.source_type, api_key=api_key, config=source.config, gateway=g)


async def test_dispatcher_claims_nothing_while_paused(db_session):
    await _source(db_session, "osv")
    await q.enqueue(db_session, "cve", uuid.uuid4(), "CVE-2021-44228")
    await set_paused(db_session, True)

    assert await q.dispatch_due(db_session) == {"paused": 1}
    (job,) = (await db_session.execute(select(EnrichmentJob))).scalars().all()
    assert (job.status, job.attempts, job.claimed_at) == ("queued", 0, None)


async def test_dispatcher_defers_a_job_that_met_the_pause(db_session, monkeypatch):
    await _source(db_session, "osv")
    for value in ("CVE-2021-44228", "CVE-2021-45046"):
        await q.enqueue(db_session, "cve", uuid.uuid4(), value)
    # Paused after the tick read the setting: the gateway refuses mid-tick.
    r = await get_redis_bytes()
    await r.set(gw.paused_key(), b"1")

    async def not_yet(db):
        return False

    import app.enrichment.pause as pause

    monkeypatch.setattr(pause, "sync_pause", not_yet)
    monkeypatch.setattr(pipeline, "adapter_for_source", _wired)
    before = datetime.now(UTC)

    assert await q.dispatch_due(db_session) == {"paused": 2}

    for job in (await db_session.execute(select(EnrichmentJob).execution_options(populate_existing=True))).scalars():
        assert (job.status, job.attempts, job.last_status, job.claimed_at) == ("queued", 0, "paused", None)
        assert (
            before + timedelta(seconds=q.PAUSE_DEFER - 1)
            <= job.due_at
            <= datetime.now(UTC) + timedelta(seconds=q.PAUSE_DEFER)
        )


@pytest.mark.committed_db
async def test_set_paused_writes_the_flag_after_the_commit(db_session, _engine, monkeypatch):
    """A dispatcher syncing between the two must read the new value."""
    from sqlalchemy.ext.asyncio import AsyncSession

    import app.enrichment.pause as pause

    seen = []
    write_flag = pause._write_flag

    async def committed_first(paused):
        async with AsyncSession(bind=_engine) as other:
            stored = await other.scalar(select(SystemSettings.settings).where(SystemSettings.id == 1))
        seen.append(stored.get(SETTING))
        await write_flag(paused)

    monkeypatch.setattr(pause, "_write_flag", committed_first)
    await set_paused(db_session, True)
    await set_paused(db_session, False)
    assert seen == [True, False]


async def test_sync_pause_reads_the_row_not_the_settings_cache(db_session):
    from app.services.system_settings import get_setting

    await set_paused(db_session, False)
    assert await get_setting(SETTING, db_session) is False  # cached
    # Another worker pauses; this process's cache hasn't caught up.
    await db_session.execute(update(SystemSettings).where(SystemSettings.id == 1).values(settings={SETTING: True}))
    assert await sync_pause(db_session) is True
    assert await (await get_redis_bytes()).exists(gw.paused_key())


async def test_sync_pause_restores_a_lost_flag(db_session):
    await set_paused(db_session, True)
    r = await get_redis_bytes()
    await r.delete(gw.paused_key())  # Redis restarted
    assert await sync_pause(db_session) is True
    assert await r.exists(gw.paused_key())


async def test_manual_enrich_queues_a_paused_source(client, auth_headers, db_session):
    from app.models.cve import CVE

    await _source(db_session, "osv")
    cve = CVE(cve_id="CVE-2021-44228")
    db_session.add(cve)
    await db_session.flush()
    await set_paused(db_session, True)

    resp = await client.post(
        "/api/enrichment/enrich",
        json={"entity_type": "cve", "entity_id": str(cve.id), "source_types": ["osv"]},
        headers=auth_headers,
    )
    body = resp.json()
    assert [r["status"] for r in body["results"]] == ["paused"]
    assert body["queued"] == ["osv"]


# ── Backfill ─────────────────────────────────────────────────────────


async def test_backfill_queues_only_missing_in_scope_entities(client, admin_headers, db_session):
    await _source(db_session, "shodan")
    rows = await _observables(db_session)
    await q.enqueue(db_session, "observable", rows[0].id, rows[0].value, lane="manual", source_types=["shodan"])

    resp = await client.post("/api/enrichment/sources/shodan/backfill", json={}, headers=admin_headers)
    assert resp.json() == {"queued": 2}

    jobs = (
        (await db_session.execute(select(EnrichmentJob).where(EnrichmentJob.source_type == "shodan"))).scalars().all()
    )
    by_value = {j.entity_value: j for j in jobs}
    assert set(by_value) == {"198.51.100.1", "198.51.100.2", "198.51.100.3"}
    assert by_value["198.51.100.1"].lane == "manual"  # already waiting: untouched
    assert by_value["198.51.100.2"].lane == by_value["198.51.100.3"].lane == "backfill"
    assert by_value["198.51.100.2"].priority == q.LANES["backfill"]

    # Nothing left in scope.
    resp = await client.post("/api/enrichment/sources/shodan/backfill", json={}, headers=admin_headers)
    assert resp.json() == {"queued": 0}


async def test_backfill_honors_the_limit(client, admin_headers, db_session):
    await _source(db_session, "shodan")
    await _observables(db_session)
    resp = await client.post(
        "/api/enrichment/sources/shodan/backfill", json={"entity_type": "observable", "limit": 1}, headers=admin_headers
    )
    assert resp.json() == {"queued": 1}


async def test_enqueue_many_batches_its_inserts(db_session, monkeypatch):
    monkeypatch.setattr(q, "ENQUEUE_CHUNK", 2)
    await _source(db_session, "osv")
    pairs = [(uuid.uuid4(), f"CVE-2026-{i:04d}") for i in range(5)]
    assert await q.enqueue_many(db_session, "cve", "osv", pairs) == 5
    jobs = (await db_session.execute(select(EnrichmentJob))).scalars().all()
    assert len(jobs) == 5 and {j.lane for j in jobs} == {"backfill"}


@pytest.mark.parametrize(
    ("source_type", "body", "code"),
    [
        ("misp_galaxy", {}, "not_lookup"),
        ("shodan", {"entity_type": "cve"}, "not_applicable"),
        ("cisa_kev", {}, "no_column"),
        ("shodan_off", {}, "source_disabled"),
    ],
)
async def test_backfill_refusals(client, admin_headers, db_session, source_type, body, code):
    if source_type == "shodan_off":
        await _source(db_session, "shodan", is_enabled=False)
        source_type = "shodan"
    else:
        await _source(db_session, source_type)
    resp = await client.post(f"/api/enrichment/sources/{source_type}/backfill", json=body, headers=admin_headers)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == code


# ── Contract with the frontend types ─────────────────────────────────


def _interface(name: str) -> dict[str, str]:
    """``{field: type}`` for every field in a TS interface, nested ones too."""
    text = FRONTEND_HOOKS.read_text()
    start = text.index(f"export interface {name} {{")
    depth, i = 0, text.index("{", start)
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            body = text[i + 1 : j]
            break
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    return {m[1]: m[2].strip().rstrip(";") for m in re.finditer(r"^\s*(\w+)\??:\s*([^\n]*)$", body, re.M)}


def _check(value, ts_type: str, where: str) -> None:
    """Type-check the simple TS types; objects and arrays are checked by key."""
    t = ts_type.rstrip("{").strip()
    if not t or t.startswith(("Array<", "Partial<", "Record<")):
        return
    options = [o.strip() for o in t.split("|")]
    if value is None:
        assert "null" in options, f"{where} is null; TS says {ts_type}"
        return
    literals = [o.strip('"') for o in options if o.startswith('"')]
    if literals:
        assert value in literals, f"{where}={value!r} not in {literals}"
    elif "number" in options:
        assert isinstance(value, int | float) and not isinstance(value, bool), where
    elif "string" in options:
        assert isinstance(value, str), where
    elif "boolean" in options:
        assert isinstance(value, bool), where
    elif "string[]" in options:
        assert isinstance(value, list) and all(isinstance(v, str) for v in value), where
    elif "number[]" in options:
        assert isinstance(value, list) and all(isinstance(v, int | float) for v in value), where


def _keys(value, skip=()) -> dict[str, object]:
    """Every key in a JSON value, with its value, except under ``skip``."""
    found: dict[str, object] = {}
    if isinstance(value, dict):
        for k, v in value.items():
            found[k] = v
            if k not in skip:
                found.update(_keys(v, skip))
    elif isinstance(value, list):
        for v in value:
            found.update(_keys(v, skip))
    return found


async def test_console_and_detail_match_the_frontend_types(client, admin_headers, db_session):
    await _scenario(db_session)
    await _observables(db_session)
    await _source(db_session, "shodan")
    console = (await client.get("/api/enrichment/console", headers=admin_headers)).json()

    assert set(console) == set(_interface("EnrichmentConsole"))
    summary = _interface("EnrichmentConsoleSummary")
    assert set(_keys(console["summary"])) == set(summary)
    for k, v in _keys(console["summary"]).items():
        _check(v, summary[k], f"summary.{k}")
    for name, rows in (
        ("EnrichmentConsoleSource", console["sources"]),
        ("EnrichmentConsoleEntityType", console["entity_types"]),
    ):
        ts = _interface(name)
        for row in rows:
            assert set(row) == set(ts), name
            for k, v in row.items():
                _check(v, ts[k], f"{name}.{k}")

    ts = _interface("EnrichmentSourceDetail")
    seen: set[str] = set()
    # NVD has jobs, Shodan a gap and column outputs, MISP Galaxy neither,
    # ETDA relationship outputs.
    await _source(db_session, "etda")
    for source_type in ("nvd", "shodan", "misp_galaxy", "etda"):
        detail = (await client.get(f"/api/enrichment/sources/{source_type}/detail", headers=admin_headers)).json()
        assert set(detail) == {"limits", "trend_24h", "queue", "outputs", "gap", "jobs"}
        found = _keys(detail, skip=("by_lane", "last_detail"))
        assert set(found) <= set(ts), set(found) - set(ts)
        seen |= set(found)
        for k, v in found.items():
            _check(v, ts[k], f"{source_type}.{k}")
        assert set(detail["queue"]["by_lane"]) <= {"manual", "new", "refresh", "backfill"}
    # Between them they send every field the type names.
    assert seen == set(ts), set(ts) - seen


async def test_sourced_job_schedules_edit_through_the_jobs_api(client, admin_headers, db_session, monkeypatch):
    """The console edits a source's job schedules with the Jobs API, and its
    detail shows the result."""
    import app.api.job_schedules as job_schedules

    store: dict = {}
    monkeypatch.setattr(job_schedules, "read_overrides_from_redis", lambda: dict(store))
    monkeypatch.setattr(job_schedules, "write_overrides_to_redis", lambda o: store.update(o))
    await _source(db_session, "epss")

    resp = await client.patch(
        "/api/job-schedules/epss-bulk-sync",
        json={"schedule": {"type": "crontab", "minute": "0", "hour": "7"}},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert (resp.json()["source"], resp.json()["human_schedule"]) == ("epss", "Daily at 7:00 AM")

    detail = (await client.get("/api/enrichment/sources/epss/detail", headers=admin_headers)).json()
    assert [(j["key"], j["schedule"]) for j in detail["jobs"]] == [("epss-bulk-sync", "Daily at 7:00 AM")]


def test_fills_keeps_mixed_case_labels_and_spells_out_relations():
    from app.enrichment.adapters.github_poc import GitHubPoCAdapter
    from app.enrichment.catalogs import RansomwareLiveSource
    from app.enrichment.console import fills

    assert fills(GitHubPoCAdapter).startswith("PoC, public PoCs")
    assert "uses TTP" in fills(RansomwareLiveSource) or "uses technique" in fills(RansomwareLiveSource)
    assert "_" not in fills(RansomwareLiveSource)
