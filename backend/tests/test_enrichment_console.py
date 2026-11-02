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
    assert (by_type["virustotal"]["status"], by_type["virustotal"]["attention"]) == (
        "needs_key",
        "needs an API key before it can run",
    )
    assert (by_type["virustotal"]["key"], by_type["virustotal"]["key_status"]) == ("virustotal", "missing")
    assert (by_type["nvd"]["key"], by_type["nvd"]["key_status"]) == ("nvd_api_key", "optional")
    assert by_type["osv"]["key"] is None and by_type["osv"]["key_status"] is None
    assert by_type["shodan"]["egress"] == "shares_ioc" and by_type["shodan"]["commercial_ok"] is False
    assert by_type["shodan"]["about"] and by_type["shodan"]["used_today"] == 2
    assert by_type["nvd"]["trigger_mode"] == "auto" and by_type["misp_galaxy"]["trigger_mode"] is None
    assert by_type["nvd"]["jobs"] == 3
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

    # One row per problem, with the action that fixes it; failing ones first.
    attention = {a["source_type"]: a for a in data["attention"]}
    assert set(attention) == {"nvd", "epss", "virustotal"}
    assert attention["nvd"]["severity"] == "bad" and attention["epss"]["severity"] == "bad"
    assert attention["virustotal"]["severity"] == "warn"
    assert [a["severity"] for a in data["attention"]] == ["bad", "bad", "warn"]

    summary = data["summary"]
    assert "needs_attention" not in summary
    assert summary["sources_on"] == 4
    assert summary["sources_total"] == len(data["sources"])
    assert summary["paused"] is False and summary["redis_ok"] is True
    activity = summary["activity_24h"]
    assert activity["requests"] == 2
    assert len(activity["trend"]) == 24 and activity["trend"][-1] == 2
    assert (activity["waiting"], activity["waiting_backfill"], activity["deferred"]) == (0, 0, 0)
    # Shodan's two requests carried no lookup's indicator; only enrich_entity counts one.
    assert activity["iocs_sent"] == 0
    assert sorted(activity["ioc_sources"]) == sorted([by_type["shodan"]["label"], by_type["virustotal"]["label"]])


async def test_console_off_wins_over_old_failures(client, admin_headers, db_session):
    """A source switched off whose last job errored, or whose breaker is open,
    reads off and needs no attention: there's nothing to act on."""
    nvd = await _source(db_session, "nvd", is_enabled=False)
    db_session.add(_run("cve-nvd-backfill", "error", 5, error="TimeLimitExceeded(960)"))
    await source_gateway(nvd, None)._trip("throttle", 600)
    await db_session.flush()

    data = (await client.get("/api/enrichment/console", headers=admin_headers)).json()
    row = next(s for s in data["sources"] if s["source_type"] == "nvd")
    assert (row["status"], row["attention"]) == ("off", None)
    assert data["attention"] == []


async def test_console_says_a_rejected_key_not_failing(client, admin_headers, db_session, monkeypatch):
    """An auth failure the gateway recorded reads "key_rejected" with its
    message, so a bad key isn't mistaken for a rate limit."""
    import app.enrichment.console as console

    async def key(row, db):
        return "bad-key" if row.source_type == "greynoise" else None

    monkeypatch.setattr(console, "_global_key", key)
    row = await _source(db_session, "greynoise")
    gateway = source_gateway(row, "bad-key")
    await gateway._mark_auth_failed(401, "GreyNoise rejected the API key (401)")

    data = (await client.get("/api/enrichment/console", headers=admin_headers)).json()
    greynoise = next(s for s in data["sources"] if s["source_type"] == "greynoise")
    assert greynoise["status"] == "key_rejected"
    assert greynoise["attention"] == "GreyNoise rejected the API key (401)"


async def test_console_marks_recently_added_sources_new(client, admin_headers, db_session):
    """New = added in the last two weeks and at least a day after the first
    rows, so a fresh install's seeded sources don't all read as new."""
    old = datetime.now(UTC) - timedelta(days=90)
    await db_session.execute(update(EnrichmentSource).values(created_at=old))
    await _source(db_session, "etda", created_at=datetime.now(UTC) - timedelta(days=2))
    await _source(db_session, "osv", created_at=datetime.now(UTC) - timedelta(days=30))
    await db_session.flush()

    data = (await client.get("/api/enrichment/console", headers=admin_headers)).json()
    new = {s["source_type"] for s in data["sources"] if s["new"]}
    assert new == {"etda"}


def test_is_new_ignores_a_fresh_installs_seeded_rows():
    from app.enrichment.console import is_new

    now = datetime.now(UTC)
    seeded = EnrichmentSource(source_type="nvd", created_at=now - timedelta(days=1, hours=1))
    assert is_new(seeded, now - timedelta(days=1, hours=2), now) is False
    later = EnrichmentSource(source_type="etda", created_at=now - timedelta(hours=1))
    assert is_new(later, now - timedelta(days=1, hours=2), now) is True


def test_refresh_days_from_the_row_the_manifest_or_the_adapter():
    from app.enrichment.console import refresh_days
    from app.enrichment.registry import SOURCE_REGISTRY

    etda = SOURCE_REGISTRY["etda"]
    # The row's own setting wins.
    assert refresh_days(etda, EnrichmentSource(source_type="etda", config={"refresh_days": 3})) == 3
    # Else the adapter module's TTL_HOURS (ETDA: 336 h).
    assert refresh_days(etda, EnrichmentSource(source_type="etda", config={})) == 14


async def test_console_fills_reads_the_manifest(client, admin_headers, db_session):
    await _source(db_session, "shodan")
    data = (await client.get("/api/enrichment/console", headers=admin_headers)).json()
    by_type = {s["source_type"]: s for s in data["sources"]}
    assert by_type["shodan"]["fills"].startswith("reputation, infra tag, open ports")
    assert by_type["cisa_kev"]["fills"].startswith("in KEV, added to KEV")
    assert by_type["epss"]["fills"] == "EPSS score, EPSS percentile, scored on"
    # A catalog source with no outputs says what its job does.
    assert by_type["misp_galaxy"]["fills"].startswith("country, motivation, description")
    assert by_type["mitre_cwe"]["fills"].startswith("Re-pull the MITRE CWE catalog")


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

    limits = dict(data["limits"])
    # Derived from the manifest / gateway; checked in their own tests.
    limits.pop("refresh_days")
    assert limits.pop("concurrency") == source_gateway(nvd, None).concurrency
    assert limits == {
        # The stored 40 is above NVD's keyless ceiling: the gateway holds it to 5.
        "rate": {"requests_per_period": 40, "period_seconds": 30},
        "effective_rate": {"requests_per_period": 5, "period_seconds": 30},
        "rate_note": "held to the source's limit",
        "ceiling_per_period": 5,  # keyless: NVD allows 5 per 30 s without a key
        "daily_budget": 100,
        "used_today": 3,
        "backfill_share": gw.BACKFILL_SHARE,
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
        # Why queued lookups wait again: the refresh one met a 429.
        "by_reason": {"rate_limited": 1},
        "failed": 1,
    }
    # What the limits form edits, so the console needs no second request.
    assert data["settings"] == {
        "trigger_mode": "auto",
        "rate_limit_config": {"requests_per_period": 40, "period_seconds": 30},
    }
    jobs = {j["key"]: j for j in data["jobs"]}
    assert set(jobs) == {"cve-nvd-refresh", "cve-nvd-backfill", "reenrich-cve-nvd"}
    assert jobs["cve-nvd-backfill"] == {
        "key": "cve-nvd-backfill",
        "description": "Backfill NVD data (CVSS, description, affected products, references) for CVEs missing it",
        "settings_keys": [],
        "schedule": "Daily at 1:30 AM",
        "runs_30d": 2,
        "ok_30d": 1,
        "last_status": "error",
        "last_error": "TimeLimitExceeded(960)",
        "last_detail": {"enriched": 0},
    }
    assert jobs["reenrich-cve-nvd"]["settings_keys"] == ["cve_reenrich_batch_size"]
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
    assert data["limits"]["scope"] == "observable (ipv4), status active with no reputation ports"
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


async def test_set_paused_leaves_the_flag_at_the_last_change_committed(db_session, monkeypatch):
    """Two quick toggles: the other one commits between this one's commit and
    its flag write, so the flag must follow the stored row, not the argument."""
    import app.enrichment.pause as pause

    sync = pause.sync_pause

    async def toggled_back_first(db):
        await db.execute(update(SystemSettings).where(SystemSettings.id == 1).values(settings={SETTING: False}))
        return await sync(db)

    monkeypatch.setattr(pause, "sync_pause", toggled_back_first)
    await set_paused(db_session, True)
    assert not await (await get_redis_bytes()).exists(gw.paused_key())


async def test_a_hung_redis_holds_the_pause_sync_only_briefly(db_session, monkeypatch):
    import asyncio

    import app.enrichment.pause as pause

    class HungPipeline:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def exists(self, *args):
            pass

        set = delete = exists

        async def execute(self):
            await asyncio.Event().wait()

    class Hung:
        def pipeline(self, transaction=True):
            return HungPipeline()

    async def hung():
        return Hung()

    await set_paused(db_session, True)
    monkeypatch.setattr(pause, "FLAG_TIMEOUT", 0.05)
    monkeypatch.setattr(pause, "get_redis_bytes", hung)
    assert await asyncio.wait_for(sync_pause(db_session), 5) is True


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
    # A person's request: the manual lane, said explicitly.
    assert body["lane"] == "manual"
    job = (await db_session.execute(select(EnrichmentJob).where(EnrichmentJob.entity_id == cve.id))).scalar_one()
    assert job.lane == "manual"


async def test_enrich_refuses_any_lane_but_manual(client, auth_headers, db_session):
    from app.models.cve import CVE

    cve = CVE(cve_id="CVE-2021-44229")
    db_session.add(cve)
    await db_session.flush()
    resp = await client.post(
        "/api/enrichment/enrich",
        json={"entity_type": "cve", "entity_id": str(cve.id), "source_types": ["osv"], "lane": "backfill"},
        headers=auth_headers,
    )
    # The app answers a request validation error with 400 (validation_error_handler).
    assert resp.status_code == 400
    error = resp.json()["error"]
    assert error["code"] == "validation_error"
    assert [d["field"] for d in error["details"]] == ["lane"]


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


async def test_detail_shows_the_stored_rate_beside_the_keyed_one(client, admin_headers, db_session, monkeypatch):
    """With a key, NVD runs at its keyed rate while the row keeps the keyless
    default. The detail returns both, so the form never saves the keyed rate
    into the row (which would turn the keyed swap off)."""
    import app.enrichment.console as console

    async def key(row, db):
        return "nvd-key"

    monkeypatch.setattr(console, "_global_key", key)
    await _source(db_session, "nvd", rate_limit_config={"requests_per_period": 5, "period_seconds": 30})

    limits = (await client.get("/api/enrichment/sources/nvd/detail", headers=admin_headers)).json()["limits"]
    assert limits["rate"] == {"requests_per_period": 5, "period_seconds": 30}
    assert limits["effective_rate"] == {"requests_per_period": 50, "period_seconds": 30}
    assert limits["rate_note"] == "with key"
    assert "key" not in limits


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


@pytest.mark.skipif(
    not FRONTEND_HOOKS.exists(),
    reason="needs the repo checkout (frontend/ or .env.example not mounted in the api container)",
)
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
        assert set(detail) == {"limits", "trend_24h", "queue", "outputs", "gap", "jobs", "settings"}
        found = _keys(detail, skip=("by_lane", "by_reason", "last_detail", "rate_limit_config"))
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


async def test_job_schedules_list_runs_and_owner(client, admin_headers, db_session, monkeypatch):
    """Engine → Jobs: every job carries its last 30 days from job_runs, and a
    source's job names its owner."""
    import app.api.job_schedules as job_schedules

    monkeypatch.setattr(job_schedules, "read_overrides_from_redis", lambda: {})
    db_session.add_all(
        [
            _run("cve-nvd-backfill", "success", 300),
            _run("cve-nvd-backfill", "error", 5, error="TimeLimitExceeded(960)"),
            _run("cve-nvd-backfill", "success", 60 * 24 * 40),  # older than 30 days
        ]
    )
    await db_session.flush()

    jobs = {j["name"]: j for j in (await client.get("/api/job-schedules", headers=admin_headers)).json()["jobs"]}
    backfill = jobs["cve-nvd-backfill"]
    assert (backfill["source"], backfill["source_label"]) == ("nvd", "NVD API 2.0")
    assert (backfill["runs_30d"], backfill["ok_30d"]) == (2, 1)
    assert (backfill["last_status"], backfill["last_error"]) == ("error", "TimeLimitExceeded(960)")
    assert backfill["last_run_at"]
    never = next(j for j in jobs.values() if j["runs_30d"] == 0)
    assert (never["ok_30d"], never["last_status"], never["last_error"]) == (0, None, None)
    unowned = next(j for j in jobs.values() if not j["source"])
    assert unowned["source_label"] is None


def test_backfill_looks_a_victim_up_by_its_domain():
    from app.enrichment.registry import SOURCE_REGISTRY

    cls = next(c for c in SOURCE_REGISTRY.values() if "ransomware_victim" in c.applies_to)
    assert cls.lookup_column("ransomware_victim") == "domain"
    assert SOURCE_REGISTRY["nvd"].lookup_column("cve") == "cve_id"


async def test_pivot_entity_carries_vendor_country_and_product_lifecycle(db_session):
    from datetime import date

    from app.intelligence.correlation import _serialize_entity, get_entity
    from app.models.country import Country
    from app.models.product import Product
    from app.models.vendor import Vendor

    country = Country(name=f"Testland {uuid.uuid4().hex[:6]}")
    db_session.add(country)
    await db_session.flush()
    vendor = Vendor(name=f"Acme {uuid.uuid4().hex[:6]}", country_id=country.id)
    product = Product(name=f"Widget {uuid.uuid4().hex[:6]}", support_status="eol", next_eol=date(2025, 10, 14))
    db_session.add_all([vendor, product])
    await db_session.flush()
    db_session.expunge_all()

    v = _serialize_entity("vendor", await get_entity(db_session, "vendor", vendor.id))
    assert (v["country_id"], v["country"]) == (str(country.id), country.name)
    p = _serialize_entity("product", await get_entity(db_session, "product", product.id))
    assert (p["support_status"], p["next_eol"]) == ("eol", "2025-10-14")


def test_fills_keeps_mixed_case_labels_and_spells_out_relations():
    from app.enrichment.adapters.github_poc import GitHubPoCAdapter
    from app.enrichment.catalogs import RansomwareLiveSource
    from app.enrichment.console import fills

    assert fills(GitHubPoCAdapter).startswith("PoC, public PoCs")
    assert "uses TTP" in fills(RansomwareLiveSource) or "uses technique" in fills(RansomwareLiveSource)
    assert "_" not in fills(RansomwareLiveSource)


# ── Attention: one row per problem, with the action that fixes it ────


def _job(source_type, status="failed", lane="new", last_status="error", last_error="HTTP 500", **fields):
    return EnrichmentJob(
        entity_type="observable",
        entity_id=uuid.uuid4(),
        entity_value="198.51.100.9",
        source_type=source_type,
        lane=lane,
        priority=q.LANES[lane],
        status=status,
        due_at=datetime.now(UTC),
        attempts=fields.pop("attempts", 5),
        last_status=last_status,
        last_error=last_error,
        **fields,
    )


async def test_attention_names_the_action_for_each_problem(client, admin_headers, db_session, monkeypatch):
    import app.enrichment.console as console

    async def key(row, db):
        return "bad-key" if row.source_type == "greynoise" else None

    monkeypatch.setattr(console, "_global_key", key)
    greynoise = await _source(db_session, "greynoise")
    await source_gateway(greynoise, "bad-key")._mark_auth_failed(401, "GreyNoise rejected the API key (401)")
    await _source(db_session, "virustotal")  # needs a key it doesn't have
    await _source(db_session, "nvd")
    db_session.add(_run("cve-nvd-backfill", "error", 5, error="boom"))
    epss = await _source(db_session, "epss")
    await source_gateway(epss, None)._trip("throttle", 600)
    await _source(db_session, "shodan")
    db_session.add_all([_job("shodan"), _job("shodan", last_error="HTTP 502")])
    await db_session.flush()

    data = (await client.get("/api/enrichment/console", headers=admin_headers)).json()
    rows = {a["source_type"]: a for a in data["attention"]}
    assert rows["greynoise"] == {
        "source_type": "greynoise",
        "label": "GreyNoise Community",
        "text": "GreyNoise rejected the API key (401)",
        "severity": "bad",
        "action": {"kind": "key", "key": "greynoise", "label": "Replace key"},
    }
    assert rows["virustotal"]["action"] == {"kind": "key", "key": "virustotal", "label": "Add key"}
    assert rows["virustotal"]["severity"] == "warn"
    assert rows["nvd"]["action"] == {"kind": "source", "source": "nvd", "tab": "jobs", "label": "Open jobs"}
    assert rows["epss"]["action"] == {"kind": "source", "source": "epss", "tab": "overview", "label": "Open"}
    assert rows["shodan"]["text"] == "2 lookups gave up after repeated errors"
    assert rows["shodan"]["action"] == {"kind": "retry", "source": "shodan", "label": "Retry all"}
    assert rows["shodan"]["severity"] == "warn"
    # Failing first, then by label.
    order = [(a["severity"] != "bad", a["label"].lower()) for a in data["attention"]]
    assert order == sorted(order)
    by_type = {s["source_type"]: s for s in data["sources"]}
    assert by_type["greynoise"]["key_status"] == "rejected"


async def test_a_key_problem_shared_by_several_sources_is_one_row(client, admin_headers, db_session):
    """Three abuse.ch sources missing their one Auth-Key are one problem,
    labelled with the credential; other problems stay one row per source."""
    for source_type in ("threatfox", "urlhaus", "malwarebazaar"):
        await _source(db_session, source_type)
    for source_type in ("shodan", "rdap"):
        await _source(db_session, source_type)
        db_session.add(_job(source_type))
    await db_session.flush()

    attention = (await client.get("/api/enrichment/console", headers=admin_headers)).json()["attention"]
    keyed = [a for a in attention if a["action"]["kind"] == "key"]
    assert len(keyed) == 1
    (row,) = keyed
    assert row["label"] == "abuse.ch Auth-Key"
    assert row["text"] == "needs an API key before it can run"
    assert row["action"] == {"kind": "key", "key": "abuse_ch", "label": "Add key"}
    assert len(row["sources"]) == 3
    retries = [a for a in attention if a["action"]["kind"] == "retry"]
    assert sorted(a["source_type"] for a in retries) == ["rdap", "shodan"]
    assert all("sources" not in a for a in retries)


async def test_a_lone_missing_key_row_keeps_its_sources_label(client, admin_headers, db_session):
    vt = await _source(db_session, "virustotal", display_name="VirusTotal (ours)")
    (row,) = (await client.get("/api/enrichment/console", headers=admin_headers)).json()["attention"]
    assert row["label"] == vt.display_name
    assert "sources" not in row


# ── Coverage ─────────────────────────────────────────────────────────


async def _coverage(client, admin_headers) -> dict:
    resp = await client.get("/api/enrichment/coverage", headers=admin_headers)
    assert resp.status_code == 200
    return {(f["entity_type"], f["field"]): f for f in resp.json()["fields"]}


async def test_coverage_offers_a_backfill_only_on_a_lookup_sources_primary_column(client, admin_headers, db_session):
    from app.enrichment.registry import SOURCE_REGISTRY
    from app.models.cve import CVE
    from app.workers.job_registry import schedule_to_human

    await _source(db_session, "nvd")
    db_session.add_all(
        [
            CVE(cve_id="CVE-2026-90001", cvss_score=9.8, description="filled"),
            CVE(cve_id="CVE-2026-90002"),
            CVE(cve_id="CVE-2026-90003"),
        ]
    )
    await db_session.flush()

    fields = await _coverage(client, admin_headers)
    cvss = fields[("cve", "cvss_score")]
    assert (cvss["filled"], cvss["total"], cvss["filled_pct"]) == (1, 3, 33.3)
    # NVD is on and cvss_score is the column its backfill fills.
    assert cvss["action"] == {"kind": "backfill", "source": "nvd", "count": 2}
    assert cvss["cadence"] is None
    assert {"source_type": "nvd", "enabled": True} == {
        k: v for s in cvss["sources"] if s["source_type"] == "nvd" for k, v in s.items() if k != "label"
    }
    # NVD fills descriptions too, but its backfill doesn't target them, and
    # no AI research covers a CVE description: its jobs fill it on schedule.
    description = fields[("cve", "description")]
    assert description["action"] is None
    assert description["cadence"] == schedule_to_human(SOURCE_REGISTRY["nvd"].jobs[0].schedule)
    # A column written along with another isn't its own row.
    assert ("cve", "severity") not in fields


async def test_coverage_falls_back_to_ai_research_where_it_covers_the_field(client, admin_headers, db_session):
    from app.models.cve import CVE
    from app.models.threat_actor import ThreatActor

    await _source(db_session, "misp_galaxy")  # a catalog: nothing to backfill through
    db_session.add_all([ThreatActor(name="CoverageActor"), CVE(cve_id="CVE-2026-90004")])
    await db_session.flush()

    fields = await _coverage(client, admin_headers)
    assert fields[("threat_actor", "country")]["action"] == {"kind": "ai", "field": "country"}
    assert fields[("threat_actor", "motivation")]["action"] == {"kind": "ai", "field": "motivation"}
    # NVD is off: the CVSS gap goes to AI research ("cvss" covers cvss_score).
    assert fields[("cve", "cvss_score")]["action"] == {"kind": "ai", "field": "cvss"}
    # Nothing is on to fill an EPSS score, and no AI covers it.
    epss = fields[("cve", "epss_score")]
    assert (epss["action"], epss["cadence"]) == (None, None)


async def test_coverage_of_a_full_column_offers_nothing(client, admin_headers, db_session):
    from app.models.cve import CVE
    from app.workers.job_registry import schedule_to_human

    await _source(db_session, "epss")
    db_session.add(CVE(cve_id="CVE-2026-90005", epss_score=0.4, epss_percentile=0.9))
    await db_session.flush()

    fields = await _coverage(client, admin_headers)
    score = fields[("cve", "epss_score")]
    assert (score["filled"], score["total"], score["action"]) == (1, 1, None)
    assert score["cadence"] == "Daily at 6:30 AM" == schedule_to_human({"type": "crontab", "minute": "30", "hour": "6"})


# ── Activity and retry ───────────────────────────────────────────────


async def test_activity_lanes_failed_lookups_and_requests(client, admin_headers, db_session):
    shodan = await _source(db_session, "shodan")
    await _send(source_gateway(shodan, None), 3)
    rdap = await _source(db_session, "rdap")
    await _send(source_gateway(rdap, None), 1)
    db_session.add_all(
        [
            _job("shodan", status="queued", lane="backfill", last_status=None, last_error=None, attempts=0),
            _job("shodan", status="queued", lane="backfill", last_status="rate_limited", last_error=None),
            # A rejected key put this one off too: deferred, not failed.
            _job("shodan", status="queued", lane="backfill", last_status="auth_failed", last_error=None),
            _job("shodan", status="running", lane="manual", last_status=None, last_error=None, attempts=0),
            _job("shodan", last_error="HTTP 500"),
            _job("shodan", last_error="HTTP 502"),
            _job("rdap", last_error="timeout"),
        ]
    )
    await db_session.flush()

    resp = await client.get("/api/enrichment/activity", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    lanes = {lane["lane"]: lane for lane in data["lanes"]}
    assert set(lanes) == set(q.LANES)
    assert lanes["backfill"] == {"lane": "backfill", "waiting": 3, "deferred": 2}
    assert lanes["manual"] == {"lane": "manual", "waiting": 1, "deferred": 0}
    assert lanes["new"] == {"lane": "new", "waiting": 0, "deferred": 0}
    assert data["backfill_share"] == gw.BACKFILL_SHARE
    assert [(f["source_type"], f["count"]) for f in data["failed"]] == [("shodan", 2), ("rdap", 1)]
    assert data["failed"][0]["last_error"] in ("HTTP 500", "HTTP 502")
    assert [(r["source_type"], r["requests"]) for r in data["requests"]] == [("shodan", 3), ("rdap", 1)]


async def test_activity_requests_are_null_when_redis_is_down(client, admin_headers, db_session, monkeypatch):
    import redis.asyncio as aioredis

    await _source(db_session, "shodan")
    dead = aioredis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.5)

    async def broken():
        return dead

    monkeypatch.setattr(gw, "get_redis_bytes", broken)
    data = (await client.get("/api/enrichment/activity", headers=admin_headers)).json()
    assert data["requests"] is None


async def test_retry_queues_failed_lookups_again_with_attempts_reset(client, admin_headers, db_session):
    await _source(db_session, "shodan")
    await _source(db_session, "rdap")
    shodan_jobs = [_job("shodan"), _job("shodan")]
    rdap_job = _job("rdap")
    waiting = _job("shodan", status="queued", last_status="rate_limited", last_error=None, attempts=2)
    db_session.add_all([*shodan_jobs, rdap_job, waiting])
    await db_session.flush()

    resp = await client.post("/api/enrichment/retry", params={"source_type": "shodan"}, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json() == {"queued": 2}
    for job in shodan_jobs:
        await db_session.refresh(job)
        assert (job.status, job.attempts, job.last_status, job.last_error) == ("queued", 0, None, None)
    await db_session.refresh(rdap_job)
    await db_session.refresh(waiting)
    assert rdap_job.status == "failed"
    # A lookup that is only waiting keeps its attempts.
    assert (waiting.attempts, waiting.last_status) == (2, "rate_limited")

    # No source: every failed lookup.
    assert (await client.post("/api/enrichment/retry", headers=admin_headers)).json() == {"queued": 1}
    await db_session.refresh(rdap_job)
    assert (rdap_job.status, rdap_job.attempts) == ("queued", 0)


async def test_coverage_activity_and_retry_are_admin_only(client, auth_headers, db_session):
    for method, path in (
        ("get", "/api/enrichment/coverage"),
        ("get", "/api/enrichment/activity"),
        ("post", "/api/enrichment/retry"),
    ):
        resp = await client.request(method, path, headers=auth_headers)
        assert resp.status_code == 403, path
