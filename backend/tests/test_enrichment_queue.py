"""The enrichment job queue: enqueue upserts, the call sites that feed it, and
the dispatcher's claim order, outcome handling, backfill share and lease.

Real database and Redis; the sources answer through ``httpx.MockTransport``
behind their real gateways, as in test_enrichment_gateway.py.
"""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import redis.asyncio as aioredis
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment import gateway as gw
from app.enrichment import pipeline
from app.enrichment import queue as q
from app.enrichment.base import EnrichmentData
from app.enrichment.registry import get_adapter, source_gateway
from app.models.cve import CVE
from app.models.enrichment import EnrichmentJob, EnrichmentResult, EnrichmentSource
from app.models.malware_family import MalwareFamily

CVE_ID = "CVE-2021-44228"


class _Source:
    """Serves canned responses and counts what reaches it."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses.pop(0) if self.responses else httpx.Response(200, json={"id": CVE_ID, "aliases": []})


@pytest.fixture(autouse=True)
async def _only_our_sources(db_session):
    """Sources other tests left enabled would add rows of their own."""
    await db_session.execute(update(EnrichmentSource).values(is_enabled=False))
    await db_session.flush()


async def _source(db, source_type="osv", **fields) -> EnrichmentSource:
    row = (
        await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == source_type))
    ).scalar_one_or_none()
    if row is None:
        row = EnrichmentSource(source_type=source_type, display_name=source_type)
        db.add(row)
    row.is_enabled = True
    row.trigger_mode = "auto"
    row.config = {}
    row.daily_budget = None
    row.min_confidence_threshold = "low"
    row.rate_limit_config = {"requests_per_period": 100, "period_seconds": 60}
    for k, v in fields.items():
        setattr(row, k, v)
    await db.flush()
    return row


def _wired(server: _Source):
    """pipeline.adapter_for_source with the gateway sending to ``server``."""

    def wired(source, api_key):
        g = source_gateway(source, api_key)
        g._inner = httpx.MockTransport(server)
        return get_adapter(source.source_type, api_key=api_key, config=source.config, gateway=g)

    return patch.object(pipeline, "adapter_for_source", wired)


async def _jobs(db, **where) -> list[EnrichmentJob]:
    stmt = select(EnrichmentJob).execution_options(populate_existing=True)
    for k, v in where.items():
        stmt = stmt.where(getattr(EnrichmentJob, k) == v)
    return list((await db.execute(stmt.order_by(EnrichmentJob.created_at))).scalars())


async def _dispatch(db, server: _Source, **kw) -> dict:
    with _wired(server):
        return await q.dispatch_due(db, **kw)


# ── enqueue ──────────────────────────────────────────────────────────


async def test_new_lane_queues_enabled_auto_sources_for_the_type(db_session):
    await _source(db_session, "osv")
    await _source(db_session, "nvd")
    await _source(db_session, "github_poc", trigger_mode="manual")
    await _source(db_session, "cvedetails", is_enabled=False)
    await _source(db_session, "shodan")  # doesn't do CVEs

    queued = await q.enqueue(db_session, "cve", uuid.uuid4(), CVE_ID)

    assert sorted(queued) == ["nvd", "osv"]
    assert {(j.source_type, j.lane, j.priority, j.status) for j in await _jobs(db_session)} == {
        ("nvd", "new", q.LANES["new"], "queued"),
        ("osv", "new", q.LANES["new"], "queued"),
    }


async def test_other_lanes_may_name_any_enabled_source(db_session):
    await _source(db_session, "github_poc", trigger_mode="manual")
    await _source(db_session, "osv")
    queued = await q.enqueue(db_session, "cve", uuid.uuid4(), CVE_ID, lane="backfill", source_types=["github_poc"])
    assert queued == ["github_poc"]


async def test_enqueue_again_upgrades_the_lane_and_keeps_the_earlier_due(db_session, test_user):
    await _source(db_session)
    eid = uuid.uuid4()
    now = datetime.now(UTC)
    await q.enqueue(db_session, "cve", eid, CVE_ID, lane="backfill", due_at=now - timedelta(hours=1))
    await q.enqueue(
        db_session,
        "cve",
        eid,
        CVE_ID,
        lane="manual",
        source_types=["osv"],
        requested_by=test_user.id,
        due_at=now + timedelta(hours=1),
    )
    (job,) = await _jobs(db_session)
    assert (job.lane, job.priority, job.requested_by) == ("manual", 0, test_user.id)
    assert job.due_at < now

    # A lower lane never downgrades it, and an earlier due_at still wins.
    await q.enqueue(db_session, "cve", eid, CVE_ID, lane="refresh", due_at=now - timedelta(hours=2))
    (job,) = await _jobs(db_session)
    assert (job.lane, job.requested_by) == ("manual", test_user.id)
    assert job.due_at < now - timedelta(minutes=90)


async def test_enqueue_revives_a_failed_job(db_session):
    await _source(db_session)
    eid = uuid.uuid4()
    await q.enqueue(db_session, "cve", eid, CVE_ID)
    await db_session.execute(update(EnrichmentJob).values(status="failed", attempts=5))
    await q.enqueue(db_session, "cve", eid, CVE_ID)
    (job,) = await _jobs(db_session)
    assert (job.status, job.attempts) == ("queued", 0)


async def test_enqueue_with_nothing_applicable_writes_nothing(db_session):
    assert await q.enqueue(db_session, "cve", uuid.uuid4(), CVE_ID) == []
    assert await _jobs(db_session) == []


# ── call sites ───────────────────────────────────────────────────────


async def test_new_ttp_is_queued(db_session, monkeypatch):
    from app.intelligence import attack_catalog
    from app.intelligence.ttp import store_ttps
    from app.models.entry import Entry
    from app.models.feed import Feed

    async def passthrough(db, ids, context_text=None):
        return {tid: tid for tid in ids}

    monkeypatch.setattr(attack_catalog, "resolve_technique_ids", passthrough)
    await _source(db_session, "mitre_attack")

    feed = Feed(title="f", url=f"https://f.example/{uuid.uuid4()}", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(feed_id=feed.id, guid=str(uuid.uuid4()), title="e", content_text="x")
    db_session.add(entry)
    await db_session.flush()

    await store_ttps(db_session, entry.id, [{"technique_id": "T1999.901", "technique_name": "Made Up"}])
    (job,) = await _jobs(db_session)
    assert (job.entity_type, job.entity_value, job.source_type, job.lane) == ("ttp", "T1999.901", "mitre_attack", "new")


async def test_new_cve_is_queued(db_session):
    from app.intelligence.cve import extract_and_store_cves
    from app.models.entry import Entry
    from app.models.feed import Feed

    await _source(db_session, "osv")
    feed = Feed(title="f", url=f"https://f.example/{uuid.uuid4()}", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(feed_id=feed.id, guid=str(uuid.uuid4()), title="e", content_text="x")
    db_session.add(entry)
    await db_session.flush()

    await extract_and_store_cves(db_session, entry.id, "Patch CVE-2026-50505 now.", enrich=False)
    (job,) = await _jobs(db_session)
    assert (job.entity_type, job.entity_value, job.source_type) == ("cve", "CVE-2026-50505", "osv")


async def test_github_rule_import_queues_new_ttps_and_cves(db_session):
    from app.models.entry import Entry
    from app.models.feed import Feed
    from app.services.github_rule_import import link_entry_cves, link_entry_ttps

    await _source(db_session, "osv")
    await _source(db_session, "mitre_attack")
    feed = Feed(title="f", url=f"https://f.example/{uuid.uuid4()}", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(feed_id=feed.id, guid=str(uuid.uuid4()), title="e", content_text="x")
    db_session.add(entry)
    await db_session.flush()

    await link_entry_ttps(db_session, entry.id, ["T1999.902"])
    await link_entry_cves(db_session, entry.id, ["CVE-2026-50606"])
    assert {(j.entity_value, j.source_type) for j in await _jobs(db_session)} == {
        ("T1999.902", "mitre_attack"),
        ("CVE-2026-50606", "osv"),
    }


async def test_new_observable_is_queued_with_its_confidence(db_session):
    from app.intelligence import observables as obs_mod

    await _source(db_session, "shodan")
    obs = await obs_mod.get_or_create_observable(db_session, "ipv4", "203.0.113.77", via="ai_extraction")
    (job,) = await _jobs(db_session)
    assert (job.entity_type, job.entity_id, job.source_type) == ("observable", obs.id, "shodan")
    assert job.entity_base_confidence == pytest.approx(0.8)

    # The bulk feed door never queues one.
    await obs_mod.get_or_create_observable(db_session, "ipv4", "203.0.113.78", via="ioc_list")
    assert len(await _jobs(db_session)) == 1


# ── dispatcher: claim ────────────────────────────────────────────────


async def test_claim_orders_by_lane_then_due(db_session):
    await _source(db_session)
    now = datetime.now(UTC)
    for lane, minutes in [("backfill", 30), ("new", 5), ("manual", 1), ("new", 20)]:
        await q.enqueue(
            db_session, "cve", uuid.uuid4(), f"{lane}-{minutes}", lane=lane, due_at=now - timedelta(minutes=minutes)
        )
    await q.enqueue(db_session, "cve", uuid.uuid4(), "later", due_at=now + timedelta(hours=1))

    claimed = await q.claim(db_session)
    assert [j.entity_value for j in claimed] == ["manual-1", "new-20", "new-5", "backfill-30"]
    assert {j.status for j in await _jobs(db_session, status="running")} == {"running"}
    assert len(await _jobs(db_session, status="running")) == 4


async def test_claim_reclaims_a_job_past_its_lease(db_session):
    await _source(db_session)
    now = datetime.now(UTC)
    await q.enqueue(db_session, "cve", uuid.uuid4(), "stale")
    await q.enqueue(db_session, "cve", uuid.uuid4(), "live")
    await db_session.execute(
        update(EnrichmentJob)
        .where(EnrichmentJob.entity_value == "stale")
        .values(status="running", claimed_at=now - q.LEASE - timedelta(minutes=1))
    )
    await db_session.execute(
        update(EnrichmentJob)
        .where(EnrichmentJob.entity_value == "live")
        .values(status="running", claimed_at=now - timedelta(minutes=1))
    )
    assert [j.entity_value for j in await q.claim(db_session)] == ["stale"]


@pytest.mark.committed_db
async def test_claim_skips_rows_another_dispatcher_holds(db_session, _engine):
    await _source(db_session)
    await q.enqueue(db_session, "cve", uuid.uuid4(), "held")
    await q.enqueue(db_session, "cve", uuid.uuid4(), "free")
    await db_session.commit()

    other = AsyncSession(bind=_engine, expire_on_commit=False)
    try:
        await other.execute(
            select(EnrichmentJob.id).where(EnrichmentJob.entity_value == "held").with_for_update()
        )  # holds the row lock until rollback
        assert [j.entity_value for j in await q.claim(db_session)] == ["free"]
    finally:
        await other.rollback()
        await other.close()


# ── dispatcher: outcomes ─────────────────────────────────────────────


async def test_success_deletes_the_job_and_stores_the_result(db_session):
    await _source(db_session)
    eid = uuid.uuid4()
    await q.enqueue(db_session, "cve", eid, CVE_ID)
    server = _Source()
    assert await _dispatch(db_session, server) == {"success": 1}
    assert await _jobs(db_session) == []
    assert len(server.requests) == 1
    (row,) = (await db_session.execute(select(EnrichmentResult).where(EnrichmentResult.entity_id == eid))).scalars()
    assert row.status == "success"


async def test_a_manual_job_asks_again_past_a_stored_result(db_session, test_user):
    await _source(db_session)
    eid = uuid.uuid4()
    now = datetime.now(UTC)
    db_session.add(
        EnrichmentResult(
            entity_type="cve",
            entity_id=eid,
            source_type="osv",
            raw_response={},
            parsed_data={"id": CVE_ID},
            enriched_at=now,
            expires_at=now + timedelta(hours=1),
            status="success",
        )
    )
    await q.enqueue(db_session, "cve", eid, CVE_ID, lane="manual", source_types=["osv"], requested_by=test_user.id)
    server = _Source()
    assert await _dispatch(db_session, server) == {"success": 1}
    assert len(server.requests) == 1


async def test_cached_deletes_the_job_without_a_request(db_session):
    await _source(db_session)
    eid = uuid.uuid4()
    now = datetime.now(UTC)
    db_session.add(
        EnrichmentResult(
            entity_type="cve",
            entity_id=eid,
            source_type="osv",
            raw_response={},
            parsed_data={"id": CVE_ID},
            enriched_at=now,
            expires_at=now + timedelta(hours=1),
            status="success",
        )
    )
    await q.enqueue(db_session, "cve", eid, CVE_ID)
    server = _Source()
    assert await _dispatch(db_session, server) == {"cached": 1}
    assert await _jobs(db_session) == [] and server.requests == []


async def test_low_confidence_new_job_is_skipped_and_deleted(db_session):
    await _source(db_session, min_confidence_threshold="high")
    await q.enqueue(db_session, "cve", uuid.uuid4(), CVE_ID, entity_confidence="low", entity_base_confidence=0.1)
    server = _Source()
    assert await _dispatch(db_session, server) == {"skipped_low_confidence": 1}
    assert await _jobs(db_session) == [] and server.requests == []


async def test_a_source_disabled_since_is_dropped(db_session):
    source = await _source(db_session)
    await q.enqueue(db_session, "cve", uuid.uuid4(), CVE_ID)
    source.is_enabled = False
    await db_session.flush()
    assert await _dispatch(db_session, _Source()) == {"unsupported": 1}
    assert await _jobs(db_session) == []


async def test_rate_limited_waits_for_retry_after(db_session):
    source = await _source(db_session, rate_limit_config={"requests_per_period": 1, "period_seconds": 3600})
    await source_gateway(source, None).acquire()
    await q.enqueue(db_session, "cve", uuid.uuid4(), CVE_ID)
    await q.enqueue(db_session, "cve", uuid.uuid4(), "CVE-2021-45046")
    server = _Source()
    before = datetime.now(UTC)

    assert await _dispatch(db_session, server) == {"rate_limited": 2}

    # The second job was held on the first's refusal: nothing was sent.
    assert server.requests == []
    for job in await _jobs(db_session):
        assert (job.status, job.attempts, job.last_status, job.claimed_at) == ("queued", 0, "rate_limited", None)
        assert job.due_at > before + timedelta(minutes=50)


async def test_breaker_open_waits_for_the_breaker(db_session):
    source = await _source(db_session)
    await source_gateway(source, None)._trip("throttle", 600)
    await q.enqueue(db_session, "cve", uuid.uuid4(), CVE_ID)
    before = datetime.now(UTC)
    assert await _dispatch(db_session, _Source()) == {"breaker_open": 1}
    (job,) = await _jobs(db_session)
    assert (job.attempts, job.last_status) == (0, "breaker_open")
    assert before + timedelta(seconds=580) < job.due_at <= before + timedelta(seconds=601)


async def test_budget_exhausted_waits_for_the_next_utc_day(db_session):
    await _source(db_session, daily_budget=0)
    await q.enqueue(db_session, "cve", uuid.uuid4(), CVE_ID)
    assert await _dispatch(db_session, _Source()) == {"budget_exhausted": 1}
    (job,) = await _jobs(db_session)
    assert job.due_at == q.next_utc_midnight(datetime.now(UTC))
    assert job.attempts == 0


async def test_gateway_unavailable_requeues_and_ends_the_tick(db_session):
    await _source(db_session)
    due = datetime.now(UTC) - timedelta(minutes=1)
    for value in (CVE_ID, "CVE-2021-45046"):
        await q.enqueue(db_session, "cve", uuid.uuid4(), value, due_at=due)
    dead = aioredis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.5)

    async def broken():
        return dead

    server = _Source()
    with patch.object(gw, "get_redis_bytes", broken):
        assert await _dispatch(db_session, server) == {"gateway_unavailable": 1}

    assert server.requests == []
    for job in await _jobs(db_session):
        assert (job.status, job.attempts, job.claimed_at) == ("queued", 0, None)
        assert abs((job.due_at - due).total_seconds()) < 1


async def test_error_backs_off_then_fails(db_session):
    await _source(db_session)
    await q.enqueue(db_session, "cve", uuid.uuid4(), CVE_ID)
    before = datetime.now(UTC)
    assert await _dispatch(db_session, _Source(httpx.Response(500))) == {"error": 1}
    (job,) = await _jobs(db_session)
    assert (job.status, job.attempts, job.last_status) == ("queued", 1, "error")
    assert job.last_error
    assert job.due_at >= before + timedelta(seconds=q.ERROR_BACKOFF)

    await db_session.execute(update(EnrichmentJob).values(attempts=q.MAX_ATTEMPTS - 1, due_at=before))
    assert await _dispatch(db_session, _Source(httpx.Response(500))) == {"error": 1}
    (job,) = await _jobs(db_session)
    assert (job.status, job.attempts) == ("failed", q.MAX_ATTEMPTS)
    # A failed job stays put and is never claimed.
    assert await q.claim(db_session) == []


async def test_out_of_time_hands_claimed_jobs_back(db_session, monkeypatch):
    await _source(db_session)
    for i in range(3):
        await q.enqueue(db_session, "cve", uuid.uuid4(), f"CVE-2021-4422{i}")
    clock = [0.0]
    monkeypatch.setattr(q.time, "monotonic", lambda: clock[0])
    real_run = q._run

    async def slow_run(db, job, held):
        clock[0] += q.TICK_SECONDS
        return await real_run(db, job, held)

    monkeypatch.setattr(q, "_run", slow_run)
    assert await _dispatch(db_session, _Source()) == {"success": 1}
    left = await _jobs(db_session)
    assert len(left) == 2 and {(j.status, j.claimed_at) for j in left} == {("queued", None)}


async def test_a_held_source_defers_its_backlog_in_one_update(db_session):
    """A refusal moves the source's whole due backlog in one statement, spaced
    at its rate, and the rest of the tick still runs other sources."""
    from sqlalchemy import event

    osv = await _source(db_session, "osv", rate_limit_config={"requests_per_period": 4, "period_seconds": 60})
    await _source(db_session, "github_poc")
    for _ in range(4):
        await source_gateway(osv, None).acquire()
    backlog = 300
    await q.enqueue_many(db_session, "cve", "osv", [(uuid.uuid4(), f"CVE-2026-{i:05d}") for i in range(backlog)])
    # Due after the whole backlog, so only a claim past the hold reaches it.
    await q.enqueue_many(db_session, "cve", "github_poc", [(uuid.uuid4(), CVE_ID)])

    job_updates = []

    def count(conn, cursor, statement, *args):
        if statement.lstrip().startswith("UPDATE enrichment_jobs"):
            job_updates.append(statement)

    engine = db_session.bind.sync_engine
    event.listen(engine, "before_cursor_execute", count)
    server = _Source(httpx.Response(200, json={"items": []}))
    before = datetime.now(UTC)
    try:
        stats = await _dispatch(db_session, server)
    finally:
        event.remove(engine, "before_cursor_execute", count)

    assert stats["rate_limited"] == q.CLAIM_BATCH
    assert sum(stats.values()) == q.CLAIM_BATCH + 1  # the GitHub job ran too
    assert {r.url.host for r in server.requests} == {"api.github.com"}
    # Claim, the refused job's start and settle, the held backlog, then
    # GitHub's claim, start and settle: a handful, however long the backlog.
    assert len(job_updates) <= 8

    jobs = await _jobs(db_session, source_type="osv")
    assert len(jobs) == backlog
    assert {(j.status, j.last_status, j.claimed_at, j.attempts) for j in jobs} == {("queued", "rate_limited", None, 0)}
    due = sorted(j.due_at for j in jobs)
    assert due[0] > before + timedelta(seconds=10)
    gaps = {round((b - a).total_seconds()) for a, b in zip(due, due[1:])}
    assert gaps == {15}  # one request interval (60 s / 4) apart


async def test_a_held_source_is_claimed_no_more_that_tick(db_session):
    await _source(db_session)
    await q.enqueue(db_session, "cve", uuid.uuid4(), CVE_ID)
    held = frozenset({("osv", None)})
    assert await q.claim(db_session, held=held) == []
    assert [j.entity_value for j in await q.claim(db_session, held=frozenset({("osv", uuid.uuid4())}))] == [CVE_ID]


async def test_a_lease_reclaim_counts_an_attempt_then_fails(db_session):
    await _source(db_session)
    await q.enqueue(db_session, "cve", uuid.uuid4(), CVE_ID)
    expired = datetime.now(UTC) - q.LEASE - timedelta(minutes=1)
    started = {"status": "running", "claimed_at": expired, "last_status": q.STARTED}
    await db_session.execute(update(EnrichmentJob).values(**started))

    (job,) = await q.claim(db_session)
    assert job.attempts == 1
    (row,) = await _jobs(db_session)
    assert (row.status, row.attempts, row.last_status) == ("running", 1, "lease_expired")

    await db_session.execute(update(EnrichmentJob).values(**started, attempts=q.MAX_ATTEMPTS - 1))
    assert await q.claim(db_session) == []
    (row,) = await _jobs(db_session)
    assert (row.status, row.attempts, row.last_status) == ("failed", q.MAX_ATTEMPTS, "lease_expired")
    assert "lease" in row.last_error


async def test_a_lease_reclaim_charges_only_the_job_that_had_started(db_session):
    """A dead worker's batch: one job was running, the rest never began."""
    await _source(db_session)
    for i in range(3):
        await q.enqueue(db_session, "cve", uuid.uuid4(), f"CVE-2021-4422{i}")
    batch = await q.claim(db_session)
    await q._start(db_session, batch[0])
    expired = datetime.now(UTC) - q.LEASE - timedelta(minutes=1)
    await db_session.execute(update(EnrichmentJob).values(claimed_at=expired, updated_at=expired))

    reclaimed = {j.entity_value: j.attempts for j in await q.claim(db_session)}
    assert reclaimed == {batch[0].entity_value: 1, batch[1].entity_value: 0, batch[2].entity_value: 0}
    rows = {j.entity_value: (j.status, j.last_status) for j in await _jobs(db_session)}
    assert rows == {
        batch[0].entity_value: ("running", "lease_expired"),
        batch[1].entity_value: ("running", None),
        batch[2].entity_value: ("running", None),
    }


async def test_a_start_keeps_a_request_made_since_the_claim(db_session, test_user):
    await _source(db_session)
    eid = uuid.uuid4()
    await q.enqueue(db_session, "cve", eid, CVE_ID, lane="backfill", source_types=["osv"])
    (job,) = await q.claim(db_session)
    await q.enqueue(db_session, "cve", eid, CVE_ID, lane="manual", source_types=["osv"], requested_by=test_user.id)
    await q._start(db_session, job)

    await q._settle(db_session, job, "success")
    (row,) = await _jobs(db_session)
    assert (row.status, row.lane) == ("queued", "manual")


async def test_a_claim_goes_on_past_rows_the_lease_limit_failed(db_session):
    await _source(db_session)
    now = datetime.now(UTC)
    await q.enqueue(db_session, "cve", uuid.uuid4(), "worn", due_at=now - timedelta(hours=1))
    await q.enqueue(db_session, "cve", uuid.uuid4(), "fresh", due_at=now - timedelta(minutes=1))
    await db_session.execute(
        update(EnrichmentJob)
        .where(EnrichmentJob.entity_value == "worn")
        .values(
            status="running",
            claimed_at=now - q.LEASE - timedelta(minutes=1),
            last_status=q.STARTED,
            attempts=q.MAX_ATTEMPTS - 1,
        )
    )

    assert [j.entity_value for j in await q.claim(db_session, limit=1)] == ["fresh"]
    assert [j.status for j in await _jobs(db_session, entity_value="worn")] == ["failed"]


@pytest.mark.committed_db
async def test_a_hold_leaves_a_row_another_dispatcher_claimed_meanwhile(db_session, _engine):
    """The hold's UPDATE waits on a row another dispatcher is claiming; once
    that claim commits the row is running, and the hold must not take it back."""
    import asyncio

    await _source(db_session)
    now = datetime.now(UTC)
    await q.enqueue(db_session, "cve", uuid.uuid4(), "refused", due_at=now - timedelta(minutes=2))
    await q.enqueue(db_session, "cve", uuid.uuid4(), "contested", due_at=now - timedelta(minutes=1))
    await db_session.commit()
    (refused,) = await q.claim(db_session, limit=1)

    other = AsyncSession(bind=_engine, expire_on_commit=False)
    try:
        await other.execute(
            update(EnrichmentJob)
            .where(EnrichmentJob.entity_value == "contested")
            .values(status="running", claimed_at=func.now())
        )  # claimed, not yet committed
        hold = asyncio.create_task(q._hold(db_session, refused, now + timedelta(hours=1), "rate_limited", []))
        await asyncio.sleep(0.5)
        assert not hold.done()  # waiting on the other claim's row lock
        await other.commit()
        await asyncio.wait_for(hold, 10)
    finally:
        await other.close()

    (row,) = await _jobs(db_session, entity_value="contested")
    assert (row.status, row.last_status) == ("running", None)


async def test_a_request_made_during_a_run_is_kept(db_session, test_user):
    await _source(db_session)
    eid = uuid.uuid4()
    await q.enqueue(db_session, "cve", eid, CVE_ID, lane="backfill", source_types=["osv"])
    (job,) = await q.claim(db_session)
    # A person asks for it while it runs.
    await q.enqueue(db_session, "cve", eid, CVE_ID, lane="manual", source_types=["osv"], requested_by=test_user.id)

    await q._settle(db_session, job, "needs_key")
    (row,) = await _jobs(db_session)
    assert (row.status, row.lane, row.requested_by, row.claimed_at) == ("queued", "manual", test_user.id, None)

    # Claimed again and nobody asks: the outcome applies.
    (job,) = await q.claim(db_session)
    await q._settle(db_session, job, "success")
    assert await _jobs(db_session) == []


async def test_a_request_made_during_a_run_is_not_deferred(db_session, test_user):
    await _source(db_session)
    eid = uuid.uuid4()
    await q.enqueue(db_session, "cve", eid, CVE_ID, lane="backfill", source_types=["osv"])
    (job,) = await q.claim(db_session)
    await q.enqueue(db_session, "cve", eid, CVE_ID, lane="manual", source_types=["osv"], requested_by=test_user.id)

    await q._settle(db_session, job, "rate_limited", retry_after=3600)
    (row,) = await _jobs(db_session)
    assert (row.status, row.lane, row.requested_by) == ("queued", "manual", test_user.id)
    assert row.due_at <= datetime.now(UTC)


# ── backfill share ───────────────────────────────────────────────────


async def test_backfill_defers_past_its_share_of_the_budget(db_session):
    source = await _source(db_session, daily_budget=10)
    g = source_gateway(source, None)
    for _ in range(6):
        await g.acquire()
    await q.enqueue(db_session, "cve", uuid.uuid4(), "backfill", lane="backfill", source_types=["osv"])
    await q.enqueue(db_session, "cve", uuid.uuid4(), "new")
    server = _Source()

    assert await _dispatch(db_session, server) == {"success": 1, "backfill_share": 1}
    (job,) = await _jobs(db_session)
    assert (job.entity_value, job.last_status) == ("backfill", "backfill_share")
    assert job.due_at == q.next_utc_midnight(datetime.now(UTC))
    assert len(server.requests) == 1  # only the new-lane job went out


async def test_backfill_runs_under_its_share(db_session):
    source = await _source(db_session, daily_budget=10)
    g = source_gateway(source, None)
    for _ in range(5):
        await g.acquire()
    await q.enqueue(db_session, "cve", uuid.uuid4(), CVE_ID, lane="backfill", source_types=["osv"])
    assert await _dispatch(db_session, _Source()) == {"success": 1}


# ── results reach the entity ─────────────────────────────────────────


async def test_results_are_written_onto_the_entity(db_session):
    await _source(db_session, "malpedia")
    family = MalwareFamily(name=f"QueueTestFamily{uuid.uuid4().hex[:6]}")
    db_session.add(family)
    await db_session.flush()
    await q.enqueue(db_session, "malware", family.id, family.name, lane="backfill", source_types=["malpedia"])

    adapter = MagicMock()
    adapter.supports_entity.return_value = True
    adapter.enrich = AsyncMock(
        return_value=EnrichmentData(raw_response={}, parsed_data={"description": "A loader seen in 2026."})
    )
    with patch.object(pipeline, "adapter_for_source", return_value=adapter):
        assert await q.dispatch_due(db_session) == {"success": 1}

    await db_session.refresh(family)
    assert family.description == "A loader seen in 2026."


# ── manual "Enrich now" ──────────────────────────────────────────────


async def test_manual_enrich_queues_refused_sources(client, auth_headers, db_session, test_user):
    source = await _source(db_session, rate_limit_config={"requests_per_period": 1, "period_seconds": 3600})
    await source_gateway(source, None).acquire()
    cve = CVE(cve_id="CVE-2026-50707")
    db_session.add(cve)
    await db_session.flush()

    with _wired(_Source()):
        resp = await client.post(
            "/api/enrichment/enrich",
            json={"entity_type": "cve", "entity_id": str(cve.id), "source_types": ["osv"]},
            headers=auth_headers,
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["results"][0]["status"] == "rate_limited"
    assert body["queued"] == ["osv"]
    (job,) = await _jobs(db_session)
    assert (job.lane, job.requested_by, job.entity_id) == ("manual", test_user.id, cve.id)
    assert job.due_at > datetime.now(UTC) + timedelta(minutes=50)


async def test_manual_enrich_queues_nothing_on_success(client, auth_headers, db_session):
    await _source(db_session)
    cve = CVE(cve_id="CVE-2026-50808")
    db_session.add(cve)
    await db_session.flush()
    with _wired(_Source()):
        resp = await client.post(
            "/api/enrichment/enrich",
            json={"entity_type": "cve", "entity_id": str(cve.id), "source_types": ["osv"]},
            headers=auth_headers,
        )
    assert resp.json()["queued"] == []
    assert await _jobs(db_session) == []


# ── wiring ───────────────────────────────────────────────────────────


def test_dispatcher_runs_on_its_own_queue_every_30s():
    from app.pipeline.registry import PIPELINE_STAGES
    from app.workers.celery_app import celery_app
    from app.workers.job_registry import build_beat_schedule

    task = "app.workers.enrichment_dispatch_tasks.dispatch_enrichment_jobs"
    celery_app.loader.import_default_modules()
    assert task in celery_app.tasks
    assert celery_app.conf.task_routes[task] == {"queue": "enrichment"}
    beat = build_beat_schedule({})["enrichment-dispatch"]
    assert beat["task"] == task and beat["schedule"] == 30
    assert beat["options"] == {"expires": 30}
    assert PIPELINE_STAGES["enrich"].task_path == task
