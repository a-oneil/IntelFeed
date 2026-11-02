"""Scheduled enrichment jobs finish inside their limits and report what they did."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

import app.workers.enrichment_tasks as tasks
from app.models.cve import CVE
from app.models.enrichment import EnrichmentResult
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import ThreatActor
from app.models.vendor import Vendor
from app.workers import task_tracking


@pytest.fixture
def worker_session(db_session, monkeypatch):
    @asynccontextmanager
    async def fake_session():
        yield db_session

    monkeypatch.setattr(tasks, "_get_worker_session", fake_session)


# ── Job runs record the stats ───────────────────────────────────────


@pytest.mark.parametrize("task", [tasks.run_cve_nvd_backfill, tasks.run_malpedia_sync, tasks.run_epss_bulk_sync])
def test_tasks_return_their_stats_for_job_runs(task, monkeypatch):
    stats = {"updated": 3}

    def fake_run_async(coro):
        coro.close()
        return stats

    monkeypatch.setattr(tasks, "run_async", fake_run_async)
    result = task()
    assert result == stats
    assert task_tracking._task_detail((), {}, result) == {"result": stats}


# ── NVD backfill time budget ────────────────────────────────────────


class _Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


@pytest.fixture
def nvd_backfill(db_session, worker_session, monkeypatch):
    import app.services.system_settings as ss
    from app.intelligence import cve as cve_mod

    async def fake_setting(key, db=None):
        return "test-key"

    clock = _Clock()
    looked_up: list[str] = []

    async def fake_enrich(cve_id, gateway, api_key=None):
        looked_up.append(cve_id)
        clock.now += 400  # a slow NVD: two lookups spend the 780s budget
        return {"description": f"{cve_id} described", "cvss_score": 7.5, "severity": "HIGH"}

    monkeypatch.setattr(ss, "get_setting", fake_setting)
    monkeypatch.setattr(cve_mod, "enrich_from_nvd", fake_enrich)
    monkeypatch.setattr(tasks, "time", clock)

    rows = [CVE(cve_id=f"CVE-2026-6000{i}", nvd_data={}) for i in range(5)]
    db_session.add_all(rows)
    return rows, looked_up


async def test_nvd_backfill_stops_at_the_time_budget(db_session, nvd_backfill):
    rows, looked_up = nvd_backfill
    await db_session.flush()

    stats = await tasks._run_cve_nvd_backfill()

    assert looked_up == ["CVE-2026-60000", "CVE-2026-60001"]
    assert stats["stopped"] == "out_of_time"
    assert stats["enriched"] == 2
    assert stats["pending"] == 5
    for row in rows[:2]:
        await db_session.refresh(row)
        assert row.description == f"{row.cve_id} described"
    await db_session.refresh(rows[2])
    assert rows[2].description is None  # tomorrow's run


async def test_nvd_backfill_loads_only_what_fits_the_budget(db_session, nvd_backfill, monkeypatch):
    rows, looked_up = nvd_backfill
    await db_session.flush()
    monkeypatch.setattr(tasks, "_per_run", lambda gateway, seconds: 2)  # room for 2 lookups at the source's rate
    monkeypatch.setattr(tasks.time, "monotonic", lambda: 0.0)

    stats = await tasks._run_cve_nvd_backfill()

    assert stats["total"] == 2
    assert stats["pending"] == 5
    assert looked_up == ["CVE-2026-60000", "CVE-2026-60001"]
    assert stats["stopped"] is None


async def test_nvd_backfill_puts_cves_nothing_has_filled_first(db_session, worker_session, monkeypatch):
    """Within what one run can look up, a CVE with no score or description
    goes before one another source already filled, KEV first among them."""
    import app.services.system_settings as ss
    from app.intelligence import cve as cve_mod

    looked_up: list[str] = []

    async def fake_setting(key, db=None):
        return None

    async def fake_enrich(cve_id, gateway, api_key=None):
        looked_up.append(cve_id)
        return None

    monkeypatch.setattr(ss, "get_setting", fake_setting)
    monkeypatch.setattr(cve_mod, "enrich_from_nvd", fake_enrich)
    monkeypatch.setattr(tasks, "_per_run", lambda gateway, seconds: 3)  # room for 3 of the 4
    db_session.add_all(
        [
            CVE(cve_id="CVE-2026-61000", cvss_score=9.1, description="from the CNA record"),
            CVE(cve_id="CVE-2026-61001"),
            CVE(cve_id="CVE-2026-61002", is_kev=True),
            CVE(cve_id="CVE-2026-61003", cvss_score=5.0),  # scored but not described: still unfilled
        ]
    )
    await db_session.flush()

    stats = await tasks._run_cve_nvd_backfill()

    assert looked_up == ["CVE-2026-61002", "CVE-2026-61001", "CVE-2026-61003"]
    assert (stats["total"], stats["pending"]) == (3, 4)  # the filled one waits for tomorrow's run


def test_per_run_is_the_requests_a_budget_affords_at_the_sources_rate():
    from app.enrichment.gateway import SourceGateway

    gateway = SourceGateway("nvd", {"requests_per_period": 5, "period_seconds": 30})
    # The tokens that refill over the budget, plus the full bucket the run starts with.
    assert tasks._per_run(gateway, 780) == 130 + 5
    assert tasks._per_run(gateway, 0) == 5


# ── NVD refresh: change windows ─────────────────────────────────────


async def test_nvd_refresh_applies_the_records_nvd_changed_since_the_last_window(
    db_session, worker_session, monkeypatch
):
    """One query per page of changed records, not one per CVE: only the CVEs
    IntelFeed holds are applied, and the window ends where this one did."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    import app.services.system_settings as ss
    from app.intelligence import cve as cve_mod
    from app.models.enrichment import EnrichmentSource

    async def fake_setting(key, db=None):
        return "test-key"

    windows: list[tuple] = []
    pages = {
        0: [{"cvss_score": 9.1, "severity": "CRITICAL", "nvd_data": {"id": "CVE-2026-61001"}}],
        1: [{"cvss_score": 5.0, "severity": "MEDIUM", "nvd_data": {"id": "CVE-2026-69999"}}],  # not ours
    }

    async def fake_changes(start, end, gateway, api_key=None, start_index=0):
        windows.append((start, end, start_index))
        return pages[start_index], 2

    monkeypatch.setattr(ss, "get_setting", fake_setting)
    monkeypatch.setattr(cve_mod, "fetch_nvd_changes", fake_changes)

    source = (
        await db_session.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "nvd"))
    ).scalar_one_or_none() or EnrichmentSource(source_type="nvd", display_name="NVD")
    source.is_enabled = True
    last = datetime.now(UTC) - timedelta(hours=3)
    source.last_synced_at = last
    db_session.add(source)
    ours = CVE(cve_id="CVE-2026-61001", nvd_data={"id": "CVE-2026-61001"})
    db_session.add(ours)
    await db_session.flush()

    stats = await tasks._run_cve_nvd_refresh()

    assert [(w[0], w[2]) for w in windows] == [(last, 0), (last, 1)]
    assert stats["pages"] == 2 and stats["total"] == 2
    assert (stats["fetched"], stats["checked"], stats["stopped"]) == (1, 1, None)
    await db_session.refresh(ours)
    await db_session.refresh(source)
    assert float(ours.cvss_score) == 9.1
    assert source.last_synced_at == windows[0][1]


async def test_nvd_refresh_keeps_the_window_start_when_it_stops(db_session, worker_session, monkeypatch):
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    import app.services.system_settings as ss
    from app.enrichment.gateway import RateLimited
    from app.intelligence import cve as cve_mod
    from app.models.enrichment import EnrichmentSource

    async def fake_setting(key, db=None):
        return None

    async def refused(start, end, gateway, api_key=None, start_index=0):
        raise RateLimited("nvd", 30)

    monkeypatch.setattr(ss, "get_setting", fake_setting)
    monkeypatch.setattr(cve_mod, "fetch_nvd_changes", refused)
    source = (
        await db_session.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "nvd"))
    ).scalar_one_or_none() or EnrichmentSource(source_type="nvd", display_name="NVD")
    source.is_enabled = True
    # Further back than NVD allows: the window is clipped to 120 days.
    source.last_synced_at = datetime.now(UTC) - timedelta(days=400)
    db_session.add(source)
    await db_session.flush()
    before = source.last_synced_at

    stats = await tasks._run_cve_nvd_refresh()

    assert stats["stopped"] == "rate_limited"
    assert datetime.fromisoformat(stats["since"]) > datetime.now(UTC) - timedelta(days=121)
    await db_session.refresh(source)
    assert source.last_synced_at == before


# ── Malpedia batched commits ────────────────────────────────────────


def _malpedia_client(families: dict, actors: dict) -> AsyncMock:
    def get(url):
        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.json.return_value = families if url.endswith("/families") else actors
        return response

    client = AsyncMock()
    client.get.side_effect = get
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    return client


async def test_malpedia_commits_in_batches(db_session, worker_session, monkeypatch):
    monkeypatch.setattr(tasks, "_MALPEDIA_COMMIT_EVERY", 2)
    malware = [MalwareFamily(name=f"Batchfam{i}") for i in range(5)]
    malware[0].description = "Analyst-written"
    actor = ThreatActor(name="Batch Spider")
    db_session.add_all([*malware, actor])
    await db_session.flush()

    families = {
        f"win.batchfam{i}": {
            "common_name": f"Batchfam{i}",
            "alt_names": ["BatchAlias" + str(i)],
            "description": "From Malpedia",
        }
        for i in range(5)
    }
    families["win.unknown"] = {"common_name": "NoSuchFamily"}
    actors = {"Batch Spider": {"description": "Actor from Malpedia", "meta": {"synonyms": ["BatchSpiderAlias"]}}}

    commits = 0
    real_commit = db_session.commit

    async def counting_commit():
        nonlocal commits
        commits += 1
        await real_commit()

    monkeypatch.setattr(db_session, "commit", counting_commit)
    with patch("httpx.AsyncClient", return_value=_malpedia_client(families, actors)):
        stats = await tasks._run_malpedia_sync()

    # 6 updated entities, 2 per batch: two mid-run commits plus the final one,
    # after the commit source_job's pause sync makes before the body runs.
    assert stats["families_updated"] == 5
    assert stats["actors_updated"] == 1
    assert commits == 1 + 3

    for row in malware:
        await db_session.refresh(row)
        assert row.malpedia_url.endswith(f"/win.{row.name.lower()}")
    assert malware[0].description == "Analyst-written"  # fill blanks only
    assert malware[1].description == "From Malpedia"
    assert malware[1].aliases == ["BatchAlias1"]
    await db_session.refresh(actor)
    assert actor.description == "Actor from Malpedia"
    assert actor.aliases == ["BatchSpiderAlias"]


# ── Idle dispatcher ticks ───────────────────────────────────────────


@pytest.mark.parametrize(
    ("task_name", "retval", "recorded"),
    [
        ("app.workers.enrichment_dispatch_tasks.dispatch_enrichment_jobs", {}, False),
        ("app.workers.enrichment_dispatch_tasks.dispatch_enrichment_jobs", {"success": 3}, True),
        ("app.workers.enrichment_tasks.run_epss_bulk_sync", {}, True),
    ],
)
def test_idle_dispatcher_ticks_are_not_recorded(task_name, retval, recorded, monkeypatch):
    """The dispatcher runs every 30s; only ticks that did something reach job_runs."""
    calls = []
    monkeypatch.setattr(task_tracking, "_record_run", lambda *a, **k: calls.append(a))
    task = MagicMock()
    task.name = task_name
    task.request = MagicMock(spec=[])
    task_tracking._job_run_postrun(task_id="t1", task=task, state="SUCCESS", args=(), kwargs={}, retval=retval)
    assert bool(calls) is recorded


# ── Wikipedia: a miss is an answer too ──────────────────────────────


async def test_a_wikipedia_miss_is_stored_for_a_month(db_session):
    vendor = Vendor(name="Nowhere Systems")
    db_session.add(vendor)
    await db_session.flush()

    await tasks._wikipedia_not_found(db_session, "vendor", vendor.id, {}, "not_found")

    row = (
        await db_session.execute(
            select(EnrichmentResult).where(
                EnrichmentResult.entity_type == "vendor",
                EnrichmentResult.entity_id == vendor.id,
                EnrichmentResult.source_type == "wikipedia",
            )
        )
    ).scalar_one()
    assert row.parsed_data == {"found": False}
    assert row.raw_response == {"via": "wikipedia-bulk-sync", "status": "not_found"}
    assert timedelta(days=29) < row.expires_at - datetime.now(UTC) < timedelta(days=31)
    await db_session.refresh(vendor)
    assert vendor.wikipedia_content is None
