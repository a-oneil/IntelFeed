"""Scheduled enrichment jobs finish inside their limits and report what they did."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import app.workers.enrichment_tasks as tasks
from app.models.cve import CVE
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import ThreatActor
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
        return "test-key"  # keyed pacing: 0.7s between calls

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
    monkeypatch.setattr(tasks, "_NVD_BACKFILL_BUDGET_S", 2)  # room for 2 lookups at 0.7s
    monkeypatch.setattr(tasks.time, "monotonic", lambda: 0.0)

    stats = await tasks._run_cve_nvd_backfill()

    assert stats["total"] == 2
    assert stats["pending"] == 5
    assert looked_up == ["CVE-2026-60000", "CVE-2026-60001"]
    assert stats["stopped"] is None


# ── NVD refresh selection ───────────────────────────────────────────


async def test_nvd_refresh_selects_by_its_own_stamp_not_updated_at(db_session, worker_session, monkeypatch):
    """EPSS bumps updated_at on nearly every CVE daily, so staleness must come
    from the refresh stamp inside nvd_data."""
    from datetime import UTC, datetime, timedelta

    import app.services.system_settings as ss
    from app.intelligence import cve as cve_mod

    async def fake_setting(key, db=None):
        return "test-key"

    looked_up: list[str] = []

    async def fake_enrich(cve_id, gateway, api_key=None):
        looked_up.append(cve_id)
        if cve_id == "CVE-2026-61002":
            return None  # NVD has nothing this time
        return {"cvss_score": 9.1, "severity": "CRITICAL", "nvd_data": {"id": cve_id}}

    monkeypatch.setattr(ss, "get_setting", fake_setting)
    monkeypatch.setattr(cve_mod, "enrich_from_nvd", fake_enrich)
    monkeypatch.setattr("asyncio.sleep", AsyncMock())

    now = datetime.now(UTC)
    never = CVE(cve_id="CVE-2026-61001", nvd_data={"id": "CVE-2026-61001"}, updated_at=now)
    stale = CVE(
        cve_id="CVE-2026-61002",
        nvd_data={"id": "CVE-2026-61002", "_refreshed_at": (now - timedelta(days=10)).isoformat()},
        updated_at=now,
    )
    fresh = CVE(
        cve_id="CVE-2026-61003",
        nvd_data={"id": "CVE-2026-61003", "_refreshed_at": (now - timedelta(days=1)).isoformat()},
        updated_at=now - timedelta(days=30),
    )
    no_record = CVE(cve_id="CVE-2026-61004", nvd_data={}, updated_at=now - timedelta(days=30))
    db_session.add_all([never, stale, fresh, no_record])
    await db_session.flush()

    stats = await tasks._run_cve_nvd_refresh()

    assert looked_up == ["CVE-2026-61001", "CVE-2026-61002"]  # never-checked first
    assert stats == {"checked": 1, "score_changes": 0, "failed": 1, "total": 2, "stopped": None}
    for row in (never, stale):
        await db_session.refresh(row)
        assert row.nvd_data["_refreshed_at"] > (now - timedelta(minutes=1)).isoformat()
    assert float(never.cvss_score) == 9.1


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

    # 6 updated entities, 2 per batch: two mid-run commits plus the final one
    assert stats["families_updated"] == 5
    assert stats["actors_updated"] == 1
    assert commits == 3

    for row in malware:
        await db_session.refresh(row)
        assert row.malpedia_url.endswith(f"/win.{row.name.lower()}")
    assert malware[0].description == "Analyst-written"  # fill blanks only
    assert malware[1].description == "From Malpedia"
    assert malware[1].aliases == ["BatchAlias1"]
    await db_session.refresh(actor)
    assert actor.description == "Actor from Malpedia"
    assert actor.aliases == ["BatchSpiderAlias"]
