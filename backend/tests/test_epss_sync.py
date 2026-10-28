"""EPSS bulk sync must upsert enrichment_results, not append (one row per CVE)."""

import gzip
from contextlib import asynccontextmanager
from datetime import UTC
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import func, select

from app.enrichment.results import upsert_enrichment_result
from app.models.cve import CVE
from app.models.enrichment import EnrichmentResult


def _epss_csv_response(rows: dict[str, tuple[float, float]]) -> MagicMock:
    lines = ["#model_version:v2023.03.01", "cve,epss,percentile"]
    lines += [f"{cve},{score},{pct}" for cve, (score, pct) in rows.items()]
    response = MagicMock()
    response.content = gzip.compress("\n".join(lines).encode())
    response.raise_for_status = MagicMock()
    return response


@pytest_asyncio.fixture
async def cves(db_session):
    rows = [CVE(cve_id="CVE-2024-0001"), CVE(cve_id="CVE-2024-0002")]
    db_session.add_all(rows)
    await db_session.flush()
    return rows


async def _run_sync_with(db_session, csv_rows):
    @asynccontextmanager
    async def fake_worker_session():
        yield db_session

    mock_client = AsyncMock()
    mock_client.get.return_value = _epss_csv_response(csv_rows)
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with (
        patch("app.workers.enrichment_tasks._get_worker_session", fake_worker_session),
        patch("httpx.AsyncClient", return_value=mock_client),
    ):
        from app.workers.enrichment_tasks import _run_epss_bulk_sync

        return await _run_epss_bulk_sync()


@pytest.mark.asyncio
async def test_epss_sync_twice_keeps_one_row_per_cve(db_session, cves):
    stats = await _run_sync_with(
        db_session,
        {"CVE-2024-0001": (0.10, 0.50), "CVE-2024-0002": (0.20, 0.60)},
    )
    assert stats["updated"] == 2

    # Second run with slightly changed scores (delta < 0.1: no event path)
    await _run_sync_with(
        db_session,
        {"CVE-2024-0001": (0.15, 0.55), "CVE-2024-0002": (0.22, 0.62)},
    )

    counts = (
        await db_session.execute(
            select(EnrichmentResult.entity_id, func.count())
            .where(EnrichmentResult.source_type == "epss")
            .group_by(EnrichmentResult.entity_id)
        )
    ).all()
    assert len(counts) == 2
    assert all(count == 1 for _, count in counts)

    # The single row reflects the latest sync, as does the CVE itself
    row = (
        await db_session.execute(
            select(EnrichmentResult).where(
                EnrichmentResult.source_type == "epss",
                EnrichmentResult.entity_id == cves[0].id,
            )
        )
    ).scalar_one()
    assert row.parsed_data["epss_score"] == 0.15
    await db_session.refresh(cves[0])
    assert cves[0].epss_score == 0.15


@pytest.mark.asyncio
async def test_epss_sync_inserts_row_for_new_cve(db_session, cves):
    await _run_sync_with(db_session, {"CVE-2024-0001": (0.10, 0.50)})

    total = (
        await db_session.execute(
            select(func.count()).select_from(EnrichmentResult).where(EnrichmentResult.source_type == "epss")
        )
    ).scalar_one()
    assert total == 1  # only the matched CVE got a row


@pytest.mark.asyncio
async def test_upsert_enrichment_result_helper(db_session, cves):
    from datetime import datetime, timedelta

    expires = datetime.now(UTC) + timedelta(hours=24)
    for payload in ({"poc_count": 1}, {"poc_count": 3}):
        await upsert_enrichment_result(
            db_session,
            entity_type="cve",
            entity_id=cves[0].id,
            source_type="github_poc",
            raw_response={},
            parsed_data=payload,
            expires_at=expires,
        )
        await db_session.flush()

    rows = (
        (await db_session.execute(select(EnrichmentResult).where(EnrichmentResult.source_type == "github_poc")))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].parsed_data["poc_count"] == 3


# ── Set-based update matches the per-row logic it replaced ──────────


def _expected_change(old: float | None, new: float) -> bool:
    """The per-CVE ORM rule the set-based UPDATE replaced."""
    return old is not None and new != old and (abs(new - old) >= 0.1 or old < 0.5 <= new)


@pytest.mark.asyncio
async def test_epss_set_based_update_matches_row_logic(db_session, monkeypatch):
    from datetime import datetime

    import app.workers.enrichment_tasks as tasks
    import app.workers.signal_tasks as signal_tasks
    from app.models.correlation_event import CorrelationEventRecord

    monkeypatch.setattr(tasks, "_EPSS_CHUNK_SIZE", 3)  # several chunks, several commits
    dispatched: list = []
    monkeypatch.setattr(signal_tasks, "dispatch_cve_rescore", dispatched.append)

    earlier = datetime(2026, 1, 1, tzinfo=UTC)
    # cve_id: (stored score, CSV score); a None CSV score = not in the CSV
    cases = {
        "CVE-2026-1001": (0.10, 0.25),  # jump >= 0.1, increase
        "CVE-2026-1002": (0.45, 0.52),  # crosses 0.5 on a small delta
        "CVE-2026-1003": (0.30, 0.35),  # small delta: no change event
        "CVE-2026-1004": (None, 0.90),  # first score: no change event
        "CVE-2026-1005": (0.80, 0.60),  # drop >= 0.1: event, no rescore
        "CVE-2026-1006": (0.52, 0.48),  # falls below 0.5 on a small delta
        "CVE-2026-1007": (0.50, 0.50),  # unchanged
        "CVE-2026-1008": (0.20, 0.30),  # 0.3 - 0.2 is just under 0.1 in floats
        "CVE-2026-1009": (0.20, None),  # unmatched: untouched
    }
    rows = {
        cve_id: CVE(
            cve_id=cve_id,
            epss_score=old,
            epss_percentile=0.5 if old is not None else None,
            epss_updated_at=earlier if old is not None else None,
            epss_previous_score=0.01,
            epss_changed_at=earlier,
        )
        for cve_id, (old, _) in cases.items()
    }
    db_session.add_all(rows.values())
    await db_session.flush()

    csv_rows = {cve_id: (new, 0.77) for cve_id, (_, new) in cases.items() if new is not None}
    csv_rows["CVE-2026-9999"] = (0.5, 0.5)  # scored by FIRST, unknown here
    stats = await _run_sync_with(db_session, csv_rows)

    assert stats["total_scores"] == 9
    assert stats["updated"] == 8

    significant = {}
    for cve_id, (old, new) in cases.items():
        row = rows[cve_id]
        await db_session.refresh(row)
        if new is None:
            assert (row.epss_score, row.epss_updated_at, row.epss_previous_score) == (old, earlier, 0.01)
            continue
        assert row.epss_score == new, cve_id
        assert row.epss_percentile == 0.77, cve_id
        assert row.epss_updated_at > earlier, cve_id
        if _expected_change(old, new):
            significant[row.id] = (old, new)
            assert row.epss_previous_score == old, cve_id
            assert row.epss_changed_at == row.epss_updated_at, cve_id
        else:
            assert row.epss_previous_score == 0.01, cve_id
            assert row.epss_changed_at == earlier, cve_id

    assert {c for c, row in rows.items() if row.id in significant} == {
        "CVE-2026-1001",
        "CVE-2026-1002",
        "CVE-2026-1005",
    }
    assert stats["score_changes"] == 3
    events = (
        (
            await db_session.execute(
                select(CorrelationEventRecord).where(CorrelationEventRecord.event_type == "cve_score_change")
            )
        )
        .scalars()
        .all()
    )
    assert {e.source_entity_id for e in events} == set(significant)
    assert all("EPSS score changed" in e.context for e in events)
    # Rescores go out for increases only
    assert sorted(dispatched) == sorted(i for i, (old, new) in significant.items() if new > old)
    assert len(dispatched) == 2

    # Every matched CVE has its one enrichment row, carrying the new score
    results = (
        await db_session.execute(
            select(EnrichmentResult.entity_id, EnrichmentResult.parsed_data).where(
                EnrichmentResult.source_type == "epss"
            )
        )
    ).all()
    matched = {rows[c].id: new for c, (_, new) in cases.items() if new is not None}
    assert {entity_id: data["epss_score"] for entity_id, data in results} == matched
