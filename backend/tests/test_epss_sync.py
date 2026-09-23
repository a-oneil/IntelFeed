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
