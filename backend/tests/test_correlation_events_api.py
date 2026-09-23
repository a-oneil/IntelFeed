"""Tests for the grouped correlation events API at /api/intelligence/events/grouped."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.correlation_event import CorrelationEventRecord


def _record(label: str, created_at: datetime) -> CorrelationEventRecord:
    return CorrelationEventRecord(
        event_type="new_ttp_for_known_actor",
        entry_id=None,
        source_entity_type="ttp",
        source_entity_id=uuid.uuid4(),
        source_entity_label=label,
        related_entity_type="threat_actor",
        related_entity_id=uuid.uuid4(),
        related_entity_label="APT29",
        context=f"{label} seen alongside APT29",
        created_at=created_at,
    )


@pytest_asyncio.fixture
async def aged_events(db_session: AsyncSession) -> None:
    """Three events spread across the last month, one per bucket."""
    now = datetime.now(UTC)
    db_session.add_all(
        [
            _record("fresh", now - timedelta(hours=2)),
            _record("recent", now - timedelta(days=3)),
            _record("old", now - timedelta(days=25)),
        ]
    )
    await db_session.flush()


async def _labels(client: AsyncClient, headers: dict, **params) -> tuple[list[str], int]:
    resp = await client.get("/api/intelligence/events/grouped", headers=headers, params=params)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    labels = [ev["source_entity_label"] for g in body["groups"] for ev in g["events"]]
    return labels, body["total"]


@pytest.mark.asyncio
async def test_no_bounds_returns_everything(client: AsyncClient, auth_headers: dict, aged_events):
    labels, total = await _labels(client, auth_headers)
    assert set(labels) == {"fresh", "recent", "old"}
    assert total == 3


@pytest.mark.asyncio
async def test_since_shorthand_filters_events_and_total(client: AsyncClient, auth_headers: dict, aged_events):
    """The category totals track the window, not the all-time count."""
    labels, total = await _labels(client, auth_headers, since="24h")
    assert labels == ["fresh"]
    assert total == 1

    labels, total = await _labels(client, auth_headers, since="7d")
    assert set(labels) == {"fresh", "recent"}
    assert total == 2


@pytest.mark.asyncio
async def test_until_bounds_the_other_end(client: AsyncClient, auth_headers: dict, aged_events):
    cutoff = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    labels, total = await _labels(client, auth_headers, until=cutoff)
    assert set(labels) == {"recent", "old"}
    assert total == 2


@pytest.mark.asyncio
async def test_since_and_until_select_a_window(client: AsyncClient, auth_headers: dict, aged_events):
    now = datetime.now(UTC)
    labels, total = await _labels(
        client,
        auth_headers,
        since=(now - timedelta(days=7)).isoformat(),
        until=(now - timedelta(days=1)).isoformat(),
    )
    assert labels == ["recent"]
    assert total == 1


@pytest.mark.asyncio
async def test_naive_iso_bound_is_read_as_utc(client: AsyncClient, auth_headers: dict, aged_events):
    """A bare date (what the widget's custom range sends) must still compare
    cleanly against the timezone-aware created_at column."""
    naive = (datetime.now(UTC) - timedelta(days=1)).replace(tzinfo=None).isoformat()
    labels, total = await _labels(client, auth_headers, since=naive)
    assert labels == ["fresh"]
    assert total == 1


@pytest.mark.asyncio
async def test_unparseable_bound_is_ignored(client: AsyncClient, auth_headers: dict, aged_events):
    labels, total = await _labels(client, auth_headers, since="not-a-date")
    assert set(labels) == {"fresh", "recent", "old"}
    assert total == 3
