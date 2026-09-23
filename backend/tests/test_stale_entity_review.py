"""Tests for the weekly stale-entity review flagging sweep
(app/workers/maintenance.py::flag_stale_entities_once)."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entity_relationship import EntityRelationship
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import ThreatActor
from app.workers.maintenance import flag_stale_entities_once

OLD = datetime.now(UTC) - timedelta(days=200)
RECENT = datetime.now(UTC) - timedelta(days=5)


@pytest.mark.asyncio
async def test_flags_only_old_low_signal_entities(db_session: AsyncSession):
    stale = ThreatActor(name="One Hit Wonder", article_count=1, first_seen_at=OLD, last_seen_at=OLD)
    zero_articles = MalwareFamily(name="Ghost Family", article_count=0, first_seen_at=OLD, last_seen_at=OLD)
    recent = ThreatActor(name="Fresh Actor", article_count=1, first_seen_at=RECENT, last_seen_at=RECENT)
    busy = ThreatActor(name="Busy Actor", article_count=25, first_seen_at=OLD, last_seen_at=OLD)
    related = ThreatActor(name="Connected Actor", article_count=1, first_seen_at=OLD, last_seen_at=OLD)
    db_session.add_all([stale, zero_articles, recent, busy, related])
    await db_session.flush()

    db_session.add(
        EntityRelationship(
            source_type="threat_actor",
            source_id=related.id,
            target_type="malware",
            target_id=zero_articles.id,
            relationship_type="uses",
            confidence="possible",
        )
    )
    await db_session.flush()

    flagged = await flag_stale_entities_once(db_session)
    # 'related' and 'zero_articles' both participate in a relationship;
    # 'recent' is too new; 'busy' has too many articles. Only 'stale' remains.
    assert flagged == 1

    rows = (
        (
            await db_session.execute(
                select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == "stale_entity_review")
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    row = rows[0]
    assert row.entity_type == "threat_actor"
    assert row.entity_id == stale.id
    assert row.mode == "shadow"
    assert row.applied is False
    assert row.before["entity"]["name"] == "One Hit Wonder"
    assert row.after["article_count"] == 1
    assert row.after["age_days"] >= 199
    assert "review" in (row.reasoning or "")


@pytest.mark.asyncio
async def test_rerun_does_not_duplicate_flags(db_session: AsyncSession):
    stale = ThreatActor(name="One Hit Wonder", article_count=0, first_seen_at=OLD, last_seen_at=OLD)
    db_session.add(stale)
    await db_session.flush()

    first = await flag_stale_entities_once(db_session)
    second = await flag_stale_entities_once(db_session)
    assert first == 1
    assert second == 0

    rows = (
        (
            await db_session.execute(
                select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == "stale_entity_review")
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_covers_all_registered_entity_types(db_session: AsyncSession):
    from app.models.product import Product
    from app.models.tool import Tool
    from app.models.vendor import Vendor

    db_session.add_all(
        [
            ThreatActor(name="Stale Actor", article_count=0, first_seen_at=OLD, last_seen_at=OLD),
            MalwareFamily(name="Stale Malware", article_count=0, first_seen_at=OLD, last_seen_at=OLD),
            Tool(name="Stale Tool", article_count=0, first_seen_at=OLD, last_seen_at=OLD),
            Vendor(name="Stale Vendor", article_count=0, first_seen_at=OLD, last_seen_at=OLD),
            Product(name="Stale Product", article_count=0, first_seen_at=OLD, last_seen_at=OLD),
        ]
    )
    await db_session.flush()

    flagged = await flag_stale_entities_once(db_session)
    assert flagged == 5

    rows = (
        (
            await db_session.execute(
                select(EntityMaintenanceLog.entity_type).where(EntityMaintenanceLog.action == "stale_entity_review")
            )
        )
        .scalars()
        .all()
    )
    assert set(rows) == {"threat_actor", "malware", "tool", "vendor", "product"}
