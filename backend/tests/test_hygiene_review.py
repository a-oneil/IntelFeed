"""Tests for the AI hygiene-proposal reviewer (workers/hygiene_review_tasks.py
+ the review endpoints in api/hygiene.py)."""

from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import ThreatActor
from app.workers.hygiene_review_tasks import _render_proposals_block, collect_pending_proposals


@pytest_asyncio.fixture
async def entry(db_session: AsyncSession) -> Entry:
    feed = Feed(title="Test Feed", url="https://example.com/feed.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    row = Entry(
        feed_id=feed.id,
        title="LockBit resurfaces",
        content_text="LockBit claimed a new victim.",
        summary="Ransomware coverage.",
    )
    db_session.add(row)
    await db_session.flush()
    return row


def _advisory(entry: Entry, actor: ThreatActor, review: str | None = None) -> EntityLinkValidationLog:
    return EntityLinkValidationLog(
        entry_id=entry.id,
        entity_type="malware",
        entity_id=actor.id,
        entity_name_snapshot=actor.name,
        action="needs_reclassification",
        reason="Articles cover the group, not a binary",
        suggested_entity_type="threat_actor",
        original_matched_names=["LockBit"],
        review_decision=review,
    )


def _alias_proposal(actor: ThreatActor, review: str | None = None) -> EntityMaintenanceLog:
    return EntityMaintenanceLog(
        entity_type="threat_actor",
        entity_id=actor.id,
        action="alias_collision",
        mode="shadow",
        before={"entity": {"id": str(actor.id), "name": actor.name, "aliases": list(actor.aliases or [])}},
        after={"bad_alias": actor.name, "kind": "alias_equals_canonical"},
        reasoning=f"Alias '{actor.name}' is identical to canonical name.",
        applied=False,
        review_decision=review,
    )


def _merge_proposal(review: str | None = None) -> EntityMaintenanceLog:
    """A merge_cluster_summary shadow proposal referencing (deliberately fake)
    ids — enough to be counted / fetched by the bulk-apply query without
    requiring real entities."""
    import uuid as _uuid

    return EntityMaintenanceLog(
        entity_type="threat_actor",
        entity_id=None,
        action="merge_cluster_summary",
        mode="shadow",
        before={"cluster_members": []},
        after={
            "merges": [{"source_id": str(_uuid.uuid4()), "target_id": str(_uuid.uuid4())}],
            "reclassifies": [],
        },
        reasoning="cluster",
        applied=False,
        review_decision=review,
    )


@pytest.mark.asyncio
async def test_collect_pending_proposals_shapes_and_skips_reviewed(db_session: AsyncSession, entry: Entry):
    actor = ThreatActor(name="LockBit", aliases=["LockBit", "ABCD Ransomware"], article_count=3)
    db_session.add(actor)
    await db_session.flush()

    pending_advisory = _advisory(entry, actor)
    reviewed_advisory = _advisory(entry, actor, review="approve")
    pending_maint = _alias_proposal(actor)
    db_session.add_all([pending_advisory, reviewed_advisory, pending_maint])
    await db_session.flush()

    items = await collect_pending_proposals(db_session)
    ids = {i["proposal_id"] for i in items}

    assert f"link_validator:{pending_advisory.id}" in ids
    assert f"entity_maintenance:{pending_maint.id}" in ids
    # Already-reviewed rows must not be re-sent.
    assert f"link_validator:{reviewed_advisory.id}" not in ids

    by_id = {i["proposal_id"]: i for i in items}
    adv = by_id[f"link_validator:{pending_advisory.id}"]
    assert adv["kind"] == "needs_reclassification"
    assert adv["context"]["suggested_type"] == "threat_actor"
    assert "LockBit" in adv["summary"]

    maint = by_id[f"entity_maintenance:{pending_maint.id}"]
    assert maint["kind"] == "alias_collision"
    assert maint["context"]["bad_alias"] == "LockBit"

    # The rendered block carries every proposal_id so the model can echo them.
    block = _render_proposals_block(items)
    for pid in ids & {i["proposal_id"] for i in items}:
        assert pid in block


@pytest.mark.asyncio
async def test_stats_include_review_counts(client, admin_headers, db_session: AsyncSession, entry: Entry):
    actor = ThreatActor(name="LockBit", article_count=3)
    db_session.add(actor)
    await db_session.flush()
    db_session.add_all(
        [
            _advisory(entry, actor, review="approve"),
            _advisory(entry, actor, review="reject"),
            _advisory(entry, actor),
            _alias_proposal(actor, review="approve"),
        ]
    )
    await db_session.flush()

    # One approved + one rejected + one unreviewed merge cluster too.
    db_session.add_all([_merge_proposal("approve"), _merge_proposal("reject"), _merge_proposal()])
    await db_session.flush()

    resp = await client.get("/api/admin/hygiene/stats", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["ai_review_approved"] == 3  # 2 advisories + 1 merge
    assert data["ai_review_rejected"] == 2  # 1 advisory + 1 merge
    assert data["ai_review_unsure"] == 0
    assert data["ai_review_unreviewed"] == 2  # 1 advisory + 1 merge
    # Bulk-apply button counts exclude AI-rejected rows (approve + unreviewed only).
    assert data["pending_advisories"] == 2  # approve + null, reject excluded
    assert data["shadow_proposals"] == 2  # approve + null, reject excluded


@pytest.mark.asyncio
async def test_feed_review_filter_and_fields(client, admin_headers, db_session: AsyncSession, entry: Entry):
    actor = ThreatActor(name="LockBit", article_count=3)
    db_session.add(actor)
    await db_session.flush()
    approved = _alias_proposal(actor, review="approve")
    approved.review_reason = "Duplicate of canonical name"
    db_session.add_all([approved, _alias_proposal(actor), _advisory(entry, actor, review="reject")])
    await db_session.flush()

    resp = await client.get(
        "/api/admin/hygiene/feed",
        params={"review": "approve"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    rows = resp.json()["rows"]
    assert len(rows) == 1
    assert rows[0]["id"] == f"entity_maintenance:{approved.id}"
    assert rows[0]["review_decision"] == "approve"
    assert rows[0]["review_reason"] == "Duplicate of canonical name"


@pytest.mark.asyncio
async def test_apply_ai_approved_applies_and_dismisses(client, admin_headers, db_session: AsyncSession, entry: Entry):
    actor = ThreatActor(name="LockBit", aliases=["LockBit", "ABCD Ransomware"], article_count=3)
    db_session.add(actor)
    await db_session.flush()

    approved = _alias_proposal(actor, review="approve")
    rejected = _alias_proposal(actor, review="reject")
    unreviewed = _advisory(entry, actor)
    db_session.add_all([approved, rejected, unreviewed])
    await db_session.flush()

    resp = await client.post(
        "/api/admin/hygiene/apply-ai-approved",
        json={"dismiss_rejected": True},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["applied"] == 1
    assert data["dismissed_rejected"] == 1
    assert data["failed"] == 0

    await db_session.refresh(actor)
    assert "LockBit" not in (actor.aliases or [])
    assert "ABCD Ransomware" in (actor.aliases or [])

    await db_session.refresh(approved)
    assert approved.applied is True
    # Rejected proposal was deleted; unreviewed advisory untouched.
    gone = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.id == rejected.id))
    ).scalar_one_or_none()
    assert gone is None
    still_there = (
        await db_session.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.id == unreviewed.id))
    ).scalar_one_or_none()
    assert still_there is not None


def _malware_advisory(entry: Entry, mal: MalwareFamily, review: str | None = None) -> EntityLinkValidationLog:
    """A needs_reclassification advisory whose source entity actually exists as
    its labelled type, so the apply path doesn't short-circuit it as 'gone'."""
    return EntityLinkValidationLog(
        entry_id=entry.id,
        entity_type="malware",
        entity_id=mal.id,
        entity_name_snapshot=mal.name,
        action="needs_reclassification",
        reason="Articles cover the group, not a binary",
        suggested_entity_type="threat_actor",
        original_matched_names=[mal.name],
        review_decision=review,
    )


@pytest.mark.asyncio
async def test_bulk_apply_advisories_skips_ai_rejected(client, admin_headers, db_session: AsyncSession, entry: Entry):
    """The blind bulk button (exclude_rejected=true) must not even fetch rejected
    advisories; per-row apply (exclude_rejected=false) still can."""
    keep = MalwareFamily(name="KeepMal", article_count=3)
    drop = MalwareFamily(name="DropMal", article_count=3)
    db_session.add_all([keep, drop])
    await db_session.flush()
    db_session.add_all([_malware_advisory(entry, keep), _malware_advisory(entry, drop, review="reject")])
    await db_session.flush()

    # Bulk button: shadow mode so we assert on the fetched set without mutating.
    resp = await client.post(
        "/api/admin/hygiene/apply-reclassify-advisories",
        json={"mode": "shadow", "exclude_rejected": True},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["advisories_considered"] == 1  # rejected one filtered out

    # Override path: rejected included when the flag is off.
    resp = await client.post(
        "/api/admin/hygiene/apply-reclassify-advisories",
        json={"mode": "shadow", "exclude_rejected": False},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["advisories_considered"] == 2


@pytest.mark.asyncio
async def test_bulk_apply_all_merges_skips_ai_rejected(client, admin_headers, db_session: AsyncSession):
    """apply-all for merge clusters is bulk-only, so it unconditionally skips
    AI-rejected clusters — they aren't processed and stay unapplied."""
    rejected = _merge_proposal("reject")
    db_session.add(rejected)
    await db_session.flush()

    resp = await client.post("/api/entity-maintenance/log/apply-all", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["rows_processed"] == 0
    assert data["rows_skipped"] == 0  # filtered by the query, never fetched

    await db_session.refresh(rejected)
    assert rejected.applied is False
