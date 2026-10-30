"""The catalogue-wide duplicate review.

- Candidate pairs come from a similar name, a shared alias or shared articles,
  minus pairs an analyst settled or the review judged recently.
- A "same" verdict becomes an adjudication_merge proposal (loser → keeper)
  that the Review queue can apply with no article behind it.
- "different" / "unsure" is remembered as merge_review_distinct for the retry
  window; dismissing a filed merge marks the pair not-duplicate for good.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, update

from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entry import Entry
from app.models.proposal_dismissal import KIND_NOT_DUPLICATE, ProposalDismissal
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.services.entity_merge_review import (
    ACTION_DISTINCT,
    ORIGIN,
    file_verdicts,
    find_merge_candidates,
    pairs_block,
)
from app.services.entry_adjudication import ACTION_MERGE

pytestmark = pytest.mark.asyncio


async def _seed_pair(db_session, feed, *, shared: int = 3):
    a = ThreatActor(name="APT29", aliases=["Cozy Bear"], article_count=20, description="Russian SVR group")
    b = ThreatActor(name="APT 29", aliases=["Cozy Bear"], article_count=2, created_via="ai_extraction")
    far = ThreatActor(name="Lazarus Group", aliases=["Hidden Cobra"], article_count=9)
    db_session.add_all([a, b, far])
    await db_session.flush()
    for _ in range(shared):
        e = Entry(feed_id=feed.id, title="SVR phishing wave", url=f"https://x/{uuid.uuid4()}", guid=str(uuid.uuid4()))
        db_session.add(e)
        await db_session.flush()
        db_session.add_all(
            [
                EntryThreatActor(entry_id=e.id, threat_actor_id=a.id),
                EntryThreatActor(entry_id=e.id, threat_actor_id=b.id),
            ]
        )
    await db_session.flush()
    return a, b, far


async def _find(db_session, **kw):
    return await find_merge_candidates(
        db_session, limit=kw.pop("limit", 10), min_similarity=kw.pop("min_similarity", 0.55), retry_days=30, **kw
    )


async def test_candidates_score_name_alias_and_shared_articles(db_session, test_feed):
    a, b, _far = await _seed_pair(db_session, test_feed)
    cands = await _find(db_session)
    assert [(c.a_id, c.b_id) for c in cands] == [tuple(sorted((a.id, b.id), key=str))] or len(cands) == 1
    c = cands[0]
    assert {c.a_id, c.b_id} == {a.id, b.id}
    assert c.alias_hit is True and c.similarity > 0.5 and c.shared_entries == 3
    assert c.pair_id == "p1" and c.a["name"] and c.b["name"]
    assert c.sample_titles == ["SVR phishing wave"] * 3

    block = pairs_block(cands)
    assert "APT29" in block and "APT 29" in block and "Cozy Bear" in block
    assert "3 shared articles" in block and "created by AI extraction" in block


async def test_same_verdict_files_a_merge_the_queue_can_apply(client, admin_headers, db_session, test_feed):
    a, b, _far = await _seed_pair(db_session, test_feed)
    cands = await _find(db_session)
    counts = await file_verdicts(
        db_session,
        cands,
        [{"pair_id": "p1", "verdict": "same", "keep": "", "confidence": "high", "reason": "same SVR group"}],
    )
    assert counts["proposed"] == 1
    row = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == ACTION_MERGE))
    ).scalar_one()
    # No keep given: the catalogue entry with more articles survives, the AI one goes.
    assert row.entity_id == b.id and row.after["target_id"] == str(a.id)
    assert row.after["merge_into"] == "APT29" and row.after["origin"] == ORIGIN and row.applied is False
    assert row.before["entity"]["name"] == "APT 29" and "entry_id" not in row.before

    # A pending merge takes the pair out of the next run's candidates.
    assert await _find(db_session) == []
    await db_session.commit()

    # The Review queue shows it as a Merge row...
    feed = (await client.get("/api/admin/hygiene/feed?pending=true", headers=admin_headers)).json()
    merge_rows = [r for r in feed["rows"] if r["action"] == "adjudication_merge"]
    assert len(merge_rows) == 1 and "duplicate review" in merge_rows[0]["subject"]
    assert merge_rows[0]["actions"] == ["apply", "dismiss"]
    groups = (await client.get("/api/admin/hygiene/review-groups", headers=admin_headers)).json()
    g = groups["groups"][0]
    assert g["name"] == "APT 29" and g["merge_into"][0]["name"] == "APT29"

    # ...and applies it with no article behind it.
    resp = await client.post(f"/api/admin/hygiene/adjudication/{row.id}/apply", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["applied"] is True
    assert await db_session.get(ThreatActor, b.id) is None
    keeper = await db_session.get(ThreatActor, a.id)
    await db_session.refresh(keeper)
    assert "APT 29" in keeper.aliases


async def test_different_is_remembered_for_the_retry_window(db_session, test_feed):
    a, b, _far = await _seed_pair(db_session, test_feed)
    cands = await _find(db_session)
    counts = await file_verdicts(
        db_session,
        cands,
        [
            {"pair_id": "p1", "verdict": "different", "keep": "", "confidence": "high", "reason": "two groups"},
            {"pair_id": "p9", "verdict": "same", "keep": "a", "confidence": "high", "reason": "unknown pair"},
        ],
    )
    assert counts == {"proposed": 0, "distinct": 1, "unsure": 0, "ignored": 1}
    row = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == ACTION_DISTINCT))
    ).scalar_one()
    assert row.applied is True and {row.entity_id, uuid.UUID(row.after["target_id"])} == {a.id, b.id}
    assert await _find(db_session) == []

    # Past the window the pair is asked again.
    await db_session.execute(
        update(EntityMaintenanceLog)
        .where(EntityMaintenanceLog.id == row.id)
        .values(created_at=datetime.now(UTC) - timedelta(days=40))
    )
    assert len(await _find(db_session)) == 1


async def test_low_confidence_same_is_only_remembered(db_session, test_feed):
    await _seed_pair(db_session, test_feed)
    cands = await _find(db_session)
    counts = await file_verdicts(
        db_session,
        cands,
        [{"pair_id": "p1", "verdict": "same", "keep": "a", "confidence": "low", "reason": "guess"}],
        min_confidence="medium",
    )
    assert counts["proposed"] == 0 and counts["unsure"] == 1


async def test_dismissing_a_filed_merge_marks_the_pair_not_duplicate(client, admin_headers, db_session, test_feed):
    a, b, _far = await _seed_pair(db_session, test_feed)
    cands = await _find(db_session)
    await file_verdicts(
        db_session, cands, [{"pair_id": "p1", "verdict": "same", "keep": "a", "confidence": "high", "reason": "r"}]
    )
    row = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == ACTION_MERGE))
    ).scalar_one()
    await db_session.commit()

    resp = await client.delete(f"/api/admin/hygiene/feed/entity_maintenance/{row.id}", headers=admin_headers)
    assert resp.status_code == 204, resp.text
    d = (
        await db_session.execute(select(ProposalDismissal).where(ProposalDismissal.kind == KIND_NOT_DUPLICATE))
    ).scalar_one()
    assert {d.entity_id, uuid.UUID(d.other_key)} == {a.id, b.id}
    assert await _find(db_session) == []


async def test_analyst_not_duplicate_keeps_the_pair_out(db_session, test_feed):
    from app.services.proposal_dismissals import mark_not_duplicate

    a, b, _far = await _seed_pair(db_session, test_feed)
    await mark_not_duplicate(db_session, "threat_actor", a.id, b.id, None)
    assert await _find(db_session) == []


async def test_scan_endpoint_dispatches_when_there_are_candidates(
    client, admin_headers, db_session, test_feed, monkeypatch
):
    from app.workers import entity_maintenance_tasks as tasks

    sent: list[dict] = []
    monkeypatch.setattr(tasks.review_duplicate_entities, "apply_async", lambda **kw: sent.append(kw))
    resp = await client.post("/api/admin/hygiene/scan-duplicates", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"dispatched": False, "candidates": 0} and sent == []

    await _seed_pair(db_session, test_feed)
    await db_session.commit()
    resp = await client.post("/api/admin/hygiene/scan-duplicates", headers=admin_headers)
    assert resp.json() == {"dispatched": True, "candidates": 1}
    assert sent == [{"queue": "ai"}]
