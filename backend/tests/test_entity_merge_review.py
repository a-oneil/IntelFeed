"""The catalogue-wide duplicate review.

- Candidate pairs come from a similar name or a shared alias (shared articles
  are context and a tie-breaker, never a signal on their own), minus pairs an
  analyst settled or the review judged recently.
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


async def test_shared_articles_alone_never_make_a_pair(db_session, test_feed):
    """Two famous things reported together is the normal case, not a duplicate."""
    _a, _b, far = await _seed_pair(db_session, test_feed, shared=0)
    other = ThreatActor(name="Kimsuky", aliases=["Velvet Chollima"], article_count=4)
    db_session.add(other)
    await db_session.flush()
    for _ in range(5):
        e = Entry(feed_id=test_feed.id, title="DPRK roundup", url=f"https://x/{uuid.uuid4()}", guid=str(uuid.uuid4()))
        db_session.add(e)
        await db_session.flush()
        db_session.add_all(
            [
                EntryThreatActor(entry_id=e.id, threat_actor_id=far.id),
                EntryThreatActor(entry_id=e.id, threat_actor_id=other.id),
            ]
        )
    await db_session.flush()
    cands = await _find(db_session)
    assert {far.id, other.id} not in [{c.a_id, c.b_id} for c in cands]
    # The look-alike pair is still found, and its (zero) shared count is reported honestly.
    assert len(cands) == 1 and cands[0].shared_entries == 0 and "shared article" not in pairs_block(cands)


async def test_same_verdict_files_a_merge_the_queue_can_apply(client, admin_headers, db_session, test_feed):
    a, b, far = await _seed_pair(db_session, test_feed)
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
    # A second, competing proposal about the same loser (another target).
    db_session.add(
        EntityMaintenanceLog(
            entity_type="threat_actor",
            entity_id=b.id,
            action=ACTION_MERGE,
            mode="shadow",
            before={"entity": {"id": str(b.id), "name": "APT 29"}},
            after={"target_id": str(far.id), "target_type": "threat_actor", "merge_into": "Lazarus Group"},
            applied=False,
        )
    )
    await db_session.commit()

    # The Review queue shows it as a Merge row, under its own origin...
    feed = (await client.get("/api/admin/hygiene/feed?pending=true", headers=admin_headers)).json()
    merge_rows = [r for r in feed["rows"] if r["action"] == "adjudication_merge"]
    assert len(merge_rows) == 2
    ours = next(r for r in merge_rows if r["payload"]["log_id"] == str(row.id))
    assert "duplicate review" in ours["subject"] and ours["origin"] == "merge_review"
    assert ours["actions"] == ["apply", "dismiss"]
    only_review = (
        await client.get("/api/admin/hygiene/feed?pending=true&origin=merge_review", headers=admin_headers)
    ).json()
    assert [r["payload"]["log_id"] for r in only_review["rows"]] == [str(row.id)]
    only_stage = (
        await client.get("/api/admin/hygiene/feed?pending=true&origin=adjudicator", headers=admin_headers)
    ).json()
    assert str(row.id) not in {r["payload"]["log_id"] for r in only_stage["rows"]}
    groups = (await client.get("/api/admin/hygiene/review-groups", headers=admin_headers)).json()
    g = groups["groups"][0]
    assert g["name"] == "APT 29" and g["merge_into"][0]["name"] == "APT29" and g["origin"] == "mixed"
    assert [m["name"] for m in g["merge_into"]] == ["APT29", "Lazarus Group"]
    by_origin = (await client.get("/api/admin/hygiene/review-groups?origin=merge_review", headers=admin_headers)).json()
    assert by_origin["total"] == 1 and by_origin["groups"][0]["origin"] == "merge_review"
    assert by_origin["groups"][0]["proposals"] == 1
    assert (await client.get("/api/admin/hygiene/feed?origin=nightly", headers=admin_headers)).status_code == 400

    # ...and applies it with no article behind it. The loser is gone, so the
    # competing proposal about it is cleared too.
    resp = await client.post(f"/api/admin/hygiene/adjudication/{row.id}/apply", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["applied"] is True
    assert await db_session.get(ThreatActor, b.id) is None
    keeper = await db_session.get(ThreatActor, a.id)
    await db_session.refresh(keeper)
    assert "APT 29" in keeper.aliases
    left = (
        (
            await db_session.execute(
                select(EntityMaintenanceLog).where(
                    EntityMaintenanceLog.entity_id == b.id, EntityMaintenanceLog.applied.is_(False)
                )
            )
        )
        .scalars()
        .all()
    )
    assert left == []


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


async def test_low_confidence_same_is_only_remembered(client, admin_headers, db_session, test_feed):
    await _seed_pair(db_session, test_feed)
    cands = await _find(db_session)
    counts = await file_verdicts(
        db_session,
        cands,
        [{"pair_id": "p1", "verdict": "same", "keep": "a", "confidence": "low", "reason": "guess"}],
        min_confidence="medium",
    )
    assert counts["proposed"] == 0 and counts["unsure"] == 1
    row = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == ACTION_DISTINCT))
    ).scalar_one()
    # The row says what happened (unsure), and keeps the model's own word.
    assert row.after["verdict"] == "unsure" and row.after["model_verdict"] == "same"
    await db_session.commit()
    hist = (
        await client.get("/api/admin/hygiene/feed?mode=apply&action=merge_review_distinct", headers=admin_headers)
    ).json()
    assert hist["rows"][0]["subject"] in (
        "Unsure: APT29 vs APT 29 · duplicate review",
        "Unsure: APT 29 vs APT29 · duplicate review",
    )
    assert hist["rows"][0]["origin"] == "merge_review" and hist["rows"][0]["actions"] == []


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


@pytest.fixture
def private_lock_key(monkeypatch) -> str:
    """The review's one-run-at-a-time lock under a key of this test's own.
    The worker and the scan endpoint read ``LOCK_KEY`` from the service
    module at call time, so the shared dev Redis's real lock is never taken
    or released here."""
    from app.services import entity_merge_review

    key = f"intelfeed:test:{uuid.uuid4().hex}:merge_review:lock"
    monkeypatch.setattr(entity_merge_review, "LOCK_KEY", key)
    return key


async def test_scan_endpoint_only_dispatches(client, admin_headers, monkeypatch, private_lock_key):
    """The candidate search runs on the worker, never inside the request; the
    endpoint reads the worker's lock to tell a run in progress."""
    import redis

    from app.config import settings
    from app.workers import entity_maintenance_tasks as tasks

    sent: list[dict] = []
    monkeypatch.setattr(tasks.review_duplicate_entities, "apply_async", lambda **kw: sent.append(kw))
    resp = await client.post("/api/admin/hygiene/scan-duplicates", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"dispatched": True, "already_running": False} and sent == [{"queue": "ai"}]

    # A run in progress holds the lock: reported, not doubled.
    r = redis.from_url(settings.redis_url)
    try:
        r.set(private_lock_key, "1", ex=60)
        resp = await client.post("/api/admin/hygiene/scan-duplicates", headers=admin_headers)
    finally:
        r.delete(private_lock_key)
        r.close()
    assert resp.json() == {"dispatched": False, "already_running": True} and len(sent) == 1


def test_worker_runs_one_review_at_a_time(private_lock_key):
    import redis

    from app.config import settings
    from app.workers.entity_maintenance_tasks import review_duplicate_entities

    r = redis.from_url(settings.redis_url)
    try:
        assert r.set(private_lock_key, "1", nx=True, ex=60)
        assert review_duplicate_entities() == {"status": "locked"}
        assert r.exists(private_lock_key)  # the skipped run never releases the other run's lock
    finally:
        r.delete(private_lock_key)
        r.close()
