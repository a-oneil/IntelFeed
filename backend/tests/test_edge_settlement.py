"""An edge's verdict follows from its per-article reviews (edge_settlement)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.entity_relationships import unreviewed_relationship_condition
from app.intelligence.correlation import _get_manual_relationships
from app.models.entity_relationship import EntityRelationship, RelationshipReview
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.threat_actor import ThreatActor
from app.models.tool import Tool
from app.services import edge_settlement as es
from app.services.entry_adjudication import _demote_edge


async def _feed(db: AsyncSession) -> Feed:
    f = Feed(title=f"Feed {uuid.uuid4().hex[:6]}", url=f"https://settle.example/{uuid.uuid4()}", feed_type="rss")
    db.add(f)
    await db.flush()
    return f


async def _entry(db: AsyncSession, feed: Feed) -> Entry:
    e = Entry(
        feed_id=feed.id,
        guid=str(uuid.uuid4()),
        title="Warlock deploys Cobalt Strike",
        url=f"https://settle.example/{uuid.uuid4()}",
        published_at=datetime.now(UTC),
    )
    db.add(e)
    await db.flush()
    return e


async def _edge(db: AsyncSession, **kw) -> EntityRelationship:
    actor = ThreatActor(name=f"Warlock {uuid.uuid4().hex[:6]}")
    tool = Tool(name=f"Cobalt Strike {uuid.uuid4().hex[:6]}")
    db.add_all([actor, tool])
    await db.flush()
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=actor.id,
        target_type="tool",
        target_id=tool.id,
        relationship_type="uses",
        confidence=kw.pop("confidence", "probable"),
        source=kw.pop("source", "auto_extracted"),
        evidence_entry_ids=[],
        **kw,
    )
    db.add(edge)
    await db.flush()
    return edge


async def _keep(db, edge, entry, reviewer=es.ADJUDICATOR, at=None):
    row = await es.record_review(db, edge.id, reviewer=reviewer, verdict=es.KEEP, entry_id=entry.id, counted=True)
    if at:
        row.created_at = at
    await es.settle_edge(db, edge)
    return row


async def _in_lens(db, edge) -> bool:
    return (
        await db.execute(
            select(EntityRelationship.id).where(EntityRelationship.id == edge.id, unreviewed_relationship_condition())
        )
    ).scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_one_articles_demote_does_not_undo_anothers_keep(db_session: AsyncSession):
    feed = await _feed(db_session)
    a, b = await _entry(db_session, feed), await _entry(db_session, feed)
    edge = await _edge(db_session)
    await _keep(db_session, edge, a)
    assert edge.adjudication_verdict is None and await _in_lens(db_session, edge)  # one keep is not enough

    before = await _demote_edge(db_session, edge.id, "Warlock is not named with the tool here.", entry_id=b.id)
    assert before["verdict_after"] == es.DISPUTED
    assert edge.confidence == "probable"  # nothing lowered while articles disagree
    assert await _in_lens(db_session, edge)


@pytest.mark.asyncio
async def test_a_demote_nobody_disputes_hides_the_edge(db_session: AsyncSession):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    edge = await _edge(db_session)
    shown = await _get_manual_relationships(db_session, "threat_actor", edge.source_id)
    assert [r["relationship_id"] for r in shown] == [str(edge.id)]

    await _demote_edge(db_session, edge.id, "Warlock and the tool sit in a roundup.", entry_id=entry.id)
    assert edge.adjudication_verdict == es.COINCIDENTAL and edge.confidence == "possible"
    assert not await _in_lens(db_session, edge)
    assert await _get_manual_relationships(db_session, "threat_actor", edge.source_id) == []


@pytest.mark.asyncio
async def test_keeps_from_two_feeds_corroborate_and_echoes_do_not_count(db_session: AsyncSession):
    from app.models.ai_analysis import AIAnalysisRequest

    f1, f2 = await _feed(db_session), await _feed(db_session)
    a, b = await _entry(db_session, f1), await _entry(db_session, f1)
    echo = await _entry(db_session, f2)
    db_session.add(AIAnalysisRequest(entry_id=echo.id, status="reused_echo", custom_id=f"ea-{echo.id}"))
    await db_session.flush()
    edge = await _edge(db_session)
    for e in (a, b, echo):
        await _keep(db_session, edge, e)
    assert edge.adjudication_verdict is None  # the second feed's article was a repost

    await _keep(db_session, edge, await _entry(db_session, f2))
    assert edge.adjudication_verdict == es.CORROBORATED and edge.confidence == "confirmed"


@pytest.mark.asyncio
async def test_sweep_keep_settles_and_a_later_dissent_disputes(db_session: AsyncSession):
    feed = await _feed(db_session)
    a, b = await _entry(db_session, feed), await _entry(db_session, feed)
    edge = await _edge(db_session, source="co_occurrence", confidence="possible")
    await es.record_review(db_session, edge.id, reviewer=es.SWEEP, verdict=es.KEEP, entry_id=a.id, counted=True)
    await es.settle_edge(db_session, edge)
    assert edge.adjudication_verdict == es.KEPT and edge.confidence == "probable"
    assert not await _in_lens(db_session, edge)

    await _demote_edge(db_session, edge.id, "Warlock is only listed beside the tool.", entry_id=b.id)
    assert edge.adjudication_verdict == es.DISPUTED and await _in_lens(db_session, edge)


@pytest.mark.asyncio
async def test_an_earlier_dissent_is_settled_by_the_sweep(db_session: AsyncSession):
    feed = await _feed(db_session)
    a, b = await _entry(db_session, feed), await _entry(db_session, feed)
    edge = await _edge(db_session)
    await _keep(db_session, edge, a, at=datetime.now(UTC) - timedelta(hours=2))
    await _demote_edge(db_session, edge.id, "Warlock is absent.", entry_id=b.id)
    assert edge.adjudication_verdict == es.DISPUTED
    await es.record_review(db_session, edge.id, reviewer=es.SWEEP, verdict=es.KEEP, entry_id=a.id, counted=True)
    await es.settle_edge(db_session, edge)
    assert edge.adjudication_verdict == es.KEPT


@pytest.mark.asyncio
async def test_a_confirmed_edge_stands_until_disputed_and_an_old_demotion_until_kept(db_session: AsyncSession):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    confirmed = await _edge(db_session, adjudication_verdict=es.CORROBORATED, confidence="confirmed")
    await es.record_review(
        db_session, confirmed.id, reviewer=es.ADJUDICATOR, verdict=es.KEEP, entry_id=entry.id, counted=True
    )
    await es.settle_edge(db_session, confirmed)
    assert confirmed.adjudication_verdict == es.CORROBORATED

    demoted = await _edge(db_session, adjudication_verdict=es.COINCIDENTAL, confidence="possible")
    await _keep(db_session, demoted, entry)
    assert demoted.adjudication_verdict == es.DISPUTED


@pytest.mark.asyncio
async def test_only_an_analyst_demotes_a_confirmed_edge(db_session: AsyncSession):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    edge = await _edge(db_session, adjudication_verdict=es.CORROBORATED, confidence="confirmed")
    assert await _demote_edge(db_session, edge.id, "Warlock absent", entry_id=entry.id) is None
    await _demote_edge(db_session, edge.id, "Warlock absent", entry_id=entry.id, reviewer=es.ANALYST)
    assert edge.adjudication_verdict == es.COINCIDENTAL


@pytest.mark.asyncio
async def test_uncounted_reviews_settle_nothing(db_session: AsyncSession):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    edge = await _edge(db_session)
    await es.record_review(db_session, edge.id, reviewer=es.ADJUDICATOR, verdict=es.DEMOTE, entry_id=entry.id)
    await es.record_review(db_session, edge.id, reviewer=es.ADJUDICATOR, verdict=es.UNANSWERED, entry_id=entry.id)
    assert await es.settle_edge(db_session, edge) is None and edge.adjudication_verdict is None
    rows = (
        (await db_session.execute(select(RelationshipReview).where(RelationshipReview.relationship_id == edge.id)))
        .scalars()
        .all()
    )
    assert {r.verdict for r in rows} == {es.DEMOTE, es.UNANSWERED} and all(r.feed_id == feed.id for r in rows)
