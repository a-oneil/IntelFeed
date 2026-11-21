"""How a machine-made relationship's verdict follows from its reviews.

Three reviewers judge an edge (``relationship_reviews.reviewer``):

* ``adjudicator`` — the per-article review (app/services/entry_adjudication.py)
  says whether *this* article states the claim;
* ``sweep`` — the edge review (app/services/relationship_sweep.py) reads every
  evidence article's passage at once and says whether any of them states it;
* ``analyst`` — Apply or Restore from Review.

Only ``counted`` rows settle an edge: apply mode, at or above the confidence
floor. ``settle_edge`` derives the verdict from them every time, so a keep
from one article never undoes a demote from another without saying so:

* the latest analyst row decides;
* else the latest sweep row is the base (``kept`` or ``coincidental``), and
  an article that disagrees after it makes the edge ``disputed``;
* else per article: demotes and no keeps → ``coincidental``; keeps and
  demotes → ``disputed``; keeps only → nothing yet (one article's keep is not
  enough to take a claim off the Review lens);
* any edge with no standing demote is ``corroborated`` once articles from two
  or more feeds (echoes excluded) have kept it, at
  ``relationship_evidence_promote_count`` articles.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entity_relationship import EntityRelationship, RelationshipReview

logger = logging.getLogger(__name__)

ADJUDICATOR = "adjudicator"
SWEEP = "sweep"
ANALYST = "analyst"

KEEP = "keep"
DEMOTE = "demote"
REVERB = "reverb"
UNANSWERED = "unanswered"
UNSURE = "unsure"

KEPT = "kept"
CORROBORATED = "corroborated"
DISPUTED = "disputed"
COINCIDENTAL = "coincidental"
# Verdicts the Review lens lists: nobody has settled these.
OPEN_VERDICTS = (DISPUTED,)
# Sources a reviewer may settle. Analyst edges and authority imports are not
# the machine's to judge.
SETTLEABLE_SOURCES = ("auto_extracted", "co_occurrence")

_CONF_RANK = {"possible": 0, "probable": 1, "confirmed": 2}


async def record_review(
    db: AsyncSession,
    edge_id: uuid.UUID,
    *,
    reviewer: str,
    verdict: str,
    entry_id: uuid.UUID | None = None,
    confidence: str | None = None,
    reason: str | None = None,
    quote: str | None = None,
    suggested_verb: str | None = None,
    flipped: bool = False,
    counted: bool = False,
    ai_result_id: uuid.UUID | None = None,
) -> RelationshipReview:
    from app.models.entry import Entry

    feed_id = None
    if entry_id is not None:
        feed_id = (await db.execute(select(Entry.feed_id).where(Entry.id == entry_id))).scalar_one_or_none()
    row = RelationshipReview(
        relationship_id=edge_id,
        entry_id=entry_id,
        feed_id=feed_id,
        reviewer=reviewer,
        verdict=verdict,
        confidence=confidence,
        reason=(reason or "")[:1000] or None,
        quote=(quote or "")[:1000] or None,
        suggested_verb=suggested_verb,
        flipped=flipped,
        counted=counted,
        ai_result_id=ai_result_id,
        created_at=datetime.now(UTC),
    )
    db.add(row)
    await db.flush()
    return row


async def _echo_entries(db: AsyncSession, entry_ids: set[uuid.UUID]) -> set[uuid.UUID]:
    """Articles whose analysis was copied from another article (a repost):
    the same text again, so no independent keep."""
    from app.models.ai_analysis import AIAnalysisRequest

    if not entry_ids:
        return set()
    rows = await db.execute(
        select(AIAnalysisRequest.entry_id).where(
            AIAnalysisRequest.entry_id.in_(entry_ids), AIAnalysisRequest.status == "reused_echo"
        )
    )
    return set(rows.scalars())


def _latest(rows: list[RelationshipReview]) -> RelationshipReview | None:
    return max(rows, key=lambda r: r.created_at) if rows else None


async def derive_verdict(db: AsyncSession, edge: EntityRelationship) -> str | None:
    """The verdict the edge's counted reviews add up to (see the module doc)."""
    from app.services.system_settings import get_setting

    rows = list(
        (
            await db.execute(
                select(RelationshipReview).where(
                    RelationshipReview.relationship_id == edge.id, RelationshipReview.counted.is_(True)
                )
            )
        ).scalars()
    )
    rows = [r for r in rows if r.verdict in (KEEP, DEMOTE)]
    if not rows:
        return edge.adjudication_verdict
    analyst = _latest([r for r in rows if r.reviewer == ANALYST])
    if analyst is not None:
        return KEPT if analyst.verdict == KEEP else COINCIDENTAL

    sweep = _latest([r for r in rows if r.reviewer == SWEEP])
    # Latest word per article.
    per_entry: dict[uuid.UUID, RelationshipReview] = {}
    for r in sorted((r for r in rows if r.reviewer == ADJUDICATOR and r.entry_id), key=lambda r: r.created_at):
        per_entry[r.entry_id] = r  # type: ignore[index]
    keeps = any(r.verdict == KEEP for r in per_entry.values())
    demotes = any(r.verdict == DEMOTE for r in per_entry.values())
    # A confirmation stands until an article disputes it, and a demotion from
    # before reviews were recorded (the nightly job) until one keeps it.
    if sweep is None and edge.adjudication_verdict == CORROBORATED:
        return DISPUTED if demotes else CORROBORATED
    if sweep is None and edge.adjudication_verdict == COINCIDENTAL and not demotes:
        return DISPUTED if keeps else COINCIDENTAL
    if sweep is not None:
        later = [r for r in per_entry.values() if r.created_at > sweep.created_at]
        base = KEPT if sweep.verdict == KEEP else COINCIDENTAL
        against = DEMOTE if base == KEPT else KEEP
        if any(r.verdict == against for r in later):
            return DISPUTED
        verdict: str | None = base
    else:
        if demotes:
            return DISPUTED if keeps else COINCIDENTAL
        verdict = None
    if verdict == COINCIDENTAL:
        return verdict

    # Corroboration: independent articles that each state the claim.
    keep_rows = [r for r in per_entry.values() if r.verdict == KEEP]
    if sweep is not None and sweep.verdict == KEEP and sweep.entry_id and sweep.entry_id not in per_entry:
        keep_rows.append(sweep)
    echoes = await _echo_entries(db, {r.entry_id for r in keep_rows if r.entry_id})
    independent = [r for r in keep_rows if r.entry_id not in echoes]
    threshold = max(1, int(await get_setting("relationship_evidence_promote_count", db) or 3))
    feeds = {r.feed_id for r in independent if r.feed_id}
    if len(independent) >= threshold and len(feeds) >= 2:
        return CORROBORATED
    return verdict


async def settle_edge(db: AsyncSession, edge: EntityRelationship) -> str | None:
    """Re-derive the edge's verdict from its reviews and move its confidence
    with it. Returns the new verdict when it changed, else None."""
    if edge.source not in SETTLEABLE_SOURCES:
        return None
    new = await derive_verdict(db, edge)
    old = edge.adjudication_verdict
    if new == old:
        return None
    edge.adjudication_verdict = new
    edge.adjudicated_at = datetime.now(UTC) if new else None
    if new == CORROBORATED:
        edge.confidence = "confirmed"
    elif new == COINCIDENTAL:
        edge.confidence = "possible"
    elif new == KEPT:
        # A claim a reviewer found stated is a report, not a signal.
        if _CONF_RANK.get(edge.confidence or "possible", 0) < _CONF_RANK["probable"]:
            edge.confidence = "probable"
    elif old == CORROBORATED and edge.confidence == "confirmed":
        edge.confidence = "probable"
    db.add(edge)
    await invalidate_edge(edge)
    return new


async def invalidate_edge(edge: EntityRelationship) -> None:
    from app.intelligence.correlation_cache import invalidate_entity_cache

    for etype, eid in ((edge.source_type, edge.source_id), (edge.target_type, edge.target_id)):
        try:
            await invalidate_entity_cache(etype, str(eid))
        except Exception:
            logger.debug("pivot cache invalidation skipped", exc_info=True)
