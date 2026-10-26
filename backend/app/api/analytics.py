"""Analytics API — trending entities, detection coverage, velocity, and overview metrics."""

import logging
import uuid

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user, get_viewer
from app.database import get_db
from app.intelligence.analytics import (
    analytics_overview,
    detection_coverage,
    entity_trending,
    intelligence_velocity,
)
from app.intelligence.insights import generate_entry_insights
from app.intelligence.source_analytics import compute_feed_value_scores, compute_source_overlap
from app.models.cve import EntryCVE
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware
from app.models.threat_actor import EntryThreatActor
from app.models.ttp import EntryTTP
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/trending/{entity_type}")
async def get_trending(
    entity_type: str = Path(..., description="Entity type to rank: threat_actor, malware, cve, or ttp."),
    days: int = Query(30, ge=1, le=36500, description="Look-back window in days."),
    limit: int = Query(20, ge=1, le=500, description="Maximum number of entities to return."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Top entities by mention count over the time window."""
    try:
        return await entity_trending(db, entity_type, days, limit)
    except Exception:
        logger.exception("Error in trending/%s", entity_type)
        return []


@router.get("/detection-coverage")
async def get_detection_coverage(
    include_gaps: bool = Query(True, description="Include the list of uncovered techniques (gaps)."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """ATT&CK coverage analysis — observed TTPs vs active detection rules."""
    try:
        return await detection_coverage(db, include_gaps)
    except Exception:
        logger.exception("Error in detection-coverage analytics")
        return {"total_ttps": 0, "covered_ttps": 0, "coverage_percentage": 0, "tactic_summary": {}, "gaps": []}


@router.get("/velocity")
async def get_velocity(
    days: int = Query(30, ge=1, le=36500, description="Look-back window in days."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Entity creation velocity — new entities per day."""
    try:
        return await intelligence_velocity(db, days)
    except Exception:
        logger.exception("Error in velocity analytics")
        return {"days": days, "velocity": {}}


@router.get("/overview")
async def get_overview(
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Combined analytics summary for dashboard."""
    try:
        return await analytics_overview(db)
    except Exception:
        logger.exception("Error in analytics overview")
        return {
            "entity_counts": {"cves": 0, "threat_actors": 0, "malware": 0, "ttps": 0},
            "detection": {"total_rules": 0, "published_rules": 0},
            "events": {"recent_7d": 0, "unread": 0},
        }


@router.get("/source-overlap")
async def get_source_overlap(
    min_overlap: float = Query(0.1, ge=0.0, le=1.0, description="Minimum shared-TTP overlap ratio (0-1)."),
    limit: int = Query(20, ge=1, le=500, description="Maximum number of feed pairs to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Which feeds cover the same topics? Helps identify redundant sources."""
    try:
        return await compute_source_overlap(db, min_overlap, limit)
    except Exception:
        logger.exception("Error in source-overlap analytics")
        return []


@router.get("/entries/{entry_id}/insights")
async def get_entry_insights(
    entry_id: uuid.UUID = Path(..., description="Entry UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate actionable insights for a specific entry's extracted entities."""
    try:
        return await generate_entry_insights(db, entry_id)
    except Exception:
        logger.exception("Error generating insights for entry %s", entry_id)
        return []


@router.get("/source-reliability")
async def get_source_reliability(
    limit: int = Query(20, ge=1, le=100, description="Maximum number of feeds to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Top feeds ranked by intelligence contribution — articles and total entities."""
    try:
        # Get all active feeds
        feed_q = select(Feed.id).where(Feed.is_active == True)  # noqa: E712

        # Article count per feed
        article_counts = dict(
            (
                await db.execute(
                    select(Entry.feed_id, func.count(Entry.id)).where(Entry.feed_id.in_(feed_q)).group_by(Entry.feed_id)
                )
            ).all()
        )

        # Entity count per feed (threat actors + malware + CVEs + TTPs)
        entity_counts: dict[uuid.UUID, int] = {}
        for LinkModel, id_col in [
            (EntryThreatActor, EntryThreatActor.threat_actor_id),
            (EntryMalware, EntryMalware.malware_family_id),
            (EntryCVE, EntryCVE.cve_id),
            (EntryTTP, EntryTTP.ttp_id),
        ]:
            rows = (
                await db.execute(
                    select(Entry.feed_id, func.count(func.distinct(id_col)))
                    .join(LinkModel, LinkModel.entry_id == Entry.id)
                    .where(Entry.feed_id.in_(feed_q))
                    .group_by(Entry.feed_id)
                )
            ).all()
            for feed_id, cnt in rows:
                entity_counts[feed_id] = entity_counts.get(feed_id, 0) + cnt

        # Get feed titles
        all_feed_ids = set(article_counts) | set(entity_counts)
        if not all_feed_ids:
            return []

        feed_titles = dict((await db.execute(select(Feed.id, Feed.title).where(Feed.id.in_(all_feed_ids)))).all())

        results = []
        for fid in all_feed_ids:
            results.append(
                {
                    "feed_id": str(fid),
                    "feed_title": feed_titles.get(fid, "Unknown"),
                    "article_count": article_counts.get(fid, 0),
                    "entity_count": entity_counts.get(fid, 0),
                }
            )

        # Sort by total intel contribution (entities)
        results.sort(key=lambda r: r["entity_count"], reverse=True)
        return results[:limit]
    except Exception:
        logger.exception("Error in source-reliability analytics")
        return []


@router.get("/feed-value")
async def get_feed_value_scores(
    days: int = Query(90, ge=7, le=365, description="Scoring window in days."),
    limit: int = Query(100, ge=1, le=500, description="Maximum number of scored feeds to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Feed value scoring — ranks feeds by actionable intelligence output.

    Composite score (0-100) based on unique entity introductions,
    correlation events triggered, detection rules generated, and FP rate.
    """
    try:
        # Score all active feeds
        feed_q = select(Feed.id).where(Feed.is_active == True)  # noqa: E712
        feed_ids = [row[0] for row in (await db.execute(feed_q)).all()]
        if not feed_ids:
            return {
                "feeds": [],
                "summary": {"total": 0, "avg_score": 0, "scored": 0, "no_value": 0},
                "review_candidates": [],
            }

        feeds = await compute_feed_value_scores(db, feed_ids=feed_ids, days=days)

        scored = [f for f in feeds if f["score"] > 0]
        no_value = [f for f in feeds if f["score"] == 0]
        avg_score = round(sum(f["score"] for f in scored) / len(scored), 1) if scored else 0

        # Removal recommendations: active feeds producing zero intel value AND
        # zero PIR matches in the window. Built from the full (pre-limit) list.
        review_candidates = [
            {
                "feed_id": f["feed_id"],
                "feed_title": f["feed_title"],
                "feed_type": f["feed_type"],
                "reliability_rating": f["reliability_rating"],
                "articles": f["articles"],
            }
            for f in no_value
            if f["pir_matches"] == 0
        ]

        return {
            "feeds": feeds[:limit],
            "summary": {
                "total": len(feeds),
                "avg_score": avg_score,
                "scored": len(scored),
                "no_value": len(no_value),
            },
            "review_candidates": review_candidates,
        }
    except Exception:
        logger.exception("Error in feed-value analytics")
        return {
            "feeds": [],
            "summary": {"total": 0, "avg_score": 0, "scored": 0, "no_value": 0},
            "review_candidates": [],
        }
