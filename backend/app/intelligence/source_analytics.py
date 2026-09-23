"""Source reliability analytics for feeds."""

import logging
import uuid
from collections import defaultdict
from datetime import UTC

from sqlalchemy import and_, func, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.correlation_event import CorrelationEventRecord
from app.models.cve import EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.intelligence_requirement import RequirementMatch
from app.models.malware_family import EntryMalware
from app.models.threat_actor import EntryThreatActor
from app.models.ttp import EntryTTP

logger = logging.getLogger(__name__)


async def compute_feed_analytics(feed_id: uuid.UUID, db: AsyncSession) -> dict:
    """Compute analytics for a single feed."""
    feed = await db.get(Feed, feed_id)
    if not feed:
        return {}

    # Total articles
    total_q = select(func.count()).select_from(Entry).where(Entry.feed_id == feed_id)
    total_articles = (await db.execute(total_q)).scalar() or 0

    # Subquery for entry IDs belonging to this feed
    feed_entry_ids = select(Entry.id).where(Entry.feed_id == feed_id)

    # Entries with at least one entity (TTP or CVE)
    entries_with_ttps = select(EntryTTP.entry_id).where(EntryTTP.entry_id.in_(feed_entry_ids)).distinct()
    entries_with_cves = select(EntryCVE.entry_id).where(EntryCVE.entry_id.in_(feed_entry_ids)).distinct()

    # Union of entries with any entity
    entities_union = union_all(entries_with_ttps, entries_with_cves).subquery()
    articles_with_entities = (
        await db.execute(select(func.count(func.distinct(entities_union.c.entry_id))))
    ).scalar() or 0

    # Unique TTPs contributed
    unique_ttps_q = select(func.count(func.distinct(EntryTTP.ttp_id))).where(EntryTTP.entry_id.in_(feed_entry_ids))
    unique_ttps = (await db.execute(unique_ttps_q)).scalar() or 0

    entity_extraction_rate = articles_with_entities / total_articles if total_articles > 0 else 0.0

    # Average time between entry publication and feed fetch (publishing lag)
    avg_time_to_publish = None
    if total_articles > 0:
        lag_q = select(
            func.avg(func.extract("epoch", Entry.fetched_at) - func.extract("epoch", Entry.published_at))
        ).where(
            Entry.feed_id == feed_id,
            Entry.published_at.isnot(None),
            Entry.fetched_at.isnot(None),
        )
        avg_lag_seconds = (await db.execute(lag_q)).scalar()
        if avg_lag_seconds is not None and avg_lag_seconds > 0:
            avg_time_to_publish = f"{avg_lag_seconds / 3600:.1f} hours"

    return {
        "feed_id": str(feed_id),
        "feed_title": feed.title,
        "reliability_rating": feed.reliability_rating,
        "timeliness_rating": feed.timeliness_rating,
        "relevance_rating": feed.relevance_rating,
        "total_articles": total_articles,
        "articles_with_entities": articles_with_entities,
        "entity_extraction_rate": round(entity_extraction_rate, 3),
        "unique_ttps_contributed": unique_ttps,
        "avg_time_to_publish": avg_time_to_publish,
    }


async def compute_source_overlap(db: AsyncSession, min_overlap: float = 0.1, limit: int = 20) -> list[dict]:
    """Compute entity overlap between feeds to identify redundant sources.

    Returns pairs of feeds with their shared entity percentage.
    Uses TTPs as the overlap metric since IOCs have been removed.
    """
    # Get all feeds with at least 1 TTP
    feed_ttps: dict[uuid.UUID, set[uuid.UUID]] = defaultdict(set)
    feed_names: dict[uuid.UUID, str] = {}

    result = await db.execute(
        select(Entry.feed_id, EntryTTP.ttp_id, Feed.title)
        .join(EntryTTP, EntryTTP.entry_id == Entry.id)
        .join(Feed, Feed.id == Entry.feed_id)
        .where(Entry.feed_id.isnot(None))
    )
    for row in result.all():
        feed_ttps[row.feed_id].add(row.ttp_id)
        feed_names[row.feed_id] = row.title

    # Calculate pairwise overlap
    overlaps = []
    feed_ids = list(feed_ttps.keys())
    for i in range(len(feed_ids)):
        for j in range(i + 1, len(feed_ids)):
            a, b = feed_ids[i], feed_ids[j]
            set_a, set_b = feed_ttps[a], feed_ttps[b]
            if not set_a or not set_b:
                continue
            intersection = len(set_a & set_b)
            smaller = min(len(set_a), len(set_b))
            overlap_pct = intersection / smaller if smaller > 0 else 0.0
            if overlap_pct >= min_overlap:
                overlaps.append(
                    {
                        "feed_a_id": str(a),
                        "feed_a_title": feed_names.get(a, ""),
                        "feed_b_id": str(b),
                        "feed_b_title": feed_names.get(b, ""),
                        "shared_entities": intersection,
                        "overlap_percentage": round(overlap_pct, 3),
                    }
                )

    overlaps.sort(key=lambda x: x["overlap_percentage"], reverse=True)
    return overlaps[:limit]


# ---------------------------------------------------------------------------
# Feed Value Scoring
# ---------------------------------------------------------------------------


def _value_weights() -> dict[str, float]:
    """Scoring weights, read from settings (DB override > env default) and
    normalized so they always sum to 1.0."""
    from app.config import settings as env_settings

    weights = {
        # Entities per article (higher = more actionable)
        "entity_yield": float(env_settings.get("feed_value_weight_entity_yield") or 0.25),
        # Unique entities first discovered via this feed
        "entity_intro": float(env_settings.get("feed_value_weight_entity_intro") or 0.25),
        # Correlation events triggered by this feed's entries
        "correlation": float(env_settings.get("feed_value_weight_correlation") or 0.20),
        # Detection rules generated from this feed's entries
        "detection": float(env_settings.get("feed_value_weight_detection") or 0.15),
        # Priority intelligence requirement (PIR) matches on this feed's entries
        "pir": float(env_settings.get("feed_value_weight_pir") or 0.15),
    }
    total = sum(weights.values()) or 1.0
    return {k: v / total for k, v in weights.items()}


def _normalize(value: float, ceiling: float) -> float:
    """Normalize a raw metric to 0-1, capped at ceiling."""
    if ceiling <= 0:
        return 0.0
    return min(value / ceiling, 1.0)


def _score_tier(score: float) -> str:
    """Map 0-100 score to a letter tier."""
    if score >= 80:
        return "S"
    if score >= 60:
        return "A"
    if score >= 40:
        return "B"
    if score >= 20:
        return "C"
    return "D"


async def compute_feed_value_scores(
    db: AsyncSession,
    feed_ids: list[uuid.UUID] | None = None,
    days: int = 90,
) -> list[dict]:
    """Compute intelligence value scores for feeds.

    Scores are 0-100 based on weighted dimensions:
    - Entity yield: unique entities per article
    - Entity introductions: entities first seen via this feed
    - Correlation events: co-occurrence / linkage events from this feed's entries
    - Detection rules: rules generated from this feed's content
    - PIR matches: intelligence requirement matches on this feed's entries

    Args:
        db: Database session.
        feed_ids: Optional list of feed IDs to score. If None, scores all active feeds.
        days: Lookback window in days for time-scoped metrics.
    """
    from datetime import datetime, timedelta

    cutoff = datetime.now(UTC) - timedelta(days=days)

    # Determine which feeds to score
    if feed_ids:
        feed_q = select(Feed.id, Feed.title, Feed.feed_type, Feed.reliability_rating).where(Feed.id.in_(feed_ids))
    else:
        feed_q = select(Feed.id, Feed.title, Feed.feed_type, Feed.reliability_rating).where(Feed.is_active.is_(True))

    feeds = (await db.execute(feed_q)).all()
    if not feeds:
        return []

    scored_feed_ids = [f.id for f in feeds]
    feed_meta = {
        f.id: {"title": f.title, "feed_type": f.feed_type, "reliability_rating": f.reliability_rating} for f in feeds
    }

    # --- Batch queries across all feeds ---

    # 1. Article counts per feed (within lookback)
    article_counts = dict(
        (
            await db.execute(
                select(Entry.feed_id, func.count(Entry.id))
                .where(Entry.feed_id.in_(scored_feed_ids), Entry.fetched_at >= cutoff)
                .group_by(Entry.feed_id)
            )
        ).all()
    )

    # 2. Unique entities per feed (actors + malware + CVEs + TTPs)
    entity_counts: dict[uuid.UUID, int] = defaultdict(int)
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
                .where(Entry.feed_id.in_(scored_feed_ids), Entry.fetched_at >= cutoff)
                .group_by(Entry.feed_id)
            )
        ).all()
        for fid, cnt in rows:
            entity_counts[fid] += cnt

    # 4. Entity introductions — entities whose EARLIEST entry belongs to this feed
    #    For each entity type, find the min(fetched_at) entry per entity, then group by feed.
    intro_counts: dict[uuid.UUID, int] = defaultdict(int)
    for LinkModel, id_col in [
        (EntryTTP, EntryTTP.ttp_id),
        (EntryCVE, EntryCVE.cve_id),
        (EntryThreatActor, EntryThreatActor.threat_actor_id),
        (EntryMalware, EntryMalware.malware_family_id),
    ]:
        # Subquery: earliest entry per entity
        first_entry = (
            select(
                id_col.label("entity_id"),
                func.min(Entry.fetched_at).label("first_seen"),
            )
            .join(Entry, Entry.id == LinkModel.entry_id)
            .where(Entry.feed_id.in_(scored_feed_ids))
            .group_by(id_col)
        ).subquery()

        # Join back to get which feed owns that earliest entry
        rows = (
            await db.execute(
                select(Entry.feed_id, func.count(func.distinct(first_entry.c.entity_id)))
                .join(LinkModel, LinkModel.entry_id == Entry.id)
                .join(
                    first_entry,
                    and_(
                        id_col == first_entry.c.entity_id,
                        Entry.fetched_at == first_entry.c.first_seen,
                    ),
                )
                .where(Entry.feed_id.in_(scored_feed_ids))
                .group_by(Entry.feed_id)
            )
        ).all()
        for fid, cnt in rows:
            intro_counts[fid] += cnt

    # 5. Correlation events per feed (via entry_id → entries.feed_id)
    correlation_counts = dict(
        (
            await db.execute(
                select(Entry.feed_id, func.count(CorrelationEventRecord.id))
                .join(Entry, Entry.id == CorrelationEventRecord.entry_id)
                .where(
                    Entry.feed_id.in_(scored_feed_ids),
                    CorrelationEventRecord.created_at >= cutoff,
                )
                .group_by(Entry.feed_id)
            )
        ).all()
    )

    # 6. Detection rules per feed (via entry_id → entries.feed_id)
    detection_counts = dict(
        (
            await db.execute(
                select(Entry.feed_id, func.count(DetectionRule.id))
                .join(Entry, Entry.id == DetectionRule.entry_id)
                .where(
                    Entry.feed_id.in_(scored_feed_ids),
                    DetectionRule.entry_id.isnot(None),
                    DetectionRule.created_at >= cutoff,
                )
                .group_by(Entry.feed_id)
            )
        ).all()
    )

    # 7. PIR matches per feed (requirement_matches → entries.feed_id)
    pir_counts = dict(
        (
            await db.execute(
                select(Entry.feed_id, func.count())
                .select_from(RequirementMatch)
                .join(Entry, Entry.id == RequirementMatch.entry_id)
                .where(
                    Entry.feed_id.in_(scored_feed_ids),
                    RequirementMatch.matched_at >= cutoff,
                )
                .group_by(Entry.feed_id)
            )
        ).all()
    )

    # --- Compute normalization ceilings from the dataset ---
    # Use the max across all feeds so scores are relative within this instance
    max_entity_yield = 0.0
    for fid in scored_feed_ids:
        articles = article_counts.get(fid, 0)
        if articles > 0:
            max_entity_yield = max(max_entity_yield, entity_counts.get(fid, 0) / articles)
    max_entity_yield = max(max_entity_yield, 1.0)  # floor at 1

    max_intros = max(intro_counts.values()) if intro_counts else 1
    max_corr = max(correlation_counts.values()) if correlation_counts else 1
    max_det = max(detection_counts.values()) if detection_counts else 1
    max_pir = max(pir_counts.values()) if pir_counts else 1

    weights = _value_weights()

    # --- Score each feed ---
    results = []
    for fid in scored_feed_ids:
        articles = article_counts.get(fid, 0)
        entities = entity_counts.get(fid, 0)
        intros = intro_counts.get(fid, 0)
        corr = correlation_counts.get(fid, 0)
        det = detection_counts.get(fid, 0)
        pir = pir_counts.get(fid, 0)

        entity_yield = entities / articles if articles > 0 else 0.0

        # Normalized dimension scores (0-1)
        s_entity = _normalize(entity_yield, max_entity_yield)
        s_intro = _normalize(intros, max_intros)
        s_corr = _normalize(corr, max_corr)
        s_det = _normalize(det, max_det)
        s_pir = _normalize(pir, max_pir)

        # Weighted composite (0-100)
        raw_score = (
            weights["entity_yield"] * s_entity
            + weights["entity_intro"] * s_intro
            + weights["correlation"] * s_corr
            + weights["detection"] * s_det
            + weights["pir"] * s_pir
        ) * 100

        # Feeds with zero articles in the window get score 0
        if articles == 0:
            raw_score = 0.0

        score = round(raw_score, 1)

        results.append(
            {
                "feed_id": str(fid),
                "feed_title": feed_meta[fid]["title"],
                "feed_type": feed_meta[fid]["feed_type"],
                "reliability_rating": feed_meta[fid]["reliability_rating"],
                "score": score,
                "tier": _score_tier(score),
                "articles": articles,
                "entity_yield": round(entity_yield, 2),
                "unique_entities": entities,
                "entity_introductions": intros,
                "correlation_events": corr,
                "detection_rules": det,
                "pir_matches": pir,
                "dimensions": {
                    "entity_yield": round(s_entity * 100, 1),
                    "entity_introductions": round(s_intro * 100, 1),
                    "correlation_events": round(s_corr * 100, 1),
                    "detection_rules": round(s_det * 100, 1),
                    "pir_matches": round(s_pir * 100, 1),
                },
            }
        )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results
