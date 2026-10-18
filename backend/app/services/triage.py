"""Triage queue — scores entries by composite priority for analyst workflow.

Priority scoring factors:
- PIR (intelligence requirement) matches → highest weight
- High-risk CVEs (KEV / high EPSS / weaponized) linked to the entry
- High-severity correlation events linked to the entry
- Feed reliability rating (A-F)
- Automation rule triggers on the entry
- Watched entities (including sectors) boost through the generic watch junctions
"""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.cve import risk_tier_rank_expr
from app.models.automation_log import AutomationLog
from app.models.correlation_event import CorrelationEventRecord
from app.models.cve import CVE, EntryCVE
from app.models.entry import Entry
from app.models.entry_state import UserEntryState
from app.models.feed import Feed
from app.models.intelligence_requirement import RequirementMatch

# Defaults — overridden by user settings when available
DEFAULT_TRIAGE_WEIGHTS = {
    "pir_weight": 10,
    "correlation_weight": 3,
    "automation_weight": 1,
    "engagement_weight": 1,
    "cve_risk_weight": 3,
    "min_priority_score": 3,
}

DEFAULT_CLUSTER_SETTINGS = {
    "days": 7,
    "window_hours": 24,
    "min_shared_entities": 2,
}

SEVERITY_WEIGHTS = {"high": 3, "medium": 2, "low": 1}
RELIABILITY_WEIGHTS = {"A": 5, "B": 4, "C": 3, "D": 2, "E": 1, "F": 0}


def _resolve_weights(user_settings: dict | None) -> dict:
    """Merge user triage_settings over defaults."""
    weights = dict(DEFAULT_TRIAGE_WEIGHTS)
    if user_settings:
        triage = user_settings.get("triage_settings")
        if isinstance(triage, dict):
            for k in weights:
                if k in triage:
                    weights[k] = triage[k]
    return weights


def _resolve_cluster_settings(user_settings: dict | None) -> dict:
    """Merge user cluster_settings over defaults."""
    settings = dict(DEFAULT_CLUSTER_SETTINGS)
    if user_settings:
        cluster = user_settings.get("cluster_settings")
        if isinstance(cluster, dict):
            for k in settings:
                if k in cluster:
                    settings[k] = cluster[k]
    return settings


async def get_triage_entries(
    db: AsyncSession,
    user_id: uuid.UUID,
    days: int = 7,
    limit: int = 50,
    offset: int = 0,
    user_settings: dict | None = None,
) -> dict:
    """Return entries scored and sorted by composite priority.

    Returns:
        {
            "items": [{
                "entry": {...},
                "priority_score": float,
                "priority_reasons": [str, ...],
                "priority_components": [
                    {"label": str, "count": int|float, "weight": int|float, "contribution": int|float},
                    ...
                ],
            }],
            "total": int,
        }
    """
    w = _resolve_weights(user_settings)
    pir_w = w["pir_weight"]
    corr_w = w["correlation_weight"]
    auto_w = w["automation_weight"]
    engagement_w = w.get("engagement_weight", 1)
    cve_risk_w = w.get("cve_risk_weight", 3)
    min_score = w["min_priority_score"]

    cutoff = datetime.now(UTC) - timedelta(days=days)

    # Get the user's active, non-muted feed IDs
    from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query

    sub_result = await db.execute(
        visible_feed_ids_query(user_id, enabled=await subscriptions_enabled(db), active_only=True)
    )
    feed_ids = [row[0] for row in sub_result.all()]
    if not feed_ids:
        return {"items": [], "total": 0}

    # --- Subqueries for scoring factors ---

    # 1. PIR match count per entry
    pir_sub = (
        select(
            RequirementMatch.entry_id,
            func.count().label("pir_count"),
        )
        .group_by(RequirementMatch.entry_id)
        .subquery()
    )

    # 2. Correlation event severity score per entry
    corr_sub = (
        select(
            CorrelationEventRecord.entry_id,
            func.sum(
                case(
                    (CorrelationEventRecord.severity == "high", 3),
                    (CorrelationEventRecord.severity == "medium", 2),
                    else_=1,
                )
            ).label("corr_score"),
            func.count().label("corr_count"),
        )
        .where(CorrelationEventRecord.created_at >= cutoff)
        .group_by(CorrelationEventRecord.entry_id)
        .subquery()
    )

    # 3. Automation trigger count per entry
    auto_sub = (
        select(
            AutomationLog.entry_id,
            func.count().label("auto_count"),
        )
        .where(AutomationLog.entry_id.isnot(None))
        .group_by(AutomationLog.entry_id)
        .subquery()
    )

    # 4. CVE risk per entry — highest risk-tier rank (3=KEV, 2=high EPSS or
    # Metasploit, 1=PoC/critical CVSS) among the entry's linked CVEs
    cve_sub = (
        select(
            EntryCVE.entry_id,
            func.max(risk_tier_rank_expr()).label("cve_risk"),
            func.bool_or(CVE.is_kev).label("has_kev"),
        )
        .join(CVE, CVE.id == EntryCVE.cve_id)
        .group_by(EntryCVE.entry_id)
        .subquery()
    )

    # Feed reliability score
    reliability_score = case(
        (Feed.reliability_rating == "A", 5),
        (Feed.reliability_rating == "B", 4),
        (Feed.reliability_rating == "C", 3),
        (Feed.reliability_rating == "D", 2),
        (Feed.reliability_rating == "E", 1),
        else_=3,  # default to C-level for unrated
    )

    # Engagement signal — total reaction count cached on entry metadata at ingest time.
    # Telegram adapter populates `metadata_.reactions_total` so triage can read a single
    # integer instead of summing the JSONB array on every priority query. Capped at +5 score
    # points so one viral post doesn't dwarf intel signals.
    from sqlalchemy import Integer

    reactions_total = func.coalesce(func.cast(Entry.metadata_["reactions_total"].astext, Integer), 0)

    # Composite priority score expression (used in both select and where)
    priority_expr = (
        func.coalesce(pir_sub.c.pir_count, 0) * pir_w
        + func.coalesce(corr_sub.c.corr_score, 0) * corr_w
        + func.coalesce(auto_sub.c.auto_count, 0) * auto_w
        + func.coalesce(cve_sub.c.cve_risk, 0) * cve_risk_w
        + reliability_score
        + func.least(reactions_total * 0.01, 5) * engagement_w
    )

    # Main query — unread entries from subscribed feeds within time window
    base_query = (
        select(
            Entry,
            Feed.title.label("feed_title"),
            Feed.feed_type.label("feed_type"),
            Feed.reliability_rating,
            priority_expr.label("priority_score"),
            func.coalesce(pir_sub.c.pir_count, 0).label("pir_count"),
            func.coalesce(corr_sub.c.corr_score, 0).label("corr_score"),
            func.coalesce(corr_sub.c.corr_count, 0).label("corr_count"),
            func.coalesce(auto_sub.c.auto_count, 0).label("auto_count"),
            func.coalesce(cve_sub.c.cve_risk, 0).label("cve_risk"),
            func.coalesce(cve_sub.c.has_kev, False).label("has_kev"),
            func.least(reactions_total * 0.01, 5).label("engagement_points"),
        )
        .join(Feed, Feed.id == Entry.feed_id)
        .outerjoin(pir_sub, pir_sub.c.entry_id == Entry.id)
        .outerjoin(corr_sub, corr_sub.c.entry_id == Entry.id)
        .outerjoin(auto_sub, auto_sub.c.entry_id == Entry.id)
        .outerjoin(cve_sub, cve_sub.c.entry_id == Entry.id)
        .outerjoin(
            UserEntryState,
            and_(UserEntryState.entry_id == Entry.id, UserEntryState.user_id == user_id),
        )
        .where(Entry.feed_id.in_(feed_ids))
        .where(Entry.published_at >= cutoff)
        # Only unread entries
        .where(or_(UserEntryState.is_read == False, UserEntryState.id == None))  # noqa: E711, E712
        # Exclude hidden
        .where(or_(UserEntryState.is_hidden == False, UserEntryState.is_hidden.is_(None)))  # noqa: E712
        # Must have at least one priority signal (score > min threshold)
        .where(priority_expr > min_score)
        .order_by(priority_expr.desc(), Entry.published_at.desc())
    )

    # Count total
    count_result = await db.execute(select(func.count()).select_from(base_query.subquery()))
    total = count_result.scalar_one()

    # Fetch page
    result = await db.execute(base_query.offset(offset).limit(limit))
    rows = result.all()

    items = []
    for row in rows:
        entry = row[0]
        feed_title = row[1]
        feed_type = row[2]
        reliability = row[3]
        score = row[4]
        pir_c = row[5]
        corr_s = row[6]
        corr_c = row[7]
        auto_c = row[8]
        cve_risk = row[9]
        has_kev = row[10]
        engagement_points = float(row[11] or 0)

        reasons = []
        if pir_c > 0:
            reasons.append(f"{pir_c} PIR match{'es' if pir_c > 1 else ''}")
        if has_kev:
            reasons.append("KEV CVE (actively exploited)")
        elif cve_risk >= 2:
            reasons.append("High-risk CVE")
        if corr_c > 0:
            reasons.append(f"{corr_c} correlation event{'s' if corr_c > 1 else ''}")
        if auto_c > 0:
            reasons.append(f"{auto_c} automation trigger{'s' if auto_c > 1 else ''}")
        if reliability in ("A", "B"):
            reasons.append(f"Feed reliability: {reliability}")

        # Per-component score breakdown — mirrors priority_expr so the UI can
        # show exactly how the score was composed. Additive to `reasons`.
        # Mirrors the SQL reliability case: unrated/F fall back to C-level (3).
        reliability_points = {"A": 5, "B": 4, "C": 3, "D": 2, "E": 1}.get(reliability, 3)
        components = []
        if pir_c > 0:
            components.append(
                {
                    "label": f"PIR match{'es' if pir_c != 1 else ''}",
                    "count": pir_c,
                    "weight": pir_w,
                    "contribution": pir_c * pir_w,
                }
            )
        if corr_s > 0:
            components.append(
                {
                    "label": f"Correlation severity ({corr_c} event{'s' if corr_c != 1 else ''})",
                    "count": corr_s,
                    "weight": corr_w,
                    "contribution": corr_s * corr_w,
                }
            )
        if cve_risk > 0:
            components.append(
                {
                    "label": "KEV CVE risk tier" if has_kev else "CVE risk tier",
                    "count": cve_risk,
                    "weight": cve_risk_w,
                    "contribution": cve_risk * cve_risk_w,
                }
            )
        if auto_c > 0:
            components.append(
                {
                    "label": f"Automation trigger{'s' if auto_c != 1 else ''}",
                    "count": auto_c,
                    "weight": auto_w,
                    "contribution": auto_c * auto_w,
                }
            )
        if reliability_points > 0:
            components.append(
                {
                    "label": f"Feed reliability ({reliability or 'unrated'})",
                    "count": reliability_points,
                    "weight": 1,
                    "contribution": reliability_points,
                }
            )
        if engagement_points > 0:
            components.append(
                {
                    "label": "Engagement (reactions)",
                    "count": round(engagement_points, 2),
                    "weight": engagement_w,
                    "contribution": round(engagement_points * engagement_w, 2),
                }
            )

        items.append(
            {
                "entry": {
                    "id": str(entry.id),
                    "feed_id": str(entry.feed_id),
                    "title": entry.title,
                    "translated_title": entry.translated_title,
                    "url": entry.url,
                    "author": entry.author,
                    "summary": (entry.summary or "")[:300],
                    "published_at": entry.published_at.isoformat() if entry.published_at else None,
                    "feed_title": feed_title,
                    "feed_type": feed_type,
                    "image_url": entry.image_url,
                },
                "priority_score": float(score),
                "priority_reasons": reasons,
                "priority_components": components,
            }
        )

    return {"items": items, "total": total}


async def get_triage_entries_signals(
    db: AsyncSession,
    user_id: uuid.UUID,
    days: int = 7,
    limit: int = 50,
    offset: int = 0,
    min_score: float | None = None,
    user_id_for_watches: uuid.UUID | None = None,
) -> dict:
    """Signal-engine triage ranking (shadow mode: compare against the legacy composite).

    Same response shape as get_triage_entries, but driven entirely by the stored
    Entry.priority_score / priority_raw + entry_signals rows — one indexed scan plus one batched
    signal fetch, replacing the live multi-subquery composite.
    """
    from app.intelligence.signals import get_radar_threshold
    from app.models.entry_signal import EntrySignal
    from app.models.user_entity_watch import UserEntityWatch
    from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query

    cutoff = datetime.now(UTC) - timedelta(days=days)
    _subs_enabled = await subscriptions_enabled(db)
    if min_score is not None:
        threshold = min_score
    else:
        threshold, _ = await get_radar_threshold()

    # Watch/mute: read-time, per-user adjustment on top of the global score
    watch_rows = []
    if user_id_for_watches:
        watch_rows = (
            (await db.execute(select(UserEntityWatch).where(UserEntityWatch.created_by == user_id_for_watches)))
            .scalars()
            .all()
        )
    mute_filters = _entity_watch_filters([w for w in watch_rows if w.mode == "mute"])
    watch_boost_sq = _watched_entries_boost_subquery([w for w in watch_rows if w.mode == "watch"])

    base = (
        select(Entry, Feed.title, Feed.feed_type)
        .join(Feed, Feed.id == Entry.feed_id)
        .outerjoin(
            UserEntryState,
            and_(UserEntryState.entry_id == Entry.id, UserEntryState.user_id == user_id),
        )
        .where(
            Entry.published_at >= cutoff,
            Entry.feed_id.in_(visible_feed_ids_query(user_id, enabled=_subs_enabled, active_only=True)),
            or_(UserEntryState.is_read.is_(None), UserEntryState.is_read == False),  # noqa: E712
        )
    )
    for mute_clause in mute_filters:
        base = base.where(~mute_clause)

    # Membership gates on the 0–10 score; ordering uses the raw sum, which the
    # watch boost is added to and which doesn't clamp at the top.
    effective_score = Entry.priority_raw
    if watch_boost_sq is not None:
        base = base.outerjoin(watch_boost_sq, watch_boost_sq.c.entry_id == Entry.id)
        effective_score = Entry.priority_raw + func.coalesce(watch_boost_sq.c.boost, 0.0)
        base = base.where(or_(Entry.priority_score >= threshold, watch_boost_sq.c.entry_id.is_not(None)))
    else:
        base = base.where(Entry.priority_score >= threshold)

    total = (await db.execute(select(func.count()).select_from(base.order_by(None).subquery()))).scalar_one()

    rows = (
        await db.execute(base.order_by(effective_score.desc(), Entry.published_at.desc()).limit(limit).offset(offset))
    ).all()

    entry_ids = [row[0].id for row in rows]
    signals_by_entry: dict[uuid.UUID, list[EntrySignal]] = {}
    if entry_ids:
        signal_rows = (await db.execute(select(EntrySignal).where(EntrySignal.entry_id.in_(entry_ids)))).scalars().all()
        for sig in signal_rows:
            signals_by_entry.setdefault(sig.entry_id, []).append(sig)

    items = []
    for entry, feed_title, feed_type in rows:
        signals = sorted(signals_by_entry.get(entry.id, []), key=lambda s: s.score, reverse=True)
        items.append(
            {
                "entry": {
                    "id": str(entry.id),
                    "feed_id": str(entry.feed_id),
                    "title": entry.title,
                    "translated_title": entry.translated_title,
                    "url": entry.url,
                    "author": entry.author,
                    "summary": (entry.summary or "")[:300],
                    "published_at": entry.published_at.isoformat() if entry.published_at else None,
                    "feed_title": feed_title,
                    "feed_type": feed_type,
                    "image_url": entry.image_url,
                },
                "priority_score": float(entry.priority_score or 0),
                "priority_reasons": [s.explanation for s in signals if s.signal_type != "feed_echo"],
                "priority_components": [
                    {
                        "label": s.signal_type.replace("_", " "),
                        "count": round(s.score, 2),
                        "weight": 1,
                        "contribution": round(s.score, 2),
                    }
                    for s in signals
                ],
            }
        )

    return {"items": items, "total": total}


_WATCH_JUNCTIONS: dict[str, tuple] = {}


def _watch_junction_map():
    """Lazy map: entity_type -> (junction model, entity-id column)."""
    global _WATCH_JUNCTIONS
    if not _WATCH_JUNCTIONS:
        from app.models.country import EntryCountry
        from app.models.cve import EntryCVE
        from app.models.cwe import EntryCWE
        from app.models.entry_sector import EntrySector
        from app.models.malware_family import EntryMalware
        from app.models.mitigation import EntryMitigation
        from app.models.product import EntryProduct
        from app.models.threat_actor import EntryThreatActor
        from app.models.tool import EntryTool
        from app.models.ttp import EntryTTP
        from app.models.vendor import EntryVendor

        _WATCH_JUNCTIONS = {
            "threat_actor": (EntryThreatActor, EntryThreatActor.threat_actor_id),
            "malware": (EntryMalware, EntryMalware.malware_family_id),
            "cve": (EntryCVE, EntryCVE.cve_id),
            "cwe": (EntryCWE, EntryCWE.cwe_id),
            "ttp": (EntryTTP, EntryTTP.ttp_id),
            "tool": (EntryTool, EntryTool.tool_id),
            "mitigation": (EntryMitigation, EntryMitigation.mitigation_id),
            "vendor": (EntryVendor, EntryVendor.vendor_id),
            "product": (EntryProduct, EntryProduct.product_id),
            "country": (EntryCountry, EntryCountry.country_id),
            "sector": (EntrySector, EntrySector.sector_id),
        }
    return _WATCH_JUNCTIONS


def _entity_watch_filters(mutes) -> list:
    """EXISTS clauses matching entries linked to any muted entity."""
    clauses = []
    junctions = _watch_junction_map()
    by_type: dict[str, list] = {}
    for w in mutes:
        by_type.setdefault(w.entity_type, []).append(w.entity_id)
    for entity_type, ids in by_type.items():
        junction, id_col = junctions.get(entity_type, (None, None))
        if junction is None:
            continue
        clauses.append(select(junction).where(junction.entry_id == Entry.id, id_col.in_(ids)).exists())
    return clauses


def _watched_entries_boost_subquery(watches):
    """Subquery of (entry_id, boost) — boost is the MAX of each watch's configured
    boost value across every watched entity linked to that entry (None if no watches).
    """
    junctions = _watch_junction_map()
    by_type: dict[str, list[tuple[uuid.UUID, float]]] = {}
    for w in watches:
        by_type.setdefault(w.entity_type, []).append((w.entity_id, w.boost))
    parts = []
    for entity_type, pairs in by_type.items():
        junction, id_col = junctions.get(entity_type, (None, None))
        if junction is None:
            continue
        boost_case = case(*[(id_col == eid, boost) for eid, boost in pairs], else_=0.0)
        parts.append(
            select(junction.entry_id.label("entry_id"), boost_case.label("boost")).where(
                id_col.in_([eid for eid, _ in pairs])
            )
        )
    if not parts:
        return None
    from sqlalchemy import union_all

    unioned = parts[0].subquery() if len(parts) == 1 else union_all(*parts).subquery()
    return select(unioned.c.entry_id, func.max(unioned.c.boost).label("boost")).group_by(unioned.c.entry_id).subquery()
