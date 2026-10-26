"""Strategic widget data API — recap, actor activity sparklines, hot correlations."""

import logging
import uuid
from datetime import date, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Date, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.widgets import _parse_date_range
from app.core.exceptions import AppError
from app.core.security import get_viewer
from app.database import get_db
from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter()


def _trend_pct(current: int, previous: int) -> float:
    # NOTE: returns 100.0 when previous == 0 and current > 0 — that's a sentinel
    # for "new in window", not a real percentage. Callers that care about the
    # distinction must check `previous == 0` themselves before formatting.
    if previous == 0:
        return 100.0 if current > 0 else 0.0
    return round(((current - previous) / max(previous, 1)) * 100, 1)


@router.get("/weekly-recap")
async def weekly_recap(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 7 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Recap counts (entries, new CVEs, new actors, detection rules) for the window vs the preceding one."""
    try:
        start, end = _parse_date_range(date_from, date_to, default_days=7)
        span = end - start
        prev_start = start - span
        window_days = max(int(round(span.total_seconds() / 86400)), 1)

        from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query

        feed_q = visible_feed_ids_query(user.id, enabled=await subscriptions_enabled(db), active_only=True)

        async def count(stmt):
            return (await db.execute(stmt)).scalar() or 0

        entries_cur = await count(
            select(func.count(Entry.id)).where(
                Entry.feed_id.in_(feed_q),
                Entry.published_at >= start,
                Entry.published_at <= end,
            )
        )
        entries_prev = await count(
            select(func.count(Entry.id)).where(
                Entry.feed_id.in_(feed_q),
                Entry.published_at >= prev_start,
                Entry.published_at < start,
            )
        )

        cves_cur = await count(select(func.count(CVE.id)).where(CVE.first_seen_at >= start, CVE.first_seen_at <= end))
        cves_prev = await count(
            select(func.count(CVE.id)).where(CVE.first_seen_at >= prev_start, CVE.first_seen_at < start)
        )

        actors_cur = await count(
            select(func.count(ThreatActor.id)).where(
                ThreatActor.first_seen_at >= start, ThreatActor.first_seen_at <= end
            )
        )
        actors_prev = await count(
            select(func.count(ThreatActor.id)).where(
                ThreatActor.first_seen_at >= prev_start, ThreatActor.first_seen_at < start
            )
        )

        det_cur = await count(
            select(func.count(DetectionRule.id)).where(
                DetectionRule.created_at >= start, DetectionRule.created_at <= end
            )
        )
        det_prev = await count(
            select(func.count(DetectionRule.id)).where(
                DetectionRule.created_at >= prev_start, DetectionRule.created_at < start
            )
        )

        return {
            "entries": {
                "count": entries_cur,
                "previous": entries_prev,
                "trend_pct": _trend_pct(entries_cur, entries_prev),
            },
            "cves": {
                "count": cves_cur,
                "previous": cves_prev,
                "trend_pct": _trend_pct(cves_cur, cves_prev),
            },
            "actors": {
                "count": actors_cur,
                "previous": actors_prev,
                "trend_pct": _trend_pct(actors_cur, actors_prev),
            },
            "detections": {
                "count": det_cur,
                "previous": det_prev,
                "trend_pct": _trend_pct(det_cur, det_prev),
            },
            "window_days": window_days,
        }
    except Exception as exc:
        logger.exception("Error in weekly_recap widget")
        raise AppError(
            code="widget_error",
            message="Failed to load weekly recap widget",
            status_code=500,
        ) from exc


@router.get("/actor-activity")
async def actor_activity(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 7 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    limit: int = Query(5, ge=1, le=25, description="Maximum number of top actors when actor_ids is not set."),
    actor_ids: str | None = Query(None, description="Comma-separated actor UUIDs to chart instead of the top N."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Daily entry-mention sparklines for the top (or explicitly selected) threat actors in the window."""
    try:
        start, end = _parse_date_range(date_from, date_to, default_days=7)

        selected_ids: list[uuid.UUID] = []
        if actor_ids:
            for raw in actor_ids.split(","):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    selected_ids.append(uuid.UUID(raw))
                except ValueError:
                    continue

        if selected_ids:
            actor_rows = (
                await db.execute(
                    select(ThreatActor.id, ThreatActor.name, ThreatActor.country).where(
                        ThreatActor.id.in_(selected_ids)
                    )
                )
            ).all()
        else:
            top_q = (
                select(
                    ThreatActor.id,
                    ThreatActor.name,
                    ThreatActor.country,
                    func.count(func.distinct(EntryThreatActor.entry_id)).label("c"),
                )
                .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
                .where(
                    EntryThreatActor.extracted_at >= start,
                    EntryThreatActor.extracted_at <= end,
                )
                .group_by(ThreatActor.id, ThreatActor.name, ThreatActor.country)
                .order_by(func.count(func.distinct(EntryThreatActor.entry_id)).desc())
                .limit(limit)
            )
            actor_rows = (await db.execute(top_q)).all()

        if not actor_rows:
            return {"actors": []}

        actor_id_list = [r[0] for r in actor_rows]
        daily = (
            await db.execute(
                select(
                    EntryThreatActor.threat_actor_id,
                    cast(EntryThreatActor.extracted_at, Date).label("day"),
                    func.count(func.distinct(EntryThreatActor.entry_id)).label("c"),
                )
                .where(
                    EntryThreatActor.threat_actor_id.in_(actor_id_list),
                    EntryThreatActor.extracted_at >= start,
                    EntryThreatActor.extracted_at <= end,
                )
                .group_by(EntryThreatActor.threat_actor_id, "day")
            )
        ).all()

        by_actor: dict[uuid.UUID, dict[date, int]] = {aid: {} for aid in actor_id_list}
        for aid, day, c in daily:
            by_actor[aid][day] = int(c)

        start_day = start.date()
        end_day = end.date()
        day_count = (end_day - start_day).days + 1
        all_days = [start_day + timedelta(days=i) for i in range(day_count)]

        actors_out = []
        for row in actor_rows:
            aid, name, country = row[0], row[1], row[2]
            counts = by_actor.get(aid, {})
            points = [{"date": d.isoformat(), "count": counts.get(d, 0)} for d in all_days]
            total = sum(p["count"] for p in points)
            actors_out.append(
                {
                    "id": str(aid),
                    "name": name,
                    "country": country,
                    "total": total,
                    "points": points,
                }
            )

        actors_out.sort(key=lambda a: a["total"], reverse=True)
        return {"actors": actors_out}
    except Exception as exc:
        logger.exception("Error in actor_activity widget")
        raise AppError(
            code="widget_error",
            message="Failed to load actor activity widget",
            status_code=500,
        ) from exc


@router.get("/hot-correlations")
async def hot_correlations(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 7 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    limit: int = Query(15, ge=1, le=100, description="Maximum number of entity pairs to return."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Actor–malware pairs (topped up with actor–CVE pairs) co-occurring in entries published in the window."""
    try:
        start, end = _parse_date_range(date_from, date_to, default_days=7)

        in_window_entries = select(Entry.id).where(Entry.published_at >= start, Entry.published_at <= end)

        actor_malware_q = (
            select(
                ThreatActor.id.label("actor_id"),
                ThreatActor.name.label("actor_name"),
                MalwareFamily.id.label("malware_id"),
                MalwareFamily.name.label("malware_name"),
                func.count(func.distinct(EntryThreatActor.entry_id)).label("co_occurrences"),
            )
            .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
            .join(EntryMalware, EntryMalware.entry_id == EntryThreatActor.entry_id)
            .join(MalwareFamily, MalwareFamily.id == EntryMalware.malware_family_id)
            .where(EntryThreatActor.entry_id.in_(in_window_entries))
            .group_by(ThreatActor.id, ThreatActor.name, MalwareFamily.id, MalwareFamily.name)
            .order_by(func.count(func.distinct(EntryThreatActor.entry_id)).desc())
            .limit(limit)
        )
        am_rows = (await db.execute(actor_malware_q)).all()

        results: list[dict] = [
            {
                "pair_type": "actor_malware",
                "actor_id": str(r.actor_id),
                "actor_name": r.actor_name,
                "malware_id": str(r.malware_id),
                "malware_name": r.malware_name,
                "co_occurrences": int(r.co_occurrences),
            }
            for r in am_rows
        ]

        if len(results) < limit:
            remaining = limit - len(results)
            actor_cve_q = (
                select(
                    ThreatActor.id.label("actor_id"),
                    ThreatActor.name.label("actor_name"),
                    CVE.id.label("cve_uuid"),
                    CVE.cve_id.label("cve_id"),
                    func.count(func.distinct(EntryThreatActor.entry_id)).label("co_occurrences"),
                )
                .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
                .join(EntryCVE, EntryCVE.entry_id == EntryThreatActor.entry_id)
                .join(CVE, CVE.id == EntryCVE.cve_id)
                .where(EntryThreatActor.entry_id.in_(in_window_entries))
                .group_by(ThreatActor.id, ThreatActor.name, CVE.id, CVE.cve_id)
                .order_by(func.count(func.distinct(EntryThreatActor.entry_id)).desc())
                .limit(remaining)
            )
            ac_rows = (await db.execute(actor_cve_q)).all()
            for r in ac_rows:
                results.append(
                    {
                        "pair_type": "actor_cve",
                        "actor_id": str(r.actor_id),
                        "actor_name": r.actor_name,
                        "cve_id": r.cve_id,
                        "cve_uuid": str(r.cve_uuid),
                        "co_occurrences": int(r.co_occurrences),
                    }
                )

        results.sort(key=lambda x: x["co_occurrences"], reverse=True)
        return results[:limit]
    except Exception as exc:
        logger.exception("Error in hot_correlations widget")
        raise AppError(
            code="widget_error",
            message="Failed to load hot correlations widget",
            status_code=500,
        ) from exc
