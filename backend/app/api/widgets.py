"""Widget data API — aggregated data for dashboard widgets."""

import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Date, case, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user, get_viewer
from app.database import get_db
from app.models.automation_log import AutomationLog
from app.models.automation_rule import AutomationRule
from app.models.correlation_event import CorrelationEventRecord
from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP
from app.models.user import User
from app.services.read_state import unread_by_user

logger = logging.getLogger(__name__)

router = APIRouter()


def _parse_date_range(date_from: str | None, date_to: str | None, default_days: int = 30) -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    if date_to:
        end = datetime.fromisoformat(date_to).replace(tzinfo=UTC)
    else:
        end = now
    if date_from:
        start = datetime.fromisoformat(date_from).replace(tzinfo=UTC)
    else:
        start = end - timedelta(days=default_days)
    return start, end


@router.get("/feed-activity")
async def feed_activity(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Daily entry counts across active feeds within the window, for the feed activity chart."""
    try:
        start, end = _parse_date_range(date_from, date_to)
        from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query

        # include_muted: this chart has always counted every active feed,
        # muted ones included — it reports what the instance ingested, not what
        # reaches the unread list. Subscriptions scope it; mute does not.
        feed_q = visible_feed_ids_query(
            user.id, enabled=await subscriptions_enabled(db), active_only=True, include_muted=True
        )
        result = await db.execute(
            select(
                cast(Entry.published_at, Date).label("day"),
                func.count(Entry.id).label("count"),
            )
            .where(Entry.feed_id.in_(feed_q), Entry.published_at >= start, Entry.published_at <= end)
            .group_by("day")
            .order_by("day")
        )
        return [{"date": str(row.day), "count": row.count} for row in result.all()]
    except Exception as exc:
        logger.exception("Error in feed_activity widget")
        raise AppError(
            code="widget_error",
            message="Failed to load feed_activity widget",
            status_code=500,
        ) from exc


@router.get("/cve-severity")
async def cve_severity(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Counts of CVEs first seen in the window, bucketed by CVSS severity (critical/high/medium/low)."""
    try:
        start, end = _parse_date_range(date_from, date_to)
        severity_case = case(
            (CVE.cvss_score >= 9.0, "critical"),
            (CVE.cvss_score >= 7.0, "high"),
            (CVE.cvss_score >= 4.0, "medium"),
            else_="low",
        ).label("severity")
        result = await db.execute(
            select(severity_case, func.count(CVE.id).label("count"))
            .where(CVE.first_seen_at >= start, CVE.first_seen_at <= end)
            .group_by(severity_case)
        )
        return [{"severity": row.severity, "count": row.count} for row in result.all()]
    except Exception as exc:
        logger.exception("Error in cve_severity widget")
        raise AppError(
            code="widget_error",
            message="Failed to load cve_severity widget",
            status_code=500,
        ) from exc


@router.get("/threat-timeline")
async def threat_timeline(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Per-actor daily entry mention counts (links extracted in the window) for the threat timeline chart."""
    try:
        start, end = _parse_date_range(date_from, date_to)
        result = await db.execute(
            select(
                ThreatActor.name,
                cast(EntryThreatActor.extracted_at, Date).label("day"),
                func.count(EntryThreatActor.entry_id).label("count"),
            )
            .join(ThreatActor, ThreatActor.id == EntryThreatActor.threat_actor_id)
            .where(EntryThreatActor.extracted_at >= start, EntryThreatActor.extracted_at <= end)
            .group_by(ThreatActor.name, "day")
            .order_by("day")
        )
        return [{"actor": row.name, "date": str(row.day), "count": row.count} for row in result.all()]
    except Exception as exc:
        logger.exception("Error in threat_timeline widget")
        raise AppError(
            code="widget_error",
            message="Failed to load threat_timeline widget",
            status_code=500,
        ) from exc


@router.get("/trending-cves")
async def trending_cves(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 7 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    limit: int = Query(10, ge=1, le=500, description="Maximum number of CVEs to return."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """CVEs ranked by number of entry mentions extracted in the window (default last 7 days)."""
    try:
        start, end = _parse_date_range(date_from, date_to, default_days=7)
        result = await db.execute(
            select(
                CVE.id,
                CVE.cve_id,
                CVE.cvss_score,
                CVE.description,
                func.count(EntryCVE.entry_id).label("mention_count"),
            )
            .join(CVE, CVE.id == EntryCVE.cve_id)
            .where(EntryCVE.extracted_at >= start, EntryCVE.extracted_at <= end)
            .group_by(CVE.id, CVE.cve_id, CVE.cvss_score, CVE.description)
            .order_by(func.count(EntryCVE.entry_id).desc())
            .limit(limit)
        )
        return [
            {
                "id": str(row.id),
                "cve_id": row.cve_id,
                "cvss_score": row.cvss_score,
                "description": row.description,
                "mention_count": row.mention_count,
            }
            for row in result.all()
        ]
    except Exception as exc:
        logger.exception("Error in trending_cves widget")
        raise AppError(
            code="widget_error",
            message="Failed to load trending_cves widget",
            status_code=500,
        ) from exc


@router.get("/new-cves")
async def new_cves(
    days: int = Query(7, ge=1, le=36500, description="Look-back window in days over CVE first-seen date."),
    limit: int = Query(20, ge=1, le=200, description="Maximum number of CVEs to return."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """CVEs first seen in the last N days, newest first, with total entry mention counts."""
    try:
        start = datetime.now(UTC) - timedelta(days=days)
        mention_count = func.count(EntryCVE.entry_id).label("mention_count")
        result = await db.execute(
            select(
                CVE.id,
                CVE.cve_id,
                CVE.cvss_score,
                CVE.exploit_availability,
                CVE.first_seen_at,
                mention_count,
            )
            .outerjoin(EntryCVE, EntryCVE.cve_id == CVE.id)
            .where(CVE.first_seen_at >= start)
            .group_by(CVE.id)
            .order_by(CVE.first_seen_at.desc())
            .limit(limit)
        )
        return [
            {
                "id": str(row.id),
                "cve_id": row.cve_id,
                "cvss_score": row.cvss_score,
                "exploit_availability": row.exploit_availability,
                "mention_count": row.mention_count,
                "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
            }
            for row in result.all()
        ]
    except Exception as exc:
        logger.exception("Error in new_cves widget")
        raise AppError(
            code="widget_error",
            message="Failed to load new_cves widget",
            status_code=500,
        ) from exc


@router.get("/attack-heatmap")
async def attack_heatmap(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Entry mention counts per ATT&CK technique (links extracted in the window) for the heatmap."""
    try:
        start, end = _parse_date_range(date_from, date_to)
        result = await db.execute(
            select(
                TTP.technique_id,
                TTP.technique_name,
                TTP.tactic,
                func.count(EntryTTP.entry_id).label("count"),
            )
            .join(TTP, TTP.id == EntryTTP.ttp_id)
            .where(EntryTTP.extracted_at >= start, EntryTTP.extracted_at <= end)
            .group_by(TTP.id, TTP.technique_id, TTP.technique_name, TTP.tactic)
            .order_by(func.count(EntryTTP.entry_id).desc())
        )
        return [
            {
                "technique_id": row.technique_id,
                "name": row.technique_name,
                "tactic": row.tactic,
                "count": row.count,
            }
            for row in result.all()
        ]
    except Exception as exc:
        logger.exception("Error in attack_heatmap widget")
        raise AppError(
            code="widget_error",
            message="Failed to load attack_heatmap widget",
            status_code=500,
        ) from exc


@router.get("/stats")
async def widget_stats(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 7 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Entry, new-CVE, and unread counts for the window, with percent trend vs the preceding equal-length window."""
    try:
        start, end = _parse_date_range(date_from, date_to, default_days=7)
        prev_start = start - (end - start)

        from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query

        feed_q = visible_feed_ids_query(user.id, enabled=await subscriptions_enabled(db), active_only=True)

        entries_count = (
            await db.execute(
                select(func.count(Entry.id)).where(
                    Entry.feed_id.in_(feed_q), Entry.published_at >= start, Entry.published_at <= end
                )
            )
        ).scalar() or 0

        cves_count = (
            await db.execute(select(func.count(CVE.id)).where(CVE.first_seen_at >= start, CVE.first_seen_at <= end))
        ).scalar() or 0

        prev_entries = (
            await db.execute(
                select(func.count(Entry.id)).where(
                    Entry.feed_id.in_(feed_q), Entry.published_at >= prev_start, Entry.published_at < start
                )
            )
        ).scalar() or 0

        prev_cves = (
            await db.execute(
                select(func.count(CVE.id)).where(CVE.first_seen_at >= prev_start, CVE.first_seen_at < start)
            )
        ).scalar() or 0

        unread_count = (
            await db.execute(
                select(func.count(Entry.id)).where(
                    Entry.feed_id.in_(feed_q),
                    unread_by_user(user.id),
                )
            )
        ).scalar() or 0

        def trend(current: int, previous: int) -> float:
            if previous == 0:
                return 100.0 if current > 0 else 0.0
            return round(((current - previous) / previous) * 100, 1)

        return {
            "entries": {"count": entries_count, "trend": trend(entries_count, prev_entries)},
            "cves": {"count": cves_count, "trend": trend(cves_count, prev_cves)},
            "unread": {"count": unread_count},
        }
    except Exception as exc:
        logger.exception("Error in widget_stats widget")
        raise AppError(
            code="widget_error",
            message="Failed to load widget_stats widget",
            status_code=500,
        ) from exc


@router.get("/new-actors")
async def new_actors(
    days: int = Query(7, ge=1, le=36500, description="Look-back window in days."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Threat actors first seen in the last N days."""
    try:
        cutoff = datetime.now(UTC) - timedelta(days=days)
        result = await db.execute(
            select(ThreatActor)
            .where(ThreatActor.first_seen_at >= cutoff)
            .order_by(ThreatActor.first_seen_at.desc())
            .limit(20)
        )
        return [
            {
                "id": str(a.id),
                "name": a.name,
                "country": a.country,
                "motivation": a.motivation,
                "article_count": a.article_count,
                "first_seen_at": a.first_seen_at.isoformat() if a.first_seen_at else None,
            }
            for a in result.scalars().all()
        ]
    except Exception as exc:
        logger.exception("Error in new_actors widget")
        raise AppError(
            code="widget_error",
            message="Failed to load new_actors widget",
            status_code=500,
        ) from exc


@router.get("/detection-coverage")
async def detection_coverage(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Percentage of observed TTPs that have at least one detection rule."""
    try:
        total_ttps = (await db.execute(select(func.count()).select_from(TTP))).scalar() or 0
        covered_ttps = (
            await db.execute(
                select(func.count(func.distinct(EntryTTP.ttp_id))).where(
                    EntryTTP.entry_id.in_(select(DetectionRule.entry_id).where(DetectionRule.entry_id.is_not(None)))
                )
            )
        ).scalar() or 0
        coverage_pct = round(covered_ttps / max(total_ttps, 1) * 100, 1)
        return {
            "total_ttps": total_ttps,
            "covered_ttps": covered_ttps,
            "coverage_pct": coverage_pct,
        }
    except Exception as exc:
        logger.exception("Error in detection_coverage widget")
        raise AppError(
            code="widget_error",
            message="Failed to load detection_coverage widget",
            status_code=500,
        ) from exc


@router.get("/correlation-events")
async def recent_correlation_events(
    limit: int = Query(10, ge=1, le=500, description="Maximum number of events to return."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Recent correlation events for widget display."""
    try:
        # Global scope (no user filter) matches /api/intelligence/correlation-events.
        # Exclude feed-health events (feed_error, feed_stale) — they have no entry_id
        # and aren't true correlation events.
        excluded_types = ("feed_error", "feed_stale")
        result = await db.execute(
            select(CorrelationEventRecord, Entry.title)
            .join(Entry, Entry.id == CorrelationEventRecord.entry_id, isouter=True)
            .where(CorrelationEventRecord.event_type.notin_(excluded_types))
            .order_by(CorrelationEventRecord.created_at.desc())
            .limit(limit)
        )
        return [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "context": e.context,
                "is_read": e.is_read,
                "created_at": e.created_at.isoformat() if e.created_at else None,
                "entry_id": str(e.entry_id) if e.entry_id else None,
                "entry_title": title,
            }
            for e, title in result.all()
        ]
    except Exception as exc:
        logger.exception("Error in correlation_events widget")
        raise AppError(
            code="widget_error",
            message="Failed to load correlation_events widget",
            status_code=500,
        ) from exc


@router.get("/new-detections")
async def new_detections(
    limit: int = Query(15, ge=1, le=100, description="Maximum number of rules to return."),
    days: int = Query(7, ge=1, le=36500, description="Look-back window in days."),
    include_drafts: bool = Query(True, description="Include draft rules; set false for published rules only."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Recently created detection rules for triage dashboard widget."""
    try:
        cutoff = datetime.now(UTC) - timedelta(days=days)
        query = (
            select(DetectionRule, Entry.title.label("entry_title"))
            .join(Entry, Entry.id == DetectionRule.entry_id, isouter=True)
            .where(DetectionRule.created_at >= cutoff)
        )
        if not include_drafts:
            query = query.where(DetectionRule.is_draft.is_(False))
        query = query.order_by(DetectionRule.created_at.desc()).limit(limit)

        result = await db.execute(query)
        rules = []
        draft_count = 0
        published_count = 0
        for rule, entry_title in result.all():
            if rule.is_draft:
                draft_count += 1
            else:
                published_count += 1
            rules.append(
                {
                    "id": str(rule.id),
                    "title": rule.title,
                    "rule_type": rule.rule_type,
                    "severity": rule.severity,
                    "is_draft": rule.is_draft,
                    "tags": rule.tags or [],
                    "entry_id": str(rule.entry_id) if rule.entry_id else None,
                    "entry_title": entry_title,
                    "created_at": rule.created_at.isoformat() if rule.created_at else None,
                }
            )

        return {
            "summary": {
                "total": len(rules),
                "draft": draft_count,
                "published": published_count,
                "window_days": days,
            },
            "rules": rules,
        }
    except Exception as exc:
        logger.exception("Error in new_detections widget")
        raise AppError(
            code="widget_error",
            message="Failed to load new_detections widget",
            status_code=500,
        ) from exc


@router.get("/automation-logs")
async def automation_logs_widget(
    limit: int = Query(15, ge=1, le=100, description="Maximum number of log rows to return."),
    status: str | None = Query(None, description="Filter logs by execution status (success, error, skipped)."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Recent automation execution logs with summary stats for dashboard widget."""
    try:
        # Only logs for rules created by this user
        user_rule_ids = select(AutomationRule.id).where(AutomationRule.created_by == user.id)

        # Summary counts (last 24h)
        last_24h = datetime.now(UTC) - timedelta(hours=24)
        summary_q = (
            select(AutomationLog.status, func.count().label("count"))
            .where(AutomationLog.rule_id.in_(user_rule_ids), AutomationLog.executed_at >= last_24h)
            .group_by(AutomationLog.status)
        )
        summary_result = await db.execute(summary_q)
        summary = {row.status: row.count for row in summary_result.all()}

        # Recent logs
        logs_q = (
            select(AutomationLog, AutomationRule.name.label("rule_name"))
            .join(AutomationRule, AutomationRule.id == AutomationLog.rule_id)
            .where(AutomationLog.rule_id.in_(user_rule_ids))
        )
        if status:
            logs_q = logs_q.where(AutomationLog.status == status)
        logs_q = logs_q.order_by(AutomationLog.executed_at.desc()).limit(limit)

        result = await db.execute(logs_q)
        logs = [
            {
                "id": str(log.id),
                "rule_id": str(log.rule_id),
                "rule_name": rule_name,
                "trigger_type": log.trigger_type,
                "status": log.status,
                "actions_executed": log.actions_executed or [],
                "error_message": log.error_message,
                "executed_at": log.executed_at.isoformat() if log.executed_at else None,
            }
            for log, rule_name in result.all()
        ]

        return {
            "summary": {
                "success": summary.get("success", 0),
                "error": summary.get("error", 0),
                "skipped": summary.get("skipped", 0),
                "total_24h": sum(summary.values()),
            },
            "logs": logs,
        }
    except Exception as exc:
        logger.exception("Error in automation_logs widget")
        raise AppError(
            code="widget_error",
            message="Failed to load automation_logs widget",
            status_code=500,
        ) from exc
