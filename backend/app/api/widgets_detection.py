"""Detection-focused widget endpoints (rule format breakdown, ATT&CK gap, KEV matches)."""

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.widgets import _parse_date_range
from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.ttp import TTP, EntryTTP
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/detection-format-breakdown")
async def detection_format_breakdown(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Detection rule counts grouped by rule format for rules created in the window."""
    try:
        start, end = _parse_date_range(date_from, date_to)
        result = await db.execute(
            select(DetectionRule.rule_type, func.count(DetectionRule.id).label("count"))
            .where(DetectionRule.created_at >= start, DetectionRule.created_at <= end)
            .group_by(DetectionRule.rule_type)
            .order_by(func.count(DetectionRule.id).desc())
        )
        return [{"rule_type": row.rule_type, "count": row.count} for row in result.all()]
    except Exception as exc:
        logger.exception("Error in detection_format_breakdown widget")
        raise AppError(
            code="widget_error",
            message="Failed to load detection format breakdown widget",
            status_code=500,
        ) from exc


@router.get("/attack-coverage-gap")
async def attack_coverage_gap(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    limit: int = Query(15, ge=1, le=200, description="Maximum number of techniques to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Most-mentioned ATT&CK techniques whose entries have no detection rule — the top coverage gaps."""
    try:
        start, end = _parse_date_range(date_from, date_to)
        covered_entries = select(DetectionRule.entry_id).where(DetectionRule.entry_id.is_not(None))
        result = await db.execute(
            select(
                TTP.id.label("ttp_id"),
                TTP.technique_id,
                TTP.technique_name,
                TTP.tactic,
                func.count(func.distinct(EntryTTP.entry_id)).label("mention_count"),
            )
            .join(TTP, TTP.id == EntryTTP.ttp_id)
            .where(
                EntryTTP.extracted_at >= start,
                EntryTTP.extracted_at <= end,
                ~EntryTTP.entry_id.in_(covered_entries),
            )
            .group_by(TTP.id, TTP.technique_id, TTP.technique_name, TTP.tactic)
            .order_by(func.count(func.distinct(EntryTTP.entry_id)).desc())
            .limit(limit)
        )
        return [
            {
                "ttp_id": str(row.ttp_id),
                "technique_id": row.technique_id,
                "technique_name": row.technique_name,
                "tactic": row.tactic,
                "mention_count": int(row.mention_count or 0),
            }
            for row in result.all()
        ]
    except Exception as exc:
        logger.exception("Error in attack_coverage_gap widget")
        raise AppError(
            code="widget_error",
            message="Failed to load attack coverage gap widget",
            status_code=500,
        ) from exc


@router.get("/kev-matches")
async def kev_matches(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    limit: int = Query(15, ge=1, le=200, description="Maximum number of CVEs to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """CVEs mentioned in the window that are marked as actively exploited, ranked by mention count."""
    try:
        start, end = _parse_date_range(date_from, date_to)
        window_cves = select(EntryCVE.cve_id).where(EntryCVE.extracted_at >= start, EntryCVE.extracted_at <= end)
        mention_subq = (
            select(
                EntryCVE.cve_id,
                func.count(func.distinct(EntryCVE.entry_id)).label("mention_count"),
            )
            .where(EntryCVE.extracted_at >= start, EntryCVE.extracted_at <= end)
            .group_by(EntryCVE.cve_id)
            .subquery()
        )
        result = await db.execute(
            select(CVE, mention_subq.c.mention_count)
            .join(mention_subq, mention_subq.c.cve_id == CVE.id)
            .where(
                CVE.id.in_(window_cves),
                or_(
                    CVE.exploit_status == "active_exploitation",
                    CVE.exploit_availability == "active_exploitation",
                ),
            )
            .order_by(mention_subq.c.mention_count.desc(), CVE.cvss_score.desc())
            .limit(limit)
        )
        return [
            {
                "id": str(cve.id),
                "cve_id": cve.cve_id,
                "cvss_score": float(cve.cvss_score) if cve.cvss_score is not None else None,
                "epss_score": float(cve.epss_score) if cve.epss_score is not None else None,
                "exploit_status": cve.exploit_status,
                "exploit_availability": cve.exploit_availability,
                "is_kev": bool(cve.is_kev),
                "kev_due_date": cve.kev_due_date.isoformat() if cve.kev_due_date else None,
                "mention_count": int(mention_count or 0),
                "first_seen_at": cve.first_seen_at.isoformat() if cve.first_seen_at else None,
            }
            for cve, mention_count in result.all()
        ]
    except Exception as exc:
        logger.exception("Error in kev_matches widget")
        raise AppError(
            code="widget_error",
            message="Failed to load KEV matches widget",
            status_code=500,
        ) from exc
