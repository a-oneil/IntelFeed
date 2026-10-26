"""Dashboard board widgets — round-2 widget data endpoints.

Everything here is a thin aggregate over data other subsystems already
maintain: the signal engine, the ransomware tracker, the relationship trust
ladder, KEV enrichment, per-user read state, campaigns, and the daily-summary
AI pipeline. No new tables; no migrations.
"""

import logging
from collections import defaultdict, namedtuple
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Date, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.widgets import _parse_date_range
from app.api.widgets_strategic import _trend_pct
from app.core.exceptions import AppError
from app.core.security import get_current_user, get_viewer
from app.database import get_db
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.campaign import Campaign, CampaignEntry
from app.models.country import Country, EntryCountry
from app.models.cve import CVE, EntryCVE
from app.models.cwe import CWE
from app.models.detection_rule import DetectionRule
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.entry_signal import EntrySignal
from app.models.entry_state import UserEntryState
from app.models.malware_family import MalwareFamily
from app.models.mitigation import Mitigation
from app.models.product import Product
from app.models.ransomware import VictimDisclosure
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import Tool
from app.models.ttp import TTP, EntryTTP
from app.models.user import User
from app.models.user_entity_watch import UserEntityWatch
from app.models.vendor import Vendor
from app.services.read_state import unread_by_user

logger = logging.getLogger(__name__)

router = APIRouter()


async def _active_feed_ids(db, user_id):
    """Subquery of feeds that count toward triage numbers (active, unmuted for this user)."""
    from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query

    return visible_feed_ids_query(user_id, enabled=await subscriptions_enabled(db), active_only=True)


def _day_grid(start: datetime, end: datetime) -> list[date]:
    days: list[date] = []
    cur = start.date()
    while cur <= end.date():
        days.append(cur)
        cur += timedelta(days=1)
    return days


def _week_grid(start: datetime, end: datetime) -> list[date]:
    """Monday-aligned week starts covering [start, end], current week included."""
    cur = start.date() - timedelta(days=start.date().weekday())
    stop = end.date() - timedelta(days=end.date().weekday())
    weeks: list[date] = []
    while cur <= stop:
        weeks.append(cur)
        cur += timedelta(days=7)
    return weeks


# ── Overview ────────────────────────────────────────────────────────────────

# Workbench entity types whose "new in window" is defined by first_seen_at.
# Country is handled separately (a closed set — "new" means newly targeted).
_ENTITY_FIRST_SEEN: list[tuple[str, type]] = [
    ("threat_actor", ThreatActor),
    ("malware", MalwareFamily),
    ("tool", Tool),
    ("cve", CVE),
    ("ttp", TTP),
    ("vendor", Vendor),
    ("product", Product),
]


@router.get("/overview")
async def board_overview(
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_viewer),
):
    """Headline strip + per-entity-type new counts with prior-window trends."""
    try:
        start, end = _parse_date_range(date_from, date_to, default_days=7)
        span = end - start
        prev_start = start - span
        feed_q = await _active_feed_ids(db, user.id)

        async def _count(stmt) -> int:
            return int((await db.execute(stmt)).scalar() or 0)

        entries_count = await _count(
            select(func.count(Entry.id)).where(
                Entry.feed_id.in_(feed_q), Entry.published_at >= start, Entry.published_at <= end
            )
        )
        prev_entries = await _count(
            select(func.count(Entry.id)).where(
                Entry.feed_id.in_(feed_q), Entry.published_at >= prev_start, Entry.published_at < start
            )
        )
        unread_count = await _count(
            select(func.count(Entry.id)).where(
                Entry.feed_id.in_(feed_q),
                unread_by_user(user.id),
            )
        )
        detections_count = await _count(
            select(func.count(DetectionRule.id)).where(
                DetectionRule.created_at >= start, DetectionRule.created_at <= end
            )
        )
        prev_detections = await _count(
            select(func.count(DetectionRule.id)).where(
                DetectionRule.created_at >= prev_start, DetectionRule.created_at < start
            )
        )

        # Radar hits reuse the Priority Queue badge logic verbatim.
        from app.api.entries import priority_unread_count

        radar_count = (await priority_unread_count(user=user, db=db))["unread_count"]

        entities = []
        for slug, model in _ENTITY_FIRST_SEEN:
            cur = await _count(
                select(func.count(model.id)).where(model.first_seen_at >= start, model.first_seen_at <= end)
            )
            prev = await _count(
                select(func.count(model.id)).where(model.first_seen_at >= prev_start, model.first_seen_at < start)
            )
            entities.append({"type": slug, "count": cur, "trend": _trend_pct(cur, prev)})

        # Countries: distinct countries linked to entries in the window.
        cur_countries = await _count(
            select(func.count(func.distinct(EntryCountry.country_id)))
            .select_from(EntryCountry)
            .join(Entry, Entry.id == EntryCountry.entry_id)
            .where(Entry.published_at >= start, Entry.published_at <= end)
        )
        prev_countries = await _count(
            select(func.count(func.distinct(EntryCountry.country_id)))
            .select_from(EntryCountry)
            .join(Entry, Entry.id == EntryCountry.entry_id)
            .where(Entry.published_at >= prev_start, Entry.published_at < start)
        )
        entities.append({"type": "country", "count": cur_countries, "trend": _trend_pct(cur_countries, prev_countries)})

        # Daily sparkline series for entries + detections.
        day = cast(Entry.published_at, Date).label("day")
        entry_rows = (
            await db.execute(
                select(day, func.count(Entry.id))
                .where(Entry.feed_id.in_(feed_q), Entry.published_at >= start, Entry.published_at <= end)
                .group_by(day)
            )
        ).all()
        entry_by_day = {r[0]: int(r[1]) for r in entry_rows}
        det_day = cast(DetectionRule.created_at, Date).label("day")
        det_rows = (
            await db.execute(
                select(det_day, func.count(DetectionRule.id))
                .where(DetectionRule.created_at >= start, DetectionRule.created_at <= end)
                .group_by(det_day)
            )
        ).all()
        det_by_day = {r[0]: int(r[1]) for r in det_rows}
        grid = _day_grid(start, end)

        return {
            "headline": {
                "entries": {"count": entries_count, "trend": _trend_pct(entries_count, prev_entries)},
                "radar": {"count": int(radar_count)},
                "unread": {"count": unread_count},
                "detections": {"count": detections_count, "trend": _trend_pct(detections_count, prev_detections)},
            },
            "entities": entities,
            "series": {
                "entries": [{"date": d.isoformat(), "count": entry_by_day.get(d, 0)} for d in grid],
                "detections": [{"date": d.isoformat(), "count": det_by_day.get(d, 0)} for d in grid],
            },
        }
    except Exception as exc:
        logger.exception("Error in board overview widget")
        raise AppError(code="widget_error", message="Failed to load overview widget", status_code=500) from exc


# ── Watchlist pulse ─────────────────────────────────────────────────────────


@router.get("/watchlist-pulse")
async def watchlist_pulse(
    days: int = Query(14, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Watched entities with a daily mention series and a half-window delta."""
    try:
        from app.api.watchlist import _ENTITY_NAME_SOURCES
        from app.services.entity_names import resolve_entity_names
        from app.services.triage import _watch_junction_map

        end = datetime.now(UTC)
        start = end - timedelta(days=days)
        mid = end - timedelta(days=days // 2)

        watches = (
            (
                await db.execute(
                    select(UserEntityWatch).where(
                        UserEntityWatch.created_by == user.id, UserEntityWatch.mode == "watch"
                    )
                )
            )
            .scalars()
            .all()
        )
        if not watches:
            return {"items": [], "window_days": days}

        names = await resolve_entity_names(db, watches, _ENTITY_NAME_SOURCES)
        junctions = _watch_junction_map()

        by_type: dict[str, list] = defaultdict(list)
        for w in watches:
            by_type[w.entity_type].append(w.entity_id)

        # (entity_type, entity_id, date) -> count
        counts: dict[tuple[str, object, date], int] = {}
        for etype, ids in by_type.items():
            if etype not in junctions:
                continue
            junction, fk = junctions[etype]
            day = cast(Entry.published_at, Date).label("day")
            rows = (
                await db.execute(
                    select(fk.label("eid"), day, func.count(func.distinct(Entry.id)))
                    .select_from(junction)
                    .join(Entry, Entry.id == junction.entry_id)
                    .where(fk.in_(ids), Entry.published_at >= start, Entry.published_at <= end)
                    .group_by(fk, day)
                )
            ).all()
            for eid, d, count in rows:
                counts[(etype, eid, d)] = int(count)

        grid = _day_grid(start, end)
        items = []
        for w in watches:
            points = [counts.get((w.entity_type, w.entity_id, d), 0) for d in grid]
            recent = sum(c for d, c in zip(grid, points, strict=True) if d >= mid.date())
            prior = sum(points) - recent
            items.append(
                {
                    "entity_type": w.entity_type,
                    "entity_id": str(w.entity_id),
                    "name": names.get((w.entity_type, w.entity_id)) or "(unknown)",
                    "points": [{"date": d.isoformat(), "count": c} for d, c in zip(grid, points, strict=True)],
                    "total": sum(points),
                    "delta": recent - prior,
                }
            )
        items.sort(key=lambda i: (-i["delta"], -i["total"], i["name"]))
        return {"items": items, "window_days": days}
    except Exception as exc:
        logger.exception("Error in watchlist-pulse widget")
        raise AppError(code="widget_error", message="Failed to load watchlist-pulse widget", status_code=500) from exc


# ── Ransomware pulse ────────────────────────────────────────────────────────


@router.get("/ransomware-pulse")
async def ransomware_pulse(
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Weekly victim disclosures stacked by group (top 5 + Other)."""
    try:
        start, end = _parse_date_range(date_from, date_to, default_days=90)
        span = end - start
        prev_start = start - span

        top_rows = (
            await db.execute(
                select(VictimDisclosure.group_id, func.count().label("n"))
                .where(
                    VictimDisclosure.posted_at >= start,
                    VictimDisclosure.posted_at <= end,
                    VictimDisclosure.group_id.is_not(None),
                )
                .group_by(VictimDisclosure.group_id)
                .order_by(func.count().desc())
                .limit(5)
            )
        ).all()
        top_ids = [r[0] for r in top_rows]
        name_rows = (
            (await db.execute(select(ThreatActor.id, ThreatActor.name).where(ThreatActor.id.in_(top_ids)))).all()
            if top_ids
            else []
        )
        group_names = {gid: name for gid, name in name_rows}

        wk = func.date_trunc("week", VictimDisclosure.posted_at).label("wk")
        rows = (
            await db.execute(
                select(wk, VictimDisclosure.group_id, func.count())
                .where(VictimDisclosure.posted_at >= start, VictimDisclosure.posted_at <= end)
                .group_by(wk, VictimDisclosure.group_id)
            )
        ).all()

        weeks = _week_grid(start, end)
        # week_start -> group label -> count
        stacked: dict[date, dict[str, int]] = {w: defaultdict(int) for w in weeks}
        for wk_dt, gid, count in rows:
            wk_date = wk_dt.date() if isinstance(wk_dt, datetime) else wk_dt
            if wk_date not in stacked:
                continue
            label = group_names.get(gid, "Other") if gid in group_names else "Other"
            stacked[wk_date][label] += int(count)

        total = sum(sum(g.values()) for g in stacked.values())
        prev_total = int(
            (
                await db.execute(
                    select(func.count()).where(
                        VictimDisclosure.posted_at >= prev_start, VictimDisclosure.posted_at < start
                    )
                )
            ).scalar()
            or 0
        )
        groups_active = int(
            (
                await db.execute(
                    select(func.count(func.distinct(VictimDisclosure.group_id))).where(
                        VictimDisclosure.posted_at >= start,
                        VictimDisclosure.posted_at <= end,
                        VictimDisclosure.group_id.is_not(None),
                    )
                )
            ).scalar()
            or 0
        )

        ordered_groups = [group_names[g] for g in top_ids] + ["Other"]
        return {
            "weeks": [
                {
                    "week_start": w.isoformat(),
                    "label": w.strftime("%b %-d") if hasattr(w, "strftime") else str(w),
                    "total": sum(stacked[w].values()),
                    "groups": {g: stacked[w].get(g, 0) for g in ordered_groups},
                }
                for w in weeks
            ],
            "groups": ordered_groups,
            "totals": {
                "victims": total,
                "trend": _trend_pct(total, prev_total),
                "groups_active": groups_active,
            },
        }
    except Exception as exc:
        logger.exception("Error in ransomware-pulse widget")
        raise AppError(code="widget_error", message="Failed to load ransomware-pulse widget", status_code=500) from exc


# ── Rules needing attention ─────────────────────────────────────────────────


@router.get("/rules-attention")
async def rules_attention(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Published rules ranked by fresh intel landed since their last update.

    Single-pass variant of /detection-rules/needing-review: one rule query, one
    TTP/CVE resolve each, one evidence sweep each — no per-rule N+1.
    """
    try:
        from app.api.intelligence import _rule_cve_strings, _rule_technique_strings

        now = datetime.now(UTC)
        floor = now - timedelta(days=120)

        rules = (
            await db.execute(
                select(
                    DetectionRule.id,
                    DetectionRule.title,
                    DetectionRule.rule_type,
                    DetectionRule.severity,
                    DetectionRule.updated_at,
                    DetectionRule.source_ttps,
                    DetectionRule.source_cves,
                ).where(DetectionRule.is_draft.is_(False))
            )
        ).all()
        if not rules:
            return {"items": [], "total_rules": 0, "stale_count": 0, "window_days": 120}

        all_techniques: set[str] = set()
        all_cves: set[str] = set()
        parsed: list[tuple] = []
        for r in rules:
            techniques = _rule_technique_strings(r.source_ttps)
            cves = _rule_cve_strings(r.source_cves)
            all_techniques.update(techniques)
            all_cves.update(cves)
            parsed.append((r, techniques, cves))

        ttp_id_by_technique: dict[str, object] = {}
        if all_techniques:
            for tid, technique in (
                await db.execute(select(TTP.id, TTP.technique_id).where(TTP.technique_id.in_(all_techniques)))
            ).all():
                ttp_id_by_technique[technique] = tid
        cve_id_by_string: dict[str, object] = {}
        if all_cves:
            for cid, cve_str in (await db.execute(select(CVE.id, CVE.cve_id).where(CVE.cve_id.in_(all_cves)))).all():
                cve_id_by_string[cve_str] = cid

        # entity id -> [(entry_id, published_at)]
        ttp_entries: dict[object, list[tuple]] = defaultdict(list)
        if ttp_id_by_technique:
            for tid, eid, pub in (
                await db.execute(
                    select(EntryTTP.ttp_id, EntryTTP.entry_id, Entry.published_at)
                    .join(Entry, Entry.id == EntryTTP.entry_id)
                    .where(EntryTTP.ttp_id.in_(list(ttp_id_by_technique.values())), Entry.published_at >= floor)
                )
            ).all():
                ttp_entries[tid].append((eid, pub))
        cve_entries: dict[object, list[tuple]] = defaultdict(list)
        if cve_id_by_string:
            for cid, eid, pub in (
                await db.execute(
                    select(EntryCVE.cve_id, EntryCVE.entry_id, Entry.published_at)
                    .join(Entry, Entry.id == EntryCVE.entry_id)
                    .where(EntryCVE.cve_id.in_(list(cve_id_by_string.values())), Entry.published_at >= floor)
                )
            ).all():
                cve_entries[cid].append((eid, pub))

        items = []
        for r, techniques, cves in parsed:
            since = r.updated_at
            fresh: set = set()
            for technique in techniques:
                tid = ttp_id_by_technique.get(technique)
                if tid is None:
                    continue
                fresh.update(eid for eid, pub in ttp_entries[tid] if pub is not None and pub > since)
            for cve_str in cves:
                cid = cve_id_by_string.get(cve_str)
                if cid is None:
                    continue
                fresh.update(eid for eid, pub in cve_entries[cid] if pub is not None and pub > since)
            if fresh:
                items.append(
                    {
                        "rule_id": str(r.id),
                        "title": r.title,
                        "rule_type": r.rule_type,
                        "severity": r.severity,
                        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
                        "new_intel_count": len(fresh),
                    }
                )
        items.sort(key=lambda i: -i["new_intel_count"])
        return {
            "items": items[:limit],
            "total_rules": len(rules),
            "stale_count": len(items),
            "window_days": 120,
        }
    except Exception as exc:
        logger.exception("Error in rules-attention widget")
        raise AppError(code="widget_error", message="Failed to load rules-attention widget", status_code=500) from exc


# ── Targeting grid ──────────────────────────────────────────────────────────


@router.get("/targeting-grid")
async def targeting_grid(
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Sector × region victim-disclosure intensity."""
    try:
        from app.intelligence.sectors import sector_label

        start, end = _parse_date_range(date_from, date_to, default_days=30)
        rows = (
            await db.execute(
                select(VictimDisclosure.sector, Country.region, func.count())
                .select_from(VictimDisclosure)
                .join(Country, Country.id == VictimDisclosure.country_id, isouter=True)
                .where(
                    VictimDisclosure.posted_at >= start,
                    VictimDisclosure.posted_at <= end,
                    VictimDisclosure.sector.is_not(None),
                )
                .group_by(VictimDisclosure.sector, Country.region)
            )
        ).all()

        region_totals: dict[str, int] = defaultdict(int)
        sector_totals: dict[str, int] = defaultdict(int)
        cell: dict[tuple[str, str], int] = defaultdict(int)
        for sector, region, count in rows:
            region = region or "Other"
            cell[(sector, region)] += int(count)
            region_totals[region] += int(count)
            sector_totals[sector] += int(count)

        top_regions = [r for r, _ in sorted(region_totals.items(), key=lambda kv: -kv[1]) if r != "Other"][:5]
        fold_other = set(region_totals) - set(top_regions)
        regions = top_regions + (["Other"] if fold_other else [])

        top_sectors = [s for s, _ in sorted(sector_totals.items(), key=lambda kv: -kv[1])][:8]
        out_rows = []
        max_cell = 0
        for sector in top_sectors:
            cells = []
            for region in regions:
                if region == "Other":
                    n = sum(cell.get((sector, r), 0) for r in fold_other)
                else:
                    n = cell.get((sector, region), 0)
                max_cell = max(max_cell, n)
                cells.append(n)
            out_rows.append(
                {"sector": sector, "label": sector_label(sector), "cells": cells, "total": sector_totals[sector]}
            )
        return {"regions": regions, "rows": out_rows, "max_cell": max_cell}
    except Exception as exc:
        logger.exception("Error in targeting-grid widget")
        raise AppError(code="widget_error", message="Failed to load targeting-grid widget", status_code=500) from exc


# ── KEV deadlines ───────────────────────────────────────────────────────────


@router.get("/kev-deadlines")
async def kev_deadlines(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_viewer),
):
    """KEV-listed CVEs with CISA remediation due dates, soonest first."""
    try:
        today = date.today()
        cves = (
            (
                await db.execute(
                    select(CVE)
                    .where(
                        CVE.is_kev.is_(True),
                        CVE.kev_due_date.is_not(None),
                        CVE.kev_due_date >= today - timedelta(days=14),
                    )
                    .order_by(CVE.kev_due_date.asc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        items = []
        due_7d = 0
        for cve in cves:
            kev_record = next(
                (s for s in (cve.exploit_sources or []) if isinstance(s, dict) and s.get("source") == "kev"),
                {},
            )
            days_left = (cve.kev_due_date - today).days
            if 0 <= days_left <= 7:
                due_7d += 1
            items.append(
                {
                    "id": str(cve.id),
                    "cve_id": cve.cve_id,
                    "kev_due_date": cve.kev_due_date.isoformat(),
                    "kev_date_added": cve.kev_date_added.isoformat() if cve.kev_date_added else None,
                    "days_left": days_left,
                    "cvss_score": float(cve.cvss_score) if cve.cvss_score is not None else None,
                    "vendor": kev_record.get("vendorProject"),
                    "product": kev_record.get("product"),
                    "name": kev_record.get("vulnerabilityName"),
                }
            )
        return {"items": items, "due_7d": due_7d}
    except Exception as exc:
        logger.exception("Error in kev-deadlines widget")
        raise AppError(code="widget_error", message="Failed to load kev-deadlines widget", status_code=500) from exc


# ── Triage flow ─────────────────────────────────────────────────────────────


@router.get("/triage-flow")
async def triage_flow(
    days: int = Query(14, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_viewer),
):
    """Entries arriving vs entries the user read, per day, plus the backlog."""
    try:
        end = datetime.now(UTC)
        # Align to calendar-day boundaries: an unaligned start makes the leftmost
        # column a partial day, which always reads as a phantom quiet day.
        start = (end - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        feed_q = await _active_feed_ids(db, user.id)

        # Arrival is when we fetched it, not when the author published it — most
        # entries land with a backdated published_at, so publish dates undercount
        # intake badly and can't be balanced against reads.
        day = cast(Entry.fetched_at, Date).label("day")
        arrived_rows = (
            await db.execute(
                select(day, func.count(Entry.id))
                .where(Entry.feed_id.in_(feed_q), Entry.fetched_at >= start, Entry.fetched_at <= end)
                .group_by(day)
            )
        ).all()
        arrived = {r[0]: int(r[1]) for r in arrived_rows}

        rday = cast(UserEntryState.read_at, Date).label("day")
        read_rows = (
            await db.execute(
                select(rday, func.count(UserEntryState.id))
                .where(
                    UserEntryState.user_id == user.id,
                    UserEntryState.is_read.is_(True),
                    UserEntryState.read_at >= start,
                    UserEntryState.read_at <= end,
                )
                .group_by(rday)
            )
        ).all()
        read = {r[0]: int(r[1]) for r in read_rows}

        backlog = int(
            (
                await db.execute(
                    select(func.count(Entry.id)).where(
                        Entry.feed_id.in_(feed_q),
                        unread_by_user(user.id),
                    )
                )
            ).scalar()
            or 0
        )

        grid = _day_grid(start, end)
        return {
            "days": [{"date": d.isoformat(), "arrived": arrived.get(d, 0), "read": read.get(d, 0)} for d in grid],
            "backlog": backlog,
        }
    except Exception as exc:
        logger.exception("Error in triage-flow widget")
        raise AppError(code="widget_error", message="Failed to load triage-flow widget", status_code=500) from exc


# ── Campaign momentum ───────────────────────────────────────────────────────


@router.get("/campaign-momentum")
async def campaign_momentum(
    limit: int = Query(6, ge=1, le=20),
    weeks: int = Query(8, ge=4, le=26),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Non-closed campaigns as weekly activity strips."""
    try:
        end = datetime.now(UTC)
        start = end - timedelta(days=weeks * 7)

        campaigns = (
            (await db.execute(select(Campaign).where(Campaign.status != "closed").order_by(Campaign.updated_at.desc())))
            .scalars()
            .all()
        )
        if not campaigns:
            return {"items": []}

        ids = [c.id for c in campaigns]
        recent_rows = (
            await db.execute(
                select(CampaignEntry.campaign_id, func.count(func.distinct(CampaignEntry.entry_id)))
                .join(Entry, Entry.id == CampaignEntry.entry_id)
                .where(CampaignEntry.campaign_id.in_(ids), Entry.published_at >= start)
                .group_by(CampaignEntry.campaign_id)
            )
        ).all()
        recent = {cid: int(n) for cid, n in recent_rows}

        campaigns.sort(key=lambda c: (-recent.get(c.id, 0), c.updated_at.timestamp() if c.updated_at else 0))
        chosen = campaigns[:limit]
        chosen_ids = [c.id for c in chosen]

        wk = func.date_trunc("week", Entry.published_at).label("wk")
        week_rows = (
            await db.execute(
                select(CampaignEntry.campaign_id, wk, func.count(func.distinct(CampaignEntry.entry_id)))
                .join(Entry, Entry.id == CampaignEntry.entry_id)
                .where(CampaignEntry.campaign_id.in_(chosen_ids), Entry.published_at >= start)
                .group_by(CampaignEntry.campaign_id, wk)
            )
        ).all()
        weekly: dict[object, dict[date, int]] = defaultdict(dict)
        for cid, wk_dt, n in week_rows:
            wk_date = wk_dt.date() if isinstance(wk_dt, datetime) else wk_dt
            weekly[cid][wk_date] = int(n)

        totals_rows = (
            await db.execute(
                select(CampaignEntry.campaign_id, func.count(CampaignEntry.entry_id))
                .where(CampaignEntry.campaign_id.in_(chosen_ids))
                .group_by(CampaignEntry.campaign_id)
            )
        ).all()
        totals = {cid: int(n) for cid, n in totals_rows}

        grid = _week_grid(start, end)
        items = []
        for c in chosen:
            items.append(
                {
                    "id": str(c.id),
                    "name": c.name,
                    "status": c.status,
                    "tlp_marking": c.tlp_marking,
                    "weeks": [{"week_start": w.isoformat(), "count": weekly.get(c.id, {}).get(w, 0)} for w in grid],
                    "recent_count": recent.get(c.id, 0),
                    "total_entries": totals.get(c.id, 0),
                }
            )
        return {"items": items}
    except Exception as exc:
        logger.exception("Error in campaign-momentum widget")
        raise AppError(code="widget_error", message="Failed to load campaign-momentum widget", status_code=500) from exc


# ── Under the radar ─────────────────────────────────────────────────────────


@router.get("/under-reported")
async def under_reported(
    limit: int = Query(10, ge=1, le=50),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_viewer),
):
    """Entries whose persisted under_reported signal fired in the window."""
    try:
        start, end = _parse_date_range(date_from, date_to, default_days=7)
        rows = (
            await db.execute(
                select(
                    EntrySignal.entry_id,
                    EntrySignal.explanation,
                    EntrySignal.payload,
                    Entry.title,
                    Entry.published_at,
                    Entry.priority_score,
                )
                .join(Entry, Entry.id == EntrySignal.entry_id)
                .where(
                    EntrySignal.signal_type == "under_reported",
                    Entry.published_at >= start,
                    Entry.published_at <= end,
                )
                .order_by(Entry.priority_raw.desc().nulls_last(), Entry.published_at.desc())
                .limit(limit)
            )
        ).all()
        items = []
        for entry_id, explanation, payload, title, published_at, priority_score in rows:
            payload = payload or {}
            items.append(
                {
                    "entry_id": str(entry_id),
                    "title": title,
                    "published_at": published_at.isoformat() if published_at else None,
                    "explanation": explanation,
                    "feeds_covering": payload.get("feeds_covering"),
                    "cve_ids": payload.get("cve_ids") or [],
                    "priority_score": float(priority_score) if priority_score is not None else None,
                }
            )
        return {"items": items}
    except Exception as exc:
        logger.exception("Error in under-reported widget")
        raise AppError(code="widget_error", message="Failed to load under-reported widget", status_code=500) from exc


# ── Morning briefing ────────────────────────────────────────────────────────


@router.get("/morning-briefing")
async def morning_briefing(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Latest daily-summary briefing (global scope preferred, per-user fallback)."""
    try:
        from app.api.entries import GLOBAL_SUMMARY_USER, _daily_summary_target_id

        task_id = (await db.execute(select(AITask.id).where(AITask.name == "daily_summary"))).scalar_one_or_none()

        row = None
        day_key: str | None = None
        if task_id is not None:
            candidates: dict[object, str] = {}
            now = datetime.now(UTC)
            for i in range(4):
                dk = (now - timedelta(days=i)).date().isoformat()
                for uid in (GLOBAL_SUMMARY_USER, user.id):
                    candidates[_daily_summary_target_id(uid, dk, {})] = dk
            row = (
                await db.execute(
                    select(AIResult)
                    .where(
                        AIResult.target_type == "daily_summary",
                        AIResult.task_id == task_id,
                        AIResult.is_current.is_(True),
                        AIResult.target_id.in_(list(candidates.keys())),
                    )
                    .order_by(AIResult.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if row is not None:
                day_key = candidates.get(row.target_id)

        if row is None:
            row = (
                await db.execute(
                    select(AIResult)
                    .where(AIResult.target_type == "daily_summary", AIResult.is_current.is_(True))
                    .order_by(AIResult.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()

        if row is None:
            return {"summary": None, "generated_at": None, "day_key": None}

        parsed = row.parsed_result if isinstance(row.parsed_result, dict) else {}
        return {
            "summary": parsed.get("summary"),
            "generated_at": row.created_at.isoformat() if row.created_at else None,
            "day_key": day_key,
        }
    except Exception as exc:
        logger.exception("Error in morning-briefing widget")
        raise AppError(code="widget_error", message="Failed to load morning-briefing widget", status_code=500) from exc


# ── Relationship inbox ──────────────────────────────────────────────────────

_AUTO_REL_SOURCES = ("co_occurrence", "auto_extracted", "external_feed")

_RelRef = namedtuple("_RelRef", ["entity_type", "entity_id"])


@router.get("/relationship-inbox")
async def relationship_inbox(
    limit: int = Query(5, ge=1, le=25),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Trust-ladder counts for the window plus the freshest pending claims."""
    try:
        from app.api.watchlist import _ENTITY_NAME_SOURCES
        from app.services.entity_names import resolve_entity_names

        start, end = _parse_date_range(date_from, date_to, default_days=7)

        async def _count(*conds) -> int:
            return int(
                (
                    await db.execute(
                        select(func.count(EntityRelationship.id)).where(
                            EntityRelationship.created_at >= start,
                            EntityRelationship.created_at <= end,
                            *conds,
                        )
                    )
                ).scalar()
                or 0
            )

        claimed = await _count(EntityRelationship.source.in_(_AUTO_REL_SOURCES))
        adjudicated = await _count(EntityRelationship.adjudication_verdict.is_not(None))
        confirmed = await _count(
            or_(
                EntityRelationship.source == "analyst_confirmed",
                EntityRelationship.adjudication_verdict == "corroborated",
            )
        )

        rels = (
            (
                await db.execute(
                    select(EntityRelationship)
                    .where(
                        EntityRelationship.source.in_(_AUTO_REL_SOURCES),
                        EntityRelationship.adjudication_verdict.is_(None),
                    )
                    .order_by(EntityRelationship.created_at.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )

        name_map = dict(_ENTITY_NAME_SOURCES)
        name_map.setdefault("ttp", (TTP, TTP.technique_id))
        name_map.setdefault("mitigation", (Mitigation, Mitigation.name))
        name_map.setdefault("cwe", (CWE, CWE.cwe_id))
        name_map.setdefault("campaign", (Campaign, Campaign.name))
        refs = [_RelRef(r.source_type, r.source_id) for r in rels] + [_RelRef(r.target_type, r.target_id) for r in rels]
        names = await resolve_entity_names(db, refs, name_map)

        items = [
            {
                "id": str(r.id),
                "source_type": r.source_type,
                "source_id": str(r.source_id),
                "source_name": names.get((r.source_type, r.source_id)) or "(unknown)",
                "relationship_type": r.relationship_type,
                "target_type": r.target_type,
                "target_id": str(r.target_id),
                "target_name": names.get((r.target_type, r.target_id)) or "(unknown)",
                "evidence_count": len(r.evidence_entry_ids or []),
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rels
        ]
        return {"ladder": {"claimed": claimed, "adjudicated": adjudicated, "confirmed": confirmed}, "items": items}
    except Exception as exc:
        logger.exception("Error in relationship-inbox widget")
        raise AppError(
            code="widget_error", message="Failed to load relationship-inbox widget", status_code=500
        ) from exc


# ── Playbook drift ──────────────────────────────────────────────────────────


@router.get("/playbook-drift")
async def playbook_drift(
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Techniques newly co-reported with watched actors in the window."""
    try:
        start, end = _parse_date_range(date_from, date_to, default_days=30)

        watched = (
            await db.execute(
                select(UserEntityWatch.entity_id).where(
                    UserEntityWatch.created_by == user.id,
                    UserEntityWatch.mode == "watch",
                    UserEntityWatch.entity_type == "threat_actor",
                )
            )
        ).all()
        actor_ids = [r[0] for r in watched]
        if not actor_ids:
            return {"items": [], "total_new": 0}

        pair_base = (
            select(
                EntryThreatActor.threat_actor_id.label("actor_id"),
                EntryTTP.ttp_id.label("ttp_id"),
                func.count(func.distinct(Entry.id)).label("n"),
            )
            .select_from(EntryThreatActor)
            .join(EntryTTP, EntryTTP.entry_id == EntryThreatActor.entry_id)
            .join(Entry, Entry.id == EntryThreatActor.entry_id)
            .where(EntryThreatActor.threat_actor_id.in_(actor_ids))
            .group_by(EntryThreatActor.threat_actor_id, EntryTTP.ttp_id)
        )
        current_rows = (await db.execute(pair_base.where(Entry.published_at >= start, Entry.published_at <= end))).all()
        historical_rows = (await db.execute(pair_base.where(Entry.published_at < start))).all()

        historical_pairs = {(r.actor_id, r.ttp_id) for r in historical_rows}
        known_counts: dict[object, int] = defaultdict(int)
        for actor_id, _ttp_id in historical_pairs:
            known_counts[actor_id] += 1

        additions: dict[object, list] = defaultdict(list)
        new_ttp_ids: set = set()
        for r in current_rows:
            if (r.actor_id, r.ttp_id) in historical_pairs:
                continue
            additions[r.actor_id].append((r.ttp_id, int(r.n)))
            new_ttp_ids.add(r.ttp_id)

        ttp_info = {}
        if new_ttp_ids:
            for tid, technique_id, technique_name in (
                await db.execute(
                    select(TTP.id, TTP.technique_id, TTP.technique_name).where(TTP.id.in_(list(new_ttp_ids)))
                )
            ).all():
                ttp_info[tid] = (technique_id, technique_name)

        actor_names = {
            aid: name
            for aid, name in (
                await db.execute(select(ThreatActor.id, ThreatActor.name).where(ThreatActor.id.in_(actor_ids)))
            ).all()
        }

        items = []
        total_new = 0
        for actor_id, adds in additions.items():
            adds.sort(key=lambda a: -a[1])
            total_new += len(adds)
            items.append(
                {
                    "actor_id": str(actor_id),
                    "actor_name": actor_names.get(actor_id) or "(unknown)",
                    "known_count": known_counts.get(actor_id, 0),
                    "additions": [
                        {
                            "ttp_id": str(tid),
                            "technique_id": ttp_info.get(tid, (None, None))[0],
                            "technique_name": ttp_info.get(tid, (None, None))[1],
                            "report_count": n,
                        }
                        for tid, n in adds
                    ],
                }
            )
        items.sort(key=lambda i: -len(i["additions"]))
        return {"items": items, "total_new": total_new}
    except Exception as exc:
        logger.exception("Error in playbook-drift widget")
        raise AppError(code="widget_error", message="Failed to load playbook-drift widget", status_code=500) from exc
