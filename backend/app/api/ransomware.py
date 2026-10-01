"""Ransomware victim tracker API (plan §7).

Read-only aggregates over victim_disclosures. Powers Leak Watch (the feed) and
Ransomware Landscape (the dashboard).

Every stat counts disclosure *events* (one posting = one "victim" on the mocks),
so group/sector/country aggregates are plain GROUP BYs over victim_disclosures,
which carries denormalized group_id/sector/country_id.
"""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import Select, and_, false, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.intelligence.sectors import sector_label
from app.models.country import Country
from app.models.ransomware import RansomwareVictim, VictimDisclosure
from app.models.sector import Sector
from app.models.threat_actor import ThreatActor
from app.models.user import User
from app.models.user_entity_watch import UserEntityWatch
from app.schemas.ransomware import (
    CountryStat,
    DisclosureResponse,
    ExposureItem,
    GroupStat,
    GroupVictimStats,
    RansomwareStats,
    SectorStat,
    StatsTotals,
    TimeseriesPoint,
    VictimDetail,
    VictimGroupRef,
    VictimSummary,
    group_color_slug,
)

router = APIRouter()

_NEW_WINDOW = timedelta(hours=24)


def _pct_change(now: int, prior: int) -> float:
    if prior == 0:
        return 100.0 if now > 0 else 0.0
    return round((now - prior) / prior * 100, 1)


async def _watched_sets(db: AsyncSession, user: User) -> tuple[set[uuid.UUID], set[uuid.UUID]]:
    """(watched_victim_ids, watched_group_ids) for the current user's 'watch' rows."""
    rows = (
        await db.execute(
            select(UserEntityWatch.entity_type, UserEntityWatch.entity_id).where(
                UserEntityWatch.created_by == user.id,
                UserEntityWatch.mode == "watch",
                UserEntityWatch.entity_type.in_(["ransomware_victim", "threat_actor"]),
            )
        )
    ).all()
    victims = {eid for etype, eid in rows if etype == "ransomware_victim"}
    groups = {eid for etype, eid in rows if etype == "threat_actor"}
    return victims, groups


def _disclosure_response(d: VictimDisclosure, watched_victims: set[uuid.UUID], now: datetime) -> DisclosureResponse:
    victim = d.victim
    group = d.group
    country = d.country
    return DisclosureResponse(
        id=d.id,
        victim_id=d.victim_id,
        victim_name=victim.name if victim else "",
        domain=victim.domain if victim else None,
        watched=d.victim_id in watched_victims,
        group_id=d.group_id,
        group_name=group.name if group else d.group_name_raw,
        group_color=group_color_slug(group.name if group else d.group_name_raw),
        sector=d.sector,
        sector_label=sector_label(d.sector) if d.sector else None,
        country_id=d.country_id,
        country_name=country.name if country else None,
        country_code=country.iso_code if country else None,
        posted_at=d.posted_at,
        published_at=d.published_at,
        claimed_data=d.claimed_data,
        leak_site_url=d.leak_site_url,
        source=d.source,
        is_new=(now - d.posted_at) <= _NEW_WINDOW,
    )


async def _country_ids_for_codes(db: AsyncSession, codes: list[str]) -> list[uuid.UUID]:
    lowered = [c.lower() for c in codes]
    cond = or_(func.lower(Country.iso_code).in_(lowered), func.lower(Country.name).in_(lowered))
    rows = (await db.execute(select(Country.id).where(cond))).scalars().all()
    return list(rows)


async def _group_ids_for_names(db: AsyncSession, names: list[str]) -> list[uuid.UUID]:
    lowered = [n.lower() for n in names]
    rows = (await db.execute(select(ThreatActor.id).where(func.lower(ThreatActor.name).in_(lowered)))).scalars().all()
    return list(rows)


@router.get("/disclosures", response_model=PaginatedResponse[DisclosureResponse])
async def list_disclosures(
    group: list[str] | None = Query(None, description="Filter by ransomware group name(s)"),
    sector: list[str] | None = Query(None, description="Filter by canonical sector slug(s)"),
    country: list[str] | None = Query(None, description="Filter by country ISO code or name"),
    watched_only: bool = Query(False, description="Only disclosures hitting the user's watched victims/groups"),
    since: int | None = Query(None, ge=0, description="Only postings newer than N days"),
    q: str | None = Query(None, description="Substring search on victim name/domain or raw group name"),
    sort: str = Query("recent", pattern="^(recent|group|sector)$", description="Sort order (newest-first tiebreak)"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    offset: int = Query(0, ge=0, description="Rows to skip for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Reverse-chron feed of leak-site disclosures — powers Leak Watch."""
    now = datetime.now(UTC)
    watched_victims, watched_groups = await _watched_sets(db, user)

    filters = []
    if since is not None:
        filters.append(VictimDisclosure.posted_at >= now - timedelta(days=since))
    if sector:
        filters.append(VictimDisclosure.sector.in_(sector))
    if group:
        gids = await _group_ids_for_names(db, group)
        lowered = [g.lower() for g in group]
        cond = func.lower(VictimDisclosure.group_name_raw).in_(lowered)
        if gids:
            cond = or_(VictimDisclosure.group_id.in_(gids), cond)
        filters.append(cond)
    if country:
        cids = await _country_ids_for_codes(db, country)
        filters.append(VictimDisclosure.country_id.in_(cids) if cids else false())
    if watched_only:
        watch_cond = []
        if watched_victims:
            watch_cond.append(VictimDisclosure.victim_id.in_(watched_victims))
        if watched_groups:
            watch_cond.append(VictimDisclosure.group_id.in_(watched_groups))
        filters.append(or_(*watch_cond) if watch_cond else false())
    if q:
        like = f"%{q.lower()}%"
        filters.append(
            or_(
                func.lower(RansomwareVictim.name).like(like),
                func.lower(RansomwareVictim.domain).like(like),
                func.lower(VictimDisclosure.group_name_raw).like(like),
            )
        )

    def _apply(stmt: Select) -> Select:
        stmt = stmt.join(RansomwareVictim, VictimDisclosure.victim_id == RansomwareVictim.id)
        return stmt.where(and_(*filters)) if filters else stmt

    total = (await db.execute(_apply(select(func.count(VictimDisclosure.id))))).scalar() or 0

    order = {
        "group": (VictimDisclosure.group_name_raw.asc(), VictimDisclosure.posted_at.desc()),
        "sector": (VictimDisclosure.sector.asc(), VictimDisclosure.posted_at.desc()),
    }.get(sort, (VictimDisclosure.posted_at.desc(),))

    stmt = (
        _apply(select(VictimDisclosure))
        .options(
            selectinload(VictimDisclosure.victim),
            selectinload(VictimDisclosure.group),
            selectinload(VictimDisclosure.country),
        )
        .order_by(*order)
        .limit(limit)
        .offset(offset)
    )
    disclosures = (await db.execute(stmt)).scalars().all()
    items = [_disclosure_response(d, watched_victims, now) for d in disclosures]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


async def _timeseries(db: AsyncSession, start: datetime, now: datetime) -> list[TimeseriesPoint]:
    week = func.date_trunc("week", VictimDisclosure.posted_at)
    rows = (
        await db.execute(
            select(week.label("wk"), func.count(VictimDisclosure.id))
            .where(VictimDisclosure.posted_at >= start)
            .group_by(week)
            .order_by(week)
        )
    ).all()
    counts = {r[0].date(): r[1] for r in rows}
    # Fill every week from the Monday of `start` up to the last *complete* week.
    # The week containing `now` is still in progress, so plotting it would drop the
    # line to a partial-bucket cliff — stop before it.
    cursor = (start - timedelta(days=start.weekday())).date()
    end = (now - timedelta(days=now.weekday())).date()  # Monday of current (partial) week
    points: list[TimeseriesPoint] = []
    while cursor < end:
        label = f"{cursor:%b} {cursor.day}"
        points.append(TimeseriesPoint(week_start=cursor, label=label, count=counts.get(cursor, 0)))
        cursor = cursor + timedelta(days=7)
    return points


async def _group_stats(db: AsyncSession, start: datetime, now: datetime, total: int) -> list[GroupStat]:
    rows = (
        await db.execute(
            select(VictimDisclosure.group_id, ThreatActor.name, func.count(VictimDisclosure.id))
            .join(ThreatActor, VictimDisclosure.group_id == ThreatActor.id, isouter=True)
            .where(VictimDisclosure.posted_at >= start)
            .group_by(VictimDisclosure.group_id, ThreatActor.name)
            .order_by(func.count(VictimDisclosure.id).desc())
            .limit(12)
        )
    ).all()

    # Week-over-week per group: last 7d vs prior 7d.
    last7 = now - timedelta(days=7)
    prior7 = now - timedelta(days=14)
    wow_rows = (
        await db.execute(
            select(
                VictimDisclosure.group_id,
                func.count(VictimDisclosure.id).filter(VictimDisclosure.posted_at >= last7),
                func.count(VictimDisclosure.id).filter(
                    and_(VictimDisclosure.posted_at >= prior7, VictimDisclosure.posted_at < last7)
                ),
            )
            .where(VictimDisclosure.posted_at >= prior7)
            .group_by(VictimDisclosure.group_id)
        )
    ).all()
    wow = {gid: (recent, prior) for gid, recent, prior in wow_rows}

    stats: list[GroupStat] = []
    for gid, name, count in rows:
        display = name or "Unattributed"
        recent, prior = wow.get(gid, (0, 0))
        trend = _pct_change(recent, prior)
        stats.append(
            GroupStat(
                id=gid,
                name=display,
                color=group_color_slug(name),
                victims=count,
                share=round(count / total * 100, 1) if total else 0.0,
                wow_trend=trend,
                trend_up=recent >= prior,
            )
        )
    return stats


async def _sector_stats(db: AsyncSession, start: datetime, total: int) -> list[SectorStat]:
    rows = (
        await db.execute(
            select(VictimDisclosure.sector, func.count(VictimDisclosure.id))
            .where(VictimDisclosure.posted_at >= start, VictimDisclosure.sector.isnot(None))
            .group_by(VictimDisclosure.sector)
            .order_by(func.count(VictimDisclosure.id).desc())
            .limit(10)
        )
    ).all()
    return [
        SectorStat(
            sector=s,
            label=sector_label(s),
            victims=c,
            share=round(c / total * 100, 1) if total else 0.0,
        )
        for s, c in rows
    ]


async def _country_stats(db: AsyncSession, start: datetime) -> list[CountryStat]:
    rows = (
        await db.execute(
            select(VictimDisclosure.country_id, Country.name, Country.iso_code, func.count(VictimDisclosure.id))
            .join(Country, VictimDisclosure.country_id == Country.id)
            .where(VictimDisclosure.posted_at >= start)
            .group_by(VictimDisclosure.country_id, Country.name, Country.iso_code)
            .order_by(func.count(VictimDisclosure.id).desc())
            .limit(10)
        )
    ).all()
    return [CountryStat(id=cid, name=name, iso_code=iso, victims=c) for cid, name, iso, c in rows]


async def _watchlist_exposure(db: AsyncSession, user: User, start: datetime) -> list[ExposureItem]:
    """The user's watched groups, orgs and sectors (all UserEntityWatch rows) vs
    disclosures in the window. Read-only exposure panel — no muting/boosting here."""
    items: list[ExposureItem] = []
    watched_victims, watched_groups = await _watched_sets(db, user)

    if watched_groups:
        rows = (
            await db.execute(
                select(ThreatActor.id, ThreatActor.name, func.count(VictimDisclosure.id))
                .select_from(ThreatActor)
                .join(
                    VictimDisclosure,
                    and_(VictimDisclosure.group_id == ThreatActor.id, VictimDisclosure.posted_at >= start),
                    isouter=True,
                )
                .where(ThreatActor.id.in_(watched_groups))
                .group_by(ThreatActor.id, ThreatActor.name)
            )
        ).all()
        for _id, name, c in rows:
            items.append(
                ExposureItem(
                    name=name,
                    kind="watched group",
                    status="hit" if c else "clear",
                    detail=f"{c} victims · window" if c else "no new activity",
                    hit=c > 0,
                )
            )

    if watched_victims:
        rows = (
            await db.execute(
                select(RansomwareVictim.id, RansomwareVictim.name, func.count(VictimDisclosure.id))
                .select_from(RansomwareVictim)
                .join(
                    VictimDisclosure,
                    and_(VictimDisclosure.victim_id == RansomwareVictim.id, VictimDisclosure.posted_at >= start),
                    isouter=True,
                )
                .where(RansomwareVictim.id.in_(watched_victims))
                .group_by(RansomwareVictim.id, RansomwareVictim.name)
            )
        ).all()
        for _id, name, c in rows:
            items.append(
                ExposureItem(
                    name=name,
                    kind="watched org",
                    status="hit" if c else "clear",
                    detail=f"{c} new disclosure(s)" if c else "no new activity",
                    hit=c > 0,
                )
            )

    watched_sectors = (
        await db.execute(
            select(Sector.slug, Sector.name)
            .join(UserEntityWatch, UserEntityWatch.entity_id == Sector.id)
            .where(
                UserEntityWatch.created_by == user.id,
                UserEntityWatch.entity_type == "sector",
                UserEntityWatch.mode == "watch",
            )
            .order_by(Sector.name)
        )
    ).all()
    for slug, name in watched_sectors:
        c = (
            await db.execute(
                select(func.count(VictimDisclosure.id)).where(
                    VictimDisclosure.sector == slug, VictimDisclosure.posted_at >= start
                )
            )
        ).scalar() or 0
        items.append(
            ExposureItem(
                name=name,
                kind="watched sector",
                status="hit" if c else "clear",
                detail=f"{c} new victims in window" if c else "no new victims",
                hit=c > 0,
            )
        )

    # Hits first.
    items.sort(key=lambda x: (not x.hit, x.name))
    return items


@router.get("/stats", response_model=RansomwareStats)
async def get_stats(
    days: int = Query(90, ge=1, le=1095, description="Aggregation window in days"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregates for the Ransomware Landscape dashboard (and the feed rail facets)."""
    now = datetime.now(UTC)
    start = now - timedelta(days=days)
    prior_start = now - timedelta(days=2 * days)

    total = (
        await db.execute(select(func.count(VictimDisclosure.id)).where(VictimDisclosure.posted_at >= start))
    ).scalar() or 0
    prior_total = (
        await db.execute(
            select(func.count(VictimDisclosure.id)).where(
                VictimDisclosure.posted_at >= prior_start, VictimDisclosure.posted_at < start
            )
        )
    ).scalar() or 0
    groups_active = (
        await db.execute(
            select(func.count(func.distinct(VictimDisclosure.group_id))).where(
                VictimDisclosure.posted_at >= start, VictimDisclosure.group_id.isnot(None)
            )
        )
    ).scalar() or 0
    sectors_hit = (
        await db.execute(
            select(func.count(func.distinct(VictimDisclosure.sector))).where(
                VictimDisclosure.posted_at >= start, VictimDisclosure.sector.isnot(None)
            )
        )
    ).scalar() or 0

    groups = await _group_stats(db, start, now, total)
    sectors = await _sector_stats(db, start, total)
    countries = await _country_stats(db, start)
    timeseries = await _timeseries(db, start, now)
    exposure = await _watchlist_exposure(db, user, start)

    most_active = groups[0] if groups else None
    riser = None
    ranked = [g for g in groups if g.victims >= 5] or groups
    if ranked:
        riser = max(ranked, key=lambda g: g.wow_trend)

    totals = StatsTotals(
        victims=total,
        prior_victims=prior_total,
        victims_wow=_pct_change(total, prior_total),
        groups_active=groups_active,
        sectors_hit=sectors_hit,
        watchlist_hits=sum(1 for e in exposure if e.hit),
    )
    return RansomwareStats(
        days=days,
        totals=totals,
        timeseries=timeseries,
        groups=groups,
        sectors=sectors,
        countries=countries,
        watchlist_exposure=exposure,
        most_active_group=most_active,
        fastest_riser=riser,
    )


@router.get("/victims/{victim_id}", response_model=VictimDetail)
async def get_victim(
    victim_id: uuid.UUID = Path(..., description="Ransomware victim UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Victim detail: disclosures, group history, geo/sector (row-expand payload)."""
    now = datetime.now(UTC)
    victim = (
        await db.execute(
            select(RansomwareVictim)
            .where(RansomwareVictim.id == victim_id)
            .options(
                selectinload(RansomwareVictim.country),
                selectinload(RansomwareVictim.disclosures).selectinload(VictimDisclosure.group),
                selectinload(RansomwareVictim.disclosures).selectinload(VictimDisclosure.country),
                selectinload(RansomwareVictim.disclosures).selectinload(VictimDisclosure.victim),
            )
        )
    ).scalar_one_or_none()
    if victim is None:
        raise HTTPException(status_code=404, detail="Victim not found")

    watched_victims, _ = await _watched_sets(db, user)
    disclosures = [_disclosure_response(d, watched_victims, now) for d in victim.disclosures]

    seen: dict[uuid.UUID | None, VictimGroupRef] = {}
    for d in victim.disclosures:
        name = d.group.name if d.group else d.group_name_raw
        key = d.group_id if d.group_id else name
        if key not in seen:
            seen[key] = VictimGroupRef(id=d.group_id, name=name, color=group_color_slug(name))

    return VictimDetail(
        id=victim.id,
        name=victim.name,
        domain=victim.domain,
        aliases=victim.aliases or [],
        country_id=victim.country_id,
        country_name=victim.country.name if victim.country else None,
        country_code=victim.country.iso_code if victim.country else None,
        sector=victim.sector,
        sector_label=sector_label(victim.sector) if victim.sector else None,
        first_seen_at=victim.first_seen_at,
        last_seen_at=victim.last_seen_at,
        disclosure_count=victim.disclosure_count,
        watched=victim.id in watched_victims,
        groups=list(seen.values()),
        disclosures=disclosures,
    )


@router.get("/groups/{actor_id}/victims/stats", response_model=GroupVictimStats)
async def get_group_victim_stats(
    actor_id: uuid.UUID = Path(..., description="ThreatActor UUID of the ransomware group"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Victim counts for a group: total on record, last 30 days, and the 30 days
    before that — the profile's trend read. Counts distinct victims by the
    disclosure's posted_at, so a re-post inside the window still counts once."""
    now = datetime.now(UTC)
    cut_30 = now - timedelta(days=30)
    cut_60 = now - timedelta(days=60)

    def _count(*where):
        return select(func.count(func.distinct(VictimDisclosure.victim_id))).where(
            VictimDisclosure.group_id == actor_id, *where
        )

    total = (await db.execute(_count())).scalar() or 0
    last_30d = (await db.execute(_count(VictimDisclosure.posted_at >= cut_30))).scalar() or 0
    prev_30d = (
        await db.execute(_count(VictimDisclosure.posted_at >= cut_60, VictimDisclosure.posted_at < cut_30))
    ).scalar() or 0
    return GroupVictimStats(total=total, last_30d=last_30d, prev_30d=prev_30d)


@router.get("/groups/{actor_id}/victims", response_model=PaginatedResponse[VictimSummary])
async def get_group_victims(
    actor_id: uuid.UUID = Path(..., description="ThreatActor UUID of the ransomware group"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    offset: int = Query(0, ge=0, description="Rows to skip for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Victims listed by a given ransomware group (ThreatActor) — profile tab feed."""
    watched_victims, _ = await _watched_sets(db, user)

    victim_ids_subq = (
        select(func.distinct(VictimDisclosure.victim_id)).where(VictimDisclosure.group_id == actor_id).subquery()
    )
    total = (await db.execute(select(func.count()).select_from(victim_ids_subq))).scalar() or 0

    stmt = (
        select(RansomwareVictim)
        .where(RansomwareVictim.id.in_(select(victim_ids_subq)))
        .options(selectinload(RansomwareVictim.country))
        .order_by(RansomwareVictim.last_seen_at.desc())
        .limit(limit)
        .offset(offset)
    )
    victims = (await db.execute(stmt)).scalars().all()
    items = [
        VictimSummary(
            id=v.id,
            name=v.name,
            domain=v.domain,
            sector=v.sector,
            sector_label=sector_label(v.sector) if v.sector else None,
            country_name=v.country.name if v.country else None,
            country_code=v.country.iso_code if v.country else None,
            last_seen_at=v.last_seen_at,
            disclosure_count=v.disclosure_count,
            watched=v.id in watched_victims,
        )
        for v in victims
    ]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)
