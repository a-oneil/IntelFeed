"""ATT&CK Navigator layer generation API."""

import json
import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.database import get_db
from app.intelligence.tactics import TACTIC_ORDER, tactic_label
from app.models.entry import Entry
from app.models.ttp import TTP, EntryTTP
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter()

_MATRIX_CACHE_PREFIX = "intelfeed:attack:matrix"
_MATRIX_CACHE_TTL_SECONDS = 180


def _technique_tactics(ttp: TTP) -> list[str]:
    return ttp.tactics or ([ttp.tactic] if ttp.tactic else [])


@router.get("/matrix")
async def get_attack_matrix(
    domain: str = Query("enterprise", pattern="^(enterprise|mobile|ics)$", description="ATT&CK matrix domain."),
    days: int | None = Query(None, ge=1, le=3650, description="Feed-frequency window; omit for all-time"),
    include_deprecated: bool = Query(False, description="Include techniques deprecated/revoked in the ATT&CK catalog."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Navigator-style matrix data: tactics in kill-chain order, techniques with
    feed frequency (article counts) and telemetry-aware detection coverage.

    Per technique: ``article_count`` (within the optional window), ``has_rule``
    (any non-draft rule references it), ``deployable`` (a referencing rule's
    data sources are all satisfiable by enabled telemetry), plus nested
    sub-techniques. Heavy aggregate — cached in Redis for a few minutes.
    """
    from app.services.detection_coverage import (
        STATUS_COVERED,
        STATUS_NO_RULE,
        classify_techniques,
        summarize,
    )

    cache_key = f"{_MATRIX_CACHE_PREFIX}:{domain}:{days or 0}:{int(include_deprecated)}"
    try:
        from app.services.redis_client import get_redis

        cached = await (await get_redis()).get(cache_key)
        if cached:
            return json.loads(cached)
    except Exception as e:
        logger.debug(f"attack matrix cache read failed: {e}")

    query = select(TTP).where(TTP.matrix_domain == domain)
    if not include_deprecated:
        query = query.where(TTP.is_deprecated.is_(False))
    techniques = (await db.execute(query)).scalars().all()

    # Feed frequency: windowed EntryTTP link counts, or the all-time rollup
    if days is not None:
        cutoff = datetime.now(UTC) - timedelta(days=days)
        agg = await db.execute(
            select(EntryTTP.ttp_id, func.count(EntryTTP.entry_id).label("count"))
            .join(Entry, Entry.id == EntryTTP.entry_id)
            .join(TTP, TTP.id == EntryTTP.ttp_id)
            .where(TTP.matrix_domain == domain, Entry.published_at >= cutoff)
            .group_by(EntryTTP.ttp_id)
        )
        counts: dict[uuid.UUID, int] = {row.ttp_id: row.count for row in agg.all()}
    else:
        counts = {t.id: t.article_count or 0 for t in techniques}

    coverage = await classify_techniques(db, [t.technique_id for t in techniques])

    def cell(t: TTP) -> dict:
        info = coverage.get(t.technique_id) or {}
        status = info.get("status", STATUS_NO_RULE)
        return {
            "id": str(t.id),
            "technique_id": t.technique_id,
            "name": t.technique_name,
            "article_count": counts.get(t.id, 0),
            "rule_count": info.get("rule_count", 0),
            "has_rule": info.get("rule_count", 0) > 0,
            "coverage": status,
            "deployable": status == STATUS_COVERED,
            "missing_data_sources": info.get("missing_data_sources", []),
            "is_deprecated": t.is_deprecated,
        }

    parents = [t for t in techniques if not t.is_subtechnique]
    parent_ids = {t.technique_id for t in parents}
    subs_by_parent: dict[str, list[TTP]] = defaultdict(list)
    orphan_subs: list[TTP] = []
    for t in techniques:
        if not t.is_subtechnique:
            continue
        if t.parent_technique_id in parent_ids:
            subs_by_parent[t.parent_technique_id].append(t)
        else:
            # Parent missing from this domain (or deprecated-filtered) — surface as top-level
            orphan_subs.append(t)

    known_order = TACTIC_ORDER.get(domain, [])
    present = {tac for t in techniques for tac in _technique_tactics(t)}
    ordered_tactics = known_order + sorted(present - set(known_order))

    top_level = sorted(parents + orphan_subs, key=lambda t: t.technique_name.lower())
    max_count = 0
    tactic_cols = []
    for slug in ordered_tactics:
        cells = []
        for t in top_level:
            if slug not in _technique_tactics(t):
                continue
            c = cell(t)
            subs = []
            for s in sorted(subs_by_parent.get(t.technique_id, []), key=lambda x: x.technique_id):
                sub_tactics = _technique_tactics(s)
                # Subs follow the parent into columns their own tactics allow
                if sub_tactics and slug not in sub_tactics:
                    continue
                subs.append(cell(s))
            c["subtechniques"] = subs
            c["rollup_article_count"] = c["article_count"] + sum(s["article_count"] for s in subs)
            max_count = max(max_count, c["rollup_article_count"])
            cells.append(c)
        # Skip tactics with no techniques (legacy/renamed slugs for other catalog versions)
        if cells:
            tactic_cols.append({"id": slug, "name": tactic_label(slug), "techniques": cells})

    payload = {
        "domain": domain,
        "days": days,
        "generated_at": datetime.now(UTC).isoformat(),
        "technique_count": len(techniques),
        "max_article_count": max_count,
        "coverage_summary": summarize(coverage),
        "tactics": tactic_cols,
    }

    try:
        from app.services.redis_client import get_redis

        await (await get_redis()).set(cache_key, json.dumps(payload), ex=_MATRIX_CACHE_TTL_SECONDS)
    except Exception as e:
        logger.debug(f"attack matrix cache write failed: {e}")

    return payload


@router.get("/layer")
async def generate_layer(
    entry_id: uuid.UUID | None = Query(
        None, description="Build the layer from a single entry's TTPs; overrides the date range."
    ),
    date_from: str | None = Query(
        None, description="ISO date/datetime lower bound on TTP extraction time (default: 30 days before date_to)."
    ),
    date_to: str | None = Query(
        None, description="ISO date/datetime upper bound on TTP extraction time (default: now)."
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate an ATT&CK Navigator layer JSON from extracted TTPs, scored and color-graded by article frequency."""
    now = datetime.now(UTC)

    # Build query
    query = select(
        TTP.technique_id,
        TTP.technique_name,
        TTP.tactic,
        func.count(EntryTTP.entry_id).label("count"),
        func.max(EntryTTP.extracted_at).label("latest"),
    ).join(TTP, TTP.id == EntryTTP.ttp_id)

    if entry_id:
        query = query.where(EntryTTP.entry_id == entry_id)
    else:
        if date_to:
            end = datetime.fromisoformat(date_to).replace(tzinfo=UTC)
        else:
            end = now
        if date_from:
            start = datetime.fromisoformat(date_from).replace(tzinfo=UTC)
        else:
            start = end - timedelta(days=30)
        query = query.where(EntryTTP.extracted_at >= start, EntryTTP.extracted_at <= end)

    query = query.group_by(TTP.id, TTP.technique_id, TTP.technique_name, TTP.tactic)
    result = await db.execute(query)
    rows = result.all()

    # Find max for gradient scaling
    max_count = max((r.count for r in rows), default=1)

    # Build Navigator layer
    techniques = []
    for row in rows:
        score = round((row.count / max_count) * 100)
        # Color gradient from white to red based on score
        intensity = int(255 - (score / 100) * 155)
        color = f"#ff{intensity:02x}{intensity:02x}"

        techniques.append(
            {
                "techniqueID": row.technique_id,
                "tactic": row.tactic or "",
                "color": color,
                "score": score,
                "comment": f"Found in {row.count} article{'s' if row.count != 1 else ''}",
                "metadata": [
                    {"name": "articles", "value": str(row.count)},
                    {"name": "latest", "value": str(row.latest.date()) if row.latest else ""},
                ],
            }
        )

    total_articles = sum(r.count for r in rows)
    date_label = now.strftime("%B %Y")

    return {
        "name": f"IntelFeed - Detected TTPs ({date_label})",
        "versions": {"attack": "15", "navigator": "4.9.5", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"TTPs detected across {total_articles} article references",
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "techniques": techniques,
    }


@router.get("/techniques")
async def list_techniques(
    date_from: str | None = Query(
        None, description="ISO date/datetime lower bound on TTP extraction time (default: 30 days before date_to)."
    ),
    date_to: str | None = Query(
        None, description="ISO date/datetime upper bound on TTP extraction time (default: now)."
    ),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of techniques to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List techniques extracted in the window, ranked by article count, with each technique's latest sighting date."""
    now = datetime.now(UTC)
    if date_to:
        end = datetime.fromisoformat(date_to).replace(tzinfo=UTC)
    else:
        end = now
    if date_from:
        start = datetime.fromisoformat(date_from).replace(tzinfo=UTC)
    else:
        start = end - timedelta(days=30)

    result = await db.execute(
        select(
            TTP.technique_id,
            TTP.technique_name,
            TTP.tactic,
            func.count(EntryTTP.entry_id).label("count"),
            func.max(EntryTTP.extracted_at).label("latest"),
        )
        .join(TTP, TTP.id == EntryTTP.ttp_id)
        .where(EntryTTP.extracted_at >= start, EntryTTP.extracted_at <= end)
        .group_by(TTP.id, TTP.technique_id, TTP.technique_name, TTP.tactic)
        .order_by(func.count(EntryTTP.entry_id).desc())
        .limit(limit)
    )
    return [
        {
            "technique_id": row.technique_id,
            "name": row.technique_name,
            "tactic": row.tactic,
            "count": row.count,
            "latest": str(row.latest.date()) if row.latest else None,
        }
        for row in result.all()
    ]
