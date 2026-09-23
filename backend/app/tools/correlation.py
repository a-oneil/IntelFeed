"""Correlation & Analysis tools."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.intelligence_requirement import IntelligenceRequirement
from app.models.telemetry_source import TelemetrySource
from app.tools import _tool


@_tool(
    name="pivot_entity",
    description=(
        "Find all entities related to a given entity via co-occurrence in entries. One-hop pivot. Related lists "
        "carry strength tiers (weak/moderate/strong) and are ranked, tier-filterable, window-filterable and "
        "paginated; related_counts reports pre-slice totals."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": sorted(entity_types.CORRELATABLE)},
            "entity_id": {"type": "string", "description": "Entity UUID"},
            "limit_per_type": {"type": "integer", "default": 50, "description": "Max related entities per type"},
            "window_days": {"type": "integer", "description": "Only count evidence from the last N days"},
            "offset": {"type": "integer", "default": 0, "description": "Pagination offset within each type"},
            "sort": {"type": "string", "enum": ["strength", "recent", "articles"], "default": "strength"},
            "min_tier": {
                "type": "string",
                "enum": ["weak", "moderate", "strong"],
                "description": "Minimum strength tier; omitted uses the system default (confirmed rels always pass)",
            },
        },
        "required": ["entity_type", "entity_id"],
    },
)
async def _pivot_entity(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_id: str,
    limit_per_type: int = 50,
    window_days: int | None = None,
    offset: int = 0,
    sort: str = "strength",
    min_tier: str | None = None,
) -> dict:
    from app.intelligence.correlation import pivot_from_entity

    return await pivot_from_entity(
        db,
        entity_type,
        uuid.UUID(entity_id),
        limit_per_type=limit_per_type,
        min_tier=min_tier,
        window_days=window_days,
        offset=offset,
        sort=sort,
    )


@_tool(
    name="get_entity_graph",
    description=(
        "Build a relationship graph centered on an entity. Claims-only: edges are typed relationship records "
        "(verb, direction, confidence, provenance) at confirmed/reported confidence — pure co-occurrence pairs "
        "are excluded; co-occurrence data only enriches edges with proximity and evidence articles."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": sorted(entity_types.CORRELATABLE)},
            "entity_id": {"type": "string", "description": "Entity UUID"},
            "depth": {"type": "integer", "default": 1, "description": "Graph traversal depth (1-3)"},
            "window_days": {"type": "integer", "description": "Restrict the evidence window per node to N days"},
        },
        "required": ["entity_type", "entity_id"],
    },
)
async def _get_entity_graph(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_id: str,
    depth: int = 1,
    window_days: int | None = None,
) -> dict:
    from app.intelligence.correlation import build_entity_graph

    return await build_entity_graph(
        db, entity_type, uuid.UUID(entity_id), depth=min(max(depth, 1), 3), window_days=window_days
    )


@_tool(
    name="get_entity_timeline",
    description="Get chronological timeline of when an entity appeared in articles.",
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": sorted(entity_types.CORRELATABLE)},
            "entity_id": {"type": "string", "description": "Entity UUID"},
        },
        "required": ["entity_type", "entity_id"],
    },
)
async def _get_entity_timeline(db: AsyncSession, user_id: uuid.UUID, entity_type: str, entity_id: str) -> dict:
    from app.intelligence.correlation import entity_timeline

    events = await entity_timeline(db, entity_type, uuid.UUID(entity_id))
    return {"events": events}


@_tool(
    name="check_detection_gaps",
    description=(
        "ATT&CK coverage analysis: observed TTPs vs non-draft detection rules, with per-tactic summary and the "
        "list of uncovered techniques. TTP-only — CVEs are not part of this analysis."
    ),
    input_schema={"properties": {}},
)
async def _check_detection_gaps(db: AsyncSession, user_id: uuid.UUID) -> dict:
    from app.intelligence.analytics import detection_coverage

    return await detection_coverage(db, include_gaps=True)


@_tool(
    name="check_requirement_match",
    description=(
        "Check an entry against all active intelligence requirements using the real matching engine (linked-entity "
        "hits, then title/body keyword hits, gated by each requirement's min_relevance and feed filter). Read-only: "
        "persists nothing; also returns matches the automated pipeline already persisted for this entry."
    ),
    input_schema={
        "properties": {"entry_id": {"type": "string", "description": "Entry UUID to check"}},
        "required": ["entry_id"],
    },
)
async def _check_requirement_match(db: AsyncSession, user_id: uuid.UUID, entry_id: str) -> dict:
    from app.intelligence.requirement_matching import (
        LINKED_ENTITY_KEYS,
        _evaluate_requirement,
        _load_entry_entities,
    )
    from app.models.feed import Feed
    from app.models.intelligence_requirement import RequirementMatch
    from app.services.content_classification import is_reporting_content

    eid = uuid.UUID(entry_id)
    entry = await db.get(Entry, eid)
    if not entry:
        return {"error": "Entry not found"}

    # The automated pipeline skips machine-record content (rule-repo files, NVD
    # records); report the flag but still evaluate — this is an interactive check.
    feed = await db.get(Feed, entry.feed_id)
    auto_match_eligible = is_reporting_content(feed.feed_type if feed else None, entry.metadata_)

    title_text = (entry.title or "").lower()
    body_text = " ".join(filter(None, [entry.summary, entry.content_text])).lower()

    reqs_q = await db.execute(select(IntelligenceRequirement).where(IntelligenceRequirement.status == "active"))
    requirements = reqs_q.scalars().all()

    entry_entities = None
    if any((req.linked_entities or {}).get(key) for req in requirements for key in LINKED_ENTITY_KEYS):
        entry_entities = await _load_entry_entities(db, eid)

    persisted_q = await db.execute(select(RequirementMatch).where(RequirementMatch.entry_id == eid))
    persisted_by_req = {m.requirement_id: m for m in persisted_q.scalars()}

    matches = []
    for req in requirements:
        if req.linked_feed_ids and entry.feed_id not in req.linked_feed_ids:
            continue
        evaluated = _evaluate_requirement(req, title_text, body_text, entry_entities)
        if not evaluated:
            continue
        match_type, matched_on, relevance = evaluated
        matches.append(
            {
                "requirement_id": str(req.id),
                "title": req.title,
                "priority": req.priority,
                "match_type": match_type,
                "matched_on": matched_on,
                "relevance": relevance,
                "auto_match": req.auto_match,
                "already_persisted": req.id in persisted_by_req,
            }
        )

    req_titles = {r.id: r.title for r in requirements}
    persisted_matches = [
        {
            "requirement_id": str(m.requirement_id),
            "title": req_titles.get(m.requirement_id),
            "match_type": m.match_type,
            "matched_on": m.matched_on,
            "relevance": m.relevance,
            "matched_at": m.matched_at.isoformat() if m.matched_at else None,
        }
        for m in persisted_by_req.values()
    ]

    return {
        "entry_id": entry_id,
        "entry_title": entry.title,
        "auto_match_eligible": auto_match_eligible,
        "matches": matches,
        "match_count": len(matches),
        "persisted_matches": persisted_matches,
    }


@_tool(
    name="check_telemetry_feasibility",
    description=(
        "Check if detection rules are feasible given configured telemetry sources. Identifies what log sources "
        "are needed vs available."
    ),
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "Optional: detection rule UUID to check"},
        },
    },
)
async def _check_telemetry_feasibility(db: AsyncSession, user_id: uuid.UUID, rule_id: str | None = None) -> dict:
    sources_q = await db.execute(
        select(TelemetrySource).where(TelemetrySource.enabled == True)  # noqa: E712
    )
    sources = sources_q.scalars().all()
    available_log_types = set()
    available_categories = set()
    for s in sources:
        available_categories.add(s.category)
        for lt in s.log_types or []:
            available_log_types.add(lt)

    result = {
        "available_sources": len(sources),
        "available_categories": sorted(available_categories),
        "available_log_types": sorted(available_log_types),
    }

    if rule_id:
        rule_q = await db.execute(select(DetectionRule).where(DetectionRule.id == uuid.UUID(rule_id)))
        rule = rule_q.scalar_one_or_none()
        if rule:
            needed = set(rule.data_sources or [])
            covered = needed & available_log_types
            gaps = needed - available_log_types
            result.update(
                {
                    "rule_title": rule.title,
                    "needed_data_sources": sorted(needed),
                    "covered": sorted(covered),
                    "gaps": sorted(gaps),
                    "feasible": len(gaps) == 0,
                }
            )

    return result


# --- New tools (post-March 2026) ---


@_tool(
    name="get_temporal_clusters",
    description="Find entries sharing entities within time windows — useful for detecting emerging campaigns.",
    input_schema={
        "properties": {
            "days": {"type": "integer", "default": 14, "description": "Lookback window in days"},
            "window_hours": {"type": "integer", "default": 72, "description": "Clustering window in hours"},
            "min_shared": {"type": "integer", "default": 3, "description": "Minimum shared entities to form a cluster"},
            "limit": {"type": "integer", "default": 10},
        },
    },
)
async def _get_temporal_clusters(
    db: AsyncSession, user_id: uuid.UUID, days: int = 14, window_hours: int = 72, min_shared: int = 3, limit: int = 10
) -> list:
    from app.intelligence.correlation import temporal_clusters

    return await temporal_clusters(
        db, days=days, window_hours=window_hours, min_shared_entities=min_shared, limit=limit, user_id=user_id
    )


@_tool(
    name="get_entry_graph",
    description="Get relationship graph for all entities linked to a single entry.",
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID"},
        },
        "required": ["entry_id"],
    },
)
async def _get_entry_graph(db: AsyncSession, user_id: uuid.UUID, entry_id: str) -> dict:
    from app.intelligence.correlation import build_entry_graph

    return await build_entry_graph(db, uuid.UUID(entry_id))
