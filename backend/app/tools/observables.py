"""Observables ledger tools that *work* the ledger, not just read it: promote
a candidate, correct a row, deny a value, pivot from an actor or family to its
infrastructure, and export a filtered slice.

Read tools (``get_observable`` / ``search_observables``) live in ``read.py``.
This module is mixed, so every write passes ``mutating=True`` explicitly;
``deny_observable`` is admin-only (``ADMIN_TOOLS``) like the API route it mirrors.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.tools import _tool


def _row(o) -> dict:
    return {
        "id": str(o.id),
        "kind": o.kind,
        "value": o.value,
        "label": o.label,
        "role": o.role,
        "status": o.status,
        "infra_tag": o.infra_tag,
        "current_confidence": o.current_confidence,
        "confidence_pinned": o.confidence_pinned,
        "is_denied": o.is_denied,
        "needs_review": o.needs_review,
        "captured_by": o.created_via,
        "evidence": o.evidence,
        "report_count": o.report_count or 0,
        "feed_source_count": o.feed_source_count or 0,
        "sighting_count": o.sighting_count or 0,
        "first_seen_at": str(o.first_seen_at) if o.first_seen_at else None,
        "last_seen_at": str(o.last_seen_at) if o.last_seen_at else None,
    }


async def _index(obs) -> None:
    from app.services.entity_indexer import index_single_entity

    try:
        await index_single_entity("observable", obs)
    except Exception:
        pass


@_tool(
    name="promote_observable",
    description=(
        "The analyst door into the observables ledger: turn a staged candidate (or any value the article "
        "prints) into a ledger row sighted in that entry, with role and evidence. Use kind from: ipv4, ipv6, "
        "domain, url, uri_path, email, md5, sha1, sha256, ja3, ja4, cert_fingerprint, cmdline, path, registry, "
        "scheduled_task, service_name, mutex, named_pipe, user_agent, http_header. Defanged input is normalized; "
        "values that fail the kind's plausibility check are rejected with the reason."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "UUID of the entry the value appears in"},
            "kind": {"type": "string", "description": "Observable kind"},
            "value": {"type": "string", "description": "The value as printed (defanged ok)"},
            "role": {
                "type": "string",
                "description": "c2, delivery, payload, phishing, exfil, exploit, scanning, persistence, execution, "
                "defense_evasion, credential_access, discovery, lateral_movement, collection",
            },
            "evidence": {"type": "string", "description": "The sentence that presents the value as malicious"},
            "label": {"type": "string", "description": "Short human label (optional)"},
        },
        "required": ["entry_id", "kind", "value"],
    },
    mutating=True,
)
async def _promote_observable(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_id: str,
    kind: str,
    value: str,
    role: str | None = None,
    evidence: str | None = None,
    label: str | None = None,
) -> dict:
    from app.intelligence.observables import get_or_create_observable, record_sighting, validate_kind_value
    from app.models.entry import Entry
    from app.models.observable import ALL_KINDS, ROLES

    if kind not in ALL_KINDS:
        return {"error": f"kind must be one of {sorted(ALL_KINDS)}"}
    if role and role not in ROLES:
        return {"error": f"role must be one of {sorted(ROLES)}"}
    eid = uuid.UUID(entry_id)
    entry = await db.get(Entry, eid)
    if entry is None:
        return {"error": "Entry not found"}
    canonical = validate_kind_value(kind, value)
    if canonical is None:
        return {
            "error": f"'{value}' is not a plausible {kind} (generic command, system path, placeholder, or wrong shape)"
        }
    staged = next(
        (c for c in (entry.observable_candidates or []) if c.get("kind") == kind and c.get("value") == canonical), {}
    )
    obs = await get_or_create_observable(
        db,
        kind,
        canonical,
        via="manual",
        entry_id=eid,
        role=role or staged.get("role"),
        evidence=evidence or staged.get("evidence"),
        label=label,
        was_defanged=bool(staged.get("was_defanged")),
    )
    if obs is None:
        return {"error": "This value is on the never-capture list"}
    created = await record_sighting(
        db,
        eid,
        obs,
        source="manual",
        surface_form=staged.get("surface_form") or value,
        confidence=staged.get("confidence"),
    )
    await db.commit()
    await db.refresh(obs)
    await _index(obs)
    if created:
        from app.workers.automation_tasks import dispatch_observable_capture_automations

        dispatch_observable_capture_automations(eid, countdown=0)
    return {"status": "promoted" if created else "already_sighted", "observable": _row(obs)}


@_tool(
    name="update_observable",
    description=(
        "Correct a ledger row: set or change its role, label or description, or pin its confidence so decay "
        "stops. Fields left out are untouched."
    ),
    input_schema={
        "properties": {
            "observable_id": {"type": "string", "description": "Observable UUID"},
            "role": {"type": "string"},
            "label": {"type": "string"},
            "description": {"type": "string"},
            "confidence_pinned": {"type": "boolean"},
        },
        "required": ["observable_id"],
    },
    mutating=True,
)
async def _update_observable(
    db: AsyncSession,
    user_id: uuid.UUID,
    observable_id: str,
    role: str | None = None,
    label: str | None = None,
    description: str | None = None,
    confidence_pinned: bool | None = None,
) -> dict:
    from app.models.observable import ROLES, Observable

    obs = await db.get(Observable, uuid.UUID(observable_id))
    if obs is None:
        return {"error": "Observable not found"}
    if role is not None:
        if role and role not in ROLES:
            return {"error": f"role must be one of {sorted(ROLES)}"}
        obs.role = role or None
    if label is not None:
        obs.label = label.strip() or None
    if description is not None:
        obs.description = description.strip() or None
    if confidence_pinned is not None:
        obs.confidence_pinned = confidence_pinned
    obs.needs_review = False
    await db.commit()
    await db.refresh(obs)
    await _index(obs)
    return {"status": "updated", "observable": _row(obs)}


@_tool(
    name="deny_observable",
    description=(
        "Admin: tombstone a value so it is never captured, sighted or exported again (false positive, benign "
        "infrastructure, your own domain). Works on an existing row by UUID or on any (kind, value) — denying a "
        "value that is not in the ledger creates the tombstone so future doors refuse it. Reversible via the API."
    ),
    input_schema={
        "properties": {
            "observable_id": {"type": "string", "description": "Observable UUID (or give kind + value)"},
            "kind": {"type": "string"},
            "value": {"type": "string"},
            "reason": {"type": "string", "description": "Why (stored as the row's description)"},
        },
        "required": [],
    },
    mutating=True,
)
async def _deny_observable(
    db: AsyncSession,
    user_id: uuid.UUID,
    observable_id: str | None = None,
    kind: str | None = None,
    value: str | None = None,
    reason: str | None = None,
) -> dict:
    from app.intelligence.observables import get_or_create_observable, normalize_value
    from app.models.observable import ALL_KINDS, Observable

    obs = None
    if observable_id:
        obs = await db.get(Observable, uuid.UUID(observable_id))
    elif kind and value:
        if kind not in ALL_KINDS:
            return {"error": f"kind must be one of {sorted(ALL_KINDS)}"}
        canonical = normalize_value(kind, value)
        obs = (
            await db.execute(select(Observable).where(Observable.kind == kind, Observable.value == canonical))
        ).scalar_one_or_none()
        if obs is None:
            obs = await get_or_create_observable(db, kind, canonical, via="manual")
    if obs is None:
        return {"error": "Give observable_id, or kind and value"}
    obs.is_denied = True
    obs.needs_review = False
    if reason:
        obs.description = reason.strip()[:2000]
    await db.commit()
    await db.refresh(obs)
    await _index(obs)
    return {"status": "denied", "observable": _row(obs)}


@_tool(
    name="get_entity_infrastructure",
    description=(
        "Pivot from a threat actor, malware family, campaign or tool to its observables, in two tiers: "
        "'claimed' (attribution edges with evidence — uses / communicates_with / controls, with trust tier) "
        "and 'reported_alongside' (observables a reporting article that names the entity also carried; "
        "indicator-list files and newsletters excluded). Answers 'what infrastructure does X use?'."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": ["threat_actor", "malware", "campaign", "tool"]},
            "entity_id": {"type": "string", "description": "Entity UUID (use the lookup tools to resolve a name)"},
            "limit": {"type": "integer", "description": "Max rows per tier (default 50, cap 500)"},
        },
        "required": ["entity_type", "entity_id"],
    },
    mutating=False,
)
async def _get_entity_infrastructure(
    db: AsyncSession, user_id: uuid.UUID, entity_type: str, entity_id: str, limit: int = 50
) -> dict:
    from app.intelligence.infrastructure import INFRASTRUCTURE_ENTITY_TYPES, get_entity_infrastructure

    if entity_type not in INFRASTRUCTURE_ENTITY_TYPES:
        return {"error": f"entity_type must be one of {sorted(INFRASTRUCTURE_ENTITY_TYPES)}"}
    return await get_entity_infrastructure(db, entity_type, uuid.UUID(entity_id), limit=min(max(limit, 1), 500))


@_tool(
    name="export_observables",
    description=(
        "Export a filtered slice of the ledger as lines (EDL), CSV rows, or JSON — the same filters as "
        "search_observables plus a minimum report count and an 'exclude dual-use infrastructure' switch. "
        "Values are returned refanged (operational form). Denied rows and, by default, infra-tagged rows are "
        "excluded."
    ),
    input_schema={
        "properties": {
            "format": {"type": "string", "enum": ["edl", "csv", "json"], "default": "edl"},
            "kind": {"type": "string"},
            "role": {"type": "string"},
            "status": {"type": "string", "description": "active, aging, expired (default active)"},
            "min_confidence": {"type": "number"},
            "min_reports": {"type": "integer", "description": "Minimum report_count (articles that reported it)"},
            "include_infra_tagged": {"type": "boolean", "default": False},
            "query": {"type": "string", "description": "Substring of value or label"},
            "limit": {"type": "integer", "description": "Max rows (default 500, cap 5000)"},
        },
        "required": [],
    },
    mutating=False,
)
async def _export_observables(
    db: AsyncSession,
    user_id: uuid.UUID,
    format: str = "edl",
    kind: str | None = None,
    role: str | None = None,
    status: str | None = "active",
    min_confidence: float | None = None,
    min_reports: int | None = None,
    include_infra_tagged: bool = False,
    query: str | None = None,
    limit: int = 500,
) -> dict:
    from app.models.observable import Observable

    q = select(Observable).where(Observable.is_denied.is_(False))
    if not include_infra_tagged:
        q = q.where(Observable.infra_tag.is_(None))
    if kind:
        q = q.where(Observable.kind == kind)
    if role:
        q = q.where(Observable.role == role)
    if status:
        q = q.where(Observable.status == status)
    if min_confidence is not None:
        q = q.where(Observable.current_confidence >= min_confidence)
    if min_reports:
        q = q.where(Observable.report_count >= min_reports)
    if query:
        pattern = f"%{query}%"
        q = q.where(or_(Observable.value.ilike(pattern), Observable.label.ilike(pattern)))
    rows = (
        (await db.execute(q.order_by(Observable.last_seen_at.desc()).limit(min(max(limit, 1), 5000)))).scalars().all()
    )
    generated = datetime.now(UTC).isoformat()
    if format == "edl":
        return {"count": len(rows), "generated_at": generated, "lines": [o.value for o in rows]}
    if format == "csv":
        header = "kind,value,role,confidence,status,reports,feeds,last_seen_at"
        lines = [header] + [
            ",".join(
                [
                    o.kind,
                    '"' + o.value.replace('"', '""') + '"',
                    o.role or "",
                    f"{o.current_confidence:.2f}",
                    o.status,
                    str(o.report_count or 0),
                    str(o.feed_source_count or 0),
                    str(o.last_seen_at or ""),
                ]
            )
            for o in rows
        ]
        return {"count": len(rows), "generated_at": generated, "csv": "\n".join(lines)}
    return {"count": len(rows), "generated_at": generated, "observables": [_row(o) for o in rows]}
