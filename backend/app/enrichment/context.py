"""Source context: the ``Context`` outputs of each lookup, stored per entity in
``entity_context`` and served to the profile's Context panel and header badges.

A source declares what it shows (``app/enrichment/manifest.py``). Each lookup
result writes one row per declared output that has a value, shaped for its
display, and removes that source's rows the new result no longer carries.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.base import Source
from app.enrichment.manifest import Context, Display, Egress
from app.models.enrichment import EnrichmentSource, EntityContext

#: How long an expired row is kept before the nightly prune deletes it.
PRUNE_AFTER = timedelta(days=30)


def contexts_for(cls: type[Source], entity_type: str) -> tuple[Context, ...]:
    """The source's Context outputs that apply to ``entity_type``."""
    if entity_type not in cls.applies_to:
        return ()
    return tuple(
        o for o in cls.outputs if isinstance(o, Context) and (not o.entity_types or entity_type in o.entity_types)
    )


def _lookup(data: dict, key: str):
    for part in key.split("."):
        data = data.get(part) if isinstance(data, dict) else None
    return data


def _text(value) -> str | None:
    """A scalar as display text: booleans as yes/no, blanks as None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value).strip()
    return text or None


def _cell(value) -> str | int | float | None:
    """A table cell: a number stays a number, a list or dict becomes one line."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    if isinstance(value, list):
        return ", ".join(t for t in (_text(_cell(v)) for v in value) if t) or None
    if isinstance(value, dict):
        return ", ".join(f"{k} {t}" for k, v in value.items() if (t := _text(_cell(v)))) or None
    return _text(value)


def _url(value) -> str | None:
    # Third-party text becomes an href: only web links.
    return value if isinstance(value, str) and value.startswith(("https://", "http://")) else None


def shape(context: Context, value):
    """``value`` (from parsed_data) as its display stores it, or None when there
    is nothing to show."""
    match context.display:
        case Display.FACT:
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return value
            if isinstance(value, list):
                return _cell(value)
            return None if isinstance(value, dict) else _text(value)
        case Display.CHIPS:
            parts = value.split(",") if isinstance(value, str) else value if isinstance(value, list) else []
            chips = [t for t in (_text(p) for p in parts if not isinstance(p, (dict, list))) if t]
            return list(dict.fromkeys(chips)) or None
        case Display.TABLE:
            if not isinstance(value, list):
                return None
            columns = list(context.item or {})
            rows = []
            for row in value:
                cells = [
                    _cell(row.get(k) if isinstance(row, dict) else row if k is None else None)
                    for k in (context.item or {}).values()
                ]
                if any(c is not None for c in cells):
                    rows.append(cells)
            return {"columns": columns, "rows": rows} if rows else None
        case Display.TIMELINE:
            if not isinstance(value, list):
                return None
            date_key, text_key = (context.item or {}).get("date"), (context.item or {}).get("text")
            events = [
                {"date": date, "text": text}
                for row in value
                if isinstance(row, dict) and (date := _text(row.get(date_key))) and (text := _text(row.get(text_key)))
            ]
            return events or None
        case Display.LINK:
            if isinstance(value, dict):
                url = _url(value.get("url"))
                label = _text(value.get("label"))
                return ({"url": url, "label": label} if label else {"url": url}) if url else None
            url = _url(value)
            return {"url": url} if url else None
        case Display.BADGE:
            return value if isinstance(value, (str, int, float, bool)) else None


async def store_context(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    source_type: str,
    parsed_data: dict,
    observed_at: datetime,
    expires_at: datetime,
) -> None:
    """Write a lookup result's Context outputs for the entity, replacing what
    this source said before: a key the result no longer carries is deleted."""
    from app.enrichment.registry import SOURCE_REGISTRY

    cls = SOURCE_REGISTRY.get(source_type)
    if cls is None:
        return
    values = {}
    for context in contexts_for(cls, entity_type):
        value = shape(context, _lookup(parsed_data or {}, context.key))
        if value is not None:
            values[context.key] = value

    stale = delete(EntityContext).where(
        EntityContext.entity_type == entity_type,
        EntityContext.entity_id == entity_id,
        EntityContext.source_type == source_type,
    )
    if values:
        stale = stale.where(EntityContext.key.not_in(values))
    await db.execute(stale)
    if not values:
        return
    insert = pg_insert(EntityContext).values(
        [
            {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "source_type": source_type,
                "key": key,
                "value": value,
                "observed_at": observed_at,
                "expires_at": expires_at,
            }
            for key, value in values.items()
        ]
    )
    await db.execute(
        insert.on_conflict_do_update(
            index_elements=["entity_type", "entity_id", "source_type", "key"],
            set_={
                "value": insert.excluded.value,
                "observed_at": insert.excluded.observed_at,
                "expires_at": insert.excluded.expires_at,
            },
        )
    )


def _badge(cls: type[Source], context: Context, value, entity_type: str) -> dict | None:
    tone = (context.tones or {}).get(value)
    if tone is None:
        return None
    badge = {
        "source_type": cls.source_type,
        "key": context.key,
        "label": context.label if value is True else f"{context.label} · {value}",
        "tone": tone,
    }
    # A badge whose key the source also writes to a column names that column,
    # so the header can show the column's provenance.
    field = next(
        (c.path for c in cls.columns() if c.key == context.key and c.entity_type == entity_type),
        None,
    )
    if field:
        badge["field"] = field
    return badge


async def entity_context(
    db: AsyncSession, entity_type: str, entity_id: uuid.UUID, user, kind: str | None = None
) -> dict:
    """The GET /api/entities/{entity_type}/{entity_id}/context body for ``user``.

    ``sources`` holds each enabled source that applies to the type and declares
    context for it, with its stored items (none yet: ``items`` empty and
    ``observed_at`` null); for an observable, only sources that take its
    ``kind``. A source missing a requirement is listed in
    ``unavailable`` for admins, and in ``sources`` only while it has stored
    items. Visitors never see a source that sends observables off the box or
    whose license bars commercial use.
    """
    from app.enrichment.pipeline import resolve_api_key
    from app.enrichment.registry import SOURCE_REGISTRY

    visitor = user.is_anonymous
    is_admin = not visitor and user.role == "admin"
    rows: dict[str, dict[str, EntityContext]] = {}
    for row in (
        await db.execute(
            select(EntityContext).where(EntityContext.entity_type == entity_type, EntityContext.entity_id == entity_id)
        )
    ).scalars():
        rows.setdefault(row.source_type, {})[row.key] = row
    source_rows = {s.source_type: s for s in (await db.execute(select(EnrichmentSource))).scalars()}

    now = datetime.now(UTC)
    sources, unavailable, badges = [], [], []
    for cls in sorted(SOURCE_REGISTRY.values(), key=lambda c: c.display_name.casefold()):
        contexts = contexts_for(cls, entity_type)
        source = source_rows.get(cls.source_type)
        kinds = cls.applies_to.get(entity_type)
        if not contexts or source is None or not source.is_enabled or (kinds and kind not in kinds):
            continue
        if visitor and (cls.egress == Egress.SHARES_IOC or not cls.license.commercial_ok):
            continue
        stored = rows.get(cls.source_type, {})
        if "api_key" in cls.requires and not await resolve_api_key(source, user.id, db):
            if is_admin:
                unavailable.append({"source_type": cls.source_type, "label": cls.display_name, "needs": "api_key"})
            if not stored:
                continue

        items = []
        for context in contexts:
            row = stored.get(context.key)
            if row is None:
                continue
            items.append({"key": context.key, "label": context.label, "display": context.display, "value": row.value})
            if context.display == Display.BADGE and (badge := _badge(cls, context, row.value, entity_type)):
                badges.append(badge)
        latest = max(stored.values(), key=lambda r: r.observed_at, default=None)
        sources.append(
            {
                "source_type": cls.source_type,
                "label": cls.display_name,
                "license": {"name": cls.license.name, "attribution": cls.license.attribution},
                "observed_at": latest.observed_at.isoformat() if latest else None,
                "stale": bool(latest and latest.expires_at <= now),
                "items": items,
            }
        )
    return {"sources": sources, "unavailable": unavailable, "badges": badges, "can_enrich": not visitor}


async def prune_expired_context(db: AsyncSession) -> int:
    """Delete rows that expired more than ``PRUNE_AFTER`` ago. Returns the count."""
    result = await db.execute(delete(EntityContext).where(EntityContext.expires_at < datetime.now(UTC) - PRUNE_AFTER))
    return result.rowcount or 0
