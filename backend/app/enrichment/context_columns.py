"""Source context as entity-table columns.

The ``fact``, ``badge`` and ``chips`` Context outputs (``app/enrichment/context.py``)
are short enough to sit in a table cell, so the workbench tables can show them
next to the entity's own columns and sort and filter on them. A column is named
``ctx:<source_type>:<key>``: that is its ``sort_by`` value on an entity list
endpoint, and the query parameter that filters it.

A filter is one of:

* ``text`` — the value contains it (any case; for a list, any item does)
* ``>N`` ``>=N`` ``<N`` ``<=N`` ``=N`` — numbers compare as numbers and a list
  compares by its length; anything else compares as text, so ``>2025-06``
  works on ISO dates
* ``*`` — has a value; ``!`` — has none

Sorting puts entities with no value last in either direction. Lists sort by
length first (Postgres orders ``jsonb`` arrays that way).
"""

from __future__ import annotations

import re
import uuid

from fastapi import Request
from sqlalchemy import Numeric, Text, and_, case, cast, exists, func, literal_column, not_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.enrichment.context import contexts_for
from app.enrichment.manifest import Display, Egress
from app.models.enrichment import EnrichmentSource, EntityContext

PREFIX = "ctx:"
#: The ``sort_by`` spelling of a context column, for the list endpoints' patterns.
SORT_PATTERN = r"ctx:[a-z0-9_]+:[a-z0-9_.]+"
SORT_DOC = "; ctx:<source>:<key> sorts by an enrichment value (GET /api/entities/{type}/context-columns)"
TABLE_DISPLAYS = (Display.FACT, Display.BADGE, Display.CHIPS)

_COMPARE = re.compile(r"^(>=|<=|>|<|=)\s*(.+)$")
_NUMBER = re.compile(r"^-?\d+(\.\d+)?$")


def column_id(source_type: str, key: str) -> str:
    return f"{PREFIX}{source_type}:{key}"


def context_filters(request: Request) -> dict[str, str]:
    """The request's ``ctx:*`` query parameters (a dependency for the list
    endpoints: the column names aren't known until the sources are)."""
    return {k: v.strip() for k, v in request.query_params.items() if k.startswith(PREFIX) and v.strip()}


async def context_columns(db: AsyncSession, entity_type: str, user) -> list[dict]:
    """The context columns ``user`` can see for ``entity_type``: each enabled
    source's table-sized outputs, in source then manifest order. Visitors never
    see a source that sends observables off the box or bars commercial use —
    the same rule as the profile's Context panel."""
    from app.enrichment.registry import SOURCE_REGISTRY

    enabled = set(
        (await db.execute(select(EnrichmentSource.source_type).where(EnrichmentSource.is_enabled.is_(True)))).scalars()
    )
    columns = []
    for cls in sorted(SOURCE_REGISTRY.values(), key=lambda c: c.display_name.casefold()):
        if cls.source_type not in enabled:
            continue
        if user.is_anonymous and (cls.egress == Egress.SHARES_IOC or not cls.license.commercial_ok):
            continue
        for context in contexts_for(cls, entity_type):
            if context.display not in TABLE_DISPLAYS:
                continue
            columns.append(
                {
                    "id": column_id(cls.source_type, context.key),
                    "source_type": cls.source_type,
                    "source_label": cls.display_name,
                    "key": context.key,
                    "label": context.label,
                    "display": context.display,
                }
            )
    return columns


def _value(model, entity_type: str, source_type: str, key: str):
    return (
        select(EntityContext.value)
        .where(
            EntityContext.entity_type == entity_type,
            EntityContext.entity_id == model.id,
            EntityContext.source_type == source_type,
            EntityContext.key == key,
        )
        .correlate(model)
        .scalar_subquery()
    )


def _matches(text: str):
    """The predicate over ``EntityContext.value`` for one filter string."""
    value = EntityContext.value
    as_text = value.op("#>>", return_type=Text)(literal_column("'{}'"))
    if text == "*":
        return None
    compare = _COMPARE.match(text)
    if not compare:
        return as_text.ilike(f"%{text}%")
    op, operand = compare.group(1), compare.group(2).strip()
    kind = func.jsonb_typeof(value)
    if _NUMBER.match(operand):
        left = case(
            (kind == "number", cast(as_text, Numeric)),
            (kind == "array", func.jsonb_array_length(value)),
        )
        right = cast(operand, Numeric)
    else:
        if op == "=":
            return and_(kind == "string", func.lower(as_text) == operand.lower())
        left, right = case((kind == "string", as_text)), operand
    return {">": left > right, ">=": left >= right, "<": left < right, "<=": left <= right, "=": left == right}[op]


async def context_query(
    db: AsyncSession, model, entity_type: str, user, sort_by: str, filters: dict[str, str]
) -> tuple[list, object | None]:
    """The WHERE clauses for ``filters`` and, when ``sort_by`` names a context
    column, its sort expression. A column the user can't see is a 400."""
    wanted = set(filters) | ({sort_by} if sort_by.startswith(PREFIX) else set())
    if not wanted:
        return [], None
    allowed = {c["id"]: c for c in await context_columns(db, entity_type, user)}
    unknown = sorted(wanted - set(allowed))
    if unknown:
        raise AppError(
            code="bad_request",
            message=f"Unknown context column for {entity_type}: {', '.join(unknown)}",
            status_code=400,
        )

    where = []
    for col_id, text in filters.items():
        column = allowed[col_id]
        owned = and_(
            EntityContext.entity_type == entity_type,
            EntityContext.entity_id == model.id,
            EntityContext.source_type == column["source_type"],
            EntityContext.key == column["key"],
        )
        if text == "!":
            where.append(not_(exists().where(owned).correlate(model)))
            continue
        predicate = _matches(text)
        where.append(exists().where(owned if predicate is None else and_(owned, predicate)).correlate(model))

    sort_expr = None
    if sort_by in allowed:
        column = allowed[sort_by]
        sort_expr = _value(model, entity_type, column["source_type"], column["key"])
    return where, sort_expr


async def context_values(db: AsyncSession, model, entity_type: str, ids: list[uuid.UUID], user) -> dict[str, dict]:
    """``{entity_id: {column_id: value}}`` for the rows ``user`` can see."""
    if not ids:
        return {}
    columns = {(c["source_type"], c["key"]) for c in await context_columns(db, entity_type, user)}
    if not columns:
        return {}
    # Through the visitor filter: a hidden entity's context isn't served.
    visible = set((await db.execute(select(model.id).where(model.id.in_(ids)))).scalars())
    if not visible:
        return {}
    rows = await db.execute(
        select(EntityContext.entity_id, EntityContext.source_type, EntityContext.key, EntityContext.value).where(
            EntityContext.entity_type == entity_type, EntityContext.entity_id.in_(visible)
        )
    )
    out: dict[str, dict] = {}
    for entity_id, source_type, key, value in rows:
        if (source_type, key) in columns:
            out.setdefault(str(entity_id), {})[column_id(source_type, key)] = value
    return out
