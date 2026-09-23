"""Batch resolution of display names for (entity_type, entity_id) references.

Callers supply their own entity_type -> (Model, name_column) mapping, since
each feature supports a different subset of entity types (e.g. notes cover
ttp/campaign, watchlist covers tool/country).
"""

import uuid
from collections import defaultdict
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def resolve_entity_names(
    db: AsyncSession,
    items: Iterable,
    sources: dict[str, tuple],
) -> dict[tuple[str, uuid.UUID], str | None]:
    """Resolve display names for objects carrying .entity_type / .entity_id.

    Groups ids by type and runs one query per entity type. Types missing from
    ``sources`` are silently skipped.
    """
    by_type: dict[str, set[uuid.UUID]] = defaultdict(set)
    for item in items:
        by_type[item.entity_type].add(item.entity_id)

    names: dict[tuple[str, uuid.UUID], str | None] = {}
    for entity_type, ids in by_type.items():
        source = sources.get(entity_type)
        if not source:
            continue
        model, name_col = source
        rows = (await db.execute(select(model.id, name_col).where(model.id.in_(ids)))).all()
        for row_id, row_name in rows:
            names[(entity_type, row_id)] = str(row_name) if row_name is not None else None
    return names
