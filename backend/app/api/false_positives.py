"""False-positive reporting — analyst-facing feedback loop for autolinker noise.

Three scopes, narrowest first:

- "entry": unlink the entity from this one article. No vocabulary change.
- "alias": the reported surface form isn't a name for this entity — drop it from
  the entity's aliases and unlink every entry that matched *only* via that form.
  The entity itself survives and keeps matching under its other names.
- "global": unlink from this article AND block the surface form from matching for
  every entity type, then rebuild the vocabulary. Does not retroactively unlink
  other entries (use scope="alias" or the entity's unlink-all action for that).

The "global" block is written to ``autolinker_blocked_surface_forms``, not the
curated ``autolinker_false_positive_names`` list: that list is deliberately
bypassed by vendor/product/tool/mitigation (whose real names are common brand
words like "windows" or "chrome"), so writing an analyst's explicit "never match
this" there would silently do nothing for those types.
"""

import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete as sql_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.intelligence.autolinker import refresh_vocabulary
from app.intelligence.correlation import ENTITY_CONFIG, VALID_ENTITY_TYPES
from app.intelligence.correlation_cache import invalidate_entity_cache
from app.models.false_positive_record import FalsePositiveRecord
from app.models.user import User

router = APIRouter()

BLOCKED_FORMS_SETTING = "autolinker_blocked_surface_forms"


class FalsePositiveReportRequest(BaseModel):
    entity_type: str
    entity_id: uuid.UUID
    entity_value: str = Field(min_length=1, max_length=500)
    source_entry_id: uuid.UUID | None = None
    reason: str | None = None
    scope: str = Field(pattern="^(entry|alias|global)$")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "malware",
                "entity_id": "d5b2f1e8-3c4a-4b6d-9e2f-7a8b9c0d1e2f",
                "entity_value": "Prometheus",
                "source_entry_id": "8a7b6c5d-4e3f-42a1-9c8d-7e6f5a4b3c2d",
                "reason": "Article is about the monitoring tool, not the ransomware",
                "scope": "global",
            }
        }
    )


class FalsePositiveReportResponse(BaseModel):
    id: uuid.UUID
    unlinked_from_entry: bool
    added_to_autolinker_fp_list: bool
    alias_removed: bool = False
    links_removed: int = 0


async def _unlink_from_entry(db: AsyncSession, entity_type: str, entity_id: uuid.UUID, entry_id: uuid.UUID) -> bool:
    _, junction, fk_col = ENTITY_CONFIG[entity_type]
    result = await db.execute(sql_delete(junction).where(junction.entry_id == entry_id, fk_col == entity_id))
    await invalidate_entity_cache(entity_type, str(entity_id))
    return result.rowcount > 0


async def _drop_alias(db: AsyncSession, entity_type: str, entity_id: uuid.UUID, surface_form: str) -> tuple[bool, int]:
    """Remove ``surface_form`` from the entity's aliases and unlink entries matched only by it.

    Returns ``(alias_removed, links_removed)``. Junction rows are deleted iff every
    value in their ``matched_names`` array is the reported form — a row that also
    matched the entity's real name stays, because that link is still justified.
    """
    from app.api.entity_profiles import MERGE_CONFIG

    if entity_type not in MERGE_CONFIG:
        raise AppError(
            code="bad_request",
            message=f"{entity_type} entities have no aliases — use scope 'entry' or 'global' instead.",
            status_code=422,
        )

    model_cls, junction_cls, fk_attr = MERGE_CONFIG[entity_type]
    fk_col = getattr(junction_cls, fk_attr)

    entity = (await db.execute(select(model_cls).where(model_cls.id == entity_id))).scalar_one_or_none()
    if entity is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)

    form = surface_form.strip()
    if form.lower() == (entity.name or "").strip().lower():
        raise AppError(
            code="bad_request",
            message=(
                f'"{form}" is this entity\'s primary name, not an alias. '
                "Convert it to another type, merge it into the right entity, or block the name everywhere."
            ),
            status_code=422,
        )

    aliases = list(entity.aliases or [])
    kept = [a for a in aliases if (a or "").strip().lower() != form.lower()]
    alias_removed = len(kept) != len(aliases)
    if alias_removed:
        entity.aliases = kept

    # Unlink entries whose only matched form was the reported one. Rows with an
    # empty matched_names array predate match tracking — leave them alone rather
    # than guessing which name triggered them.
    links_removed = 0
    rows = (await db.execute(select(junction_cls).where(fk_col == entity_id))).scalars().all()
    for row in rows:
        names = row.matched_names or []
        if names and all((n or "").strip().lower() == form.lower() for n in names):
            await db.delete(row)
            links_removed += 1

    if alias_removed or links_removed:
        await invalidate_entity_cache(entity_type, str(entity_id))
    return alias_removed, links_removed


async def _block_surface_form(db: AsyncSession, surface_form: str) -> bool:
    """Add a surface form to the all-types block list. Returns False if already blocked."""
    from app.intelligence.entity_resolution import sync_name_list_setting

    return await sync_name_list_setting(db, BLOCKED_FORMS_SETTING, add=[surface_form])


@router.post("", response_model=FalsePositiveReportResponse, status_code=201)
async def report_false_positive(
    body: FalsePositiveReportRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Report a mislinked entity at one of three scopes.

    `entry` unlinks it from the source article only. `alias` additionally drops the
    reported surface form from the entity's aliases and unlinks every entry that
    matched only via it. `global` blocks the surface form from matching for any
    entity type and rebuilds the autolinker vocabulary. Always writes a
    FalsePositiveRecord audit row.
    """
    if body.entity_type not in VALID_ENTITY_TYPES:
        raise AppError(
            code="bad_request",
            message=f"entity_type must be one of {sorted(VALID_ENTITY_TYPES)}",
            status_code=422,
        )

    unlinked = False
    if body.source_entry_id is not None:
        unlinked = await _unlink_from_entry(db, body.entity_type, body.entity_id, body.source_entry_id)

    alias_removed = False
    links_removed = 0
    if body.scope == "alias":
        alias_removed, links_removed = await _drop_alias(db, body.entity_type, body.entity_id, body.entity_value)

    added_to_fp_list = False
    if body.scope == "global":
        added_to_fp_list = await _block_surface_form(db, body.entity_value)

    record = FalsePositiveRecord(
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        entity_value=body.entity_value,
        source_entry_id=body.source_entry_id,
        reason=body.reason,
        marked_by=user.id,
    )
    db.add(record)
    await db.commit()

    # Rebuild after the commit so the automaton reflects durable state — an alias
    # drop or a new block only takes effect once the vocabulary is regenerated.
    if added_to_fp_list or alias_removed:
        await refresh_vocabulary(db)

    return FalsePositiveReportResponse(
        id=record.id,
        unlinked_from_entry=unlinked,
        added_to_autolinker_fp_list=added_to_fp_list,
        alias_removed=alias_removed,
        links_removed=links_removed,
    )
