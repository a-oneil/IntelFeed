"""Entity watchlist/mute API — /api/intelligence/watchlist."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, select
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.database import get_db
from app.models.country import Country
from app.models.cve import CVE
from app.models.cwe import CWE
from app.models.malware_family import MalwareFamily
from app.models.observable import Observable
from app.models.product import Product
from app.models.ransomware import RansomwareVictim
from app.models.sector import Sector
from app.models.threat_actor import ThreatActor
from app.models.tool import Tool
from app.models.user import User
from app.models.user_entity_watch import UserEntityWatch
from app.models.vendor import Vendor
from app.services.entity_names import resolve_entity_names

router = APIRouter()

# Weaknesses are watchable for the same reason CVEs are: new vulnerabilities
# land under a class continuously, so "boost anything new under CWE-502" is a
# standing interest. TTPs and mitigations stay out — they don't accrete new
# members the way a weakness class does.
WATCHABLE_ENTITY_TYPES = {
    "threat_actor",
    "malware",
    "cve",
    "cwe",
    "tool",
    "vendor",
    "product",
    "country",
    "sector",
    "ransomware_victim",
    "observable",
}

# entity_type → (model, display-name column)
_ENTITY_NAME_SOURCES = {
    "threat_actor": (ThreatActor, ThreatActor.name),
    "malware": (MalwareFamily, MalwareFamily.name),
    "cve": (CVE, CVE.cve_id),
    "cwe": (CWE, CWE.cwe_id),
    "tool": (Tool, Tool.name),
    "vendor": (Vendor, Vendor.name),
    "product": (Product, Product.name),
    "country": (Country, Country.name),
    "sector": (Sector, Sector.name),
    "ransomware_victim": (RansomwareVictim, RansomwareVictim.name),
    "observable": (Observable, Observable.value),
}


class WatchRequest(BaseModel):
    entity_type: str
    entity_id: uuid.UUID
    mode: str = Field(pattern="^(watch|mute|stack)$")
    boost: float = Field(default=1.0, ge=0.0, le=5.0)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "threat_actor",
                "entity_id": "d5b2c8a1-4f3e-4b7a-9c6d-2e8f1a0b3c4d",
                "mode": "watch",
                "boost": 1.5,
            }
        }
    )


# mode=stack means "I run this" — only vendors and products can be in a stack.
STACK_ENTITY_TYPES = {"vendor", "product"}


class WatchResponse(BaseModel):
    id: uuid.UUID
    entity_type: str
    entity_id: uuid.UUID
    mode: str
    boost: float
    entity_name: str | None = None

    model_config = {"from_attributes": True}


@router.get("", response_model=list[WatchResponse])
async def list_watches(
    mode: str | None = Query(None, description="Filter by watch mode: 'watch', 'mute', or 'stack'"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the current user's entity watches (watch/mute/stack), with resolved entity display names."""
    query = select(UserEntityWatch).where(UserEntityWatch.created_by == user.id)
    if mode is not None:
        query = query.where(UserEntityWatch.mode == mode)
    rows = (await db.execute(query)).scalars().all()
    names = await resolve_entity_names(db, rows, _ENTITY_NAME_SOURCES)
    return [
        WatchResponse(
            id=w.id,
            entity_type=w.entity_type,
            entity_id=w.entity_id,
            mode=w.mode,
            boost=w.boost,
            entity_name=names.get((w.entity_type, w.entity_id)),
        )
        for w in rows
    ]


@router.put("", response_model=WatchResponse)
async def upsert_watch(
    body: WatchRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create or update a watch on an entity for the current user (upsert on entity type + id).

    mode is 'watch', 'mute', or 'stack'; 'stack' ("I run this") is only valid for
    vendors and products. boost weights the entity in priority scoring.
    """
    if body.entity_type not in WATCHABLE_ENTITY_TYPES:
        raise HTTPException(status_code=422, detail=f"entity_type must be one of {sorted(WATCHABLE_ENTITY_TYPES)}")
    if body.mode == "stack" and body.entity_type not in STACK_ENTITY_TYPES:
        raise HTTPException(status_code=422, detail=f"mode=stack requires entity_type in {sorted(STACK_ENTITY_TYPES)}")
    stmt = pg_insert(UserEntityWatch).values(
        id=uuid.uuid4(),
        created_by=user.id,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        mode=body.mode,
        boost=body.boost,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_user_entity_watch",
        set_={"mode": stmt.excluded.mode, "boost": stmt.excluded.boost},
    )
    await db.execute(stmt)

    # Watch IS the board's Track: watching a threat pins it to the Threats
    # page (insert-if-absent — a handled or muted row was a human decision and
    # a watch doesn't outrank it). One verb, one mental model; the nightly
    # promote task remains the backfill for activity-gated cases.
    if body.mode == "watch":
        await _pin_watched_threat(db, body.entity_type, body.entity_id)

    await db.commit()
    row = (
        await db.execute(
            select(UserEntityWatch).where(
                UserEntityWatch.created_by == user.id,
                UserEntityWatch.entity_type == body.entity_type,
                UserEntityWatch.entity_id == body.entity_id,
            )
        )
    ).scalar_one()
    return row


# Entity types the Threats board ranks; their rule_coverage/board key shape.
_BOARD_TYPES = {"threat_actor", "malware", "cve"}


async def _board_key(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> str | None:
    """The board's key for an entity: uuid for threats, cve_id for CVEs."""
    if entity_type == "cve":
        return (
            await db.execute(sa_text("SELECT cve_id FROM cves WHERE id = :id"), {"id": str(entity_id)})
        ).scalar_one_or_none()
    return str(entity_id)


async def _pin_watched_threat(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> None:
    if entity_type not in _BOARD_TYPES:
        return
    key = await _board_key(db, entity_type, entity_id)
    if key is None:
        return
    await db.execute(
        sa_text(
            "INSERT INTO threat_board_state (entity_type, entity_key, state, new_count_at_decision) "
            "VALUES (:et, :ek, 'tracked', 0) ON CONFLICT (entity_type, entity_key) DO NOTHING"
        ),
        {"et": entity_type, "ek": key},
    )


async def _unpin_watched_threat(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> None:
    """Unwatching clears the pin — but ONLY a tracked row. Handled and muted
    are human decisions about the threat itself and survive the unwatch."""
    if entity_type not in _BOARD_TYPES:
        return
    key = await _board_key(db, entity_type, entity_id)
    if key is None:
        return
    await db.execute(
        sa_text("DELETE FROM threat_board_state WHERE entity_type = :et AND entity_key = :ek AND state = 'tracked'"),
        {"et": entity_type, "ek": key},
    )


@router.delete("/{entity_type}/{entity_id}")
async def delete_watch(
    entity_type: str = Path(..., description="Entity type of the watch (e.g. threat_actor, malware, cve, vendor)"),
    entity_id: uuid.UUID = Path(..., description="UUID of the watched entity"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the current user's watch on an entity. Returns 404 if no such watch exists.

    Unwatching a threat also clears its Threats-board pin (tracked only —
    handled/muted are human decisions about the threat and survive)."""
    await _unpin_watched_threat(db, entity_type, entity_id)
    result = await db.execute(
        delete(UserEntityWatch).where(
            UserEntityWatch.created_by == user.id,
            UserEntityWatch.entity_type == entity_type,
            UserEntityWatch.entity_id == entity_id,
        )
    )
    await db.commit()
    if not result.rowcount:
        raise HTTPException(status_code=404, detail="Watch not found")
    return {"deleted": True}
