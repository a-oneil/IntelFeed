"""GET /api/entities/{entity_type}/{entity_id}/context: what the enabled
enrichment sources say about one entity (app/enrichment/context.py)."""

import uuid

from fastapi import APIRouter, Depends, Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_viewer
from app.database import get_db
from app.enrichment.context import entity_context
from app.intelligence.correlation import ENTITY_CONFIG
from app.models.campaign import Campaign
from app.models.user import User

router = APIRouter()

#: Every profile type's model; a campaign has a profile but no article junction.
_MODELS = {**{t: config[0] for t, config in ENTITY_CONFIG.items()}, "campaign": Campaign}

_EXAMPLE = {
    "sources": [
        {
            "source_type": "shodan",
            "label": "Shodan InternetDB",
            "license": {"name": "InternetDB, free for non-commercial use", "attribution": "Shodan"},
            "observed_at": "2026-10-28T10:00:00+00:00",
            "stale": False,
            "items": [{"key": "ports", "label": "Open ports", "display": "chips", "value": ["22", "443"]}],
        }
    ],
    "unavailable": [{"source_type": "virustotal", "label": "VirusTotal v3", "needs": "api_key"}],
    "badges": [
        {
            "source_type": "greynoise",
            "key": "classification",
            "label": "noise · benign",
            "tone": "success",
            "field": "reputation.gn_classification",
        }
    ],
    "can_enrich": True,
}


@router.get(
    "/{entity_type}/{entity_id}/context",
    responses={200: {"content": {"application/json": {"example": _EXAMPLE}}}},
)
async def get_entity_context(
    entity_type: str = Path(..., description="Entity type slug, e.g. cve or observable."),
    entity_id: uuid.UUID = Path(..., description="Entity UUID."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """The profile's Context panel and header badges, from each source's manifest.

    ``sources`` lists the enabled sources that apply to the entity and declare
    context for it, each with its stored items shaped by display (``fact``,
    ``chips``, ``table``, ``timeline``, ``link``, ``badge``), when it last
    looked, and whether that is past its expiry (``stale``). A source with
    nothing stored yet has empty ``items`` and a null ``observed_at``.
    ``badges`` are the badge items that have a tone; ``field`` names the
    column a badge mirrors. ``unavailable`` lists, for admins only, enabled
    sources missing a requirement such as an API key. Visitors (public
    read-only mode) never see sources that send observables to a third party
    or whose license bars commercial use, and get a 404 for an entity they
    can't see.
    """
    model = _MODELS.get(entity_type)
    if model is None:
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)
    # Through the visitor filter: a hidden entity is not found.
    entity = (await db.execute(select(model).where(model.id == entity_id))).scalar_one_or_none()
    if entity is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)
    return await entity_context(
        db, entity_type, entity_id, user, kind=entity.kind if entity_type == "observable" else None
    )
