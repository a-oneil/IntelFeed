"""GET /api/entities/{entity_type}/{entity_id}/context: what the enabled
enrichment sources say about one entity (app/enrichment/context.py)."""

import uuid

from fastapi import APIRouter, Depends, Path
from pydantic import BaseModel, ConfigDict, Field
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


class ContextColumn(BaseModel):
    id: str = Field(description="ctx:<source_type>:<key>: the sort_by value and filter parameter on the list endpoint")
    source_type: str
    source_label: str
    key: str
    label: str
    display: str = Field(description="fact, badge or chips")


class ContextValuesRequest(BaseModel):
    ids: list[uuid.UUID] = Field(description="Entity UUIDs (the rows the table has loaded); the first 1000 are served")


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
            "key": "noise_class",
            "label": "noise · benign",
            "tone": "success",
            "field": "noise_class",
        }
    ],
    "can_enrich": True,
}


@router.get("/{entity_type}/context-columns", response_model=list[ContextColumn])
async def get_context_columns(
    entity_type: str = Path(..., description="Entity type slug, e.g. cve or observable."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """The enrichment values the entity table can show as columns: each enabled
    source's ``fact``, ``badge`` and ``chips`` outputs for the type
    (``app/enrichment/context_columns.py``). The type's list endpoint sorts on
    a column with ``sort_by=<id>`` and filters it with ``<id>=<filter>``: text
    to match, ``>N``/``<N``/``=N`` (lists compare by length, dates as text),
    ``*`` for any value or ``!`` for none. Visitors don't see sources that send
    observables to a third party or bar commercial use."""
    from app.enrichment.context_columns import context_columns

    if entity_type not in _MODELS:
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)
    return await context_columns(db, entity_type, user)


@router.post(
    "/{entity_type}/context-values",
    responses={200: {"content": {"application/json": {"example": {"<uuid>": {"ctx:epss:epss": 0.94}}}}}},
)
async def get_context_values(
    body: ContextValuesRequest,
    entity_type: str = Path(..., description="Entity type slug, e.g. cve or observable."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """The context-column values of the given entities, ``{entity_id: {column_id:
    value}}``; an entity with none is left out. Only columns the user can see
    (see ``context-columns``), and only entities they can see."""
    from app.enrichment.context_columns import context_values

    model = _MODELS.get(entity_type)
    if model is None:
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)
    return await context_values(db, model, entity_type, body.ids[:1000], user)


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


class GlanceItem(BaseModel):
    text: str
    tone: str | None = Field(description="bad or warn; null is neutral")
    source: str | None = Field(description="The source that said it; null for a count the enrichment links made")
    observed_at: str | None


class GlanceSource(BaseModel):
    source_type: str
    label: str


class GlanceKeySource(GlanceSource):
    key: str | None = Field(description="The credential id the source needs")


class EntityGlanceResponse(BaseModel):
    chips: list[GlanceItem] = Field(description="At most two verdict chips")
    facts: list[GlanceItem] = Field(description="At most three short facts")
    lookup_sources: list[GlanceSource] = Field(description="What the Look up button runs; empty for visitors")
    needs_key: list[GlanceKeySource] = Field(description="Admins only: sources that need a key first")
    looked_up: bool = Field(description="Some source has answered for this entity")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "chips": [
                    {
                        "text": "Exploited in the wild",
                        "tone": "bad",
                        "source": "CISA KEV",
                        "observed_at": "2026-10-28T10:00:00+00:00",
                    }
                ],
                "facts": [
                    {"text": "EPSS 0.94", "tone": None, "source": "EPSS", "observed_at": "2026-10-28T10:00:00+00:00"}
                ],
                "lookup_sources": [{"source_type": "nvd", "label": "NVD"}],
                "needs_key": [{"source_type": "vulncheck", "label": "VulnCheck", "key": "vulncheck_api_key"}],
                "looked_up": True,
            }
        }
    )


@router.get("/{entity_type}/{entity_id}/glance", response_model=EntityGlanceResponse)
async def get_entity_glance(
    entity_type: str = Path(..., description="Entity type slug, e.g. cve or observable."),
    entity_id: uuid.UUID = Path(..., description="Entity UUID."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """The highlight popover's glance: up to two verdict ``chips`` (``tone``
    bad or warn) and three neutral ``facts`` from enrichment, each with the
    source that said it and when (``app/enrichment/glance.py``). Empty lists
    when nothing has been looked up. ``lookup_sources`` are the sources the
    popover's Look up button runs for this entity (none for visitors);
    ``needs_key`` lists, for admins, sources that need a key first; and
    ``looked_up`` says whether any source has answered yet. Visitors never see
    sources that send observables to a third party or bar commercial use, and
    get a 404 for an entity they can't see."""
    from app.enrichment.glance import entity_for, glance

    if entity_type not in _MODELS:
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)
    entity = await entity_for(db, entity_type, entity_id)
    if entity is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)
    return await glance(db, entity_type, entity, user)
