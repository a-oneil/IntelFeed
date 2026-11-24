"""Hunt packs and the hunt package (see app/services/hunt_pack.py, hunt_package.py).

One router for both surfaces: the Threats board drawer asks for a window
scope (7d, 14d, 30d), the profile for ``all``. A pack is a starting point for
a hunt, not a record of one — nothing about the hunt itself is stored here.
"""

from fastapi import APIRouter, Depends, Path, Query
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.query_language import QUERY_LANGUAGES, preferred_query_language
from app.ai.query_language import language as query_language
from app.core.content_disposition import attachment
from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.threat_board import HuntPackResponse
from app.services import hunt_pack as hp

router = APIRouter()

_TYPES = ", ".join(hp.HUNT_TYPES)
_TYPE_DESC = f"One of {_TYPES}"
_KEY_DESC = "Entity uuid, or the canonical id the board uses (CVE-2026-1234, T1059.001)"
_SCOPE_DESC = "all (everything reported, the profile's pack) or a Threats board window: 7d, 14d, 30d"
_LANGUAGE_DESC = (
    "Query language id (kql, spl, esql, eql, cql, yaral, aql, sumo, sql, panther, sigma); "
    "defaults to the user's query_language setting"
)
_SCOPE_PATTERN = "^(7d|14d|30d|all)$"


def _language(requested: str | None, user: User) -> str:
    if requested is None:
        return preferred_query_language(user.settings)
    if requested not in QUERY_LANGUAGES:
        raise AppError(
            code="bad_request",
            message=f"language must be one of {', '.join(QUERY_LANGUAGES)}",
            status_code=400,
        )
    return requested


def _check_type(entity_type: str) -> None:
    if entity_type not in hp.HUNT_TYPES:
        raise AppError(
            code="bad_request",
            message=f"Hunt packs can be drafted for {_TYPES} only.",
            status_code=400,
        )


async def _response(db: AsyncSession, entity_type: str, entity_key: str, scope: str, lang: str) -> HuntPackResponse:
    try:
        state = await hp.pack_status(db, entity_type, entity_key, scope, lang)
    except LookupError:
        raise AppError(code="not_found", message="Entity not found", status_code=404) from None
    pack = await hp.annotate_techniques(db, await hp.annotate_telemetry(db, state["pack"])) if state["pack"] else None
    return HuntPackResponse(
        status=state["status"],
        language=lang,
        language_name=query_language(lang).name,
        pack=pack,
        started_at=state["started_at"],
        error=state["error"],
    )


@router.get("/{entity_type}/{entity_key}", response_model=HuntPackResponse)
async def get_hunt_pack(
    entity_type: str = Path(..., description=_TYPE_DESC),
    entity_key: str = Path(..., description=_KEY_DESC),
    scope: str = Query(hp.PROFILE_SCOPE, pattern=_SCOPE_PATTERN, description=_SCOPE_DESC),
    language: str | None = Query(None, description=_LANGUAGE_DESC),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The entity's hunt pack for a scope and language, and whether a draft is running.

    `status` is `none` until someone drafts one, `drafting` while the AI
    worker writes it (poll this; `pack` still holds the previous pack, if
    any), `ready`, or `failed` with the reason in `error`. Each hypothesis's
    `telemetry` is checked against the enabled telemetry inventory at read
    time, so ticking a source in Settings flips `runnable` without a redraft.
    """
    _check_type(entity_type)
    return await _response(db, entity_type, entity_key, scope, _language(language, user))


@router.post("/{entity_type}/{entity_key}", response_model=HuntPackResponse, status_code=202)
async def draft_hunt_pack(
    entity_type: str = Path(..., description=_TYPE_DESC),
    entity_key: str = Path(..., description=_KEY_DESC),
    scope: str = Query(hp.PROFILE_SCOPE, pattern=_SCOPE_PATTERN, description=_SCOPE_DESC),
    language: str | None = Query(None, description=_LANGUAGE_DESC),
    more: bool = Query(
        False,
        description="Draft more: keep the existing hypotheses and add new ones after them (H6, H7…), "
        "instead of replacing the pack",
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Queue a draft (or redraft) of the entity's hunt pack on the AI worker.

    Returns at once with `status: drafting`; poll GET for the result. A board
    window drafts one to three hypotheses from that window; `all` drafts up
    to five from the entity's claimed techniques and tools, techniques with
    no rule first. The result replaces any cached pack for this entity, scope
    and language. 422 when the `hunt_pack` AI task has no provider; 409 when
    there is nothing to hypothesize from, or the engine is stopped.
    """
    _check_type(entity_type)
    lang = _language(language, user)
    try:
        await hp.start_draft(db, user.id, entity_type, entity_key, scope, lang, append=more)
    except LookupError:
        raise AppError(code="not_found", message="Entity not found", status_code=404) from None
    except hp.NothingToHunt:
        raise AppError(
            code="nothing_to_hunt",
            message="No articles or extracted techniques to draft hunts from",
            status_code=409,
        ) from None
    except hp.EngineStopped:
        raise AppError(
            code="engine_stopped",
            message="The engine is stopped; start it in Settings › Engine to draft hunts.",
            status_code=409,
        ) from None
    except hp.NotConfigured:
        raise AppError(
            code="not_configured",
            message="The hunt_pack AI task has no provider assigned. Assign one in Settings › AI Configuration.",
            status_code=422,
        ) from None
    return await _response(db, entity_type, entity_key, scope, lang)


@router.get("/{entity_type}/{entity_key}/hunts/{hypothesis_id}.md", response_class=PlainTextResponse)
async def export_hunt_file(
    entity_type: str = Path(..., description=_TYPE_DESC),
    entity_key: str = Path(..., description=_KEY_DESC),
    hypothesis_id: str = Path(..., pattern=r"^H\d{1,2}$", description="The hypothesis, H1..H5"),
    scope: str = Query(hp.PROFILE_SCOPE, pattern=_SCOPE_PATTERN, description=_SCOPE_DESC),
    language: str | None = Query(None, description=_LANGUAGE_DESC),
    hunt_id: str = Query(
        hp.PLACEHOLDER_HUNT_ID,
        pattern=rf"^(H-XXXX|{hp.HUNT_ID_PATTERN[1:-1]})$",
        description="The workspace's next hunt number (H-0042); the H-XXXX placeholder when unknown",
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """One hypothesis as an ATHF hunt file (Markdown download).

    One file per hypothesis, because each is its own hunt in the ATHF
    workspace: YAML frontmatter plus the LOCK body, Learn, Observe and Check
    filled, Keep empty for the hunt itself. `athf hunt validate` passes once
    the file carries a real id: pass `hunt_id` when you know the workspace's
    next number. 404 until a pack has been drafted.
    """
    _check_type(entity_type)
    lang = _language(language, user)
    pack = await hp.get_cached_pack(db, entity_type, entity_key, scope, lang)
    one = hp.single_hypothesis(pack, hypothesis_id) if pack else None
    if one is None:
        raise AppError(code="not_found", message="No such hunt drafted yet", status_code=404)
    one = await hp.annotate_telemetry(db, one)
    body = await hp.build_hunt_file(db, one, hunter=user.username, hunt_id=hunt_id)
    return PlainTextResponse(
        body,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": attachment(hp.hunt_filename(one, hunt_id))},
    )


@router.get("/{entity_type}/{entity_key}/package.zip")
async def download_hunt_package(
    entity_type: str = Path(..., description=_TYPE_DESC),
    entity_key: str = Path(..., description=_KEY_DESC),
    language: str | None = Query(None, description=_LANGUAGE_DESC),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The hunt package: one zip with the entity's hunts, rules, layers, entities, IOCs and articles.

    README.md lists what is inside and what was left out. Hunts come from the
    cached packs (the profile's and any Threats board window's) in the given
    language; draft them first with POST — this download never calls a model.
    """
    from app.services.hunt_package import build_hunt_package

    _check_type(entity_type)
    built = await build_hunt_package(db, user, entity_type, entity_key, _language(language, user))
    if built is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)
    name, data = built
    return Response(content=data, media_type="application/zip", headers={"Content-Disposition": attachment(name)})
