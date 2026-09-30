"""Serves the repo's ``docs/`` markdown as in-app documentation.

Discovery, titling and slug resolution all live in
``app.services.documentation`` — this router is the HTTP face of it, and the
copilot's ``app.tools.docs`` is the other. When ``docs/`` is missing the index
degrades to empty rather than erroring.
"""

import mimetypes
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi import Path as PathParam
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import decode_token, get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.documentation import (
    DocumentationIndexResponse,
    DocumentationPageResponse,
    DocumentationPageSummary,
)
from app.services import documentation as docs_service

router = APIRouter()


@router.get(
    "",
    response_model=DocumentationIndexResponse,
    summary="List documentation pages",
    description=(
        "Returns every markdown page under `docs/`, grouped by the directory it lives in and "
        "ordered for display. Pages are discovered from disk on every request, so a new doc "
        "appears without a code change or an API restart."
    ),
)
async def list_pages(_user: User = Depends(get_current_user)) -> DocumentationIndexResponse:
    pages = [
        DocumentationPageSummary(slug=p.slug, title=p.title, section=p.section, summary=p.summary)
        for p in docs_service.index()
    ]
    sections: list[str] = []
    for page in pages:
        if page.section not in sections:
            sections.append(page.section)
    return DocumentationIndexResponse(pages=pages, sections=sections)


# Images referenced by the docs markdown (docs/assets/**). Declared above the
# "/{slug:path}" catch-all below, which would otherwise swallow this path.
_ASSET_TYPES = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"}


async def _resolve_user(request: Request, token: str | None, db: AsyncSession) -> User:
    """Accept the JWT via Authorization header, or `?token=` for <img> tags.

    Mirrors app.api.telegram_media: an <img src> cannot set a header, and these
    screenshots show real collection data, so the route stays auth-gated.
    """
    raw_token: str | None = None
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        raw_token = auth_header.split(" ", 1)[1].strip()
    elif token:
        raw_token = token
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    payload = decode_token(raw_token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


@router.get(
    "/assets/{path:path}",
    summary="Get a documentation image",
    description=(
        "Serves an image referenced by the documentation markdown, from `docs/assets/`. "
        "Auth is required; pass the access token in the `Authorization` header or, for an "
        "`<img>` tag that cannot set one, as the `token` query parameter."
    ),
    responses={200: {"content": {"image/png": {}}, "description": "The image bytes."}},
)
async def get_asset(
    request: Request,
    path: str = PathParam(
        description="Path under `docs/assets/`.",
        examples=["screenshots/dashboard.png"],
    ),
    token: str | None = Query(
        default=None,
        description="JWT access token, for <img> tags that cannot send an Authorization header.",
    ),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    await _resolve_user(request, token, db)

    root = docs_service.docs_dir()
    if root is None:
        raise AppError(code="not_found", message="No documentation assets available", status_code=404)

    base = (root / "assets").resolve()
    target = (base / path).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        raise AppError(
            code="invalid_asset_path",
            message="Documentation asset path traversal blocked.",
            status_code=400,
        )

    if target.suffix.lower() not in _ASSET_TYPES or not target.is_file():
        raise AppError(
            code="not_found",
            message=f"No documentation asset named '{path}'",
            status_code=404,
        )

    content_type, _ = mimetypes.guess_type(str(target))
    return FileResponse(
        str(target),
        media_type=content_type or "application/octet-stream",
        headers={"Cache-Control": "private, max-age=86400"},
    )


@router.get(
    "/{slug:path}",
    response_model=DocumentationPageResponse,
    summary="Get one documentation page",
    description=(
        "Returns the raw markdown for a single page. Mermaid fences are left intact and are "
        "rendered client-side. The slug is the path under `docs/` without the `.md` suffix, "
        "e.g. `architecture` or `diagrams/engine-signal-scoring`."
    ),
)
async def get_page(
    slug: str = PathParam(description="Page slug, e.g. `architecture`.", examples=["architecture"]),
    _user: User = Depends(get_current_user),
) -> DocumentationPageResponse:
    page = docs_service.read_page(slug)
    if page is None:
        raise AppError(code="not_found", message=f"No documentation page named '{slug}'", status_code=404)
    title, markdown = page
    return DocumentationPageResponse(
        slug=slug,
        title=title,
        section=docs_service.section_for(slug),
        markdown=markdown,
    )
