"""Serves the repo's ``docs/`` markdown as in-app documentation.

Discovery, titling and slug resolution all live in
``app.services.documentation`` — this router is the HTTP face of it, and the
copilot's ``app.tools.docs`` is the other. When ``docs/`` is missing the index
degrades to empty rather than erroring.
"""

from fastapi import APIRouter, Depends
from fastapi import Path as PathParam

from app.core.exceptions import AppError
from app.core.security import get_current_user
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
