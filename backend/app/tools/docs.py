"""Documentation tools — let the copilot answer from the shipped docs.

The docs tree is the same one the Documentation page renders
(``app.services.documentation``). Exposing it as tools means "how do I set up
Telegram?" or "what does the signal engine score on?" is answered from the
version of the docs that shipped with this deployment, with a citable slug,
instead of from the model's recollection of the product.

Read-only by construction: these only ever read markdown off the read-only
``docs/`` mount.
"""

from sqlalchemy.ext.asyncio import AsyncSession

from app.services import documentation as docs_service
from app.tools import _tool

# Excerpt budget per matching page. Enough to carry a full paragraph of context
# around the hit without letting one broad query flood the model's window.
_EXCERPT_CHARS = 400
_MAX_EXCERPTS_PER_PAGE = 3


def _excerpts(markdown: str, needle: str) -> tuple[int, list[str]]:
    """Count case-insensitive hits and render up to N windows around the first few."""
    haystack = markdown.lower()
    hits: list[int] = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            break
        hits.append(idx)
        start = idx + len(needle)

    windows: list[str] = []
    for idx in hits[:_MAX_EXCERPTS_PER_PAGE]:
        lo = max(0, idx - _EXCERPT_CHARS // 2)
        hi = min(len(markdown), idx + _EXCERPT_CHARS // 2)
        snippet = " ".join(markdown[lo:hi].split())
        windows.append(f"{'…' if lo > 0 else ''}{snippet}{'…' if hi < len(markdown) else ''}")
    return len(hits), windows


@_tool(
    "list_documentation_pages",
    "List every IntelFeed documentation page shipped with this deployment (slug, title, "
    "section, one-line summary). Start here when answering a question about how IntelFeed "
    "works, then fetch the relevant page with get_documentation_page.",
    {"properties": {}, "required": []},
)
async def list_documentation_pages(db: AsyncSession, user_id, **kwargs):
    pages = docs_service.index()
    return {
        "count": len(pages),
        "pages": [{"slug": p.slug, "title": p.title, "section": p.section, "summary": p.summary} for p in pages],
    }


@_tool(
    "get_documentation_page",
    "Read one IntelFeed documentation page in full, as markdown. The slug is the path under "
    "docs/ without the .md suffix, e.g. 'architecture', 'user-guide' or "
    "'diagrams/entry-pipeline'. Cite the page you used as a /documentation/<slug> link.",
    {
        "properties": {
            "slug": {
                "type": "string",
                "description": "Page slug, e.g. 'architecture' or 'diagrams/entry-pipeline'.",
            }
        },
        "required": ["slug"],
    },
)
async def get_documentation_page(db: AsyncSession, user_id, slug: str, **kwargs):
    page = docs_service.read_page(slug)
    if page is None:
        available = [p.slug for p in docs_service.index()]
        return {"error": f"No documentation page named '{slug}'", "available_slugs": available}
    title, markdown = page
    return {
        "slug": slug,
        "title": title,
        "section": docs_service.section_for(slug),
        "url": f"/documentation/{slug}",
        "markdown": markdown,
    }


@_tool(
    "search_documentation",
    "Full-text search across all IntelFeed documentation, returning the pages that mention a "
    "term along with excerpts around each hit. Use this to find which page covers a topic, "
    "then read it with get_documentation_page.",
    {
        "properties": {
            "query": {"type": "string", "description": "Text to search for across the docs."},
            "limit": {
                "type": "integer",
                "description": "Maximum pages to return (default 8).",
                "default": 8,
            },
        },
        "required": ["query"],
    },
)
async def search_documentation(db: AsyncSession, user_id, query: str, limit: int = 8, **kwargs):
    needle = (query or "").strip().lower()
    if not needle:
        return {"error": "query is required"}

    matches = []
    for page in docs_service.index():
        read = docs_service.read_page(page.slug)
        if read is None:
            continue
        _, markdown = read
        # A title hit is worth more than a body hit — a page named after the
        # topic is almost always the page the analyst wants.
        title_hit = needle in page.title.lower()
        count, windows = _excerpts(markdown, needle)
        if not count and not title_hit:
            continue
        matches.append(
            {
                "slug": page.slug,
                "title": page.title,
                "section": page.section,
                "url": f"/documentation/{page.slug}",
                "match_count": count,
                "excerpts": windows,
                "_rank": (0 if title_hit else 1, -count),
            }
        )

    matches.sort(key=lambda m: m["_rank"])
    for m in matches:
        del m["_rank"]
    return {"query": query, "total_matches": len(matches), "pages": matches[: max(1, limit)]}
