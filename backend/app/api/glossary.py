import re
import uuid

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user, get_viewer
from app.database import get_db
from app.models.entry import Entry
from app.models.glossary_term import GlossaryTerm
from app.models.user import User
from app.schemas.glossary import (
    NIST_CSF_CATEGORIES,
    NIST_CSF_COLORS,
    DetectRequest,
    GlossaryCategoryResponse,
    GlossaryMatchResponse,
    GlossaryTermCreate,
    GlossaryTermResponse,
    GlossaryTermUpdate,
)

router = APIRouter()


def _term_response(term: GlossaryTerm) -> GlossaryTermResponse:
    return GlossaryTermResponse(
        id=term.id,
        name=term.name,
        category=term.category,
        maturity=term.maturity,
        description=term.description,
        long_description=term.long_description,
        technologies=term.technologies or [],
        search_terms=term.search_terms or [],
        is_system=term.is_system,
        created_by=term.created_by,
        created_at=term.created_at,
        updated_at=term.updated_at,
    )


@router.get("", response_model=list[GlossaryTermResponse])
async def list_glossary_terms(
    category: str | None = Query(
        default=None, description="Filter by exact category name (e.g. a NIST CSF function like 'detect')."
    ),
    search: str | None = Query(default=None, description="Case-insensitive substring match on term names."),
    is_system: bool | None = Query(
        default=None, description="true = built-in terms only, false = user-created terms only."
    ),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List glossary terms alphabetically, with optional category, name-search, and system/user filters."""
    query = select(GlossaryTerm)

    if category is not None:
        query = query.where(GlossaryTerm.category == category)

    if is_system is not None:
        if is_system:
            query = query.where(GlossaryTerm.is_system == True)  # noqa: E712
        else:
            query = query.where(GlossaryTerm.is_system == False)  # noqa: E712

    if search:
        query = query.where(GlossaryTerm.name.ilike(f"%{search}%"))

    query = query.order_by(GlossaryTerm.name)

    result = await db.execute(query)
    return [_term_response(t) for t in result.scalars().all()]


_COUNTS_CACHE_PREFIX = "intelfeed:glossary:counts:"
_COUNTS_CACHE_TTL = 600


async def _drop_counts_cache() -> None:
    """Forget cached counts once a term's names change."""
    from app.services.redis_client import get_redis

    try:
        redis = await get_redis()
        keys = [k async for k in redis.scan_iter(match=_COUNTS_CACHE_PREFIX + "*")]
        if keys:
            await redis.delete(*keys)
    except Exception:
        pass


@router.post("", response_model=GlossaryTermResponse, status_code=201)
async def create_glossary_term(
    body: GlossaryTermCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a user glossary term. Returns 409 if a term with the same name already exists."""
    existing = await db.execute(
        select(GlossaryTerm).where(
            GlossaryTerm.name == body.name,
        )
    )
    if existing.scalar_one_or_none():
        raise AppError(code="conflict", message="Glossary term with this name already exists", status_code=409)

    term = GlossaryTerm(
        created_by=user.id,
        is_system=False,
        name=body.name,
        category=body.category,
        maturity=body.maturity,
        description=body.description,
        long_description=body.long_description,
        technologies=[t.model_dump() for t in body.technologies],
        search_terms=body.search_terms,
    )
    db.add(term)
    await db.flush()
    await _drop_counts_cache()
    await db.refresh(term)
    return _term_response(term)


@router.put("/{term_id}", response_model=GlossaryTermResponse)
async def update_glossary_term(
    term_id: uuid.UUID = Path(..., description="Glossary term UUID."),
    body: GlossaryTermUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a glossary term. Only non-null fields are applied; renaming to an existing term's name returns 409."""
    result = await db.execute(select(GlossaryTerm).where(GlossaryTerm.id == term_id))
    term = result.scalar_one_or_none()
    if not term:
        raise AppError(code="not_found", message="Glossary term not found", status_code=404)

    if body.name is not None:
        dup = await db.execute(
            select(GlossaryTerm).where(
                GlossaryTerm.name == body.name,
                GlossaryTerm.id != term_id,
            )
        )
        if dup.scalar_one_or_none():
            raise AppError(code="conflict", message="Glossary term with this name already exists", status_code=409)
        term.name = body.name
    if body.category is not None:
        term.category = body.category
    if body.maturity is not None:
        term.maturity = body.maturity
    if body.description is not None:
        term.description = body.description
    if body.long_description is not None:
        term.long_description = body.long_description
    if body.technologies is not None:
        term.technologies = [t.model_dump() for t in body.technologies]
    if body.search_terms is not None:
        term.search_terms = body.search_terms

    db.add(term)
    await db.flush()
    await _drop_counts_cache()
    await db.refresh(term)
    return _term_response(term)


@router.delete("/{term_id}", status_code=204)
async def delete_glossary_term(
    term_id: uuid.UUID = Path(..., description="Glossary term UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a user-created glossary term. System terms cannot be deleted (403)."""
    result = await db.execute(select(GlossaryTerm).where(GlossaryTerm.id == term_id))
    term = result.scalar_one_or_none()
    if not term:
        raise AppError(code="not_found", message="Glossary term not found", status_code=404)

    if term.is_system:
        raise AppError(code="forbidden", message="Cannot delete system glossary terms", status_code=403)

    await db.delete(term)
    await db.flush()
    await _drop_counts_cache()


@router.get("/categories", response_model=list[GlossaryCategoryResponse])
async def list_glossary_categories(
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List distinct glossary categories with their NIST CSF flag and display color."""
    result = await db.execute(select(GlossaryTerm.category).distinct())
    categories = [row[0] for row in result.all()]

    return [
        GlossaryCategoryResponse(
            name=cat,
            is_nist=cat in NIST_CSF_CATEGORIES,
            color=NIST_CSF_COLORS.get(cat, "#6b7280"),
        )
        for cat in sorted(categories)
    ]


@router.get("/counts")
async def get_glossary_counts(
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Return approximate article counts for all visible glossary terms."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    from app.services import meilisearch_client

    result = await db.execute(select(GlossaryTerm))
    terms = result.scalars().all()
    if not terms:
        return {"counts": {}}

    try:
        client = meilisearch_client._get_client()
        index = client.index(meilisearch_client.INDEX_NAME)
    except Exception:
        return {"counts": {}}

    from app.services.public_view import meili_feed_filter, visitor_feed_ids

    # The index holds every feed: a visitor's counts cover the ones they see.
    params: dict = {"limit": 0}
    if feed_filter := meili_feed_filter(await visitor_feed_ids(db)):
        params["filter"] = feed_filter

    # One search per name per term (~2,000 on the seeded glossary): cache the
    # answer per feed filter so neither a visitor loop nor a busy UI repeats it.
    import hashlib
    import json

    from app.services.redis_client import get_redis

    cache_key = _COUNTS_CACHE_PREFIX + hashlib.sha256((params.get("filter") or "").encode()).hexdigest()[:16]
    try:
        redis = await get_redis()
        if cached := await redis.get(cache_key):
            return {"counts": json.loads(cached)}
    except Exception:
        redis = None

    def _search_count(names: list[str]) -> int:
        total = 0
        for name in names:
            try:
                res = index.search(f'"{name}"', params)
                total += res.get("estimatedTotalHits", 0)
            except Exception:
                pass
        return total

    loop = asyncio.get_event_loop()
    counts: dict[str, int] = {}

    def _all_names(t: GlossaryTerm) -> list[str]:
        return [t.name] + (t.search_terms or [])

    # Run searches in thread pool to avoid blocking, batched to limit concurrency
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {str(t.id): loop.run_in_executor(executor, _search_count, _all_names(t)) for t in terms}
        results = await asyncio.gather(*futures.values())
        for term_id, count in zip(futures.keys(), results):
            counts[term_id] = count

    if redis is not None:
        try:
            await redis.set(cache_key, json.dumps(counts), ex=_COUNTS_CACHE_TTL)
        except Exception:
            pass
    return {"counts": counts}


@router.get("/{term_id}/entries")
async def get_term_entries(
    term_id: uuid.UUID = Path(..., description="Glossary term UUID."),
    limit: int = Query(20, ge=1, le=500, description="Maximum number of entries to return."),
    offset: int = Query(0, ge=0, description="Number of entries to skip for pagination."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Find entries that contain this glossary term (exact word-boundary match)."""
    from app.services import meilisearch_client

    result = await db.execute(select(GlossaryTerm).where(GlossaryTerm.id == term_id))
    term = result.scalar_one_or_none()
    if not term:
        raise AppError(code="not_found", message="Glossary term not found", status_code=404)

    # Search all names (display name + search terms)
    all_names = [term.name] + (term.search_terms or [])

    # Build a combined regex for all names
    pattern = re.compile(
        "|".join(r"\b" + re.escape(n) + r"\b" for n in all_names),
        re.IGNORECASE,
    )

    # Get candidates from Meilisearch for each name
    from app.services.public_view import visitor_feed_ids

    # The index holds every feed; a visitor searches the ones they see.
    shown_feeds = await visitor_feed_ids(db)
    if shown_feeds == []:
        return {"entries": [], "total": 0}
    seen_ids: set[str] = set()
    all_candidates: list[dict] = []
    for name in all_names:
        candidates = meilisearch_client.search_entries(query=f'"{name}"', feed_id=shown_feeds, limit=200, sort="newest")
        for hit in candidates.get("hits", []):
            if hit["id"] not in seen_ids:
                seen_ids.add(hit["id"])
                all_candidates.append(hit)

    # Post-filter with exact word-boundary regex
    exact_hits = []
    for hit in all_candidates:
        text = (hit.get("content_text") or "") + " " + (hit.get("title") or "")
        if pattern.search(text):
            exact_hits.append(
                {
                    "id": hit["id"],
                    "title": hit.get("title", ""),
                    "feed_title": hit.get("feed_title", ""),
                    "published_at": hit.get("published_at"),
                }
            )

    total = len(exact_hits)
    page = exact_hits[offset : offset + limit]

    return {"entries": page, "total": total}


@router.post("/detect", response_model=list[GlossaryMatchResponse])
async def detect_glossary_terms(
    body: DetectRequest,
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Detect glossary terms in an entry's text via word-boundary matching, returned with per-term match counts."""
    entry = await db.get(Entry, body.entry_id)
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    text = entry.content_text or entry.summary or ""
    if not text:
        return []

    result = await db.execute(select(GlossaryTerm))
    terms = result.scalars().all()

    # Sort by name length descending so longer terms match first
    terms_sorted = sorted(terms, key=lambda t: len(t.name), reverse=True)

    matches = []
    for term in terms_sorted:
        all_names = [term.name] + (term.search_terms or [])
        pattern = re.compile(
            "|".join(r"\b" + re.escape(n) + r"\b" for n in all_names),
            re.IGNORECASE,
        )
        found = pattern.findall(text)
        if found:
            matches.append(
                GlossaryMatchResponse(
                    term=_term_response(term),
                    match_count=len(found),
                )
            )

    matches.sort(key=lambda m: m.match_count, reverse=True)
    return matches
