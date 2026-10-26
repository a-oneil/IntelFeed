"""Reader workflow tools — per-user entry state, similar/story lookups, translation,
manual URL ingestion, public share links, and saved searches.

Each tool mirrors its API endpoint (app/api/entries.py, ingest.py, shared.py,
saved_searches.py): same validation, same side effects (unread-cache invalidation,
search-index state sync, pipeline dispatch, TTS pre-generation).
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from datetime import date as date_cls

from sqlalchemy import and_, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.entries import (
    ALLOWED_BULK_ACTIONS,
    _daily_summary_target_id,
    _invalidate_unread_cache,
    _scope_user_id,
)
from app.core.exceptions import AppError
from app.models.entry import Entry
from app.models.entry_state import UserEntryState
from app.models.feed import Feed
from app.models.saved_search import SavedSearch
from app.models.shared_entry import SharedEntry
from app.services import meilisearch_client, translation
from app.services.read_state import has_no_state_for_user
from app.tools import _tool

logger = logging.getLogger(__name__)

# Bulk state actions — imported from the endpoint's canonical set, not restated.
_BULK_ACTIONS = sorted(ALLOWED_BULK_ACTIONS)


async def _get_entry(db: AsyncSession, entry_id: str) -> tuple[Entry | None, dict | None]:
    """Fetch an entry by id string; returns (entry, None) or (None, error dict)."""
    try:
        eid = uuid.UUID(entry_id)
    except ValueError:
        return None, {"error": f"Invalid entry_id: {entry_id}"}
    entry = (await db.execute(select(Entry).where(Entry.id == eid))).scalar_one_or_none()
    if not entry:
        return None, {"error": f"Entry not found (id: {entry_id})"}
    return entry, None


async def _get_or_create_state(db: AsyncSession, user_id: uuid.UUID, entry_id: uuid.UUID) -> UserEntryState:
    result = await db.execute(
        select(UserEntryState).where(UserEntryState.user_id == user_id, UserEntryState.entry_id == entry_id)
    )
    state = result.scalar_one_or_none()
    if not state:
        state = UserEntryState(user_id=user_id, entry_id=entry_id)
        db.add(state)
    return state


# ---------------------------------------------------------------------------
# Per-entry read/star/bookmark state
# ---------------------------------------------------------------------------


@_tool(
    name="mark_entry_read",
    description=(
        "Mark an entry as read (read=true, the default) or unread (read=false) for the current "
        "user. Also syncs the flag to the search index and invalidates the feed unread-count cache."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID"},
            "read": {"type": "boolean", "description": "true = mark read (default); false = mark unread"},
        },
        "required": ["entry_id"],
    },
    mutating=True,
)
async def _mark_entry_read(db: AsyncSession, user_id: uuid.UUID, entry_id: str, read: bool = True) -> dict:
    entry, err = await _get_entry(db, entry_id)
    if err:
        return err
    state = await _get_or_create_state(db, user_id, entry.id)
    state.is_read = read
    state.read_at = func.now() if read else None
    db.add(state)
    await db.flush()
    await _invalidate_unread_cache(user_id)
    meilisearch_client.update_entry_state(entry.id, is_read=read)
    return {"entry_id": str(entry.id), "is_read": read, "message": "Marked as read" if read else "Marked as unread"}


@_tool(
    name="star_entry",
    description=(
        "Set an entry's starred flag for the current user (starred=true by default; pass false to "
        "unstar). Syncs the flag to the search index. Returns the new value."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID"},
            "starred": {"type": "boolean", "description": "true = star (default); false = unstar"},
        },
        "required": ["entry_id"],
    },
    mutating=True,
)
async def _star_entry(db: AsyncSession, user_id: uuid.UUID, entry_id: str, starred: bool = True) -> dict:
    entry, err = await _get_entry(db, entry_id)
    if err:
        return err
    state = await _get_or_create_state(db, user_id, entry.id)
    state.is_starred = starred
    db.add(state)
    await db.flush()
    meilisearch_client.update_entry_state(entry.id, is_starred=starred)
    return {"entry_id": str(entry.id), "is_starred": starred}


@_tool(
    name="bookmark_entry",
    description=(
        "Set an entry's bookmarked flag for the current user (bookmarked=true by default; pass "
        "false to remove the bookmark). Syncs the flag to the search index. Returns the new value."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID"},
            "bookmarked": {"type": "boolean", "description": "true = bookmark (default); false = remove"},
        },
        "required": ["entry_id"],
    },
    mutating=True,
)
async def _bookmark_entry(db: AsyncSession, user_id: uuid.UUID, entry_id: str, bookmarked: bool = True) -> dict:
    entry, err = await _get_entry(db, entry_id)
    if err:
        return err
    state = await _get_or_create_state(db, user_id, entry.id)
    state.is_bookmarked = bookmarked
    db.add(state)
    await db.flush()
    meilisearch_client.update_entry_state(entry.id, is_bookmarked=bookmarked)
    return {"entry_id": str(entry.id), "is_bookmarked": bookmarked}


@_tool(
    name="bulk_entry_action",
    description=(
        "Apply one state action to a list of entries for the current user: read, unread, star, "
        "unstar, bookmark, unbookmark, or hide (hide also marks the entries read). Syncs state to "
        "the search index. Returns the count of entries actually changed."
    ),
    input_schema={
        "properties": {
            "entry_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Entry UUIDs to act on",
            },
            "action": {
                "type": "string",
                "enum": _BULK_ACTIONS,
                "description": "State action to apply to every entry",
            },
        },
        "required": ["entry_ids", "action"],
    },
    mutating=True,
)
async def _bulk_entry_action(db: AsyncSession, user_id: uuid.UUID, entry_ids: list[str], action: str) -> dict:
    if action not in ALLOWED_BULK_ACTIONS:
        return {"error": f"Invalid action '{action}'. Must be one of: {', '.join(_BULK_ACTIONS)}"}
    if not entry_ids:
        return {"updated": 0}
    try:
        ids = [uuid.UUID(e) for e in entry_ids]
    except ValueError as exc:
        return {"error": f"Invalid entry id: {exc}"}

    # Act only on entries that exist so a typo'd UUID can't fail the whole batch on flush.
    existing_ids = {row[0] for row in (await db.execute(select(Entry.id).where(Entry.id.in_(ids)))).all()}
    missing = [str(i) for i in ids if i not in existing_ids]
    ids = [i for i in ids if i in existing_ids]
    if not ids:
        return {"error": f"No entries found for the given ids: {missing}"}

    existing_result = await db.execute(
        select(UserEntryState).where(UserEntryState.user_id == user_id, UserEntryState.entry_id.in_(ids))
    )
    states_by_entry = {s.entry_id: s for s in existing_result.scalars().all()}

    updated = 0
    for eid in ids:
        state = states_by_entry.get(eid)
        if not state:
            state = UserEntryState(user_id=user_id, entry_id=eid)
        if action == "read":
            if not state.is_read:
                state.is_read = True
                state.read_at = func.now()
                updated += 1
        elif action == "unread":
            if state.is_read:
                state.is_read = False
                state.read_at = None
                updated += 1
        elif action == "star":
            if not state.is_starred:
                state.is_starred = True
                updated += 1
        elif action == "unstar":
            if state.is_starred:
                state.is_starred = False
                updated += 1
        elif action == "bookmark":
            if not state.is_bookmarked:
                state.is_bookmarked = True
                updated += 1
        elif action == "unbookmark":
            if state.is_bookmarked:
                state.is_bookmarked = False
                updated += 1
        elif action == "hide":
            if not state.is_hidden:
                state.is_hidden = True
                state.is_read = True
                state.read_at = func.now()
                updated += 1
        db.add(state)

    await db.flush()
    if action in ("read", "unread", "hide"):
        await _invalidate_unread_cache(user_id)

    state_map = {
        "read": {"is_read": True},
        "unread": {"is_read": False},
        "star": {"is_starred": True},
        "unstar": {"is_starred": False},
        "bookmark": {"is_bookmarked": True},
        "unbookmark": {"is_bookmarked": False},
        "hide": {"is_read": True},
    }
    meili_kwargs = state_map.get(action, {})
    if meili_kwargs:
        for eid in ids:
            try:
                meilisearch_client.update_entry_state(eid, **meili_kwargs)
            except Exception:
                pass  # Non-critical — search state will self-correct

    result: dict = {"updated": updated, "action": action}
    if missing:
        result["skipped_missing"] = missing
    return result


@_tool(
    name="mark_all_read",
    description=(
        "Bulk-mark entries as read for the current user, optionally scoped to a single feed or a "
        "category. With no scope, marks EVERY entry in every feed as read — confirm intent before "
        "calling unscoped. The search-index sync runs on a background worker. Returns the number "
        "of entries marked."
    ),
    input_schema={
        "properties": {
            "feed_id": {"type": "string", "description": "Optional feed UUID to scope to"},
            "category_id": {"type": "string", "description": "Optional category UUID to scope to"},
        },
        "required": [],
    },
    mutating=True,
)
async def _mark_all_read(
    db: AsyncSession,
    user_id: uuid.UUID,
    feed_id: str | None = None,
    category_id: str | None = None,
) -> dict:
    try:
        fid = uuid.UUID(feed_id) if feed_id else None
        cid = uuid.UUID(category_id) if category_id else None
    except ValueError:
        return {"error": "feed_id/category_id must be UUIDs"}

    from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query

    feed_query = visible_feed_ids_query(user_id, enabled=await subscriptions_enabled(db), include_muted=True)
    if fid:
        feed_query = feed_query.where(Feed.id == fid)
    if cid:
        feed_query = feed_query.where(Feed.category_id == cid)
    feed_ids = [row[0] for row in (await db.execute(feed_query)).all()]
    if not feed_ids:
        return {"marked": 0}

    entry_sub = select(Entry.id).where(Entry.feed_id.in_(feed_ids))

    update_result = await db.execute(
        update(UserEntryState)
        .where(
            UserEntryState.user_id == user_id,
            UserEntryState.entry_id.in_(entry_sub),
            UserEntryState.is_read == False,  # noqa: E712
        )
        .values(is_read=True, read_at=func.now())
        .returning(UserEntryState.entry_id)
    )
    updated_ids = [row[0] for row in update_result.all()]

    missing_sub = entry_sub.where(has_no_state_for_user(user_id))
    missing_ids = [row[0] for row in (await db.execute(missing_sub)).all()]
    if missing_ids:
        await db.execute(
            insert(UserEntryState),
            [
                {
                    "id": uuid.uuid4(),
                    "user_id": user_id,
                    "entry_id": eid,
                    "is_read": True,
                    "is_starred": False,
                    "is_bookmarked": False,
                    "is_hidden": False,
                    "read_at": datetime.now(UTC),
                }
                for eid in missing_ids
            ],
        )

    marked = len(updated_ids) + len(missing_ids)
    if marked == 0:
        return {"marked": 0}

    await db.flush()
    await _invalidate_unread_cache(user_id)

    # Search-index sync runs off-path on a Celery worker (same as the endpoint).
    try:
        from app.workers.intel_feed_tasks import sync_read_state_to_search

        sync_read_state_to_search.delay([str(eid) for eid in (updated_ids + missing_ids)], True)
    except Exception:
        logger.warning("Failed to dispatch read-state search sync", exc_info=True)

    return {"marked": marked}


# ---------------------------------------------------------------------------
# Similar / story / translate / daily summary
# ---------------------------------------------------------------------------


@_tool(
    name="get_similar_entries",
    description=(
        "Find entries similar to the given entry. Answers from the embedding index when the entry "
        "has been embedded — nearest neighbours find the article telling the same story in "
        "different words — and falls back to keyword search over the search index otherwise. "
        "Excludes the entry itself and its exact duplicates (same content hash)."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID"},
            "limit": {"type": "integer", "description": "Maximum similar entries to return (1-30, default 10)"},
        },
        "required": ["entry_id"],
    },
    mutating=False,
)
async def _get_similar_entries(db: AsyncSession, user_id: uuid.UUID, entry_id: str, limit: int = 10) -> dict:
    entry, err = await _get_entry(db, entry_id)
    if err:
        return err
    if not 1 <= limit <= 30:
        return {"error": "limit must be between 1 and 30"}

    duplicate_ids = []
    if entry.content_hash:
        dup_result = await db.execute(
            select(Entry.id).where(Entry.content_hash == entry.content_hash, Entry.id != entry.id)
        )
        duplicate_ids = [row[0] for row in dup_result.all()]

    from app.intelligence.story_threads import similar_entries as vector_similar

    neighbours = await vector_similar(db, entry.id, limit=limit, exclude_ids=duplicate_ids)
    if neighbours:
        return {
            "items": [
                {
                    "id": str(n["entry_id"]),
                    "title": n["title"],
                    "url": n["url"],
                    "feed_title": n["feed_title"],
                    "published_at": n["published_at"],
                    "similarity": round(float(n["similarity"] or 0), 3),
                    "thread_id": str(n["thread_id"]) if n["thread_id"] else None,
                }
                for n in neighbours
            ],
            "total": len(neighbours),
            "query_keywords": [],
            "method": "embedding",
        }

    exclude_ids = [str(entry.id), *(str(d) for d in duplicate_ids)]
    search_result = meilisearch_client.find_similar_entries(
        entry_id=str(entry.id),
        title=entry.title or "",
        summary=entry.summary,
        content_text=entry.content_text,
        exclude_ids=exclude_ids,
        limit=limit,
    )
    return {
        "items": search_result.get("hits", []),
        "total": search_result.get("estimatedTotalHits", 0),
        "query_keywords": search_result.get("query_keywords", []),
        "method": "keyword",
    }


# Entity types strong enough to chain a "story" on their own (a shared CVE or
# actor is a real link; a shared country or vendor alone is too weak/common).
_STORY_STRONG_TYPES = {"cve", "threat_actor", "malware"}
_STORY_WINDOW_DAYS = 30


@_tool(
    name="get_entry_story",
    description=(
        "Chain follow-up/precursor articles to an entry via shared entities: within a ±30 day "
        "window, entries sharing at least one strong entity (CVE, threat actor, malware) or two "
        "entities of any type join the story. Ordered chronologically (a timeline, not a "
        "relevance ranking — use get_similar_entries for that)."
    ),
    input_schema={
        "properties": {"entry_id": {"type": "string", "description": "Entry UUID"}},
        "required": ["entry_id"],
    },
    mutating=False,
)
async def _get_entry_story(db: AsyncSession, user_id: uuid.UUID, entry_id: str) -> dict:
    from app.intelligence.correlation import ENTITY_CONFIG

    source, err = await _get_entry(db, entry_id)
    if err:
        return err

    window_start = (source.published_at or datetime.now(UTC)) - timedelta(days=_STORY_WINDOW_DAYS)
    window_end = (source.published_at or datetime.now(UTC)) + timedelta(days=_STORY_WINDOW_DAYS)

    matches: dict[uuid.UUID, set[tuple[str, uuid.UUID]]] = {}
    for entity_type, (_model, junction, fk_col) in ENTITY_CONFIG.items():
        source_ids_result = await db.execute(select(fk_col).where(junction.entry_id == source.id).distinct())
        source_entity_ids = [row[0] for row in source_ids_result.all()]
        if not source_entity_ids:
            continue
        candidates_result = await db.execute(
            select(junction.entry_id, fk_col)
            .join(Entry, Entry.id == junction.entry_id)
            .where(
                fk_col.in_(source_entity_ids),
                junction.entry_id != source.id,
                Entry.published_at >= window_start,
                Entry.published_at <= window_end,
            )
        )
        for cand_entry_id, cand_entity_id in candidates_result.all():
            matches.setdefault(cand_entry_id, set()).add((entity_type, cand_entity_id))

    if not matches:
        return {"entry_id": str(source.id), "story": []}

    qualifying_ids = [
        eid for eid, ents in matches.items() if len(ents) >= 2 or any(t in _STORY_STRONG_TYPES for t, _ in ents)
    ]
    if not qualifying_ids:
        return {"entry_id": str(source.id), "story": []}

    exclude_ids: set[uuid.UUID] = set()
    if source.content_hash:
        dup_result = await db.execute(
            select(Entry.id).where(Entry.content_hash == source.content_hash, Entry.id != source.id)
        )
        exclude_ids = {row[0] for row in dup_result.all()}

    result = await db.execute(
        select(Entry, Feed.title, UserEntryState.is_read)
        .join(Feed, Feed.id == Entry.feed_id)
        .outerjoin(
            UserEntryState,
            and_(UserEntryState.entry_id == Entry.id, UserEntryState.user_id == user_id),
        )
        .where(Entry.id.in_(qualifying_ids), Entry.id.notin_(exclude_ids))
        .order_by(Entry.published_at.asc())
    )

    story = []
    for entry, feed_title, is_read in result.all():
        shared = matches[entry.id]
        story.append(
            {
                "entry_id": str(entry.id),
                "title": entry.title,
                "feed_title": feed_title,
                "published_at": entry.published_at.isoformat() if entry.published_at else None,
                "is_read": bool(is_read),
                "shared_entity_count": len(shared),
                "shared_entity_types": sorted({t for t, _ in shared}),
            }
        )
    return {"entry_id": str(source.id), "story": story}


@_tool(
    name="translate_entry",
    description=(
        "Translate an entry's HTML content (and title) via the LibreTranslate sidecar and store "
        "the translation on the entry row. Re-requesting with the same target language returns "
        "the cached translation; a different target re-translates. target is an ISO-639-1 code "
        "and defaults to the configured target language (usually 'en')."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID"},
            "target": {"type": "string", "description": "Target ISO-639-1 language code (default from settings)"},
        },
        "required": ["entry_id"],
    },
    mutating=True,
)
async def _translate_entry(db: AsyncSession, user_id: uuid.UUID, entry_id: str, target: str = "") -> dict:
    from app.config import settings as app_settings

    entry, err = await _get_entry(db, entry_id)
    if err:
        return err
    target_lang = (target or app_settings.get("translation_default_target") or "en").lower()

    source_html = entry.content_html or (f"<p>{entry.summary}</p>" if entry.summary else "")
    if not source_html.strip():
        return {"error": "Entry has no content to translate"}

    if entry.translated_html and entry.translation_target_language == target_lang:
        return {
            "entry_id": str(entry.id),
            "translated_html": entry.translated_html,
            "translated_title": entry.translated_title,
            "source_language": entry.translation_source_language or entry.language or "auto",
            "target_language": target_lang,
            "translated_at": entry.translated_at or datetime.now(UTC),
            "cached": True,
        }

    # Only honor a confident detection; otherwise let /translate auto-detect
    # server-side (same heuristic as the endpoint).
    detected_lang = entry.language
    if not detected_lang:
        sample = (entry.content_text or entry.title or "")[:2000]
        if sample.strip():
            try:
                cand, conf = await translation.detect_language(sample)
                if conf >= 0.5:
                    detected_lang = cand
            except translation.TranslationError:
                detected_lang = None

    if detected_lang and detected_lang.lower() == target_lang:
        return {"error": f"Entry is already in {target_lang}"}

    try:
        translated, body_detected = await translation.translate_html(
            source_html, source=detected_lang or "auto", target=target_lang
        )
    except translation.TranslationError as exc:
        return {"error": f"Translation failed: {exc.message}"}

    title_source = detected_lang or body_detected or "auto"
    translated_title: str | None = None
    if entry.title and entry.title.strip():
        try:
            translated_title, _ = await translation.translate_text(entry.title, source=title_source, target=target_lang)
        except translation.TranslationError:
            translated_title = None
        # Auto-detect on short titles can no-op; retry with the body's detected language.
        if (
            translated_title is not None
            and translated_title.strip() == entry.title.strip()
            and title_source == "auto"
            and body_detected
            and body_detected.lower() != target_lang
        ):
            try:
                retried, _ = await translation.translate_text(entry.title, source=body_detected, target=target_lang)
                if retried and retried.strip() != entry.title.strip():
                    translated_title = retried
            except translation.TranslationError:
                pass

    effective_source = detected_lang or body_detected
    now = datetime.now(UTC)
    entry.translated_html = translated
    if translated_title:
        entry.translated_title = translated_title
    entry.translation_source_language = effective_source or "auto"
    entry.translation_target_language = target_lang
    entry.translated_at = now
    if effective_source and not entry.language:
        entry.language = effective_source
    db.add(entry)
    await db.flush()

    return {
        "entry_id": str(entry.id),
        "translated_html": translated,
        "translated_title": translated_title,
        "source_language": effective_source or "auto",
        "target_language": target_lang,
        "translated_at": now,
        "cached": False,
    }


@_tool(
    name="get_daily_summary",
    description=(
        "Return the cached AI daily summary (briefing) for a day, or null if none has been "
        "generated. date is YYYY-MM-DD, defaulting to today (UTC). Read-only: this never "
        "generates a summary — generation runs via the daily_summary AI task/automation."
    ),
    input_schema={
        "properties": {
            "date": {"type": "string", "description": "Day key YYYY-MM-DD (default: today, UTC)"},
        },
        "required": [],
    },
    mutating=False,
)
async def _get_daily_summary(db: AsyncSession, user_id: uuid.UUID, date: str | None = None) -> dict:
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    day_key = date or date_cls.today().isoformat()
    try:
        date_cls.fromisoformat(day_key)
    except ValueError:
        return {"error": f"Invalid date '{day_key}': expected YYYY-MM-DD"}

    # Default (unfiltered) briefing scope — shared across users via the sentinel key.
    filters_dict = {
        "feed_id": None,
        "category_id": None,
        "is_read": None,
        "is_starred": None,
        "is_bookmarked": None,
        "content_type": None,
        "change_type": None,
        "country_id": None,
        "country_role": None,
        "campaign_id": None,
        "dedup": True,
    }
    primary_target_id = _daily_summary_target_id(_scope_user_id(user_id, filters_dict), day_key, filters_dict)

    task_id = (await db.execute(select(AITask.id).where(AITask.name == "daily_summary"))).scalar_one_or_none()
    if not task_id:
        return {"date": day_key, "summary": None, "cached": False, "generated_at": None}

    candidate_target_ids = [primary_target_id]
    per_user_target_id = _daily_summary_target_id(user_id, day_key, filters_dict)
    if per_user_target_id not in candidate_target_ids:
        candidate_target_ids.append(per_user_target_id)
    legacy_target_id = _daily_summary_target_id(user_id, day_key, {**filters_dict, "is_read": False})
    if legacy_target_id not in candidate_target_ids:
        candidate_target_ids.append(legacy_target_id)

    result = await db.execute(
        select(AIResult)
        .where(
            AIResult.target_type == "daily_summary",
            AIResult.target_id.in_(candidate_target_ids),
            AIResult.task_id == task_id,
            AIResult.is_current == True,  # noqa: E712
        )
        .order_by(AIResult.created_at.desc())
        .limit(1)
    )
    cached = result.scalar_one_or_none()
    if not cached or not cached.parsed_result or "summary" not in (cached.parsed_result or {}):
        return {"date": day_key, "summary": None, "cached": False, "generated_at": None}
    return {
        "date": day_key,
        "summary": cached.parsed_result.get("summary"),
        "cached": True,
        "generated_at": cached.created_at,
    }


# ---------------------------------------------------------------------------
# Manual URL ingestion
# ---------------------------------------------------------------------------


@_tool(
    name="ingest_url",
    description=(
        "Ingest a web page/article URL as a manual entry: fetches and sanitizes the content, "
        "stores it under the Manual Uploads feed, dispatches the full intelligence pipeline "
        "(autolink + extraction), indexes it for search, and broadcasts an ingest event. "
        "Optionally overrides the extracted title. Errors if the URL was already ingested."
    ),
    input_schema={
        "properties": {
            "url": {"type": "string", "description": "http(s) URL of the article to ingest"},
            "title": {"type": "string", "description": "Optional title override for the created entry"},
        },
        "required": ["url"],
    },
    mutating=True,
)
async def _ingest_url(db: AsyncSession, user_id: uuid.UUID, url: str, title: str | None = None) -> dict:
    from app.api.ingest import _index_entry
    from app.services.manual_ingest import ingest_url as do_ingest_url

    try:
        entry = await do_ingest_url(db, url.strip())
    except AppError as exc:
        return {"error": exc.message}

    if title and title.strip():
        entry.title = title.strip()
    await db.flush()

    # Dispatch the full intelligence pipeline (worker retries cover the window
    # until the executor commits this transaction).
    from app.workers.feed_tasks import dispatch_entry_pipeline

    dispatch_entry_pipeline(str(entry.id), run_extraction=True)

    _index_entry(entry)

    try:
        from app.api.events import broadcast_event

        broadcast_event(
            "entry_ingested",
            {"entry_id": str(entry.id), "feed_id": str(entry.feed_id), "title": entry.title, "source": "url"},
        )
    except Exception:
        logger.debug("Failed to broadcast ingest event", exc_info=True)

    return {
        "id": str(entry.id),
        "title": entry.title,
        "url": entry.url,
        "word_count": entry.word_count,
        "feed_id": str(entry.feed_id),
        "content_hash": entry.content_hash,
        "message": "Entry created",
    }


# ---------------------------------------------------------------------------
# Bulk ingest (batches of pasted text, files, URLs and one-time GitHub repos)
# ---------------------------------------------------------------------------


def _ingest_item_dict(item) -> dict:
    return {
        "id": str(item.id),
        "kind": item.kind,
        "status": item.status,
        "filename": item.filename,
        "source_url": item.source_url,
        "entry_id": str(item.entry_id) if item.entry_id else None,
        "error": item.error,
    }


def _ingest_batch_dict(batch, items) -> dict:
    from app.services.ingest_batches import summarize_items

    return {
        "batch_id": str(batch.id),
        "label": batch.label,
        "created_at": batch.created_at.isoformat() if batch.created_at else None,
        "summary": summarize_items(items),
        "items": [_ingest_item_dict(i) for i in items],
    }


@_tool(
    name="ingest_text",
    description=(
        "Ingest pasted text (a report body, an advisory, a chat log, an indicator dump) as one manual entry: "
        "stores the paste as a .txt original under Manual Uploads, queues it on the worker, and returns the "
        "batch id to poll with get_ingest_batch. Set is_ioc_list when the text is one indicator per line so "
        "it goes through the curated indicator-list door instead of candidate staging. One paste = one entry."
    ),
    input_schema={
        "properties": {
            "text": {"type": "string", "description": "The text to ingest"},
            "title": {"type": "string", "description": "Optional entry title"},
            "source_url": {"type": "string", "description": "Optional http(s) URL the text came from"},
            "is_ioc_list": {"type": "boolean", "description": "Treat the body as a curated indicator list"},
        },
        "required": ["text"],
    },
    mutating=True,
)
async def _ingest_text(
    db: AsyncSession,
    user_id: uuid.UUID,
    text: str,
    title: str | None = None,
    source_url: str | None = None,
    is_ioc_list: bool = False,
) -> dict:
    from app.services import ingest_batches as batches

    try:
        batch = await batches.create_batch(db, user_id, label=title, source="tool")
        item = await batches.add_text_item(
            db, batch, text=text, title=title, source_url=source_url, is_ioc_list=bool(is_ioc_list)
        )
    except AppError as exc:
        return {"error": exc.message}
    await db.commit()
    batches.dispatch_item(item)
    return _ingest_batch_dict(batch, [item])


@_tool(
    name="ingest_file",
    description=(
        "Ingest one file (PDF, DOCX, TXT, MD, HTML, CSV, EML, ZIP, ...) given as base64 as a manual entry: "
        "stores the original under Manual Uploads, queues it, returns the batch id to poll with "
        "get_ingest_batch. A .zip expands into one entry per member. Keep files under the configured per-file "
        "cap (default 50 MB); the base64 payload must fit in one tool call."
    ),
    input_schema={
        "properties": {
            "filename": {"type": "string", "description": "Original filename, extension included"},
            "content_base64": {"type": "string", "description": "The file bytes, base64-encoded"},
            "title": {"type": "string", "description": "Optional entry title override"},
            "is_ioc_list": {"type": "boolean", "description": "Treat the body as a curated indicator list"},
        },
        "required": ["filename", "content_base64"],
    },
    mutating=True,
)
async def _ingest_file(
    db: AsyncSession,
    user_id: uuid.UUID,
    filename: str,
    content_base64: str,
    title: str | None = None,
    is_ioc_list: bool = False,
) -> dict:
    import base64
    import binascii

    from app.services import ingest_batches as batches

    try:
        data = base64.b64decode(content_base64, validate=True)
    except (binascii.Error, ValueError):
        return {"error": "content_base64 is not valid base64"}
    if not data:
        return {"error": "The file is empty"}
    try:
        batch = await batches.create_batch(db, user_id, label=filename, source="tool")
        item = await batches.add_file_item(
            db, batch, data=data, filename=filename, content_type=None, title=title, is_ioc_list=bool(is_ioc_list)
        )
    except AppError as exc:
        return {"error": exc.message}
    await db.commit()
    batches.dispatch_item(item)
    return _ingest_batch_dict(batch, [item])


@_tool(
    name="ingest_batch",
    description=(
        "Ingest many URLs and/or text blobs in one batch under Manual Uploads. Each URL becomes one entry; a "
        "github.com/owner/repo link (optionally /tree/<branch>/<path>) is fetched once and becomes one entry per "
        "file with no feed created. Each text becomes one entry. Returns the batch id; poll get_ingest_batch "
        "for per-item status (created / duplicate / no_text / unsupported / failed)."
    ),
    input_schema={
        "properties": {
            "urls": {"type": "array", "items": {"type": "string"}, "description": "http(s) URLs or GitHub repo links"},
            "texts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"},
                        "title": {"type": "string"},
                        "source_url": {"type": "string"},
                    },
                    "required": ["text"],
                },
                "description": "Text blobs, one entry each",
            },
            "label": {"type": "string", "description": "Optional batch label"},
            "is_ioc_list": {"type": "boolean", "description": "Treat every item as a curated indicator list"},
        },
    },
    mutating=True,
)
async def _ingest_batch(
    db: AsyncSession,
    user_id: uuid.UUID,
    urls: list[str] | None = None,
    texts: list[dict] | None = None,
    label: str | None = None,
    is_ioc_list: bool = False,
) -> dict:
    from app.services import ingest_batches as batches

    urls = [u for u in (urls or []) if isinstance(u, str) and u.strip()]
    texts = [t for t in (texts or []) if isinstance(t, dict) and str(t.get("text") or "").strip()]
    if not urls and not texts:
        return {"error": "Give at least one URL or one text"}
    items = []
    try:
        batch = await batches.create_batch(db, user_id, label=label, source="tool")
        if urls:
            items.extend(await batches.add_url_items(db, batch, urls, is_ioc_list=bool(is_ioc_list)))
        for t in texts:
            items.append(
                await batches.add_text_item(
                    db,
                    batch,
                    text=str(t["text"]),
                    title=t.get("title"),
                    source_url=t.get("source_url"),
                    is_ioc_list=bool(is_ioc_list),
                )
            )
    except AppError as exc:
        return {"error": exc.message}
    await db.commit()
    batches.dispatch_items(items)
    return _ingest_batch_dict(batch, items)


@_tool(
    name="get_ingest_batch",
    description=(
        "Status of one ingest batch: per-item status (queued / parsing / created / expanded / duplicate / "
        "no_text / unsupported / too_large / failed), the entry id each item produced, and a summary. "
        "Poll until summary.status is 'complete'. Created entries still go on to the pipeline and the "
        "one-pass AI analysis afterwards, like any polled entry."
    ),
    input_schema={
        "properties": {
            "batch_id": {"type": "string", "description": "Batch id from ingest_text / ingest_file / ingest_batch"}
        },
        "required": ["batch_id"],
    },
    mutating=False,
)
async def _get_ingest_batch(db: AsyncSession, user_id: uuid.UUID, batch_id: str) -> dict:
    from app.services import ingest_batches as batches

    try:
        bid = uuid.UUID(str(batch_id))
    except ValueError:
        return {"error": "batch_id is not a UUID"}
    batch = await batches.get_batch(db, bid)
    if batch is None:
        return {"error": "Batch not found"}
    items = list(batch.items)
    if await batches.mark_stale_parsing(db, items):
        await db.commit()
    return _ingest_batch_dict(batch, items)


# ---------------------------------------------------------------------------
# Public share links
# ---------------------------------------------------------------------------


def _share_link_dict(share: SharedEntry) -> dict:
    return {
        "token": share.token,
        "url": f"/shared/{share.token}",
        "created_at": share.created_at,
        "expires_at": share.expires_at,
    }


@_tool(
    name="create_share_link",
    description=(
        "Create a public (unauthenticated) share link for an entry, or return this user's existing "
        "active one (share links are per-analyst, so another user's link for the same entry is not "
        "reused). ttl_days optionally sets an expiry on a newly created link (the API default "
        "is no expiry); it is ignored when an active link already exists. When server-side TTS is "
        "enabled, read-aloud audio is pre-generated best-effort with a 24h eviction TTL."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID to share"},
            "ttl_days": {"type": "number", "description": "Optional days until the link expires (new links only)"},
        },
        "required": ["entry_id"],
    },
    mutating=True,
)
async def _create_share_link(
    db: AsyncSession, user_id: uuid.UUID, entry_id: str, ttl_days: float | None = None
) -> dict:
    from app.api.shared import _entry_tts_text
    from app.config import settings

    entry, err = await _get_entry(db, entry_id)
    if err:
        return err

    # Shares are per-(entry, creator): another analyst sharing the same entry
    # holds their own row, so this must match on the caller — both to avoid
    # handing back someone else's token and because an entry-wide lookup now
    # legitimately returns more than one row.
    existing = await db.execute(
        select(SharedEntry).where(
            SharedEntry.entry_id == entry.id,
            SharedEntry.created_by == user_id,
            SharedEntry.is_active.is_(True),
        )
    )
    share = existing.scalars().first()
    already_existed = share is not None

    if not share:
        share = SharedEntry(entry_id=entry.id, created_by=user_id)
        if ttl_days is not None:
            if ttl_days <= 0:
                return {"error": "ttl_days must be positive"}
            share.expires_at = datetime.now(UTC) + timedelta(days=ttl_days)
        db.add(share)
        await db.flush()

    # Pre-generate read-aloud audio so it's ready when the share is first opened
    # (best-effort; ttl_days=1 keeps the audio share-scoped, same as the API).
    if settings.tts_enabled:
        try:
            from app.services import tts

            await tts.get_or_enqueue(
                db, source="entry", ref_id=str(entry.id), text=_entry_tts_text(entry), ttl_days=1.0
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Share TTS pre-generation failed for entry %s: %s", entry.id, exc)

    return {**_share_link_dict(share), "already_existed": already_existed}


@_tool(
    name="get_share_link",
    description=(
        "Return this user's active public share link for an entry ({token, url, created_at, expires_at}), "
        "or null if they have not shared it. Other analysts' share links for the same entry are not returned."
    ),
    input_schema={
        "properties": {"entry_id": {"type": "string", "description": "Entry UUID to look up"}},
        "required": ["entry_id"],
    },
    mutating=False,
)
async def _get_share_link(db: AsyncSession, user_id: uuid.UUID, entry_id: str) -> dict:
    entry, err = await _get_entry(db, entry_id)
    if err:
        return err
    result = await db.execute(
        select(SharedEntry).where(
            SharedEntry.entry_id == entry.id,
            SharedEntry.created_by == user_id,
            SharedEntry.is_active.is_(True),
        )
    )
    share = result.scalars().first()
    return {"entry_id": str(entry.id), "share": _share_link_dict(share) if share else None}


@_tool(
    name="revoke_share_link",
    description=(
        "Deactivate this user's active public share link for an entry so its public URL stops resolving. "
        "Share links other analysts created for the same entry are left alone. "
        "Reversible in effect (create_share_link issues a fresh link, with a new token)."
    ),
    input_schema={
        "properties": {"entry_id": {"type": "string", "description": "Entry UUID whose share link to revoke"}},
        "required": ["entry_id"],
    },
    mutating=True,
)
async def _revoke_share_link(db: AsyncSession, user_id: uuid.UUID, entry_id: str) -> dict:
    entry, err = await _get_entry(db, entry_id)
    if err:
        return err
    # Only the caller's own share — revoking someone else's link is exactly the
    # cross-user write the per-creator share model exists to prevent.
    result = await db.execute(
        select(SharedEntry).where(
            SharedEntry.entry_id == entry.id,
            SharedEntry.created_by == user_id,
            SharedEntry.is_active.is_(True),
        )
    )
    shares = result.scalars().all()
    if not shares:
        return {"error": "No active share link for this entry"}
    for share in shares:
        share.is_active = False
    await db.flush()
    return {"entry_id": str(entry.id), "message": "Share link revoked"}


# ---------------------------------------------------------------------------
# Saved searches
# ---------------------------------------------------------------------------


@_tool(
    name="list_saved_searches",
    description=(
        "List this user's saved searches with unread/total entry counts. Counts come from a "
        "10-minute cache and are computed inline (via search-index queries) on a cache miss."
    ),
    input_schema={"properties": {}, "required": []},
    mutating=False,
)
async def _list_saved_searches(db: AsyncSession, user_id: uuid.UUID) -> dict:
    import json as _json

    from app.api.saved_searches import _compute_counts_inline

    result = await db.execute(
        select(SavedSearch).where(SavedSearch.created_by == user_id).order_by(SavedSearch.created_at.desc())
    )
    searches = result.scalars().all()

    counts: dict[str, dict] = {}
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        cached = await r.get(f"saved_search_counts:{user_id}")
        if cached:
            counts = _json.loads(cached)
    except Exception:
        pass
    if not counts and searches:
        counts = await _compute_counts_inline(searches, user_id, db)

    return {
        "saved_searches": [
            {
                "id": str(s.id),
                "name": s.name,
                "display_name": s.display_name,
                "query": s.query,
                "filters": s.filters,
                "unread_count": counts.get(str(s.id), {}).get("unread", 0),
                "total_count": counts.get(str(s.id), {}).get("total", 0),
                "created_at": s.created_at,
            }
            for s in searches
        ]
    }


@_tool(
    name="create_saved_search",
    description=(
        'Create a saved search from a query-language string (e.g. "ransomware cve.severity:critical '
        'is:unread"). Saved searches are per-user and appear in the reader sidebar. '
        "display_name optionally sets a friendlier label than the name."
    ),
    input_schema={
        "properties": {
            "name": {"type": "string", "description": "Short unique-ish name (1-255 chars)"},
            "query": {"type": "string", "description": "Search query-language string the saved search runs"},
            "display_name": {"type": "string", "description": "Optional display label (max 255 chars)"},
        },
        "required": ["name", "query"],
    },
    mutating=True,
)
async def _create_saved_search(
    db: AsyncSession, user_id: uuid.UUID, name: str, query: str, display_name: str | None = None
) -> dict:
    if not name or not name.strip() or len(name) > 255:
        return {"error": "name must be 1-255 characters"}
    if display_name is not None and len(display_name) > 255:
        return {"error": "display_name must be at most 255 characters"}
    saved = SavedSearch(created_by=user_id, name=name.strip(), display_name=display_name, query=query, filters={})
    db.add(saved)
    await db.flush()
    await db.refresh(saved)
    return {
        "id": str(saved.id),
        "name": saved.name,
        "display_name": saved.display_name,
        "query": saved.query,
        "filters": saved.filters,
        "created_at": saved.created_at,
        "message": "Saved search created",
    }


@_tool(
    name="delete_saved_search",
    description=(
        "Delete one of this user's saved searches by id. The underlying entries are untouched "
        "and the search is trivially recreatable from its name and query."
    ),
    input_schema={
        "properties": {"search_id": {"type": "string", "description": "Saved search UUID"}},
        "required": ["search_id"],
    },
    mutating=True,
)
async def _delete_saved_search(db: AsyncSession, user_id: uuid.UUID, search_id: str) -> dict:
    try:
        sid = uuid.UUID(search_id)
    except ValueError:
        return {"error": f"Invalid search_id: {search_id}"}
    saved = (await db.execute(select(SavedSearch).where(SavedSearch.id == sid))).scalar_one_or_none()
    if not saved:
        return {"error": f"Saved search not found (id: {search_id})"}
    if saved.created_by != user_id:
        return {"error": "Only the saved search's owner can delete it"}
    name = saved.name
    await db.delete(saved)
    await db.flush()
    return {"deleted": True, "search_id": search_id, "name": name}
