"""Condition evaluation for automation rules.

Supports AND/OR combinable logic with nested groups.
"""

import logging
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE, EntryCVE
from app.models.entry import Entry
from app.models.entry_state import UserEntryState
from app.models.feed import Feed
from app.models.note import Note
from app.models.tag import EntryTag, Tag

logger = logging.getLogger(__name__)


async def evaluate_conditions(db: AsyncSession, entry: Entry, conditions: dict, user_id=None) -> bool:
    """Evaluate a conditions block against an entry.

    Conditions can be:
    - Empty dict → always true (no conditions)
    - {"operator": "AND"|"OR", "conditions": [...]} → combined logic
    - {"type": "...", "config": {...}} → single condition
    """
    if not conditions:
        return True

    # Single condition (no operator)
    if "type" in conditions:
        return await _evaluate_single(db, entry, conditions, user_id)

    operator = conditions.get("operator", "AND").upper()
    sub_conditions = conditions.get("conditions", [])

    if not sub_conditions:
        return True

    if operator == "OR":
        for cond in sub_conditions:
            if await evaluate_conditions(db, entry, cond, user_id):
                return True
        return False
    else:  # AND
        for cond in sub_conditions:
            if not await evaluate_conditions(db, entry, cond, user_id):
                return False
        return True


async def _evaluate_single(db: AsyncSession, entry: Entry, condition: dict, user_id=None) -> bool:
    """Evaluate a single condition against an entry."""
    cond_type = condition.get("type", "")
    config = condition.get("config", {})

    try:
        match cond_type:
            case "feed_matches":
                return await _eval_feed_matches(db, entry, config, user_id)
            case "content_contains":
                return _eval_content_contains(entry, config)
            case "severity_above":
                return await _eval_severity_above(db, entry, config)
            case "author_matches":
                return _eval_author_matches(entry, config)
            case "tag_matches":
                return await _eval_tag_matches(db, entry, config)
            case "feed_type_matches":
                return await _eval_feed_type_matches(db, entry, config)
            case "is_read":
                return await _eval_is_read(db, entry, user_id)
            case "is_starred":
                return await _eval_is_starred(db, entry, user_id)
            case "is_bookmarked":
                return await _eval_is_bookmarked(db, entry, user_id)
            case "has_note":
                return await _eval_has_note(db, entry, user_id)
            case "priority_score_above":
                return _eval_priority_score_above(entry, config)
            case "has_signal":
                return await _eval_has_signal(db, entry, config)
            case "entity_watchlisted":
                return await _eval_entity_watchlisted(db, entry, user_id)
            case _:
                logger.warning(f"Unknown condition type: {cond_type}")
                return False
    except Exception as e:
        logger.error(f"Error evaluating condition {cond_type}: {e}")
        return False


async def _eval_feed_matches(db: AsyncSession, entry: Entry, config: dict, user_id=None) -> bool:
    """Check if entry's feed matches specified feed or category IDs."""
    feed_ids = config.get("feed_ids", [])
    category_ids = config.get("category_ids", [])

    if feed_ids and str(entry.feed_id) in [str(fid) for fid in feed_ids]:
        return True

    if category_ids:
        # Resolve which feeds belong to the specified categories
        result = await db.execute(
            select(Feed.id).where(
                Feed.category_id.in_([str(c) for c in category_ids]),
            )
        )
        category_feed_ids = {row[0] for row in result.all()}
        if entry.feed_id in category_feed_ids:
            return True

    return bool(not feed_ids and not category_ids)


def _eval_content_contains(entry: Entry, config: dict) -> bool:
    """Check if entry content matches a keyword or regex pattern."""
    pattern = config.get("pattern", "")
    is_regex = config.get("is_regex", False)

    if not pattern:
        return True

    text = f"{entry.title or ''} {entry.content_text or ''} {entry.summary or ''}"

    if is_regex:
        return bool(re.search(pattern, text, re.IGNORECASE))
    else:
        return pattern.lower() in text.lower()


async def _eval_severity_above(db: AsyncSession, entry: Entry, config: dict) -> bool:
    """Check if any CVE linked to this entry exceeds the minimum CVSS score."""
    min_cvss = config.get("min_cvss", 0.0)

    result = await db.execute(
        select(CVE.cvss_score)
        .join(EntryCVE, EntryCVE.cve_id == CVE.id)
        .where(EntryCVE.entry_id == entry.id, CVE.cvss_score.isnot(None))
    )
    scores = [row[0] for row in result.all()]
    return any(float(score) >= min_cvss for score in scores)


def _eval_author_matches(entry: Entry, config: dict) -> bool:
    """Check if entry author matches any of the specified authors."""
    authors = config.get("authors", [])
    if not authors or not entry.author:
        return not authors

    return any(a.lower() in entry.author.lower() for a in authors)


async def _eval_tag_matches(db: AsyncSession, entry: Entry, config: dict) -> bool:
    """Check if entry has any of the specified tags."""
    tag_names = config.get("tags", [])
    if not tag_names:
        return True

    result = await db.execute(
        select(Tag.name).join(EntryTag, EntryTag.tag_id == Tag.id).where(EntryTag.entry_id == entry.id)
    )
    entry_tags = {row[0].lower() for row in result.all()}
    return any(t.lower() in entry_tags for t in tag_names)


async def _eval_feed_type_matches(db: AsyncSession, entry: Entry, config: dict) -> bool:
    """Check if entry's feed type matches specified types."""
    types = config.get("types", [])
    if not types:
        return True

    # Use cached _feed_type if set by engine, otherwise load from DB
    feed_type = getattr(entry, "_feed_type", None)
    if not feed_type:
        result = await db.execute(select(Feed.feed_type).where(Feed.id == entry.feed_id))
        feed_type = result.scalar_one_or_none()

    if feed_type:
        return feed_type in types

    return False


# ---------------------------------------------------------------------------
# Entry-state conditions
# ---------------------------------------------------------------------------


async def _eval_is_read(db: AsyncSession, entry: Entry, user_id) -> bool:
    """Check if the entry has been read by the user."""
    if not user_id:
        return False
    result = await db.execute(
        select(UserEntryState.is_read).where(
            UserEntryState.entry_id == entry.id,
            UserEntryState.user_id == user_id,
        )
    )
    val = result.scalar_one_or_none()
    return bool(val)


async def _eval_is_starred(db: AsyncSession, entry: Entry, user_id) -> bool:
    """Check if the entry is starred by the user."""
    if not user_id:
        return False
    result = await db.execute(
        select(UserEntryState.is_starred).where(
            UserEntryState.entry_id == entry.id,
            UserEntryState.user_id == user_id,
        )
    )
    val = result.scalar_one_or_none()
    return bool(val)


async def _eval_is_bookmarked(db: AsyncSession, entry: Entry, user_id) -> bool:
    """Check if the entry is bookmarked by the user."""
    if not user_id:
        return False
    result = await db.execute(
        select(UserEntryState.is_bookmarked).where(
            UserEntryState.entry_id == entry.id,
            UserEntryState.user_id == user_id,
        )
    )
    val = result.scalar_one_or_none()
    return bool(val)


async def _eval_has_note(db: AsyncSession, entry: Entry, user_id) -> bool:
    """Check if entry has any notes."""
    result = await db.execute(
        select(Note.id)
        .where(
            Note.entry_id == entry.id,
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


# ── Signal engine conditions (engine phase 7) ─────────────────────


def _eval_priority_score_above(entry: Entry, config: dict) -> bool:
    """Entry's signal-engine priority score exceeds a minimum.

    Note: scoring runs after post-processing, so on_new_entry rules see the
    score only if the entry was already scored (e.g. scheduled rules). For
    score reactions use the on_entry_scored trigger, which fires after the
    score is persisted; has_signal/entity_watchlisted remain the ingest-time
    alternatives.
    """
    try:
        min_score = float(config.get("min", 1.0))
    except (TypeError, ValueError):
        return False
    return entry.priority_score is not None and entry.priority_score >= min_score


async def _eval_has_signal(db: AsyncSession, entry: Entry, config: dict) -> bool:
    """Entry carries at least one of the given signal types (any type if unset)."""
    from app.models.entry_signal import EntrySignal

    types = config.get("types") or []
    query = select(EntrySignal.id).where(EntrySignal.entry_id == entry.id)
    if types:
        query = query.where(EntrySignal.signal_type.in_(types))
    result = await db.execute(query.limit(1))
    return result.scalar_one_or_none() is not None


async def _eval_entity_watchlisted(db: AsyncSession, entry: Entry, user_id) -> bool:
    """Entry links an entity on the rule creator's watchlist (mode=watch)."""
    from app.models.user_entity_watch import UserEntityWatch
    from app.services.triage import _watch_junction_map

    if user_id is None:
        return False
    watches = (
        (
            await db.execute(
                select(UserEntityWatch).where(UserEntityWatch.created_by == user_id, UserEntityWatch.mode == "watch")
            )
        )
        .scalars()
        .all()
    )
    if not watches:
        return False
    junctions = _watch_junction_map()
    by_type: dict[str, list] = {}
    for w in watches:
        by_type.setdefault(w.entity_type, []).append(w.entity_id)
    for entity_type, ids in by_type.items():
        junction, id_col = junctions.get(entity_type, (None, None))
        if junction is None:
            continue
        hit = await db.execute(select(junction.entry_id).where(junction.entry_id == entry.id, id_col.in_(ids)).limit(1))
        if hit.scalar_one_or_none() is not None:
            return True
    return False
