"""Information credibility: the number half of an Admiralty grade, per article.

The feed's A-F letter rates the source over time; this 1-6 number rates one
report. The two are kept apart on purpose — stamping the source's grade on
everything it says is the failure the scale exists to avoid.

Three inputs, in order of authority:

1. An analyst's rating (``info_rating_by = 'analyst'``) always wins.
2. Corroboration lifts a 2 or 3 to 1 ("confirmed by other independent
   sources") when another outlet in the same story thread reports the story.
   Copies don't count: a thread member marked as an echo, or the article this
   one echoes (or anything else from that article's outlet), is the same
   report again, not a second source.
3. Otherwise the AI's own score from the article alone (2-6; it never sees
   other sources, so it never awards 1).

Corroboration changes as threads grow, merge and get pruned, so
``sync_corroboration`` re-derives it after every thread sweep rather than
tracking each membership change.
"""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

INFO_RATING_LABELS = {
    1: "Confirmed",
    2: "Probably true",
    3: "Possibly true",
    4: "Doubtfully true",
    5: "Improbable",
    6: "Cannot be judged",
}
ACCESS_VALUES = ("firsthand", "secondhand", "unclear")
# Only these AI scores can be lifted to 1. A 4-6 article stays where it is
# however many outlets repeat it.
CONFIRMABLE = (2, 3)
# Matches the story-thread window; older threads no longer change.
SYNC_WINDOW_DAYS = 30


def normalize_ai_rating(raw) -> dict | None:
    """The AI's ``information_rating`` object, cleaned, or None if unusable."""
    if not isinstance(raw, dict):
        return None
    try:
        score = int(raw.get("score"))
    except (TypeError, ValueError):
        return None
    # The model is told never to answer 1; if it does, it has no basis for it.
    if score == 1:
        score = 2
    if score not in INFO_RATING_LABELS:
        return None
    access = str(raw.get("access") or "").strip().lower()
    return {
        "score": score,
        "access": access if access in ACCESS_VALUES else "unclear",
        "rationale": str(raw.get("rationale") or "").strip()[:500] or None,
    }


async def store_ai_rating(db: AsyncSession, entry_id: uuid.UUID, raw) -> int | None:
    """Record the AI's score on the entry and derive the effective rating.

    Leaves an analyst's rating in place; the AI columns are still refreshed so
    "reset to AI" has something current to fall back to.
    """
    rating = normalize_ai_rating(raw)
    if rating is None:
        return None
    await db.execute(
        text(
            """
            UPDATE entries SET
                info_rating_ai = :score,
                info_rating_access = :access,
                info_rating_note = CASE WHEN info_rating_by = 'analyst' THEN info_rating_note ELSE :note END,
                info_rating_by = COALESCE(info_rating_by, 'ai')
            WHERE id = :id
            """
        ),
        {"id": entry_id, "score": rating["score"], "access": rating["access"], "note": rating["rationale"]},
    )
    await sync_corroboration(db, entry_ids=[entry_id])
    return rating["score"]


async def set_analyst_rating(
    db: AsyncSession, entry_id: uuid.UUID, rating: int | None, note: str | None, user_label: str
) -> None:
    """An analyst's rating, or ``None`` to hand the article back to the AI."""
    if rating is None:
        await db.execute(
            text(
                """
                UPDATE entries SET
                    info_rating_by = CASE WHEN info_rating_ai IS NULL THEN NULL ELSE 'ai' END,
                    info_rating = info_rating_ai,
                    info_rating_note = NULL
                WHERE id = :id
                """
            ),
            {"id": entry_id},
        )
        await sync_corroboration(db, entry_ids=[entry_id])
        return
    stamp = f"{user_label}, {datetime.now(UTC):%Y-%m-%d}"
    await db.execute(
        text(
            """
            UPDATE entries SET info_rating = :rating, info_rating_by = 'analyst', info_rating_note = :note
            WHERE id = :id
            """
        ),
        {"id": entry_id, "rating": rating, "note": f"{note.strip()} ({stamp})" if note and note.strip() else stamp},
    )


async def sync_corroboration(
    db: AsyncSession, entry_ids: list[uuid.UUID] | None = None, since: datetime | None = None
) -> int:
    """Re-derive ``info_rating`` for AI-rated articles. Returns rows changed.

    Scoped to ``entry_ids`` when given, else to articles published since
    ``since`` (default: the thread window).
    """
    params: dict = {"confirmable": list(CONFIRMABLE)}
    if entry_ids is not None:
        if not entry_ids:
            return 0
        scope = "e.id = ANY(:ids)"
        params["ids"] = entry_ids
    else:
        scope = "COALESCE(e.published_at, e.created_at) >= :since"
        params["since"] = since or (datetime.now(UTC) - timedelta(days=SYNC_WINDOW_DAYS))
    result = await db.execute(
        text(
            f"""
            UPDATE entries e SET info_rating = derived.rating
            FROM (
                SELECT e.id,
                       CASE WHEN e.info_rating_ai = ANY(:confirmable) AND EXISTS (
                                SELECT 1
                                FROM story_thread_entries me
                                JOIN story_thread_entries other
                                  ON other.thread_id = me.thread_id AND other.entry_id <> me.entry_id
                                JOIN entries oe ON oe.id = other.entry_id
                                WHERE me.entry_id = e.id
                                  AND other.role <> 'echo'
                                  AND other.source_key IS DISTINCT FROM me.source_key
                                  AND other.entry_id IS DISTINCT FROM me.duplicate_of_entry_id
                                  -- A copy isn't confirmed by the outlet it copied, either.
                                  AND other.source_key IS DISTINCT FROM (
                                      SELECT d.source_key FROM story_thread_entries d
                                      WHERE d.entry_id = me.duplicate_of_entry_id
                                  )
                                  -- A doubtful article doesn't confirm anything.
                                  AND (oe.info_rating_ai IS NULL OR oe.info_rating_ai = ANY(:confirmable))
                            ) THEN 1
                            ELSE e.info_rating_ai
                       END AS rating
                FROM entries e
                WHERE {scope}
                  AND e.info_rating_ai IS NOT NULL
                  AND e.info_rating_by = 'ai'
            ) derived
            WHERE e.id = derived.id AND e.info_rating IS DISTINCT FROM derived.rating
            """
        ),
        params,
    )
    return result.rowcount or 0
