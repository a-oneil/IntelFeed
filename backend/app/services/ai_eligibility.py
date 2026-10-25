"""Will the one-pass AI analysis read this entry?

One answer shared by AI queueing (``enqueue_entry_analysis``) and the
autolinker's pending tier. The pending tier holds dictionary-word matches
("Play", "Royal", "Hive") until the AI confirms them; if the two disagreed,
matches on a feed the AI never reads would sit in the hold until they expire.

Only the policy parts live here: the instance switch and the feed's switches.
The per-entry gates that come later in queueing (junk relevance, echo reuse)
depend on signals that don't exist yet when the autolinker runs.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# Feed-policy skips are recorded (so the Engine matrix can say why an entry
# was never analyzed) but stay re-evaluable: turning the feed's AI back on
# lets the missed-entry sweep pick the row up again.
SKIPPED_FEED_AI_OFF = "skipped_feed_ai"
SKIPPED_FEED_NONE = "skipped_feed_none"
FEED_SKIP_STATUSES = (SKIPPED_FEED_AI_OFF, SKIPPED_FEED_NONE)


def feed_ai_skip_status(mode: str | None, ai_analysis_enabled: bool | None) -> str | None:
    """The feed-policy skip status for a feed's entries, or None if the AI may read them.

    Two separate switches, because they answer different questions: mode
    "none" means "extract nothing from this feed at all", while
    ai_analysis_enabled=False means "keep matching it against the catalog,
    just don't let the AI read it and invent entities".
    """
    if mode == "none":
        return SKIPPED_FEED_NONE
    if ai_analysis_enabled is False:
        return SKIPPED_FEED_AI_OFF
    return None


async def entry_will_get_ai_analysis(db: AsyncSession, entry_id: uuid.UUID) -> bool:
    """True when the instance AI switch is on and the entry's feed lets the AI read it."""
    from app.models.entry import Entry
    from app.models.feed import Feed
    from app.services.system_settings import get_setting

    if not bool(await get_setting("ai_one_pass_enabled", db)):
        return False
    row = (
        await db.execute(
            select(Feed.intel_extraction_mode, Feed.ai_analysis_enabled)
            .join(Entry, Entry.feed_id == Feed.id)
            .where(Entry.id == entry_id)
        )
    ).one_or_none()
    if row is None:
        # No feed row (manual entry, deleted feed): queueing doesn't apply a
        # feed policy either.
        return True
    return feed_ai_skip_status(row.intel_extraction_mode, row.ai_analysis_enabled) is None
