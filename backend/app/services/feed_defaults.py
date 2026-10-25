"""What a new feed starts with: its own values, then its category's, then global.

A category's ``feed_defaults`` holds pipeline settings for feeds added to it
later. Every place that creates a feed — ``POST /api/feeds``, OPML and
starter-pack import (which is onboarding), and the ``create_feed`` tool — runs
its explicit values through :func:`new_feed_settings`, so a value the caller
sent wins, a category default fills what it left out, and the Feed column
default covers the rest.

Defaults apply once, at creation. Moving a feed into a category, or editing
the category's defaults, leaves existing feeds as they are; the category
bulk-update is how feeds already there are changed.
"""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.category import Category
from app.models.feed import Feed

FEED_DEFAULT_FIELDS = (
    "intel_extraction_mode",
    "ai_analysis_enabled",
    "extract_tools",
    "auto_extract_on_ingest",
    "extract_detection_rules",
)

_MODES = ("full", "selective", "manual", "none")


def clean_defaults(raw: dict | None) -> dict:
    """Keep only known keys with values of the right type; drop nulls."""
    out: dict = {}
    for key, value in (raw or {}).items():
        if key not in FEED_DEFAULT_FIELDS or value is None:
            continue
        if key == "intel_extraction_mode":
            if value in _MODES:
                out[key] = value
        elif isinstance(value, bool):
            out[key] = value
    return out


async def category_defaults(db: AsyncSession, category_id: uuid.UUID | None) -> dict:
    if category_id is None:
        return {}
    category = await db.get(Category, category_id)
    return clean_defaults(category.feed_defaults) if category else {}


async def category_for_feed_type(db: AsyncSession, feed_type: str) -> uuid.UUID | None:
    """The category most feeds of this type are filed under, for a caller that named none.

    A feed left in "Uncategorized" is skipped by every bulk update by category
    and inherits no defaults, so a create without a category is filed beside
    its own kind instead. None when no feed of the type has a category yet.
    """
    row = (
        await db.execute(
            select(Feed.category_id, func.count().label("n"))
            .where(Feed.feed_type == feed_type, Feed.category_id.is_not(None))
            .group_by(Feed.category_id)
            .order_by(func.count().desc(), Feed.category_id)
            .limit(1)
        )
    ).first()
    return row.category_id if row else None


async def new_feed_settings(db: AsyncSession, category_id: uuid.UUID | None, explicit: dict) -> dict:
    """Feed constructor kwargs for the pipeline fields.

    ``explicit`` holds what the caller asked for; None means "not specified".
    Fields neither the caller nor the category sets are left out, so the Feed
    column default applies.
    """
    settings = await category_defaults(db, category_id)
    for key, value in explicit.items():
        if value is not None:
            settings[key] = value
    return settings
