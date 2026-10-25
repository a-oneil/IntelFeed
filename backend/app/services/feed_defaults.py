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

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.category import Category

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
