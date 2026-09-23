"""Retro match-scan dispatch for entities whose match surface grew.

Creating an entity fires ``link_new_entity_to_entries`` so it retroactively picks
up articles that already mention it. Adding an alias widens exactly the same
match surface — the autolinker searches name + aliases — so every path that
grows an entity's alias list queues the same scan.

The task itself is idempotent (junction inserts use ON CONFLICT DO NOTHING) and
guarded by a per-entity Redis lock, so overlapping dispatches are harmless.
"""

import logging
import uuid

from app import entity_types

logger = logging.getLogger(__name__)


# The retro scan can only search types the autolinker knows how to match on.
# app.intelligence.autolinker isn't imported here: it pulls in the whole
# model/Redis stack, and this module is imported from API request paths.
_SCANNABLE = entity_types.AUTOLINKABLE


def dispatch_entity_backlink(entity_type: str, entity_id: str | uuid.UUID) -> bool:
    """Queue a Celery task to search existing entries for mentions of an entity.

    Returns whether a scan was queued. Types the autolinker has no match surface
    for (campaign, victim, detection_rule, ...) are skipped here rather than
    queued and failed inside the worker.
    """
    entity_type = entity_types.normalize_entity_type(entity_type)
    if entity_type not in _SCANNABLE:
        logger.debug("No autolinker vocabulary for %s — skipping backlink scan for %s", entity_type, entity_id)
        return False
    try:
        from app.workers.intel_feed_tasks import link_new_entity_to_entries

        link_new_entity_to_entries.apply_async(
            kwargs={"entity_type": entity_type, "entity_id": str(entity_id)},
            countdown=5,  # Small delay to let the transaction commit
        )
        return True
    except Exception:
        logger.warning("Failed to dispatch entity backlink task for %s/%s", entity_type, entity_id, exc_info=True)
        return False


def dispatch_backlink_for_added_aliases(
    entity_type: str,
    entity_id: str | uuid.UUID,
    old_aliases: list[str] | None,
    new_aliases: list[str] | None,
) -> bool:
    """Queue a retro scan iff ``new_aliases`` introduces a name not already present.

    Compared case-insensitively: matching is case-insensitive too, so a re-cased
    alias matches nothing the entity wasn't already matching. Returns whether a
    scan was dispatched.
    """
    old_set = {a.lower() for a in (old_aliases or []) if a}
    added = {a.lower() for a in (new_aliases or []) if a} - old_set
    if not added:
        return False
    if not dispatch_entity_backlink(entity_type, entity_id):
        return False
    logger.info("Aliases added to %s/%s (%s) — queued retro match scan", entity_type, entity_id, sorted(added))
    return True
