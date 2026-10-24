"""Feed / category / automation / webhook-preset / note / campaign management tools.

Coverage-build module: mirrors the corresponding API routers (app/api/feeds.py,
categories.py, automation.py, webhook_presets.py, notes.py, entity_notes.py,
campaigns.py) so the agent CLI can manage these objects with the same semantics
and side effects as the web UI.
"""

import uuid
from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import adapters, entity_types
from app.models.automation_rule import AutomationRule
from app.models.campaign import Campaign, CampaignEntity, CampaignEntry
from app.models.category import Category
from app.models.entity_note import EntityNote
from app.models.feed import Feed
from app.models.note import Note
from app.models.webhook_preset import WebhookPreset
from app.schemas.automation import VALID_ACTION_TYPES, VALID_TRIGGER_TYPES
from app.schemas.tlp import TLP_VALUES, normalize_tlp
from app.tools import _tool
from app.tools.delete import _make_token, _verify_token

# ---------------------------------------------------------------------------
# Derived enums (canonical sources; test_tool_registry_sync.py enforces these)
# ---------------------------------------------------------------------------

# Feed types the update endpoint accepts, restricted to adapters that actually
# exist in the registry (the API's legacy list also names "github", which has
# no registered adapter — offering it here would create an unfetchable feed).
_UPDATE_FEED_TYPES = sorted(
    {"rss", "atom", "youtube", "podcast", "reddit", "github", "web_scraper", "telegram", "bluesky"}
    & (set(adapters._ADAPTERS) | set(adapters._EXTENDED_ADAPTERS))
)

# Mirrors FeedUpdateRequest's Field patterns (app/schemas/feed.py).
_INTEL_MODES = ["full", "selective", "manual", "none"]
_RELIABILITY_RATINGS = ["A", "B", "C", "D", "E", "F"]
_TIMELINESS_RATINGS = ["excellent", "good", "fair", "poor"]
_RELEVANCE_RATINGS = ["high", "medium", "low"]

# Mirrors CampaignUpdate's status pattern (app/schemas/campaign.py).
_CAMPAIGN_STATUSES = ["active", "monitoring", "closed", "historical"]

# TLP 2.0 vocabulary; TLP:WHITE accepted as a legacy alias (normalized to CLEAR).
_TLP_ENUM = [*TLP_VALUES, "TLP:WHITE"]

# Entity types the entity_notes DB CHECK accepts, plus "campaign" (an object
# kind rather than an entity type). ransomware_victim is excluded — the CHECK
# constraint does not cover it. Matches create_entity_note in app/tools/write.py.
_ENTITY_NOTE_TYPES = sorted((entity_types.ALL - {entity_types.RANSOMWARE_VICTIM}) | {"campaign"})


def _parse_uuid(value: str, label: str) -> tuple[uuid.UUID | None, dict | None]:
    try:
        return uuid.UUID(value), None
    except (ValueError, TypeError, AttributeError):
        return None, {"error": f"invalid {label} '{value}' (expected a UUID)"}


def _parse_date(value: str, label: str) -> tuple[date | None, dict | None]:
    try:
        return date.fromisoformat(value), None
    except (ValueError, TypeError):
        return None, {"error": f"invalid {label} '{value}' (expected YYYY-MM-DD)"}


# ---------------------------------------------------------------------------
# Feeds
# ---------------------------------------------------------------------------


@_tool(
    name="update_feed",
    description=(
        "Partially update a feed — only the provided fields change (mirrors PUT /api/feeds/{id}). "
        "Changing the URL resets fetch state (etag, error counters) and rejects duplicates. "
        "category is resolved by name and must already exist. exclude_shorts only applies to YouTube "
        "feeds. adapter_config is merged into the existing config (Telegram channel URLs are "
        "normalized, Bluesky app passwords encrypted at rest). Setting any reliability/timeliness/"
        "relevance rating or analyst notes stamps last_reviewed_at."
    ),
    input_schema={
        "properties": {
            "feed_id": {"type": "string", "description": "UUID of the feed to update"},
            "url": {"type": "string", "description": "New feed URL (resets fetch state; duplicates rejected)"},
            "title": {"type": "string", "description": "Custom display title"},
            "category": {"type": "string", "description": "Category name to move the feed into (must exist)"},
            "is_muted": {"type": "boolean", "description": "Mute the feed (hidden from main timeline)"},
            "is_active": {"type": "boolean", "description": "Enable/disable fetching"},
            "fetch_interval_minutes": {"type": "integer", "description": "Polling cadence in minutes"},
            "exclude_shorts": {"type": "boolean", "description": "YouTube feeds only: skip Shorts"},
            "feed_type": {"type": "string", "enum": _UPDATE_FEED_TYPES},
            "retention_days": {
                "type": "integer",
                "description": "Entry retention window in days (0 or less clears the override)",
            },
            "reliability_rating": {"type": "string", "enum": _RELIABILITY_RATINGS},
            "timeliness_rating": {"type": "string", "enum": _TIMELINESS_RATINGS},
            "relevance_rating": {"type": "string", "enum": _RELEVANCE_RATINGS},
            "analyst_notes": {"type": "string", "description": "Source assessment notes"},
            "intel_extraction_mode": {"type": "string", "enum": _INTEL_MODES},
            "ai_analysis_enabled": {"type": "boolean"},
            "auto_extract_on_ingest": {"type": "boolean"},
            "extract_detection_rules": {"type": "boolean"},
            "extract_tools": {"type": "boolean"},
            "adapter_config": {
                "type": "object",
                "description": "Adapter-specific config keys to merge into the existing config",
            },
        },
        "required": ["feed_id"],
    },
    mutating=True,
)
async def _update_feed(
    db: AsyncSession,
    user_id: uuid.UUID,
    feed_id: str,
    url: str | None = None,
    title: str | None = None,
    category: str | None = None,
    is_muted: bool | None = None,
    is_active: bool | None = None,
    fetch_interval_minutes: int | None = None,
    exclude_shorts: bool | None = None,
    feed_type: str | None = None,
    retention_days: int | None = None,
    reliability_rating: str | None = None,
    timeliness_rating: str | None = None,
    relevance_rating: str | None = None,
    analyst_notes: str | None = None,
    intel_extraction_mode: str | None = None,
    ai_analysis_enabled: bool | None = None,
    auto_extract_on_ingest: bool | None = None,
    extract_detection_rules: bool | None = None,
    extract_tools: bool | None = None,
    adapter_config: dict | None = None,
) -> dict:
    fid, err = _parse_uuid(feed_id, "feed_id")
    if err:
        return err
    feed = await db.get(Feed, fid)
    if not feed:
        return {"error": f"Feed not found (id: {feed_id})"}

    updated: list[str] = []
    warnings: list[str] = []

    if url is not None:
        clean_url = url.strip()
        if clean_url != feed.url:
            existing = (await db.execute(select(Feed).where(Feed.url == clean_url))).scalar_one_or_none()
            if existing:
                return {"error": "a feed with this URL already exists", "existing_feed_id": str(existing.id)}
            feed.url = clean_url
            feed.etag = None
            feed.last_modified = None
            feed.error_count = 0
            feed.last_error = None
            updated.append("url")

    if title is not None:
        feed.custom_title = title
        updated.append("title")

    if category is not None:
        cat = (await db.execute(select(Category).where(Category.name == category))).scalar_one_or_none()
        if not cat:
            return {"error": f"category '{category}' does not exist — create it first with create_category"}
        feed.category_id = cat.id
        updated.append("category")

    if is_muted is not None:
        feed.is_muted = is_muted
        updated.append("is_muted")
    if is_active is not None:
        feed.is_active = is_active
        updated.append("is_active")
    if fetch_interval_minutes is not None:
        feed.fetch_interval_minutes = fetch_interval_minutes
        updated.append("fetch_interval_minutes")

    if exclude_shorts is not None:
        if feed.feed_type == "youtube":
            config = dict(feed.adapter_config or {})
            config["exclude_shorts"] = exclude_shorts
            feed.adapter_config = config
            updated.append("exclude_shorts")
        else:
            warnings.append("exclude_shorts ignored — feed is not a YouTube feed")

    if adapter_config is not None:
        from app.api.feeds import _normalize_telegram_config, _validate_bluesky_author_entity
        from app.core.exceptions import AppError

        old_config = dict(feed.adapter_config or {})
        config = dict(old_config)
        config.update(adapter_config)
        if feed.feed_type == "telegram":
            config = _normalize_telegram_config(config)
        if feed.feed_type == "bluesky":
            new_pw = adapter_config.get("app_password")
            if new_pw is None or new_pw == "" or (isinstance(new_pw, str) and set(new_pw) == {"•"}):
                if old_config.get("app_password"):
                    config["app_password"] = old_config["app_password"]
                else:
                    config.pop("app_password", None)
            elif not (isinstance(new_pw, str) and new_pw.startswith("gAAAAA")):
                from app.core.encryption import encrypt_value

                config["app_password"] = encrypt_value(new_pw)
            try:
                await _validate_bluesky_author_entity(config, db)
            except AppError as e:
                return {"error": e.message}
        feed.adapter_config = config
        # A changed backfill_days on a github_repo feed resets fetch state so the
        # next refresh re-backfills with the new window (mirrors the API).
        if feed.feed_type == "github_repo" and config.get("backfill_days") != old_config.get("backfill_days"):
            feed.last_fetched_at = None
            config.pop("last_commit_sha", None)
            feed.adapter_config = config
        updated.append("adapter_config")

    if feed_type is not None:
        if feed_type not in _UPDATE_FEED_TYPES:
            return {"error": f"invalid feed_type '{feed_type}'; valid: {_UPDATE_FEED_TYPES}"}
        feed.feed_type = feed_type
        updated.append("feed_type")

    if retention_days is not None:
        feed.retention_days = retention_days if retention_days > 0 else None
        updated.append("retention_days")

    reliability_changed = False
    if reliability_rating is not None:
        feed.reliability_rating = reliability_rating
        reliability_changed = True
        updated.append("reliability_rating")
    if timeliness_rating is not None:
        feed.timeliness_rating = timeliness_rating
        reliability_changed = True
        updated.append("timeliness_rating")
    if relevance_rating is not None:
        feed.relevance_rating = relevance_rating
        reliability_changed = True
        updated.append("relevance_rating")
    if analyst_notes is not None:
        feed.analyst_notes = analyst_notes
        reliability_changed = True
        updated.append("analyst_notes")
    if reliability_changed:
        feed.last_reviewed_at = datetime.now(UTC)

    if intel_extraction_mode is not None:
        feed.intel_extraction_mode = intel_extraction_mode
        updated.append("intel_extraction_mode")
    if ai_analysis_enabled is not None:
        feed.ai_analysis_enabled = ai_analysis_enabled
        updated.append("ai_analysis_enabled")
    if auto_extract_on_ingest is not None:
        feed.auto_extract_on_ingest = auto_extract_on_ingest
        updated.append("auto_extract_on_ingest")
    if extract_detection_rules is not None:
        feed.extract_detection_rules = extract_detection_rules
        updated.append("extract_detection_rules")
    if extract_tools is not None:
        feed.extract_tools = extract_tools
        updated.append("extract_tools")

    if not updated:
        return {"id": str(feed.id), "updated": [], "message": "no fields provided — nothing changed"}

    db.add(feed)
    await db.flush()

    result = {
        "id": str(feed.id),
        "updated": updated,
        "title": feed.custom_title or feed.title,
        "url": feed.url,
        "is_active": feed.is_active,
        "is_muted": feed.is_muted,
    }
    if warnings:
        result["warnings"] = warnings
    return result


@_tool(
    name="delete_feed",
    description=(
        "Delete a feed and ALL of its entries (cascade), removing them from the search index first. "
        "REQUIRES user confirmation. First call returns a confirmation prompt with an entry count — "
        "present it to the user. Only call again with the confirmation_token after the user explicitly "
        "approves."
    ),
    input_schema={
        "properties": {
            "feed_id": {"type": "string", "description": "UUID of the feed to delete"},
            "confirmation_token": {
                "type": "string",
                "description": "Confirmation token from a previous call. Only provide after user confirms.",
            },
        },
        "required": ["feed_id"],
    },
    mutating=True,
)
async def _delete_feed(
    db: AsyncSession,
    user_id: uuid.UUID,
    feed_id: str,
    confirmation_token: str | None = None,
) -> dict:
    fid, err = _parse_uuid(feed_id, "feed_id")
    if err:
        return err
    feed = await db.get(Feed, fid)
    if not feed:
        return {"error": f"Feed not found (id: {feed_id})"}

    title = feed.custom_title or feed.title

    if not confirmation_token:
        from sqlalchemy import func

        from app.models.entry import Entry

        entry_count = (
            await db.execute(select(func.count()).select_from(Entry).where(Entry.feed_id == fid))
        ).scalar() or 0
        return {
            "status": "confirmation_required",
            "message": f"Are you sure you want to delete the feed '{title}'?",
            "feed_id": feed_id,
            "title": title,
            "entry_count": entry_count,
            "confirmation_token": _make_token("feed", feed_id, user_id),
            "warning": f"This permanently deletes the feed and all {entry_count} of its entries.",
        }

    if not _verify_token(confirmation_token, "feed", feed_id, user_id):
        return {"error": "Invalid or expired confirmation token. Please request a new confirmation."}

    # Mirror the API cleanup order: search docs are removed BEFORE the cascade
    # delete so no orphaned documents survive (app/api/feeds.py delete_feed).
    from app.services.meilisearch_client import delete_entries_by_feed

    delete_entries_by_feed(fid)
    await db.delete(feed)
    await db.flush()

    return {"status": "deleted", "feed_id": feed_id, "title": title, "message": f"Feed '{title}' has been deleted."}


@_tool(
    name="refresh_feed",
    description=(
        "Queue an immediate background fetch of a feed via Celery (same as the UI's refresh button). "
        "Returns as soon as the fetch task is queued; new entries appear once the worker completes."
    ),
    input_schema={
        "properties": {
            "feed_id": {"type": "string", "description": "UUID of the feed to refresh"},
        },
        "required": ["feed_id"],
    },
    mutating=True,
)
async def _refresh_feed(db: AsyncSession, user_id: uuid.UUID, feed_id: str) -> dict:
    fid, err = _parse_uuid(feed_id, "feed_id")
    if err:
        return err
    feed = await db.get(Feed, fid)
    if not feed:
        return {"error": f"Feed not found (id: {feed_id})"}

    from app.workers.feed_tasks import fetch_feed

    fetch_feed.delay(str(fid))
    return {"feed_id": feed_id, "title": feed.custom_title or feed.title, "status": "refresh_queued"}


# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------


@_tool(
    name="list_categories",
    description=(
        "List feed categories as a tree (top-level categories with nested children), each with its direct feed count."
    ),
    input_schema={"properties": {}, "required": []},
    mutating=False,
)
async def _list_categories(db: AsyncSession, user_id: uuid.UUID) -> dict:
    from sqlalchemy import func

    categories = (await db.execute(select(Category).order_by(Category.position))).scalars().all()

    count_result = await db.execute(
        select(Feed.category_id, func.count().label("cnt"))
        .where(Feed.category_id.is_not(None))
        .group_by(Feed.category_id)
    )
    count_map = {row.category_id: row.cnt for row in count_result.all()}

    def _cat_dict(cat: Category) -> dict:
        return {
            "id": str(cat.id),
            "name": cat.name,
            "position": cat.position,
            "feed_count": count_map.get(cat.id, 0),
        }

    items = []
    for cat in categories:
        if cat.parent_id is None:
            node = _cat_dict(cat)
            node["children"] = [_cat_dict(child) for child in categories if child.parent_id == cat.id]
            items.append(node)

    return {"categories": items, "total": len(categories)}


@_tool(
    name="create_category",
    description="Create a feed category. Returns the existing category instead if one with the same name exists.",
    input_schema={
        "properties": {
            "name": {"type": "string", "description": "Category name"},
        },
        "required": ["name"],
    },
    mutating=True,
)
async def _create_category(db: AsyncSession, user_id: uuid.UUID, name: str) -> dict:
    name = name.strip()
    if not name:
        return {"error": "category name cannot be empty"}
    existing = (await db.execute(select(Category).where(Category.name == name))).scalar_one_or_none()
    if existing:
        return {"id": str(existing.id), "created": False, "name": existing.name, "already_exists": True}
    category = Category(created_by=user_id, name=name)
    db.add(category)
    await db.flush()
    return {"id": str(category.id), "created": True, "name": name}


# ---------------------------------------------------------------------------
# Automation rules
# ---------------------------------------------------------------------------


@_tool(
    name="update_automation_rule",
    description=(
        "Partially update an automation rule — only the provided fields change (mirrors "
        "PUT /api/automation/rules/{id}). Trigger types: "
        + ", ".join(sorted(VALID_TRIGGER_TYPES))
        + ". Each action is {type, config}; valid action types: "
        + ", ".join(sorted(VALID_ACTION_TYPES))
        + " (branch sub-actions are validated recursively). Note: actions replaces the whole list."
    ),
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "UUID of the automation rule"},
            "name": {"type": "string"},
            "description": {"type": "string"},
            "trigger_type": {"type": "string", "enum": sorted(VALID_TRIGGER_TYPES)},
            "trigger_config": {
                "type": "object",
                "description": "Trigger configuration (e.g. feed_ids, pattern, min_severity, execution_mode)",
            },
            "conditions": {"type": "object", "description": "Conditions to check before executing"},
            "actions": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Full replacement action list, each {type: <action type>, config: {...}}",
            },
            "labels": {"type": "array", "items": {"type": "string"}},
            "is_enabled": {"type": "boolean"},
        },
        "required": ["rule_id"],
    },
    mutating=True,
)
async def _update_automation_rule(
    db: AsyncSession,
    user_id: uuid.UUID,
    rule_id: str,
    name: str | None = None,
    description: str | None = None,
    trigger_type: str | None = None,
    trigger_config: dict | None = None,
    conditions: dict | None = None,
    actions: list | None = None,
    labels: list | None = None,
    is_enabled: bool | None = None,
) -> dict:
    rid, err = _parse_uuid(rule_id, "rule_id")
    if err:
        return err
    rule = await db.get(AutomationRule, rid)
    if not rule:
        return {"error": f"Automation rule not found (id: {rule_id})"}

    if trigger_type is not None and trigger_type not in VALID_TRIGGER_TYPES:
        return {"error": f"invalid trigger_type '{trigger_type}'; valid: {sorted(VALID_TRIGGER_TYPES)}"}

    if actions is not None:
        if not all(isinstance(a, dict) for a in actions):
            return {"error": "each action must be an object of shape {type, config}"}
        from app.api.automation import _validate_action_types

        action_errors = _validate_action_types(actions)
        if action_errors:
            return {
                "error": "invalid action types",
                "details": action_errors,
                "valid_action_types": sorted(VALID_ACTION_TYPES),
            }

    updated: list[str] = []
    for field, value in [
        ("name", name),
        ("description", description),
        ("trigger_type", trigger_type),
        ("trigger_config", trigger_config),
        ("conditions", conditions),
        ("actions", actions),
        ("labels", labels),
        ("is_enabled", is_enabled),
    ]:
        if value is not None:
            setattr(rule, field, value)
            updated.append(field)

    if not updated:
        return {"id": str(rule.id), "updated": [], "message": "no fields provided — nothing changed"}

    db.add(rule)
    await db.flush()
    return {"id": str(rule.id), "updated": updated, "name": rule.name, "is_enabled": rule.is_enabled}


@_tool(
    name="toggle_automation_rule",
    description="Flip an automation rule's enabled state and return the new state.",
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "UUID of the automation rule to toggle"},
        },
        "required": ["rule_id"],
    },
    mutating=True,
)
async def _toggle_automation_rule(db: AsyncSession, user_id: uuid.UUID, rule_id: str) -> dict:
    rid, err = _parse_uuid(rule_id, "rule_id")
    if err:
        return err
    rule = await db.get(AutomationRule, rid)
    if not rule:
        return {"error": f"Automation rule not found (id: {rule_id})"}
    rule.is_enabled = not rule.is_enabled
    db.add(rule)
    await db.flush()
    return {"id": str(rule.id), "name": rule.name, "is_enabled": rule.is_enabled}


@_tool(
    name="delete_automation_rule",
    description=(
        "Delete an automation rule permanently. REQUIRES user confirmation. First call returns a "
        "confirmation prompt with a token — present it to the user. Only call again with the "
        "confirmation_token after the user explicitly approves. To just stop a rule from running, "
        "use toggle_automation_rule instead."
    ),
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "UUID of the automation rule to delete"},
            "confirmation_token": {
                "type": "string",
                "description": "Confirmation token from a previous call. Only provide after user confirms.",
            },
        },
        "required": ["rule_id"],
    },
    mutating=True,
)
async def _delete_automation_rule(
    db: AsyncSession,
    user_id: uuid.UUID,
    rule_id: str,
    confirmation_token: str | None = None,
) -> dict:
    rid, err = _parse_uuid(rule_id, "rule_id")
    if err:
        return err
    rule = await db.get(AutomationRule, rid)
    if not rule:
        return {"error": f"Automation rule not found (id: {rule_id})"}

    if not confirmation_token:
        return {
            "status": "confirmation_required",
            "message": f"Are you sure you want to delete the automation rule '{rule.name}'?",
            "rule_id": rule_id,
            "name": rule.name,
            "is_enabled": rule.is_enabled,
            "confirmation_token": _make_token("automation_rule", rule_id, user_id),
            "warning": "This permanently deletes the rule and cannot be undone (its execution logs are removed too).",
        }

    if not _verify_token(confirmation_token, "automation_rule", rule_id, user_id):
        return {"error": "Invalid or expired confirmation token. Please request a new confirmation."}

    name = rule.name
    await db.delete(rule)
    await db.flush()
    return {"status": "deleted", "rule_id": rule_id, "name": name, "message": f"Automation rule '{name}' deleted."}


# ---------------------------------------------------------------------------
# Webhook presets
# ---------------------------------------------------------------------------


@_tool(
    name="list_webhook_presets",
    description=(
        "List saved webhook presets (reusable URL + payload + header combinations for automation "
        "actions), ordered by name. Webhook URLs and header values are redacted — inspect them in "
        "the web UI if needed."
    ),
    input_schema={
        "properties": {
            "preset_type": {"type": "string", "description": "Filter by preset type (e.g. 'webhook')"},
            "limit": {"type": "integer", "default": 100, "description": "Maximum presets to return"},
        },
        "required": [],
    },
    mutating=False,
)
async def _list_webhook_presets(
    db: AsyncSession, user_id: uuid.UUID, preset_type: str | None = None, limit: int = 100
) -> dict:
    from sqlalchemy import func

    base = select(WebhookPreset)
    count_base = select(func.count()).select_from(WebhookPreset)
    if preset_type:
        base = base.where(WebhookPreset.preset_type == preset_type)
        count_base = count_base.where(WebhookPreset.preset_type == preset_type)
    total = (await db.execute(count_base)).scalar() or 0
    presets = (await db.execute(base.order_by(WebhookPreset.name).limit(max(1, min(int(limit), 500))))).scalars().all()

    items = [
        {
            "id": str(p.id),
            "name": p.name,
            "preset_type": p.preset_type,
            "url": "<REDACTED>" if p.url else "",
            "payload": p.payload,
            "headers": {k: "<REDACTED>" for k in (p.headers or {})},
            "config": p.config,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in presets
    ]
    return {"presets": items, "total": total}


@_tool(
    name="create_webhook_preset",
    description=(
        "Create a webhook preset — a reusable URL + payload + headers combination that automation "
        "rule actions can reference by preset id instead of repeating the URL."
    ),
    input_schema={
        "properties": {
            "name": {"type": "string", "description": "Preset name"},
            "url": {"type": "string", "description": "Webhook URL", "default": ""},
            "payload": {
                "type": "string",
                "description": "Payload template as a JSON string (single-brace {var} placeholders)",
                "default": "{}",
            },
            "headers": {"type": "object", "description": "HTTP headers to send", "default": {}},
            "preset_type": {"type": "string", "default": "webhook"},
            "config": {"type": "object", "description": "Extra preset configuration", "default": {}},
        },
        "required": ["name"],
    },
    mutating=True,
)
async def _create_webhook_preset(
    db: AsyncSession,
    user_id: uuid.UUID,
    name: str,
    url: str = "",
    payload: str = "{}",
    headers: dict | None = None,
    preset_type: str = "webhook",
    config: dict | None = None,
) -> dict:
    name = name.strip()
    if not name:
        return {"error": "preset name cannot be empty"}
    preset = WebhookPreset(
        created_by=user_id,
        name=name,
        preset_type=preset_type,
        url=url,
        payload=payload,
        headers=headers or {},
        config=config or {},
    )
    db.add(preset)
    await db.flush()
    return {"id": str(preset.id), "created": True, "name": name, "preset_type": preset_type}


@_tool(
    name="delete_webhook_preset",
    description=(
        "Delete a webhook preset. Automation actions referencing it by id will stop resolving — "
        "check rules that use it first."
    ),
    input_schema={
        "properties": {
            "preset_id": {"type": "string", "description": "UUID of the webhook preset to delete"},
        },
        "required": ["preset_id"],
    },
    mutating=True,
)
async def _delete_webhook_preset(db: AsyncSession, user_id: uuid.UUID, preset_id: str) -> dict:
    pid, err = _parse_uuid(preset_id, "preset_id")
    if err:
        return err
    preset = await db.get(WebhookPreset, pid)
    if not preset:
        return {"error": f"Webhook preset not found (id: {preset_id})"}
    name = preset.name
    await db.delete(preset)
    await db.flush()
    return {"status": "deleted", "preset_id": preset_id, "name": name}


# ---------------------------------------------------------------------------
# Notes (entry / standalone analyst notes)
# ---------------------------------------------------------------------------


@_tool(
    name="list_notes",
    description=(
        "List analyst notes (entry-attached and standalone), pinned first then most recently "
        "updated. Optionally filter to one entry or search title/content by substring. Each note "
        "includes its author and, when attached to an entry, the entry and feed titles."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Only notes attached to this entry UUID"},
            "search": {
                "type": "string",
                "description": "Case-insensitive substring search over note title and markdown content",
            },
            "limit": {"type": "integer", "default": 50, "description": "Maximum notes to return"},
        },
        "required": [],
    },
    mutating=False,
)
async def _list_notes(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_id: str | None = None,
    search: str | None = None,
    limit: int = 50,
) -> dict:
    from sqlalchemy import func

    from app.models.entry import Entry
    from app.models.user import User

    query = (
        select(
            Note,
            Entry.title.label("entry_title"),
            func.coalesce(Feed.custom_title, Feed.title).label("feed_title"),
            User.username.label("creator_username"),
        )
        .outerjoin(Entry, Entry.id == Note.entry_id)
        .outerjoin(Feed, Feed.id == Entry.feed_id)
        .outerjoin(User, User.id == Note.created_by)
    )
    count_q = select(func.count()).select_from(Note)

    if entry_id is not None:
        eid, err = _parse_uuid(entry_id, "entry_id")
        if err:
            return err
        query = query.where(Note.entry_id == eid)
        count_q = count_q.where(Note.entry_id == eid)
    if search:
        search_filter = Note.title.ilike(f"%{search}%") | Note.content_markdown.ilike(f"%{search}%")
        query = query.where(search_filter)
        count_q = count_q.where(search_filter)

    total = (await db.execute(count_q)).scalar() or 0
    query = query.order_by(Note.is_pinned.desc(), Note.updated_at.desc()).limit(max(1, min(int(limit), 500)))
    rows = (await db.execute(query)).all()

    items = [
        {
            "id": str(note.id),
            "title": note.title,
            "content_markdown": note.content_markdown,
            "entry_id": str(note.entry_id) if note.entry_id else None,
            "entry_title": entry_title,
            "feed_title": feed_title,
            "tags": note.tags,
            "is_pinned": note.is_pinned,
            "created_by": creator_username,
            "created_at": note.created_at.isoformat() if note.created_at else None,
            "updated_at": note.updated_at.isoformat() if note.updated_at else None,
        }
        for note, entry_title, feed_title, creator_username in rows
    ]
    return {"notes": items, "total": total}


@_tool(
    name="update_note",
    description=(
        "Update an analyst note's markdown content (and optionally its title). The stored HTML is "
        "re-rendered from the new markdown, same as the notes API."
    ),
    input_schema={
        "properties": {
            "note_id": {"type": "string", "description": "UUID of the note to update"},
            "content": {"type": "string", "description": "New note content (markdown)"},
            "title": {"type": "string", "description": "New note title (unchanged if omitted)"},
        },
        "required": ["note_id", "content"],
    },
    mutating=True,
)
async def _update_note(
    db: AsyncSession, user_id: uuid.UUID, note_id: str, content: str, title: str | None = None
) -> dict:
    from app.services.markdown import render_markdown

    nid, err = _parse_uuid(note_id, "note_id")
    if err:
        return err
    note = await db.get(Note, nid)
    if not note:
        return {"error": f"Note not found (id: {note_id})"}
    if note.created_by != user_id:
        return {"error": "Only the note's author can modify it"}

    note.content_markdown = content
    note.content_html = render_markdown(content)
    if title is not None:
        note.title = title[:500]
    db.add(note)
    await db.flush()
    return {"id": str(note.id), "updated": True, "title": note.title}


@_tool(
    name="delete_note",
    description="Delete an analyst note. The entry it was attached to (if any) is not affected.",
    input_schema={
        "properties": {
            "note_id": {"type": "string", "description": "UUID of the note to delete"},
        },
        "required": ["note_id"],
    },
    mutating=True,
)
async def _delete_note(db: AsyncSession, user_id: uuid.UUID, note_id: str) -> dict:
    nid, err = _parse_uuid(note_id, "note_id")
    if err:
        return err
    note = await db.get(Note, nid)
    if not note:
        return {"error": f"Note not found (id: {note_id})"}
    if note.created_by != user_id:
        return {"error": "Only the note's author can delete it"}
    title = note.title
    await db.delete(note)
    await db.flush()
    return {"status": "deleted", "note_id": note_id, "title": title}


# ---------------------------------------------------------------------------
# Entity notes
# ---------------------------------------------------------------------------


@_tool(
    name="list_entity_notes",
    description=(
        "List the analytical notes attached to one intelligence entity, newest first, with author "
        "usernames. Supported entity types match the entity_notes constraint (ransomware victims "
        "are not supported)."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": _ENTITY_NOTE_TYPES},
            "entity_id": {"type": "string", "description": "UUID of the entity whose notes to list"},
            "limit": {"type": "integer", "default": 50, "description": "Maximum notes to return"},
        },
        "required": ["entity_type", "entity_id"],
    },
    mutating=False,
)
async def _list_entity_notes(
    db: AsyncSession, user_id: uuid.UUID, entity_type: str, entity_id: str, limit: int = 50
) -> dict:
    from sqlalchemy import func

    from app.models.user import User

    entity_type = entity_types.normalize_entity_type(entity_type)
    if entity_type not in _ENTITY_NOTE_TYPES:
        return {"error": f"unsupported entity_type '{entity_type}'; valid: {_ENTITY_NOTE_TYPES}"}
    eid, err = _parse_uuid(entity_id, "entity_id")
    if err:
        return err

    filters = (EntityNote.entity_type == entity_type, EntityNote.entity_id == eid)
    total = (await db.execute(select(func.count()).select_from(EntityNote).where(*filters))).scalar() or 0
    notes = (
        (
            await db.execute(
                select(EntityNote)
                .where(*filters)
                .order_by(EntityNote.created_at.desc())
                .limit(max(1, min(int(limit), 500)))
            )
        )
        .scalars()
        .all()
    )

    user_ids = {n.user_id for n in notes}
    user_map: dict = {}
    if user_ids:
        users_result = await db.execute(select(User.id, User.username).where(User.id.in_(user_ids)))
        user_map = {row.id: row.username for row in users_result.all()}

    items = [
        {
            "id": str(n.id),
            "title": n.title,
            "content": n.content,
            "note_type": n.note_type,
            "tags": n.tags,
            "author": user_map.get(n.user_id),
            "created_at": n.created_at.isoformat() if n.created_at else None,
            "updated_at": n.updated_at.isoformat() if n.updated_at else None,
        }
        for n in notes
    ]
    return {"entity_type": entity_type, "entity_id": entity_id, "notes": items, "total": total}


@_tool(
    name="update_entity_note",
    description="Update the content of an existing entity note. Other fields (title, type, tags) are unchanged.",
    input_schema={
        "properties": {
            "note_id": {"type": "string", "description": "UUID of the entity note to update"},
            "content": {"type": "string", "description": "New note content"},
        },
        "required": ["note_id", "content"],
    },
    mutating=True,
)
async def _update_entity_note(db: AsyncSession, user_id: uuid.UUID, note_id: str, content: str) -> dict:
    nid, err = _parse_uuid(note_id, "note_id")
    if err:
        return err
    note = await db.get(EntityNote, nid)
    if not note:
        return {"error": f"Entity note not found (id: {note_id})"}
    if note.user_id != user_id:
        return {"error": "Only the note's author can modify it"}
    note.content = content
    db.add(note)
    await db.flush()
    return {"id": str(note.id), "updated": True, "entity_type": note.entity_type, "entity_id": str(note.entity_id)}


@_tool(
    name="delete_entity_note",
    description="Permanently delete an entity note. The entity it was attached to is not affected.",
    input_schema={
        "properties": {
            "note_id": {"type": "string", "description": "UUID of the entity note to delete"},
        },
        "required": ["note_id"],
    },
    mutating=True,
)
async def _delete_entity_note(db: AsyncSession, user_id: uuid.UUID, note_id: str) -> dict:
    nid, err = _parse_uuid(note_id, "note_id")
    if err:
        return err
    note = await db.get(EntityNote, nid)
    if not note:
        return {"error": f"Entity note not found (id: {note_id})"}
    if note.user_id != user_id:
        return {"error": "Only the note's author can delete it"}
    entity_type, entity_id = note.entity_type, str(note.entity_id)
    await db.delete(note)
    await db.flush()
    return {"status": "deleted", "note_id": note_id, "entity_type": entity_type, "entity_id": entity_id}


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------


@_tool(
    name="update_campaign",
    description=(
        "Partially update a campaign — only the provided fields change (mirrors "
        "PUT /api/campaigns/{id}). Statuses: active, monitoring, closed, historical. TLP markings "
        "use TLP 2.0; the legacy TLP:WHITE is accepted and normalized to TLP:CLEAR. Note: tags "
        "replaces the whole tag list."
    ),
    input_schema={
        "properties": {
            "campaign_id": {"type": "string", "description": "Campaign UUID"},
            "name": {"type": "string"},
            "description": {"type": "string"},
            "status": {"type": "string", "enum": _CAMPAIGN_STATUSES},
            "tlp_marking": {"type": "string", "enum": _TLP_ENUM},
            "start_date": {"type": "string", "description": "Campaign start date (YYYY-MM-DD)"},
            "end_date": {"type": "string", "description": "Campaign end date (YYYY-MM-DD)"},
            "tags": {"type": "array", "items": {"type": "string"}, "description": "Full replacement tag list"},
        },
        "required": ["campaign_id"],
    },
    mutating=True,
)
async def _update_campaign(
    db: AsyncSession,
    user_id: uuid.UUID,
    campaign_id: str,
    name: str | None = None,
    description: str | None = None,
    status: str | None = None,
    tlp_marking: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    tags: list | None = None,
) -> dict:
    cid, err = _parse_uuid(campaign_id, "campaign_id")
    if err:
        return err
    campaign = await db.get(Campaign, cid)
    if not campaign:
        return {"error": f"Campaign not found (id: {campaign_id})"}

    if status is not None and status not in _CAMPAIGN_STATUSES:
        return {"error": f"invalid status '{status}'; valid: {_CAMPAIGN_STATUSES}"}
    if tlp_marking is not None:
        tlp_marking = normalize_tlp(tlp_marking)
        if tlp_marking not in TLP_VALUES:
            return {"error": f"invalid tlp_marking; valid: {list(TLP_VALUES)}"}

    parsed_start = parsed_end = None
    if start_date is not None:
        parsed_start, err = _parse_date(start_date, "start_date")
        if err:
            return err
    if end_date is not None:
        parsed_end, err = _parse_date(end_date, "end_date")
        if err:
            return err

    updated: list[str] = []
    for field, value in [
        ("name", name),
        ("description", description),
        ("status", status),
        ("tlp_marking", tlp_marking),
        ("start_date", parsed_start),
        ("end_date", parsed_end),
        ("tags", tags),
    ]:
        if value is not None:
            setattr(campaign, field, value)
            updated.append(field)

    if not updated:
        return {"id": str(campaign.id), "updated": [], "message": "no fields provided — nothing changed"}

    db.add(campaign)
    await db.flush()
    return {
        "id": str(campaign.id),
        "updated": updated,
        "name": campaign.name,
        "status": campaign.status,
        "tlp_marking": campaign.tlp_marking,
    }


@_tool(
    name="delete_campaign",
    description=(
        "Delete a campaign and its entry/entity/saved-search links. Linked entries and entities "
        "themselves are NOT deleted. REQUIRES user confirmation. First call returns a confirmation "
        "prompt with link counts — present it to the user. Only call again with the "
        "confirmation_token after the user explicitly approves."
    ),
    input_schema={
        "properties": {
            "campaign_id": {"type": "string", "description": "Campaign UUID"},
            "confirmation_token": {
                "type": "string",
                "description": "Confirmation token from a previous call. Only provide after user confirms.",
            },
        },
        "required": ["campaign_id"],
    },
    mutating=True,
)
async def _delete_campaign(
    db: AsyncSession,
    user_id: uuid.UUID,
    campaign_id: str,
    confirmation_token: str | None = None,
) -> dict:
    cid, err = _parse_uuid(campaign_id, "campaign_id")
    if err:
        return err
    campaign = await db.get(Campaign, cid)
    if not campaign:
        return {"error": f"Campaign not found (id: {campaign_id})"}

    if not confirmation_token:
        from sqlalchemy import func

        entry_count = (
            await db.execute(select(func.count()).select_from(CampaignEntry).where(CampaignEntry.campaign_id == cid))
        ).scalar() or 0
        entity_count = (
            await db.execute(select(func.count()).select_from(CampaignEntity).where(CampaignEntity.campaign_id == cid))
        ).scalar() or 0
        return {
            "status": "confirmation_required",
            "message": f"Are you sure you want to delete the campaign '{campaign.name}'?",
            "campaign_id": campaign_id,
            "name": campaign.name,
            "entry_count": entry_count,
            "entity_count": entity_count,
            "confirmation_token": _make_token("campaign", campaign_id, user_id),
            "warning": (
                "This permanently deletes the campaign and its links "
                f"({entry_count} entries, {entity_count} entities). Linked entries/entities are kept."
            ),
        }

    if not _verify_token(confirmation_token, "campaign", campaign_id, user_id):
        return {"error": "Invalid or expired confirmation token. Please request a new confirmation."}

    name = campaign.name
    await db.delete(campaign)
    await db.flush()
    return {"status": "deleted", "campaign_id": campaign_id, "name": name, "message": f"Campaign '{name}' deleted."}


@_tool(
    name="remove_from_campaign",
    description=(
        "Unlink an entry or entity from a campaign (the reverse of add_to_campaign). Provide either "
        "entry_id, or entity_type + entity_id. The entry/entity itself is not deleted, only the "
        "campaign link — no confirmation needed."
    ),
    input_schema={
        "properties": {
            "campaign_id": {"type": "string", "description": "Campaign UUID"},
            "entry_id": {"type": "string", "description": "Entry UUID to unlink (optional)"},
            "entity_type": {
                "type": "string",
                "enum": sorted(entity_types.ALL),
                "description": "Entity type to unlink (optional, requires entity_id)",
            },
            "entity_id": {"type": "string", "description": "Entity UUID to unlink (optional)"},
        },
        "required": ["campaign_id"],
    },
    mutating=True,
)
async def _remove_from_campaign(
    db: AsyncSession,
    user_id: uuid.UUID,
    campaign_id: str,
    entry_id: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
) -> dict:
    cid, err = _parse_uuid(campaign_id, "campaign_id")
    if err:
        return err
    campaign = await db.get(Campaign, cid)
    if not campaign:
        return {"error": f"Campaign not found (id: {campaign_id})"}

    if entry_id:
        eid, err = _parse_uuid(entry_id, "entry_id")
        if err:
            return err
        link = (
            await db.execute(
                select(CampaignEntry).where(CampaignEntry.campaign_id == cid, CampaignEntry.entry_id == eid)
            )
        ).scalar_one_or_none()
        if not link:
            return {"error": "entry is not linked to this campaign"}
        await db.delete(link)
        await db.flush()
        return {"status": "removed", "type": "entry", "campaign_id": campaign_id, "entry_id": entry_id}

    if entity_type and entity_id:
        ent_id, err = _parse_uuid(entity_id, "entity_id")
        if err:
            return err
        links = (
            (
                await db.execute(
                    select(CampaignEntity).where(
                        CampaignEntity.campaign_id == cid,
                        CampaignEntity.entity_type == entity_type,
                        CampaignEntity.entity_id == ent_id,
                    )
                )
            )
            .scalars()
            .all()
        )
        if not links:
            return {"error": "entity is not linked to this campaign"}
        for link in links:
            await db.delete(link)
        await db.flush()
        return {
            "status": "removed",
            "type": "entity",
            "campaign_id": campaign_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
        }

    return {"error": "provide either entry_id, or entity_type + entity_id"}
