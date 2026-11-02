"""Write / Create Operations tools."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import adapters, entity_types
from app.intelligence.entity_resolution import (
    coerce_malware_type,
    gate_aliases,
    resolve_entity_creation,
)
from app.intelligence.relationship_matrix import (
    _CONFIDENCE_ORDER,
    ALLOWED_RELATIONSHIPS,
    allowed_verbs_for_pair,
    orient_relationship,
)
from app.intelligence.reporting import REPORT_TEMPLATES
from app.models.automation_rule import AutomationRule
from app.models.campaign import Campaign
from app.models.detection_rule import DetectionRule
from app.models.entity_note import EntityNote
from app.models.entity_relationship import EntityRelationship
from app.models.feed import Feed
from app.models.intel_report import IntelReport
from app.models.intelligence_requirement import IntelligenceRequirement
from app.models.malware_family import MalwareFamily
from app.models.note import Note
from app.models.tag import Tag
from app.models.threat_actor import ThreatActor
from app.schemas.automation import VALID_ACTION_TYPES, VALID_TRIGGER_TYPES
from app.schemas.intelligence import RULE_TYPE_PATTERN
from app.schemas.tlp import TLP_VALUES, normalize_tlp
from app.services.entity_backlink import dispatch_backlink_for_added_aliases
from app.tools import _tool

# Endpoint types the relationship matrix actually allows — derived rather than
# restated so a matrix edit can't leave this schema advertising a dead pair.
_RELATIONSHIP_ENDPOINT_TYPES = sorted(
    {src for src, _, _ in ALLOWED_RELATIONSHIPS} | {tgt for _, _, tgt in ALLOWED_RELATIONSHIPS}
)

# Relationship verbs the matrix allows — derived so a matrix edit can't drift this schema.
_RELATIONSHIP_VERBS = sorted({verb for _, verb, _ in ALLOWED_RELATIONSHIPS})

# TLP 2.0 vocabulary from the shared constant; "TLP:WHITE" is accepted as a
# legacy input alias and normalized to "TLP:CLEAR" before storage.
_TLP_ENUM = [*TLP_VALUES, "TLP:WHITE"]

# Report template slugs — derived from the canonical registry.
_REPORT_TEMPLATE_TYPES = sorted(REPORT_TEMPLATES)

# Detection rule formats — derived from the API's validation pattern.
_RULE_TYPES = sorted(RULE_TYPE_PATTERN.removeprefix("^(").removesuffix(")$").split("|"))

# Feed types — derived from the adapter registry (standard + extended adapters).
_FEED_TYPES = sorted(set(adapters._ADAPTERS) | set(adapters._EXTENDED_ADAPTERS))

# Entity types the entity_notes DB CHECK accepts (plus "campaign", which is an
# object kind rather than an entity type). ransomware_victim is excluded — the
# CHECK constraint does not cover it.
_ENTITY_NOTE_TYPES = sorted((entity_types.ALL - {entity_types.RANSOMWARE_VICTIM}) | {"campaign"})


def _normalize_tlp_or_error(tlp_marking: str) -> tuple[str | None, dict | None]:
    """Normalize a TLP marking (folding TLP:WHITE → TLP:CLEAR); error dict if invalid."""
    tlp = normalize_tlp(tlp_marking)
    if tlp not in TLP_VALUES:
        return None, {"error": f"invalid tlp_marking '{tlp_marking}'; valid: {list(TLP_VALUES)}"}
    return tlp, None


def _validate_template_type(template_type: str) -> dict | None:
    if template_type not in REPORT_TEMPLATES:
        return {"error": f"unknown template_type '{template_type}'; valid: {_REPORT_TEMPLATE_TYPES}"}
    return None


def _merge_aliases(entity_type: str, entity, name: str, aliases: list[str] | None) -> None:
    """Fold an incoming name + aliases into ``entity.aliases`` without duplicates.

    Used when a create tool resolves to an existing entity so newly-supplied names
    are retained as aliases rather than silently dropped. Any genuinely new name
    queues the same retro match scan a fresh entity gets.
    """
    seen = {a.lower() for a in (entity.aliases or [])}
    seen.add(entity.name.lower())
    original = list(entity.aliases or [])
    merged = list(original)
    for candidate in [name, *(aliases or [])]:
        if candidate and candidate.strip() and candidate.lower() not in seen:
            merged.append(candidate.strip())
            seen.add(candidate.lower())
    if len(merged) != len(original):
        entity.aliases = merged
        dispatch_backlink_for_added_aliases(entity_type, entity.id, original, merged)


@_tool(
    name="create_threat_actor",
    description=(
        "Create a new threat actor entity. Runs the entity resolver first: if the name or an alias "
        "matches an existing actor, that entity is returned (created: false) with new aliases folded in; "
        "if the creation gates reject the name (tombstone, dictionary word, etc.) the result is "
        "blocked: true with a reason instead of a new entity."
    ),
    input_schema={
        "properties": {
            "name": {"type": "string", "description": "Primary name"},
            "aliases": {"type": "array", "items": {"type": "string"}, "default": []},
            "description": {"type": "string"},
            "country": {"type": "string"},
            "motivation": {"type": "string"},
        },
        "required": ["name"],
    },
)
async def _create_threat_actor(
    db: AsyncSession,
    user_id: uuid.UUID,
    name: str,
    aliases: list[str] | None = None,
    description: str | None = None,
    country: str | None = None,
    motivation: str | None = None,
) -> dict:
    # Resolver: exact + normalized dedup, tombstones, creation gates. CLI/
    # automation callers get no "create anyway" override (manual UI does).
    decision = await resolve_entity_creation(db, "threat_actor", name, aliases, source="cli")
    if decision.action == "matched":
        existing = decision.entity
        _merge_aliases(
            "threat_actor",
            existing,
            name,
            await gate_aliases(db, "threat_actor", existing.name, aliases, entity_id=existing.id),
        )
        return {"id": str(existing.id), "created": False, "name": existing.name}
    if decision.action != "create":
        return {
            "created": False,
            "blocked": True,
            "reason": decision.reason or decision.action,
            "name": name,
        }
    now = datetime.now(UTC)
    actor = ThreatActor(
        name=name,
        aliases=await gate_aliases(db, "threat_actor", name, aliases),
        description=description,
        country=country,
        motivation=motivation,
        first_seen_at=now,
        last_seen_at=now,
        article_count=0,
    )
    db.add(actor)
    await db.flush()
    return {"id": str(actor.id), "created": True, "name": name}


@_tool(
    name="create_malware",
    description=(
        "Create a new malware family entity. Runs the entity resolver first: if the name or an alias "
        "matches an existing family, that entity is returned (created: false) with new aliases folded in; "
        "if the creation gates reject the name the result is blocked: true with a reason. "
        "malware_type is coerced onto the controlled vocabulary (raw value kept in metadata)."
    ),
    input_schema={
        "properties": {
            "name": {"type": "string", "description": "Primary name"},
            "aliases": {"type": "array", "items": {"type": "string"}, "default": []},
            "description": {"type": "string"},
            "malware_type": {
                "type": "string",
                "description": "e.g. ransomware, backdoor, loader, RAT, wiper",
            },
        },
        "required": ["name"],
    },
)
async def _create_malware(
    db: AsyncSession,
    user_id: uuid.UUID,
    name: str,
    aliases: list[str] | None = None,
    description: str | None = None,
    malware_type: str | None = None,
) -> dict:
    # Resolver: exact + normalized dedup, tombstones, creation gates. CLI/
    # automation callers get no "create anyway" override (manual UI does).
    decision = await resolve_entity_creation(db, "malware", name, aliases, source="cli")
    if decision.action == "matched":
        existing = decision.entity
        _merge_aliases(
            "malware",
            existing,
            name,
            await gate_aliases(db, "malware", existing.name, aliases, entity_id=existing.id),
        )
        return {"id": str(existing.id), "created": False, "name": existing.name}
    if decision.action != "create":
        return {
            "created": False,
            "blocked": True,
            "reason": decision.reason or decision.action,
            "name": name,
        }
    coerced_type, raw_type = coerce_malware_type(malware_type)
    now = datetime.now(UTC)
    mw = MalwareFamily(
        name=name,
        aliases=await gate_aliases(db, "malware", name, aliases),
        description=description,
        malware_type=coerced_type,
        metadata_={"raw_malware_type": raw_type} if raw_type else {},
        associated_actors=[],
        first_seen_at=now,
        last_seen_at=now,
        article_count=0,
    )
    db.add(mw)
    await db.flush()
    return {"id": str(mw.id), "created": True, "name": name}


@_tool(
    name="create_detection_rule",
    description=(
        "Save a detection rule to the library. The rule is stored as a DRAFT (is_draft=true) — an "
        "analyst promotes it from the Detection workbench. Optional provenance: tags, reference URLs, "
        "and source entry UUIDs the rule was derived from."
    ),
    input_schema={
        "properties": {
            "title": {"type": "string", "description": "Rule title"},
            "rule_type": {
                "type": "string",
                "enum": _RULE_TYPES,
            },
            "rule_content": {"type": "string", "description": "The rule content"},
            "description": {"type": "string"},
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
            },
            "entry_id": {
                "type": "string",
                "description": "Optional: source entry UUID",
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional free-form tags",
            },
            "references": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional advisory/blog URLs the rule cites",
            },
            "source_entry_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional entry UUIDs the rule was derived from",
            },
        },
        "required": ["title", "rule_type", "rule_content"],
    },
)
async def _create_detection_rule(
    db: AsyncSession,
    user_id: uuid.UUID,
    title: str,
    rule_type: str,
    rule_content: str,
    description: str | None = None,
    severity: str | None = None,
    entry_id: str | None = None,
    tags: list[str] | None = None,
    references: list[str] | None = None,
    source_entry_ids: list[str] | None = None,
) -> dict:
    rule = DetectionRule(
        created_by=user_id,
        entry_id=uuid.UUID(entry_id) if entry_id else None,
        rule_type=rule_type,
        title=title,
        description=description,
        rule_content=rule_content,
        severity=severity,
        is_draft=True,
        tags=tags or [],
        references=references or [],
        source_entries=[uuid.UUID(e) for e in (source_entry_ids or [])],
    )
    db.add(rule)
    await db.flush()
    return {
        "id": str(rule.id),
        "created": True,
        "title": title,
        "rule_type": rule_type,
        "is_draft": True,
    }


@_tool(
    name="create_campaign",
    description=(
        "Create a new campaign to track a threat operation and link entities/entries to it. "
        "TLP markings use TLP 2.0 (TLP:CLEAR/GREEN/AMBER/AMBER+STRICT/RED); the legacy "
        "TLP:WHITE is accepted and normalized to TLP:CLEAR."
    ),
    input_schema={
        "properties": {
            "name": {"type": "string", "description": "Campaign name"},
            "description": {"type": "string"},
            "status": {
                "type": "string",
                "enum": ["active", "monitoring", "closed", "historical"],
                "default": "active",
            },
            "tlp_marking": {
                "type": "string",
                "enum": _TLP_ENUM,
                "default": "TLP:GREEN",
            },
        },
        "required": ["name"],
    },
)
async def _create_campaign(
    db: AsyncSession,
    user_id: uuid.UUID,
    name: str,
    description: str | None = None,
    status: str = "active",
    tlp_marking: str = "TLP:GREEN",
) -> dict:
    tlp_marking, tlp_err = _normalize_tlp_or_error(tlp_marking)
    if tlp_err:
        return tlp_err
    campaign = Campaign(
        created_by=user_id,
        name=name,
        description=description,
        status=status,
        tlp_marking=tlp_marking,
        tags=[],
    )
    db.add(campaign)
    await db.flush()
    return {"id": str(campaign.id), "created": True, "name": name}


@_tool(
    name="create_feed",
    description=(
        "Subscribe to a new feed. feed_type covers every registered adapter (rss, atom, youtube, "
        "podcast, reddit, github_releases, github_advisories, github_repo, nvd, mastodon, web_scraper, "
        "telegram, bluesky — for telegram prefer add_telegram_feed). Rejects duplicate URLs with a "
        "structured error and queues an initial fetch via Celery. Extended adapter types usually need "
        "an adapter_config (see the adapter's expected keys). If a named category does not exist the "
        "feed is still created and a warning is returned."
    ),
    input_schema={
        "properties": {
            "url": {"type": "string", "description": "Feed URL"},
            "title": {
                "type": "string",
                "description": "Display title (defaults to the URL if omitted)",
            },
            "feed_type": {
                "type": "string",
                "enum": _FEED_TYPES,
                "default": "rss",
            },
            "category": {
                "type": "string",
                "description": "Category name to organize the feed under (must already exist)",
            },
            "adapter_config": {
                "type": "object",
                "description": "Adapter-specific configuration (extended adapter types)",
            },
        },
        "required": ["url"],
    },
)
async def _create_feed(
    db: AsyncSession,
    user_id: uuid.UUID,
    url: str,
    title: str | None = None,
    feed_type: str = "rss",
    category: str | None = None,
    adapter_config: dict | None = None,
) -> dict:
    if feed_type not in _FEED_TYPES:
        return {"error": f"unknown feed_type '{feed_type}'; valid: {_FEED_TYPES}"}

    # Duplicate-URL check (mirrors the feeds API 409) — friendlier than an IntegrityError.
    existing = (await db.execute(select(Feed).where(Feed.url == url))).scalar_one_or_none()
    if existing:
        return {"error": "a feed with this URL already exists", "id": str(existing.id), "url": url}

    warning = None
    category_id = None
    if category:
        from app.models.category import Category

        cat = (await db.execute(select(Category).where(Category.name == category))).scalar_one_or_none()
        if cat:
            category_id = cat.id
        else:
            warning = f"category '{category}' does not exist; feed filed with others of its type, if any"

    # The same config handling POST /api/feeds applies: Telegram configs are
    # normalized, and a Bluesky app password is encrypted before it is stored
    # (the adapter only ever decrypts it).
    from app.api.feeds import (
        _encrypt_bluesky_app_password,
        _normalize_telegram_config,
        _validate_bluesky_author_entity,
    )
    from app.core.exceptions import AppError

    adapter_config = dict(adapter_config or {})
    try:
        if feed_type == "telegram":
            adapter_config = _normalize_telegram_config(adapter_config)
        elif feed_type == "bluesky":
            adapter_config = _encrypt_bluesky_app_password(adapter_config)
            await _validate_bluesky_author_entity(adapter_config, db)
    except AppError as e:
        return {"error": e.message}

    from app.services.feed_defaults import category_for_feed_type, new_feed_settings

    if category_id is None:
        category_id = await category_for_feed_type(db, feed_type)

    feed = Feed(
        url=url,
        title=title or url,
        custom_title=title,
        feed_type=feed_type,
        adapter_config=adapter_config,
        category_id=category_id,
        is_active=True,
        error_count=0,
        # Same inheritance as POST /api/feeds: the category's defaults, else global.
        **await new_feed_settings(db, category_id, {}),
    )
    db.add(feed)
    await db.flush()

    from app.services.feed_visibility import ensure_subscription, subscribe_all_users, subscriptions_enabled

    if await subscriptions_enabled(db):
        await ensure_subscription(db, user_id, feed.id)
    else:
        await subscribe_all_users(db, feed.id)
    await db.flush()

    # Queue the initial fetch (mirrors the feeds API create path).
    from app.workers.feed_tasks import fetch_feed

    fetch_feed.delay(str(feed.id))

    result = {"id": str(feed.id), "created": True, "title": feed.title, "url": url, "initial_fetch": "queued"}
    if warning:
        result["warning"] = warning
    return result


@_tool(
    name="add_telegram_feed",
    description=(
        "Subscribe to a Telegram channel feed. Requires server-side Telegram setup "
        "(scripts/telegram/telegram_login.py). The channel must be public OR the IntelFeed account "
        "must already be a member. Accepts @handle, t.me/https://t.me URLs (including /s/ preview "
        "URLs), or a numeric channel id; invite links (+hash / joinchat) are rejected — join first, "
        "then subscribe by handle or id. Queues an initial fetch on creation. Optionally "
        "auto-attribute every message to a threat actor or campaign — use this for ransomware leak "
        "channels, hacktivist channels, and broker channels that are themselves the actor."
    ),
    input_schema={
        "properties": {
            "channel": {
                "type": "string",
                "description": "@channelname, https://t.me/channel, or numeric channel id",
            },
            "title": {
                "type": "string",
                "description": "Display title (defaults to 'Telegram: <channel>')",
            },
            "include_media": {
                "type": "boolean",
                "default": True,
                "description": "Download photos/videos/voice notes/documents",
            },
            "extract_forwards": {
                "type": "boolean",
                "default": True,
                "description": "Show 'Forwarded from' attribution",
            },
            "max_message_age_days": {
                "type": "integer",
                "default": 30,
                "description": "Skip messages older than N days on first fetch (0 = no limit)",
            },
            "max_messages_per_fetch": {
                "type": "integer",
                "default": 200,
                "description": "Safety cap per polling cycle",
            },
            "fetch_interval_minutes": {
                "type": "integer",
                "default": 30,
                "description": "Polling cadence (lower = higher flood-wait risk)",
            },
            "threat_actor_id": {
                "type": "string",
                "description": "Optional UUID — auto-attribute every message to this actor",
            },
            "campaign_id": {
                "type": "string",
                "description": "Optional UUID — auto-link every message to this campaign",
            },
            "session_name": {
                "type": "string",
                "description": "Optional named session if running multiple Telegram identities",
            },
            "category": {
                "type": "string",
                "description": "Category name to organize the feed under",
            },
        },
        "required": ["channel"],
    },
)
async def _add_telegram_feed(
    db: AsyncSession,
    user_id: uuid.UUID,
    channel: str,
    title: str | None = None,
    include_media: bool = True,
    extract_forwards: bool = True,
    max_message_age_days: int = 30,
    max_messages_per_fetch: int = 200,
    fetch_interval_minutes: int = 30,
    threat_actor_id: str | None = None,
    campaign_id: str | None = None,
    session_name: str | None = None,
    category: str | None = None,
) -> dict:
    from app.adapters.telegram import normalize_channel_handle

    # Normalize all advertised input forms down to a bare handle or numeric id.
    # normalize_channel_handle strips the web-preview /s/ segment first.
    raw = normalize_channel_handle(channel.strip())
    lowered = raw.lower()
    for scheme in ("https://", "http://", ""):
        for host in ("t.me/", "telegram.me/"):
            prefix = f"{scheme}{host}"
            if prefix and lowered.startswith(prefix):
                raw = raw[len(prefix) :]
                lowered = raw.lower()
    raw = raw.strip().lstrip("@").rstrip("/")

    # Invite links (t.me/+hash or t.me/joinchat/...) can't be resolved by the
    # adapter's get_entity path — the account must already be a member, at which
    # point the channel has a resolvable id/username instead.
    if raw.startswith("+") or raw.lower().startswith("joinchat"):
        return {
            "error": (
                "invite links are not supported — join the channel with the IntelFeed Telegram "
                "account first, then subscribe using the channel's @handle or numeric id"
            )
        }
    if not raw:
        return {"error": "could not extract a channel handle from the given input"}

    # Numeric ids route to adapter_config['channel_id'] (private channels without
    # a username); handles route to adapter_config['channel'].
    is_numeric = raw.lstrip("-").isdigit()
    if is_numeric:
        url = f"https://t.me/c/{raw.lstrip('-')}"
        display = raw
    else:
        url = f"https://t.me/{raw}"
        display = f"@{raw}"

    existing = await db.execute(select(Feed).where(Feed.url == url))
    if existing.scalar_one_or_none():
        return {"error": "telegram feed already exists for this channel", "url": url}

    adapter_config: dict = {
        "include_media": include_media,
        "extract_forwards": extract_forwards,
        "max_message_age_days": max_message_age_days,
        "max_messages_per_fetch": max_messages_per_fetch,
    }
    if is_numeric:
        adapter_config["channel_id"] = int(raw)
    else:
        adapter_config["channel"] = f"@{raw}"
    if threat_actor_id:
        adapter_config["threat_actor_id"] = threat_actor_id
    if campaign_id:
        adapter_config["campaign_id"] = campaign_id
    if session_name:
        adapter_config["session_name"] = session_name

    warning = None
    category_id = None
    if category:
        from app.models.category import Category

        cat_row = await db.execute(select(Category).where(Category.name == category))
        existing_cat = cat_row.scalar_one_or_none()
        if existing_cat:
            category_id = existing_cat.id
        else:
            warning = f"category '{category}' does not exist; feed created without a category"

    feed = Feed(
        url=url,
        title=title or f"Telegram: {display}",
        custom_title=title,
        feed_type="telegram",
        adapter_config=adapter_config,
        is_active=True,
        error_count=0,
        fetch_interval_minutes=fetch_interval_minutes,
        category_id=category_id,
    )
    db.add(feed)
    await db.flush()

    from app.services.feed_visibility import ensure_subscription, subscribe_all_users, subscriptions_enabled

    if await subscriptions_enabled(db):
        await ensure_subscription(db, user_id, feed.id)
    else:
        await subscribe_all_users(db, feed.id)
    await db.flush()

    # Queue the initial fetch (mirrors the feeds API create path).
    from app.workers.feed_tasks import fetch_feed

    fetch_feed.delay(str(feed.id))

    result = {
        "id": str(feed.id),
        "created": True,
        "url": url,
        "title": feed.title,
        "adapter_config": adapter_config,
        "initial_fetch": "queued",
    }
    if warning:
        result["warning"] = warning
    return result


@_tool(
    name="create_note",
    description=(
        "Add an analyst note to an entry. Markdown content is rendered and stored as HTML "
        "(same as the notes API). If no title is given, one is derived from the first line "
        "of the content, falling back to the entry title."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID"},
            "content": {"type": "string", "description": "Note content (markdown)"},
            "title": {
                "type": "string",
                "description": "Note title (derived from content/entry title if omitted)",
            },
        },
        "required": ["entry_id", "content"],
    },
)
async def _create_note(
    db: AsyncSession, user_id: uuid.UUID, entry_id: str, content: str, title: str | None = None
) -> dict:
    from app.models.entry import Entry
    from app.services.markdown import render_markdown

    eid = uuid.UUID(entry_id)
    entry = (await db.execute(select(Entry).where(Entry.id == eid))).scalar_one_or_none()
    if not entry:
        return {"error": "Entry not found"}

    if not title:
        first_line = next((ln.strip() for ln in content.splitlines() if ln.strip()), "")
        title = first_line.lstrip("#").strip() or (f"Note: {entry.title}" if entry.title else "Note")
    title = title[:500]

    note = Note(
        created_by=user_id,
        entry_id=eid,
        title=title,
        content_markdown=content,
        content_html=render_markdown(content),
    )
    db.add(note)
    await db.flush()
    return {"id": str(note.id), "created": True, "title": title}


@_tool(
    name="create_entity_note",
    description=(
        "Add an analytical note to an intelligence entity. Supported entity types: campaign, country, "
        "cve, cwe, malware, mitigation, observable, product, sector, threat_actor, tool, ttp, vendor "
        "(matches the entity_notes DB constraint; ransomware victims are not supported)."
    ),
    input_schema={
        "properties": {
            "entity_type": {
                "type": "string",
                "enum": _ENTITY_NOTE_TYPES,
            },
            "entity_id": {"type": "string", "description": "Entity UUID"},
            "content": {"type": "string", "description": "Note content (markdown)"},
        },
        "required": ["entity_type", "entity_id", "content"],
    },
)
async def _create_entity_note(
    db: AsyncSession, user_id: uuid.UUID, entity_type: str, entity_id: str, content: str
) -> dict:
    entity_type = entity_types.normalize_entity_type(entity_type)
    if entity_type not in _ENTITY_NOTE_TYPES:
        return {"error": f"unsupported entity_type '{entity_type}'; valid: {_ENTITY_NOTE_TYPES}"}
    note = EntityNote(
        entity_type=entity_type,
        entity_id=uuid.UUID(entity_id),
        user_id=user_id,
        content=content,
    )
    db.add(note)
    await db.flush()
    return {"id": str(note.id), "created": True}


@_tool(
    name="add_tag",
    description="Tag an entry with an existing or new tag.",
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID"},
            "tag_name": {
                "type": "string",
                "description": "Tag name (creates if doesn't exist)",
            },
        },
        "required": ["entry_id", "tag_name"],
    },
)
async def _add_tag(db: AsyncSession, user_id: uuid.UUID, entry_id: str, tag_name: str) -> dict:
    """The assignment is the caller's own unless the tag is global."""
    from app.automation.actions import _clean_tag_name
    from app.services.entry_tags import ensure_assignment, sync_entry_tags_to_search

    tag_name = _clean_tag_name(tag_name)  # same normalisation as a rule's add_tags
    if not tag_name:
        return {"error": "tag_name is required"}
    tag_q = await db.execute(select(Tag).where(Tag.name == tag_name))
    tag = tag_q.scalar_one_or_none()
    if not tag:
        tag = Tag(name=tag_name, created_by=user_id)
        db.add(tag)
        await db.flush()

    entry_uuid = uuid.UUID(entry_id)
    if not await ensure_assignment(db, entry_uuid, tag, user_id):
        return {"tag_id": str(tag.id), "already_tagged": True}

    await db.flush()
    await sync_entry_tags_to_search(db, [entry_uuid])
    return {"tag_id": str(tag.id), "created": True, "tag_name": tag_name}


@_tool(
    name="add_to_campaign",
    description=(
        "Link an entry or entity to a campaign. Re-linking an already-linked entry/entity returns "
        "already_linked instead of an error. Note: the campaign UI and reports resolve names only for "
        "threat_actor, malware, cve, ttp and ransomware_victim links — other entity types are stored "
        "but render as bare IDs in campaign views."
    ),
    input_schema={
        "properties": {
            "campaign_id": {"type": "string", "description": "Campaign UUID"},
            "entry_id": {
                "type": "string",
                "description": "Entry UUID to link (optional)",
            },
            "entity_type": {
                "type": "string",
                "enum": sorted(entity_types.ALL),
                "description": "Entity type to link (optional)",
            },
            "entity_id": {
                "type": "string",
                "description": "Entity UUID to link (optional)",
            },
            "role": {
                "type": "string",
                "enum": ["primary", "secondary", "related"],
                "default": "related",
            },
        },
        "required": ["campaign_id"],
    },
)
async def _add_to_campaign(
    db: AsyncSession,
    user_id: uuid.UUID,
    campaign_id: str,
    entry_id: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    role: str = "related",
) -> dict:
    from app.models.campaign import CampaignEntity, CampaignEntry

    cid = uuid.UUID(campaign_id)
    if entry_id:
        eid = uuid.UUID(entry_id)
        existing = (
            await db.execute(
                select(CampaignEntry).where(CampaignEntry.campaign_id == cid, CampaignEntry.entry_id == eid)
            )
        ).scalar_one_or_none()
        if existing:
            return {"already_linked": True, "type": "entry", "entry_id": entry_id}
        db.add(CampaignEntry(campaign_id=cid, entry_id=eid, added_by=user_id))
        await db.flush()
        return {"created": True, "type": "entry", "entry_id": entry_id}
    if entity_type and entity_id:
        ent_id = uuid.UUID(entity_id)
        existing = (
            await db.execute(
                select(CampaignEntity).where(
                    CampaignEntity.campaign_id == cid,
                    CampaignEntity.entity_type == entity_type,
                    CampaignEntity.entity_id == ent_id,
                )
            )
        ).scalar_one_or_none()
        if existing:
            return {"already_linked": True, "type": "entity", "entity_type": entity_type, "entity_id": entity_id}
        db.add(
            CampaignEntity(
                campaign_id=cid,
                entity_type=entity_type,
                entity_id=ent_id,
                role=role,
                added_by=user_id,
            )
        )
        await db.flush()
        return {
            "created": True,
            "type": "entity",
            "entity_type": entity_type,
            "entity_id": entity_id,
        }
    return {"error": "Provide either entry_id or entity_type+entity_id"}


@_tool(
    name="link_entities",
    description=(
        "Assert an analyst-grade relationship between two intelligence entities. The (source, verb, "
        "target) triple is validated against the semantic relationship matrix and auto-flipped into "
        "its canonical orientation (e.g. 'cve exploited-by actor' is stored as 'actor exploits cve'). "
        f"Valid verbs (per-pair restrictions apply): {', '.join(_RELATIONSHIP_VERBS)}. Written with "
        "source=analyst_created; re-asserting an existing triple promotes it to analyst_created and "
        "merges confidence/description/evidence instead of erroring."
    ),
    input_schema={
        "properties": {
            "source_type": {
                "type": "string",
                "enum": _RELATIONSHIP_ENDPOINT_TYPES,
            },
            "source_id": {"type": "string"},
            "target_type": {
                "type": "string",
                "enum": _RELATIONSHIP_ENDPOINT_TYPES,
            },
            "target_id": {"type": "string"},
            "relationship_type": {
                "type": "string",
                "enum": _RELATIONSHIP_VERBS,
            },
            "description": {"type": "string"},
            "confidence": {
                "type": "string",
                "enum": list(_CONFIDENCE_ORDER),
                "default": "possible",
            },
            "evidence_entry_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Entry UUIDs that evidence this relationship",
            },
        },
        "required": [
            "source_type",
            "source_id",
            "target_type",
            "target_id",
            "relationship_type",
        ],
    },
)
async def _link_entities(
    db: AsyncSession,
    user_id: uuid.UUID,
    source_type: str,
    source_id: str,
    target_type: str,
    target_id: str,
    relationship_type: str,
    description: str | None = None,
    confidence: str = "possible",
    evidence_entry_ids: list[str] | None = None,
) -> dict:
    rel_type = relationship_type.strip().lower().replace("-", "_").replace(" ", "_")
    if rel_type not in _RELATIONSHIP_VERBS:
        return {"error": f"invalid relationship_type '{relationship_type}'; valid: {_RELATIONSHIP_VERBS}"}
    if confidence not in _CONFIDENCE_ORDER:
        return {"error": f"invalid confidence '{confidence}'; valid: {list(_CONFIDENCE_ORDER)}"}
    src_id, tgt_id = uuid.UUID(source_id), uuid.UUID(target_id)
    evidence = [uuid.UUID(e) for e in (evidence_entry_ids or [])]

    oriented = orient_relationship(source_type, rel_type, target_type)
    if oriented is None:
        verbs = allowed_verbs_for_pair(source_type, target_type) + [
            f"{v} (as {target_type}→{source_type})" for v in allowed_verbs_for_pair(target_type, source_type)
        ]
        return {
            "error": f"'{source_type} {rel_type} {target_type}' is not a tracked combination; "
            f"valid for this pair: {verbs or 'none'}"
        }
    if oriented[0] != source_type:
        source_type, target_type = oriented[0], oriented[2]
        src_id, tgt_id = tgt_id, src_id

    existing = (
        await db.execute(
            select(EntityRelationship).where(
                EntityRelationship.source_type == source_type,
                EntityRelationship.source_id == src_id,
                EntityRelationship.target_type == target_type,
                EntityRelationship.target_id == tgt_id,
                EntityRelationship.relationship_type == rel_type,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        # Mirror the analyst API's upsert-promote semantics: merge evidence,
        # take the asserted confidence, and promote the row to analyst_created.
        merged = list(existing.evidence_entry_ids or [])
        merged += [e for e in evidence if e not in merged]
        existing.evidence_entry_ids = merged
        existing.confidence = confidence
        if description is not None:
            existing.description = description
        existing.source = "analyst_created"
        db.add(existing)
        await db.flush()
        from app.api.entity_relationships import _invalidate_rel_caches

        await _invalidate_rel_caches(existing)
        return {
            "id": str(existing.id),
            "created": False,
            "updated": True,
            "note": "existing relationship promoted to analyst_created and evidence merged",
        }

    rel = EntityRelationship(
        source_type=source_type,
        source_id=src_id,
        target_type=target_type,
        target_id=tgt_id,
        relationship_type=rel_type,
        description=description,
        confidence=confidence,
        evidence_entry_ids=evidence,
        source="analyst_created",
        created_by=user_id,
    )
    db.add(rel)
    await db.flush()
    from app.api.entity_relationships import _invalidate_rel_caches

    await _invalidate_rel_caches(rel)
    return {"id": str(rel.id), "created": True}


@_tool(
    name="create_automation_rule",
    description=(
        "Set up an automation rule with trigger, conditions, and actions. Trigger types: "
        + ", ".join(sorted(VALID_TRIGGER_TYPES))
        + ". Each action is {type, config}; valid action types: "
        + ", ".join(sorted(VALID_ACTION_TYPES))
        + ". The rule is created enabled."
    ),
    input_schema={
        "properties": {
            "name": {"type": "string", "description": "Rule name"},
            "description": {"type": "string"},
            "trigger_type": {
                "type": "string",
                "enum": sorted(VALID_TRIGGER_TYPES),
                "description": "What triggers the rule",
            },
            "trigger_config": {
                "type": "object",
                "description": "Trigger configuration (e.g. feed_ids, pattern, min_severity, execution_mode)",
            },
            "conditions": {
                "type": "object",
                "description": "Conditions to check before executing",
            },
            "actions": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Actions to execute, each {type: <action type>, config: {...}}",
            },
        },
        "required": ["name", "trigger_type", "actions"],
    },
)
async def _create_automation_rule(
    db: AsyncSession,
    user_id: uuid.UUID,
    name: str,
    trigger_type: str,
    actions: list,
    description: str | None = None,
    trigger_config: dict | None = None,
    conditions: dict | None = None,
) -> dict:
    if trigger_type not in VALID_TRIGGER_TYPES:
        return {"error": f"invalid trigger_type '{trigger_type}'; valid: {sorted(VALID_TRIGGER_TYPES)}"}
    invalid_actions = [
        (a.get("type") if isinstance(a, dict) else str(a))
        for a in actions
        if not isinstance(a, dict) or a.get("type") not in VALID_ACTION_TYPES
    ]
    if invalid_actions:
        return {
            "error": "invalid action types",
            "invalid_actions": invalid_actions,
            "valid_action_types": sorted(VALID_ACTION_TYPES),
        }
    rule = AutomationRule(
        created_by=user_id,
        name=name,
        description=description,
        trigger_type=trigger_type,
        trigger_config=trigger_config or {},
        conditions=conditions or {},
        actions=actions,
        is_enabled=True,
    )
    db.add(rule)
    await db.flush()
    return {"id": str(rule.id), "created": True, "name": name}


@_tool(
    name="create_intel_report",
    description=(
        "Create a draft intelligence report from a template with linked entities and entries. "
        f"Templates: {', '.join(_REPORT_TEMPLATE_TYPES)}. TLP 2.0 markings; the legacy TLP:WHITE "
        "is accepted and normalized to TLP:CLEAR."
    ),
    input_schema={
        "properties": {
            "title": {"type": "string", "description": "Report title"},
            "template_type": {
                "type": "string",
                "enum": _REPORT_TEMPLATE_TYPES,
            },
            "entry_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Source entry UUIDs",
            },
            "entity_ids": {
                "type": "object",
                "description": "Entity UUIDs by type: {ttps: [...], actors: [...]}",
            },
            "tlp_marking": {
                "type": "string",
                "enum": _TLP_ENUM,
                "default": "TLP:GREEN",
            },
        },
        "required": ["title", "template_type"],
    },
)
async def _create_intel_report(
    db: AsyncSession,
    user_id: uuid.UUID,
    title: str,
    template_type: str,
    entry_ids: list[str] | None = None,
    entity_ids: dict | None = None,
    tlp_marking: str = "TLP:GREEN",
) -> dict:
    from app.intelligence.reporting import generate_report_content

    template_err = _validate_template_type(template_type)
    if template_err:
        return template_err
    tlp_marking, tlp_err = _normalize_tlp_or_error(tlp_marking)
    if tlp_err:
        return tlp_err

    eids = [uuid.UUID(e) for e in (entry_ids or [])]
    content = await generate_report_content(template_type, eids, entity_ids or {}, db)
    report = IntelReport(
        created_by=user_id,
        title=title,
        template_type=template_type,
        tlp_marking=tlp_marking,
        content=content,
        entry_ids=eids,
        entity_ids=entity_ids or {},
        status="draft",
    )
    db.add(report)
    await db.flush()
    return {"id": str(report.id), "created": True, "title": title}


async def _settle_merged(db: AsyncSession, entity_type: str, source_id: uuid.UUID, result) -> None:
    """An applied merge removes the source: close its pending Review proposals."""
    if getattr(result, "applied", False) and getattr(result, "mode", None) == "apply":
        from app.services.proposal_dismissals import settle_gone_entity

        await settle_gone_entity(db, entity_type, source_id, successor=(entity_type, result.target_id))


# Display/identity column per type, for name lookups.
_REF_NAME_COLUMN = {"cve": "cve_id", "ttp": "technique_id", "observable": "value"}


def _ref_model(entity_type: str):
    from app.services.entity_summary import ENTITY_MODEL_MAP

    spec = ENTITY_MODEL_MAP.get(entity_type)
    return spec[0] if spec else None


async def resolve_entity_ref(db: AsyncSession, entity_type: str, ref: str | None):
    """An entity by UUID or by name: exact name (case-insensitive) first, then a
    unique alias. Returns ``(entity, None)`` or ``(None, {"error": ...})``."""
    from sqlalchemy import func

    model = _ref_model(entity_type)
    if model is None:
        return None, {"error": f"unsupported entity_type: {entity_type}"}
    if not ref or not str(ref).strip():
        return None, {"error": "give an entity id or name"}
    ref = str(ref).strip()
    try:
        eid = uuid.UUID(ref)
    except ValueError:
        eid = None
    if eid is not None:
        entity = (await db.execute(select(model).where(model.id == eid))).scalar_one_or_none()
        return (entity, None) if entity else (None, {"error": f"{entity_type} {ref} not found"})
    col = getattr(model, _REF_NAME_COLUMN.get(entity_type, "name"))
    hits = (await db.execute(select(model).where(func.lower(col) == ref.lower()).limit(5))).scalars().all()
    if not hits and hasattr(model, "aliases"):
        lowered = func.lower(func.array_to_string(model.aliases, "\x1f"))
        rows = (await db.execute(select(model).where(lowered.contains(ref.lower())).limit(25))).scalars().all()
        hits = [r for r in rows if ref.lower() in {(a or "").lower() for a in (r.aliases or [])}]
    if len(hits) == 1:
        return hits[0], None
    if not hits:
        return None, {"error": f"no {entity_type} named {ref!r}"}
    return None, {
        "error": f"{ref!r} matches {len(hits)} {entity_type} entities; pass an id",
        "candidates": [{"id": str(h.id), "name": str(getattr(h, col.key))} for h in hits],
    }


_ALIAS_TYPES = ("threat_actor", "malware", "country", "tool", "vendor", "product")


@_tool(
    name="merge_entities",
    description=(
        "Merge duplicate entities of one type into a keeper, by name or id (POST /entities/{type}/merge): entry "
        "links move to the keeper, the merged names and aliases become keeper aliases, and the merged entities "
        "are deleted along with their pending Review proposals (a merge proposal into one of them moves to the "
        "keeper). Names match the entity name first, then a unique alias. Admin only."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": _ALIAS_TYPES},
            "keeper": {"type": "string", "description": "The entity to keep: UUID or name"},
            "merge": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Entities to merge into the keeper: UUIDs or names",
            },
        },
        "required": ["entity_type", "keeper", "merge"],
    },
)
async def _merge_entities_by_ref(
    db: AsyncSession, user_id: uuid.UUID, entity_type: str, keeper: str, merge: list[str]
) -> dict:
    from app.api.entity_profiles import EntityMergeRequest
    from app.api.entity_profiles import merge_entities as _route

    if entity_type not in _ALIAS_TYPES:
        return {"error": f"entity_type must be one of {list(_ALIAS_TYPES)}"}
    keep, err = await resolve_entity_ref(db, entity_type, keeper)
    if err:
        return err
    ids: list[uuid.UUID] = []
    for ref in merge or []:
        ent, err = await resolve_entity_ref(db, entity_type, ref)
        if err:
            return err
        if ent.id != keep.id and ent.id not in ids:
            ids.append(ent.id)
    if not ids:
        return {"error": "nothing to merge (every name resolved to the keeper)"}
    return await _route(
        entity_type=entity_type, body=EntityMergeRequest(keeper_id=keep.id, merge_ids=ids), user=None, db=db
    )


@_tool(
    name="remove_entity_aliases",
    description=(
        "Remove aliases from an entity, by entity name or id. Entries linked only through a removed alias are "
        "unlinked and the stored article count is recounted (the same path as editing aliases on the profile). "
        "Alias matching is case-insensitive. Admin only."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": _ALIAS_TYPES},
            "entity": {"type": "string", "description": "UUID or name of the entity"},
            "aliases": {"type": "array", "items": {"type": "string"}, "description": "Aliases to remove"},
        },
        "required": ["entity_type", "entity", "aliases"],
    },
)
async def _remove_entity_aliases(
    db: AsyncSession, user_id: uuid.UUID, entity_type: str, entity: str, aliases: list[str]
) -> dict:
    from app.api.entity_profiles import _unlink_entries_for_removed_aliases
    from app.intelligence.correlation_cache import invalidate_entity_cache
    from app.services.entity_indexer import index_single_entity
    from app.services.entity_summary import ENTITY_MODEL_MAP

    if entity_type not in _ALIAS_TYPES:
        return {"error": f"entity_type must be one of {list(_ALIAS_TYPES)}"}
    ent, err = await resolve_entity_ref(db, entity_type, entity)
    if err:
        return err
    drop = {(a or "").strip().lower() for a in aliases or [] if (a or "").strip()}
    current = list(ent.aliases or [])
    kept = [a for a in current if (a or "").lower() not in drop]
    removed = [a for a in current if (a or "").lower() in drop]
    if not removed:
        return {"id": str(ent.id), "name": ent.name, "removed": [], "unlinked": 0, "aliases": current}
    _, junction, fk_attr = ENTITY_MODEL_MAP[entity_type]
    unlinked = await _unlink_entries_for_removed_aliases(
        db, current, kept, junction, getattr(junction, fk_attr), ent.id, entity=ent
    )
    ent.aliases = kept
    await db.flush()
    await invalidate_entity_cache(entity_type, str(ent.id))
    await index_single_entity(entity_type, ent)
    return {
        "id": str(ent.id),
        "name": ent.name,
        "removed": removed,
        "unlinked": unlinked,
        "aliases": kept,
        "article_count": getattr(ent, "article_count", None),
    }


@_tool(
    name="merge_threat_actors",
    description=(
        "Merge a duplicate threat actor into another. Moves all entries and country links from source → target, "
        "unions aliases (source.name + source.aliases get added to target.aliases), optionally updates the "
        "description, then deletes the source actor. Set mode='shadow' to log what would happen without making "
        "changes. ALWAYS supply 'reasoning' so the maintenance log can be audited."
    ),
    input_schema={
        "properties": {
            "target_id": {"type": "string", "description": "Surviving actor UUID."},
            "source_id": {
                "type": "string",
                "description": "Actor to merge away (deleted at the end).",
            },
            "mode": {"type": "string", "enum": ["shadow", "apply"], "default": "apply"},
            "new_description": {
                "type": "string",
                "description": "Replace target description. Omit to leave existing.",
            },
            "extra_aliases": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
            },
            "reasoning": {
                "type": "string",
                "description": "Why this merge — recorded in the maintenance log.",
            },
        },
        "required": ["target_id", "source_id"],
    },
)
async def _merge_threat_actors(
    db: AsyncSession,
    user_id: uuid.UUID,
    target_id: str,
    source_id: str,
    mode: str = "apply",
    new_description: str | None = None,
    extra_aliases: list[str] | None = None,
    reasoning: str | None = None,
) -> dict:
    from app.api.entity_merge import MergeRequest, perform_actor_merge

    body = MergeRequest(
        source_id=uuid.UUID(source_id),
        mode=mode,  # type: ignore[arg-type]
        new_description=new_description,
        extra_aliases=extra_aliases or [],
        reasoning=reasoning,
    )
    result = await perform_actor_merge(db, uuid.UUID(target_id), body)
    await _settle_merged(db, "threat_actor", body.source_id, result)
    return result.model_dump(mode="json")


@_tool(
    name="reclassify_entity",
    description=(
        "Move an entity from one type to another (cross-type) when it was filed under the wrong type — e.g. a "
        "malware that's actually a tool, or a product mistakenly stored as a vendor. "
        "Supports " + " / ".join(sorted(entity_types.RECLASSIFIABLE)) + ". If target_id is given, the "
        "source is merged into that existing entity in the target type; if omitted, a new entity is created in "
        "target_type by copying name/aliases/description, unless target_type already has an entity of the same "
        "name, which it is merged into. Name the source by source_id or source_name (and the target by "
        "target_id or target_name). Type-specific fields (motivation, malware_type, "
        "vendor_id, tool_type, etc.) are NOT carried across — fix them after with update_entity_profile. "
        "The source's pending Review proposals are closed. "
        "Use mode='shadow' to log without acting; always include reasoning."
    ),
    input_schema={
        "properties": {
            "source_type": {
                "type": "string",
                "enum": sorted(entity_types.RECLASSIFIABLE),
            },
            "source_id": {"type": "string", "description": "Source entity UUID (or give source_name)."},
            "source_name": {"type": "string", "description": "Source entity name or alias, instead of source_id."},
            "target_type": {
                "type": "string",
                "enum": sorted(entity_types.RECLASSIFIABLE),
            },
            "target_id": {
                "type": "string",
                "description": "Optional: existing target entity to merge into. Omit to use the same-named "
                "target entity, or create a new one.",
            },
            "target_name": {"type": "string", "description": "Optional: existing target entity by name or alias."},
            "mode": {"type": "string", "enum": ["shadow", "apply"], "default": "apply"},
            "new_description": {"type": "string"},
            "extra_aliases": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
            },
            "reasoning": {"type": "string"},
        },
        "required": ["source_type", "target_type"],
    },
)
async def _reclassify_entity(
    db: AsyncSession,
    user_id: uuid.UUID,
    source_type: str,
    target_type: str,
    source_id: str | None = None,
    source_name: str | None = None,
    target_id: str | None = None,
    target_name: str | None = None,
    mode: str = "apply",
    new_description: str | None = None,
    extra_aliases: list[str] | None = None,
    reasoning: str | None = None,
) -> dict:
    from sqlalchemy import func

    from app.api.entity_merge import ReclassifyRequest, perform_reclassify
    from app.services.proposal_dismissals import settle_gone_entity

    source, err = await resolve_entity_ref(db, source_type, source_id or source_name)
    if err:
        return err
    target_uuid = None
    if target_id or target_name:
        target, err = await resolve_entity_ref(db, target_type, target_id or target_name)
        if err:
            return err
        target_uuid = target.id
    else:
        # The Review queue's rule: the same-named entity of the target type absorbs it.
        tmodel = _ref_model(target_type)
        if tmodel is not None:
            target_uuid = (
                await db.execute(select(tmodel.id).where(func.lower(tmodel.name) == source.name.lower()).limit(1))
            ).scalar_one_or_none()

    body = ReclassifyRequest(
        source_type=source_type,
        source_id=source.id,
        target_type=target_type,
        target_id=target_uuid,
        mode=mode,  # type: ignore[arg-type]
        new_description=new_description,
        extra_aliases=extra_aliases or [],
        reasoning=reasoning,
    )
    result = await perform_reclassify(db, body)
    if result.applied and result.mode == "apply":
        await settle_gone_entity(
            db, result.source_type, result.source_id, successor=(result.target_type, result.target_id)
        )
    return result.model_dump(mode="json")


@_tool(
    name="merge_vendors",
    description=(
        "Merge a duplicate vendor into another. Same semantics as merge_threat_actors. Moves all entries, unions "
        "aliases, optionally rewrites description, then deletes the source. Always include reasoning."
    ),
    input_schema={
        "properties": {
            "target_id": {"type": "string"},
            "source_id": {"type": "string"},
            "mode": {"type": "string", "enum": ["shadow", "apply"], "default": "apply"},
            "new_description": {"type": "string"},
            "extra_aliases": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
            },
            "reasoning": {"type": "string"},
        },
        "required": ["target_id", "source_id"],
    },
)
async def _merge_vendors(
    db: AsyncSession,
    user_id: uuid.UUID,
    target_id: str,
    source_id: str,
    mode: str = "apply",
    new_description: str | None = None,
    extra_aliases: list[str] | None = None,
    reasoning: str | None = None,
) -> dict:
    # Same-type vendor/product/tool merges piggyback on perform_reclassify with
    # source_type == target_type — but ReclassifyRequest rejects same-type. So
    # we use a small helper that mirrors the actor/malware merge primitives.
    from app.api.entity_merge import perform_same_type_merge

    result = await perform_same_type_merge(
        db,
        entity_type="vendor",
        target_id=uuid.UUID(target_id),
        source_id=uuid.UUID(source_id),
        mode=mode,
        new_description=new_description,
        extra_aliases=extra_aliases or [],
        reasoning=reasoning,
    )
    await _settle_merged(db, "vendor", uuid.UUID(source_id), result)
    return result.model_dump(mode="json")


@_tool(
    name="merge_products",
    description="Merge a duplicate product into another. Same semantics as merge_vendors.",
    input_schema={
        "properties": {
            "target_id": {"type": "string"},
            "source_id": {"type": "string"},
            "mode": {"type": "string", "enum": ["shadow", "apply"], "default": "apply"},
            "new_description": {"type": "string"},
            "extra_aliases": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
            },
            "reasoning": {"type": "string"},
        },
        "required": ["target_id", "source_id"],
    },
)
async def _merge_products(
    db: AsyncSession,
    user_id: uuid.UUID,
    target_id: str,
    source_id: str,
    mode: str = "apply",
    new_description: str | None = None,
    extra_aliases: list[str] | None = None,
    reasoning: str | None = None,
) -> dict:
    from app.api.entity_merge import perform_same_type_merge

    result = await perform_same_type_merge(
        db,
        entity_type="product",
        target_id=uuid.UUID(target_id),
        source_id=uuid.UUID(source_id),
        mode=mode,
        new_description=new_description,
        extra_aliases=extra_aliases or [],
        reasoning=reasoning,
    )
    await _settle_merged(db, "product", uuid.UUID(source_id), result)
    return result.model_dump(mode="json")


@_tool(
    name="merge_tools",
    description="Merge a duplicate tool into another. Same semantics as merge_vendors.",
    input_schema={
        "properties": {
            "target_id": {"type": "string"},
            "source_id": {"type": "string"},
            "mode": {"type": "string", "enum": ["shadow", "apply"], "default": "apply"},
            "new_description": {"type": "string"},
            "extra_aliases": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
            },
            "reasoning": {"type": "string"},
        },
        "required": ["target_id", "source_id"],
    },
)
async def _merge_tools(
    db: AsyncSession,
    user_id: uuid.UUID,
    target_id: str,
    source_id: str,
    mode: str = "apply",
    new_description: str | None = None,
    extra_aliases: list[str] | None = None,
    reasoning: str | None = None,
) -> dict:
    from app.api.entity_merge import perform_same_type_merge

    result = await perform_same_type_merge(
        db,
        entity_type="tool",
        target_id=uuid.UUID(target_id),
        source_id=uuid.UUID(source_id),
        mode=mode,
        new_description=new_description,
        extra_aliases=extra_aliases or [],
        reasoning=reasoning,
    )
    await _settle_merged(db, "tool", uuid.UUID(source_id), result)
    return result.model_dump(mode="json")


@_tool(
    name="merge_malware",
    description=(
        "Merge a duplicate malware family into another. Same semantics as merge_threat_actors but for malware. "
        "Use mode='shadow' for dry-run; always include 'reasoning'."
    ),
    input_schema={
        "properties": {
            "target_id": {"type": "string", "description": "Surviving malware UUID."},
            "source_id": {"type": "string", "description": "Malware to merge away."},
            "mode": {"type": "string", "enum": ["shadow", "apply"], "default": "apply"},
            "new_description": {"type": "string"},
            "extra_aliases": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
            },
            "reasoning": {"type": "string"},
        },
        "required": ["target_id", "source_id"],
    },
)
async def _merge_malware(
    db: AsyncSession,
    user_id: uuid.UUID,
    target_id: str,
    source_id: str,
    mode: str = "apply",
    new_description: str | None = None,
    extra_aliases: list[str] | None = None,
    reasoning: str | None = None,
) -> dict:
    from app.api.entity_merge import MergeRequest, perform_malware_merge

    body = MergeRequest(
        source_id=uuid.UUID(source_id),
        mode=mode,  # type: ignore[arg-type]
        new_description=new_description,
        extra_aliases=extra_aliases or [],
        reasoning=reasoning,
    )
    result = await perform_malware_merge(db, uuid.UUID(target_id), body)
    await _settle_merged(db, "malware", body.source_id, result)
    return result.model_dump(mode="json")


# Per-type editable fields — mirrors the field lists of the canonical PUT
# endpoints in app/api/entity_profiles.py (and campaigns for "campaign").
_PROFILE_SAFE_FIELDS: dict[str, set[str]] = {
    "threat_actor": {"name", "aliases", "description", "mitre_id", "country", "motivation"},
    "malware": {"name", "aliases", "description", "malpedia_url", "malware_type"},
    "cve": {"description", "severity", "exploit_status", "affected_products", "exploit_availability"},
    "ttp": {"technique_name", "tactic", "description"},
    "country": {"name", "iso_code", "aliases", "region", "description"},
    # Closed vocabulary: the name and slug are the vocabulary itself.
    "sector": {"aliases", "description"},
    "tool": {"name", "aliases", "description", "tool_type", "malpedia_url", "github_url"},
    "vendor": {"name", "aliases", "description", "website", "vendor_type"},
    "product": {"name", "aliases", "description", "product_type", "website", "vendor_id"},
    "campaign": {"name", "description", "status", "tags", "tlp_marking"},
}

# Types whose name column carries a uniqueness guarantee — renames run the
# same clash guard the API uses (_assert_name_available).
_NAME_GUARDED_TYPES = frozenset({"threat_actor", "malware", "country", "tool", "vendor", "product"})


@_tool(
    name="update_entity_profile",
    description=(
        "Update an entity's profile. Supports every profile type with per-type editable fields: "
        "threat_actor (name/aliases/description/mitre_id/country/motivation), malware (name/aliases/"
        "description/malpedia_url/malware_type), cve (description/severity/exploit_status/"
        "affected_products/exploit_availability), ttp (technique_name/tactic/description), country "
        "(name/iso_code/aliases/region/description), sector (aliases/description), tool (name/aliases/"
        "description/tool_type/malpedia_url/github_url), vendor (name/aliases/description/website/"
        "vendor_type), product (name/aliases/description/product_type/website/vendor_id), campaign "
        "(name/description/status/"
        "tags/tlp_marking). Renames are checked for name clashes; removing aliases unlinks entries "
        "matched only via those aliases; new aliases queue a retro-scan of existing entries; the "
        "search-index document is refreshed."
    ),
    input_schema={
        "properties": {
            "entity_type": {
                "type": "string",
                "enum": sorted(_PROFILE_SAFE_FIELDS),
            },
            "entity_id": {"type": "string", "description": "Entity UUID"},
            "updates": {
                "type": "object",
                "description": "Fields to update (e.g. {description: '...', aliases: [...]})",
            },
        },
        "required": ["entity_type", "entity_id", "updates"],
    },
)
async def _update_entity_profile(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_id: str,
    updates: dict,
) -> dict:
    from app.api.entity_profiles import (
        ENTITY_MODEL_MAP,
        _assert_name_available,
        _unlink_entries_for_removed_aliases,
    )
    from app.core.exceptions import AppError
    from app.intelligence.correlation_cache import invalidate_entity_cache
    from app.services.entity_indexer import index_single_entity

    entity_type = entity_types.normalize_entity_type(entity_type)
    safe_fields = _PROFILE_SAFE_FIELDS.get(entity_type)
    if not safe_fields:
        return {"error": f"Unsupported entity type: {entity_type}; valid: {sorted(_PROFILE_SAFE_FIELDS)}"}

    if entity_type == "campaign":
        model, junction, fk_attr = Campaign, None, None
    else:
        model, junction, fk_attr = ENTITY_MODEL_MAP[entity_type]
    if entity_type == "sector":
        # Sectors are never autolinked, so no entry was ever matched *via* an
        # alias — there is nothing to unlink when one is removed.
        junction, fk_attr = None, None

    eid = uuid.UUID(entity_id)
    result = await db.execute(select(model).where(model.id == eid))
    entity = result.scalar_one_or_none()
    if not entity:
        return {"error": f"{entity_type} not found"}

    # Renames run the same uniqueness guard the API uses (unique-name tables).
    new_name = updates.get("name")
    if (
        entity_type in _NAME_GUARDED_TYPES
        and isinstance(new_name, str)
        and new_name.strip().lower() != (entity.name or "").lower()
    ):
        try:
            await _assert_name_available(db, model, new_name, eid)
        except AppError as exc:
            return {"error": exc.message}

    # Campaign TLP updates go through the shared TLP normalizer.
    if entity_type == "campaign" and "tlp_marking" in updates:
        tlp, tlp_err = _normalize_tlp_or_error(updates["tlp_marking"])
        if tlp_err:
            return tlp_err
        updates = {**updates, "tlp_marking": tlp}

    # Removing aliases unlinks entries matched only via those aliases (API parity).
    original_aliases = list(getattr(entity, "aliases", None) or [])
    if junction is not None and "aliases" in updates and updates["aliases"] is not None:
        await _unlink_entries_for_removed_aliases(
            db,
            original_aliases,
            updates["aliases"],
            junction,
            getattr(junction, fk_attr),
            eid,
        )

    updated = []
    for key, value in updates.items():
        if key in safe_fields and hasattr(entity, key):
            if key == "vendor_id" and value is not None:
                value = uuid.UUID(str(value))
            setattr(entity, key, value)
            updated.append(key)

    # Analyst-set exploit status is provenance-tracked so enrichment won't clobber it.
    if entity_type == "cve" and ({"exploit_status", "exploit_availability"} & set(updated)):
        entity.exploit_status_source = "manual"
        updated.append("exploit_status_source")

    await db.flush()
    await invalidate_entity_cache(entity_type, entity_id)
    await index_single_entity(entity_type, entity)

    # Newly added aliases widen the match surface — retro-scan existing entries.
    # Types with no autolinker vocabulary (campaign) are dropped by the dispatcher.
    if "aliases" in updated:
        dispatch_backlink_for_added_aliases(entity_type, entity.id, original_aliases, entity.aliases)

    return {"updated": True, "entity_type": entity_type, "fields_updated": updated}


# --- New tools (post-March 2026) ---


@_tool(
    name="create_requirement",
    description="Create a new Priority Intelligence Requirement (PIR).",
    input_schema={
        "properties": {
            "title": {"type": "string", "description": "Requirement title"},
            "description": {
                "type": "string",
                "description": "What intelligence is needed and why",
            },
            "priority": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low"],
                "default": "medium",
            },
            "category": {
                "type": "string",
                "enum": ["strategic", "operational", "tactical", "technical"],
                "default": "operational",
            },
            "keywords": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Keywords to match against articles",
            },
            "auto_match": {
                "type": "boolean",
                "default": True,
                "description": "Automatically match new articles to this requirement",
            },
        },
        "required": ["title", "keywords"],
    },
)
async def _create_requirement(
    db: AsyncSession,
    user_id: uuid.UUID,
    title: str,
    keywords: list[str],
    description: str | None = None,
    priority: str = "medium",
    category: str | None = None,
    auto_match: bool = True,
) -> dict:
    req = IntelligenceRequirement(
        created_by=user_id,
        title=title,
        description=description,
        priority=priority,
        status="active",
        category=category or "operational",
        keywords=keywords,
        auto_match=auto_match,
        match_count=0,
    )
    db.add(req)
    await db.flush()
    return {"id": str(req.id), "created": True, "title": title}


@_tool(
    name="update_requirement",
    description="Update an existing intelligence requirement (keywords, status, priority, etc.).",
    input_schema={
        "properties": {
            "requirement_id": {"type": "string", "description": "Requirement UUID"},
            "updates": {
                "type": "object",
                "description": "Fields to update: title, description, keywords, priority, status, category, auto_match",
            },
        },
        "required": ["requirement_id", "updates"],
    },
)
async def _update_requirement(db: AsyncSession, user_id: uuid.UUID, requirement_id: str, updates: dict) -> dict:
    rid = uuid.UUID(requirement_id)
    result = await db.execute(select(IntelligenceRequirement).where(IntelligenceRequirement.id == rid))
    req = result.scalar_one_or_none()
    if not req:
        return {"error": "Requirement not found"}

    safe_fields = {
        "title",
        "description",
        "keywords",
        "priority",
        "status",
        "category",
        "auto_match",
    }
    updated = []
    for key, value in updates.items():
        if key in safe_fields and hasattr(req, key):
            setattr(req, key, value)
            updated.append(key)

    await db.flush()
    return {
        "updated": True,
        "requirement_id": requirement_id,
        "fields_updated": updated,
    }


@_tool(
    name="test_automation_rule",
    description="Dry-run an automation rule against an entry to see what would happen without executing actions.",
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "Automation rule UUID"},
            "entry_id": {"type": "string", "description": "Entry UUID to test against"},
        },
        "required": ["rule_id", "entry_id"],
    },
)
async def _test_automation_rule(db: AsyncSession, user_id: uuid.UUID, rule_id: str, entry_id: str) -> dict:
    from app.automation.engine import execute_automation
    from app.models.entry import Entry

    rid = uuid.UUID(rule_id)
    rule_q = await db.execute(select(AutomationRule).where(AutomationRule.id == rid))
    rule = rule_q.scalar_one_or_none()
    if not rule:
        return {"error": "Rule not found"}

    eid = uuid.UUID(entry_id)
    entry_q = await db.execute(select(Entry).where(Entry.id == eid))
    entry = entry_q.scalar_one_or_none()
    if not entry:
        return {"error": "Entry not found"}

    log = await execute_automation(db, entry, rule, dry_run=True)
    return {
        "dry_run": True,
        "rule_name": rule.name,
        "status": log.status,
        "actions_executed": log.actions_executed,
        "error_message": log.error_message,
    }


@_tool(
    name="run_automation_rule",
    description=(
        "Execute an automation rule immediately, once per matching recent entry. Trigger-level "
        "filters (keyword pattern, CVE severity) and rule conditions are applied first; only "
        "entries whose actions actually ran count as matched. WARNING: this executes actions "
        "PER ENTRY — never use it to test batch/briefing rules (it will flood one briefing per "
        "entry); use test_automation_rule (dry-run) or the rule's schedule instead."
    ),
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "Automation rule UUID"},
            "hours": {
                "type": "integer",
                "default": 24,
                "description": "How many hours back to look for entries",
            },
        },
        "required": ["rule_id"],
    },
)
async def _run_automation_rule(db: AsyncSession, user_id: uuid.UUID, rule_id: str, hours: int = 24) -> dict:
    from datetime import timedelta

    from app.automation.engine import (
        _check_cve_trigger,
        _check_keyword_trigger,
        _enrich_entry_feed_type,
        execute_automation,
    )
    from app.models.entry import Entry

    rid = uuid.UUID(rule_id)
    rule_q = await db.execute(select(AutomationRule).where(AutomationRule.id == rid))
    rule = rule_q.scalar_one_or_none()
    if not rule:
        return {"error": "Rule not found"}

    since = datetime.now(UTC) - timedelta(hours=hours)
    entries_q = await db.execute(
        select(Entry).where(Entry.fetched_at >= since).order_by(Entry.fetched_at.desc()).limit(100)
    )
    entries = entries_q.scalars().all()

    # Apply trigger-level filters first (mirrors the run-now API endpoint), then
    # execute. The engine evaluates rule conditions itself and bumps run_count /
    # last_triggered_at per successful execution — no extra bump here.
    succeeded = 0
    skipped = 0
    errors = 0
    for entry in entries:
        try:
            await _enrich_entry_feed_type(db, entry)
            should_fire = True
            if rule.trigger_type == "on_keyword_match":
                should_fire = _check_keyword_trigger(entry, rule.trigger_config or {})
            elif rule.trigger_type == "on_cve_detected":
                should_fire = await _check_cve_trigger(db, entry, rule.trigger_config or {})
            if not should_fire:
                continue
            log = await execute_automation(db, entry, rule)
            if log.status == "success":
                succeeded += 1
            elif log.status == "skipped":
                skipped += 1
            else:
                errors += 1
        except Exception:
            errors += 1

    return {
        "rule_name": rule.name,
        "entries_scanned": len(entries),
        "entries_matched": succeeded,
        "entries_skipped_by_conditions": skipped,
        "entries_errored": errors,
    }


@_tool(
    name="publish_report",
    description="Publish an intelligence report — saves current version and sets status to published.",
    input_schema={
        "properties": {
            "report_id": {"type": "string", "description": "Report UUID"},
        },
        "required": ["report_id"],
    },
)
async def _publish_report(db: AsyncSession, user_id: uuid.UUID, report_id: str) -> dict:
    from app.models.intel_report import IntelReportVersion

    rid = uuid.UUID(report_id)
    result = await db.execute(select(IntelReport).where(IntelReport.id == rid))
    report = result.scalar_one_or_none()
    if not report:
        return {"error": "Report not found"}
    if report.status == "published":
        return {"error": "Report is already published"}

    version = IntelReportVersion(
        report_id=report.id,
        version=report.version,
        content=report.content,
        change_description="Published",
        created_by=user_id,
    )
    db.add(version)
    report.version = (report.version or 0) + 1
    report.status = "published"
    report.published_at = datetime.now(UTC)
    await db.flush()
    return {"published": True, "report_id": report_id, "version": report.version}


@_tool(
    name="generate_full_report",
    description=(
        "Generate an AI-powered intelligence report from source entries (created as a draft, then "
        f"AI generation is queued via Celery). Templates: {', '.join(_REPORT_TEMPLATE_TYPES)}. "
        "TLP 2.0 markings; legacy TLP:WHITE is normalized to TLP:CLEAR."
    ),
    input_schema={
        "properties": {
            "title": {"type": "string", "description": "Report title"},
            "template_type": {
                "type": "string",
                "enum": _REPORT_TEMPLATE_TYPES,
            },
            "entry_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Source entry UUIDs",
            },
            "focus": {
                "type": "string",
                "description": "What the report should focus on",
            },
            "tlp_marking": {
                "type": "string",
                "enum": _TLP_ENUM,
                "default": "TLP:GREEN",
            },
        },
        "required": ["title", "template_type", "entry_ids"],
    },
)
async def _generate_full_report(
    db: AsyncSession,
    user_id: uuid.UUID,
    title: str,
    template_type: str,
    entry_ids: list[str],
    focus: str | None = None,
    tlp_marking: str = "TLP:GREEN",
) -> dict:
    from app.intelligence.reporting import generate_report_content

    template_err = _validate_template_type(template_type)
    if template_err:
        return template_err
    tlp_marking, tlp_err = _normalize_tlp_or_error(tlp_marking)
    if tlp_err:
        return tlp_err

    eids = [uuid.UUID(e) for e in entry_ids]
    content = await generate_report_content(template_type, eids, {}, db)
    report = IntelReport(
        created_by=user_id,
        title=title,
        template_type=template_type,
        tlp_marking=tlp_marking,
        content=content,
        entry_ids=eids,
        entity_ids={},
        status="draft",
    )
    db.add(report)
    await db.flush()

    # Queue AI generation
    from app.ai.engine import SiteAllowanceExceeded, UserKeyRequired, derive_caller, preflight_report

    try:
        await preflight_report(db, await derive_caller(db, user_id), report.template_type)
        from app.workers.report_tasks import generate_full_report

        generate_full_report.delay(str(report.id), str(user_id))
        ai_status = "queued"
    except (SiteAllowanceExceeded, UserKeyRequired) as e:
        # The report row stands; what is refused is today's generation.
        ai_status = f"refused: {e.message}"
    except Exception:
        ai_status = "not_available"

    return {
        "id": str(report.id),
        "created": True,
        "title": title,
        "ai_status": ai_status,
    }


@_tool(
    name="generate_campaign_report",
    description=(
        "Generate an intelligence report from a campaign's linked entries and entities (draft + "
        f"queued AI generation). Templates: {', '.join(_REPORT_TEMPLATE_TYPES)} (default "
        "campaign_tracker). TLP 2.0 markings; legacy TLP:WHITE is normalized to TLP:CLEAR."
    ),
    input_schema={
        "properties": {
            "campaign_id": {"type": "string", "description": "Campaign UUID"},
            "template_type": {
                "type": "string",
                "enum": _REPORT_TEMPLATE_TYPES,
                "default": "campaign_tracker",
            },
            "title": {
                "type": "string",
                "description": "Report title (defaults to campaign name)",
            },
            "tlp_marking": {
                "type": "string",
                "enum": _TLP_ENUM,
                "default": "TLP:GREEN",
            },
        },
        "required": ["campaign_id"],
    },
)
async def _generate_campaign_report(
    db: AsyncSession,
    user_id: uuid.UUID,
    campaign_id: str,
    template_type: str = "campaign_tracker",
    title: str | None = None,
    tlp_marking: str = "TLP:GREEN",
) -> dict:
    from app.intelligence.reporting import generate_report_content
    from app.models.campaign import CampaignEntity, CampaignEntry

    template_err = _validate_template_type(template_type)
    if template_err:
        return template_err
    tlp_marking, tlp_err = _normalize_tlp_or_error(tlp_marking)
    if tlp_err:
        return tlp_err

    cid = uuid.UUID(campaign_id)
    campaign_q = await db.execute(select(Campaign).where(Campaign.id == cid))
    campaign = campaign_q.scalar_one_or_none()
    if not campaign:
        return {"error": "Campaign not found"}

    # Get entry IDs
    entries_q = await db.execute(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == cid))
    entry_ids = [row[0] for row in entries_q]

    # Get entity IDs grouped by type
    entities_q = await db.execute(select(CampaignEntity).where(CampaignEntity.campaign_id == cid))
    entity_ids = {}
    type_map = {
        "ttp": "ttps",
        "cve": "cves",
        "threat_actor": "actors",
        "malware": "malware",
    }
    for e in entities_q.scalars():
        key = type_map.get(e.entity_type, e.entity_type)
        entity_ids.setdefault(key, []).append(str(e.entity_id))

    report_title = title or f"Campaign Report: {campaign.name}"
    content = await generate_report_content(template_type, entry_ids, entity_ids, db)
    report = IntelReport(
        created_by=user_id,
        title=report_title,
        template_type=template_type,
        tlp_marking=tlp_marking,
        content=content,
        entry_ids=entry_ids,
        entity_ids=entity_ids,
        status="draft",
    )
    db.add(report)
    await db.flush()

    from app.ai.engine import SiteAllowanceExceeded, UserKeyRequired, derive_caller, preflight_report

    try:
        await preflight_report(db, await derive_caller(db, user_id), report.template_type)
        from app.workers.report_tasks import generate_full_report

        generate_full_report.delay(str(report.id), str(user_id))
        ai_status = "queued"
    except (SiteAllowanceExceeded, UserKeyRequired) as e:
        # The report row stands; what is refused is today's generation.
        ai_status = f"refused: {e.message}"
    except Exception:
        ai_status = "not_available"

    return {
        "id": str(report.id),
        "created": True,
        "title": report_title,
        "ai_status": ai_status,
    }


@_tool(
    name="export_report",
    description="Export an intelligence report in markdown or HTML format.",
    input_schema={
        "properties": {
            "report_id": {"type": "string", "description": "Report UUID"},
            "format": {
                "type": "string",
                "enum": ["markdown", "html"],
                "description": "Export format",
            },
        },
        "required": ["report_id", "format"],
    },
)
async def _export_report(db: AsyncSession, user_id: uuid.UUID, report_id: str, format: str) -> dict:
    rid = uuid.UUID(report_id)
    result = await db.execute(select(IntelReport).where(IntelReport.id == rid))
    report = result.scalar_one_or_none()
    if not report:
        return {"error": "Report not found"}

    from app.intelligence.reporting import render_html, render_markdown

    if format == "markdown":
        return {"format": "markdown", "content": render_markdown(report)}
    elif format == "html":
        return {"format": "html", "content": render_html(report)}
    return {"error": f"Unknown format: {format}"}
