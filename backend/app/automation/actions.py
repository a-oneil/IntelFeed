"""Action execution for automation rules.

Actions execute sequentially and share a context dict. Earlier actions
can store outputs (e.g. AI summaries) that later actions reference.
Context keys:
  - ai_summary: str — AI-generated summary from run_ai_task(summarization)
  - ai_results: dict[task_name, parsed_result] — all AI task outputs
  - tags_added: list[str] — tags added so far

Batch mode:
  When running scheduled or manual "Run Now" rules against multiple entries,
  actions are split into two phases:
    1. Per-entry actions (extract, tag, AI, etc.) run on each entry individually
    2. Batch actions (send_notification, run_webhook) run once with all entries
  This prevents sending N notifications for N entries — instead a single digest
  notification is sent.
"""

import asyncio
import logging
import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.caller import Caller, caller_scope
from app.automation.variables import BATCH_ENTRY_FIELDS, PER_ENTRY_FIELDS
from app.models.entry import Entry
from app.models.entry_state import UserEntryState
from app.models.note import Note
from app.models.tag import EntryTag, Tag
from app.services.entry_tags import MissingOwner, ensure_assignment, sync_entry_tags_to_search, visible_to

logger = logging.getLogger(__name__)


async def _validate_webhook_url(url: str) -> str | None:
    """Why a webhook must not be called, or None. Resolves the hostname: a
    name that points at the LAN is the attack, not the literal address."""
    from app.config import settings
    from app.core.outbound import check_outbound_url

    return await check_outbound_url(url, allow_private=settings.webhook_allow_private_networks)


def _webhook_client(**kwargs):
    """The client every webhook is sent with. _validate_webhook_url gives the
    user a readable refusal up front; this enforces the same rule on the
    connection itself, so a hostname that re-resolves after the check (DNS
    rebinding) cannot land the POST somewhere else. Redirects are not followed."""
    from app.config import settings
    from app.core.safe_http import safe_async_client

    return safe_async_client(allow_private=settings.webhook_allow_private_networks, **kwargs)


async def observable_template_context(db: AsyncSession, entry: Entry) -> dict:
    """``{observables_count}`` / ``{observables}`` for notification templates:
    the entry's captured observables sighted by a reporting door (the
    indicator-feed door is excluded — a blocklist mirror is not news),
    defanged, one per line as ``kind value (role)``."""
    from app.intelligence.observables import defang
    from app.models.observable import EntryObservable, Observable

    rows = (
        (
            await db.execute(
                select(Observable)
                .join(EntryObservable, EntryObservable.observable_id == Observable.id)
                .where(
                    EntryObservable.entry_id == entry.id,
                    EntryObservable.source != "feed",
                    Observable.is_denied.is_(False),
                )
                .order_by(Observable.kind, Observable.value)
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    lines = [f"{o.kind} {defang(o.kind, o.value)}" + (f" ({o.role})" if o.role else "") for o in rows]
    return {"observables_count": len(rows), "observables": "\n".join(lines)}


def _render_template(template: str, entry: Entry, context: dict | None = None) -> str:
    """Render a message template with entry and context variables.

    Supported variables are the single-brace ({ }) set declared in
    ``variables.NOTIFICATION_TEMPLATE_FIELDS``:
      {title}, {url}, {author}, {summary}, {published_at},
      {ai_summary}, {feed_name}
    """
    ctx = context or {}
    ai_summary = ctx.get("ai_summary", "")
    summary = ai_summary or (entry.summary or "")[:500]

    replacements = {
        "title": entry.title or "Untitled",
        "url": entry.url or "",
        "author": entry.author or "Unknown",
        "summary": summary,
        "published_at": str(entry.published_at) if entry.published_at else "",
        "ai_summary": ai_summary or "",
        "feed_name": getattr(entry, "_feed_title", "") or "",
        # Seeded by execute_automation (observable_template_context) so a
        # "new C2 captured" rule can name the indicators in its message.
        "observables_count": str(ctx.get("observables_count", "")),
        "observables": ctx.get("observables", "") or "",
    }

    result = template
    for key, value in replacements.items():
        result = result.replace(f"{{{key}}}", str(value))
    return result


# Keys an AI task result may carry its main text under. `raw` covers
# schema-less tasks — the engine stores their free-form (non-JSON) output as
# {"raw": "..."}, so without it a custom briefing's {ai_summary} renders empty.
_SUMMARY_TEXT_KEYS = (
    "summary",
    "text",
    "briefing",
    "report",
    "raw",
    "markdown",
    "content",
    "output",
    "body",
)


def _extract_summary_text(parsed: dict) -> str:
    """Best-effort extraction of an AI task's main text output for notification
    and webhook templates ({ai_summary})."""
    for key in _SUMMARY_TEXT_KEYS:
        val = parsed.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return ""


def _entry_app_url(entry_id) -> str:
    """In-app reader deep link for an entry. Absolute when PUBLIC_BASE_URL is
    configured (so the link works in Discord/Slack), otherwise relative."""
    from app.config import settings

    base = (settings.public_base_url or "").rstrip("/")
    return f"{base}/?entry={entry_id}" if base else f"/?entry={entry_id}"


_REL_ENTRY_LINK_RE = re.compile(r"\((/\?entry=[0-9a-fA-F-]{36})\)")


def _absolutize_app_links(text: str) -> str:
    """Make relative in-app reader links usable outside the app.

    The daily briefing links articles as ``(/?entry=<id>)``, which resolves fine
    in the SPA and nowhere else. When a rule chooses to keep app links in an
    outbound post, at least give them the public origin.
    """
    from app.config import settings

    base = (settings.public_base_url or "").rstrip("/")
    if not base or not text:
        return text or ""
    return _REL_ENTRY_LINK_RE.sub(lambda m: f"({base}{m.group(1)})", text)


def _render_template_json_safe(template: str, entry: Entry, context: dict | None = None) -> str:
    """Like _render_template but escapes values for safe embedding in JSON strings."""
    import json as _json

    ctx = context or {}
    ai_summary = ctx.get("ai_summary", "")
    summary = ai_summary or (entry.summary or "")[:500]

    replacements = {
        "title": entry.title or "Untitled",
        "url": entry.url or "",
        "author": entry.author or "Unknown",
        "summary": summary,
        "published_at": str(entry.published_at) if entry.published_at else "",
        "ai_summary": ai_summary or "",
        "feed_name": getattr(entry, "_feed_title", "") or "",
    }

    result = template
    for key, value in replacements.items():
        # json.dumps adds surrounding quotes — strip them to get the escaped interior
        escaped = _json.dumps(str(value))[1:-1]
        result = result.replace(f"{{{key}}}", escaped)
    return result


async def execute_action(
    db: AsyncSession,
    entry: Entry,
    action: dict,
    user_id: uuid.UUID,
    context: dict | None = None,
) -> dict:
    """Execute a single automation action against an entry, as automation.

    The rule's author is ``user_id``, but nothing in here is the author
    clicking: every AI call beneath this frame defaults to an automation
    caller, so a new action can't bill a personal key by omission.
    """
    with caller_scope(Caller.automation(user_id)):
        return await _execute_action(db, entry, action, user_id, context)


async def _execute_action(
    db: AsyncSession,
    entry: Entry,
    action: dict,
    user_id: uuid.UUID,
    context: dict | None = None,
) -> dict:
    """Execute a single automation action against an entry.

    Args:
        context: Shared mutable dict that flows between actions in a rule.
                 Earlier actions write outputs here; later actions can read them.

    Returns a result dict with action type, status, and details.
    """
    if context is None:
        context = {}

    action_type = action.get("type", "")
    config = action.get("config", {})

    try:
        match action_type:
            case "run_ai_task":
                result = await _action_run_ai_task(db, entry, config, user_id, context)
            case "add_tags":
                result = await _action_add_tags(db, entry, config, user_id)
            case "remove_tags":
                result = await _action_remove_tags(db, entry, config, user_id)
            case "send_notification":
                result = await _action_send_notification(entry, config, context)
            case "run_webhook":
                result = await _action_run_webhook(entry, config, context)
            case "mark_priority":
                result = await _action_mark_priority(db, entry, config, user_id)
            case "mark_read":
                result = await _action_mark_read(db, entry, user_id)
            case "star_entry":
                result = await _action_star_entry(db, entry, user_id)
            case "bookmark_entry":
                result = await _action_bookmark_entry(db, entry, user_id)
            case "hide_entry":
                result = await _action_hide_entry(db, entry, user_id)
            case "create_note":
                result = await _action_create_note(db, entry, config, user_id, context)
            case "extract_ttps":
                result = await _action_extract_ttps(db, entry, config, user_id, context)
            case "extract_cves":
                result = await _action_extract_cves(db, entry, context)
            case "extract_threat_actors":
                result = await _action_extract_threat_actors(db, entry, user_id, context)
            case "extract_malware":
                result = await _action_extract_malware(db, entry, user_id, context)
            case "generate_detection_rules":
                result = await _action_generate_detection_rules(db, entry, config, user_id, context)
            case "add_to_campaign":
                result = await _action_add_to_campaign(db, entry, config, user_id)
            case "create_intel_report":
                result = await _action_create_intel_report(db, entry, config, user_id, context)
            case "chain_rule":
                result = await _action_chain_rule(db, entry, config, user_id)
            case "track_on_threat_board":
                result = await _action_track_on_threat_board(db, entry)
            case "use_daily_summary":
                # Inherently a digest action — there is one briefing for the whole
                # day, not one per entry. Only meaningful in batch mode.
                result = {
                    "status": "skipped",
                    "message": "use_daily_summary only runs in batch mode (scheduled/manual digest rules)",
                }
            case _:
                result = {"status": "error", "message": f"Unknown action type: {action_type}"}

        return {"type": action_type, **result}

    except Exception as e:
        logger.error(f"Error executing action {action_type}: {e}")
        return {"type": action_type, "status": "error", "message": str(e)}


# Actions that naturally aggregate across entries in batch mode.
# These receive all entries at once instead of running per-entry.
BATCH_ACTIONS = {"send_notification", "run_webhook", "run_ai_task", "use_daily_summary"}

# Actions that must still run per-entry even in batch mode (they modify
# individual entry state in the database).
PER_ENTRY_ACTIONS = {
    "add_tags",
    "remove_tags",
    "add_to_campaign",
    "mark_priority",
    "mark_read",
    "star_entry",
    "bookmark_entry",
    "hide_entry",
    "create_note",
    "extract_ttps",
    "extract_cves",
    "extract_threat_actors",
    "extract_malware",
    "generate_detection_rules",
    "create_intel_report",
    "chain_rule",
    "track_on_threat_board",
}


async def execute_actions_batch(
    db: AsyncSession,
    entries: list[Entry],
    actions: list[dict],
    user_id: uuid.UUID,
) -> list[dict]:
    """Execute actions in batch mode for scheduled/manual runs, as automation."""
    with caller_scope(Caller.automation(user_id)):
        return await _execute_actions_batch(db, entries, actions, user_id)


async def _execute_actions_batch(
    db: AsyncSession,
    entries: list[Entry],
    actions: list[dict],
    user_id: uuid.UUID,
) -> list[dict]:
    """Execute actions in batch mode for scheduled/manual runs.

    Actions run sequentially, sharing a batch context dict:
    - Per-entry actions (tagging, extraction, etc.) loop over entries internally
    - Batch actions (AI tasks, notifications, webhooks) receive all entries at once
    - Branch actions evaluate per-entry and route to the appropriate sub-chain

    This means an AI summarization gets ALL entries and produces ONE summary,
    and a notification sends ONE digest message.
    """
    from app.automation.conditions import evaluate_conditions

    results: list[dict] = []
    batch_context: dict = {
        "entries": entries,
        "entry_count": len(entries),
    }

    for action in actions:
        action_type = action.get("type", "")
        config = action.get("config", {})

        try:
            if action_type == "branch":
                # Branch in batch mode: evaluate condition per entry and
                # split into two groups, then run sub-chains on each group
                condition = config.get("condition", {})
                then_entries: list[Entry] = []
                else_entries: list[Entry] = []
                for entry in entries:
                    matched = await evaluate_conditions(db, entry, condition, user_id=user_id)
                    if matched:
                        then_entries.append(entry)
                    else:
                        else_entries.append(entry)

                sub_results: list[dict] = []
                if then_entries:
                    then_results = await execute_actions_batch(
                        db,
                        then_entries,
                        config.get("then_actions", []),
                        user_id,
                    )
                    sub_results.extend(then_results)
                if else_entries:
                    else_results = await execute_actions_batch(
                        db,
                        else_entries,
                        config.get("else_actions", []),
                        user_id,
                    )
                    sub_results.extend(else_results)

                results.append(
                    {
                        "type": "branch",
                        "status": "success",
                        "then_count": len(then_entries),
                        "else_count": len(else_entries),
                        "sub_results": sub_results,
                    }
                )
            elif action_type in PER_ENTRY_ACTIONS:
                # Run on each entry individually
                for entry in entries:
                    result = await execute_action(db, entry, action, user_id)
                    results.append(result)
            elif action_type == "run_ai_task":
                result = await _action_run_ai_task_batch(db, entries, config, user_id, batch_context)
                results.append({"type": action_type, **result})
            elif action_type == "use_daily_summary":
                result = await _action_use_daily_summary(db, entries, config, batch_context)
                results.append({"type": action_type, **result})
            elif action_type == "send_notification":
                result = await _action_send_notification_batch(entries, config, batch_context)
                results.append({"type": action_type, **result})
            elif action_type == "run_webhook":
                result = await _action_run_webhook_batch(entries, config, batch_context)
                results.append({"type": action_type, **result})
            else:
                # Unknown — try per-entry
                for entry in entries:
                    result = await execute_action(db, entry, action, user_id)
                    results.append(result)
        except Exception as e:
            logger.error(f"Error executing batch action {action_type}: {e}")
            results.append({"type": action_type, "status": "error", "message": str(e)})

    return results


async def _action_run_ai_task(db: AsyncSession, entry: Entry, config: dict, user_id: uuid.UUID, context: dict) -> dict:
    """Run an AI task on the entry and store result in context for downstream actions."""
    from app.ai.engine import run_task

    task_name = config.get("task_id") or config.get("task_name", "")
    if not task_name:
        return {"status": "error", "message": "No task_id specified"}

    # Build only the fields declared in the variable contract (variables.py),
    # so what the builder UI advertises matches what's actually injected.
    entry_values = {
        "id": str(entry.id),
        "title": entry.title,
        "content_text": entry.content_text or "",
        "content_html": entry.content_html,
        "summary": entry.summary,
        "author": entry.author,
        "url": entry.url,
        "app_url": _entry_app_url(entry.id),
        "published_at": str(entry.published_at) if entry.published_at else "",
    }
    variables = {"entry": {f: entry_values[f] for f in PER_ENTRY_FIELDS}}

    result = await run_task(
        db=db,
        user_id=user_id,
        task_name=task_name,
        variables=variables,
        entry_id=entry.id,
    )

    if result is None:
        return {"status": "skipped", "message": f"AI task '{task_name}' not configured for user"}

    # Store AI output in context so downstream actions can use it
    ai_results = context.setdefault("ai_results", {})
    # run_task returns the parsed dict itself (the cached one on a dedup hit).
    parsed = result if isinstance(result, dict) else None
    if parsed:
        ai_results[task_name] = parsed
        # Convenience: store summary text for notification/webhook actions
        if task_name == "summarization":
            summary_text = parsed.get("summary") or parsed.get("text") or str(parsed)
            context["ai_summary"] = summary_text

    return {"status": "success", "task": task_name}


async def _action_run_ai_task_batch(
    db: AsyncSession,
    entries: list[Entry],
    config: dict,
    user_id: uuid.UUID,
    batch_context: dict,
) -> dict:
    """Run an AI task against ALL entries at once, producing one combined result.

    Passes entries as a list (like detection_engineering_summary does) so the
    prompt can iterate over all articles and produce a single output — e.g.
    one morning briefing summary covering 30 articles.
    """
    from app.ai.engine import run_task

    task_name = config.get("task_id") or config.get("task_name", "")
    if not task_name:
        return {"status": "error", "message": "No task_id specified"}

    if not entries:
        return {"status": "skipped", "message": "No entries to process"}

    # One article per story, unless the rule opts out. The fold is reported in
    # the action result so a run that collapsed 30 articles into 12 says so.
    total_articles = len(entries)
    coverage: dict = {}
    if config.get("fold_threads", True):
        from app.intelligence.story_threads import fold_by_thread

        entries, coverage = await fold_by_thread(db, entries)

    # Build variables with all entries — supports both single-entry and
    # multi-entry prompt templates. Fields are selected from the batch contract
    # (variables.py) so the builder UI stays in sync with what's injected.
    def _batch_entry_dict(e: Entry) -> dict:
        story = coverage.get(e.id, {})
        values = {
            "id": str(e.id),
            "title": e.title or "Untitled",
            "content_text": (e.content_text or "")[:3000],
            "content_html": e.content_html,
            "summary": e.summary,
            "author": e.author,
            "url": e.url,
            "app_url": _entry_app_url(e.id),
            "published_at": str(e.published_at) if e.published_at else "",
            "feed_title": getattr(e, "_feed_title", "") or "",
            # Coverage of the story this article belongs to, for prompts that
            # want to say "and nine other outlets" instead of listing them.
            "thread_title": story.get("thread_title", ""),
            "outlet_count": story.get("outlet_count", 0),
            "also_reported_by": story.get("also_reported_by", 0),
        }
        return {f: values[f] for f in BATCH_ENTRY_FIELDS}

    entry_dicts = [_batch_entry_dict(e) for e in entries]

    variables: dict = {
        # "entries" (plural) for multi-entry prompts like the digest/briefing
        "entries": entry_dicts,
        "entry_count": len(entry_dicts),
        # What the batch held before folding, so a briefing can say "12 stories
        # from 30 articles" rather than quietly dropping eighteen.
        "article_count": total_articles,
        # Also provide "entry" (singular) pointing to the first entry for
        # backward compatibility with single-entry prompt templates
        "entry": entry_dicts[0] if entry_dicts else {},
    }

    result = await run_task(
        db=db,
        user_id=user_id,
        task_name=task_name,
        variables=variables,
        entry_id=entries[0].id,
    )

    if result is None:
        return {"status": "skipped", "message": f"AI task '{task_name}' not configured for user"}

    # Store in batch context for downstream actions (notification, webhook)
    parsed = result if isinstance(result, dict) else None
    if parsed:
        batch_context.setdefault("ai_results", {})[task_name] = parsed
        # Extract main text for notification templates ({ai_summary})
        summary_text = _extract_summary_text(parsed)
        if summary_text:
            batch_context["ai_summary"] = summary_text

    return {
        "status": "success",
        "task": task_name,
        "entries_processed": total_articles,
        "stories": len(entry_dicts),
        "folded": total_articles - len(entry_dicts),
    }


async def _action_use_daily_summary(
    db: AsyncSession,
    entries: list[Entry],
    config: dict,
    batch_context: dict,
) -> dict:
    """Reuse the shared daily briefing instead of generating a second one.

    Drop-in replacement for run_ai_task in a digest rule: it populates the same
    ``ai_summary`` / ``ai_results`` context keys the notification and webhook
    actions read, so ``{ai_summary}`` renders identically — but reads the
    day-divider summary the 06:00 job already paid for rather than sending the
    day's articles to the model a second time.

    ``on_missing: "generate"`` (the default) generates it through the same shared
    cache the divider reads, so a briefing is never lost when the beat job is off
    or failed — and the divider gets backfilled as a side effect.

    The cached markdown links each article as ``/?entry=<id>`` — the in-app
    reader. That is the wrong link for a Discord/Slack/webhook push, where the
    reader has no session (and may have no account), so ``links: "original"``
    (the default) rewrites every one of them to the article's own source URL
    before it reaches the notification/webhook actions. ``links: "app"`` keeps
    the IntelFeed deep links instead, absolutised via PUBLIC_BASE_URL.
    """
    from app.services.daily_briefing import (
        ensure_daily_summary,
        externalize_entry_links,
        get_cached_daily_summary,
        today_key,
        yesterday_key,
    )

    day = config.get("day", "yesterday")
    if day not in ("yesterday", "today"):
        return {"status": "error", "message": f"Invalid day '{day}': expected 'yesterday' or 'today'"}
    on_missing = config.get("on_missing", "generate")
    links = config.get("links", "original")
    if links not in ("original", "app"):
        return {"status": "error", "message": f"Invalid links '{links}': expected 'original' or 'app'"}

    day_key = today_key() if day == "today" else yesterday_key()

    summary = await get_cached_daily_summary(db, day_key)
    source = "cache"

    if summary is None:
        if on_missing == "skip":
            return {"status": "skipped", "day": day_key, "message": f"No cached daily summary for {day_key}"}
        result = await ensure_daily_summary(db, day_key)
        summary = result.get("summary")
        source = "generated" if result.get("generated") else "cache"
        if not summary:
            return {
                "status": "skipped",
                "day": day_key,
                "message": f"No daily summary available for {day_key}: {result.get('reason') or result.get('error')}",
            }

    # Everything downstream of this action leaves the app (notification /
    # webhook), so the in-app reader links are rewritten to the original
    # articles unless the rule explicitly asks for app links.
    summary = await externalize_entry_links(db, summary) if links == "original" else _absolutize_app_links(summary)

    batch_context.setdefault("ai_results", {})["daily_summary"] = {"summary": summary}
    batch_context["ai_summary"] = summary

    return {
        "status": "success",
        "day": day_key,
        "source": source,
        "links": links,
        "chars": len(summary),
        "entries_processed": len(entries),
    }


async def _sync_entry_tags_index(db: AsyncSession, entry_id: uuid.UUID) -> None:
    """Push the entry's current tags to the search index.

    Meilisearch stores tags as a full array per document, so we recompute the
    entry's complete tag fields (global tag names + personal assignment tokens)
    and sync them best-effort. Without this, automation-applied tags never
    reach the index and `tag:` search returns nothing.
    """
    await sync_entry_tags_to_search(db, [entry_id])


_HEX_COLOR = re.compile(r"^#[0-9A-Fa-f]{6}$")


def _clean_tag_name(raw: object) -> str:
    """A tag name as the Tag model accepts it: trimmed, capped at the column's
    100 chars, with the two characters a search filter can't take (`"` and `\\`)
    dropped — see TAG_NAME_PATTERN in app.schemas.tag."""
    return str(raw or "").replace('"', "").replace("\\", "").strip()[:100]


def _tag_spec(item) -> dict | None:
    """Normalise one `add_tags` entry: a bare name, or a dict that also carries
    the presentation and scope to use if the tag has to be created."""
    if isinstance(item, str):
        name = _clean_tag_name(item)
        return {"name": name} if name else None
    if isinstance(item, dict):
        name = _clean_tag_name(item.get("name"))
        return {**item, "name": name} if name else None
    return None


async def _action_add_tags(db: AsyncSession, entry: Entry, config: dict, user_id: uuid.UUID | None) -> dict:
    """Add tags to the entry.

    `config["tags"]` holds bare names or `{name, color, description, chip,
    global}` objects. The presentation and scope fields apply only when the tag
    doesn't exist yet: an existing tag's record is the source of truth and is
    never recoloured or re-scoped from under the other entries carrying it.

    Each assignment belongs to the rule's owner — it shows on their cards and
    nobody else's — unless the tag is global, in which case it is shared. A
    rule with no owner cannot apply a personal tag and skips it.
    """
    specs = [spec for spec in map(_tag_spec, config.get("tags") or []) if spec]
    if not specs:
        return {"status": "skipped", "message": "No tags specified"}

    added: list[str] = []
    unowned: list[str] = []
    for spec in specs:
        name = spec["name"]
        # Find or create tag
        result = await db.execute(select(Tag).where(Tag.name == name))
        tag = result.scalar_one_or_none()
        if not tag and user_id is None and not spec.get("global"):
            # Nobody to own the assignment, so don't mint an orphan definition.
            unowned.append(name)
            continue
        if not tag:
            color = spec.get("color")
            description = spec.get("description")
            tag = Tag(
                created_by=user_id,
                name=name,
                color=color if isinstance(color, str) and _HEX_COLOR.match(color) else "#6B7280",
                display_as_chip=bool(spec.get("chip")),
                description=str(description).strip()[:255] or None if description else None,
                is_global=bool(spec.get("global")),
            )
            db.add(tag)
            await db.flush()

        try:
            if await ensure_assignment(db, entry.id, tag, user_id):
                added.append(name)
        except MissingOwner:
            unowned.append(name)

    await db.flush()
    if unowned and not added:
        return {
            "status": "skipped",
            "message": f"Rule has no owner; personal tags need one: {', '.join(unowned)}",
            "tags_skipped": unowned,
        }
    if added:
        await _sync_entry_tags_index(db, entry.id)
    result_payload: dict = {"status": "success", "tags_added": added}
    if unowned:
        result_payload["tags_skipped"] = unowned
    return result_payload


async def _action_send_notification(entry: Entry, config: dict, context: dict | None = None) -> dict:
    """Send a notification via webhook (Slack, Discord, or custom).

    Config fields:
      - platform: "slack" | "discord" | "custom" (default: "discord")
      - webhook_url: The webhook endpoint URL (required)
      - channel: Channel name to post to (e.g. "#threat-intel", "alerts")
      - username: Bot display name (default: "IntelFeed")
      - message_template: Custom message with {title}, {url}, {author},
            {summary}, {ai_summary}, {published_at}, {feed_name} variables.
            If empty, uses a sensible default per platform.
      - include_embeds: Whether to include rich embeds (default: true for discord)

    If an AI summary exists in context (from a prior run_ai_task action),
    it's included in the payload automatically via {ai_summary} or in embeds.
    """
    platform = config.get("platform", "discord").lower()
    webhook_url = config.get("webhook_url", "")
    channel = config.get("channel", "")
    username = config.get("username", "IntelFeed")
    message_template = config.get("message_template", "")
    include_embeds = config.get("include_embeds", platform == "discord")

    if not webhook_url:
        return {"status": "error", "message": "No webhook_url specified"}

    ssrf_err = await _validate_webhook_url(webhook_url)
    if ssrf_err:
        return {"status": "error", "message": ssrf_err}

    ctx = context or {}
    ai_summary = ctx.get("ai_summary")
    summary_text = ai_summary or (entry.summary or "")[:500]

    # Render custom message or build default
    if message_template:
        message_text = _render_template(message_template, entry, ctx)
    else:
        parts = [f"**{entry.title or 'Untitled'}**"]
        if entry.url:
            parts.append(entry.url)
        if summary_text:
            parts.append(f"\n{summary_text}")
        message_text = "\n".join(parts)

    # Build platform-specific payload
    if platform == "slack":
        payload = _build_slack_payload(entry, message_text, summary_text, channel, username, ctx)
    elif platform == "discord":
        payload = _build_discord_payload(entry, message_text, summary_text, username, include_embeds, ctx)
    else:
        # Custom: send structured JSON with all data
        payload = _build_custom_payload(entry, message_text, channel, ctx)

    async with _webhook_client(timeout=15.0) as client:
        response = await client.post(webhook_url, json=payload)
        if response.status_code < 300:
            return {
                "status": "success",
                "platform": platform,
                "channel": channel or "(default)",
                "included_ai_summary": bool(ai_summary),
            }
        else:
            return {"status": "error", "message": f"Webhook returned {response.status_code}"}


def _build_slack_payload(
    entry: Entry,
    message_text: str,
    summary_text: str,
    channel: str,
    username: str,
    ctx: dict,
) -> dict:
    """Build a Slack-compatible webhook payload."""
    payload: dict = {
        "text": message_text,
        "username": username,
        "icon_emoji": ":shield:",
        "unfurl_links": False,
        "unfurl_media": False,
    }
    if channel:
        payload["channel"] = channel if channel.startswith("#") else f"#{channel}"

    # Slack Block Kit for rich formatting
    blocks = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*<{entry.url}|{entry.title or 'Untitled'}>*"},
        },
    ]
    if summary_text:
        blocks.extend(_slack_blocks_from_text(_markdown_to_mrkdwn(summary_text)))

    fields = []
    if entry.author:
        fields.append({"type": "mrkdwn", "text": f"*Author:* {entry.author}"})
    fields.append({"type": "mrkdwn", "text": "*Source:* IntelFeed"})
    if fields:
        blocks.append({"type": "section", "fields": fields})

    # Slack rejects messages with more than 50 blocks; keep the trailing
    # fields block and trim the middle if an AI summary was enormous.
    if len(blocks) > 50:
        blocks = blocks[:49] + [blocks[-1]]
    payload["blocks"] = blocks
    return payload


def _build_discord_payload(
    entry: Entry,
    message_text: str,
    summary_text: str,
    username: str,
    include_embeds: bool,
    ctx: dict,
) -> dict:
    """Build a Discord-compatible webhook payload."""
    payload: dict = {
        "content": message_text,
        "username": username,
    }

    if include_embeds:
        payload["embeds"] = [
            {
                "title": entry.title or "IntelFeed Alert",
                "url": entry.url,
                "description": summary_text[:4096] if summary_text else None,
                "fields": [
                    {"name": "Author", "value": entry.author or "Unknown", "inline": True},
                    {"name": "Source", "value": "IntelFeed Automation", "inline": True},
                ],
                "color": 0xF78166,
            }
        ]

    ai_results = ctx.get("ai_results", {})
    if ai_results:
        payload["ai_results"] = ai_results

    return payload


def _build_custom_payload(
    entry: Entry,
    message_text: str,
    channel: str,
    ctx: dict,
) -> dict:
    """Build a generic JSON payload for custom integrations."""
    payload: dict = {
        "message": message_text,
        "entry_id": str(entry.id),
        "title": entry.title,
        "url": entry.url,
        "author": entry.author,
        "published_at": str(entry.published_at) if entry.published_at else None,
    }
    if channel:
        payload["channel"] = channel

    ai_summary = ctx.get("ai_summary")
    if ai_summary:
        payload["ai_summary"] = ai_summary
    ai_results = ctx.get("ai_results")
    if ai_results:
        payload["ai_results"] = ai_results

    return payload


# ---------------------------------------------------------------------------
# Discord message chunking
# ---------------------------------------------------------------------------
# Discord webhook limits: content 2000 chars, embed description 4096 chars,
# max 10 embeds per message, ~6000 combined chars per message. Long briefings
# must therefore be split across multiple embeds and multiple sequential POSTs
# so nothing is silently truncated.

_DISCORD_EMBED_LIMIT = 4000  # stay safely under the 4096 embed description cap
_DISCORD_MSG_CHAR_LIMIT = 5500  # stay under the 6000 combined-per-message cap
_DISCORD_MSG_EMBED_LIMIT = 10
_DISCORD_COLOR = 0xF78166


def _split_for_discord(text: str, chunk_size: int = _DISCORD_EMBED_LIMIT) -> list[str]:
    """Split text into chunks no larger than chunk_size.

    Breaks on paragraph, then line, then word boundaries so markdown
    (masked links, headers, lists) stays intact across chunk edges.
    """
    text = (text or "").strip()
    if len(text) <= chunk_size:
        return [text] if text else []

    chunks: list[str] = []
    remaining = text
    while remaining:
        if len(remaining) <= chunk_size:
            chunks.append(remaining)
            break
        window = remaining[:chunk_size]
        split_at = window.rfind("\n\n")
        if split_at < chunk_size // 2:
            split_at = window.rfind("\n")
        if split_at < chunk_size // 2:
            split_at = window.rfind(" ")
        if split_at <= 0:
            split_at = chunk_size
        chunks.append(remaining[:split_at].strip())
        remaining = remaining[split_at:].strip()
    return [c for c in chunks if c]


def _discord_embed_messages(text: str, username: str) -> list[dict]:
    """Pack a long text into one or more Discord webhook payloads via embeds.

    Returns a list of payloads to POST sequentially. Each message holds up to
    10 embeds and ~5500 combined chars; each embed description is <= 4000 chars.
    """
    chunks = _split_for_discord(text)
    messages: list[dict] = []
    group: list[str] = []
    group_len = 0

    def _flush() -> None:
        nonlocal group, group_len
        if group:
            messages.append(
                {
                    "username": username,
                    "embeds": [{"description": c, "color": _DISCORD_COLOR} for c in group],
                }
            )
            group, group_len = [], 0

    for ch in chunks:
        if group and (len(group) >= _DISCORD_MSG_EMBED_LIMIT or group_len + len(ch) > _DISCORD_MSG_CHAR_LIMIT):
            _flush()
        group.append(ch)
        group_len += len(ch)
    _flush()
    return messages


# ---------------------------------------------------------------------------
# Slack message building
# ---------------------------------------------------------------------------
# Slack's mrkdwn is not Markdown: **bold** renders literally, [text](url)
# renders literally, and # headings render literally. AI briefings arrive as
# GitHub-flavored Markdown, so they must be converted before posting. Slack
# limits: 3000 chars per section block text, 150 chars per header block text,
# 50 blocks per message.

_SLACK_SECTION_LIMIT = 2900  # stay under the 3000-char section text cap
_SLACK_HEADER_LIMIT = 150
_SLACK_MSG_BLOCK_LIMIT = 48  # stay under the 50-blocks-per-message cap

_MD_LINK_RE = re.compile(r"!?\[([^\]]+)\]\((https?://[^)\s]+)\)")
_MD_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_MD_BOLD_UNDER_RE = re.compile(r"__(.+?)__")
_MD_STRIKE_RE = re.compile(r"~~(.+?)~~")
_MD_BULLET_RE = re.compile(r"^(\s*)[-*]\s+")
_MD_HEADING_RE = re.compile(r"^#{1,6}\s+(.*)$")
_MRKDWN_MARKS_RE = re.compile(r"[*_~`]")


def _markdown_to_mrkdwn(text: str) -> str:
    """Convert GitHub-flavored Markdown to Slack mrkdwn.

    Heading lines are left with their # prefix — _slack_blocks_from_text
    turns them into header blocks. Fenced code blocks pass through untouched.
    """
    out: list[str] = []
    in_fence = False
    for line in (text or "").split("\n"):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence or _MD_HEADING_RE.match(line):
            out.append(line)
            continue
        line = _MD_LINK_RE.sub(r"<\2|\1>", line)
        line = _MD_BOLD_RE.sub(r"*\1*", line)
        line = _MD_BOLD_UNDER_RE.sub(r"*\1*", line)
        line = _MD_STRIKE_RE.sub(r"~\1~", line)
        line = _MD_BULLET_RE.sub(r"\g<1>• ", line)
        out.append(line)
    return "\n".join(out)


def _slack_blocks_from_text(text: str) -> list[dict]:
    """Turn mrkdwn text into Block Kit blocks.

    # headings become header blocks, --- lines become dividers, and the text
    between them is packed into section blocks of at most 2900 chars each.
    """
    blocks: list[dict] = []
    buf: list[str] = []

    def _flush() -> None:
        joined = "\n".join(buf).strip()
        buf.clear()
        for chunk in _split_for_discord(joined, _SLACK_SECTION_LIMIT):
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": chunk}})

    for line in (text or "").split("\n"):
        heading = _MD_HEADING_RE.match(line)
        if heading:
            _flush()
            title = _MRKDWN_MARKS_RE.sub("", heading.group(1)).strip()[:_SLACK_HEADER_LIMIT]
            if title:
                blocks.append({"type": "header", "text": {"type": "plain_text", "text": title}})
        elif line.strip() in ("---", "***", "___"):
            _flush()
            blocks.append({"type": "divider"})
        else:
            buf.append(line)
    _flush()
    return blocks


def _slack_block_messages(
    blocks: list[dict],
    username: str,
    channel: str,
    fallback_text: str,
) -> list[dict]:
    """Group blocks into one or more webhook payloads of <= 48 blocks each."""
    payloads: list[dict] = []
    for i in range(0, len(blocks), _SLACK_MSG_BLOCK_LIMIT):
        payload: dict = {
            "text": fallback_text if i == 0 else f"{fallback_text} (continued)",
            "username": username,
            "icon_emoji": ":shield:",
            "unfurl_links": False,
            "unfurl_media": False,
            "blocks": blocks[i : i + _SLACK_MSG_BLOCK_LIMIT],
        }
        if channel:
            payload["channel"] = channel if channel.startswith("#") else f"#{channel}"
        payloads.append(payload)
    return payloads


# ---------------------------------------------------------------------------
# Batch (digest) variants for scheduled/manual runs
# ---------------------------------------------------------------------------


async def _action_send_notification_batch(
    entries: list[Entry],
    config: dict,
    batch_context: dict,
) -> dict:
    """Send a single notification for a batch run.

    If a prior AI task produced an ai_summary in batch_context, sends that
    as the main message body (e.g. a morning briefing). Otherwise falls back
    to listing entries as a digest.
    """
    platform = config.get("platform", "discord").lower()
    webhook_url = config.get("webhook_url", "")
    channel = config.get("channel", "")
    username = config.get("username", "IntelFeed")
    message_template = config.get("message_template", "")

    if not webhook_url:
        return {"status": "error", "message": "No webhook_url specified"}

    ssrf_err = await _validate_webhook_url(webhook_url)
    if ssrf_err:
        return {"status": "error", "message": ssrf_err}

    if not entries:
        return {"status": "skipped", "message": "No entries to notify about"}

    count = len(entries)
    ai_summary = batch_context.get("ai_summary", "")

    # If there's a custom message template, render it with batch context
    if message_template:
        # For batch, render template once with first entry + batch context
        message_text = _render_template(message_template, entries[0], batch_context)
    elif ai_summary:
        # AI produced a combined summary — use it as the main body
        message_text = ai_summary
    else:
        # No AI summary, no template — build an entry listing
        lines: list[str] = []
        for entry in entries:
            title = entry.title or "Untitled"
            url_str = entry.url or ""
            summary = (entry.summary or "")[:200]
            if platform == "slack":
                line = f"• *<{url_str}|{title}>*"
            elif platform == "discord":
                line = f"• **[{title}]({url_str})**"
            else:
                line = f"• {title} — {url_str}"
            if summary:
                line += f"\n  {summary}"
            lines.append(line)
        message_text = "\n\n".join(lines)

    # Guard: never POST an empty body (Slack/Discord reject it with a 400). This
    # happens when a template like {ai_summary} renders empty because the AI task
    # produced no extractable text.
    if not (message_text or "").strip():
        return {
            "status": "skipped",
            "message": (
                "Nothing to send — the rendered message was empty. If you used "
                "{ai_summary}, the AI task returned no extractable text."
            ),
        }

    header = f"📋 **IntelFeed Digest** — {count} {'entry' if count == 1 else 'entries'}"

    # Build platform-specific payload(s). Discord may require several messages
    # to fit a long briefing within its per-message limits.
    payloads: list[dict]
    if platform == "slack":
        if ai_summary or message_template:
            # AI briefing / rendered template — arrives as Markdown, convert
            # to mrkdwn and split across blocks (and messages if needed) so
            # nothing is truncated.
            blocks = _slack_blocks_from_text(_markdown_to_mrkdwn(message_text))
            fallback = f"IntelFeed Briefing — {count} {'entry' if count == 1 else 'entries'}"
        else:
            # Entry listing — already built as mrkdwn, add a header
            blocks = [
                {"type": "header", "text": {"type": "plain_text", "text": f"IntelFeed Digest — {count} entries"}},
                {"type": "divider"},
                *_slack_blocks_from_text(message_text),
            ]
            fallback = f"IntelFeed Digest — {count} {'entry' if count == 1 else 'entries'}"
        payloads = _slack_block_messages(blocks, username, channel, fallback)

    elif platform == "discord":
        # The body is the AI briefing / rendered template as-is; only the bare
        # entry-listing fallback gets the digest header prepended.
        body = message_text if (ai_summary or message_template) else f"{header}\n\n{message_text}"
        if len(body) <= 2000:
            payloads = [{"content": body, "username": username}]
        else:
            # Split across multiple embeds / messages so nothing is dropped.
            payloads = _discord_embed_messages(body, username)

    else:
        # Custom platform
        payloads = [
            {
                "message": message_text,
                "header": header,
                "entry_count": count,
                "ai_summary": ai_summary,
                "entries": [{"entry_id": str(e.id), "title": e.title, "url": e.url} for e in entries],
            }
        ]
        if channel:
            payloads[0]["channel"] = channel

    async with _webhook_client(timeout=30.0) as client:
        for i, payload in enumerate(payloads):
            # Respect webhook rate limits when fanning out: Slack allows
            # ~1 msg/sec, Discord 5 req/2s.
            if i > 0:
                await asyncio.sleep(1.1 if platform == "slack" else 0.4)
            response = await client.post(webhook_url, json=payload)
            if response.status_code >= 300:
                body_excerpt = (response.text or "")[:300].replace("\n", " ")
                return {
                    "status": "error",
                    "message": f"Webhook returned {response.status_code}: {body_excerpt}",
                    "messages_sent": i,
                    "messages_total": len(payloads),
                }

    return {
        "status": "success",
        "platform": platform,
        "entries_included": count,
        "has_ai_summary": bool(ai_summary),
        "channel": channel or "(default)",
        "messages_sent": len(payloads),
    }


async def _action_run_webhook_batch(
    entries: list[Entry],
    config: dict,
    batch_context: dict,
) -> dict:
    """POST batch data to a webhook URL."""
    url = config.get("url", "")
    headers = config.get("headers", {})

    if not url:
        return {"status": "error", "message": "No URL specified"}

    ssrf_err = await _validate_webhook_url(url)
    if ssrf_err:
        return {"status": "error", "message": ssrf_err}

    if not entries:
        return {"status": "skipped", "message": "No entries"}

    custom_payload = config.get("payload")
    if custom_payload and custom_payload.strip() and custom_payload.strip() != "{}":
        # Render template variables using the first entry for context
        rendered = _render_template_json_safe(custom_payload, entries[0], batch_context)
        import json as _json

        try:
            payload = _json.loads(rendered)
        except _json.JSONDecodeError:
            return {"status": "error", "message": "Invalid JSON in custom payload"}
    else:
        payload = {
            "entry_count": len(entries),
            "ai_summary": batch_context.get("ai_summary", ""),
            "ai_results": batch_context.get("ai_results", {}),
            "entries": [
                {
                    "entry_id": str(entry.id),
                    "title": entry.title,
                    "url": entry.url,
                    "author": entry.author,
                    "content_text": (entry.content_text or "")[:2000],
                    "published_at": str(entry.published_at) if entry.published_at else None,
                }
                for entry in entries
            ],
        }

    send_headers = {"Connection": "close", **headers}
    async with _webhook_client(timeout=30.0) as client:
        response = await client.post(url, json=payload, headers=send_headers)
        return {
            "status": "success" if response.status_code < 300 else "error",
            "http_status": response.status_code,
            "entries_included": len(entries),
        }


async def _action_run_webhook(entry: Entry, config: dict, context: dict | None = None) -> dict:
    """POST entry data to a URL. Includes AI results from context if available."""
    url = config.get("url", "")
    headers = config.get("headers", {})

    if not url:
        return {"status": "error", "message": "No URL specified"}

    ssrf_err = await _validate_webhook_url(url)
    if ssrf_err:
        return {"status": "error", "message": ssrf_err}

    ctx = context or {}

    custom_payload = config.get("payload")
    if custom_payload and custom_payload.strip() and custom_payload.strip() != "{}":
        # Render template variables in the raw payload string before parsing
        rendered = _render_template_json_safe(custom_payload, entry, ctx)
        import json as _json

        try:
            payload: dict = _json.loads(rendered)
        except _json.JSONDecodeError:
            return {"status": "error", "message": "Invalid JSON in custom payload"}
    else:
        payload = {
            "entry_id": str(entry.id),
            "title": entry.title,
            "url": entry.url,
            "author": entry.author,
            "content_text": (entry.content_text or "")[:5000],
            "published_at": str(entry.published_at) if entry.published_at else None,
        }

        # Include AI outputs if prior actions produced them
        ai_summary = ctx.get("ai_summary")
        if ai_summary:
            payload["ai_summary"] = ai_summary
        ai_results = ctx.get("ai_results")
        if ai_results:
            payload["ai_results"] = ai_results

    send_headers = {"Connection": "close", **headers}
    async with _webhook_client(timeout=15.0) as client:
        response = await client.post(url, json=payload, headers=send_headers)
        return {"status": "success" if response.status_code < 300 else "error", "http_status": response.status_code}


async def _action_mark_priority(db: AsyncSession, entry: Entry, config: dict, user_id: uuid.UUID) -> dict:
    """Mark an entry with a priority level by adding a priority tag."""
    level = config.get("level", "medium")
    tag_name = f"priority-{level}"

    # Reuse add_tags logic
    return await _action_add_tags(db, entry, {"tags": [tag_name]}, user_id)


async def _action_chain_rule(db: AsyncSession, entry: Entry, config: dict, user_id: uuid.UUID) -> dict:
    """Trigger another automation rule by ID."""
    from app.models.automation_rule import AutomationRule

    rule_id = config.get("rule_id", "")
    if not rule_id:
        return {"status": "error", "message": "No rule_id specified"}

    result = await db.execute(
        select(AutomationRule).where(
            AutomationRule.id == uuid.UUID(str(rule_id)),
        )
    )
    chained_rule = result.scalar_one_or_none()
    if not chained_rule:
        return {"status": "error", "message": "Chained rule not found"}

    if not chained_rule.is_enabled:
        return {"status": "skipped", "message": "Chained rule is disabled"}

    # Import here to avoid circular dependency
    from app.automation.engine import execute_automation

    log = await execute_automation(db, entry, chained_rule)
    return {"status": log.status, "chained_rule": chained_rule.name, "chained_log_status": log.status}


# ---------------------------------------------------------------------------
# Entry-state actions
# ---------------------------------------------------------------------------


async def _get_or_create_entry_state(
    db: AsyncSession,
    entry: Entry,
    user_id: uuid.UUID,
) -> UserEntryState:
    """Get or create a UserEntryState record for this entry + user."""
    result = await db.execute(
        select(UserEntryState).where(
            UserEntryState.entry_id == entry.id,
            UserEntryState.user_id == user_id,
        )
    )
    state = result.scalar_one_or_none()
    if not state:
        state = UserEntryState(entry_id=entry.id, user_id=user_id)
        db.add(state)
        await db.flush()
    return state


async def _action_mark_read(db: AsyncSession, entry: Entry, user_id: uuid.UUID) -> dict:
    """Mark an entry as read."""
    state = await _get_or_create_entry_state(db, entry, user_id)
    if state.is_read:
        return {"status": "skipped", "message": "Already read"}
    state.is_read = True
    state.read_at = datetime.now(UTC)
    await db.flush()
    return {"status": "success"}


async def _action_star_entry(db: AsyncSession, entry: Entry, user_id: uuid.UUID) -> dict:
    """Star an entry."""
    state = await _get_or_create_entry_state(db, entry, user_id)
    if state.is_starred:
        return {"status": "skipped", "message": "Already starred"}
    state.is_starred = True
    await db.flush()
    return {"status": "success"}


async def _action_bookmark_entry(db: AsyncSession, entry: Entry, user_id: uuid.UUID) -> dict:
    """Bookmark an entry."""
    state = await _get_or_create_entry_state(db, entry, user_id)
    if state.is_bookmarked:
        return {"status": "skipped", "message": "Already bookmarked"}
    state.is_bookmarked = True
    await db.flush()
    return {"status": "success"}


async def _action_hide_entry(db: AsyncSession, entry: Entry, user_id: uuid.UUID) -> dict:
    """Hide an entry from the user's view."""
    state = await _get_or_create_entry_state(db, entry, user_id)
    if state.is_hidden:
        return {"status": "skipped", "message": "Already hidden"}
    state.is_hidden = True
    await db.flush()
    return {"status": "success"}


async def _action_remove_tags(db: AsyncSession, entry: Entry, config: dict, user_id: uuid.UUID) -> dict:
    """Remove tags from an entry."""
    # Names normalised exactly as `add_tags` does, so a rule removes what it added.
    tag_names = [spec["name"] for spec in map(_tag_spec, config.get("tags") or []) if spec]
    if not tag_names:
        return {"status": "skipped", "message": "No tags specified"}

    removed = []
    for name in tag_names:
        result = await db.execute(select(Tag).where(Tag.name == name))
        tag = result.scalar_one_or_none()
        if not tag:
            continue

        # The rule owner's own assignment, or the shared one for a global tag;
        # another analyst's assignment of a personal tag is theirs to keep.
        et_result = await db.execute(
            delete(EntryTag).where(
                EntryTag.entry_id == entry.id,
                EntryTag.tag_id == tag.id,
                visible_to(user_id),
            )
        )
        if et_result.rowcount:
            removed.append(name)

    await db.flush()
    if removed:
        await _sync_entry_tags_index(db, entry.id)
    return {"status": "success", "tags_removed": removed}


async def _action_create_note(
    db: AsyncSession,
    entry: Entry,
    config: dict,
    user_id: uuid.UUID,
    context: dict,
) -> dict:
    """Create a note attached to the entry.

    Config:
      - title: Note title (supports template variables)
      - content: Note body in markdown (supports template variables)
    """
    title_template = config.get("title", "Auto-note: {title}")
    content_template = config.get("content", "{summary}")

    title = _render_template(title_template, entry, context)
    content = _render_template(content_template, entry, context)

    from app.services.markdown import render_markdown

    note = Note(
        created_by=user_id,
        entry_id=entry.id,
        title=title[:500],
        content_markdown=content,
        content_html=render_markdown(content),
    )
    db.add(note)
    await db.flush()
    return {"status": "success", "note_id": str(note.id)}


# ---------------------------------------------------------------------------
# Intelligence extraction actions
# ---------------------------------------------------------------------------


def _entry_to_dict(entry: Entry) -> dict:
    """Convert Entry ORM object to dict for intelligence extraction functions."""
    return {
        "title": entry.title,
        "content_text": entry.content_text or "",
        "content_html": entry.content_html,
        "summary": entry.summary,
        "author": entry.author,
        "url": entry.url,
        "published_at": str(entry.published_at) if entry.published_at else "",
        "feed_title": "",
    }


async def _action_extract_ttps(
    db: AsyncSession,
    entry: Entry,
    config: dict,
    user_id: uuid.UUID,
    context: dict,
) -> dict:
    """Extract MITRE ATT&CK TTPs from entry.

    Config:
      - use_ai: bool (default: true)
    """
    from app.intelligence.ttp import extract_ttps, store_ttps

    use_ai = config.get("use_ai", True)
    entry_data = _entry_to_dict(entry)

    ttp_results, status, err = await extract_ttps(db, user_id, entry.id, entry_data, use_ai=use_ai)
    if status != "success":
        return {"status": "error", "message": err or f"TTP extraction {status}"}

    if not ttp_results:
        return {"status": "skipped", "message": "No TTPs found"}

    stored = await store_ttps(db, entry.id, ttp_results)
    await db.flush()

    ttp_count = len(stored)
    new_count = sum(1 for _, is_new in stored if is_new)

    context.setdefault("extraction_results", {})["ttps"] = [
        {"technique_id": ttp.technique_id, "technique_name": ttp.technique_name, "tactic": ttp.tactic}
        for ttp, _ in stored
    ]

    return {"status": "success", "ttps_found": ttp_count, "new_ttps": new_count}


async def _action_extract_cves(
    db: AsyncSession,
    entry: Entry,
    context: dict,
) -> dict:
    """Extract CVE references from entry and enrich from NVD."""
    from app.intelligence.cve import extract_and_store_cves

    text = f"{entry.title or ''} {entry.content_text or ''} {entry.summary or ''}"
    cves = await extract_and_store_cves(db, entry.id, text)
    await db.flush()

    if not cves:
        return {"status": "skipped", "message": "No CVEs found"}

    context.setdefault("extraction_results", {})["cves"] = [
        {"cve_id": cve.cve_id, "cvss_score": cve.cvss_score, "severity": cve.severity} for cve in cves
    ]

    return {"status": "success", "cves_found": len(cves)}


async def _action_extract_threat_actors(
    db: AsyncSession,
    entry: Entry,
    user_id: uuid.UUID,
    context: dict,
) -> dict:
    """AI-identify threat actors mentioned in entry."""
    from app.intelligence.enrichment import extract_threat_actors

    entry_data = _entry_to_dict(entry)
    items, status, err = await extract_threat_actors(db, user_id, entry.id, entry_data)

    if status != "success":
        return {"status": "error", "message": err or f"Threat actor extraction {status}"}

    if not items:
        return {"status": "skipped", "message": "No threat actors found"}

    await db.flush()

    context.setdefault("extraction_results", {})["threat_actors"] = [
        {"name": actor.name, "id": str(actor.id)} for actor, _ in items
    ]

    return {
        "status": "success",
        "actors_found": len(items),
        "new_actors": sum(1 for _, is_new in items if is_new),
    }


async def _action_extract_malware(
    db: AsyncSession,
    entry: Entry,
    user_id: uuid.UUID,
    context: dict,
) -> dict:
    """AI-identify malware families mentioned in entry."""
    from app.intelligence.enrichment import extract_malware

    entry_data = _entry_to_dict(entry)
    items, status, err = await extract_malware(db, user_id, entry.id, entry_data)

    if status != "success":
        return {"status": "error", "message": err or f"Malware extraction {status}"}

    if not items:
        return {"status": "skipped", "message": "No malware families found"}

    await db.flush()

    context.setdefault("extraction_results", {})["malware"] = [{"name": mw.name, "id": str(mw.id)} for mw, _ in items]

    return {
        "status": "success",
        "malware_found": len(items),
        "new_malware": sum(1 for _, is_new in items if is_new),
    }


async def _action_generate_detection_rules(
    db: AsyncSession,
    entry: Entry,
    config: dict,
    user_id: uuid.UUID,
    context: dict,
) -> dict:
    """Generate detection rules from entry TTPs.

    Config:
      - rule_types: list[str] — e.g. ["sigma", "splunk_spl", "kql"]
        Supported: sigma, splunk_spl, crowdstrike_ql, elastic_ql, kql, yara, snort_suricata
        Default: ["sigma"]

    Uses TTPs from context if a prior extract action ran, otherwise
    queries existing extracted data from the database.
    """
    from app.intelligence.detection import generate_detection_rules
    from app.models.ttp import TTP, EntryTTP

    rule_types = config.get("rule_types", ["sigma"])
    if isinstance(rule_types, str):
        rule_types = [rt.strip() for rt in rule_types.split(",") if rt.strip()]

    entry_data = _entry_to_dict(entry)

    # Try context first (from prior extract actions), fall back to DB
    extraction = context.get("extraction_results", {})

    ttps_data = extraction.get("ttps")
    if ttps_data is None:
        result = await db.execute(
            select(TTP).join(EntryTTP, EntryTTP.ttp_id == TTP.id).where(EntryTTP.entry_id == entry.id)
        )
        ttps_data = [
            {"technique_id": ttp.technique_id, "technique_name": ttp.technique_name, "tactic": ttp.tactic}
            for ttp in result.scalars().all()
        ]

    if not ttps_data:
        return {"status": "skipped", "message": "No TTPs available for rule generation"}

    rules = await generate_detection_rules(db, user_id, entry.id, entry_data, ttps_data, rule_types)
    await db.flush()

    context.setdefault("extraction_results", {})["detection_rules"] = [
        {"id": str(r.id), "title": r.title, "rule_type": r.rule_type} for r in rules
    ]

    return {
        "status": "success",
        "rules_generated": len(rules),
        "rule_types": [r.rule_type for r in rules],
    }


async def _action_add_to_campaign(
    db: AsyncSession,
    entry: Entry,
    config: dict,
    user_id: uuid.UUID,
) -> dict:
    """Link entry to a campaign.

    Config:
      - campaign_id: str (UUID, required)
      - notes: str (optional)
      - link_observables: bool (optional) — also attach the entry's captured
        observables (reporting doors only, dual-use infra excluded) as
        campaign entities, so an on_observable_captured rule builds the
        campaign's infrastructure list as articles land.
      - observable_kinds / observable_roles: comma lists narrowing which
        captured observables are attached (blank = any).
    """
    from app.models.campaign import Campaign, CampaignEntry

    campaign_id = config.get("campaign_id", "")
    if not campaign_id:
        return {"status": "error", "message": "No campaign_id specified"}

    result = await db.execute(
        select(Campaign).where(
            Campaign.id == uuid.UUID(str(campaign_id)),
        )
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        return {"status": "error", "message": "Campaign not found"}

    # Check if already linked
    existing = await db.execute(
        select(CampaignEntry).where(
            CampaignEntry.campaign_id == campaign.id,
            CampaignEntry.entry_id == entry.id,
        )
    )
    already_linked = existing.scalar_one_or_none() is not None
    if not already_linked:
        ce = CampaignEntry(
            campaign_id=campaign.id,
            entry_id=entry.id,
            added_by=user_id,
            notes=config.get("notes"),
        )
        db.add(ce)
        await db.flush()

    linked_observables = 0
    if str(config.get("link_observables", "")).lower() in ("true", "1", "yes"):
        linked_observables = await _link_captured_observables_to_campaign(db, entry, campaign.id, config, user_id)

    if already_linked and not linked_observables:
        return {"status": "skipped", "message": "Entry already in campaign"}
    return {"status": "success", "campaign": campaign.name, "observables_linked": linked_observables}


async def _link_captured_observables_to_campaign(
    db: AsyncSession, entry: Entry, campaign_id: uuid.UUID, config: dict, user_id: uuid.UUID
) -> int:
    """CampaignEntity(entity_type="observable") rows for the entry's
    reporting-door observables; idempotent. Returns rows added."""
    from app.models.campaign import CampaignEntity
    from app.models.observable import EntryObservable, Observable

    def _as_list(v) -> list[str]:
        if not v:
            return []
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return [str(x).strip() for x in v if str(x).strip()]

    query = (
        select(Observable.id)
        .join(EntryObservable, EntryObservable.observable_id == Observable.id)
        .where(
            EntryObservable.entry_id == entry.id,
            EntryObservable.source != "feed",
            Observable.is_denied.is_(False),
            Observable.infra_tag.is_(None),
        )
    )
    kinds = _as_list(config.get("observable_kinds"))
    roles = _as_list(config.get("observable_roles"))
    if kinds:
        query = query.where(Observable.kind.in_(kinds))
    if roles:
        query = query.where(Observable.role.in_(roles))
    candidate_ids = set((await db.execute(query)).scalars().all())
    if not candidate_ids:
        return 0
    present = set(
        (
            await db.execute(
                select(CampaignEntity.entity_id).where(
                    CampaignEntity.campaign_id == campaign_id,
                    CampaignEntity.entity_type == "observable",
                    CampaignEntity.entity_id.in_(candidate_ids),
                )
            )
        )
        .scalars()
        .all()
    )
    added = 0
    for oid in candidate_ids - present:
        db.add(
            CampaignEntity(
                campaign_id=campaign_id, entity_type="observable", entity_id=oid, role="related", added_by=user_id
            )
        )
        added += 1
    if added:
        await db.flush()
    return added


async def _action_create_intel_report(
    db: AsyncSession,
    entry: Entry,
    config: dict,
    user_id: uuid.UUID,
    context: dict,
) -> dict:
    """Create an intelligence report from the entry.

    Config:
      - title: str (supports template variables, default: "Intel Report: {title}")
      - template_type: str (flash_alert, ioc_bulletin, actor_profile,
            campaign_tracker, landscape_report, custom. Default: flash_alert)
      - tlp_marking: str (default: "TLP:GREEN")
      - summary: str (supports template variables)
    """
    from app.models.intel_report import IntelReport

    title_template = config.get("title", "Intel Report: {title}")
    template_type = config.get("template_type", "flash_alert")
    tlp_marking = config.get("tlp_marking", "TLP:GREEN")
    summary_template = config.get("summary", "{summary}")

    title = _render_template(title_template, entry, context)
    summary = _render_template(summary_template, entry, context)

    # Gather entity IDs from context if available
    entity_ids: dict = {}
    extraction = context.get("extraction_results", {})
    for entity_type in ["ttps", "cves", "threat_actors", "malware"]:
        items = extraction.get(entity_type, [])
        if items:
            entity_ids[entity_type] = [item.get("id", "") for item in items if item.get("id")]

    report = IntelReport(
        created_by=user_id,
        title=title[:500],
        template_type=template_type,
        tlp_marking=tlp_marking,
        summary=summary,
        entry_ids=[entry.id],
        entity_ids=entity_ids,
    )
    db.add(report)
    await db.flush()
    return {"status": "success", "report_id": str(report.id)}


async def _action_track_on_threat_board(db: AsyncSession, entry: Entry) -> dict:
    """Pin the entry's linked actors/malware onto the Threats board as tracked.

    The automation seed for the board's pull path: a PIR or sector trigger
    ("healthcare ransomware", "any KEV in our stack") tracks threats without a
    human noticing first. Insert-if-absent only — a handled or muted threat was
    decided by a person, and an automation rule doesn't outrank that.
    """
    from sqlalchemy import text as sa_text

    result = await db.execute(
        sa_text(
            """
            INSERT INTO threat_board_state (entity_type, entity_key, state, new_count_at_decision)
            SELECT 'threat_actor', ea.threat_actor_id::text, 'tracked', 0
            FROM entry_threat_actors ea WHERE ea.entry_id = :eid
            UNION
            SELECT 'malware', em.malware_family_id::text, 'tracked', 0
            FROM entry_malware em WHERE em.entry_id = :eid
            ON CONFLICT (entity_type, entity_key) DO NOTHING
            """
        ),
        {"eid": entry.id},
    )
    tracked = result.rowcount or 0
    return {
        "status": "success",
        "message": f"Tracked {tracked} threat{'s' if tracked != 1 else ''} on the Threats board",
        "tracked": tracked,
    }
