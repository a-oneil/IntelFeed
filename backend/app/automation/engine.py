"""Automation engine — executes rules against entries.

Main entry points:
- execute_automation(): Run a single rule against an entry
- run_automations_for_entry(): Find and run all matching rules for an entry
- run_automations_for_correlation_event(): Run correlation-triggered rules
"""

import logging
import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.automation.actions import execute_action
from app.automation.conditions import evaluate_conditions
from app.models.automation_log import AutomationLog
from app.models.automation_rule import AutomationRule
from app.models.entry import Entry
from app.models.feed import Feed

logger = logging.getLogger(__name__)


async def _execute_action_chain(
    db: AsyncSession,
    entry: Entry,
    actions: list[dict],
    user_id: uuid.UUID,
    context: dict,
    dry_run: bool = False,
) -> list[dict]:
    """Execute a list of actions, handling branch actions recursively.

    Branch actions evaluate a condition and run one of two sub-chains
    (then_actions / else_actions). The shared context dict flows through
    whichever branch is taken, so downstream actions can reference outputs
    from either path.
    """
    results: list[dict] = []

    for action in actions:
        action_type = action.get("type", "unknown")

        if action_type == "branch":
            config = action.get("config", {})
            condition = config.get("condition", {})

            if dry_run:
                # In dry-run, report both branches without evaluating
                then_results = await _execute_action_chain(
                    db,
                    entry,
                    config.get("then_actions", []),
                    user_id,
                    context,
                    dry_run=True,
                )
                else_results = await _execute_action_chain(
                    db,
                    entry,
                    config.get("else_actions", []),
                    user_id,
                    context,
                    dry_run=True,
                )
                results.append(
                    {
                        "type": "branch",
                        "status": "dry_run",
                        "then_results": then_results,
                        "else_results": else_results,
                    }
                )
            else:
                # Evaluate the branch condition
                branch_matched = await evaluate_conditions(
                    db,
                    entry,
                    condition,
                    user_id=user_id,
                )
                branch_taken = "then" if branch_matched else "else"
                sub_actions = config.get(f"{branch_taken}_actions", [])
                sub_results = await _execute_action_chain(
                    db,
                    entry,
                    sub_actions,
                    user_id,
                    context,
                    dry_run=False,
                )
                results.append(
                    {
                        "type": "branch",
                        "status": "success",
                        "branch_taken": branch_taken,
                        "condition": condition,
                        "sub_results": sub_results,
                    }
                )
        elif dry_run:
            results.append({"type": action_type, "status": "dry_run"})
        else:
            result = await execute_action(db, entry, action, user_id, context=context)
            results.append(result)

    return results


async def execute_automation(
    db: AsyncSession, entry: Entry, rule: AutomationRule, dry_run: bool = False
) -> AutomationLog:
    """Execute a single automation rule against an entry.

    Returns the log record (not committed if dry_run=True).
    """
    from app.automation.actions import _CHAIN_STACK

    token = _CHAIN_STACK.set((*_CHAIN_STACK.get(), rule.id))
    try:
        return await _execute_automation(db, entry, rule, dry_run)
    finally:
        _CHAIN_STACK.reset(token)


async def _execute_automation(db: AsyncSession, entry: Entry, rule: AutomationRule, dry_run: bool) -> AutomationLog:
    log = AutomationLog(
        rule_id=rule.id,
        entry_id=entry.id,
        trigger_type=rule.trigger_type,
    )

    # Ownerless rules must not fire: conditions and actions (mark read, star,
    # watchlist checks) resolve against the owner's per-user state.
    if rule.created_by is None:
        log.status = "skipped"
        log.actions_executed = []
        log.error_message = "Rule has no owner; assign one by re-saving it"
        if not dry_run:
            db.add(log)
            await db.flush()
        return log

    try:
        # 1. Evaluate conditions
        if not await evaluate_conditions(db, entry, rule.conditions, user_id=rule.created_by):
            log.status = "skipped"
            log.actions_executed = []
            if not dry_run:
                db.add(log)
                await db.flush()
            return log

        # 2. Execute actions sequentially (with branch support). The context
        # starts with the entry's captured observables so message templates
        # can cite them ({observables_count} / {observables}).
        action_context: dict = {}
        try:
            from app.automation.actions import observable_template_context

            action_context.update(await observable_template_context(db, entry))
        except Exception:
            logger.debug("observable template context unavailable", exc_info=True)
        results = await _execute_action_chain(
            db,
            entry,
            rule.actions,
            rule.created_by,
            action_context,
            dry_run=dry_run,
        )

        log.status = "success"
        log.actions_executed = results

        if not dry_run:
            # Update rule stats
            rule.last_triggered_at = datetime.now(UTC)
            rule.run_count += 1
            db.add(rule)
            db.add(log)
            await db.flush()

    except Exception as e:
        log.status = "error"
        log.error_message = str(e)
        log.actions_executed = []
        logger.error(f"Automation rule {rule.id} failed: {e}")

        if not dry_run:
            db.add(log)
            await db.flush()

    return log


async def _enrich_entry_feed_type(db: AsyncSession, entry: Entry) -> None:
    """Load the feed type onto an entry so feed_type_matches conditions work."""
    if getattr(entry, "_feed_type", None):
        return
    result = await db.execute(select(Feed.feed_type).where(Feed.id == entry.feed_id))
    feed_type = result.scalar_one_or_none()
    entry._feed_type = feed_type  # type: ignore[attr-defined]


def _check_keyword_trigger(entry: Entry, trigger_config: dict) -> bool:
    """Check if entry matches an on_keyword_match trigger's pattern."""
    pattern = trigger_config.get("pattern", "")
    if not pattern:
        return False
    text = f"{entry.title or ''} {entry.content_text or ''} {entry.summary or ''}"
    is_regex = trigger_config.get("is_regex", True)
    if is_regex:
        return bool(re.search(pattern, text, re.IGNORECASE))
    return pattern.lower() in text.lower()


async def _check_cve_trigger(db: AsyncSession, entry: Entry, trigger_config: dict) -> bool:
    """Check if entry has CVEs detected (via EntryCVE records)."""
    from app.models.cve import CVE, EntryCVE

    min_severity = trigger_config.get("min_severity", "")
    severity_to_cvss = {"low": 0.1, "medium": 4.0, "high": 7.0, "critical": 9.0}

    if min_severity:
        min_cvss = severity_to_cvss.get(min_severity.lower(), 0.0)
        result = await db.execute(
            select(CVE.cvss_score)
            .join(EntryCVE, EntryCVE.cve_id == CVE.id)
            .where(EntryCVE.entry_id == entry.id, CVE.cvss_score.isnot(None))
        )
        scores = [row[0] for row in result.all()]
        return any(float(s) >= min_cvss for s in scores)
    else:
        result = await db.execute(select(EntryCVE.id).where(EntryCVE.entry_id == entry.id).limit(1))
        return result.scalar_one_or_none() is not None


async def run_automations_for_entry(db: AsyncSession, entry: Entry, feed_id: uuid.UUID) -> list[AutomationLog]:
    """Find and run all matching automation rules for a newly ingested entry.

    Handles trigger types: on_new_entry, on_keyword_match, on_cve_detected.
    """
    # Enrich entry with feed type for condition evaluation
    await _enrich_entry_feed_type(db, entry)

    # Trigger types that fire on new entries
    entry_triggers = ["on_new_entry", "on_keyword_match", "on_cve_detected"]

    # Query ALL enabled rules directly (no per-user subscription lookup)
    result = await db.execute(
        select(AutomationRule).where(
            AutomationRule.is_enabled.is_(True),
            AutomationRule.trigger_type.in_(entry_triggers),
        )
    )
    rules = result.scalars().all()

    logs = []

    for rule in rules:
        try:
            # Check trigger-specific conditions before running the rule
            should_fire = False
            match rule.trigger_type:
                case "on_new_entry":
                    should_fire = True
                case "on_keyword_match":
                    should_fire = _check_keyword_trigger(entry, rule.trigger_config)
                case "on_cve_detected":
                    should_fire = await _check_cve_trigger(db, entry, rule.trigger_config)

            if should_fire:
                log = await execute_automation(db, entry, rule)
                logs.append(log)
        except Exception as e:
            logger.error(f"Error running automation rule {rule.id} for entry {entry.id}: {e}")

    return logs


async def run_automations_for_scored_entry(db: AsyncSession, entry: Entry) -> list[AutomationLog]:
    """Run on_entry_scored rules for an entry the signal engine just scored.

    Fires from score_entry_task after signals + priority_score are persisted, so
    priority_score_above / has_signal conditions see real values — on_new_entry
    runs concurrently with scoring and reads NULL. Initial pipeline scoring only;
    rescores and backfills don't re-fire rules.
    """
    await _enrich_entry_feed_type(db, entry)
    result = await db.execute(
        select(AutomationRule).where(
            AutomationRule.is_enabled.is_(True),
            AutomationRule.trigger_type == "on_entry_scored",
        )
    )
    rules = result.scalars().all()

    logs = []
    for rule in rules:
        try:
            logs.append(await execute_automation(db, entry, rule))
        except Exception as e:
            logger.error(f"Error running automation rule {rule.id} for scored entry {entry.id}: {e}")
    return logs


async def _check_observable_capture_trigger(db: AsyncSession, entry: Entry, trigger_config: dict) -> bool:
    """on_observable_captured fires when the entry carries a reporting-door
    observable matching ``trigger_config`` — the same shape as the
    ``has_observable`` condition (kinds, roles, min_confidence,
    exclude_infra_tagged, sources), so the trigger can be narrow ("C2 only")
    and the conditions stay for everything else about the entry."""
    from app.automation.conditions import _eval_has_observable

    return await _eval_has_observable(db, entry, trigger_config or {})


async def run_automations_for_observable_capture(db: AsyncSession, entry: Entry) -> list[AutomationLog]:
    """Run on_observable_captured rules for an entry a judgment door just
    wrote observables for (the one-pass AI, the publisher IOC file, an
    analyst promote). Fires once per rule per entry: the AI door and the
    publisher door can both land on the same article, and the second capture
    must not re-notify, so a rule that already logged a run for this entry is
    skipped."""
    await _enrich_entry_feed_type(db, entry)
    result = await db.execute(
        select(AutomationRule).where(
            AutomationRule.is_enabled.is_(True),
            AutomationRule.trigger_type == "on_observable_captured",
        )
    )
    rules = result.scalars().all()
    if not rules:
        return []
    already = set(
        (
            await db.execute(
                select(AutomationLog.rule_id).where(
                    AutomationLog.entry_id == entry.id,
                    AutomationLog.rule_id.in_([r.id for r in rules]),
                    AutomationLog.status != "skipped",
                )
            )
        )
        .scalars()
        .all()
    )

    logs = []
    for rule in rules:
        if rule.id in already:
            continue
        try:
            if await _check_observable_capture_trigger(db, entry, rule.trigger_config):
                logs.append(await execute_automation(db, entry, rule))
        except Exception as e:
            logger.error(f"Error running automation rule {rule.id} for observable capture on {entry.id}: {e}")
    return logs


def _check_correlation_trigger(event_data: dict, trigger_config: dict) -> bool:
    """Check if a correlation event matches a rule's trigger_config.

    trigger_config shape:
    {
        "event_types": ["new_ttp_for_known_actor", ...],  # optional filter
        "entity_filters": {
            "threat_actor_names": ["APT29"],
            "malware_names": ["Cobalt Strike"],
            "min_article_count": 3
        }
    }
    """
    # Check event type filter
    event_types = trigger_config.get("event_types")
    if event_types and event_data.get("event_type") not in event_types:
        return False

    # Check entity filters
    filters = trigger_config.get("entity_filters", {})
    if not filters:
        return True

    actor_names = filters.get("threat_actor_names")
    if actor_names:
        # Check if any entity in the event is one of the specified actors
        matched = False
        if event_data.get("source_entity_type") == "threat_actor":
            matched = event_data.get("source_entity_label", "") in actor_names
        if event_data.get("related_entity_type") == "threat_actor":
            matched = matched or event_data.get("related_entity_label", "") in actor_names
        if not matched:
            return False

    malware_names = filters.get("malware_names")
    if malware_names:
        matched = False
        if event_data.get("source_entity_type") == "malware":
            matched = event_data.get("source_entity_label", "") in malware_names
        if event_data.get("related_entity_type") == "malware":
            matched = matched or event_data.get("related_entity_label", "") in malware_names
        if not matched:
            return False

    return True


async def run_automations_for_correlation_event(db: AsyncSession, event_data: dict) -> list[AutomationLog]:
    """Find and run all matching automation rules for a correlation event.

    Queries all users' on_correlation_event rules, checks trigger match, executes.
    """
    result = await db.execute(
        select(AutomationRule).where(
            AutomationRule.is_enabled.is_(True),
            AutomationRule.trigger_type == "on_correlation_event",
        )
    )
    rules = result.scalars().all()

    if not rules:
        return []

    # Load the entry from the event
    entry_id = event_data.get("entry_id")
    entry = None
    if entry_id:
        entry_result = await db.execute(select(Entry).where(Entry.id == uuid.UUID(str(entry_id))))
        entry = entry_result.scalar_one_or_none()

    logs = []
    for rule in rules:
        try:
            if not _check_correlation_trigger(event_data, rule.trigger_config):
                continue

            if entry:
                log = await execute_automation(db, entry, rule)
            else:
                # No entry context — log as skipped
                log = AutomationLog(
                    rule_id=rule.id,
                    entry_id=None,
                    trigger_type="on_correlation_event",
                    status="skipped",
                    actions_executed=[],
                )
                db.add(log)
                await db.flush()

            logs.append(log)
        except Exception as e:
            logger.error(f"Error running correlation rule {rule.id}: {e}")

    return logs
