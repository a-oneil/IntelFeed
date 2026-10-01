"""Automation rules API — CRUD, toggle, dry-run test, run-now, execution logs."""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.automation.actions import execute_actions_batch
from app.automation.engine import execute_automation
from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_admin_user, get_current_user
from app.database import get_db
from app.models.automation_log import AutomationLog
from app.models.automation_rule import AutomationRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.user import User
from app.schemas.automation import (
    VALID_ACTION_TYPES,
    VALID_TRIGGER_TYPES,
    AutomationLogResponse,
    AutomationRuleCreate,
    AutomationRuleResponse,
    AutomationRuleUpdate,
    AutomationRunResponse,
    RuleExportItem,
    RuleExportMetadata,
    RuleExportPayload,
    RuleImportResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# --- Templates ---


@router.get("/templates")
async def list_templates(
    category: str | None = Query(None, description="Filter by category"),
):
    """Return pre-built automation rule templates."""
    from app.automation.templates import AUTOMATION_TEMPLATES, TEMPLATE_CATEGORIES

    templates = AUTOMATION_TEMPLATES
    if category:
        templates = [t for t in templates if t["category"] == category]

    return {"templates": templates, "categories": TEMPLATE_CATEGORIES}


@router.get("/variable-contexts")
async def get_variable_contexts():
    """Template variables each action injects, so the builder can show accurate,
    context-aware hints. ``ai_prompt`` is keyed by execution mode (Run AI Task,
    Jinja {{ }}); ``notification_template`` is the single-brace ({ }) set."""
    from app.automation.variables import (
        ai_prompt_variable_contexts,
        notification_template_variables,
    )

    return {
        "ai_prompt": ai_prompt_variable_contexts(),
        "notification_template": notification_template_variables(),
    }


# --- Import / Export ---


def _rule_to_export_item(rule: AutomationRule, include_secrets: bool = False) -> dict:
    """Convert an AutomationRule to a portable export dict."""
    item = RuleExportItem(
        name=rule.name,
        description=rule.description,
        trigger_type=rule.trigger_type,
        trigger_config=rule.trigger_config or {},
        conditions=rule.conditions or {},
        actions=rule.actions or [],
        labels=rule.labels or [],
    )
    data = item.model_dump()
    if not include_secrets:
        data["actions"] = _mask_secrets_in_actions(data["actions"])
        # Mask webhook URLs in trigger_config too
        tc = data.get("trigger_config", {})
        if "webhook_url" in tc:
            tc["webhook_url"] = "<REDACTED>"
    return data


def _mask_secrets_in_actions(actions: list[dict]) -> list[dict]:
    """Replace webhook URLs and auth headers with placeholders."""
    masked = []
    for action in actions:
        a = {**action}
        config = {**(a.get("config") or {})}
        if "webhook_url" in config:
            config["webhook_url"] = "<REDACTED>"
        if "url" in config and a.get("type") == "run_webhook":
            config["url"] = "<REDACTED>"
        if "headers" in config:
            config["headers"] = {k: "<REDACTED>" for k in config["headers"]}
        # Recurse into branch sub-actions
        if a.get("type") == "branch":
            if "then_actions" in config:
                config["then_actions"] = _mask_secrets_in_actions(config["then_actions"])
            if "else_actions" in config:
                config["else_actions"] = _mask_secrets_in_actions(config["else_actions"])
        a["config"] = config
        masked.append(a)
    return masked


def _collect_action_warnings(actions: list[dict]) -> list[str]:
    """Return warnings for actions that reference instance-specific UUIDs."""
    warnings = []
    uuid_action_fields = {
        "add_to_campaign": "campaign_id",
        "chain_rule": "rule_id",
        "run_ai_task": "task_id",
    }
    for action in actions:
        atype = action.get("type", "")
        config = action.get("config", {})
        if atype in uuid_action_fields:
            field = uuid_action_fields[atype]
            if config.get(field):
                warnings.append(
                    f"Action '{atype}' references {field}='{config[field]}' which may not exist on the target instance"
                )
        if atype == "branch":
            warnings.extend(_collect_action_warnings(config.get("then_actions", [])))
            warnings.extend(_collect_action_warnings(config.get("else_actions", [])))
    return warnings


@router.get("/rules/export", response_model=RuleExportPayload)
async def export_rules(
    rule_ids: str | None = Query(None, description="Comma-separated rule IDs to export (all if omitted)"),
    include_secrets: bool = Query(False, description="Include webhook URLs and auth headers"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export automation rules as a portable JSON payload."""
    query = select(AutomationRule)
    if rule_ids:
        ids = [uuid.UUID(rid.strip()) for rid in rule_ids.split(",") if rid.strip()]
        query = query.where(AutomationRule.id.in_(ids))

    result = await db.execute(query.order_by(AutomationRule.created_at))
    rules = result.scalars().all()

    if not rules:
        raise AppError(code="not_found", message="No rules found to export", status_code=404)

    return RuleExportPayload(
        intelfeed_rule_export=RuleExportMetadata(
            exported_at=datetime.now(UTC),
        ),
        rules=[_rule_to_export_item(r, include_secrets) for r in rules],
    )


@router.get("/rules/export/{rule_id}", response_model=RuleExportPayload)
async def export_single_rule(
    rule_id: uuid.UUID = Path(..., description="ID of the rule to export"),
    include_secrets: bool = Query(False, description="Include webhook URLs and auth headers instead of redacting them"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export a single automation rule."""
    rule = await _get_rule(db, rule_id)
    return RuleExportPayload(
        intelfeed_rule_export=RuleExportMetadata(
            exported_at=datetime.now(UTC),
        ),
        rules=[_rule_to_export_item(rule, include_secrets)],
    )


def _validate_action_types(actions: list[dict]) -> list[str]:
    """Recursively validate action types, returning error strings for unknowns."""
    errors = []
    for action in actions:
        atype = action.get("type", "")
        if atype not in VALID_ACTION_TYPES:
            errors.append(f"Unknown action type: '{atype}'")
        if atype == "branch":
            config = action.get("config", {})
            errors.extend(_validate_action_types(config.get("then_actions", [])))
            errors.extend(_validate_action_types(config.get("else_actions", [])))
    return errors


@router.post("/rules/import", response_model=RuleImportResponse)
async def import_rules(
    body: RuleExportPayload,
    enabled_on_import: bool = Query(False, description="Enable imported rules immediately"),
    overwrite_existing: bool = Query(False, description="Update rules with matching names"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Import automation rules from an export payload."""
    version = body.intelfeed_rule_export.version
    if version != 1:
        raise AppError(
            code="unsupported_version",
            message=f"Export format version {version} is not supported (expected 1)",
            status_code=400,
        )

    imported_rules: list[AutomationRule] = []
    skipped = 0
    errors: list[str] = []
    warnings: list[str] = []

    # Pre-load existing rule names — the caller's own rules only. Rules run
    # with their owner's identity, so an import must never overwrite (or plant
    # actions into) someone else's rule. Admins overwrite by name instance-wide.
    existing_q = select(AutomationRule)
    if user.role != "admin":
        existing_q = existing_q.where(AutomationRule.created_by == user.id)
    existing_result = await db.execute(existing_q)
    existing_by_name: dict[str, AutomationRule] = {r.name: r for r in existing_result.scalars().all()}

    for item in body.rules:
        # Validate trigger type
        if item.trigger_type not in VALID_TRIGGER_TYPES:
            errors.append(f"Rule '{item.name}': unknown trigger type '{item.trigger_type}'")
            continue

        # Validate action types
        action_errors = _validate_action_types(item.actions)
        if action_errors:
            errors.append(f"Rule '{item.name}': {'; '.join(action_errors)}")
            continue

        # Collect warnings about instance-specific references
        warnings.extend(f"Rule '{item.name}': {w}" for w in _collect_action_warnings(item.actions))

        existing = existing_by_name.get(item.name)
        if existing and not overwrite_existing:
            skipped += 1
            continue

        if existing and overwrite_existing:
            # Update in place
            existing.description = item.description
            existing.trigger_type = item.trigger_type
            existing.trigger_config = item.trigger_config
            existing.conditions = item.conditions
            existing.actions = item.actions
            existing.labels = item.labels
            existing.is_enabled = enabled_on_import
            db.add(existing)
            await db.flush()
            await db.refresh(existing)
            imported_rules.append(existing)
        else:
            # Create new
            rule = AutomationRule(
                created_by=user.id,
                name=item.name,
                description=item.description,
                trigger_type=item.trigger_type,
                trigger_config=item.trigger_config,
                conditions=item.conditions,
                actions=item.actions,
                labels=item.labels,
                is_enabled=enabled_on_import,
            )
            db.add(rule)
            await db.flush()
            await db.refresh(rule)
            imported_rules.append(rule)
            existing_by_name[rule.name] = rule

    return RuleImportResponse(
        imported=len(imported_rules),
        skipped=skipped,
        errors=errors,
        warnings=warnings,
        rules=[AutomationRuleResponse.model_validate(r) for r in imported_rules],
    )


# --- Rule CRUD ---


@router.get("/rules", response_model=PaginatedResponse[AutomationRuleResponse])
async def list_rules(
    limit: int = Query(50, ge=1, le=500, description="Maximum number of rules to return"),
    offset: int = Query(0, ge=0, description="Number of rules to skip for pagination"),
    label: str | None = Query(None, description="Filter rules by label"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List automation rules, newest first, optionally filtered by label."""
    base = select(AutomationRule)
    count_q = select(func.count()).select_from(AutomationRule)

    if label:
        # JSONB contains — filter rules whose labels array includes this value
        label_filter = AutomationRule.labels.contains([label])
        base = base.where(label_filter)
        count_q = count_q.where(label_filter)

    total = (await db.execute(count_q)).scalar() or 0
    result = await db.execute(base.order_by(AutomationRule.created_at.desc()).limit(limit).offset(offset))
    items = result.scalars().all()

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.post("/rules", response_model=AutomationRuleResponse, status_code=201)
async def create_rule(
    body: AutomationRuleCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new automation rule owned by the current user."""
    rule = AutomationRule(
        created_by=user.id,
        name=body.name,
        description=body.description,
        trigger_type=body.trigger_type,
        trigger_config=body.trigger_config,
        conditions=body.conditions,
        actions=body.actions,
        labels=body.labels,
        is_enabled=body.is_enabled,
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule


@router.get("/rules/{rule_id}", response_model=AutomationRuleResponse)
async def get_rule(
    rule_id: uuid.UUID = Path(..., description="ID of the automation rule"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return a single automation rule by ID."""
    return await _get_rule(db, rule_id)


@router.put("/rules/{rule_id}", response_model=AutomationRuleResponse)
async def update_rule(
    rule_id: uuid.UUID = Path(..., description="ID of the automation rule to update"),
    body: AutomationRuleUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Partially update an automation rule; only the fields present in the body are changed."""
    rule = await _get_rule(db, rule_id)
    _assert_rule_owner(rule, user)

    if body.name is not None:
        rule.name = body.name
    if body.description is not None:
        rule.description = body.description
    if body.trigger_type is not None:
        rule.trigger_type = body.trigger_type
    if body.trigger_config is not None:
        rule.trigger_config = body.trigger_config
    if body.conditions is not None:
        rule.conditions = body.conditions
    if body.actions is not None:
        rule.actions = body.actions
    if body.labels is not None:
        rule.labels = body.labels
    if body.is_enabled is not None:
        rule.is_enabled = body.is_enabled

    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: uuid.UUID = Path(..., description="ID of the automation rule to delete"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete an automation rule."""
    rule = await _get_rule(db, rule_id)
    _assert_rule_owner(rule, user)
    await db.delete(rule)
    await db.flush()


# --- Toggle & Test ---


@router.post("/rules/{rule_id}/toggle", response_model=AutomationRuleResponse)
async def toggle_rule(
    rule_id: uuid.UUID = Path(..., description="ID of the automation rule to toggle"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Flip a rule's enabled state and return the updated rule."""
    rule = await _get_rule(db, rule_id)
    _assert_rule_owner(rule, user)
    rule.is_enabled = not rule.is_enabled
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule


@router.post("/rules/{rule_id}/test", response_model=AutomationLogResponse)
async def test_rule(
    rule_id: uuid.UUID = Path(..., description="ID of the automation rule to dry-run"),
    entry_id: uuid.UUID = Query(..., description="Entry ID to test the rule against"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Dry-run a rule against a specific entry without persisting results."""
    rule = await _get_rule(db, rule_id)
    _assert_rule_owner(rule, user)

    result = await db.execute(select(Entry).where(Entry.id == entry_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    log = await execute_automation(db, entry, rule, dry_run=True)
    return AutomationLogResponse(
        id=log.id if log.id else uuid.uuid4(),
        rule_id=rule.id,
        entry_id=entry.id,
        trigger_type=log.trigger_type,
        status=log.status,
        actions_executed=log.actions_executed,
        error_message=log.error_message,
        executed_at=log.executed_at,
    )


# --- Run Now ---


@router.post("/rules/{rule_id}/run", response_model=AutomationRunResponse)
async def run_rule_now(
    rule_id: uuid.UUID = Path(..., description="ID of the automation rule to execute"),
    limit: int = Query(50, ge=1, le=500, description="Max entries to evaluate"),
    hours: int = Query(24, ge=1, le=720, description="Look back this many hours for entries"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Execute a rule now against recent entries.

    Evaluates the rule's conditions and trigger logic against each entry,
    executing actions on those that match.
    """
    rule = await _get_rule(db, rule_id)
    _assert_rule_owner(rule, user)

    # Read limits from trigger_config, with query params as override
    entry_filter = rule.trigger_config.get("entry_filter", {})
    config_max = rule.trigger_config.get("max_entries")
    effective_limit = limit if limit != 50 else (config_max or 50)
    # Respect entry_filter.since for lookback hours
    since_str = entry_filter.get("since", "")
    if since_str and since_str.startswith("-") and since_str.endswith("h"):
        config_hours = int(since_str[1:-1])
    else:
        config_hours = None
    effective_hours = hours if hours != 24 else (config_hours or 24)

    # Build entry query: recent entries
    since = datetime.now(UTC) - timedelta(hours=effective_hours)
    entry_query = (
        select(Entry)
        .where(
            Entry.fetched_at >= since,
        )
        .order_by(Entry.fetched_at.desc())
        .limit(effective_limit)
    )
    filter_feed_ids = entry_filter.get("feed_ids")
    filter_category_ids = entry_filter.get("category_ids")

    # Combine category feeds + explicit feed IDs
    combined_feed_ids: set[uuid.UUID] = set()
    if filter_category_ids:
        cat_feed_result = await db.execute(
            select(Feed.id).where(
                Feed.category_id.in_([uuid.UUID(cid) for cid in filter_category_ids]),
            )
        )
        combined_feed_ids.update(row[0] for row in cat_feed_result.all())
    if filter_feed_ids:
        combined_feed_ids.update(uuid.UUID(fid) for fid in filter_feed_ids)
    if combined_feed_ids:
        entry_query = entry_query.where(Entry.feed_id.in_(list(combined_feed_ids)))

    result = await db.execute(entry_query)
    entries = result.scalars().all()

    # Enrich entries with feed type for condition evaluation
    from app.automation.conditions import evaluate_conditions
    from app.automation.engine import (
        _check_cve_trigger,
        _check_keyword_trigger,
        _check_observable_capture_trigger,
        _enrich_entry_feed_type,
    )

    # Filter entries by trigger logic and conditions
    matched_entries: list[Entry] = []
    for entry in entries:
        try:
            await _enrich_entry_feed_type(db, entry)

            # Check trigger-specific logic
            should_fire = True
            match rule.trigger_type:
                case "on_keyword_match":
                    should_fire = _check_keyword_trigger(entry, rule.trigger_config)
                case "on_cve_detected":
                    should_fire = await _check_cve_trigger(db, entry, rule.trigger_config)
                case "on_observable_captured":
                    should_fire = await _check_observable_capture_trigger(db, entry, rule.trigger_config)
                case "on_new_entry" | "on_schedule" | "on_manual":
                    should_fire = True

            if not should_fire:
                continue

            # Also evaluate rule conditions
            if not await evaluate_conditions(db, entry, rule.conditions, user_id=rule.created_by):
                continue

            matched_entries.append(entry)
        except Exception as e:
            logger.error(f"Run-now filter error for rule {rule.id}, entry {entry.id}: {e}")

    entries_matched = len(matched_entries)

    # Check execution mode from trigger config
    execution_mode = rule.trigger_config.get("execution_mode", "per_entry")

    logs: list[AutomationLog] = []

    if execution_mode == "batch" and matched_entries:
        # Batch mode: per-entry actions run individually, batch actions run once as digest
        try:
            results = await execute_actions_batch(db, matched_entries, rule.actions, rule.created_by)
            log = AutomationLog(
                rule_id=rule.id,
                entry_id=matched_entries[0].id,
                trigger_type=rule.trigger_type,
                status="success",
                actions_executed=results,
            )
            rule.last_triggered_at = datetime.now(UTC)
            rule.run_count += 1
            db.add(rule)
            db.add(log)
            await db.flush()
            logs.append(log)
        except Exception as e:
            logger.error(f"Run-now batch error for rule {rule.id}: {e}")
            log = AutomationLog(
                rule_id=rule.id,
                entry_id=matched_entries[0].id if matched_entries else None,
                trigger_type=rule.trigger_type,
                status="error",
                error_message=str(e),
                actions_executed=[],
            )
            db.add(log)
            await db.flush()
            logs.append(log)
    else:
        # No batch actions — run per-entry as before
        for entry in matched_entries:
            try:
                log = await execute_automation(db, entry, rule)
                logs.append(log)
            except Exception as e:
                logger.error(f"Run-now error for rule {rule.id}, entry {entry.id}: {e}")

    return AutomationRunResponse(
        logs=[
            AutomationLogResponse(
                id=log.id or uuid.uuid4(),
                rule_id=rule.id,
                entry_id=log.entry_id,
                trigger_type=log.trigger_type,
                status=log.status,
                actions_executed=log.actions_executed,
                error_message=log.error_message,
                executed_at=log.executed_at,
            )
            for log in logs
        ],
        entries_evaluated=len(entries),
        entries_matched=entries_matched,
        message=f"Evaluated {len(entries)} entries, {entries_matched} matched and executed",
    )


# --- Logs ---


@router.get("/rules/{rule_id}/logs", response_model=PaginatedResponse[AutomationLogResponse])
async def get_rule_logs(
    rule_id: uuid.UUID = Path(..., description="ID of the automation rule"),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of log entries to return"),
    offset: int = Query(0, ge=0, description="Number of log entries to skip for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List execution logs for one rule, most recent first."""
    # Verify rule exists
    rule = await _get_rule(db, rule_id)

    count_q = select(func.count()).select_from(AutomationLog).where(AutomationLog.rule_id == rule_id)
    total = (await db.execute(count_q)).scalar() or 0

    result = await db.execute(
        select(AutomationLog)
        .where(AutomationLog.rule_id == rule_id)
        .order_by(AutomationLog.executed_at.desc())
        .limit(limit)
        .offset(offset)
    )
    items = result.scalars().all()
    log_items = [_log_to_response(log, rule.name) for log in items]

    return PaginatedResponse(
        items=log_items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total
    )


@router.get("/logs", response_model=PaginatedResponse[AutomationLogResponse])
async def list_all_logs(
    limit: int = Query(50, ge=1, le=500, description="Maximum number of log entries to return"),
    offset: int = Query(0, ge=0, description="Number of log entries to skip for pagination"),
    exclude_status: str | None = Query(None, description="Comma-separated statuses to exclude (e.g. 'skipped')"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List execution logs across all automation rules, most recent first."""
    from sqlalchemy.orm import selectinload

    excluded = [s.strip() for s in exclude_status.split(",") if s.strip()] if exclude_status else []

    count_q = select(func.count()).select_from(AutomationLog)
    data_q = select(AutomationLog).options(selectinload(AutomationLog.rule)).order_by(AutomationLog.executed_at.desc())

    if excluded:
        count_q = count_q.where(AutomationLog.status.notin_(excluded))
        data_q = data_q.where(AutomationLog.status.notin_(excluded))

    total = (await db.execute(count_q)).scalar() or 0

    result = await db.execute(data_q.limit(limit).offset(offset))
    items = result.scalars().all()
    log_items = [_log_to_response(log, log.rule.name if log.rule else None) for log in items]

    return PaginatedResponse(
        items=log_items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total
    )


@router.delete("/logs", status_code=204)
async def clear_all_logs(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete all automation logs. Admin only."""
    await db.execute(sa_delete(AutomationLog))
    await db.flush()


# --- Helpers ---


def _log_to_response(log: AutomationLog, rule_name: str | None = None) -> AutomationLogResponse:
    return AutomationLogResponse(
        id=log.id,
        rule_id=log.rule_id,
        entry_id=log.entry_id,
        trigger_type=log.trigger_type,
        status=log.status,
        actions_executed=log.actions_executed,
        error_message=log.error_message,
        executed_at=log.executed_at,
        rule_name=rule_name,
    )


def _assert_rule_owner(rule: AutomationRule, user: User) -> None:
    """Rules execute with their owner's identity, so only the owner (or an admin) may change or run them."""
    if user.role != "admin" and rule.created_by != user.id:
        raise AppError(
            code="forbidden",
            message="Only the rule's owner or an admin can modify or run this rule",
            status_code=403,
        )


async def _get_rule(db: AsyncSession, rule_id: uuid.UUID) -> AutomationRule:
    result = await db.execute(select(AutomationRule).where(AutomationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise AppError(code="not_found", message="Automation rule not found", status_code=404)
    return rule
