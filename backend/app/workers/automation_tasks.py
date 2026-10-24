"""Celery tasks for automation rule execution."""

import logging
import random
import time as _time
from datetime import UTC, timedelta

from sqlalchemy import select, update

from app.core.metrics import (
    AUTOMATION_RUNS_TOTAL,
    CELERY_TASK_DURATION_SECONDS,
    CELERY_TASKS_TOTAL,
    CORRELATION_EVENTS_TOTAL,
)
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session
from app.workers.pipeline_logging import pipeline_stage

logger = logging.getLogger(__name__)


def _get_worker_session():
    return worker_session()


@celery_app.task(
    name="app.workers.automation_tasks.run_entry_automations",
    bind=True,
    max_retries=2,
    soft_time_limit=120,
    time_limit=180,
)
@pipeline_stage("automate")
def run_entry_automations(self, entry_id: str, feed_id: str):
    """Run all matching automation rules for a newly ingested entry."""
    start = _time.monotonic()
    try:
        run_async(_run_entry_automations(entry_id, feed_id))
        CELERY_TASKS_TOTAL.labels(task_name="run_entry_automations", status="success").inc()
    except Exception as exc:
        CELERY_TASKS_TOTAL.labels(task_name="run_entry_automations", status="retry").inc()
        logger.error(f"Error running automations for entry {entry_id}: {exc}")
        raise self.retry(exc=exc, countdown=min(300, 2**self.request.retries * 10 + random.uniform(0, 10)))
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_entry_automations").observe(_time.monotonic() - start)


async def _run_entry_automations(entry_id: str, feed_id: str):
    import uuid

    from app.automation.engine import run_automations_for_entry
    from app.models.entry import Entry

    async with _get_worker_session() as db:
        result = await db.execute(select(Entry).where(Entry.id == uuid.UUID(entry_id)))
        entry = result.scalar_one_or_none()
        if not entry:
            logger.warning(f"Entry {entry_id} not found for automation")
            return

        logs = await run_automations_for_entry(db, entry, uuid.UUID(feed_id))
        await db.commit()

        if logs:
            executed = [lg for lg in logs if lg.status != "skipped"]
            for log_entry in logs:
                AUTOMATION_RUNS_TOTAL.labels(
                    trigger_type="on_ingest", status="success" if log_entry.status != "skipped" else "skipped"
                ).inc()
            if executed:
                logger.info(f"Entry {entry_id}: {len(executed)} automation(s) executed")

                # Publish SSE event for automation results
                try:
                    from app.api.events import broadcast_event

                    broadcast_event(
                        "automation_result",
                        {"entry_id": entry_id, "rules_executed": len(executed)},
                    )
                except Exception:
                    logger.warning("Failed to publish SSE automation results for entry %s", entry_id, exc_info=True)

        # Note: correlation event detection is handled by detect_correlation_events task
        # dispatched separately with a delay to ensure autolink/extraction have completed.


@celery_app.task(
    name="app.workers.automation_tasks.run_scored_entry_automations",
    bind=True,
    max_retries=2,
    soft_time_limit=120,
    time_limit=180,
)
def run_scored_entry_automations(self, entry_id: str):
    """Run on_entry_scored rules after the signal engine scores an entry."""
    start = _time.monotonic()
    try:
        run_async(_run_scored_entry_automations(entry_id))
        CELERY_TASKS_TOTAL.labels(task_name="run_scored_entry_automations", status="success").inc()
    except Exception as exc:
        CELERY_TASKS_TOTAL.labels(task_name="run_scored_entry_automations", status="retry").inc()
        logger.error(f"Error running scored-entry automations for entry {entry_id}: {exc}")
        raise self.retry(exc=exc, countdown=min(300, 2**self.request.retries * 10 + random.uniform(0, 10)))
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_scored_entry_automations").observe(_time.monotonic() - start)


async def _run_scored_entry_automations(entry_id: str):
    import uuid

    from app.automation.engine import run_automations_for_scored_entry
    from app.models.entry import Entry

    async with _get_worker_session() as db:
        result = await db.execute(select(Entry).where(Entry.id == uuid.UUID(entry_id)))
        entry = result.scalar_one_or_none()
        if not entry:
            logger.warning(f"Entry {entry_id} not found for scored-entry automation")
            return

        logs = await run_automations_for_scored_entry(db, entry)
        await db.commit()

        for log_entry in logs:
            AUTOMATION_RUNS_TOTAL.labels(
                trigger_type="on_entry_scored",
                status="success" if log_entry.status != "skipped" else "skipped",
            ).inc()
        executed = [lg for lg in logs if lg.status != "skipped"]
        if executed:
            logger.info(f"Scored entry {entry_id}: {len(executed)} automation(s) executed")


@celery_app.task(
    name="app.workers.automation_tasks.run_observable_capture_automations",
    bind=True,
    max_retries=2,
    soft_time_limit=120,
    time_limit=180,
)
def run_observable_capture_automations(self, entry_id: str):
    """Run on_observable_captured rules after a judgment door wrote observables for an entry."""
    start = _time.monotonic()
    try:
        run_async(_run_observable_capture_automations(entry_id))
        CELERY_TASKS_TOTAL.labels(task_name="run_observable_capture_automations", status="success").inc()
    except Exception as exc:
        CELERY_TASKS_TOTAL.labels(task_name="run_observable_capture_automations", status="retry").inc()
        logger.error(f"Error running observable-capture automations for entry {entry_id}: {exc}")
        raise self.retry(exc=exc, countdown=min(300, 2**self.request.retries * 10 + random.uniform(0, 10)))
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_observable_capture_automations").observe(
            _time.monotonic() - start
        )


def dispatch_observable_capture_automations(entry_id, *, countdown: int = 5) -> None:
    """Queue the on_observable_captured runner for an entry. Called from inside
    the capturing transaction (ingest, the publisher door, analyst promote),
    so a short countdown lets that commit land before the worker reads the
    sightings. A broker hiccup must never fail the capture itself."""
    try:
        run_observable_capture_automations.apply_async(args=[str(entry_id)], countdown=countdown)
    except Exception:  # pragma: no cover - broker outage
        logger.warning("Could not queue observable-capture automations for entry %s", entry_id, exc_info=True)


async def _run_observable_capture_automations(entry_id: str):
    import uuid

    from app.automation.engine import run_automations_for_observable_capture
    from app.models.entry import Entry

    async with _get_worker_session() as db:
        result = await db.execute(select(Entry).where(Entry.id == uuid.UUID(entry_id)))
        entry = result.scalar_one_or_none()
        if not entry:
            logger.warning(f"Entry {entry_id} not found for observable-capture automation")
            return

        logs = await run_automations_for_observable_capture(db, entry)
        await db.commit()

        for log_entry in logs:
            AUTOMATION_RUNS_TOTAL.labels(
                trigger_type="on_observable_captured",
                status="success" if log_entry.status != "skipped" else "skipped",
            ).inc()
        executed = [lg for lg in logs if lg.status != "skipped"]
        if executed:
            logger.info(f"Observable capture on entry {entry_id}: {len(executed)} automation(s) executed")


@celery_app.task(
    name="app.workers.automation_tasks.detect_correlation_events",
    bind=True,
    max_retries=2,
    soft_time_limit=120,
    time_limit=180,
)
@pipeline_stage("correlation")
def detect_correlation_events(self, entry_id: str):
    """Detect correlation events for an entry after autolink/extraction have completed."""
    start = _time.monotonic()
    try:
        run_async(_detect_correlation_events(entry_id))
        CELERY_TASKS_TOTAL.labels(task_name="detect_correlation_events", status="success").inc()
    except Exception as exc:
        CELERY_TASKS_TOTAL.labels(task_name="detect_correlation_events", status="retry").inc()
        logger.error(f"Error detecting correlation events for entry {entry_id}: {exc}")
        raise self.retry(exc=exc, countdown=min(300, 2**self.request.retries * 10 + random.uniform(0, 10)))
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="detect_correlation_events").observe(_time.monotonic() - start)


async def _detect_correlation_events(entry_id: str):
    import uuid

    from app.intelligence.correlation_events import correlate_new_entities

    async with _get_worker_session() as db:
        events = await correlate_new_entities(db, uuid.UUID(entry_id))
        await db.commit()

        for event in events:
            CORRELATION_EVENTS_TOTAL.labels(event_type=event.event_type).inc()
            run_correlation_automations.delay(event.to_dict())
            logger.info(f"Correlation event: {event.event_type} for entry {entry_id}")

        if not events:
            logger.debug(f"No correlation events for entry {entry_id}")


@celery_app.task(
    name="app.workers.automation_tasks.run_correlation_automations",
    bind=True,
    max_retries=2,
    soft_time_limit=120,
    time_limit=180,
)
def run_correlation_automations(self, event_data: dict):
    """Run automation rules triggered by a correlation event."""
    start = _time.monotonic()
    try:
        run_async(_run_correlation_automations(event_data))
        CELERY_TASKS_TOTAL.labels(task_name="run_correlation_automations", status="success").inc()
    except Exception as exc:
        CELERY_TASKS_TOTAL.labels(task_name="run_correlation_automations", status="retry").inc()
        logger.error(f"Error running correlation automations: {exc}")
        raise self.retry(exc=exc, countdown=min(300, 2**self.request.retries * 10 + random.uniform(0, 10)))
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_correlation_automations").observe(_time.monotonic() - start)


async def _run_correlation_automations(event_data: dict):
    from app.automation.engine import run_automations_for_correlation_event

    async with _get_worker_session() as db:
        logs = await run_automations_for_correlation_event(db, event_data)
        await db.commit()

        if logs:
            for log_entry in logs:
                AUTOMATION_RUNS_TOTAL.labels(
                    trigger_type="on_correlation_event",
                    status="success" if log_entry.status != "skipped" else "skipped",
                ).inc()
            executed = [lg for lg in logs if lg.status != "skipped"]
            if executed:
                logger.info(f"Correlation event {event_data.get('event_type')}: {len(executed)} automation(s) executed")


@celery_app.task(name="app.workers.automation_tasks.run_scheduled_automations", soft_time_limit=300, time_limit=360)
def run_scheduled_automations():
    """Check for cron-based automation rules that are due to run."""
    start = _time.monotonic()
    try:
        run_async(_run_scheduled_automations())
        CELERY_TASKS_TOTAL.labels(task_name="run_scheduled_automations", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_scheduled_automations", status="error").inc()
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_scheduled_automations").observe(_time.monotonic() - start)


async def _run_scheduled_automations():
    """Evaluate on_schedule rules and execute their actions.

    Scheduled rules can optionally specify an entry_filter in their action configs
    to query entries from a time window (e.g. last 24h). If no filter is specified,
    actions run without a target entry (entry_id=None in the log).
    """
    from datetime import datetime, timedelta

    from app.automation.actions import execute_action
    from app.models.automation_log import AutomationLog
    from app.models.automation_rule import AutomationRule
    from app.models.entry import Entry

    async with _get_worker_session() as db:
        result = await db.execute(
            select(AutomationRule).where(
                AutomationRule.is_enabled.is_(True),
                # Ownerless rules must not fire: conditions/actions resolve against the owner
                AutomationRule.created_by.isnot(None),
                AutomationRule.trigger_type == "on_schedule",
            )
        )
        rules = result.scalars().all()

        if not rules:
            return

        now = datetime.now(UTC)

        for rule in rules:
            cron_expr = rule.trigger_config.get("cron", "")
            if not cron_expr:
                continue

            if not _should_run_cron(cron_expr, now, rule.last_triggered_at):
                continue

            # Claim the slot BEFORE running actions. Batch actions (AI briefing
            # generation) can take minutes while dispatchers arrive every 60s;
            # each one reading the not-yet-updated last_triggered_at would fire
            # the same slot again. The compare-and-set only succeeds for the
            # dispatcher that saw the value it read, and committing immediately
            # publishes the claim. A failed run consumes its slot — no retry —
            # which also prevents a persistently-erroring rule from refiring
            # every minute for the whole catch-up window.
            claim = await db.execute(
                update(AutomationRule)
                .where(
                    AutomationRule.id == rule.id,
                    AutomationRule.last_triggered_at.is_(None)
                    if rule.last_triggered_at is None
                    else AutomationRule.last_triggered_at == rule.last_triggered_at,
                )
                .values(last_triggered_at=now, run_count=AutomationRule.run_count + 1)
            )
            if claim.rowcount == 0:
                continue  # another dispatcher claimed this slot
            await db.commit()

            try:
                # Check if trigger_config specifies an entry filter for batch operations
                entry_filter = rule.trigger_config.get("entry_filter", {})
                target_entries = []

                if entry_filter:
                    query = select(Entry)
                    # Time-based filter: e.g. "since": "-24h"
                    # Use fetched_at by default — published_at reflects source dates
                    # which can be days old for infrequently-polled feeds.
                    since_str = entry_filter.get("since", "")
                    if since_str and since_str.startswith("-") and since_str.endswith("h"):
                        hours = int(since_str[1:-1])
                        since_dt = now - timedelta(hours=hours)
                        since_field = entry_filter.get("since_field", "fetched_at")
                        time_col = Entry.fetched_at if since_field == "fetched_at" else Entry.published_at
                        query = query.where(time_col >= since_dt)
                    # Combine category feeds + explicit feed IDs
                    import uuid as _uuid

                    combined_fids: set = set()
                    if entry_filter.get("category_ids"):
                        from app.models.feed import Feed

                        cat_ids = [_uuid.UUID(str(c)) for c in entry_filter["category_ids"]]
                        cat_result = await db.execute(
                            select(Feed.id).where(
                                Feed.category_id.in_(cat_ids),
                            )
                        )
                        combined_fids.update(row[0] for row in cat_result.all())
                    if entry_filter.get("feed_ids"):
                        combined_fids.update(_uuid.UUID(str(f)) for f in entry_filter["feed_ids"])
                    if combined_fids:
                        query = query.where(Entry.feed_id.in_(list(combined_fids)))

                    max_entries = rule.trigger_config.get("max_entries", 200)
                    query = query.order_by(Entry.published_at.desc()).limit(max_entries)
                    entry_result = await db.execute(query)
                    target_entries = list(entry_result.scalars().all())

                # Execute actions — check execution_mode from trigger config
                from app.automation.actions import execute_actions_batch

                execution_mode = rule.trigger_config.get("execution_mode", "per_entry")

                results = []
                if target_entries:
                    if execution_mode == "batch":
                        # Batch mode: AI tasks get all entries at once,
                        # notifications send one digest
                        results = await execute_actions_batch(db, target_entries, rule.actions, rule.created_by)
                    else:
                        # Per-entry mode: each entry runs the full action chain
                        for entry in target_entries:
                            action_context: dict = {}
                            for action in rule.actions:
                                r = await execute_action(db, entry, action, rule.created_by, context=action_context)
                                results.append(r)
                else:
                    # No entries — run actions that don't need an entry (webhook, notification with summary)
                    for action in rule.actions:
                        action_type = action.get("type", "")
                        if action_type in ("send_notification", "run_webhook"):
                            # Create a minimal dummy entry-like for notification context
                            r = await _execute_scheduled_notification(action, rule, now)
                            results.append(r)
                        else:
                            results.append({"type": action_type, "status": "skipped", "message": "No target entries"})

                log = AutomationLog(
                    rule_id=rule.id,
                    entry_id=target_entries[0].id if target_entries else None,
                    trigger_type="on_schedule",
                    status="success",
                    actions_executed=results,
                )
                db.add(log)

                AUTOMATION_RUNS_TOTAL.labels(trigger_type="on_schedule", status="success").inc()
                logger.info(f"Scheduled automation rule {rule.id} ({rule.name}) triggered, {len(results)} action(s)")

            except Exception as e:
                log = AutomationLog(
                    rule_id=rule.id,
                    entry_id=None,
                    trigger_type="on_schedule",
                    status="error",
                    error_message=str(e),
                    actions_executed=[],
                )
                db.add(log)
                AUTOMATION_RUNS_TOTAL.labels(trigger_type="on_schedule", status="error").inc()
                logger.error(f"Scheduled automation rule {rule.id} failed: {e}")

        await db.commit()


async def _execute_scheduled_notification(action: dict, rule, now) -> dict:
    """Execute a notification/webhook action for a scheduled rule without a target entry."""

    action_type = action.get("type", "")
    config = action.get("config", {})

    url = config.get("webhook_url") or config.get("url", "")
    if not url:
        return {"type": action_type, "status": "error", "message": "No URL specified"}

    # The same SSRF gate every other webhook path applies: the URL and headers
    # are whatever the rule's author typed.
    from app.automation.actions import _validate_webhook_url

    ssrf_err = await _validate_webhook_url(url)
    if ssrf_err:
        return {"type": action_type, "status": "error", "message": ssrf_err}

    payload = {
        "text": f"IntelFeed Scheduled: {rule.name}",
        "rule": {"id": str(rule.id), "name": rule.name},
        "triggered_at": now.isoformat(),
    }

    try:
        headers = config.get("headers", {})
        from app.automation.actions import _webhook_client

        async with _webhook_client(timeout=15.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            status = "success" if response.status_code < 300 else "error"
            return {"type": action_type, "status": status, "http_status": response.status_code}
    except Exception as e:
        return {"type": action_type, "status": "error", "message": str(e)}


# How far back to look for a missed cron slot. The dispatcher task can execute
# minutes late when the worker queue is saturated (or not at all across a deploy);
# any slot within this window that hasn't been served yet still fires — once.
CRON_CATCHUP_LOOKBACK = timedelta(hours=48)

# A rule that has never run gets a much shorter grace so that creating/enabling
# it doesn't immediately fire an hours-old slot.
CRON_FIRST_RUN_GRACE = timedelta(minutes=10)


def _should_run_cron(cron_expr: str, now, last_triggered_at) -> bool:
    """Determine whether a cron expression is due.

    Fires when the most recent cron slot (within CRON_CATCHUP_LOOKBACK) is newer
    than last_triggered_at, so a dispatcher that executes late — queue backlog,
    deploy restart — catches up instead of silently skipping the slot. At most
    one catch-up fire: only the latest missed slot counts, and firing advances
    last_triggered_at past it.
    """
    prev_fire = _prev_cron_fire(cron_expr, now)
    if prev_fire is None:
        return False
    if last_triggered_at is None:
        return (now - prev_fire) <= CRON_FIRST_RUN_GRACE
    return last_triggered_at < prev_fire


def _prev_cron_fire(cron_expr: str, now):
    """Most recent minute <= now matching the cron expression, or None.

    Walks back minute-by-minute, bounded by CRON_CATCHUP_LOOKBACK.
    Supports standard 5-field cron: minute hour day_of_month month day_of_week
    with *, specific values, ranges (1-5), lists (1,3,5), step values (*/5, 1-10/2).
    """
    try:
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return None

        minute, hour, dom, month, dow = parts

        candidate = now.replace(second=0, microsecond=0)
        floor = now - CRON_CATCHUP_LOOKBACK
        while candidate >= floor:
            if (
                _cron_field_matches(minute, candidate.minute, 0, 59)
                and _cron_field_matches(hour, candidate.hour, 0, 23)
                and _cron_field_matches(dom, candidate.day, 1, 31)
                and _cron_field_matches(month, candidate.month, 1, 12)
                # day of week: 0=Monday in Python, cron uses 0=Sunday
                and _cron_field_matches(dow, (candidate.weekday() + 1) % 7, 0, 6)
            ):
                return candidate
            candidate -= timedelta(minutes=1)

        return None
    except Exception:
        return None


def _cron_field_matches(field: str, value: int, range_min: int = 0, range_max: int = 59) -> bool:
    """Check if a cron field matches a value.

    Supports: *, specific values, ranges (1-5), lists (1,3,5), step values (*/5, 1-10/2)
    """
    if field == "*":
        return True

    for part in field.split(","):
        # Step values: */5 or 1-10/2
        if "/" in part:
            base, step_str = part.split("/", 1)
            step = int(step_str)
            if step <= 0:
                continue
            if base == "*":
                if (value - range_min) % step == 0:
                    return True
            elif "-" in base:
                low, high = base.split("-", 1)
                low, high = int(low), int(high)
                if low <= value <= high and (value - low) % step == 0:
                    return True
            else:
                start = int(base)
                if value >= start and (value - start) % step == 0:
                    return True
        elif "-" in part:
            low, high = part.split("-", 1)
            if int(low) <= value <= int(high):
                return True
        elif part.isdigit() and int(part) == value:
            return True

    return False
