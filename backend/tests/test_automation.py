"""Tests for automation engine: conditions, actions, triggers, and API."""

import uuid
from datetime import UTC

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.automation_log import AutomationLog
from app.models.automation_rule import AutomationRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.tag import Tag
from app.models.user import User

# ---- Fixtures ----


@pytest_asyncio.fixture
async def auto_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(title="Security News", url="https://example.com/auto-feed", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def auto_entry(db_session: AsyncSession, auto_feed: Feed) -> Entry:
    entry = Entry(
        feed_id=auto_feed.id,
        title="Critical CVE-2026-1234 in Fortinet",
        guid="auto-entry-1",
        content_text="A critical vulnerability CVE-2026-1234 was found in FortiOS. Indicators: 203.0.113.42",
        author="CISA",
        url="https://example.com/advisory/1",
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest_asyncio.fixture
async def auto_rule(db_session: AsyncSession, test_user: User) -> AutomationRule:
    rule = AutomationRule(
        created_by=test_user.id,
        name="Test Rule",
        trigger_type="on_new_entry",
        conditions={"operator": "AND", "conditions": [{"type": "content_contains", "config": {"pattern": "CVE"}}]},
        actions=[{"type": "add_tags", "config": {"tags": ["has-cve"]}}],
    )
    db_session.add(rule)
    await db_session.flush()
    return rule


# ---- Condition Evaluation Tests ----


@pytest.mark.asyncio
async def test_evaluate_conditions_empty(db_session: AsyncSession, auto_entry: Entry):
    from app.automation.conditions import evaluate_conditions

    assert await evaluate_conditions(db_session, auto_entry, {}) is True


@pytest.mark.asyncio
async def test_evaluate_conditions_content_contains(db_session: AsyncSession, auto_entry: Entry):
    from app.automation.conditions import evaluate_conditions

    cond = {"type": "content_contains", "config": {"pattern": "CVE-2026"}}
    assert await evaluate_conditions(db_session, auto_entry, cond) is True

    cond_miss = {"type": "content_contains", "config": {"pattern": "NOTHERE"}}
    assert await evaluate_conditions(db_session, auto_entry, cond_miss) is False


@pytest.mark.asyncio
async def test_evaluate_conditions_content_contains_regex(db_session: AsyncSession, auto_entry: Entry):
    from app.automation.conditions import evaluate_conditions

    cond = {"type": "content_contains", "config": {"pattern": r"CVE-\d{4}-\d+", "is_regex": True}}
    assert await evaluate_conditions(db_session, auto_entry, cond) is True


@pytest.mark.asyncio
async def test_evaluate_conditions_author_matches(db_session: AsyncSession, auto_entry: Entry):
    from app.automation.conditions import evaluate_conditions

    cond = {"type": "author_matches", "config": {"authors": ["CISA"]}}
    assert await evaluate_conditions(db_session, auto_entry, cond) is True

    cond_miss = {"type": "author_matches", "config": {"authors": ["Microsoft"]}}
    assert await evaluate_conditions(db_session, auto_entry, cond_miss) is False


@pytest.mark.asyncio
async def test_evaluate_conditions_feed_matches(db_session: AsyncSession, auto_entry: Entry, auto_feed: Feed):
    from app.automation.conditions import evaluate_conditions

    cond = {"type": "feed_matches", "config": {"feed_ids": [str(auto_feed.id)]}}
    assert await evaluate_conditions(db_session, auto_entry, cond) is True

    cond_miss = {"type": "feed_matches", "config": {"feed_ids": [str(uuid.uuid4())]}}
    assert await evaluate_conditions(db_session, auto_entry, cond_miss) is False


@pytest.mark.asyncio
async def test_evaluate_conditions_and_logic(db_session: AsyncSession, auto_entry: Entry):
    from app.automation.conditions import evaluate_conditions

    cond = {
        "operator": "AND",
        "conditions": [
            {"type": "content_contains", "config": {"pattern": "CVE"}},
            {"type": "author_matches", "config": {"authors": ["CISA"]}},
        ],
    }
    assert await evaluate_conditions(db_session, auto_entry, cond) is True

    # One fails → AND is False
    cond_fail = {
        "operator": "AND",
        "conditions": [
            {"type": "content_contains", "config": {"pattern": "CVE"}},
            {"type": "author_matches", "config": {"authors": ["Nonexistent"]}},
        ],
    }
    assert await evaluate_conditions(db_session, auto_entry, cond_fail) is False


@pytest.mark.asyncio
async def test_evaluate_conditions_or_logic(db_session: AsyncSession, auto_entry: Entry):
    from app.automation.conditions import evaluate_conditions

    cond = {
        "operator": "OR",
        "conditions": [
            {"type": "content_contains", "config": {"pattern": "NOTHERE"}},
            {"type": "author_matches", "config": {"authors": ["CISA"]}},
        ],
    }
    assert await evaluate_conditions(db_session, auto_entry, cond) is True


@pytest.mark.asyncio
async def test_evaluate_conditions_feed_type_matches(db_session: AsyncSession, auto_entry: Entry):
    from app.automation.conditions import evaluate_conditions

    cond = {"type": "feed_type_matches", "config": {"types": ["rss"]}}
    assert await evaluate_conditions(db_session, auto_entry, cond) is True

    cond_miss = {"type": "feed_type_matches", "config": {"types": ["youtube"]}}
    assert await evaluate_conditions(db_session, auto_entry, cond_miss) is False


@pytest.mark.asyncio
async def test_evaluate_conditions_tag_matches(db_session: AsyncSession, auto_entry: Entry, test_user: User):
    from app.automation.conditions import evaluate_conditions

    tag = Tag(created_by=test_user.id, name="critical")
    db_session.add(tag)
    await db_session.flush()
    from app.services.entry_tags import ensure_assignment

    await ensure_assignment(db_session, auto_entry.id, tag, test_user.id)

    cond = {"type": "tag_matches", "config": {"tags": ["critical"]}}
    # The condition sees what the rule's owner sees: their own assignment.
    assert await evaluate_conditions(db_session, auto_entry, cond, user_id=test_user.id) is True
    # Another user's rule does not see it; a global tag it would.
    assert await evaluate_conditions(db_session, auto_entry, cond) is False

    cond_miss = {"type": "tag_matches", "config": {"tags": ["nonexistent"]}}
    assert await evaluate_conditions(db_session, auto_entry, cond_miss) is False


# ---- Action Execution Tests ----


@pytest.mark.asyncio
async def test_action_add_tags(db_session: AsyncSession, auto_entry: Entry, test_user: User):
    from app.automation.actions import execute_action

    action = {"type": "add_tags", "config": {"tags": ["automated", "critical"]}}
    result = await execute_action(db_session, auto_entry, action, test_user.id)

    assert result["type"] == "add_tags"
    assert result["status"] == "success"
    assert "automated" in result["tags_added"]
    assert "critical" in result["tags_added"]


@pytest.mark.asyncio
async def test_action_add_tags_idempotent(db_session: AsyncSession, auto_entry: Entry, test_user: User):
    from app.automation.actions import execute_action

    action = {"type": "add_tags", "config": {"tags": ["test-tag"]}}
    await execute_action(db_session, auto_entry, action, test_user.id)
    # Second call should not error
    result = await execute_action(db_session, auto_entry, action, test_user.id)
    assert result["status"] == "success"
    assert result["tags_added"] == []  # Already tagged


@pytest.mark.asyncio
async def test_action_mark_priority(db_session: AsyncSession, auto_entry: Entry, test_user: User):
    from app.automation.actions import execute_action

    action = {"type": "mark_priority", "config": {"level": "high"}}
    result = await execute_action(db_session, auto_entry, action, test_user.id)

    assert result["type"] == "mark_priority"
    assert result["status"] == "success"
    assert "priority-high" in result["tags_added"]


@pytest.mark.asyncio
async def test_action_unknown_type(db_session: AsyncSession, auto_entry: Entry, test_user: User):
    from app.automation.actions import execute_action

    action = {"type": "nonexistent", "config": {}}
    result = await execute_action(db_session, auto_entry, action, test_user.id)
    assert result["status"] == "error"


# ---- Engine Pipeline Tests ----


@pytest.mark.asyncio
async def test_execute_automation_success(db_session: AsyncSession, auto_entry: Entry, auto_rule: AutomationRule):
    from app.automation.engine import execute_automation

    log = await execute_automation(db_session, auto_entry, auto_rule)
    assert log.status == "success"
    assert len(log.actions_executed) == 1
    assert log.actions_executed[0]["type"] == "add_tags"
    assert auto_rule.run_count == 1


@pytest.mark.asyncio
async def test_execute_automation_skipped(db_session: AsyncSession, auto_entry: Entry, test_user: User):
    from app.automation.engine import execute_automation

    rule = AutomationRule(
        created_by=test_user.id,
        name="Skip Rule",
        trigger_type="on_new_entry",
        conditions={"type": "content_contains", "config": {"pattern": "NONEXISTENT"}},
        actions=[{"type": "add_tags", "config": {"tags": ["should-not-apply"]}}],
    )
    db_session.add(rule)
    await db_session.flush()

    log = await execute_automation(db_session, auto_entry, rule)
    assert log.status == "skipped"


@pytest.mark.asyncio
async def test_execute_automation_dry_run(db_session: AsyncSession, auto_entry: Entry, auto_rule: AutomationRule):
    from app.automation.engine import execute_automation

    log = await execute_automation(db_session, auto_entry, auto_rule, dry_run=True)
    assert log.status == "success"
    assert all(a["status"] == "dry_run" for a in log.actions_executed)
    assert auto_rule.run_count == 0  # Dry run should not increment


@pytest.mark.asyncio
async def test_run_automations_for_entry(
    db_session: AsyncSession,
    auto_entry: Entry,
    auto_feed: Feed,
    auto_rule: AutomationRule,
):
    from app.automation.engine import run_automations_for_entry

    logs = await run_automations_for_entry(db_session, auto_entry, auto_feed.id)
    assert len(logs) == 1
    assert logs[0].status == "success"


@pytest.mark.asyncio
async def test_keyword_trigger_fires(
    db_session: AsyncSession,
    auto_entry: Entry,
    auto_feed: Feed,
    test_user: User,
):
    from app.automation.engine import run_automations_for_entry

    rule = AutomationRule(
        created_by=test_user.id,
        name="Keyword Rule",
        trigger_type="on_keyword_match",
        trigger_config={"pattern": r"CVE-\d{4}", "is_regex": True},
        conditions={},
        actions=[{"type": "add_tags", "config": {"tags": ["keyword-matched"]}}],
    )
    db_session.add(rule)
    await db_session.flush()

    logs = await run_automations_for_entry(db_session, auto_entry, auto_feed.id)
    # Should include logs from both on_new_entry rules and on_keyword_match rules
    keyword_logs = [lg for lg in logs if lg.rule_id == rule.id]
    assert len(keyword_logs) == 1
    assert keyword_logs[0].status == "success"


@pytest.mark.asyncio
async def test_scored_entry_trigger(
    db_session: AsyncSession,
    auto_entry: Entry,
    test_user: User,
):
    """on_entry_scored rules fire after scoring, with score-based conditions evaluated."""
    from app.automation.engine import run_automations_for_scored_entry

    rule = AutomationRule(
        created_by=test_user.id,
        name="High Score Rule",
        trigger_type="on_entry_scored",
        conditions={
            "operator": "AND",
            "conditions": [{"type": "priority_score_above", "config": {"min": 1.5}}],
        },
        actions=[{"type": "add_tags", "config": {"tags": ["on-radar"]}}],
    )
    db_session.add(rule)
    await db_session.flush()

    # Below threshold → rule skipped
    auto_entry.priority_score = 0.4
    logs = await run_automations_for_scored_entry(db_session, auto_entry)
    assert len(logs) == 1
    assert logs[0].status == "skipped"

    # At/above threshold → rule executes
    auto_entry.priority_score = 2.1
    logs = await run_automations_for_scored_entry(db_session, auto_entry)
    assert len(logs) == 1
    assert logs[0].status == "success"
    assert logs[0].trigger_type == "on_entry_scored"


# ---- Cron Parser Tests ----


def test_cron_field_basic():
    from app.workers.automation_tasks import _cron_field_matches

    assert _cron_field_matches("*", 5) is True
    assert _cron_field_matches("5", 5) is True
    assert _cron_field_matches("5", 6) is False
    assert _cron_field_matches("1-5", 3) is True
    assert _cron_field_matches("1-5", 6) is False
    assert _cron_field_matches("1,3,5", 3) is True
    assert _cron_field_matches("1,3,5", 4) is False


def test_cron_field_step_values():
    from app.workers.automation_tasks import _cron_field_matches

    # */5 should match 0, 5, 10, 15...
    assert _cron_field_matches("*/5", 0, 0, 59) is True
    assert _cron_field_matches("*/5", 5, 0, 59) is True
    assert _cron_field_matches("*/5", 10, 0, 59) is True
    assert _cron_field_matches("*/5", 3, 0, 59) is False

    # */6 for hours
    assert _cron_field_matches("*/6", 0, 0, 23) is True
    assert _cron_field_matches("*/6", 6, 0, 23) is True
    assert _cron_field_matches("*/6", 12, 0, 23) is True
    assert _cron_field_matches("*/6", 7, 0, 23) is False

    # 1-10/2 should match 1, 3, 5, 7, 9
    assert _cron_field_matches("1-10/2", 1, 0, 59) is True
    assert _cron_field_matches("1-10/2", 3, 0, 59) is True
    assert _cron_field_matches("1-10/2", 2, 0, 59) is False
    assert _cron_field_matches("1-10/2", 11, 0, 59) is False


def test_should_run_cron():
    from datetime import datetime

    from app.workers.automation_tasks import _should_run_cron

    # Monday 8:00 AM UTC
    now = datetime(2026, 3, 2, 8, 0, tzinfo=UTC)  # Monday

    # "0 8 * * 1-5" = weekdays at 8 AM
    assert _should_run_cron("0 8 * * 1-5", now, None) is True

    # Don't re-trigger within same minute
    assert _should_run_cron("0 8 * * 1-5", now, now) is False

    # Wrong hour
    wrong_hour = datetime(2026, 3, 2, 9, 0, tzinfo=UTC)
    assert _should_run_cron("0 8 * * 1-5", wrong_hour, None) is False


def test_should_run_cron_catches_up_missed_slot():
    """A dispatcher that executes minutes late must still fire the missed slot."""
    from datetime import datetime

    from app.workers.automation_tasks import _should_run_cron

    cron = "0 8 * * 1-5"
    # Monday 8:14 — dispatcher was stuck in the queue during the 8:00 minute.
    late = datetime(2026, 3, 2, 8, 14, tzinfo=UTC)

    # Last ran the previous Friday → Monday's 8:00 slot is unserved → fire.
    last_friday = datetime(2026, 2, 27, 8, 0, 40, tzinfo=UTC)
    assert _should_run_cron(cron, late, last_friday) is True

    # Already fired for today's slot (late) → don't fire again.
    served_today = datetime(2026, 3, 2, 8, 12, tzinfo=UTC)
    assert _should_run_cron(cron, late, served_today) is False

    # At most one catch-up: firing advances last_triggered_at past the slot,
    # so the next minute's check is a no-op.
    assert _should_run_cron(cron, late.replace(minute=15), late) is False


def test_should_run_cron_catchup_bounded():
    from datetime import datetime

    from app.workers.automation_tasks import _should_run_cron

    # Slot older than the 48h lookback is not resurrected: Wednesday 9:00
    # looking for a slot that only existed the previous Friday.
    now = datetime(2026, 3, 4, 9, 0, tzinfo=UTC)  # Wednesday
    long_ago = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    assert _should_run_cron("0 8 * * 5", now, long_ago) is False  # Fridays only

    # Never-run rules get only a short grace — creating a rule at 9:00 must
    # not immediately fire its 8:00 slot...
    assert _should_run_cron("0 8 * * 1-5", now, None) is False
    # ...but a slot a few minutes old (queue delay) still fires.
    just_after = datetime(2026, 3, 4, 8, 5, tzinfo=UTC)
    assert _should_run_cron("0 8 * * 1-5", just_after, None) is True


@pytest.mark.asyncio
@pytest.mark.committed_db
async def test_concurrent_dispatchers_fire_slot_once(db_session: AsyncSession, test_user: User, monkeypatch):
    """Two dispatcher runs overlapping in time must fire a due slot exactly once.

    Regression (2026-08-21): last_triggered_at was only written after the
    slow batch actions, so a dispatcher arriving mid-run read the stale value
    and re-fired the same slot — duplicate briefing posts. The slot must be
    claimed (compare-and-set + commit) before actions execute.
    """
    import asyncio
    from contextlib import asynccontextmanager
    from datetime import datetime

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.workers import automation_tasks
    from tests.conftest import TEST_DATABASE_URL

    rule = AutomationRule(
        created_by=test_user.id,
        name="Concurrent Cron Rule",
        trigger_type="on_schedule",
        trigger_config={"cron": "* * * * *"},
        conditions={},
        actions=[{"type": "send_notification", "config": {"message": "hi"}}],
    )
    db_session.add(rule)
    await db_session.commit()

    # Each dispatcher gets its own engine+session, like real worker tasks
    engines = []

    @asynccontextmanager
    async def fake_worker_session():
        engine = create_async_engine(TEST_DATABASE_URL)
        engines.append(engine)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as session:
            yield session

    monkeypatch.setattr(automation_tasks, "_get_worker_session", fake_worker_session)

    # Slow action keeps dispatcher A busy while dispatcher B checks the rule
    notified = []

    async def slow_notification(action, rule, now):
        await asyncio.sleep(0.3)
        notified.append(action)
        return {"type": "send_notification", "status": "success"}

    monkeypatch.setattr(automation_tasks, "_execute_scheduled_notification", slow_notification)

    # Pin the cron slot: if the two dispatchers straddle a minute boundary,
    # "* * * * *" gives the second one a genuinely new slot and it fires again
    slot = datetime.now(UTC).replace(second=0, microsecond=0)
    monkeypatch.setattr(automation_tasks, "_prev_cron_fire", lambda cron_expr, now: slot)

    async def staggered_second_dispatcher():
        await asyncio.sleep(0.05)
        await automation_tasks._run_scheduled_automations()

    try:
        await asyncio.gather(
            automation_tasks._run_scheduled_automations(),
            staggered_second_dispatcher(),
        )
    finally:
        for engine in engines:
            await engine.dispose()

    result = await db_session.execute(select(AutomationLog).where(AutomationLog.rule_id == rule.id))
    logs = result.scalars().all()
    assert len(logs) == 1
    assert len(notified) == 1

    await db_session.refresh(rule)
    assert rule.last_triggered_at is not None
    assert rule.run_count == 1


def test_prev_cron_fire():
    from datetime import datetime

    from app.workers.automation_tasks import _prev_cron_fire

    now = datetime(2026, 3, 2, 8, 14, 30, tzinfo=UTC)  # Monday
    assert _prev_cron_fire("0 8 * * 1-5", now) == datetime(2026, 3, 2, 8, 0, tzinfo=UTC)
    # Every-minute cron → current minute, seconds floored
    assert _prev_cron_fire("* * * * *", now) == datetime(2026, 3, 2, 8, 14, tzinfo=UTC)
    # Malformed expressions → None
    assert _prev_cron_fire("not a cron", now) is None
    assert _prev_cron_fire("0 8 * *", now) is None
    # No match within the lookback window (Feb 30 never exists)
    assert _prev_cron_fire("0 8 30 2 *", now) is None


# ---- API Tests ----


@pytest.mark.asyncio
async def test_create_automation_rule(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/automation/rules",
        json={
            "name": "Test API Rule",
            "trigger_type": "on_new_entry",
            "conditions": {},
            "actions": [{"type": "add_tags", "config": {"tags": ["api-test"]}}],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Test API Rule"
    assert data["is_enabled"] is True
    assert data["trigger_type"] == "on_new_entry"


@pytest.mark.asyncio
async def test_list_automation_rules(client: AsyncClient, auth_headers: dict, auto_rule: AutomationRule):
    resp = await client.get("/api/automation/rules", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert any(r["name"] == "Test Rule" for r in data["items"])


@pytest.mark.asyncio
async def test_get_automation_rule(client: AsyncClient, auth_headers: dict, auto_rule: AutomationRule):
    resp = await client.get(f"/api/automation/rules/{auto_rule.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "Test Rule"


@pytest.mark.asyncio
async def test_update_automation_rule(client: AsyncClient, auth_headers: dict, auto_rule: AutomationRule):
    resp = await client.put(
        f"/api/automation/rules/{auto_rule.id}",
        json={"name": "Updated Rule", "is_enabled": False},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "Updated Rule"
    assert resp.json()["is_enabled"] is False


@pytest.mark.asyncio
async def test_toggle_automation_rule(client: AsyncClient, auth_headers: dict, auto_rule: AutomationRule):
    resp = await client.post(f"/api/automation/rules/{auto_rule.id}/toggle", headers=auth_headers)
    assert resp.status_code == 200
    toggled = resp.json()["is_enabled"]
    assert toggled is False  # Was True, now False


@pytest.mark.asyncio
async def test_delete_automation_rule(client: AsyncClient, auth_headers: dict, auto_rule: AutomationRule):
    resp = await client.delete(f"/api/automation/rules/{auto_rule.id}", headers=auth_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_create_rule_validation(client: AsyncClient, auth_headers: dict):
    # Missing actions
    resp = await client.post(
        "/api/automation/rules",
        json={
            "name": "Bad Rule",
            "trigger_type": "on_new_entry",
            "actions": [],
        },
        headers=auth_headers,
    )
    # Request validation errors are mapped to 400 by validation_error_handler
    assert resp.status_code == 400

    # Invalid trigger type
    resp = await client.post(
        "/api/automation/rules",
        json={
            "name": "Bad Rule",
            "trigger_type": "invalid_trigger",
            "actions": [{"type": "add_tags", "config": {"tags": ["x"]}}],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_automation_logs(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
    auto_rule: AutomationRule,
):
    log = AutomationLog(
        rule_id=auto_rule.id,
        entry_id=None,
        trigger_type="on_new_entry",
        status="success",
        actions_executed=[{"type": "add_tags", "status": "success"}],
    )
    db_session.add(log)
    await db_session.flush()

    resp = await client.get(f"/api/automation/rules/{auto_rule.id}/logs", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1

    # Global logs
    resp2 = await client.get("/api/automation/logs", headers=auth_headers)
    assert resp2.status_code == 200


# ---------------------------------------------------------------------------
# Slack message building (markdown -> mrkdwn -> Block Kit)
# ---------------------------------------------------------------------------

from app.automation.actions import (  # noqa: E402
    _markdown_to_mrkdwn,
    _slack_block_messages,
    _slack_blocks_from_text,
)


def test_markdown_to_mrkdwn_converts_syntax():
    md = "**bold** and [a link](https://example.com/x) and ~~gone~~\n- item one\n* item two"
    out = _markdown_to_mrkdwn(md)
    assert "*bold*" in out
    assert "**" not in out
    assert "<https://example.com/x|a link>" in out
    assert "~gone~" in out
    assert "• item one" in out
    assert "• item two" in out


def test_markdown_to_mrkdwn_preserves_headings_and_fences():
    md = "## Section Title\n```\n**not converted** [x](https://a.b)\n```"
    out = _markdown_to_mrkdwn(md)
    assert "## Section Title" in out
    assert "**not converted** [x](https://a.b)" in out


def test_slack_blocks_headers_dividers_sections():
    text = "## TL;DR\nSummary line.\n---\n## Details\nBody text."
    blocks = _slack_blocks_from_text(text)
    types = [b["type"] for b in blocks]
    assert types == ["header", "section", "divider", "header", "section"]
    assert blocks[0]["text"]["text"] == "TL;DR"
    assert blocks[0]["text"]["type"] == "plain_text"
    assert blocks[1]["text"]["type"] == "mrkdwn"


def test_slack_blocks_split_long_text_under_section_cap():
    paragraphs = "\n\n".join(f"Paragraph {i} " + "x" * 400 for i in range(30))
    blocks = _slack_blocks_from_text(paragraphs)
    assert len(blocks) > 1
    assert all(len(b["text"]["text"]) <= 3000 for b in blocks)
    # nothing dropped beyond whitespace
    total = sum(len(b["text"]["text"]) for b in blocks)
    assert total >= len(paragraphs) - 200


def test_slack_block_messages_chunks_at_48_blocks():
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": f"block {i}"}} for i in range(100)]
    payloads = _slack_block_messages(blocks, "IntelFeed", "alerts", "fallback")
    assert len(payloads) == 3
    assert all(len(p["blocks"]) <= 48 for p in payloads)
    assert sum(len(p["blocks"]) for p in payloads) == 100
    assert payloads[0]["channel"] == "#alerts"
    assert payloads[0]["text"] == "fallback"
    assert payloads[1]["text"] == "fallback (continued)"


def test_slack_block_messages_single_payload_no_channel():
    blocks = _slack_blocks_from_text("## Hi\nbody")
    payloads = _slack_block_messages(blocks, "IntelFeed", "", "fb")
    assert len(payloads) == 1
    assert "channel" not in payloads[0]


@pytest.mark.asyncio
async def test_action_track_on_threat_board(db_session: AsyncSession, auto_entry: Entry, test_user: User):
    """The automation seed for the board's pull path — and it never outranks a
    human decision (a handled threat stays handled)."""
    from sqlalchemy import text

    from app.automation.actions import execute_action
    from app.models.malware_family import EntryMalware, MalwareFamily
    from app.models.threat_actor import EntryThreatActor, ThreatActor

    actor = ThreatActor(name="Sector Trigger Crew")
    handled = MalwareFamily(name="AlreadyDecided")
    db_session.add_all([actor, handled])
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=auto_entry.id, threat_actor_id=actor.id))
    db_session.add(EntryMalware(entry_id=auto_entry.id, malware_family_id=handled.id))
    await db_session.execute(
        text(
            "INSERT INTO threat_board_state (entity_type, entity_key, state, new_count_at_decision) "
            "VALUES ('malware', :ek, 'handled', 0)"
        ),
        {"ek": str(handled.id)},
    )
    await db_session.flush()

    result = await execute_action(db_session, auto_entry, {"type": "track_on_threat_board"}, test_user.id)
    assert result["status"] == "success"
    assert result["tracked"] == 1  # the actor; the handled malware was a human decision

    states = dict(
        (
            await db_session.execute(
                text("SELECT entity_key, state FROM threat_board_state WHERE entity_key IN (:a, :m)"),
                {"a": str(actor.id), "m": str(handled.id)},
            )
        ).all()
    )
    assert states[str(actor.id)] == "tracked"
    assert states[str(handled.id)] == "handled"


# ---- Same-story folding in batch AI actions ----


async def _story(db_session, members: list[tuple], *, title: str, sources: int):
    """A story thread over (entry, role) members."""
    from sqlalchemy import text as sql

    thread_id = uuid.uuid4()
    await db_session.execute(
        sql(
            "INSERT INTO story_threads (id, slug, title, status, entry_count, source_count, echo_count) "
            "VALUES (:id, :slug, :title, 'open', :n, :src, 0)"
        ),
        {"id": thread_id, "slug": f"s-{thread_id.hex[:8]}", "title": title, "n": len(members), "src": sources},
    )
    for entry, role in members:
        await db_session.execute(
            sql(
                "INSERT INTO story_thread_entries (id, thread_id, entry_id, role, similarity, source_key) "
                "VALUES (:id, :t, :e, :role, 0.95, 'x.example')"
            ),
            {"id": uuid.uuid4(), "t": thread_id, "e": entry.id, "role": role},
        )
    await db_session.flush()
    return thread_id


async def _batch_entry(db_session, feed, title: str, score: float) -> Entry:
    entry = Entry(
        feed_id=feed.id,
        title=title,
        guid=f"guid-{uuid.uuid4()}",
        url=f"https://example.com/{uuid.uuid4()}",
        content_text="body",
        priority_score=score,
        priority_raw=score,
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest.mark.asyncio
async def test_batch_folds_one_story_into_one_article(db_session: AsyncSession, auto_feed: Feed):
    """Eight articles about one event are one briefing item, not eight."""
    from app.intelligence.story_threads import fold_by_thread

    weak = await _batch_entry(db_session, auto_feed, "PaperCut zero-day (wire copy)", 2.0)
    best = await _batch_entry(db_session, auto_feed, "PaperCut zero-day exploited in the wild", 9.0)
    repeat = await _batch_entry(db_session, auto_feed, "PaperCut zero-day (syndicated)", 8.0)
    standalone = await _batch_entry(db_session, auto_feed, "Unrelated breach disclosure", 5.0)
    await _story(
        db_session,
        [(weak, "origin"), (best, "beat"), (repeat, "echo")],
        title="PaperCut NG/MF zero-day",
        sources=11,
    )

    kept, coverage = await fold_by_thread(db_session, [weak, best, repeat, standalone])

    assert [e.id for e in kept] == [best.id, standalone.id]
    assert coverage[best.id] == {
        "thread_title": "PaperCut NG/MF zero-day",
        "outlet_count": 11,
        "also_reported_by": 2,
    }
    # An article no thread holds is passed through untouched.
    assert standalone.id not in coverage


@pytest.mark.asyncio
async def test_batch_fold_never_lets_an_echo_represent_its_story(db_session: AsyncSession, auto_feed: Feed):
    """Even when the re-report scores higher than the article it re-reports."""
    from app.intelligence.story_threads import fold_by_thread

    original = await _batch_entry(db_session, auto_feed, "Qilin claims hospital breach", 3.0)
    loud_echo = await _batch_entry(db_session, auto_feed, "Qilin claims hospital breach (aggregated)", 9.9)
    await _story(db_session, [(original, "origin"), (loud_echo, "echo")], title="Qilin hospital", sources=4)

    kept, _ = await fold_by_thread(db_session, [original, loud_echo])

    assert [e.id for e in kept] == [original.id]


@pytest.mark.asyncio
async def test_batch_without_threads_is_unchanged(db_session: AsyncSession, auto_feed: Feed):
    """Nothing is threaded before its first sweep — the batch must survive that."""
    from app.intelligence.story_threads import fold_by_thread

    entries = [await _batch_entry(db_session, auto_feed, f"Story {i}", float(i)) for i in range(3)]

    kept, coverage = await fold_by_thread(db_session, entries)

    assert kept == entries
    assert coverage == {}


@pytest.mark.asyncio
async def test_daily_briefing_input_is_one_article_per_story(db_session: AsyncSession, auto_feed: Feed):
    """The path the live Weekday Morning Briefing actually runs through.

    The rule uses use_daily_summary, which reads the cached daily briefing —
    so the fold has to happen where that briefing's entries are gathered, not
    only in run_ai_task batches.
    """
    from app.api.entries import DailySummaryRequest, _fetch_day_entries
    from app.services.daily_briefing import day_window

    since, before = day_window("2026-09-12")
    made = []
    for i, title in enumerate(["PaperCut zero-day exploited", "PaperCut flaw under attack", "Unrelated policy change"]):
        entry = Entry(
            feed_id=auto_feed.id,
            title=title,
            guid=f"guid-{uuid.uuid4()}",
            url=f"https://example.com/{uuid.uuid4()}",
            content_text="body text",
            published_at=since,
            priority_score=float(i),
            priority_raw=float(i),
        )
        db_session.add(entry)
        made.append(entry)
    await db_session.flush()
    await _story(db_session, [(made[0], "origin"), (made[1], "beat")], title="PaperCut zero-day", sources=9)

    payloads = await _fetch_day_entries(
        db_session, None, DailySummaryRequest(day_key="2026-09-12", since=since, before=before)
    )

    titles = [p["title"] for p in payloads]
    assert "Unrelated policy change" in titles
    assert len([t for t in titles if t.startswith("PaperCut")]) == 1
    story = next(p for p in payloads if p["title"].startswith("PaperCut"))
    assert story["outlet_count"] == 9
    assert story["also_reported_by"] == 1
