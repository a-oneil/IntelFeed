"""Tests for the shared (global) daily-summary scoping.

The default, unfiltered daily briefing is cached once under a sentinel user and
shared across accounts; filtered summaries stay per-user. These tests lock the
scope predicate, the cache-key derivation, and the user-less entry fetch used by
the Generate Daily Summaries job.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.entries import (
    GLOBAL_SUMMARY_USER,
    DailySummaryRequest,
    _daily_summary_target_id,
    _fetch_day_entries,
    _filters_for_cache_key,
    _is_global_scope,
    _scope_user_id,
)
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.entry import Entry
from app.models.entry_state import UserEntryState
from app.models.feed import Feed
from app.models.user import User


def _default_filters() -> dict:
    return _filters_for_cache_key(
        DailySummaryRequest(
            day_key="2026-07-08",
            since=datetime(2026, 7, 8, tzinfo=UTC),
            before=datetime(2026, 7, 8, 23, 59, tzinfo=UTC),
        )
    )


# --- scope predicate ---------------------------------------------------------


def test_is_global_scope_default_is_global():
    assert _is_global_scope(_default_filters()) is True


def test_is_global_scope_dedup_off_still_global():
    # dedup is not a per-user/per-view distinction — a dedup toggle alone stays global.
    assert _is_global_scope({"dedup": False}) is True


@pytest.mark.parametrize(
    "override",
    [
        {"feed_id": str(uuid.uuid4())},
        {"category_id": str(uuid.uuid4())},
        {"is_starred": True},
        {"is_bookmarked": True},
        {"change_type": "added"},
        {"country_id": str(uuid.uuid4())},
        {"campaign_id": str(uuid.uuid4())},
    ],
)
def test_is_global_scope_any_filter_makes_it_per_user(override):
    filters = {**_default_filters(), **override}
    assert _is_global_scope(filters) is False


# --- cache-key derivation ----------------------------------------------------


def test_scope_user_id_global_vs_filtered():
    user_id = uuid.uuid4()
    assert _scope_user_id(user_id, _default_filters()) == GLOBAL_SUMMARY_USER
    filtered = {**_default_filters(), "is_starred": True}
    assert _scope_user_id(user_id, filtered) == user_id


def test_global_target_id_is_user_independent():
    """Two different users resolve to the same shared target_id for the default view."""
    a, b = uuid.uuid4(), uuid.uuid4()
    filters = _default_filters()
    tid_a = _daily_summary_target_id(_scope_user_id(a, filters), "2026-07-08", filters)
    tid_b = _daily_summary_target_id(_scope_user_id(b, filters), "2026-07-08", filters)
    assert tid_a == tid_b
    # ...and differs from either user's per-user key (used as legacy fallback).
    assert tid_a != _daily_summary_target_id(a, "2026-07-08", filters)


def test_filtered_target_id_is_per_user():
    a, b = uuid.uuid4(), uuid.uuid4()
    filters = {**_default_filters(), "is_starred": True}
    tid_a = _daily_summary_target_id(_scope_user_id(a, filters), "2026-07-08", filters)
    tid_b = _daily_summary_target_id(_scope_user_id(b, filters), "2026-07-08", filters)
    assert tid_a != tid_b


# --- user-less entry fetch (the job's global path) ---------------------------


@pytest_asyncio.fixture
async def day_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(title="Day Feed", url="https://example.com/day.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    return feed


async def _make_entry(db: AsyncSession, feed: Feed, title: str, when: datetime) -> Entry:
    entry = Entry(
        feed_id=feed.id,
        title=title,
        guid=f"guid-{title}",
        url=f"https://example.com/{title}",
        content_text=f"Content for {title}.",
        published_at=when,
    )
    db.add(entry)
    await db.flush()
    return entry


@pytest.mark.asyncio
async def test_fetch_day_entries_global_ignores_hidden(db_session: AsyncSession, day_feed: Feed, test_user: User):
    """The global path (user=None) includes an entry that the user has hidden;
    the per-user path excludes it."""
    day = datetime(2026, 7, 8, 12, 0, tzinfo=UTC)
    e1 = await _make_entry(db_session, day_feed, "visible", day)
    e2 = await _make_entry(db_session, day_feed, "hidden", day)

    # User hides e2.
    db_session.add(UserEntryState(user_id=test_user.id, entry_id=e2.id, is_hidden=True))
    await db_session.flush()

    req = DailySummaryRequest(
        day_key="2026-07-08",
        since=day - timedelta(hours=12),
        before=day + timedelta(hours=12),
    )

    global_titles = {p["title"] for p in await _fetch_day_entries(db_session, None, req)}
    assert global_titles == {"visible", "hidden"}

    user_titles = {p["title"] for p in await _fetch_day_entries(db_session, test_user, req)}
    assert user_titles == {"visible"}
    assert e1.title in user_titles


# --- GET /entries/daily-summary fallback chain -------------------------------

_DAY = "2026-07-08"


@pytest_asyncio.fixture
async def daily_summary_task(db_session: AsyncSession) -> AITask:
    task = AITask(
        name="daily_summary",
        display_name="Daily Summary",
        default_prompt_template="Summarize: {entries}",
    )
    db_session.add(task)
    await db_session.flush()
    return task


async def _add_result(db: AsyncSession, task: AITask, target_id, summary: str) -> AIResult:
    row = AIResult(
        task_id=task.id,
        target_type="daily_summary",
        target_id=target_id,
        is_current=True,
        parsed_result={"summary": summary},
    )
    db.add(row)
    await db.flush()
    return row


@pytest.mark.asyncio
async def test_get_daily_summary_resolves_shared_row(client, auth_headers, db_session, daily_summary_task, test_user):
    """The default all-view read resolves the shared (sentinel-keyed) row."""
    shared_id = _daily_summary_target_id(GLOBAL_SUMMARY_USER, _DAY, {"dedup": True})
    await _add_result(db_session, daily_summary_task, shared_id, "SHARED BRIEFING")

    resp = await client.get(f"/api/entries/daily-summary?day_key={_DAY}&dedup=true", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["cached"] is True
    assert body["summary"] == "SHARED BRIEFING"


@pytest.mark.asyncio
async def test_get_daily_summary_falls_back_to_own_per_user_row(
    client, auth_headers, db_session, daily_summary_task, test_user
):
    """Before a shared row exists, a user's own previously-cached (per-user) row
    still resolves."""
    per_user_id = _daily_summary_target_id(test_user.id, _DAY, {"dedup": True})
    await _add_result(db_session, daily_summary_task, per_user_id, "MY OLD SUMMARY")

    resp = await client.get(f"/api/entries/daily-summary?day_key={_DAY}&dedup=true", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["cached"] is True
    assert body["summary"] == "MY OLD SUMMARY"


@pytest.mark.asyncio
async def test_get_daily_summary_ignores_other_users_per_user_row(client, auth_headers, db_session, daily_summary_task):
    """A different user's stale per-user row must not leak into this user's read."""
    other_user_id = uuid.uuid4()
    other_id = _daily_summary_target_id(other_user_id, _DAY, {"dedup": True})
    await _add_result(db_session, daily_summary_task, other_id, "SOMEONE ELSE'S SUMMARY")

    resp = await client.get(f"/api/entries/daily-summary?day_key={_DAY}&dedup=true", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["cached"] is False
    assert body["summary"] is None


# --- reuse by the automation action ------------------------------------------
# The Slack/Discord briefing rule reads this same shared row instead of running
# a second LLM pass over the same day. These lock that reuse path.


@pytest.mark.asyncio
async def test_get_cached_daily_summary_reads_shared_row(db_session, daily_summary_task):
    from app.services.daily_briefing import get_cached_daily_summary

    shared_id = _daily_summary_target_id(GLOBAL_SUMMARY_USER, _DAY, {"dedup": True})
    await _add_result(db_session, daily_summary_task, shared_id, "SHARED BRIEFING")

    assert await get_cached_daily_summary(db_session, _DAY) == "SHARED BRIEFING"


@pytest.mark.asyncio
async def test_get_cached_daily_summary_missing_returns_none(db_session, daily_summary_task):
    from app.services.daily_briefing import get_cached_daily_summary

    assert await get_cached_daily_summary(db_session, _DAY) is None


@pytest.mark.asyncio
async def test_use_daily_summary_action_fills_ai_summary(db_session, daily_summary_task, day_feed):
    """The action populates the same context key {ai_summary} renders from,
    without calling the model."""
    from app.automation.actions import _action_use_daily_summary
    from app.services.daily_briefing import yesterday_key

    day = yesterday_key()
    shared_id = _daily_summary_target_id(GLOBAL_SUMMARY_USER, day, {"dedup": True})
    await _add_result(db_session, daily_summary_task, shared_id, "## TL;DR\nReused briefing.")

    entry = await _make_entry(db_session, day_feed, "any", datetime.now(UTC))
    ctx: dict = {}
    result = await _action_use_daily_summary(db_session, [entry], {}, ctx)

    assert result["status"] == "success"
    assert result["source"] == "cache"
    assert result["day"] == day
    assert ctx["ai_summary"] == "## TL;DR\nReused briefing."
    assert ctx["ai_results"]["daily_summary"]["summary"] == "## TL;DR\nReused briefing."


@pytest.mark.asyncio
async def test_use_daily_summary_action_skips_when_missing(db_session, daily_summary_task, day_feed):
    """on_missing='skip' leaves the context empty so the notification action
    skips rather than posting an empty message."""
    from app.automation.actions import _action_use_daily_summary

    entry = await _make_entry(db_session, day_feed, "any", datetime.now(UTC))
    ctx: dict = {}
    result = await _action_use_daily_summary(db_session, [entry], {"on_missing": "skip"}, ctx)

    assert result["status"] == "skipped"
    assert "ai_summary" not in ctx


@pytest.mark.asyncio
async def test_use_daily_summary_action_generate_without_task_is_skipped(db_session, day_feed):
    """on_missing='generate' with no daily_summary AITask configured degrades to
    a skip rather than raising through the rule."""
    from app.automation.actions import _action_use_daily_summary

    entry = await _make_entry(db_session, day_feed, "any", datetime.now(UTC))
    ctx: dict = {}
    result = await _action_use_daily_summary(db_session, [entry], {"on_missing": "generate"}, ctx)

    assert result["status"] == "skipped"
    assert "ai_summary" not in ctx


@pytest.mark.asyncio
async def test_use_daily_summary_action_rejects_bad_day(db_session, day_feed):
    from app.automation.actions import _action_use_daily_summary

    entry = await _make_entry(db_session, day_feed, "any", datetime.now(UTC))
    result = await _action_use_daily_summary(db_session, [entry], {"day": "last_tuesday"}, {})
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_use_daily_summary_runs_once_per_batch(db_session, daily_summary_task, day_feed):
    """Registered as a batch action: one briefing for the whole run, not one per
    entry (the bug that would reintroduce N generations)."""
    from app.automation.actions import BATCH_ACTIONS, execute_actions_batch
    from app.services.daily_briefing import yesterday_key

    assert "use_daily_summary" in BATCH_ACTIONS

    day = yesterday_key()
    shared_id = _daily_summary_target_id(GLOBAL_SUMMARY_USER, day, {"dedup": True})
    await _add_result(db_session, daily_summary_task, shared_id, "BRIEFING")

    entries = [await _make_entry(db_session, day_feed, f"e{i}", datetime.now(UTC)) for i in range(3)]
    results = await execute_actions_batch(
        db_session, entries, [{"type": "use_daily_summary", "config": {}}], uuid.uuid4()
    )

    assert len(results) == 1
    assert results[0]["type"] == "use_daily_summary"
    assert results[0]["status"] == "success"


# --- outbound link rewriting -------------------------------------------------


@pytest.mark.asyncio
async def test_externalize_entry_links_swaps_in_app_links(db_session, day_feed):
    """In-app reader links become the articles' own URLs for outbound posts."""
    from app.services.daily_briefing import externalize_entry_links

    a = await _make_entry(db_session, day_feed, "alpha", datetime.now(UTC))
    b = await _make_entry(db_session, day_feed, "beta", datetime.now(UTC))
    md = f"See [Alpha](/?entry={a.id}) and [Beta](https://intel.example.com/?entry={b.id})."

    out = await externalize_entry_links(db_session, md)

    assert out == "See [Alpha](https://example.com/alpha) and [Beta](https://example.com/beta)."


@pytest.mark.asyncio
async def test_externalize_entry_links_keeps_link_without_source_url(db_session, day_feed, monkeypatch):
    """An entry with no source URL keeps its app link, absolutised when the
    public origin is configured."""
    from app.config import settings
    from app.services.daily_briefing import externalize_entry_links

    entry = Entry(feed_id=day_feed.id, title="No URL", guid="guid-nourl", published_at=datetime.now(UTC))
    db_session.add(entry)
    await db_session.flush()

    monkeypatch.setattr(settings, "public_base_url", "https://intel.example.com")
    out = await externalize_entry_links(db_session, f"[X](/?entry={entry.id})")
    assert out == f"[X](https://intel.example.com/?entry={entry.id})"

    monkeypatch.setattr(settings, "public_base_url", "")
    out = await externalize_entry_links(db_session, f"[X](/?entry={entry.id})")
    assert out == f"[X](/?entry={entry.id})"


@pytest.mark.asyncio
async def test_externalize_entry_links_ignores_other_links(db_session):
    from app.services.daily_briefing import externalize_entry_links

    md = "[Vendor](https://vendor.example.com/post) and [CVE](/workbench/cve/CVE-2026-1)."
    assert await externalize_entry_links(db_session, md) == md


@pytest.mark.asyncio
async def test_use_daily_summary_action_externalizes_links(db_session, daily_summary_task, day_feed):
    """The briefing handed to the notification/webhook actions carries source
    URLs, not reader deep links."""
    from app.automation.actions import _action_use_daily_summary
    from app.services.daily_briefing import yesterday_key

    entry = await _make_entry(db_session, day_feed, "gamma", datetime.now(UTC))
    day = yesterday_key()
    shared_id = _daily_summary_target_id(GLOBAL_SUMMARY_USER, day, {"dedup": True})
    await _add_result(db_session, daily_summary_task, shared_id, f"Read [Gamma](/?entry={entry.id}).")

    ctx: dict = {}
    result = await _action_use_daily_summary(db_session, [entry], {}, ctx)

    assert result["status"] == "success"
    assert result["links"] == "original"
    assert ctx["ai_summary"] == "Read [Gamma](https://example.com/gamma)."
    assert ctx["ai_results"]["daily_summary"]["summary"] == ctx["ai_summary"]


@pytest.mark.asyncio
async def test_use_daily_summary_action_links_app_keeps_reader_links(
    db_session, daily_summary_task, day_feed, monkeypatch
):
    """links='app' keeps the IntelFeed deep links, absolutised for the post."""
    from app.automation.actions import _action_use_daily_summary
    from app.config import settings
    from app.services.daily_briefing import yesterday_key

    entry = await _make_entry(db_session, day_feed, "delta", datetime.now(UTC))
    day = yesterday_key()
    shared_id = _daily_summary_target_id(GLOBAL_SUMMARY_USER, day, {"dedup": True})
    await _add_result(db_session, daily_summary_task, shared_id, f"Read [Delta](/?entry={entry.id}).")

    monkeypatch.setattr(settings, "public_base_url", "https://intel.example.com")
    ctx: dict = {}
    result = await _action_use_daily_summary(db_session, [entry], {"links": "app"}, ctx)

    assert result["status"] == "success"
    assert ctx["ai_summary"] == f"Read [Delta](https://intel.example.com/?entry={entry.id})."


@pytest.mark.asyncio
async def test_use_daily_summary_action_rejects_bad_links_option(db_session, day_feed):
    from app.automation.actions import _action_use_daily_summary

    entry = await _make_entry(db_session, day_feed, "any", datetime.now(UTC))
    result = await _action_use_daily_summary(db_session, [entry], {"links": "sideways"}, {})
    assert result["status"] == "error"
