"""Muting hides a feed from reading; its AI cost is shown, and the public proxy leaves it out."""

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.entry import Entry
from app.models.feed import Feed


@pytest.mark.asyncio
async def test_ai_usage_sums_the_feeds_calls_in_the_window(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession
):
    task = AITask(name="usage_task", display_name="Usage", default_prompt_template="x")
    muted = Feed(title="Muted", url="https://usage-muted.example/rss", feed_type="rss", is_muted=True)
    other = Feed(title="Other", url="https://usage-other.example/rss", feed_type="rss")
    db_session.add_all([task, muted, other])
    await db_session.flush()
    mine = Entry(feed_id=muted.id, guid="u-1", title="a", url="https://usage-muted.example/a")
    theirs = Entry(feed_id=other.id, guid="u-2", title="b", url="https://usage-other.example/b")
    db_session.add_all([mine, theirs])
    await db_session.flush()

    now = datetime.now(UTC)

    def result(entry, tin, tout, when, **kw):
        return AIResult(
            entry_id=entry.id,
            target_type="entry",
            target_id=entry.id,
            task_id=task.id,
            tokens_input=tin,
            tokens_output=tout,
            created_at=when,
            **kw,
        )

    db_session.add_all(
        [
            result(mine, 1000, 200, now - timedelta(days=1)),
            result(mine, 3000, 300, now - timedelta(days=10), is_current=False),
            # A reuse from a near-duplicate moves no tokens and is not a call.
            result(mine, 0, 0, now - timedelta(days=2)),
            # Outside the window.
            result(mine, 9999, 9999, now - timedelta(days=45), is_current=False),
            # Another feed's article.
            result(theirs, 5000, 500, now - timedelta(days=1)),
        ]
    )
    await db_session.flush()

    response = await client.get(f"/api/feeds/{muted.id}/ai-usage", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["runs"] == 2
    assert data["tokens_input"] == 4000
    assert data["tokens_output"] == 500
    assert data["days"] == 30
    assert data["ai_analysis_enabled"] is True
    assert data["last_run_at"] is not None


@pytest.mark.asyncio
async def test_ai_usage_of_a_quiet_feed_is_zero(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = Feed(title="Quiet", url="https://usage-quiet.example/rss", feed_type="rss", ai_analysis_enabled=False)
    db_session.add(feed)
    await db_session.flush()

    data = (await client.get(f"/api/feeds/{feed.id}/ai-usage", headers=auth_headers)).json()
    assert (data["runs"], data["tokens_input"], data["last_run_at"]) == (0, 0, None)
    assert data["ai_analysis_enabled"] is False


@pytest.mark.asyncio
async def test_public_rss_leaves_out_muted_feeds(db_session: AsyncSession):
    from app.api.public_rss import _fetch_entries

    shown = Feed(title="Shown", url="https://rss-shown.example/rss", feed_type="rss")
    muted = Feed(title="Muted", url="https://rss-muted.example/rss", feed_type="rss", is_muted=True)
    db_session.add_all([shown, muted])
    await db_session.flush()
    db_session.add_all(
        [
            Entry(feed_id=shown.id, guid="p-1", title="kept", url="https://rss-shown.example/1"),
            Entry(feed_id=muted.id, guid="p-2", title="hidden", url="https://rss-muted.example/2"),
        ]
    )
    await db_session.flush()

    rows = await _fetch_entries(db_session, category_id=None, limit=50)
    titles = {entry.title for entry, _ in rows}
    assert "kept" in titles
    assert "hidden" not in titles
