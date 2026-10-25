"""scripts/maintenance/repair_js_wall_entries.py: restore RSS bodies over stored JS-wall notices."""

import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entry import Entry
from app.models.feed import Feed

WALL_HTML = '<p class="c-wysiwyg"> Please enable JavaScript in your web browser to get the best experience.</p>'
WALL_TEXT = "Please enable JavaScript in your web browser to get the best experience."


def _script():
    path = Path(__file__).resolve().parents[2] / "scripts" / "maintenance" / "repair_js_wall_entries.py"
    spec = importlib.util.spec_from_file_location("repair_js_wall_entries", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _wall_entry(feed: Feed, guid: str, summary: str | None, url: str | None = None) -> Entry:
    return Entry(
        feed_id=feed.id,
        guid=guid,
        url=url or f"https://example.org/{guid}",
        title=f"Title {guid}",
        content_html=WALL_HTML,
        content_text=WALL_TEXT,
        summary=summary,
        word_count=13,
    )


@pytest.fixture
async def wall_setup(db_session: AsyncSession):
    ai_feed = Feed(title="NCSC (UK) News", url="https://example.org/ncsc.xml", feed_type="rss")
    quiet_feed = Feed(
        title="Europol",
        url="https://example.org/europol.xml",
        feed_type="rss",
        ai_analysis_enabled=False,
    )
    db_session.add_all([ai_feed, quiet_feed])
    await db_session.flush()
    entries = {
        "summary": _wall_entry(ai_feed, "a", "Key findings from the sixth year of the ACD programme."),
        "feed": _wall_entry(ai_feed, "b", None),
        "article": _wall_entry(quiet_feed, "c", None),
        "unresolved": _wall_entry(quiet_feed, "d", None),
        "real": Entry(
            feed_id=ai_feed.id,
            guid="e",
            title="Real",
            content_html="<p>A real article about enabling JavaScript in PDF readers.</p>" * 40,
            content_text="A real article about enabling JavaScript in PDF readers. " * 40,
        ),
    }
    db_session.add_all(entries.values())
    await db_session.commit()
    return ai_feed, quiet_feed, entries


@pytest.mark.asyncio
async def test_dry_run_counts_per_feed_and_changes_nothing(db_session: AsyncSession, wall_setup):
    _, _, entries = wall_setup
    module = _script()
    report = await module.repair(db_session, apply=False)

    assert dict(report.found) == {"NCSC (UK) News": 2, "Europol": 2}
    await db_session.refresh(entries["summary"])
    assert entries["summary"].content_text == WALL_TEXT


@pytest.mark.asyncio
async def test_apply_restores_reindexes_and_requeues_only_ai_feeds(db_session: AsyncSession, wall_setup):
    ai_feed, quiet_feed, entries = wall_setup
    module = _script()

    async def fake_feed_items(feed):
        return {"b": "<p>The feed's own description of item b.</p>"} if feed.id == ai_feed.id else {}

    async def fake_article(url, feed_id):
        if url.endswith("/c"):
            return "<p>The article text for c, fetched again.</p>"
        return WALL_HTML  # still a wall: must not be stored

    reindexed, queued = [], []
    with patch("app.services.system_settings.get_setting", new=AsyncMock(return_value=True)):
        report = await module.repair(
            db_session,
            apply=True,
            fetch_feed_items=fake_feed_items,
            fetch_article=fake_article,
            reindex=lambda e: reindexed.append(e.id),
            enqueue=queued.append,
        )

    for e in entries.values():
        await db_session.refresh(e)
    assert entries["summary"].content_text == "Key findings from the sixth year of the ACD programme."
    assert entries["summary"].word_count == 10
    assert "own description of item b" in entries["feed"].content_text
    assert "article text for c" in entries["article"].content_text
    assert entries["unresolved"].content_text == WALL_TEXT
    assert "real article" in entries["real"].content_text

    assert dict(report.repaired) == {"summary": 1, "feed": 1, "article": 1}
    assert [r[1] for r in report.unresolved] == [entries["unresolved"].id]
    assert set(reindexed) == {entries["summary"].id, entries["feed"].id, entries["article"].id}
    # Europol's AI is off: only the NCSC entries are re-analysed.
    assert set(queued) == {entries["summary"].id, entries["feed"].id}


@pytest.mark.asyncio
async def test_apply_skips_analysis_when_one_pass_is_off(db_session: AsyncSession, wall_setup):
    module = _script()
    queued = []
    with patch("app.services.system_settings.get_setting", new=AsyncMock(return_value=False)):
        await module.repair(
            db_session,
            apply=True,
            fetch_feed_items=AsyncMock(return_value={}),
            fetch_article=AsyncMock(return_value=None),
            reindex=lambda e: None,
            enqueue=queued.append,
        )
    assert queued == []
