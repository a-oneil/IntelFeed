"""A new feed gets a real name and lands in a category even when the caller gave neither."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import ParsedFeedMeta
from app.adapters.web_scraper import WebScraperAdapter, _page_title
from app.models.category import Category
from app.models.feed import Feed

# ---------- naming ----------


def test_scraper_names_the_feed_after_the_page_not_the_host():
    page = """<html><head><meta property="og:site_name" content="CISA">
    <title>Known Exploited Vulnerabilities
      Catalog | CISA</title></head><body></body></html>"""
    meta = WebScraperAdapter()._build_meta(
        {"blog_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}, page
    )
    assert meta.title == "Known Exploited Vulnerabilities Catalog | CISA"


def test_scraper_falls_back_to_site_name_then_host():
    assert _page_title('<meta property="og:site_name" content="Acme &amp; Co">') == "Acme & Co"
    meta = WebScraperAdapter()._build_meta({"blog_url": "https://blog.example.com/"}, None)
    assert meta.title == "blog.example.com"


@pytest.mark.asyncio
async def test_first_fetch_replaces_a_url_placeholder_title():
    from app.workers import feed_tasks

    adapter = MagicMock()
    adapter.fetch_entries = AsyncMock(return_value=(ParsedFeedMeta(title="Known Exploited Vulnerabilities"), []))
    feed = MagicMock()
    feed.id = "feed-scraper"
    feed.feed_type = "web_scraper"
    feed.url = "https://www.cisa.gov/kev"
    feed.title = "https://www.cisa.gov/kev"
    feed.adapter_config = {}
    feed.last_fetched_at = None
    feed.exclude_title_patterns = None

    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: None))
    db.commit = AsyncMock()
    db.flush = AsyncMock()

    with (
        patch("app.adapters.get_extended_adapter", return_value=adapter),
        patch("app.services.system_settings._ensure_cache", new=AsyncMock()),
    ):
        await feed_tasks._fetch_extended_feed(db, feed)

    assert feed.title == "Known Exploited Vulnerabilities"


def test_a_real_title_is_kept():
    from app.workers.feed_tasks import _title_is_placeholder

    assert _title_is_placeholder(SimpleNamespace(title="", url="https://x"))
    assert _title_is_placeholder(SimpleNamespace(title="https://x", url="https://x"))
    assert not _title_is_placeholder(SimpleNamespace(title="My name", url="https://x"))


# ---------- category ----------


async def _seed(db: AsyncSession) -> tuple[Category, Category]:
    videos, news = Category(name="Videos (fallback)"), Category(name="News (fallback)")
    db.add_all([videos, news])
    await db.flush()
    db.add_all(
        [
            Feed(title="v1", url="https://fb-v1.example", feed_type="youtube", category_id=videos.id),
            Feed(title="v2", url="https://fb-v2.example", feed_type="youtube", category_id=videos.id),
            Feed(title="v3", url="https://fb-v3.example", feed_type="youtube", category_id=news.id),
            Feed(title="r1", url="https://fb-r1.example", feed_type="rss", category_id=news.id),
        ]
    )
    await db.flush()
    return videos, news


@pytest.mark.asyncio
async def test_api_create_without_a_category_files_it_with_its_type(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    videos, _ = await _seed(db_session)
    discovered = SimpleNamespace(
        title="Some channel", url="https://fb-new-channel.example", feed_type="youtube", description=""
    )
    with (
        patch("app.api.feeds.discover_feed", return_value=discovered),
        patch("app.workers.feed_tasks.fetch_feed.delay"),
    ):
        response = await client.post(
            "/api/feeds", json={"url": "https://fb-new-channel.example"}, headers=admin_headers
        )
    assert response.status_code == 201
    assert response.json()["category_id"] == str(videos.id)


@pytest.mark.asyncio
async def test_an_explicit_category_is_kept(client: AsyncClient, admin_headers: dict, db_session: AsyncSession):
    _, news = await _seed(db_session)
    discovered = SimpleNamespace(title="Chan", url="https://fb-explicit.example", feed_type="youtube", description="")
    with (
        patch("app.api.feeds.discover_feed", return_value=discovered),
        patch("app.workers.feed_tasks.fetch_feed.delay"),
    ):
        response = await client.post(
            "/api/feeds",
            json={"url": "https://fb-explicit.example", "category_id": str(news.id)},
            headers=admin_headers,
        )
    assert response.json()["category_id"] == str(news.id)


@pytest.mark.asyncio
async def test_a_type_nobody_has_filed_stays_uncategorized(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    await _seed(db_session)
    with patch("app.workers.feed_tasks.fetch_feed.delay"):
        response = await client.post(
            "/api/feeds",
            json={"url": "nvd://fallback", "feed_type": "nvd", "adapter_config": {}},
            headers=admin_headers,
        )
    assert response.status_code == 201
    assert response.json()["category_id"] is None


@pytest.mark.asyncio
async def test_top_level_opml_outline_is_filed_with_its_type(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    _, news = await _seed(db_session)
    opml = """<?xml version="1.0"?><opml version="1.0"><body>
      <outline text="Loose" type="rss" xmlUrl="https://fb-loose.example/rss" />
    </body></opml>"""
    with patch("app.workers.feed_tasks.fetch_feed.delay"):
        response = await client.post(
            "/api/opml/import", headers=admin_headers, files={"file": ("s.opml", opml.encode(), "text/xml")}
        )
    assert response.status_code == 200
    feed = (await db_session.execute(select(Feed).where(Feed.url == "https://fb-loose.example/rss"))).scalar_one()
    assert feed.category_id == news.id
