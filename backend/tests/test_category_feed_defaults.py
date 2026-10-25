"""Categories store pipeline defaults that feeds added to them inherit."""

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.category import Category
from app.models.feed import Feed
from app.models.user import User
from app.services.feed_defaults import clean_defaults


async def _category(db: AsyncSession, name: str, defaults: dict | None = None) -> Category:
    category = Category(name=name, feed_defaults=defaults or {})
    db.add(category)
    await db.flush()
    return category


def test_clean_defaults_keeps_only_known_well_typed_keys():
    assert clean_defaults(
        {
            "ai_analysis_enabled": False,
            "intel_extraction_mode": "bogus",
            "extract_tools": "no",
            "fetch_interval_minutes": 5,
            "extract_detection_rules": None,
            "auto_extract_on_ingest": True,
        }
    ) == {"ai_analysis_enabled": False, "auto_extract_on_ingest": True}


@pytest.mark.asyncio
async def test_api_created_feed_inherits_the_category_defaults(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    category = await _category(
        db_session,
        "Advisories (defaults)",
        {"intel_extraction_mode": "full", "ai_analysis_enabled": False, "extract_tools": False},
    )
    discovered = SimpleNamespace(title="CERT", url="https://cert-defaults.example/rss", feed_type="rss", description="")
    with (
        patch("app.api.feeds.discover_feed", return_value=discovered),
        patch("app.workers.feed_tasks.fetch_feed.delay"),
    ):
        response = await client.post(
            "/api/feeds",
            json={
                "url": "https://cert-defaults.example/rss",
                "category_id": str(category.id),
                # What the caller names beats the category.
                "extract_tools": True,
            },
            headers=admin_headers,
        )
    assert response.status_code == 201
    data = response.json()
    assert data["intel_extraction_mode"] == "full"
    assert data["ai_analysis_enabled"] is False
    assert data["extract_tools"] is True
    # Not in the defaults: the global default.
    assert data["extract_detection_rules"] is False


@pytest.mark.asyncio
async def test_opml_import_inherits_defaults_but_outline_tuning_wins(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    await _category(db_session, "Vendor Research", {"ai_analysis_enabled": False, "extract_tools": False})
    opml = """<?xml version="1.0"?>
<opml version="1.0" xmlns:intelfeed="https://intelfeed.dev/opml">
  <body>
    <outline text="Vendor Research">
      <outline text="Plain" type="rss" xmlUrl="https://plain-defaults.example/rss" />
      <outline text="Tuned" type="rss" xmlUrl="https://tuned-defaults.example/rss" intelfeed:extractTools="true" />
    </outline>
  </body>
</opml>"""
    from app.feed_packs import INTELFEED_NS

    opml = opml.replace("https://intelfeed.dev/opml", INTELFEED_NS)
    with patch("app.workers.feed_tasks.fetch_feed.delay"):
        response = await client.post(
            "/api/opml/import",
            headers=admin_headers,
            files={"file": ("subs.opml", opml.encode(), "text/xml")},
        )
    assert response.status_code == 200
    assert response.json()["feeds_added"] == 2

    plain = (
        await db_session.execute(select(Feed).where(Feed.url == "https://plain-defaults.example/rss"))
    ).scalar_one()
    tuned = (
        await db_session.execute(select(Feed).where(Feed.url == "https://tuned-defaults.example/rss"))
    ).scalar_one()
    assert (plain.ai_analysis_enabled, plain.extract_tools) == (False, False)
    assert (tuned.ai_analysis_enabled, tuned.extract_tools) == (False, True)


@pytest.mark.asyncio
async def test_create_feed_tool_inherits_the_category_defaults(db_session: AsyncSession, admin_user: User):
    from app.tools import execute_tool

    await _category(db_session, "Tool defaults", {"extract_tools": False})
    with patch("app.workers.feed_tasks.fetch_feed.delay"):
        raw = await execute_tool(
            "create_feed",
            {"url": "https://tool-defaults.example/rss", "category": "Tool defaults"},
            db_session,
            admin_user.id,
        )
    feed_id = json.loads(raw)["id"]
    feed = await db_session.get(Feed, feed_id)
    assert feed.extract_tools is False


@pytest.mark.asyncio
async def test_bulk_update_can_save_the_category_default(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    category = await _category(db_session, "Bulk defaults")
    feed = Feed(title="Here now", url="https://bulk-defaults.example/rss", feed_type="rss", category_id=category.id)
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/category/{category.id}/bulk-update",
        json={
            "ai_analysis_enabled": False,
            "extract_detection_rules": True,
            "fetch_interval_minutes": 120,
            "save_as_category_default": True,
        },
        headers=admin_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["updated"] == 1
    # Only pipeline fields become defaults; the interval applied to today's feeds alone.
    assert body["feed_defaults"] == {"ai_analysis_enabled": False, "extract_detection_rules": True}

    await db_session.refresh(feed)
    await db_session.refresh(category)
    assert feed.ai_analysis_enabled is False
    assert feed.fetch_interval_minutes == 120
    assert category.feed_defaults == {"ai_analysis_enabled": False, "extract_detection_rules": True}


@pytest.mark.asyncio
async def test_bulk_update_can_change_only_the_defaults(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    category = await _category(db_session, "Defaults only", {"ai_analysis_enabled": False})
    feed = Feed(title="Untouched", url="https://defaults-only.example/rss", feed_type="rss", category_id=category.id)
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/category/{category.id}/bulk-update",
        json={"extract_tools": False, "apply_to_feeds": False, "save_as_category_default": True},
        headers=admin_headers,
    )
    assert response.status_code == 200
    assert response.json() == {
        "updated": 0,
        "feed_defaults": {"ai_analysis_enabled": False, "extract_tools": False},
    }
    await db_session.refresh(feed)
    assert feed.extract_tools is True


@pytest.mark.asyncio
async def test_detection_rule_changes_are_counted(client: AsyncClient, admin_headers: dict, db_session: AsyncSession):
    category = await _category(db_session, "Rules counted")
    db_session.add(Feed(title="R", url="https://rules-counted.example/rss", feed_type="rss", category_id=category.id))
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/category/{category.id}/bulk-update",
        json={"extract_detection_rules": True},
        headers=admin_headers,
    )
    assert response.json()["updated"] == 1


@pytest.mark.asyncio
async def test_category_defaults_edit_is_admin_only_and_listed(
    client: AsyncClient, auth_headers: dict, admin_headers: dict, db_session: AsyncSession
):
    category = await _category(db_session, "Edited defaults")

    response = await client.put(
        f"/api/categories/{category.id}",
        json={"feed_defaults": {"ai_analysis_enabled": False}},
        headers=auth_headers,
    )
    assert response.status_code == 403

    response = await client.put(
        f"/api/categories/{category.id}",
        json={"feed_defaults": {"ai_analysis_enabled": False, "intel_extraction_mode": "full"}},
        headers=admin_headers,
    )
    assert response.status_code == 200
    assert response.json()["feed_defaults"] == {"ai_analysis_enabled": False, "intel_extraction_mode": "full"}

    listed = await client.get("/api/categories", headers=admin_headers)
    row = next(c for c in listed.json() if c["id"] == str(category.id))
    assert row["feed_defaults"] == {"ai_analysis_enabled": False, "intel_extraction_mode": "full"}

    # {} clears them.
    response = await client.put(f"/api/categories/{category.id}", json={"feed_defaults": {}}, headers=admin_headers)
    assert response.json()["feed_defaults"] == {}
