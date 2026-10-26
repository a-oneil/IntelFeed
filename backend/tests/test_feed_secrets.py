"""Feed credentials stay on the server, and the Telegram mentions list is a pure read.

A GitHub token, an NVD API key and the (encrypted) Bluesky app password live in
``adapter_config``. The API masks them, an edit that echoes the mask back keeps
the stored value, and an OPML export leaves them out.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.opml import feed_outline_attrs
from app.models.feed import Feed
from app.models.telegram_mention import TelegramChannelMention
from app.schemas.feed import MASKED_SECRET


async def _github_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(
        title="Repo releases",
        url="https://github.com/acme/tool",
        feed_type="github_repo",
        adapter_config={"owner": "acme", "repo": "tool", "token": "ghp_realtoken123"},
    )
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest.mark.asyncio
async def test_feed_response_masks_every_credential(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = Feed(
        title="NVD",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        feed_type="nvd",
        adapter_config={"api_key": "nvd-secret-key", "min_cvss": 7, "token": "", "app_password": "gAAAAAcipher"},
    )
    db_session.add(feed)
    await db_session.flush()

    response = await client.get(f"/api/feeds/{feed.id}", headers=auth_headers)

    assert response.status_code == 200
    config = response.json()["adapter_config"]
    assert config["api_key"] == MASKED_SECRET
    assert config["app_password"] == MASKED_SECRET
    assert config["token"] == ""  # unset stays visibly unset
    assert config["min_cvss"] == 7
    assert "nvd-secret-key" not in response.text
    assert "gAAAAAcipher" not in response.text


@pytest.mark.asyncio
async def test_feed_list_masks_tokens(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    await _github_feed(db_session)

    response = await client.get("/api/feeds", headers=auth_headers)

    assert response.status_code == 200
    assert "ghp_realtoken123" not in response.text


@pytest.mark.asyncio
async def test_edit_echoing_the_mask_keeps_the_stored_token(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    feed = await _github_feed(db_session)

    response = await client.put(
        f"/api/feeds/{feed.id}",
        json={"adapter_config": {"owner": "acme", "repo": "tool", "token": MASKED_SECRET, "branch": "main"}},
        headers=admin_headers,
    )

    assert response.status_code == 200
    await db_session.refresh(feed)
    assert feed.adapter_config["token"] == "ghp_realtoken123"
    assert feed.adapter_config["branch"] == "main"


@pytest.mark.asyncio
async def test_edit_with_a_new_token_replaces_it(client: AsyncClient, admin_headers: dict, db_session: AsyncSession):
    feed = await _github_feed(db_session)

    response = await client.put(
        f"/api/feeds/{feed.id}",
        json={"adapter_config": {"token": "rotated-value"}},
        headers=admin_headers,
    )

    assert response.status_code == 200
    await db_session.refresh(feed)
    assert feed.adapter_config["token"] == "rotated-value"


@pytest.mark.asyncio
async def test_opml_export_leaves_credentials_out(db_session: AsyncSession):
    feed = await _github_feed(db_session)

    attrs = feed_outline_attrs(feed)

    config = attrs["intelfeed:config"]
    assert "ghp_realtoken123" not in config
    assert '"token"' not in config
    assert '"repo":"tool"' in config


@pytest.mark.asyncio
async def test_telegram_mentions_list_does_not_write(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    """Subscription state comes from the live feed list; the cached feed_id is left alone."""
    feed = Feed(
        title="Leak channel",
        url="https://t.me/leakchan",
        feed_type="telegram",
        adapter_config={"channel": "@leakchan"},
    )
    db_session.add(feed)
    subscribed = TelegramChannelMention(handle="leakchan", canonical_url="https://t.me/leakchan")
    unsubscribed = TelegramChannelMention(handle="otherchan", canonical_url="https://t.me/otherchan")
    db_session.add_all([subscribed, unsubscribed])
    await db_session.flush()
    assert subscribed.feed_id is None  # stale cache: the feed exists but isn't cached

    response = await client.get("/api/telegram/mentions", headers=auth_headers)

    assert response.status_code == 200
    by_handle = {item["handle"]: item for item in response.json()["items"]}
    assert by_handle["leakchan"]["is_subscribed"] is True
    assert by_handle["leakchan"]["feed_id"] == str(feed.id)
    assert by_handle["otherchan"]["is_subscribed"] is False
    await db_session.refresh(subscribed)
    assert subscribed.feed_id is None

    response = await client.get("/api/telegram/mentions?only_unsubscribed=true", headers=auth_headers)

    assert [item["handle"] for item in response.json()["items"]] == ["otherchan"]
