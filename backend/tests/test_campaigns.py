"""Tests for BE-6: Campaign management API."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.campaign import Campaign
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.user import User


@pytest_asyncio.fixture
async def campaign_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(title="Campaign Feed", url="https://example.com/campaign-feed", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def campaign_entry(db_session: AsyncSession, campaign_feed: Feed) -> Entry:
    entry = Entry(feed_id=campaign_feed.id, title="Campaign Entry", guid="campaign-entry-1")
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest_asyncio.fixture
async def test_campaign(db_session: AsyncSession, test_user: User) -> Campaign:
    campaign = Campaign(
        created_by=test_user.id,
        name="APT29 Campaign Q1 2026",
        description="Tracking APT29 activity in Q1 2026",
        status="active",
        tags=["apt29", "russia"],
    )
    db_session.add(campaign)
    await db_session.flush()
    return campaign


@pytest.mark.asyncio
async def test_create_campaign(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/campaigns",
        json={
            "name": "New Campaign",
            "description": "Test campaign",
            "status": "active",
            "tlp_marking": "TLP:AMBER",
            "tags": ["test"],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "New Campaign"
    assert data["tlp_marking"] == "TLP:AMBER"
    assert data["entry_count"] == 0
    assert data["entity_count"] == 0


@pytest.mark.asyncio
async def test_list_campaigns(client: AsyncClient, auth_headers: dict, test_campaign: Campaign):
    resp = await client.get("/api/campaigns", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


@pytest.mark.asyncio
async def test_get_campaign(client: AsyncClient, auth_headers: dict, test_campaign: Campaign):
    resp = await client.get(f"/api/campaigns/{test_campaign.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "APT29 Campaign Q1 2026"


@pytest.mark.asyncio
async def test_update_campaign(client: AsyncClient, auth_headers: dict, test_campaign: Campaign):
    resp = await client.put(
        f"/api/campaigns/{test_campaign.id}",
        json={"status": "monitoring", "name": "Updated Campaign"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "monitoring"
    assert resp.json()["name"] == "Updated Campaign"


@pytest.mark.asyncio
async def test_delete_campaign(client: AsyncClient, auth_headers: dict, test_campaign: Campaign):
    resp = await client.delete(f"/api/campaigns/{test_campaign.id}", headers=auth_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_add_entry_to_campaign(
    client: AsyncClient, auth_headers: dict, test_campaign: Campaign, campaign_entry: Entry
):
    resp = await client.post(
        f"/api/campaigns/{test_campaign.id}/entries",
        json={"entry_id": str(campaign_entry.id)},
        headers=auth_headers,
    )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_add_entity_to_campaign(client: AsyncClient, auth_headers: dict, test_campaign: Campaign):
    resp = await client.post(
        f"/api/campaigns/{test_campaign.id}/entities",
        json={
            "entity_type": "threat_actor",
            "entity_id": str(uuid.uuid4()),
            "role": "primary",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_filter_campaigns_by_status(client: AsyncClient, auth_headers: dict, test_campaign: Campaign):
    resp = await client.get("/api/campaigns?status=active", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


@pytest.mark.asyncio
async def test_invalid_campaign_status(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/campaigns",
        json={"name": "Test", "status": "invalid_status"},
        headers=auth_headers,
    )
    assert resp.status_code == 400
