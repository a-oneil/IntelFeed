"""Tests for campaign workbench enhancement endpoints.

Covers: detection-gaps, export, stats, entities (list), countries, auto-detect, saved-searches.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.campaign import Campaign, CampaignEntity, CampaignEntry
from app.models.country import Country, EntryCountry
from app.models.country_junction import CampaignCountry
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.saved_search import SavedSearch
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP
from app.models.user import User

# ── Fixtures ─────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def user(db_session: AsyncSession) -> User:
    u = User(
        username="camp_enh_user",
        password_hash=hash_password("testpassword"),
        role="user",
    )
    db_session.add(u)
    await db_session.flush()
    return u


@pytest_asyncio.fixture
async def headers(user: User) -> dict:
    token = create_access_token(user.id, user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def feed(db_session: AsyncSession) -> Feed:
    f = Feed(title="Enhancement Test Feed", url="https://enhance-test.example.com/rss", feed_type="rss")
    db_session.add(f)
    await db_session.flush()
    return f


@pytest_asyncio.fixture
async def populated_campaign(db_session: AsyncSession, user: User, feed: Feed):
    """Campaign with 2 entries and TTPs — used by most tests."""
    campaign = Campaign(
        created_by=user.id,
        name="Enhancement Test Campaign",
        status="active",
        tags=["test"],
    )
    db_session.add(campaign)
    await db_session.flush()

    entries = []
    for i in range(2):
        entry = Entry(
            feed_id=feed.id,
            title=f"Enh Entry {i + 1}",
            guid=f"enh-entry-{i + 1}",
            published_at=datetime(2026, 1, 10 + i, tzinfo=UTC),
        )
        db_session.add(entry)
        await db_session.flush()
        entries.append(entry)

        db_session.add(
            CampaignEntry(
                campaign_id=campaign.id,
                entry_id=entry.id,
                added_by=user.id,
            )
        )

    # TTPs
    ttp1 = TTP(technique_id="T1059.001", technique_name="PowerShell", tactic="execution")
    ttp2 = TTP(technique_id="T1566.001", technique_name="Spearphishing Attachment", tactic="initial-access")
    db_session.add_all([ttp1, ttp2])
    await db_session.flush()

    db_session.add(EntryTTP(entry_id=entries[0].id, ttp_id=ttp1.id))
    db_session.add(EntryTTP(entry_id=entries[1].id, ttp_id=ttp2.id))

    await db_session.flush()
    return campaign, entries, [ttp1, ttp2]


# ── Detection Gaps ───────────────────────────────────────────────────


async def test_detection_gaps_all_gaps(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
):
    """No detection rules exist → all TTPs are gaps."""
    campaign, _, ttps = populated_campaign

    resp = await client.get(f"/api/campaigns/{campaign.id}/detection-gaps", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_ttps"] == 2
    assert data["gap_count"] == 2
    assert data["no_rule_count"] == 2
    assert data["covered_count"] == 0
    assert data["library_only_count"] == 0
    assert data["coverage_percentage"] == 0
    assert len(data["gaps"]) == 2
    assert len(data["library_only"]) == 0
    assert len(data["covered"]) == 0


async def test_detection_gaps_with_coverage(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    db_session: AsyncSession,
    user: User,
):
    """Add a satisfiable detection rule covering one TTP → one covered, one gap."""
    campaign, _, ttps = populated_campaign

    rule = DetectionRule(
        created_by=user.id,
        rule_type="sigma",
        title="PowerShell Execution",
        rule_content="title: PowerShell\nstatus: test",
        is_draft=False,
        mitre_tactics=["T1059.001"],
    )
    db_session.add(rule)
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/detection-gaps", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_ttps"] == 2
    assert data["covered_count"] == 1
    assert data["library_only_count"] == 0
    assert data["gap_count"] == 1
    assert data["coverage_percentage"] == 50.0
    assert len(data["covered"]) == 1
    assert data["covered"][0]["technique_id"] == "T1059.001"
    assert len(data["covered"][0]["rules"]) == 1


async def test_detection_gaps_library_only_when_telemetry_missing(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    db_session: AsyncSession,
    user: User,
):
    """A rule whose data sources aren't in the telemetry inventory is library_only, not covered."""
    from app.models.telemetry_source import TelemetrySource

    campaign, _, ttps = populated_campaign

    # Enabled telemetry that does NOT satisfy the rule's requirements
    db_session.add(
        TelemetrySource(
            name="Firewall Logs",
            category="network_security",
            log_types=["traffic_log"],
        )
    )
    rule = DetectionRule(
        created_by=user.id,
        rule_type="elastic_ql",
        title="PowerShell via process events",
        rule_content="process where true",
        is_draft=False,
        source_ttps=["T1059.001"],
        data_sources=["logs-endpoint.events.process*"],
    )
    db_session.add(rule)
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/detection-gaps", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_ttps"] == 2
    # Rule exists but can't fire → NOT counted as covered
    assert data["covered_count"] == 0
    assert data["library_only_count"] == 1
    assert data["no_rule_count"] == 1
    assert data["coverage_percentage"] == 0
    lib = data["library_only"][0]
    assert lib["technique_id"] == "T1059.001"
    assert lib["missing_data_sources"] == ["logs-endpoint.events.process*"]
    assert len(lib["rules"]) == 1


async def test_detection_gaps_draft_rules_ignored(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    db_session: AsyncSession,
    user: User,
):
    """Draft rules never count toward coverage."""
    campaign, _, ttps = populated_campaign

    rule = DetectionRule(
        created_by=user.id,
        rule_type="sigma",
        title="Draft PowerShell",
        rule_content="title: PowerShell\nstatus: test",
        is_draft=True,
        source_ttps=["T1059.001"],
    )
    db_session.add(rule)
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/detection-gaps", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["covered_count"] == 0
    assert data["library_only_count"] == 0
    assert data["no_rule_count"] == 2


async def test_detection_gaps_empty_campaign(
    client: AsyncClient,
    headers: dict,
    db_session: AsyncSession,
    user: User,
):
    """Campaign with no entries → zero TTPs."""
    campaign = Campaign(created_by=user.id, name="Empty Campaign", status="active")
    db_session.add(campaign)
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/detection-gaps", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_ttps"] == 0
    assert data["coverage_percentage"] == 0


async def test_detection_gaps_not_found(client: AsyncClient, headers: dict):
    resp = await client.get(f"/api/campaigns/{uuid.uuid4()}/detection-gaps", headers=headers)
    assert resp.status_code == 404


# ── Export ────────────────────────────────────────────────────────────


async def test_export_campaign(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
):
    campaign, entries, ttps = populated_campaign

    resp = await client.get(f"/api/campaigns/{campaign.id}/export", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    # Campaign metadata
    assert data["campaign"]["name"] == "Enhancement Test Campaign"
    assert data["campaign"]["status"] == "active"

    # Entries
    assert len(data["entries"]) == 2

    # TTPs
    tech_ids = {t["technique_id"] for t in data["ttps"]}
    assert "T1059.001" in tech_ids
    assert "T1566.001" in tech_ids

    # Stats
    assert data["stats"]["entry_count"] == 2
    assert data["stats"]["ttp_count"] == 2


async def test_export_empty_campaign(
    client: AsyncClient,
    headers: dict,
    db_session: AsyncSession,
    user: User,
):
    campaign = Campaign(created_by=user.id, name="Empty Export", status="active")
    db_session.add(campaign)
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/export", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["stats"]["entry_count"] == 0
    assert data["entries"] == []


async def test_export_not_found(client: AsyncClient, headers: dict):
    resp = await client.get(f"/api/campaigns/{uuid.uuid4()}/export", headers=headers)
    assert resp.status_code == 404


# ── Stats ─────────────────────────────────────────────────────────────


async def test_stats_populated(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
):
    campaign, _, _ = populated_campaign

    resp = await client.get(f"/api/campaigns/{campaign.id}/stats", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["entry_count"] == 2
    assert data["entity_counts"]["ttp"] == 2
    assert data["date_range"]["earliest_entry"] is not None
    assert data["date_range"]["latest_entry"] is not None
    assert len(data["top_sources"]) >= 1
    assert data["top_sources"][0]["feed_name"] == "Enhancement Test Feed"
    assert len(data["entries_over_time"]) >= 1


async def test_stats_empty_campaign(
    client: AsyncClient,
    headers: dict,
    db_session: AsyncSession,
    user: User,
):
    campaign = Campaign(created_by=user.id, name="Empty Stats", status="active")
    db_session.add(campaign)
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/stats", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["entry_count"] == 0
    assert data["entity_counts"]["ttp"] == 0
    assert data["date_range"]["earliest_entry"] is None


async def test_stats_not_found(client: AsyncClient, headers: dict):
    resp = await client.get(f"/api/campaigns/{uuid.uuid4()}/stats", headers=headers)
    assert resp.status_code == 404


async def test_stats_total_entity_count(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    db_session: AsyncSession,
    user: User,
):
    """Regression (B3): the entity total must count distinct entities referenced
    by campaign entries, not just explicitly linked CampaignEntity rows."""
    campaign, _, ttps = populated_campaign

    # Explicitly link one TTP that already appears via entries (must not double
    # count) and one threat actor that does not appear in any entry.
    actor = ThreatActor(name="Stats Actor")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        CampaignEntity(
            campaign_id=campaign.id,
            entity_type="ttp",
            entity_id=ttps[0].id,
            role="primary",
            added_by=user.id,
        )
    )
    db_session.add(
        CampaignEntity(
            campaign_id=campaign.id,
            entity_type="threat_actor",
            entity_id=actor.id,
            role="related",
            added_by=user.id,
        )
    )
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/stats", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    # 2 TTPs from entries (one also explicitly linked) + 1 explicit actor
    assert data["entity_counts"]["ttp"] == 2
    assert data["total_entity_count"] == 3


async def test_stats_entries_over_time_buckets(
    client: AsyncClient,
    headers: dict,
    db_session: AsyncSession,
    user: User,
    feed: Feed,
):
    """Regression (B4): entries over time must produce contiguous zero-filled
    buckets across the campaign date range instead of sparse giant bars."""
    campaign = Campaign(created_by=user.id, name="Bucket Stats", status="active")
    db_session.add(campaign)
    await db_session.flush()

    # Two entries ~7 months apart → monthly buckets, zero-filled in between
    for i, dt in enumerate(
        [
            datetime(2026, 1, 5, tzinfo=UTC),
            datetime(2026, 8, 20, tzinfo=UTC),
        ]
    ):
        entry = Entry(
            feed_id=feed.id,
            title=f"Bucket Entry {i + 1}",
            guid=f"bucket-entry-{i + 1}",
            published_at=dt,
        )
        db_session.add(entry)
        await db_session.flush()
        db_session.add(CampaignEntry(campaign_id=campaign.id, entry_id=entry.id, added_by=user.id))
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/stats", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["entries_over_time_bucket"] == "month"
    buckets = data["entries_over_time"]
    assert len(buckets) == 8  # Jan..Aug, contiguous
    assert buckets[0] == {"date": "2026-01-01", "count": 1}
    assert buckets[-1] == {"date": "2026-08-01", "count": 1}
    assert all(b["count"] == 0 for b in buckets[1:-1])


async def test_stats_entries_over_time_daily_bucket(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
):
    """Entries one day apart → daily buckets."""
    campaign, _, _ = populated_campaign

    resp = await client.get(f"/api/campaigns/{campaign.id}/stats", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["entries_over_time_bucket"] == "day"
    assert data["entries_over_time"] == [
        {"date": "2026-01-10", "count": 1},
        {"date": "2026-01-11", "count": 1},
    ]


# ── Entities (list) ──────────────────────────────────────────────────


async def test_list_entities(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    db_session: AsyncSession,
    user: User,
):
    campaign, _, ttps = populated_campaign

    # Add a TTP entity
    db_session.add(
        CampaignEntity(
            campaign_id=campaign.id,
            entity_type="ttp",
            entity_id=ttps[0].id,
            role="primary",
            added_by=user.id,
        )
    )
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/entities", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["entity_type"] == "ttp"
    assert data[0]["role"] == "primary"
    # Name should be enriched with technique_id prefix
    assert "T1059.001" in data[0]["entity_name"]


async def test_list_entities_filter_by_type(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    db_session: AsyncSession,
    user: User,
):
    campaign, _, ttps = populated_campaign

    db_session.add(
        CampaignEntity(
            campaign_id=campaign.id,
            entity_type="ttp",
            entity_id=ttps[0].id,
            role="primary",
            added_by=user.id,
        )
    )
    db_session.add(
        CampaignEntity(
            campaign_id=campaign.id,
            entity_type="ttp",
            entity_id=ttps[1].id,
            role="related",
            added_by=user.id,
        )
    )
    await db_session.flush()

    resp = await client.get(
        f"/api/campaigns/{campaign.id}/entities?entity_type=ttp",
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert data[0]["entity_type"] == "ttp"


async def test_list_entities_empty(
    client: AsyncClient,
    headers: dict,
    db_session: AsyncSession,
    user: User,
):
    campaign = Campaign(created_by=user.id, name="No Entities", status="active")
    db_session.add(campaign)
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/entities", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


# ── Countries ─────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def country(db_session: AsyncSession) -> Country:
    c = Country(name="Russia", iso_code="RU")
    db_session.add(c)
    await db_session.flush()
    return c


@pytest_asyncio.fixture
async def country2(db_session: AsyncSession) -> Country:
    c = Country(name="United States", iso_code="US")
    db_session.add(c)
    await db_session.flush()
    return c


async def test_add_and_list_countries(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    country: Country,
    country2: Country,
):
    campaign, _, _ = populated_campaign

    # Add origin country
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/countries",
        json={"country_id": str(country.id), "role": "origin"},
        headers=headers,
    )
    assert resp.status_code == 201
    assert resp.json()["country_name"] == "Russia"
    assert resp.json()["role"] == "origin"

    # Add target country
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/countries",
        json={"country_id": str(country2.id), "role": "target"},
        headers=headers,
    )
    assert resp.status_code == 201

    # List
    resp = await client.get(f"/api/campaigns/{campaign.id}/countries", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    roles = {d["role"] for d in data}
    assert roles == {"origin", "target"}


async def test_add_country_duplicate(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    country: Country,
):
    campaign, _, _ = populated_campaign

    await client.post(
        f"/api/campaigns/{campaign.id}/countries",
        json={"country_id": str(country.id), "role": "origin"},
        headers=headers,
    )
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/countries",
        json={"country_id": str(country.id), "role": "origin"},
        headers=headers,
    )
    assert resp.status_code == 409


async def test_add_country_invalid_role(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    country: Country,
):
    campaign, _, _ = populated_campaign

    resp = await client.post(
        f"/api/campaigns/{campaign.id}/countries",
        json={"country_id": str(country.id), "role": "invalid"},
        headers=headers,
    )
    assert resp.status_code == 400


async def test_remove_country(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    country: Country,
):
    campaign, _, _ = populated_campaign

    await client.post(
        f"/api/campaigns/{campaign.id}/countries",
        json={"country_id": str(country.id), "role": "target"},
        headers=headers,
    )

    resp = await client.delete(
        f"/api/campaigns/{campaign.id}/countries/{country.id}",
        headers=headers,
    )
    assert resp.status_code == 204

    resp = await client.get(f"/api/campaigns/{campaign.id}/countries", headers=headers)
    assert resp.json() == []


async def test_remove_country_not_found(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
):
    campaign, _, _ = populated_campaign
    resp = await client.delete(
        f"/api/campaigns/{campaign.id}/countries/{uuid.uuid4()}",
        headers=headers,
    )
    assert resp.status_code == 404


async def test_suggested_countries(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    db_session: AsyncSession,
    country: Country,
    country2: Country,
):
    """Countries referenced by campaign entries are suggested with a role."""
    campaign, entries, _ = populated_campaign

    # Russia appears in both entries as origin; US in one entry as target
    db_session.add(EntryCountry(entry_id=entries[0].id, country_id=country.id, role="origin"))
    db_session.add(EntryCountry(entry_id=entries[1].id, country_id=country.id, role="origin"))
    db_session.add(EntryCountry(entry_id=entries[1].id, country_id=country2.id, role="target"))
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/countries/suggested", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    # Sorted by entry count descending
    assert data[0]["country_name"] == "Russia"
    assert data[0]["entry_count"] == 2
    assert data[0]["suggested_role"] == "origin"
    assert data[1]["country_name"] == "United States"
    assert data[1]["suggested_role"] == "target"


async def test_suggested_countries_excludes_linked(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    db_session: AsyncSession,
    country: Country,
):
    """Countries already linked to the campaign are not suggested."""
    campaign, entries, _ = populated_campaign

    db_session.add(EntryCountry(entry_id=entries[0].id, country_id=country.id, role="target"))
    db_session.add(CampaignCountry(campaign_id=campaign.id, country_id=country.id, role="target"))
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/countries/suggested", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_suggested_countries_empty_campaign(
    client: AsyncClient,
    headers: dict,
    db_session: AsyncSession,
    user: User,
):
    campaign = Campaign(created_by=user.id, name="No Geo", status="active")
    db_session.add(campaign)
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/countries/suggested", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_suggested_countries_not_found(client: AsyncClient, headers: dict):
    resp = await client.get(f"/api/campaigns/{uuid.uuid4()}/countries/suggested", headers=headers)
    assert resp.status_code == 404


# ── Saved Searches ───────────────────────────────────────────────────


@pytest_asyncio.fixture
async def saved_search(db_session: AsyncSession, user: User) -> SavedSearch:
    ss = SavedSearch(created_by=user.id, name="Test Search", query="ransomware")
    db_session.add(ss)
    await db_session.flush()
    return ss


async def test_saved_search_lifecycle(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    saved_search: SavedSearch,
):
    campaign, _, _ = populated_campaign

    # Add
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/saved-searches",
        json={"saved_search_id": str(saved_search.id), "auto_sync": True},
        headers=headers,
    )
    assert resp.status_code == 201
    css_id = resp.json()["id"]
    assert resp.json()["saved_search_name"] == "Test Search"
    assert resp.json()["auto_sync"] is True

    # List
    resp = await client.get(
        f"/api/campaigns/{campaign.id}/saved-searches",
        headers=headers,
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    # Update (toggle auto_sync)
    resp = await client.patch(
        f"/api/campaigns/{campaign.id}/saved-searches/{css_id}",
        json={"auto_sync": False},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["auto_sync"] is False

    # Remove
    resp = await client.delete(
        f"/api/campaigns/{campaign.id}/saved-searches/{css_id}",
        headers=headers,
    )
    assert resp.status_code == 204

    resp = await client.get(
        f"/api/campaigns/{campaign.id}/saved-searches",
        headers=headers,
    )
    assert resp.json() == []


async def test_saved_search_duplicate(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
    saved_search: SavedSearch,
):
    campaign, _, _ = populated_campaign

    await client.post(
        f"/api/campaigns/{campaign.id}/saved-searches",
        json={"saved_search_id": str(saved_search.id)},
        headers=headers,
    )
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/saved-searches",
        json={"saved_search_id": str(saved_search.id)},
        headers=headers,
    )
    assert resp.status_code == 409


async def test_saved_search_not_found(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
):
    campaign, _, _ = populated_campaign
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/saved-searches",
        json={"saved_search_id": str(uuid.uuid4())},
        headers=headers,
    )
    assert resp.status_code == 404


# ── Auto-Detect ──────────────────────────────────────────────────────


async def test_auto_detect_with_clusters(
    client: AsyncClient,
    headers: dict,
    db_session: AsyncSession,
    user: User,
    feed: Feed,
):
    """Create a threat actor appearing in 3+ recent entries → should suggest a campaign."""
    actor = ThreatActor(name="APT99", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()

    now = datetime.now(UTC)
    for i in range(4):
        entry = Entry(
            feed_id=feed.id,
            title=f"APT99 Report {i + 1}",
            guid=f"autodetect-entry-{i}",
            published_at=now - timedelta(days=i),
        )
        db_session.add(entry)
        await db_session.flush()
        db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))

    await db_session.flush()

    resp = await client.post(
        "/api/campaigns/auto-detect?min_entries=3&days=30",
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    assert data[0]["suggested_name"] == "APT99 Activity"
    assert data[0]["pivot_entity"]["type"] == "threat_actor"
    assert data[0]["entry_count"] >= 3
    assert len(data[0]["sample_entries"]) >= 1


async def test_auto_detect_empty(
    client: AsyncClient,
    headers: dict,
):
    """No qualifying clusters → empty list."""
    resp = await client.post(
        "/api/campaigns/auto-detect?min_entries=10&days=7",
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json() == []


async def test_auto_detect_prefers_story_threads_and_seeds_from_them(
    client: AsyncClient,
    headers: dict,
    db_session: AsyncSession,
    user: User,
    feed: Feed,
):
    """An actor carrying two stories outranks volume, and seeds from the stories only.

    The volume pass sweeps up every entry that mentions the actor; seeding a
    campaign with all of them is the noise the thread pass exists to avoid. The
    wider count is reported so the analyst knows the rest are waiting.
    """
    from app.models.story_thread import StoryThread, StoryThreadEntry

    actor = ThreatActor(name="APT98", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()

    now = datetime.now(UTC)
    entries = []
    for i in range(9):
        entry = Entry(
            feed_id=feed.id,
            title=f"APT98 Report {i + 1}",
            guid=f"threadseed-entry-{i}",
            published_at=now - timedelta(days=i),
        )
        db_session.add(entry)
        await db_session.flush()
        db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
        entries.append(entry)

    # Two stories, four articles between them. The other five only mention APT98.
    for n, (slug, members) in enumerate([("apt98-breaks-in", entries[:2]), ("apt98-comes-back", entries[2:4])]):
        thread = StoryThread(
            slug=slug,
            title=slug.replace("-", " "),
            status="open",
            entry_count=len(members),
            source_count=2,
            first_seen=now - timedelta(days=8 - n),
            last_seen=now - timedelta(days=n),
            key_entities=[{"entity_type": "threat_actor", "entity_id": str(actor.id), "label": "APT98", "count": 2}],
        )
        db_session.add(thread)
        await db_session.flush()
        for member in members:
            db_session.add(StoryThreadEntry(thread_id=thread.id, entry_id=member.id, role="beat"))
    await db_session.flush()

    resp = await client.post("/api/campaigns/auto-detect?min_entries=3&days=30", headers=headers)
    assert resp.status_code == 200
    candidate = next(c for c in resp.json() if c["pivot_entity"]["id"] == str(actor.id))

    assert candidate["evidence"] == "story_threads"
    assert candidate["thread_count"] == 2
    assert {t["slug"] for t in candidate["threads"]} == {"apt98-breaks-in", "apt98-comes-back"}
    # Seeded from the stories, not the whole sweep.
    assert candidate["entry_count"] == 4
    assert len(candidate["entry_ids"]) == 4
    assert candidate["wider_entry_count"] == 9


async def test_auto_detect_ignores_a_single_burst_of_coverage(
    client: AsyncClient,
    headers: dict,
    db_session: AsyncSession,
    user: User,
    feed: Feed,
):
    """One short story is today's news; a campaign has to show duration."""
    from app.models.story_thread import StoryThread, StoryThreadEntry

    actor = ThreatActor(name="APT97", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()

    now = datetime.now(UTC)
    thread = StoryThread(
        slug="apt97-one-day-wonder",
        title="APT97 one day wonder",
        status="open",
        entry_count=3,
        source_count=3,
        first_seen=now - timedelta(days=1),
        last_seen=now,
        key_entities=[{"entity_type": "threat_actor", "entity_id": str(actor.id), "label": "APT97", "count": 3}],
    )
    db_session.add(thread)
    await db_session.flush()

    for i in range(3):
        entry = Entry(
            feed_id=feed.id,
            title=f"APT97 Report {i + 1}",
            guid=f"burst-entry-{i}",
            published_at=now - timedelta(hours=i),
        )
        db_session.add(entry)
        await db_session.flush()
        db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
        db_session.add(StoryThreadEntry(thread_id=thread.id, entry_id=entry.id, role="beat"))
    await db_session.flush()

    resp = await client.post("/api/campaigns/auto-detect?min_entries=3&days=30", headers=headers)
    assert resp.status_code == 200
    candidate = next(c for c in resp.json() if c["pivot_entity"]["id"] == str(actor.id))
    # The volume pass still offers it — one burst is just not thread-backed evidence.
    assert candidate["evidence"] == "entity_volume"
    assert candidate["thread_count"] == 0


# ── PATCH campaign update ────────────────────────────────────────────


async def test_patch_campaign(
    client: AsyncClient,
    headers: dict,
    populated_campaign,
):
    """Verify PATCH method works for campaign updates (fix for frontend compatibility)."""
    campaign, _, _ = populated_campaign

    resp = await client.patch(
        f"/api/campaigns/{campaign.id}",
        json={"name": "Patched Name"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "Patched Name"


# ── Stats: content-type exclusion ─────────────────────────────────────


async def test_stats_top_sources_exclude_machine_records(
    client: AsyncClient,
    headers: dict,
    db_session: AsyncSession,
    populated_campaign,
):
    """Rule-repo and NVD entries should not count toward campaign top sources."""
    campaign, _, _ = populated_campaign

    rule_feed = Feed(
        title="Rule Repo Feed",
        url="https://github.com/elastic/detection-rules-test",
        feed_type="github_repo",
    )
    nvd_feed = Feed(title="NVD Feed", url="https://nvd.example.com", feed_type="nvd")
    db_session.add_all([rule_feed, nvd_feed])
    await db_session.flush()

    for i in range(3):
        rule_entry = Entry(
            feed_id=rule_feed.id,
            title=f"Sigma rule {i}",
            guid=f"stats-rule-entry-{i}",
            metadata_={"content_type": "sigma_rule"},
            published_at=datetime(2026, 1, 15, tzinfo=UTC),
        )
        db_session.add(rule_entry)
        await db_session.flush()
        db_session.add(CampaignEntry(campaign_id=campaign.id, entry_id=rule_entry.id))

    nvd_entry = Entry(
        feed_id=nvd_feed.id,
        title="CVE-2026-9999",
        guid="stats-nvd-entry",
        published_at=datetime(2026, 1, 16, tzinfo=UTC),
    )
    db_session.add(nvd_entry)
    await db_session.flush()
    db_session.add(CampaignEntry(campaign_id=campaign.id, entry_id=nvd_entry.id))
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/stats", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    # All linked entries still count toward entry_count
    assert data["entry_count"] == 6
    # ... but machine records are excluded from top sources
    source_names = [s["feed_name"] for s in data["top_sources"]]
    assert "Rule Repo Feed" not in source_names
    assert "NVD Feed" not in source_names
    assert "Enhancement Test Feed" in source_names
