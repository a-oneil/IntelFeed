"""Tests for the Atlas calendar + map endpoints and the new entries filters."""

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.campaign import Campaign, CampaignEntry
from app.models.category import Category
from app.models.country import Country, EntryCountry
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.saved_search import SavedSearch
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.user import User

# ── Helpers ─────────────────────────────────────────────────────


async def _mk_feed(db: AsyncSession, title: str, url: str, *, category_id=None) -> Feed:
    feed = Feed(title=title, url=url, feed_type="rss", category_id=category_id)
    db.add(feed)
    await db.flush()
    return feed


async def _mk_entry(
    db: AsyncSession,
    feed: Feed,
    *,
    title: str = "e",
    guid: str | None = None,
    published_at: datetime | None = None,
) -> Entry:
    e = Entry(
        feed_id=feed.id,
        title=title,
        guid=guid or f"g-{uuid.uuid4().hex[:10]}",
        url=f"https://example.com/{uuid.uuid4().hex[:8]}",
        published_at=published_at,
    )
    db.add(e)
    await db.flush()
    return e


async def _mk_country(
    db: AsyncSession, name: str, *, iso_code: str | None = None, region: str | None = None
) -> Country:
    c = Country(name=name, iso_code=iso_code, region=region)
    db.add(c)
    await db.flush()
    return c


async def _link_country(
    db: AsyncSession,
    entry: Entry,
    country: Country,
    *,
    role: str = "mentioned",
    confidence: str = "medium",
) -> None:
    db.add(
        EntryCountry(
            entry_id=entry.id,
            country_id=country.id,
            role=role,
            confidence=confidence,
        )
    )
    await db.flush()


# ── Calendar ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_calendar_empty_db(client: AsyncClient, auth_headers: dict):
    resp = await client.get(
        "/api/entries/calendar?from=2026-01-01&to=2026-01-31",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_calendar_groups_by_day(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
    test_category: Category,
):
    feed_a = await _mk_feed(db_session, "Feed A", "https://a.example/rss", category_id=test_category.id)
    feed_b = await _mk_feed(db_session, "Feed B", "https://b.example/rss", category_id=test_category.id)
    day_a = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    day_b = datetime(2026, 4, 11, 9, 0, tzinfo=UTC)
    for _ in range(2):
        await _mk_entry(db_session, feed_a, published_at=day_a)
    await _mk_entry(db_session, feed_b, published_at=day_a)
    await _mk_entry(db_session, feed_b, published_at=day_b)

    resp = await client.get(
        "/api/entries/calendar?from=2026-04-01&to=2026-04-30",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    buckets = {b["date"]: b["entry_count"] for b in resp.json()}
    assert buckets == {"2026-04-10": 3, "2026-04-11": 1}


@pytest.mark.asyncio
async def test_calendar_feed_filter(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed_a = await _mk_feed(db_session, "Feed A", "https://a2.example/rss")
    feed_b = await _mk_feed(db_session, "Feed B", "https://b2.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    await _mk_entry(db_session, feed_a, published_at=pub)
    await _mk_entry(db_session, feed_a, published_at=pub)
    await _mk_entry(db_session, feed_b, published_at=pub)

    resp = await client.get(
        f"/api/entries/calendar?from=2026-04-01&to=2026-04-30&feed_id={feed_a.id}",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == [{"date": "2026-04-10", "entry_count": 2}]


@pytest.mark.asyncio
async def test_calendar_category_filter(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
    test_user: User,
):
    cat = Category(created_by=test_user.id, name="Cat A")
    db_session.add(cat)
    await db_session.flush()
    feed_in = await _mk_feed(db_session, "F1", "https://c1.example/rss", category_id=cat.id)
    feed_out = await _mk_feed(db_session, "F2", "https://c2.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    await _mk_entry(db_session, feed_in, published_at=pub)
    await _mk_entry(db_session, feed_out, published_at=pub)

    resp = await client.get(
        f"/api/entries/calendar?from=2026-04-01&to=2026-04-30&category_id={cat.id}",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == [{"date": "2026-04-10", "entry_count": 1}]


@pytest.mark.asyncio
async def test_calendar_entity_threat_actor(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
    test_threat_actor: ThreatActor,
):
    feed = await _mk_feed(db_session, "F", "https://e1.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    e1 = await _mk_entry(db_session, feed, published_at=pub)
    await _mk_entry(db_session, feed, published_at=pub)
    db_session.add(EntryThreatActor(entry_id=e1.id, threat_actor_id=test_threat_actor.id))
    await db_session.flush()

    resp = await client.get(
        f"/api/entries/calendar?from=2026-04-01&to=2026-04-30"
        f"&entity_type=threat_actor&entity_id={test_threat_actor.id}",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == [{"date": "2026-04-10", "entry_count": 1}]


@pytest.mark.asyncio
async def test_calendar_entity_country(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = await _mk_feed(db_session, "F", "https://e2.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    country = await _mk_country(db_session, "Russia", iso_code="RUS")
    e1 = await _mk_entry(db_session, feed, published_at=pub)
    await _mk_entry(db_session, feed, published_at=pub)
    await _link_country(db_session, e1, country, role="origin")

    resp = await client.get(
        f"/api/entries/calendar?from=2026-04-01&to=2026-04-30&entity_type=country&entity_id={country.id}",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == [{"date": "2026-04-10", "entry_count": 1}]


@pytest.mark.asyncio
async def test_calendar_region_filter(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = await _mk_feed(db_session, "F", "https://e3.example/rss")
    europe_country = await _mk_country(db_session, "Germany", iso_code="DEU", region="Europe")
    asia_country = await _mk_country(db_session, "Japan", iso_code="JPN", region="Asia")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    e_eu = await _mk_entry(db_session, feed, published_at=pub)
    e_as = await _mk_entry(db_session, feed, published_at=pub)
    await _link_country(db_session, e_eu, europe_country)
    await _link_country(db_session, e_as, asia_country)

    resp = await client.get(
        "/api/entries/calendar?from=2026-04-01&to=2026-04-30&region=Europe",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == [{"date": "2026-04-10", "entry_count": 1}]


@pytest.mark.asyncio
async def test_calendar_campaign_filter(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
    test_user: User,
):
    feed = await _mk_feed(db_session, "F", "https://e4.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    e1 = await _mk_entry(db_session, feed, published_at=pub)
    await _mk_entry(db_session, feed, published_at=pub)
    camp = Campaign(name="Op X", created_by=test_user.id)
    db_session.add(camp)
    await db_session.flush()
    db_session.add(CampaignEntry(campaign_id=camp.id, entry_id=e1.id))
    await db_session.flush()

    resp = await client.get(
        f"/api/entries/calendar?from=2026-04-01&to=2026-04-30&campaign_id={camp.id}",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == [{"date": "2026-04-10", "entry_count": 1}]


@pytest.mark.asyncio
async def test_calendar_saved_search_filter(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
    test_user: User,
):
    feed = await _mk_feed(db_session, "F", "https://e5.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    e1 = await _mk_entry(db_session, feed, title="ransomware spike", published_at=pub)
    await _mk_entry(db_session, feed, title="other thing", published_at=pub)
    saved = SavedSearch(created_by=test_user.id, name="ransom-watch", query="ransomware")
    db_session.add(saved)
    await db_session.flush()

    # Mock meilisearch to return only e1
    fake_result = {"hits": [{"id": str(e1.id)}], "estimatedTotalHits": 1}
    with patch("app.search.meili_builder.execute_entry_search", return_value=fake_result):
        resp = await client.get(
            f"/api/entries/calendar?from=2026-04-01&to=2026-04-30&saved_search_id={saved.id}",
            headers=auth_headers,
        )
    assert resp.status_code == 200
    assert resp.json() == [{"date": "2026-04-10", "entry_count": 1}]


@pytest.mark.asyncio
async def test_calendar_range_too_long(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/entries/calendar?from=2024-01-01&to=2026-01-01", headers=auth_headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_calendar_top_entities_range_cap(client: AsyncClient, auth_headers: dict):
    resp = await client.get(
        "/api/entries/calendar?from=2026-01-01&to=2026-06-01&with_top_entities=true",
        headers=auth_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_calendar_with_top_entities(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
    test_threat_actor: ThreatActor,
):
    feed = await _mk_feed(db_session, "F", "https://etop.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    other = ThreatActor(name="APT-Other")
    db_session.add(other)
    await db_session.flush()
    # 3 entries link APT29, 1 links APT-Other
    for _ in range(3):
        e = await _mk_entry(db_session, feed, published_at=pub)
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=test_threat_actor.id))
    e_other = await _mk_entry(db_session, feed, published_at=pub)
    db_session.add(EntryThreatActor(entry_id=e_other.id, threat_actor_id=other.id))
    await db_session.flush()

    resp = await client.get(
        "/api/entries/calendar?from=2026-04-01&to=2026-04-30&with_top_entities=true",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    bucket = data[0]
    assert bucket["entry_count"] == 4
    assert bucket["top_entities"]
    # Should be sorted by count desc; APT29 (3) before APT-Other (1)
    counts = [te["count"] for te in bucket["top_entities"]]
    assert counts == sorted(counts, reverse=True)
    assert bucket["top_entities"][0]["name"] == "APT29"
    assert bucket["top_entities"][0]["count"] == 3


# ── Map ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_map_empty_db(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/entries/map?from=2026-01-01&to=2026-01-31", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_map_basic_role_breakdown(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = await _mk_feed(db_session, "F", "https://m1.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    russia = await _mk_country(db_session, "Russia", iso_code="RUS", region="Europe")
    germany = await _mk_country(db_session, "Germany", iso_code="DEU", region="Europe")
    e1 = await _mk_entry(db_session, feed, published_at=pub)
    e2 = await _mk_entry(db_session, feed, published_at=pub)
    e3 = await _mk_entry(db_session, feed, published_at=pub)
    await _link_country(db_session, e1, russia, role="origin", confidence="high")
    await _link_country(db_session, e2, russia, role="origin", confidence="medium")
    await _link_country(db_session, e3, russia, role="target", confidence="high")
    await _link_country(db_session, e1, germany, role="target", confidence="high")

    resp = await client.get("/api/entries/map?from=2026-04-01&to=2026-04-30", headers=auth_headers)
    assert resp.status_code == 200
    by_iso = {b["iso_code"]: b for b in resp.json()}
    assert by_iso["RUS"]["entry_count"] == 3
    assert by_iso["RUS"]["role_breakdown"] == {"origin": 2, "target": 1}
    assert by_iso["DEU"]["entry_count"] == 1
    assert by_iso["DEU"]["role_breakdown"] == {"target": 1}


@pytest.mark.asyncio
async def test_map_role_filter(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = await _mk_feed(db_session, "F", "https://m2.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    russia = await _mk_country(db_session, "Russia", iso_code="RUS")
    e1 = await _mk_entry(db_session, feed, published_at=pub)
    e2 = await _mk_entry(db_session, feed, published_at=pub)
    await _link_country(db_session, e1, russia, role="origin")
    await _link_country(db_session, e2, russia, role="target")

    resp = await client.get(
        "/api/entries/map?from=2026-04-01&to=2026-04-30&role=origin",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["entry_count"] == 1
    assert data[0]["role_breakdown"] == {"origin": 1}


@pytest.mark.asyncio
async def test_map_min_confidence_filter(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = await _mk_feed(db_session, "F", "https://m3.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    russia = await _mk_country(db_session, "Russia", iso_code="RUS")
    e1 = await _mk_entry(db_session, feed, published_at=pub)
    e2 = await _mk_entry(db_session, feed, published_at=pub)
    await _link_country(db_session, e1, russia, role="origin", confidence="high")
    await _link_country(db_session, e2, russia, role="origin", confidence="low")

    resp = await client.get(
        "/api/entries/map?from=2026-04-01&to=2026-04-30&min_confidence=high",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["entry_count"] == 1


@pytest.mark.asyncio
async def test_map_region_filter(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = await _mk_feed(db_session, "F", "https://m4.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    germany = await _mk_country(db_session, "Germany", iso_code="DEU", region="Europe")
    japan = await _mk_country(db_session, "Japan", iso_code="JPN", region="Asia")
    e1 = await _mk_entry(db_session, feed, published_at=pub)
    e2 = await _mk_entry(db_session, feed, published_at=pub)
    await _link_country(db_session, e1, germany, role="target")
    await _link_country(db_session, e2, japan, role="target")

    resp = await client.get(
        "/api/entries/map?from=2026-04-01&to=2026-04-30&region=Europe",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["iso_code"] == "DEU"


@pytest.mark.asyncio
async def test_map_country_with_null_iso(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = await _mk_feed(db_session, "F", "https://m5.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    odd = await _mk_country(db_session, "Atlantis", iso_code=None)
    e1 = await _mk_entry(db_session, feed, published_at=pub)
    await _link_country(db_session, e1, odd, role="mentioned")

    resp = await client.get("/api/entries/map?from=2026-04-01&to=2026-04-30", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["iso_code"] is None
    assert data[0]["country_name"] == "Atlantis"


@pytest.mark.asyncio
async def test_map_invalid_role(client: AsyncClient, auth_headers: dict):
    resp = await client.get(
        "/api/entries/map?from=2026-04-01&to=2026-04-30&role=bogus",
        headers=auth_headers,
    )
    assert resp.status_code == 422


# ── /api/entries filter extension ───────────────────────────────


@pytest.mark.asyncio
async def test_entries_country_id_filter(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = await _mk_feed(db_session, "F", "https://x1.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    russia = await _mk_country(db_session, "Russia", iso_code="RUS")
    e_with = await _mk_entry(db_session, feed, title="linked", published_at=pub)
    await _mk_entry(db_session, feed, title="unlinked", published_at=pub)
    await _link_country(db_session, e_with, russia, role="origin")

    resp = await client.get(f"/api/entries?country_id={russia.id}", headers=auth_headers)
    assert resp.status_code == 200
    titles = [e["title"] for e in resp.json()["items"]]
    assert titles == ["linked"]


@pytest.mark.asyncio
async def test_entries_country_role_narrows(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = await _mk_feed(db_session, "F", "https://x2.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    russia = await _mk_country(db_session, "Russia", iso_code="RUS")
    e_origin = await _mk_entry(db_session, feed, title="origin entry", published_at=pub)
    e_target = await _mk_entry(db_session, feed, title="target entry", published_at=pub)
    await _link_country(db_session, e_origin, russia, role="origin")
    await _link_country(db_session, e_target, russia, role="target")

    resp = await client.get(
        f"/api/entries?country_id={russia.id}&country_role=origin",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    titles = [e["title"] for e in resp.json()["items"]]
    assert titles == ["origin entry"]


@pytest.mark.asyncio
async def test_entries_campaign_filter(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
    test_user: User,
):
    feed = await _mk_feed(db_session, "F", "https://x3.example/rss")
    pub = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    e_in = await _mk_entry(db_session, feed, title="in camp", published_at=pub)
    await _mk_entry(db_session, feed, title="not in camp", published_at=pub)
    camp = Campaign(name="Op Y", created_by=test_user.id)
    db_session.add(camp)
    await db_session.flush()
    db_session.add(CampaignEntry(campaign_id=camp.id, entry_id=e_in.id))
    await db_session.flush()

    resp = await client.get(f"/api/entries?campaign_id={camp.id}", headers=auth_headers)
    assert resp.status_code == 200
    titles = [e["title"] for e in resp.json()["items"]]
    assert titles == ["in camp"]


@pytest.mark.asyncio
async def test_entries_invalid_country_role(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    russia = await _mk_country(db_session, "Russia", iso_code="RUS")
    resp = await client.get(
        f"/api/entries?country_id={russia.id}&country_role=bogus",
        headers=auth_headers,
    )
    assert resp.status_code == 422
