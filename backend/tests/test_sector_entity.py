"""Sector as a first-class entity.

The vocabulary is seeded into the test schema by conftest (the way the Alembic
migration seeds prod), so these tests exercise the entity surface on top of it:
deterministic ids, slug-addressable routes, the AI door bumping article counts,
pivots through entry_sectors, the victimology profile, notes, watches,
provenance and the registry tools.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.intelligence.enrichment import store_sectors
from app.intelligence.sectors import CANONICAL_SECTORS, sector_uuid
from app.models.entry import Entry
from app.models.entry_sector import EntrySector
from app.models.feed import Feed
from app.models.ransomware import RansomwareVictim, VictimDisclosure
from app.models.sector import Sector, ThreatActorTargetSector
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.search.query_planner import classify_field

HEALTHCARE = sector_uuid("healthcare")


@pytest.fixture
async def feed(db_session):
    f = Feed(title="Sector Feed", url="https://example.com/sectors.xml", feed_type="rss")
    db_session.add(f)
    await db_session.flush()
    return f


async def _entry(db_session, feed_id, n):
    e = Entry(
        feed_id=feed_id,
        title=f"Hospital ransomware {n}",
        guid=f"sector-{n}",
        url=f"https://example.com/sector/{n}",
        published_at=datetime.now(UTC) - timedelta(hours=n),
    )
    db_session.add(e)
    await db_session.flush()
    return e


# --- vocabulary ----------------------------------------------------------------


async def test_vocabulary_is_seeded_with_deterministic_ids(db_session):
    rows = (await db_session.execute(select(Sector))).scalars().all()
    assert {s.slug for s in rows} == set(CANONICAL_SECTORS)
    for s in rows:
        assert s.id == sector_uuid(s.slug)
        assert s.name == CANONICAL_SECTORS[s.slug]
        assert s.description
    assert "banks" in next(s for s in rows if s.slug == "financial-services").aliases


async def test_entry_sector_row_derives_its_fk_from_the_slug(db_session, feed):
    e = await _entry(db_session, feed.id, 1)
    db_session.add(EntrySector(entry_id=e.id, sector="energy"))
    await db_session.flush()
    row = (await db_session.execute(select(EntrySector).where(EntrySector.entry_id == e.id))).scalar_one()
    assert row.sector_id == sector_uuid("energy")


# --- routes --------------------------------------------------------------------


async def test_list_and_get_by_slug_or_uuid(client, auth_headers):
    resp = await client.get("/api/sectors", params={"sort_by": "name", "sort_order": "asc"}, headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == len(CANONICAL_SECTORS)
    assert body["items"][0]["name"] == "Aerospace"
    assert {"targeting_actor_count", "targeting_malware_count", "victim_count"} <= set(body["items"][0])

    by_slug = await client.get("/api/sectors/healthcare", headers=auth_headers)
    assert by_slug.status_code == 200
    assert by_slug.json()["id"] == str(HEALTHCARE)
    by_id = await client.get(f"/api/sectors/{HEALTHCARE}", headers=auth_headers)
    assert by_id.json()["slug"] == "healthcare"
    by_name = await client.get("/api/sectors/Financial%20Services", headers=auth_headers)
    assert by_name.json()["slug"] == "financial-services"

    missing = await client.get("/api/sectors/underwater-basket-weaving", headers=auth_headers)
    assert missing.status_code == 404


async def test_search_matches_name_slug_and_alias(client, auth_headers):
    for q in ("Financial", "financial-services", "banks"):
        resp = await client.get("/api/sectors", params={"search": q}, headers=auth_headers)
        assert [s["slug"] for s in resp.json()["items"]] == ["financial-services"], q


async def test_ai_door_links_bumps_count_and_feeds_pivot_and_profile(client, auth_headers, db_session, feed):
    e1 = await _entry(db_session, feed.id, 1)
    e2 = await _entry(db_session, feed.id, 2)
    actor = ThreatActor(name="Sector Spider")
    db_session.add(actor)
    await db_session.flush()
    db_session.add_all(
        [
            EntryThreatActor(entry_id=e1.id, threat_actor_id=actor.id),
            EntryThreatActor(entry_id=e2.id, threat_actor_id=actor.id),
        ]
    )
    await db_session.flush()

    # The one-pass analysis emits free phrasing; the door normalizes it and
    # stores the FK. A duplicate on the same entry is a no-op, not a second bump.
    stored = await store_sectors(db_session, e1.id, [{"name": "Hospitals", "confidence": "high"}])
    assert stored[0]["id"] == str(HEALTHCARE) and stored[0]["name"] == "Healthcare"
    await store_sectors(db_session, e1.id, [{"name": "healthcare"}])
    await store_sectors(db_session, e2.id, [{"name": "Health care sector"}, {"name": "not a sector"}])
    await db_session.flush()

    sector = (await db_session.execute(select(Sector).where(Sector.id == HEALTHCARE))).scalar_one()
    assert sector.article_count == 2

    linked = await client.get(f"/api/entries/{e1.id}/sectors", headers=auth_headers)
    assert linked.status_code == 200
    assert linked.json()[0]["id"] == str(HEALTHCARE)
    assert linked.json()[0]["sector"] == "healthcare"  # legacy field kept

    pivot = await client.get(f"/api/intelligence/pivot/sector/{HEALTHCARE}", headers=auth_headers)
    assert pivot.status_code == 200
    related_actors = pivot.json()["related"]["threat_actors"]
    assert [a["name"] for a in related_actors] == ["Sector Spider"]
    assert "sector_relationship" not in related_actors[0]  # reported, not asserted

    db_session.add(ThreatActorTargetSector(threat_actor_id=actor.id, sector_id=HEALTHCARE, source="analyst"))
    await db_session.flush()

    profile = await client.get("/api/sectors/healthcare/profile", headers=auth_headers)
    assert profile.status_code == 200
    body = profile.json()
    assert body["sector"]["slug"] == "healthcare"
    assert body["reported_actors"] == [{"id": str(actor.id), "name": "Sector Spider", "article_count": 2}]
    assert body["asserted_actors"][0]["source"] == "analyst"
    assert [e["id"] for e in body["recent_entries"]] == [str(e1.id), str(e2.id)]  # newest first
    assert body["victims"]["total"] == 0

    entries = await client.get(
        "/api/entries", params={"entity_type": "sector", "entity_id": str(HEALTHCARE)}, headers=auth_headers
    )
    assert entries.status_code == 200
    assert {e["title"] for e in entries.json()["items"]} == {e1.title, e2.title}


async def test_unlink_decrements_article_count(client, auth_headers, db_session, feed):
    e = await _entry(db_session, feed.id, 1)
    await store_sectors(db_session, e.id, [{"name": "retail"}])
    await db_session.commit()

    resp = await client.delete(f"/api/entries/{e.id}/sectors/{sector_uuid('retail')}", headers=auth_headers)
    assert resp.status_code == 204
    again = await client.delete(f"/api/entries/{e.id}/sectors/{sector_uuid('retail')}", headers=auth_headers)
    assert again.status_code == 404
    count = (await client.get("/api/sectors/retail", headers=auth_headers)).json()["article_count"]
    assert count == 0


async def test_profile_reads_leak_site_victims(client, auth_headers, db_session):
    victim = RansomwareVictim(name="Mercy General", sector="healthcare")
    db_session.add(victim)
    await db_session.flush()
    db_session.add_all(
        [
            VictimDisclosure(
                victim_id=victim.id,
                group_name_raw="lockbit3",
                posted_at=datetime.now(UTC) - timedelta(days=d),
                sector="healthcare",
                source="ransomware.live",
                guid=f"victim-{d}",
            )
            for d in (1, 2, 400)
        ]
    )
    await db_session.flush()

    body = (await client.get("/api/sectors/healthcare/profile", headers=auth_headers)).json()
    assert body["victims"]["total"] == 3
    assert body["victims"]["in_window"] == 2
    assert body["victims"]["top_groups"] == [{"group": "lockbit3", "victims": 2}]
    assert body["victims"]["recent"][0]["victim_name"] == "Mercy General"

    listing = (await client.get("/api/sectors/healthcare", headers=auth_headers)).json()
    assert listing["victim_count"] == 2


# --- the entity apparatus ------------------------------------------------------


async def test_sector_is_an_entity_search_field():
    assert classify_field("sector") == "entity"
    assert classify_field("sector.slug") == "entity"


async def test_description_edit_records_provenance(client, auth_headers):
    resp = await client.put(
        f"/api/entities/sectors/{HEALTHCARE}",
        json={"description": "Hospitals and health systems."},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "Healthcare"  # name is immutable, not in the body

    prov = await client.get(f"/api/entities/sector/{HEALTHCARE}/provenance", headers=auth_headers)
    assert prov.status_code == 200
    assert "description" in prov.json()["fields"]


async def test_notes_and_watches_accept_sector(client, auth_headers):
    note = await client.post(
        "/api/entity-notes",
        json={"entity_type": "sector", "entity_id": str(HEALTHCARE), "content": "Watch for Qilin here."},
        headers=auth_headers,
    )
    assert note.status_code == 201, note.text

    watch = await client.put(
        "/api/intelligence/watchlist",
        json={"entity_type": "sector", "entity_id": str(HEALTHCARE), "mode": "watch"},
        headers=auth_headers,
    )
    assert watch.status_code in (200, 201), watch.text
    listed = await client.get("/api/intelligence/watchlist", headers=auth_headers)
    assert [w["entity_name"] for w in listed.json() if w["entity_type"] == "sector"] == ["Healthcare"]


async def test_registry_tools(db_session, test_user, feed):
    from app.tools import TOOL_DEFINITIONS, execute_tool

    names = {t["name"] for t in TOOL_DEFINITIONS}
    assert {"list_sectors", "get_sector", "who_targets_sector", "sector_victims"} <= names
    pivot_tool = next(t for t in TOOL_DEFINITIONS if t["name"] == "pivot_entity")
    assert "sector" in pivot_tool["input_schema"]["properties"]["entity_type"]["enum"]

    e = await _entry(db_session, feed.id, 1)
    await store_sectors(db_session, e.id, [{"name": "Energy"}])
    await db_session.flush()

    listed = json.loads(await execute_tool("list_sectors", {"search": "oil"}, db_session, test_user.id))
    assert [s["slug"] for s in listed["sectors"]] == ["energy"]
    got = json.loads(await execute_tool("get_sector", {"sector": "energy"}, db_session, test_user.id))
    assert got["sector"]["id"] == str(sector_uuid("energy"))
    assert [x["id"] for x in got["recent_entries"]] == [str(e.id)]
    who = json.loads(
        await execute_tool(
            "who_targets_sector", {"sector": str(uuid.UUID(got["sector"]["id"]))}, db_session, test_user.id
        )
    )
    assert who["reported_actors"] == []
