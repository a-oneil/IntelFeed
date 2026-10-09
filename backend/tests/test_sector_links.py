"""Target-sector junctions: the claims layer behind the sector chips.

Covers the service (precedence, rollup ownership, the cache rebuild), the
rewritten nightly rollup, the analyst endpoints on actors/malware/campaigns,
merge handling, the junction-backed search filter, and the backfill classifier.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.intelligence.enrichment import store_sectors
from app.intelligence.sector_backfill import classify
from app.intelligence.sectors import sector_uuid
from app.models.campaign import Campaign, CampaignEntry
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.services.sector_links import (
    add_target_sector,
    list_target_sectors,
    refresh_targeted_sectors_cache,
    remove_target_sector,
    set_rollup_sectors,
)
from app.workers.maintenance import rollup_targeted_sectors_for_session

HEALTHCARE = sector_uuid("healthcare")
FINANCE = sector_uuid("financial-services")
ENERGY = sector_uuid("energy")


@pytest.fixture
async def feed(db_session):
    f = Feed(title="Sector Feed", url="https://example.com/sectors.xml", feed_type="rss")
    db_session.add(f)
    await db_session.flush()
    return f


async def _entry(db_session, feed_id, n):
    e = Entry(
        feed_id=feed_id,
        title=f"Article {n}",
        guid=f"sector-links-{n}",
        url=f"https://example.com/sl/{n}",
        published_at=datetime.now(UTC) - timedelta(hours=n),
    )
    db_session.add(e)
    await db_session.flush()
    return e


async def _actor(db_session, name="Sector Spider"):
    a = ThreatActor(name=name)
    db_session.add(a)
    await db_session.flush()
    return a


# --- service -------------------------------------------------------------------


async def test_add_keeps_the_strongest_source_and_never_weakens(db_session):
    actor = await _actor(db_session)
    assert await add_target_sector(db_session, "threat_actor", actor.id, HEALTHCARE, "rollup", article_count=3)
    assert not await add_target_sector(db_session, "threat_actor", actor.id, HEALTHCARE, "rollup", article_count=3)
    assert await add_target_sector(db_session, "threat_actor", actor.id, HEALTHCARE, "analyst")
    # A later, weaker assertion does not demote the analyst's claim.
    assert not await add_target_sector(db_session, "threat_actor", actor.id, HEALTHCARE, "enrichment")
    rows = await list_target_sectors(db_session, "threat_actor", actor.id)
    assert [(r["slug"], r["source"], r["article_count"]) for r in rows] == [("healthcare", "analyst", 3)]

    with pytest.raises(ValueError):
        await add_target_sector(db_session, "threat_actor", actor.id, HEALTHCARE, "guess")
    with pytest.raises(ValueError):
        await list_target_sectors(db_session, "country", actor.id)


async def test_rollup_owns_only_its_rows(db_session):
    actor = await _actor(db_session)
    await add_target_sector(db_session, "threat_actor", actor.id, FINANCE, "analyst")
    await set_rollup_sectors(db_session, "threat_actor", actor.id, {HEALTHCARE: 4, ENERGY: 2})
    slugs = {r["slug"]: r for r in await list_target_sectors(db_session, "threat_actor", actor.id)}
    assert set(slugs) == {"financial-services", "healthcare", "energy"}
    assert slugs["healthcare"]["source"] == "rollup" and slugs["healthcare"]["article_count"] == 4

    # Evidence moves on: energy drops out, healthcare count changes, finance (analyst) stays.
    assert await set_rollup_sectors(db_session, "threat_actor", actor.id, {HEALTHCARE: 5})
    slugs = {r["slug"]: r for r in await list_target_sectors(db_session, "threat_actor", actor.id)}
    assert set(slugs) == {"financial-services", "healthcare"}
    assert slugs["healthcare"]["article_count"] == 5
    assert not await set_rollup_sectors(db_session, "threat_actor", actor.id, {HEALTHCARE: 5})

    labels = await refresh_targeted_sectors_cache(db_session, "threat_actor", actor)
    assert labels == ["Healthcare", "Financial Services"]  # evidence first, then alphabetical
    assert actor.targeted_sectors == labels

    assert await remove_target_sector(db_session, "threat_actor", actor.id, FINANCE)
    assert not await remove_target_sector(db_session, "threat_actor", actor.id, FINANCE)
    assert await refresh_targeted_sectors_cache(db_session, "threat_actor", actor) == ["Healthcare"]


# --- the nightly rollup ----------------------------------------------------------


async def test_rollup_derives_rows_from_the_entities_articles(db_session, feed):
    actor = await _actor(db_session)
    lonely = await _actor(db_session, "One Article Crew")
    e1, e2, e3 = [await _entry(db_session, feed.id, n) for n in (1, 2, 3)]
    db_session.add_all(
        [
            EntryThreatActor(entry_id=e1.id, threat_actor_id=actor.id),
            EntryThreatActor(entry_id=e2.id, threat_actor_id=actor.id),
            EntryThreatActor(entry_id=e3.id, threat_actor_id=lonely.id),
        ]
    )
    await db_session.flush()
    for e in (e1, e2, e3):
        await store_sectors(db_session, e.id, [{"name": "Healthcare"}])
    await store_sectors(db_session, e1.id, [{"name": "Energy"}])  # one article: below the floor
    # A stale rollup row with no evidence behind it, and an analyst row that must survive.
    await add_target_sector(db_session, "threat_actor", actor.id, FINANCE, "rollup", article_count=9)
    await add_target_sector(db_session, "malware", (await _malware(db_session)).id, ENERGY, "analyst")

    stats = await rollup_targeted_sectors_for_session(db_session)
    assert stats["threat_actor"]["with_observed_sectors"] == 1  # lonely has a single article
    assert stats["threat_actor"]["updated"] == 1

    rows = {r["slug"]: r for r in await list_target_sectors(db_session, "threat_actor", actor.id)}
    assert set(rows) == {"healthcare"}
    assert rows["healthcare"] == {**rows["healthcare"], "source": "rollup", "article_count": 2}
    await db_session.refresh(actor)
    assert actor.targeted_sectors == ["Healthcare"]
    assert await list_target_sectors(db_session, "threat_actor", lonely.id) == []

    # Running again changes nothing.
    assert (await rollup_targeted_sectors_for_session(db_session))["threat_actor"]["updated"] == 0


async def _malware(db_session, name="SectorLocker"):
    m = MalwareFamily(name=name)
    db_session.add(m)
    await db_session.flush()
    return m


# --- endpoints ----------------------------------------------------------------------


async def test_actor_target_sector_endpoints(client, auth_headers, db_session):
    actor = await _actor(db_session)
    await db_session.commit()
    base = f"/api/entities/threat_actor/{actor.id}/target-sectors"

    resp = await client.post(base, json={"sector": "banks"}, headers=auth_headers)
    assert resp.status_code == 201, resp.text
    assert resp.json()["slug"] == "financial-services" and resp.json()["changed"] is True

    listed = await client.get(base, headers=auth_headers)
    assert [(r["slug"], r["source"]) for r in listed.json()] == [("financial-services", "analyst")]

    row = (await db_session.execute(select(ThreatActor).where(ThreatActor.id == actor.id))).scalar_one()
    await db_session.refresh(row)
    assert row.targeted_sectors == ["Financial Services"]

    prov = await client.get(f"/api/entities/threat_actor/{actor.id}/provenance", headers=auth_headers)
    assert "targeted_sectors" in prov.json()["fields"]

    gone = await client.delete(f"{base}/financial-services", headers=auth_headers)
    assert gone.status_code == 204
    assert (await client.get(base, headers=auth_headers)).json() == []
    assert (await client.delete(f"{base}/financial-services", headers=auth_headers)).status_code == 404

    bad = await client.post(
        f"/api/entities/country/{actor.id}/target-sectors", json={"sector": "x"}, headers=auth_headers
    )
    assert bad.status_code == 400


async def test_campaign_sector_endpoints(client, auth_headers, db_session, test_user, feed):
    campaign = Campaign(name="Hospital wave", created_by=test_user.id)
    db_session.add(campaign)
    await db_session.flush()
    e1 = await _entry(db_session, feed.id, 1)
    db_session.add(CampaignEntry(campaign_id=campaign.id, entry_id=e1.id))
    await db_session.flush()
    await store_sectors(db_session, e1.id, [{"name": "Healthcare"}, {"name": "Energy"}])
    await db_session.commit()
    base = f"/api/campaigns/{campaign.id}/sectors"

    suggested = await client.get(f"{base}/suggested", headers=auth_headers)
    assert suggested.status_code == 200, suggested.text
    assert {s["slug"] for s in suggested.json()} == {"healthcare", "energy"}

    added = await client.post(base, json={"sector": "healthcare"}, headers=auth_headers)
    assert added.status_code == 201, added.text
    assert (await client.post(base, json={"sector": "healthcare"}, headers=auth_headers)).status_code == 409
    assert [s["slug"] for s in (await client.get(base, headers=auth_headers)).json()] == ["healthcare"]
    assert {s["slug"] for s in (await client.get(f"{base}/suggested", headers=auth_headers)).json()} == {"energy"}

    profile = await client.get("/api/sectors/healthcare/profile", headers=auth_headers)
    assert [c["name"] for c in profile.json()["campaigns"]] == ["Hospital wave"]

    assert (await client.delete(f"{base}/healthcare", headers=auth_headers)).status_code == 204
    assert (await client.get(base, headers=auth_headers)).json() == []


# --- merge, search, backfill ------------------------------------------------------


async def test_merge_moves_claims_onto_the_survivor(db_session):
    from app.api.entity_merge import _move_target_sectors

    target = await _actor(db_session, "Survivor")
    source = await _actor(db_session, "Duplicate")
    await add_target_sector(db_session, "threat_actor", target.id, HEALTHCARE, "rollup", article_count=2)
    await add_target_sector(db_session, "threat_actor", source.id, HEALTHCARE, "analyst", article_count=1)
    await add_target_sector(db_session, "threat_actor", source.id, ENERGY, "seed")

    moved = await _move_target_sectors(db_session, "threat_actor", source.id, target)
    assert moved == 1  # energy moved; healthcare merged into the existing row
    rows = {r["slug"]: r for r in await list_target_sectors(db_session, "threat_actor", target.id)}
    assert rows["healthcare"]["source"] == "analyst" and rows["healthcare"]["article_count"] == 2
    assert rows["energy"]["source"] == "seed"
    assert await list_target_sectors(db_session, "threat_actor", source.id) == []
    assert target.targeted_sectors == ["Healthcare", "Energy"]


async def test_search_filter_reads_the_junction(db_session):
    from app.search.entity_builder import _build_join_condition
    from app.search.query_planner import EntityCondition

    actor = await _actor(db_session)
    other = await _actor(db_session, "Bystander")
    await add_target_sector(db_session, "threat_actor", actor.id, FINANCE, "analyst")
    cond = _build_join_condition(
        "threat_actor.sector", EntityCondition(field="threat_actor.sector", op="contains", value="banks")
    )
    hits = (await db_session.execute(select(ThreatActor.id).where(cond))).scalars().all()
    assert hits == [actor.id]
    assert other.id not in hits


def test_backfill_classifier():
    countries = {"ukraine", "ukrainian", "south korea", "israel", "israeli"}
    assert classify("Healthcare").kind == "mapped"
    assert classify("Government agencies").slug == "government"
    assert classify("Banking Customers").slug == "financial-services"
    assert classify("Electric Utilities").slug == "energy"
    assert classify("Think tanks").slug == "ngo"
    assert classify("Middle East").kind == "dropped_geo"
    ukraine = classify("Ukraine", countries)
    assert ukraine.kind == "rehomed_country" and ukraine.country == "ukraine"
    assert classify("Israeli organizations", countries).country == "israeli"
    assert classify("Email servers").kind == "dropped_asset"
    assert classify("Android users").kind == "dropped_asset"
    assert classify("e").kind == "dropped_junk"
    assert classify("Various organizations").kind == "dropped_junk"
    assert classify("Fundraising for militia groups").kind == "dropped_asset"
    assert classify("Winter Olympics").kind == "dropped_other"
