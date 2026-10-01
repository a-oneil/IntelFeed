"""Intel profiles: CRUD, threat-surface matching, exposure report generation."""

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.sectors import sector_uuid
from app.models.country import Country, EntryCountry
from app.models.country_junction import ThreatActorTargetCountry
from app.models.entry import Entry
from app.models.entry_sector import EntrySector
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.sector import MalwareTargetSector, ThreatActorTargetSector
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.user import User


@pytest_asyncio.fixture
async def scope_data(db_session: AsyncSession, test_user: User):
    """A country + sector scope with one fully-matched actor, one region-only
    actor, and one sector-matched malware family."""
    feed = Feed(title="Intel Feed", url="https://example.com/feed.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    us = Country(name="United States", iso_code="US")
    de = Country(name="Germany", iso_code="DE")
    spider = ThreatActor(name="Scattered Spider", aliases=["UNC3944"], targeted_sectors=["Financial Services"])
    apt28 = ThreatActor(name="APT28", aliases=["Fancy Bear"])
    inc = MalwareFamily(name="INC Ransom", malware_type="ransomware", targeted_sectors=["healthcare"])
    db_session.add_all([us, de, spider, apt28, inc])
    await db_session.flush()

    now = datetime.now(UTC)
    # In-window entry linking spider + US + financial-services sector.
    e1 = Entry(feed_id=feed.id, title="Spider hits US banks", published_at=now - timedelta(days=3), guid="ip-1")
    # In-window entry linking apt28 + DE (region only, no scope sector).
    e2 = Entry(feed_id=feed.id, title="APT28 in Germany", published_at=now - timedelta(days=5), guid="ip-2")
    # Out-of-window entry — must not count.
    e3 = Entry(feed_id=feed.id, title="Old spider news", published_at=now - timedelta(days=400), guid="ip-3")
    # In-window entry linking malware + healthcare sector.
    e4 = Entry(feed_id=feed.id, title="INC hits hospitals", published_at=now - timedelta(days=2), guid="ip-4")
    db_session.add_all([e1, e2, e3, e4])
    await db_session.flush()

    db_session.add_all(
        [
            EntryThreatActor(entry_id=e1.id, threat_actor_id=spider.id),
            EntryCountry(entry_id=e1.id, country_id=us.id),
            EntrySector(entry_id=e1.id, sector="financial-services"),
            EntryThreatActor(entry_id=e2.id, threat_actor_id=apt28.id),
            EntryCountry(entry_id=e2.id, country_id=de.id),
            EntryThreatActor(entry_id=e3.id, threat_actor_id=spider.id),
            EntryCountry(entry_id=e3.id, country_id=us.id),
            EntryMalware(entry_id=e4.id, malware_family_id=inc.id),
            EntrySector(entry_id=e4.id, sector="healthcare"),
            # Claim: APT28 targets Germany (rides alongside the co-occurrence).
            ThreatActorTargetCountry(threat_actor_id=apt28.id, country_id=de.id),
            # Sector claims live on the target-sector junctions; the label arrays
            # above are only the read cache those junctions rebuild.
            ThreatActorTargetSector(
                threat_actor_id=spider.id, sector_id=sector_uuid("financial-services"), source="seed"
            ),
            MalwareTargetSector(malware_family_id=inc.id, sector_id=sector_uuid("healthcare"), source="seed"),
        ]
    )
    await db_session.flush()

    return {
        "us": us,
        "de": de,
        "spider": spider,
        "apt28": apt28,
        "inc": inc,
        "entries": [e1, e2, e3, e4],
    }


@pytest.mark.asyncio
async def test_profile_crud(client: AsyncClient, auth_headers: dict, scope_data):
    us = scope_data["us"]
    resp = await client.post(
        "/api/intel-profiles",
        json={
            "name": "FinServ portfolio",
            "country_ids": [str(us.id)],
            "sectors": ["Financial Services", "banks"],  # normalized + deduped
            "window_days": 90,
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201, resp.text
    profile = resp.json()
    assert profile["sectors"] == ["financial-services"]
    assert profile["countries"] == [{"id": str(us.id), "name": "United States"}]
    assert profile["sector_labels"] == ["Financial Services"]

    # Duplicate name rejects.
    dup = await client.post("/api/intel-profiles", json={"name": "finserv PORTFOLIO"}, headers=auth_headers)
    assert dup.status_code == 409

    listed = await client.get("/api/intel-profiles", headers=auth_headers)
    assert listed.status_code == 200
    assert listed.json()["total"] == 1

    updated = await client.put(
        f"/api/intel-profiles/{profile['id']}",
        json={"sectors": ["healthcare"], "window_days": 30},
        headers=auth_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["sectors"] == ["healthcare"]
    assert updated.json()["window_days"] == 30

    deleted = await client.delete(f"/api/intel-profiles/{profile['id']}", headers=auth_headers)
    assert deleted.status_code == 204


@pytest.mark.asyncio
async def test_threat_surface_matching(client: AsyncClient, auth_headers: dict, scope_data):
    us, de = scope_data["us"], scope_data["de"]
    resp = await client.post(
        "/api/intel-profiles/surface-preview",
        json={
            "country_ids": [str(us.id), str(de.id)],
            "sectors": ["financial-services", "healthcare"],
            "window_days": 90,
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    surface = resp.json()

    actors = {a["name"]: a for a in surface["actors"]}
    assert set(actors) == {"Scattered Spider", "APT28"}

    spider = actors["Scattered Spider"]
    assert spider["region_hit"] and spider["sector_hit"]
    assert spider["partial"] is False
    assert spider["matched_regions"] == ["United States"]
    assert spider["matched_sectors"] == ["Financial Services"]
    assert "claim" in spider["sector_sources"]  # targeted_sectors field
    assert "reporting" in spider["region_sources"]  # co-occurrence
    assert spider["entry_count"] == 1  # out-of-window entry excluded
    assert spider["latest_entry"]["title"] == "Spider hits US banks"

    apt28 = actors["APT28"]
    assert apt28["region_hit"] and not apt28["sector_hit"]
    assert apt28["partial"] is True
    assert set(apt28["region_sources"]) == {"claim", "reporting"}

    # Both-dimension match outranks the partial one.
    assert surface["actors"][0]["name"] == "Scattered Spider"

    malware = {m["name"]: m for m in surface["malware"]}
    assert set(malware) == {"INC Ransom"}
    assert malware["INC Ransom"]["sector_hit"]
    assert malware["INC Ransom"]["matched_sectors"] == ["Healthcare"]


@pytest.mark.asyncio
async def test_profile_surface_endpoint(client: AsyncClient, auth_headers: dict, scope_data):
    us = scope_data["us"]
    created = await client.post(
        "/api/intel-profiles",
        json={"name": "US FinServ", "country_ids": [str(us.id)], "sectors": ["financial-services"]},
        headers=auth_headers,
    )
    profile_id = created.json()["id"]

    resp = await client.get(f"/api/intel-profiles/{profile_id}/surface", headers=auth_headers)
    assert resp.status_code == 200
    surface = resp.json()
    assert surface["profile_id"] == profile_id
    names = [a["name"] for a in surface["actors"]]
    assert "Scattered Spider" in names
    assert "APT28" not in names  # Germany is out of this profile's scope


@pytest.mark.asyncio
async def test_generate_exposure_report(client: AsyncClient, auth_headers: dict, scope_data):
    us, de = scope_data["us"], scope_data["de"]
    spider, apt28 = scope_data["spider"], scope_data["apt28"]

    created = await client.post(
        "/api/intel-profiles",
        json={
            "name": "Two-region portfolio",
            "country_ids": [str(us.id), str(de.id)],
            "sectors": ["financial-services"],
        },
        headers=auth_headers,
    )
    profile_id = created.json()["id"]

    resp = await client.post(
        "/api/intel-reports/generate-exposure",
        json={
            "profile_id": profile_id,
            "actor_ids": [str(spider.id)],
            "dropped_actor_ids": [str(apt28.id)],
            "tlp_marking": "TLP:AMBER",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201, resp.text
    report = resp.json()
    assert report["template_type"] == "exposure_report"
    assert report["title"] == "Threat exposure: Two-region portfolio"
    assert report["tlp_marking"] == "TLP:AMBER"
    # Kept actor present; backing entry is the in-window in-scope one.
    assert str(spider.id) in report["entity_ids"]["actors"]

    sections = report["content"]["sections"]
    surface_items = sections["threat_surface"]["items"]
    assert [i["name"] for i in surface_items] == ["Scattered Spider"]
    assert "United States" in sections["scope"]["body"]
    assert report["content"]["metadata"]["profile_name"] == "Two-region portfolio"

    # Curation is remembered on the profile.
    prof = await client.get(f"/api/intel-profiles/{profile_id}", headers=auth_headers)
    assert prof.json()["curation"]["kept"]["actors"] == [str(spider.id)]
    assert prof.json()["curation"]["dropped"]["actors"] == [str(apt28.id)]

    # Markdown export renders the threat-surface matrix.
    export = await client.get(
        f"/api/intel-reports/{report['id']}/export", params={"format": "markdown"}, headers=auth_headers
    )
    assert export.status_code == 200
    assert "Scattered Spider" in export.text
    assert "| Entity | Type | Regions" in export.text


@pytest.mark.asyncio
async def test_attach_to_report(client: AsyncClient, auth_headers: dict, scope_data):
    spider = scope_data["spider"]
    entries = scope_data["entries"]

    created = await client.post(
        "/api/intel-reports",
        json={"title": "Draft flash", "template_type": "flash_alert", "entry_ids": [str(entries[0].id)]},
        headers=auth_headers,
    )
    assert created.status_code == 201
    report_id = created.json()["id"]

    resp = await client.post(
        f"/api/intel-reports/{report_id}/attach",
        json={
            "entry_ids": [str(entries[0].id), str(entries[1].id)],  # first is a dup
            "entity_ids": {"actors": [str(spider.id)]},
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert sorted(body["entry_ids"]) == sorted([str(entries[0].id), str(entries[1].id)])
    assert body["entity_ids"]["actors"] == [str(spider.id)]

    # Published reports reject new evidence.
    await client.post(f"/api/intel-reports/{report_id}/publish", headers=auth_headers)
    rejected = await client.post(f"/api/intel-reports/{report_id}/attach", json={"entry_ids": []}, headers=auth_headers)
    assert rejected.status_code == 400
