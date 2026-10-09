"""The infrastructure view: claimed edges vs reported-alongside co-occurrence,
with indicator-list files and newsletters kept out."""

import uuid

import pytest
from sqlalchemy import select

from app.intelligence.infrastructure import get_entity_infrastructure, get_observable_backlinks
from app.intelligence.observables import get_or_create_observable, record_sighting
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor


async def _feed(db, title="t", feed_type="rss"):
    feed = Feed(title=title, url=f"https://t.example/{uuid.uuid4()}", feed_type=feed_type)
    db.add(feed)
    await db.flush()
    return feed


async def _entry(db, feed, title="e", metadata=None):
    e = Entry(feed_id=feed.id, guid=str(uuid.uuid4()), title=title, content_text="x", metadata_=metadata or {})
    db.add(e)
    await db.flush()
    return e


@pytest.mark.asyncio
async def test_infrastructure_tiers_and_guards(db_session):
    feed = await _feed(db_session)
    actor = ThreatActor(name=f"UAT-{uuid.uuid4().hex[:6]}")
    db_session.add(actor)
    await db_session.flush()

    # Article 1: the actor + a C2 domain the AI judged, plus an asserted claim.
    a1 = await _entry(db_session, feed, "report one")
    db_session.add(EntryThreatActor(entry_id=a1.id, threat_actor_id=actor.id, confidence="high", source="ai"))
    c2 = await get_or_create_observable(db_session, "domain", "c2.example-bad.net", via="ai_extraction", role="c2")
    await record_sighting(db_session, a1.id, c2, source="ai", surface_form="c2[.]example-bad[.]net")
    db_session.add(
        EntityRelationship(
            source_type="threat_actor",
            source_id=actor.id,
            target_type="observable",
            target_id=c2.id,
            relationship_type="communicates_with",
            confidence="probable",
            source="auto_extracted",
            evidence_entry_ids=[a1.id],
        )
    )
    # Article 2: the actor + a dropped path, reported but not claimed.
    a2 = await _entry(db_session, feed, "report two")
    db_session.add(EntryThreatActor(entry_id=a2.id, threat_actor_id=actor.id, confidence="high", source="ai"))
    path = await get_or_create_observable(db_session, "path", "C:\\ProgramData\\AnyDesk.exe", via="ai_extraction")
    await record_sighting(db_session, a2.id, path, source="ai")
    # Newsletter: names the actor and three other actors; its IP must not attach.
    news = await _entry(db_session, feed, "weekly roundup")
    db_session.add(EntryThreatActor(entry_id=news.id, threat_actor_id=actor.id, confidence="medium", source="ai"))
    for _ in range(3):
        other = ThreatActor(name=f"Other-{uuid.uuid4().hex[:6]}")
        db_session.add(other)
        await db_session.flush()
        db_session.add(EntryThreatActor(entry_id=news.id, threat_actor_id=other.id, confidence="medium", source="ai"))
    noise = await get_or_create_observable(db_session, "ipv4", "45.33.32.156", via="ai_extraction")
    await record_sighting(db_session, news.id, noise, source="ai")
    # Indicator-list file linked to the actor: never reporting.
    lst = await _entry(db_session, feed, "ips.txt", {"content_type": "ioc_list", "file_path": "data/x C2 IPs.txt"})
    db_session.add(EntryThreatActor(entry_id=lst.id, threat_actor_id=actor.id, confidence="high", source="manual"))
    listed = await get_or_create_observable(db_session, "ipv4", "185.199.108.153", via="ioc_list")
    await record_sighting(db_session, lst.id, listed, source="feed")
    await db_session.commit()

    infra = await get_entity_infrastructure(db_session, "threat_actor", actor.id)
    claimed = {c["value"]: c for c in infra["claimed"]}
    reported = {r["value"]: r for r in infra["reported_alongside"]}
    assert set(claimed) == {"c2.example-bad.net"}
    assert claimed["c2.example-bad.net"]["relationship_type"] == "communicates_with"
    assert claimed["c2.example-bad.net"]["evidence_count"] == 1
    # Claimed value not repeated; newsletter noise and list rows excluded.
    assert set(reported) == {"C:\\ProgramData\\AnyDesk.exe"}
    assert reported["C:\\ProgramData\\AnyDesk.exe"]["article_count"] == 1
    assert infra["counts"]["by_kind"] == {"domain": 1, "path": 1}

    back = await get_observable_backlinks(db_session, path.id)
    assert back["claimed_by"] == []
    assert [(r["entity_type"], r["name"]) for r in back["reported_with"]] == [("threat_actor", actor.name)]
    back_c2 = await get_observable_backlinks(db_session, c2.id)
    assert back_c2["claimed_by"][0]["relationship_type"] == "communicates_with"
    assert back_c2["reported_with"] == []  # the claimant is not repeated as co-mention


@pytest.mark.asyncio
async def test_infrastructure_endpoints_and_pivot(client, auth_headers, db_session):
    feed = await _feed(db_session)
    fam = MalwareFamily(name=f"Fam-{uuid.uuid4().hex[:6]}")
    db_session.add(fam)
    await db_session.flush()
    e = await _entry(db_session, feed)
    db_session.add(EntryMalware(entry_id=e.id, malware_family_id=fam.id, confidence="high", source="ai"))
    obs = await get_or_create_observable(db_session, "mutex", "cfgmgr_mtx", via="ai_extraction", role="persistence")
    await record_sighting(db_session, e.id, obs, source="ai")
    await db_session.commit()

    resp = await client.get(f"/api/entities/malware/{fam.id}/infrastructure", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["reported_alongside"][0]["value"] == "cfgmgr_mtx"
    csv_resp = await client.get(f"/api/entities/malware/{fam.id}/infrastructure?format=csv", headers=auth_headers)
    assert csv_resp.status_code == 200 and "reported_alongside,mutex,cfgmgr_mtx,persistence" in csv_resp.text
    bad = await client.get(f"/api/entities/cve/{fam.id}/infrastructure", headers=auth_headers)
    assert bad.status_code == 422
    back = await client.get(f"/api/observables/{obs.id}/backlinks", headers=auth_headers)
    assert back.status_code == 200 and back.json()["reported_with"][0]["entity_type"] == "malware"

    # The profile's "Open in observables browser" pivot: only this family's
    # infrastructure, and an entity with none yields an empty page, not the
    # whole ledger.
    other = await get_or_create_observable(db_session, "ipv4", "203.0.113.9", via="ioc_list")
    await record_sighting(db_session, (await _entry(db_session, feed)).id, other, source="feed")
    await db_session.commit()
    linked = await client.get(f"/api/observables?linked_entity=malware:{fam.id}", headers=auth_headers)
    assert linked.status_code == 200 and [r["value"] for r in linked.json()["items"]] == ["cfgmgr_mtx"]
    nothing = await client.get(f"/api/observables?linked_entity=malware:{uuid.uuid4()}", headers=auth_headers)
    assert nothing.status_code == 200 and nothing.json()["total"] == 0
    assert (await client.get("/api/observables?linked_entity=cve:x", headers=auth_headers)).status_code == 400
    # Honest empty state: the count of this family's articles with staged candidates.
    assert body["counts"]["staged_candidate_articles"] == 0
    e.observable_candidates = [{"kind": "domain", "value": "staged.example-bad.net", "origin": "ai"}]
    await db_session.commit()
    again = await client.get(f"/api/entities/malware/{fam.id}/infrastructure", headers=auth_headers)
    assert again.json()["counts"]["staged_candidate_articles"] == 1

    # A claim makes the observable visible in the family's pivot (co-mention
    # alone never does).
    from app.intelligence.correlation import pivot_from_entity

    before = await pivot_from_entity(db_session, "malware", fam.id)
    assert before["related"].get("observables") == []
    db_session.add(
        EntityRelationship(
            source_type="malware",
            source_id=fam.id,
            target_type="observable",
            target_id=obs.id,
            relationship_type="uses",
            confidence="probable",
            source="auto_extracted",
            evidence_entry_ids=[e.id],
        )
    )
    await db_session.commit()
    assert len((await db_session.execute(select(EntityRelationship))).scalars().all()) == 1
    from app.intelligence.correlation_cache import invalidate_entity_cache

    await invalidate_entity_cache("malware", str(fam.id))
    after = await pivot_from_entity(db_session, "malware", fam.id)
    rows = after["related"].get("observables") or []
    assert [r["value"] for r in rows] == ["cfgmgr_mtx"]
    assert rows[0]["relationship_type"] == "uses" and rows[0]["relationship_direction"] == "outbound"


@pytest.mark.asyncio
async def test_ai_claim_on_captured_observable_lands_as_evidence_backed_edge(db_session):
    """Plan §5.1: the one-pass payload's relationship to a value it also reported
    becomes an EntityRelationship with the entry as evidence, at the reported
    tier, from the auto_extracted source — once the observable row exists."""
    from app.intelligence.enrichment import store_ai_relationships
    from app.intelligence.observables import store_observables

    feed = await _feed(db_session)
    actor = ThreatActor(name=f"UAT-{uuid.uuid4().hex[:6]}")
    db_session.add(actor)
    await db_session.flush()
    e = await _entry(db_session, feed, "report")
    parsed = {
        "threat_actors": [{"name": actor.name, "aliases": [], "confidence": "high"}],
        "iocs": [{"kind": "domain", "value": "c2[.]uat-example[.]net", "role": "c2", "evidence": "x"}],
        "relationships": [
            {
                "source_type": "threat_actor",
                "source_name": actor.name,
                "target_type": "observable",
                "target_name": "c2[.]uat-example[.]net",
                "target_kind": "domain",
                "relationship_type": "controls",
                "evidence": f"{actor.name} controls c2[.]uat-example[.]net as its primary C2.",
                "confidence": "high",
            }
        ],
    }
    assert await store_observables(db_session, e.id, parsed["iocs"]) == 1
    assert await store_ai_relationships(db_session, parsed["relationships"], e.id, parsed=parsed) == 1
    row = (
        await db_session.execute(
            select(EntityRelationship).where(
                EntityRelationship.source_id == actor.id, EntityRelationship.target_type == "observable"
            )
        )
    ).scalar_one()
    assert row.relationship_type == "controls"
    assert row.confidence == "probable" and row.source == "auto_extracted"
    assert row.evidence_entry_ids == [e.id]
    await db_session.commit()
    infra = await get_entity_infrastructure(db_session, "threat_actor", actor.id, use_cache=False)
    assert [c["value"] for c in infra["claimed"]] == ["c2.uat-example.net"]
