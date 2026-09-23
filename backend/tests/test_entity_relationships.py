"""Tests for BE-9: Entity relationship API."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.correlation import _directed_pair, create_cooccurrence_relationships
from app.models.cve import CVE, EntryCVE
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.models.user import User


@pytest_asyncio.fixture
async def test_relationship(db_session: AsyncSession, test_user: User) -> EntityRelationship:
    rel = EntityRelationship(
        source_type="threat_actor",
        source_id=uuid.uuid4(),
        target_type="malware",
        target_id=uuid.uuid4(),
        relationship_type="uses",
        confidence="probable",
        source="analyst_created",
        created_by=test_user.id,
    )
    db_session.add(rel)
    await db_session.flush()
    return rel


@pytest.mark.asyncio
async def test_create_entity_relationship(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/entity-relationships",
        json={
            "source_type": "threat_actor",
            "source_id": str(uuid.uuid4()),
            "target_type": "ttp",
            "target_id": str(uuid.uuid4()),
            "relationship_type": "uses",
            "confidence": "confirmed",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["relationship_type"] == "uses"
    assert data["confidence"] == "confirmed"
    assert data["source"] == "analyst_created"


@pytest.mark.asyncio
async def test_list_entity_relationships(
    client: AsyncClient, auth_headers: dict, test_relationship: EntityRelationship
):
    resp = await client.get(
        f"/api/entity-relationships?entity_type={test_relationship.source_type}&entity_id={test_relationship.source_id}",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


@pytest.mark.asyncio
async def test_update_entity_relationship(
    client: AsyncClient, auth_headers: dict, test_relationship: EntityRelationship
):
    resp = await client.put(
        f"/api/entity-relationships/{test_relationship.id}",
        json={"confidence": "confirmed", "description": "Updated description"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["confidence"] == "confirmed"


@pytest.mark.asyncio
async def test_delete_entity_relationship(
    client: AsyncClient, auth_headers: dict, test_relationship: EntityRelationship
):
    resp = await client.delete(f"/api/entity-relationships/{test_relationship.id}", headers=auth_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_invalid_relationship_type(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/entity-relationships",
        json={
            "source_type": "threat_actor",
            "source_id": str(uuid.uuid4()),
            "target_type": "ttp",
            "target_id": str(uuid.uuid4()),
            "relationship_type": "invalid_type",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 400


# ─── R1: semantic direction, upsert, confirm/reject, co-occurrence engine ───


@pytest_asyncio.fixture
async def malware_row(db_session: AsyncSession) -> MalwareFamily:
    m = MalwareFamily(name="TestLoader")
    db_session.add(m)
    await db_session.flush()
    return m


def test_directed_pair_orients_semantically():
    actor_id, malware_id = uuid.uuid4(), uuid.uuid4()
    expected = ("threat_actor", actor_id, "malware", malware_id, "uses", True)
    assert _directed_pair("threat_actor", actor_id, "malware", malware_id) == expected
    # Encounter order must not matter
    assert _directed_pair("malware", malware_id, "threat_actor", actor_id) == expected


def test_directed_pair_flips_previously_inverted_pairs():
    a, b = uuid.uuid4(), uuid.uuid4()
    src_type, src_id, tgt_type, tgt_id, verb, mapped = _directed_pair("cve", a, "threat_actor", b)
    assert (src_type, src_id, tgt_type, tgt_id, verb, mapped) == ("threat_actor", b, "cve", a, "exploits", True)
    src_type, src_id, tgt_type, tgt_id, verb, _ = _directed_pair("country", a, "malware", b)
    assert (src_type, src_id, tgt_type, tgt_id, verb) == ("malware", b, "country", a, "targets")


def test_directed_pair_unmapped_is_stable_related_to():
    a, b = uuid.uuid4(), uuid.uuid4()
    first = _directed_pair("tool", a, "cve", b)
    second = _directed_pair("cve", b, "tool", a)
    assert first == second
    assert first[4] == "related_to"
    assert first[5] is False


@pytest.mark.asyncio
async def test_duplicate_create_upserts(client: AsyncClient, auth_headers: dict):
    e1, e2 = str(uuid.uuid4()), str(uuid.uuid4())
    body = {
        "source_type": "threat_actor",
        "source_id": str(uuid.uuid4()),
        "target_type": "malware",
        "target_id": str(uuid.uuid4()),
        "relationship_type": "uses",
        "evidence_entry_ids": [e1],
    }
    r1 = await client.post("/api/entity-relationships", json=body, headers=auth_headers)
    assert r1.status_code == 201

    body["evidence_entry_ids"] = [e2]
    r2 = await client.post("/api/entity-relationships", json=body, headers=auth_headers)
    assert r2.status_code == 200
    assert r2.json()["id"] == r1.json()["id"]
    assert set(r2.json()["evidence_entry_ids"]) == {e1, e2}


@pytest.mark.asyncio
async def test_confirm_entity_relationship(
    client: AsyncClient, auth_headers: dict, test_relationship: EntityRelationship
):
    resp = await client.post(f"/api/entity-relationships/{test_relationship.id}/confirm", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "analyst_confirmed"
    assert data["confidence"] == "confirmed"


@pytest.mark.asyncio
async def test_reject_hides_relationship(
    client: AsyncClient, auth_headers: dict, test_relationship: EntityRelationship
):
    resp = await client.post(f"/api/entity-relationships/{test_relationship.id}/reject", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["source"] == "analyst_rejected"

    listing = await client.get(
        f"/api/entity-relationships?entity_type=threat_actor&entity_id={test_relationship.source_id}",
        headers=auth_headers,
    )
    assert listing.json()["total"] == 0

    listing = await client.get(
        f"/api/entity-relationships?entity_type=threat_actor&entity_id={test_relationship.source_id}&include_rejected=true",
        headers=auth_headers,
    )
    assert listing.json()["total"] == 1


@pytest.mark.asyncio
async def test_cooccurrence_stores_semantic_direction(db_session, test_entry, test_threat_actor, malware_row):
    db_session.add_all(
        [
            EntryThreatActor(entry_id=test_entry.id, threat_actor_id=test_threat_actor.id, paragraph_indices=[0]),
            EntryMalware(entry_id=test_entry.id, malware_family_id=malware_row.id, paragraph_indices=[0]),
        ]
    )
    await db_session.flush()

    created = await create_cooccurrence_relationships(db_session, test_entry.id)
    assert created == 1

    rel = (await db_session.execute(select(EntityRelationship))).scalars().one()
    assert (rel.source_type, rel.source_id) == ("threat_actor", test_threat_actor.id)
    assert (rel.target_type, rel.target_id) == ("malware", malware_row.id)
    assert rel.relationship_type == "uses"
    # New edges always start at "possible" — probable is earned by multi-feed
    # corroboration, never granted on first sight.
    assert rel.confidence == "possible"
    assert rel.evidence_entry_ids == [test_entry.id]


@pytest.mark.asyncio
async def test_cooccurrence_respects_rejected(db_session, test_entry, test_threat_actor, malware_row):
    rejected = EntityRelationship(
        source_type="threat_actor",
        source_id=test_threat_actor.id,
        target_type="malware",
        target_id=malware_row.id,
        relationship_type="uses",
        confidence="possible",
        source="analyst_rejected",
        evidence_entry_ids=[],
    )
    db_session.add(rejected)
    db_session.add_all(
        [
            EntryThreatActor(entry_id=test_entry.id, threat_actor_id=test_threat_actor.id, paragraph_indices=[0]),
            EntryMalware(entry_id=test_entry.id, malware_family_id=malware_row.id, paragraph_indices=[0]),
        ]
    )
    await db_session.flush()

    await create_cooccurrence_relationships(db_session, test_entry.id)
    await db_session.refresh(rejected)
    assert rejected.source == "analyst_rejected"
    assert rejected.evidence_entry_ids == []
    assert rejected.confidence == "possible"


@pytest.mark.asyncio
async def test_cooccurrence_suppresses_weak_unmapped_pairs(db_session, test_feed):
    tool = Tool(name="TestTool")
    ttp = TTP(technique_id="T9999", technique_name="Test Technique")
    db_session.add_all([tool, ttp])
    await db_session.flush()

    # Adjacent paragraphs → proximity 0.5, below the strong threshold: an
    # unmapped (tool, ttp) pair earns no generic related_to edge.
    weak = Entry(feed_id=test_feed.id, title="weak", guid="cooc-weak", url="https://example.com/w")
    db_session.add(weak)
    await db_session.flush()
    db_session.add_all(
        [
            EntryTool(entry_id=weak.id, tool_id=tool.id, paragraph_indices=[0]),
            EntryTTP(entry_id=weak.id, ttp_id=ttp.id, paragraph_indices=[1]),
        ]
    )
    await db_session.flush()
    assert await create_cooccurrence_relationships(db_session, weak.id) == 0

    # Same paragraph → proximity 1.0: kept as related_to.
    strong = Entry(feed_id=test_feed.id, title="strong", guid="cooc-strong", url="https://example.com/s")
    db_session.add(strong)
    await db_session.flush()
    db_session.add_all(
        [
            EntryTool(entry_id=strong.id, tool_id=tool.id, paragraph_indices=[2]),
            EntryTTP(entry_id=strong.id, ttp_id=ttp.id, paragraph_indices=[2]),
        ]
    )
    await db_session.flush()
    assert await create_cooccurrence_relationships(db_session, strong.id) == 1
    rel = (await db_session.execute(select(EntityRelationship))).scalars().one()
    assert (rel.source_type, rel.relationship_type, rel.target_type) == ("tool", "related_to", "ttp")


@pytest.mark.asyncio
async def test_cooccurrence_blocks_pairs_outside_matrix(db_session, test_feed):
    from app.models.country import Country, EntryCountry

    country = Country(name="Testland", iso_code="TL")
    cve = CVE(cve_id="CVE-2026-99999")
    tool = Tool(name="MatrixTool")
    db_session.add_all([country, cve, tool])
    await db_session.flush()

    # Same paragraph → proximity 1.0, but country↔cve and country↔tool have no
    # allowed orientation: nothing is stored no matter how close the co-mention.
    entry = Entry(feed_id=test_feed.id, title="blocked", guid="cooc-blocked", url="https://example.com/b")
    db_session.add(entry)
    await db_session.flush()
    db_session.add_all(
        [
            EntryCountry(entry_id=entry.id, country_id=country.id, paragraph_indices=[0]),
            EntryCVE(entry_id=entry.id, cve_id=cve.id, paragraph_indices=[0]),
            EntryTool(entry_id=entry.id, tool_id=tool.id, paragraph_indices=[0]),
        ]
    )
    await db_session.flush()

    # The only edge allowed out of this trio is tool exploits cve — but that
    # pair is unmapped, so only its canonical related_to would apply, which the
    # matrix rejects (canonical direction is cve→tool). Expect zero rows for
    # the country pairs specifically.
    await create_cooccurrence_relationships(db_session, entry.id)
    rows = (await db_session.execute(select(EntityRelationship))).scalars().all()
    assert all("country" not in (r.source_type, r.target_type) for r in rows)
    assert all(not (r.source_type == "cve" and r.target_type == "tool") for r in rows)


# ─── Minimum relationship confidence (display filter) ───


def test_hidden_relationship_confidences(monkeypatch):
    from app.config import settings as env_settings
    from app.intelligence.relationship_matrix import hidden_relationship_confidences

    assert hidden_relationship_confidences() == frozenset()
    monkeypatch.setattr(env_settings, "relationship_min_confidence", "probable")
    assert hidden_relationship_confidences() == {"possible"}
    monkeypatch.setattr(env_settings, "relationship_min_confidence", "confirmed")
    assert hidden_relationship_confidences() == {"possible", "probable"}
    monkeypatch.setattr(env_settings, "relationship_min_confidence", "garbage")
    assert hidden_relationship_confidences() == frozenset()


@pytest.mark.asyncio
async def test_min_confidence_hides_possible_rows(
    client: AsyncClient, auth_headers: dict, db_session, test_threat_actor, malware_row, monkeypatch
):
    from app.config import settings as env_settings

    db_session.add_all(
        [
            EntityRelationship(
                source_type="threat_actor",
                source_id=test_threat_actor.id,
                target_type="malware",
                target_id=malware_row.id,
                relationship_type="uses",
                confidence="possible",
                source="co_occurrence",
            ),
            EntityRelationship(
                source_type="threat_actor",
                source_id=test_threat_actor.id,
                target_type="malware",
                target_id=malware_row.id,
                relationship_type="delivers",
                confidence="confirmed",
                source="analyst_confirmed",
            ),
        ]
    )
    await db_session.flush()

    monkeypatch.setattr(env_settings, "relationship_min_confidence", "probable")
    listing = await client.get(
        f"/api/entity-relationships?entity_type=threat_actor&entity_id={test_threat_actor.id}",
        headers=auth_headers,
    )
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["confidence"] == "confirmed"

    # Management surfaces opt out and see everything
    listing = await client.get(
        f"/api/entity-relationships?entity_type=threat_actor&entity_id={test_threat_actor.id}&all_confidence=true",
        headers=auth_headers,
    )
    assert listing.json()["total"] == 2

    # by-entity endpoint respects the filter too
    by_entity = await client.get(
        f"/api/entity-relationships/by-entity/threat_actor/{test_threat_actor.id}",
        headers=auth_headers,
    )
    assert [r["confidence"] for r in by_entity.json()] == ["confirmed"]

    # default setting shows everything again
    monkeypatch.setattr(env_settings, "relationship_min_confidence", "possible")
    listing = await client.get(
        f"/api/entity-relationships?entity_type=threat_actor&entity_id={test_threat_actor.id}",
        headers=auth_headers,
    )
    assert listing.json()["total"] == 2


# ─── Semantic relationship matrix ───


def test_matrix_country_and_cve_are_passive():
    from app.intelligence.relationship_matrix import ALLOWED_RELATIONSHIPS

    country_sourced = [t for t in ALLOWED_RELATIONSHIPS if t[0] == "country"]
    assert country_sourced == []
    cve_sourced = {t for t in ALLOWED_RELATIONSHIPS if t[0] == "cve"}
    assert cve_sourced == {("cve", "related_to", "ttp")}


def test_orient_relationship_flips_and_rejects():
    from app.intelligence.relationship_matrix import orient_relationship

    # Reversed assertion flips to allowed orientation
    assert orient_relationship("country", "attributed_to", "threat_actor") == (
        "threat_actor",
        "attributed_to",
        "country",
    )
    assert orient_relationship("cve", "exploits", "malware") == ("malware", "exploits", "cve")
    # No valid orientation → rejected
    assert orient_relationship("country", "related_to", "cve") is None
    assert orient_relationship("vendor", "uses", "malware") is None


@pytest.mark.asyncio
async def test_create_rejects_untracked_combination(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/entity-relationships",
        json={
            "source_type": "country",
            "source_id": str(uuid.uuid4()),
            "target_type": "cve",
            "target_id": str(uuid.uuid4()),
            "relationship_type": "related_to",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_relationship"


@pytest.mark.asyncio
async def test_create_flips_reversed_combination(client: AsyncClient, auth_headers: dict):
    country_id, actor_id = str(uuid.uuid4()), str(uuid.uuid4())
    resp = await client.post(
        "/api/entity-relationships",
        json={
            "source_type": "country",
            "source_id": country_id,
            "target_type": "threat_actor",
            "target_id": actor_id,
            "relationship_type": "attributed_to",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert (data["source_type"], data["source_id"]) == ("threat_actor", actor_id)
    assert (data["target_type"], data["target_id"]) == ("country", country_id)


@pytest.mark.asyncio
async def test_update_rejects_untracked_verb(
    client: AsyncClient, auth_headers: dict, test_relationship: EntityRelationship
):
    # threat_actor → malware exists; "exploits" is not a tracked verb for it
    resp = await client.put(
        f"/api/entity-relationships/{test_relationship.id}",
        json={"relationship_type": "exploits"},
        headers=auth_headers,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_merge_repoints_relationships(db_session, test_threat_actor, malware_row):
    from app.api.entity_merge import MergeRequest, perform_actor_merge

    dupe = ThreatActor(name="APT29-dupe")
    db_session.add(dupe)
    await db_session.flush()

    e1, e2 = uuid.uuid4(), uuid.uuid4()
    db_session.add_all(
        [
            EntityRelationship(
                source_type="threat_actor",
                source_id=dupe.id,
                target_type="malware",
                target_id=malware_row.id,
                relationship_type="uses",
                confidence="probable",
                source="co_occurrence",
                evidence_entry_ids=[e1],
            ),
            EntityRelationship(
                source_type="threat_actor",
                source_id=test_threat_actor.id,
                target_type="malware",
                target_id=malware_row.id,
                relationship_type="uses",
                confidence="possible",
                source="co_occurrence",
                evidence_entry_ids=[e2],
            ),
        ]
    )
    await db_session.flush()

    await perform_actor_merge(db_session, test_threat_actor.id, MergeRequest(source_id=dupe.id))

    rows = (await db_session.execute(select(EntityRelationship))).scalars().all()
    assert len(rows) == 1
    survivor = rows[0]
    assert survivor.source_id == test_threat_actor.id
    assert set(survivor.evidence_entry_ids) == {e1, e2}
    assert survivor.confidence == "probable"  # stronger confidence survives the merge
