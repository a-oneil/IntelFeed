"""AI-asserted relationships in the one-pass flow (store_ai_relationships)."""

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.enrichment import store_ai_relationships
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import ThreatActor


@pytest.fixture(autouse=True)
def _reset_settings_cache(monkeypatch):
    import app.services.system_settings as ss_mod

    monkeypatch.setattr(ss_mod, "_cache", None)
    monkeypatch.setattr(ss_mod, "_cache_ts", 0.0)
    yield


@pytest_asyncio.fixture
async def feed(db_session) -> Feed:
    f = Feed(title="LV Feed", url="https://lv.example/feed", feed_type="rss")
    db_session.add(f)
    await db_session.flush()
    return f


async def _make_entry(
    db_session, feed, *, content="Storm activity was observed.\n\nThe Storm group deployed loaders."
) -> Entry:
    entry = Entry(
        feed_id=feed.id,
        title="Ingest validation entry",
        guid=f"guid-{uuid.uuid4()}",
        content_text=content,
        published_at=datetime.now(UTC),
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


def _payload(**overrides) -> dict:
    base = {
        "summary": "s",
        "ttps": [],
        "threat_actors": [],
        "malware": [],
        "tools": [],
        "countries": [],
        "sectors": [],
        "mitigations": [],
        "relationships": [],
        "_extraction_status": "success",
    }
    base.update(overrides)
    return base


# ------------------------------------------------------------ relationships


async def _mk_actor_and_malware(db_session) -> tuple[ThreatActor, MalwareFamily]:
    actor = ThreatActor(name="APT-Storm")
    malware = MalwareFamily(name="StormLoader")
    db_session.add_all([actor, malware])
    await db_session.flush()
    return actor, malware


def _rel_payload() -> dict:
    return _payload(
        threat_actors=[{"name": "APT-Storm", "aliases": [], "confidence": "high"}],
        malware=[{"name": "StormLoader", "aliases": [], "confidence": "high"}],
    )


@pytest.mark.asyncio
async def test_relationship_stored_with_evidence(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    actor, malware = await _mk_actor_and_malware(db_session)
    rels = [
        {
            "source_type": "threat_actor",
            "source_name": "APT-Storm",
            "target_type": "malware",
            "target_name": "StormLoader",
            "relationship_type": "uses",
            "evidence": "APT-Storm deployed StormLoader against victims.",
            "confidence": "high",
        }
    ]
    stored = await store_ai_relationships(db_session, rels, entry.id, parsed=_rel_payload())
    assert stored == 1
    row = (
        await db_session.execute(select(EntityRelationship).where(EntityRelationship.source_id == actor.id))
    ).scalar_one()
    assert row.relationship_type == "uses"
    assert row.source == "auto_extracted"
    # High-confidence ingest assertions cap at "probable" (reported tier):
    # corroborated is earned by the adjudicator / authority / analyst pin.
    assert row.confidence == "probable"
    assert entry.id in row.evidence_entry_ids


@pytest.mark.asyncio
async def test_relationship_rejected_without_both_names_in_evidence(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    await _mk_actor_and_malware(db_session)
    rels = [
        {
            "source_type": "threat_actor",
            "source_name": "APT-Storm",
            "target_type": "malware",
            "target_name": "StormLoader",
            "relationship_type": "uses",
            "evidence": "This week's roundup covers many threats.",
            "confidence": "high",
        }
    ]
    stored = await store_ai_relationships(db_session, rels, entry.id, parsed=_rel_payload())
    assert stored == 0


@pytest.mark.asyncio
async def test_relationship_rejected_when_endpoint_not_in_payload(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    await _mk_actor_and_malware(db_session)
    rels = [
        {
            "source_type": "threat_actor",
            "source_name": "APT-Storm",
            "target_type": "malware",
            "target_name": "StormLoader",
            "relationship_type": "uses",
            "evidence": "APT-Storm deployed StormLoader against victims.",
            "confidence": "high",
        }
    ]
    parsed = _rel_payload()
    parsed["malware"] = []  # endpoint missing from extraction
    stored = await store_ai_relationships(db_session, rels, entry.id, parsed=parsed)
    assert stored == 0


@pytest.mark.asyncio
async def test_relationship_upgrades_existing_cooccurrence_edge(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    actor, malware = await _mk_actor_and_malware(db_session)
    other_entry = uuid.uuid4()
    db_session.add(
        EntityRelationship(
            source_type="threat_actor",
            source_id=actor.id,
            target_type="malware",
            target_id=malware.id,
            relationship_type="uses",
            confidence="possible",
            source="co_occurrence",
            evidence_entry_ids=[other_entry],
        )
    )
    await db_session.flush()
    rels = [
        {
            "source_type": "threat_actor",
            "source_name": "APT-Storm",
            "target_type": "malware",
            "target_name": "StormLoader",
            "relationship_type": "uses",
            "evidence": "APT-Storm operates StormLoader infrastructure.",
            "confidence": "medium",
        }
    ]
    stored = await store_ai_relationships(db_session, rels, entry.id, parsed=_rel_payload())
    assert stored == 1
    rows = (
        (await db_session.execute(select(EntityRelationship).where(EntityRelationship.source_id == actor.id)))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    row = rows[0]
    assert row.source == "auto_extracted"
    assert row.confidence == "probable"
    assert set(row.evidence_entry_ids) == {other_entry, entry.id}


@pytest.mark.asyncio
async def test_relationship_never_resurrects_analyst_rejected(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    actor, malware = await _mk_actor_and_malware(db_session)
    db_session.add(
        EntityRelationship(
            source_type="threat_actor",
            source_id=actor.id,
            target_type="malware",
            target_id=malware.id,
            relationship_type="uses",
            confidence="possible",
            source="analyst_rejected",
            evidence_entry_ids=[],
        )
    )
    await db_session.flush()
    rels = [
        {
            "source_type": "threat_actor",
            "source_name": "APT-Storm",
            "target_type": "malware",
            "target_name": "StormLoader",
            "relationship_type": "uses",
            "evidence": "APT-Storm operates StormLoader infrastructure.",
            "confidence": "high",
        }
    ]
    stored = await store_ai_relationships(db_session, rels, entry.id, parsed=_rel_payload())
    assert stored == 0
    row = (
        await db_session.execute(select(EntityRelationship).where(EntityRelationship.source_id == actor.id))
    ).scalar_one()
    assert row.source == "analyst_rejected"
    assert row.evidence_entry_ids == []


# ------------------------------------------------------------ audit gaps


@pytest.mark.asyncio
async def test_same_type_relationship_verb_accepted(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    parent = ThreatActor(name="Storm-Parent")
    child = ThreatActor(name="Storm-Child")
    db_session.add_all([parent, child])
    await db_session.flush()
    parsed = _payload(
        threat_actors=[
            {"name": "Storm-Parent", "aliases": [], "confidence": "high"},
            {"name": "Storm-Child", "aliases": [], "confidence": "high"},
        ]
    )
    rels = [
        {
            "source_type": "threat_actor",
            "source_name": "Storm-Child",
            "target_type": "threat_actor",
            "target_name": "Storm-Parent",
            "relationship_type": "subgroup_of",
            "evidence": "Storm-Child operates as a subgroup of Storm-Parent.",
            "confidence": "medium",
        }
    ]
    stored = await store_ai_relationships(db_session, rels, entry.id, parsed=parsed)
    assert stored == 1
    row = (
        await db_session.execute(select(EntityRelationship).where(EntityRelationship.source_id == child.id))
    ).scalar_one()
    assert row.relationship_type == "subgroup_of"
    assert row.target_id == parent.id


@pytest.mark.asyncio
async def test_unresolvable_relationship_name_skipped(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    actor = ThreatActor(name="APT-Storm")
    db_session.add(actor)
    await db_session.flush()
    parsed = _payload(
        threat_actors=[{"name": "APT-Storm", "aliases": [], "confidence": "high"}],
        malware=[{"name": "GhostLoader", "aliases": [], "confidence": "high"}],
    )
    rels = [
        {
            "source_type": "threat_actor",
            "source_name": "APT-Storm",
            "target_type": "malware",
            "target_name": "GhostLoader",  # never created in the catalog
            "relationship_type": "uses",
            "evidence": "APT-Storm deployed GhostLoader in the campaign.",
            "confidence": "high",
        }
    ]
    stored = await store_ai_relationships(db_session, rels, entry.id, parsed=parsed)
    assert stored == 0
