"""Ingest-time link validation + AI-asserted relationships in the one-pass flow."""

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.enrichment import store_ai_relationships
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import MalwareFamily
from app.models.system_setting import SystemSettings
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.services.entry_analysis import apply_link_validations, collect_link_candidates


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


async def _make_actor_link(db_session, entry, *, name="Storm", paragraph_indices=None) -> ThreatActor:
    actor = ThreatActor(name=name, article_count=3)
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        EntryThreatActor(
            entry_id=entry.id,
            threat_actor_id=actor.id,
            confidence="medium",
            source="auto_link",
            matched_names=[name],
            paragraph_indices=paragraph_indices or [1],
            extracted_at=datetime.now(UTC),
        )
    )
    await db_session.flush()
    return actor


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
        "link_validations": [],
        "relationships": [],
        "_extraction_status": "success",
    }
    base.update(overrides)
    return base


async def _seed_mode(db_session, mode: str):
    db_session.add(SystemSettings(id=1, settings={"link_validation_mode": mode}, secrets={}))
    await db_session.flush()


# ------------------------------------------------------------ candidates


@pytest.mark.asyncio
async def test_collect_link_candidates_context_and_shape(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    actor = await _make_actor_link(db_session, entry, paragraph_indices=[1])
    candidates = await collect_link_candidates(db_session, entry)
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand["entity_key"] == f"threat_actor:{actor.id}"
    assert cand["matched_names"] == ["Storm"]
    assert "Storm" in cand["context"]


@pytest.mark.asyncio
async def test_collect_link_candidates_empty_without_links(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    assert await collect_link_candidates(db_session, entry) == []


# ------------------------------------------------------------ apply


@pytest.mark.asyncio
async def test_remove_shadow_mode_logs_and_keeps_junction(db_session: AsyncSession, feed):
    await _seed_mode(db_session, "shadow")
    entry = await _make_entry(db_session, feed)
    actor = await _make_actor_link(db_session, entry)
    parsed = _payload(
        link_validations=[
            {
                "entity_key": f"threat_actor:{actor.id}",
                "decision": "REMOVE",
                "reason": "weather storm",
                "suggested_type": "",
            }
        ]
    )
    counts = await apply_link_validations(db_session, entry.id, parsed)
    assert counts.get("links_shadow_removed") == 1
    junction = (
        await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id))
    ).scalar_one_or_none()
    assert junction is not None
    log = (
        await db_session.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.entry_id == entry.id))
    ).scalar_one()
    assert log.action == "shadow_remove"
    stamped = (await db_session.get(Entry, entry.id)).last_link_validation_at
    assert stamped is not None


@pytest.mark.asyncio
async def test_remove_apply_mode_deletes_junction(db_session: AsyncSession, feed):
    await _seed_mode(db_session, "apply")
    entry = await _make_entry(db_session, feed)
    actor = await _make_actor_link(db_session, entry)
    parsed = _payload(
        link_validations=[
            {
                "entity_key": f"threat_actor:{actor.id}",
                "decision": "REMOVE",
                "reason": "weather storm",
                "suggested_type": "",
            }
        ]
    )
    counts = await apply_link_validations(db_session, entry.id, parsed)
    assert counts.get("links_removed") == 1
    junction = (
        await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id))
    ).scalar_one_or_none()
    assert junction is None
    count = (await db_session.execute(select(ThreatActor.article_count).where(ThreatActor.id == actor.id))).scalar_one()
    assert count == 2
    log = (
        await db_session.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.entry_id == entry.id))
    ).scalar_one()
    assert log.action == "removed"


@pytest.mark.asyncio
async def test_positive_evidence_overrides_remove(db_session: AsyncSession, feed):
    await _seed_mode(db_session, "apply")
    entry = await _make_entry(db_session, feed)
    actor = await _make_actor_link(db_session, entry)
    parsed = _payload(
        threat_actors=[{"name": "Storm", "aliases": [], "confidence": "high"}],
        link_validations=[
            {
                "entity_key": f"threat_actor:{actor.id}",
                "decision": "REMOVE",
                "reason": "contradiction",
                "suggested_type": "",
            }
        ],
    )
    counts = await apply_link_validations(db_session, entry.id, parsed)
    assert counts.get("links_keep_overridden") == 1
    assert not counts.get("links_removed")
    junction = (
        await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id))
    ).scalar_one_or_none()
    assert junction is not None


@pytest.mark.asyncio
async def test_missing_decision_keeps_and_skips_stamp(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    await _make_actor_link(db_session, entry)
    counts = await apply_link_validations(db_session, entry.id, _payload(link_validations=[]))
    assert counts.get("links_kept") == 1
    assert (await db_session.get(Entry, entry.id)).last_link_validation_at is None


@pytest.mark.asyncio
async def test_reclassify_logs_without_touching_junction(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    actor = await _make_actor_link(db_session, entry)
    parsed = _payload(
        link_validations=[
            {
                "entity_key": f"threat_actor:{actor.id}",
                "decision": "RECLASSIFY",
                "reason": "actually malware",
                "suggested_type": "malware",
            }
        ]
    )
    counts = await apply_link_validations(db_session, entry.id, parsed)
    assert counts.get("links_reclassified") == 1
    junction = (
        await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id))
    ).scalar_one_or_none()
    assert junction is not None
    log = (
        await db_session.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.entry_id == entry.id))
    ).scalar_one()
    assert log.action == "needs_reclassification"
    assert log.suggested_entity_type == "malware"


@pytest.mark.asyncio
async def test_reclassify_without_suggested_type_downgrades_to_keep(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    actor = await _make_actor_link(db_session, entry)
    parsed = _payload(
        link_validations=[
            {"entity_key": f"threat_actor:{actor.id}", "decision": "RECLASSIFY", "reason": "?", "suggested_type": ""}
        ]
    )
    counts = await apply_link_validations(db_session, entry.id, parsed)
    assert counts.get("links_kept") == 1
    assert not counts.get("links_reclassified")


@pytest.mark.asyncio
async def test_echo_reused_payload_never_applies(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    actor = await _make_actor_link(db_session, entry)
    parsed = _payload(
        _reused_from=str(uuid.uuid4()),
        link_validations=[
            {"entity_key": f"threat_actor:{actor.id}", "decision": "REMOVE", "reason": "x", "suggested_type": ""}
        ],
    )
    counts = await apply_link_validations(db_session, entry.id, parsed)
    assert counts == {}
    assert (await db_session.get(Entry, entry.id)).last_link_validation_at is None


@pytest.mark.asyncio
async def test_payload_without_link_validations_is_noop(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    await _make_actor_link(db_session, entry)
    parsed = _payload()
    parsed.pop("link_validations")
    counts = await apply_link_validations(db_session, entry.id, parsed)
    assert counts == {}
    assert (await db_session.get(Entry, entry.id)).last_link_validation_at is None


@pytest.mark.asyncio
async def test_no_links_stamps_entry(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    counts = await apply_link_validations(db_session, entry.id, _payload())
    assert counts == {}
    assert (await db_session.get(Entry, entry.id)).last_link_validation_at is not None


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
async def test_unknown_entity_key_ignored_and_still_stamps(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    actor = await _make_actor_link(db_session, entry)
    parsed = _payload(
        link_validations=[
            {"entity_key": f"threat_actor:{actor.id}", "decision": "KEEP", "reason": "real", "suggested_type": ""},
            {"entity_key": f"threat_actor:{uuid.uuid4()}", "decision": "REMOVE", "reason": "??", "suggested_type": ""},
        ]
    )
    counts = await apply_link_validations(db_session, entry.id, parsed)
    assert counts.get("links_kept") == 1
    assert not counts.get("links_removed") and not counts.get("links_shadow_removed")
    assert (await db_session.get(Entry, entry.id)).last_link_validation_at is not None


@pytest.mark.asyncio
async def test_previously_restored_annotation_on_candidates(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    actor = await _make_actor_link(db_session, entry)
    db_session.add(
        EntityLinkValidationLog(
            entry_id=entry.id,
            entity_type="threat_actor",
            entity_id=actor.id,
            entity_name_snapshot="Storm",
            action="restored",
        )
    )
    await db_session.flush()
    candidates = await collect_link_candidates(db_session, entry)
    assert candidates[0]["previously_restored"] is True


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


@pytest.mark.asyncio
async def test_promoted_pending_rows_do_not_block_stamp(db_session: AsyncSession, feed):
    """store_entry_analysis order: apply (stamps) runs before reconcile (promotes)."""
    from app.models.pending_autolink import PendingAutolinkMatch
    from app.services.entry_analysis import store_entry_analysis

    entry = await _make_entry(db_session, feed)
    actor = ThreatActor(name="Storm")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        PendingAutolinkMatch(
            entry_id=entry.id,
            entity_type="threat_actor",
            entity_id=actor.id,
            canonical_name="Storm",
            matched_names=["Storm"],
            paragraph_indices=[1],
            confidence="medium",
        )
    )
    await db_session.flush()
    parsed = _payload(threat_actors=[{"name": "Storm", "aliases": [], "confidence": "high"}])
    await store_entry_analysis(db_session, entry.id, parsed)

    pending = (
        await db_session.execute(select(PendingAutolinkMatch).where(PendingAutolinkMatch.entry_id == entry.id))
    ).scalar_one()
    assert pending.resolution == "promoted"
    assert (await db_session.get(Entry, entry.id)).last_link_validation_at is not None
