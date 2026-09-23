"""ATT&CK `uses` relationship import — the authority layer of the trust ladder."""

import pytest
from sqlalchemy import select

from app.intelligence.attack_catalog import parse_attack_bundle, sync_attack_relationships
from app.models.entity_relationship import EntityRelationship
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import ThreatActor
from app.models.tool import Tool
from app.models.ttp import TTP


def _bundle() -> dict:
    return {
        "objects": [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--g1",
                "name": "APT-Test",
                "aliases": ["TestBear"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "G9999"}],
            },
            {"type": "malware", "id": "malware--m1", "name": "TestLoader", "x_mitre_aliases": ["TL"]},
            {"type": "tool", "id": "tool--t1", "name": "TestStrike"},
            {
                "type": "attack-pattern",
                "id": "attack-pattern--a1",
                "name": "Phishing",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9998"}],
            },
            {
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--g1",
                "target_ref": "malware--m1",
            },
            {
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--g1",
                "target_ref": "tool--t1",
            },
            {
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "malware--m1",
                "target_ref": "attack-pattern--a1",
            },
            {
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "tool--t1",
                "target_ref": "attack-pattern--a1",
            },
            # revoked edges are skipped
            {
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--g1",
                "target_ref": "attack-pattern--a1",
                "revoked": True,
            },
        ]
    }


def test_parse_collects_software_and_uses():
    parsed = parse_attack_bundle(_bundle(), "enterprise")
    assert parsed.software["malware--m1"]["kind"] == "malware"
    assert parsed.software["tool--t1"]["name"] == "TestStrike"
    assert ("intrusion-set--g1", "malware--m1") in parsed.uses
    # revoked uses edge dropped
    assert ("intrusion-set--g1", "attack-pattern--a1") not in parsed.uses
    assert parsed.technique_stix["attack-pattern--a1"] == "T9998"


@pytest.mark.asyncio
async def test_sync_creates_confirmed_edges_for_existing_entities(db_session):
    actor = ThreatActor(name="APT-Test")
    malware = MalwareFamily(name="TestLoader")
    tool = Tool(name="TestStrike")
    ttp = TTP(technique_id="T9998", technique_name="Phishing")
    db_session.add_all([actor, malware, tool, ttp])
    await db_session.flush()

    parsed = parse_attack_bundle(_bundle(), "enterprise")
    stats = await sync_attack_relationships(db_session, [parsed])
    assert stats["created"] == 4
    assert stats["unresolved"] == 0

    rows = (await db_session.execute(select(EntityRelationship))).scalars().all()
    triples = {(r.source_type, r.relationship_type, r.target_type) for r in rows}
    assert ("threat_actor", "uses", "malware") in triples
    assert ("threat_actor", "uses", "tool") in triples
    assert ("malware", "uses", "ttp") in triples
    # tools relate to techniques — the matrix reserves `uses` for operators
    assert ("tool", "related_to", "ttp") in triples
    assert all(r.source == "external_feed" and r.confidence == "confirmed" for r in rows)
    assert all(r.description == "MITRE ATT&CK" for r in rows)

    # Idempotent: re-run changes nothing
    stats2 = await sync_attack_relationships(db_session, [parsed])
    assert stats2["created"] == 0 and stats2["unchanged"] == 4


@pytest.mark.asyncio
async def test_sync_upgrades_machine_rows_and_respects_rejections(db_session):
    actor = ThreatActor(name="APT-Test")
    malware = MalwareFamily(name="TestLoader")
    tool = Tool(name="TestStrike")
    db_session.add_all([actor, malware, tool])
    await db_session.flush()

    db_session.add_all(
        [
            EntityRelationship(
                source_type="threat_actor",
                source_id=actor.id,
                target_type="malware",
                target_id=malware.id,
                relationship_type="uses",
                confidence="possible",
                source="co_occurrence",
                evidence_entry_ids=[],
            ),
            EntityRelationship(
                source_type="threat_actor",
                source_id=actor.id,
                target_type="tool",
                target_id=tool.id,
                relationship_type="uses",
                confidence="possible",
                source="analyst_rejected",
                evidence_entry_ids=[],
            ),
        ]
    )
    await db_session.flush()

    parsed = parse_attack_bundle(_bundle(), "enterprise")
    stats = await sync_attack_relationships(db_session, [parsed])
    assert stats["upgraded"] == 1
    assert stats["skipped"] >= 1  # the rejected edge stays dead

    rows = (await db_session.execute(select(EntityRelationship))).scalars().all()
    by_target = {r.target_type: r for r in rows if r.source_type == "threat_actor"}
    assert by_target["malware"].confidence == "confirmed"
    assert by_target["malware"].source == "external_feed"
    assert by_target["tool"].source == "analyst_rejected"
    assert by_target["tool"].confidence == "possible"
