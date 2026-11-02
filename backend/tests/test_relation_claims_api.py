"""GET /api/entity-relationships/claims/{type}/{id}: which enrichment sources
claim a profile's connections, and the names they gave that resolved to no
entity — the Relationships tab's source tags, "via" chips and "unresolved · N"."""

import uuid
from datetime import UTC, datetime

from app.models.enrichment import EntityRelationClaim


def _claim(entity_type, entity_id, source_type, name, target_type=None, target_id=None, held=None, **kw):
    now = datetime.now(UTC)
    return EntityRelationClaim(
        entity_type=entity_type,
        entity_id=entity_id,
        source_type=source_type,
        output=kw.pop("output", "tools"),
        target_key=name.casefold(),
        relation=kw.pop("relation", "uses"),
        target_name=name,
        target_type=target_type,
        target_id=target_id,
        held_reason=held,
        first_seen_at=now,
        last_seen_at=now,
        **kw,
    )


async def test_claims_tag_targets_by_source_from_either_end_and_list_held(client, auth_headers, db_session):
    actor, adfind, zip7, malware, observable = (uuid.uuid4() for _ in range(5))
    db_session.add_all(
        [
            _claim("threat_actor", actor, "etda", "AdFind", "tool", adfind),
            _claim("threat_actor", actor, "etda", "7-Zip", "tool", zip7),
            _claim("threat_actor", actor, "malpedia", "7-Zip", "tool", zip7),
            _claim("threat_actor", actor, "etda", "ATI-Agent", "tool", held="unknown", evidence="card"),
            # A claim another entity's source made about this one tags its row too.
            _claim("malware", malware, "malpedia", "APT29", "threat_actor", actor, relation="attributed_to"),
            # Someone else's claim: not this profile's.
            _claim("observable", observable, "threatfox", "Emotet", "malware", malware, relation="communicates_with"),
        ]
    )
    await db_session.flush()

    resp = await client.get(f"/api/entity-relationships/claims/threat_actor/{actor}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["by_target"] == {
        f"tool-{adfind}": ["etda"],
        f"tool-{zip7}": ["etda", "malpedia"],
        f"malware-{malware}": ["malpedia"],
    }
    assert [(s["source_type"], s["linked"]) for s in data["sources"]] == [("etda", 2), ("malpedia", 2)]
    assert all(s["label"] for s in data["sources"])
    assert data["held_count"] == 1
    held = data["held"][0]
    assert (held["source_type"], held["target_name"], held["relation"], held["held_reason"]) == (
        "etda",
        "ATI-Agent",
        "uses",
        "unknown",
    )
    assert held["target_type"] == "tool" and held["evidence"] == "card" and held["source_label"]


async def test_claims_for_an_entity_with_none(client, auth_headers):
    resp = await client.get(f"/api/entity-relationships/claims/malware/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["sources"] == [] and resp.json()["held_count"] == 0 and resp.json()["by_target"] == {}


async def test_claims_are_signed_in_only(client):
    resp = await client.get(f"/api/entity-relationships/claims/malware/{uuid.uuid4()}")
    assert resp.status_code == 401
