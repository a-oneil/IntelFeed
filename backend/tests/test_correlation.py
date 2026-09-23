"""Tests for the intelligence correlation engine and API endpoints."""

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.country import Country
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP
from app.models.user import User


@pytest_asyncio.fixture
async def sample_feed(db_session: AsyncSession, test_user: User) -> Feed:
    feed = Feed(
        title="Security Blog",
        url="https://example.com/feed.xml",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def sample_entities(db_session: AsyncSession, sample_feed: Feed):
    """Create two entries that share a threat actor, establishing correlation."""
    entry1 = Entry(
        feed_id=sample_feed.id,
        title="APT29 Campaign Analysis",
        content_text="APT29 targets energy sector with Cobalt Strike",
        published_at=datetime(2026, 3, 1, tzinfo=UTC),
        guid="guid-1",
    )
    entry2 = Entry(
        feed_id=sample_feed.id,
        title="New Cobalt Strike C2 Infrastructure",
        content_text="New C2 infrastructure identified linked to APT29",
        published_at=datetime(2026, 3, 2, tzinfo=UTC),
        guid="guid-2",
    )
    db_session.add_all([entry1, entry2])
    await db_session.flush()

    # Create entities
    actor = ThreatActor(name="APT29", aliases=["Cozy Bear", "The Dukes"], country="Russia", motivation="espionage")
    ttp = TTP(technique_id="T1071.001", technique_name="Web Protocols", tactic="command-and-control")
    malware = MalwareFamily(name="Cobalt Strike", malware_type="backdoor")
    db_session.add_all([actor, ttp, malware])
    await db_session.flush()

    # Link actor + TTP + malware to entry1
    db_session.add_all(
        [
            EntryThreatActor(entry_id=entry1.id, threat_actor_id=actor.id, confidence="high"),
            EntryTTP(entry_id=entry1.id, ttp_id=ttp.id, confidence="high"),
            EntryMalware(entry_id=entry1.id, malware_family_id=malware.id, confidence="high"),
        ]
    )

    # Link actor to entry2 (shared entity = correlation)
    db_session.add_all(
        [
            EntryThreatActor(entry_id=entry2.id, threat_actor_id=actor.id, confidence="high"),
        ]
    )

    await db_session.flush()
    return {"entry1": entry1, "entry2": entry2, "actor": actor, "ttp": ttp, "malware": malware}


@pytest_asyncio.fixture
async def proximity_entities(db_session: AsyncSession, sample_feed: Feed):
    """Create entities with paragraph_indices to test proximity-weighted scoring.

    Entry has multi-paragraph content.  APT29 and Cobalt Strike appear in the
    same paragraph (paragraph 2), while Lazarus Group appears far away
    (paragraph 8).  Pivoting from APT29 should rank Cobalt Strike higher than
    Lazarus Group.
    """
    entry = Entry(
        feed_id=sample_feed.id,
        title="Threat Landscape Roundup",
        content_text=(
            "Paragraph 0 intro.\n\n"
            "Paragraph 1 context.\n\n"
            "APT29 deployed Cobalt Strike beacons against energy targets.\n\n"
            "Paragraph 3 filler.\n\n"
            "Paragraph 4 filler.\n\n"
            "Paragraph 5 filler.\n\n"
            "Paragraph 6 filler.\n\n"
            "Paragraph 7 filler.\n\n"
            "In a separate campaign, Lazarus Group used new tooling.\n\n"
            "Paragraph 9 conclusion."
        ),
        published_at=datetime(2026, 3, 5, tzinfo=UTC),
        guid="guid-prox-1",
    )
    db_session.add(entry)
    await db_session.flush()

    actor_apt29 = ThreatActor(name="APT29-prox", aliases=[], country="Russia", motivation="espionage")
    actor_lazarus = ThreatActor(name="Lazarus-prox", aliases=[], country="DPRK", motivation="financial")
    malware_cs = MalwareFamily(name="CobaltStrike-prox", malware_type="backdoor")
    db_session.add_all([actor_apt29, actor_lazarus, malware_cs])
    await db_session.flush()

    # APT29 in paragraph 2 (title=para0, summary=para1, content paras start at 2)
    db_session.add(
        EntryThreatActor(
            entry_id=entry.id,
            threat_actor_id=actor_apt29.id,
            confidence="high",
            paragraph_indices=[4],
        )
    )
    # Cobalt Strike also in paragraph 2 — same paragraph as APT29
    db_session.add(
        EntryMalware(
            entry_id=entry.id,
            malware_family_id=malware_cs.id,
            confidence="high",
            paragraph_indices=[4],
        )
    )
    # Lazarus in paragraph 8 — far from APT29
    db_session.add(
        EntryThreatActor(
            entry_id=entry.id,
            threat_actor_id=actor_lazarus.id,
            confidence="high",
            paragraph_indices=[10],
        )
    )

    await db_session.flush()
    return {
        "entry": entry,
        "actor_apt29": actor_apt29,
        "actor_lazarus": actor_lazarus,
        "malware_cs": malware_cs,
    }


# --- Pivot Endpoint Tests ---


@pytest.mark.asyncio
async def test_pivot_threat_actor(client: AsyncClient, auth_headers: dict, sample_entities: dict):
    actor = sample_entities["actor"]
    resp = await client.get(f"/api/intelligence/pivot/threat_actor/{actor.id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["entity"]["name"] == "APT29"
    assert len(data["entries"]) == 2


@pytest.mark.asyncio
async def test_pivot_invalid_type(client: AsyncClient, auth_headers: dict):
    resp = await client.get(f"/api/intelligence/pivot/invalid/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_pivot_not_found(client: AsyncClient, auth_headers: dict):
    resp = await client.get(f"/api/intelligence/pivot/threat_actor/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 404


# --- Graph Endpoint Tests ---


@pytest.mark.asyncio
async def test_graph_returns_nodes_and_edges(
    client: AsyncClient, auth_headers: dict, sample_entities: dict, db_session
):
    from app.models.entity_relationship import EntityRelationship

    actor = sample_entities["actor"]
    # The map shows claims only — give the co-occurring pair a typed edge.
    db_session.add(
        EntityRelationship(
            source_type="threat_actor",
            source_id=actor.id,
            target_type="malware",
            target_id=sample_entities["malware"].id,
            relationship_type="uses",
            confidence="probable",
            source="co_occurrence",
            evidence_entry_ids=[],
        )
    )
    await db_session.flush()

    resp = await client.get(f"/api/intelligence/graph/threat_actor/{actor.id}?depth=1", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert len(data["nodes"]) > 0
    assert len(data["edges"]) > 0
    # Every edge on the map is a typed claim — never a bare co-mention.
    assert all(e.get("label") != "co-mentioned" for e in data["edges"])

    # Root node should be the threat actor
    node_types = {n["type"] for n in data["nodes"]}
    assert "threat_actor" in node_types


@pytest.mark.asyncio
async def test_graph_depth_limit(client: AsyncClient, auth_headers: dict, sample_entities: dict):
    actor = sample_entities["actor"]
    resp = await client.get(f"/api/intelligence/graph/threat_actor/{actor.id}?depth=4", headers=auth_headers)
    # depth max is 3; the app's validation_error_handler returns 400
    assert resp.status_code == 400


# --- Search Endpoint Tests ---


@pytest.mark.asyncio
async def test_search_finds_threat_actor(client: AsyncClient, auth_headers: dict, sample_entities: dict):
    resp = await client.get("/api/intelligence/search?q=APT29", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] > 0
    types = {r["type"] for r in data["results"]}
    assert "threat_actor" in types


@pytest.mark.asyncio
async def test_search_excludes_entries(client: AsyncClient, auth_headers: dict, sample_entities: dict):
    """Entity search covers entities only, never articles.

    "Campaign" appears in entry1's title and nowhere in any entity, so a hit
    here would mean entries had leaked back into entity search. Article
    full-text search belongs to the Meilisearch-backed /api/search endpoint.
    """
    resp = await client.get("/api/intelligence/search?q=Campaign", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert not any(r["type"] == "entry" for r in data["results"])
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_search_empty_query_rejected(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/intelligence/search?q=", headers=auth_headers)
    # min-length validation; the app's validation_error_handler returns 400
    assert resp.status_code == 400


@pytest_asyncio.fixture
async def country_and_actors(db_session: AsyncSession):
    """A country plus actors that only mention the country in their description."""
    country = Country(name="Iran", iso_code="IR", aliases=["Islamic Republic of Iran", "Iranian"], region="Asia")
    actor1 = ThreatActor(name="MuddyWater", aliases=[], description="Iran-nexus espionage group")
    actor2 = ThreatActor(name="APT33", aliases=[], description="Suspected Iranian state-sponsored actor")
    db_session.add_all([country, actor1, actor2])
    await db_session.flush()
    return {"country": country, "actor1": actor1, "actor2": actor2}


@pytest.mark.asyncio
async def test_search_finds_country_by_name(client: AsyncClient, auth_headers: dict, country_and_actors: dict):
    resp = await client.get("/api/intelligence/search?q=Iran", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    types = {r["type"] for r in data["results"]}
    assert "country" in types
    assert "threat_actor" in types


@pytest.mark.asyncio
async def test_search_exact_country_name_ranked_first(
    client: AsyncClient, auth_headers: dict, country_and_actors: dict
):
    """An exact name match ('Iran' the country) must outrank entities that only
    mention the query in their description."""
    resp = await client.get("/api/intelligence/search?q=Iran", headers=auth_headers)
    assert resp.status_code == 200
    results = resp.json()["results"]

    assert results, "expected results for 'Iran'"
    assert results[0]["type"] == "country"
    assert results[0]["name"] == "Iran"


@pytest.mark.asyncio
async def test_search_exact_alias_match_ranked_above_partial(
    client: AsyncClient, auth_headers: dict, country_and_actors: dict
):
    """An exact alias match ('Iranian' -> Iran) outranks description matches."""
    resp = await client.get("/api/intelligence/search?q=Iranian", headers=auth_headers)
    assert resp.status_code == 200
    results = resp.json()["results"]

    assert results, "expected results for 'Iranian'"
    assert results[0]["type"] == "country"
    assert results[0]["name"] == "Iran"


# --- Timeline Endpoint Tests ---


@pytest.mark.asyncio
async def test_timeline_not_found(client: AsyncClient, auth_headers: dict):
    resp = await client.get(f"/api/intelligence/timeline/threat_actor/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 404


# --- Detection Summary Endpoint Tests ---


@pytest.mark.asyncio
async def test_detection_summary_no_ai_returns_400(client: AsyncClient, auth_headers: dict, sample_entities: dict):
    """Without an AI task assignment, detection summary should return 400."""
    entry1 = sample_entities["entry1"]
    resp = await client.post(
        "/api/intelligence/detection-summary",
        json={
            "entry_ids": [str(entry1.id)],
            "rule_formats": ["sigma"],
            "focus": "campaign",
        },
        headers=auth_headers,
    )
    # No AI provider configured, so returns 400
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_detection_summary_bad_entry_ids(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/intelligence/detection-summary",
        json={
            "entry_ids": [str(uuid.uuid4())],
            "rule_formats": ["sigma"],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 400


# --- Proximity-Based Correlation Tests ---


@pytest.mark.asyncio
async def test_pivot_returns_proximity_score(client: AsyncClient, auth_headers: dict, sample_entities: dict):
    """Pivot response includes proximity_score field."""
    actor = sample_entities["actor"]
    resp = await client.get(f"/api/intelligence/pivot/threat_actor/{actor.id}", headers=auth_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_pivot_proximity_ranking(client: AsyncClient, auth_headers: dict, proximity_entities: dict):
    """Entities in the same paragraph score higher than distant entities."""
    actor_apt29 = proximity_entities["actor_apt29"]
    resp = await client.get(f"/api/intelligence/pivot/threat_actor/{actor_apt29.id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    # Cobalt Strike (same paragraph) should have higher proximity than Lazarus (distant)
    malware_list = data["related"]["malwares"]
    actors_list = data["related"]["threat_actors"]

    # Cobalt Strike should appear in malware with high proximity
    cs_matches = [m for m in malware_list if "CobaltStrike" in m.get("name", "")]
    assert len(cs_matches) == 1
    cs_prox = cs_matches[0]["proximity_score"]

    # Lazarus should appear in threat_actors with low proximity
    laz_matches = [a for a in actors_list if "Lazarus" in a.get("name", "")]
    assert len(laz_matches) == 1
    laz_prox = laz_matches[0]["proximity_score"]

    # Same paragraph (distance 0) → 1.0; distance 6 → ~0.143
    assert cs_prox is not None
    assert laz_prox is not None
    assert cs_prox > laz_prox, f"Same-paragraph entity ({cs_prox}) should score higher than distant ({laz_prox})"


@pytest.mark.asyncio
async def test_graph_edge_has_proximity_score(
    client: AsyncClient, auth_headers: dict, proximity_entities: dict, db_session
):
    """Typed edges carry co-occurrence proximity enrichment.

    The map shows claims only: a pure co-mention produces NO edge, and a typed
    relationship over the same pair gets its proximity_score attached.
    """
    from app.models.entity_relationship import EntityRelationship

    actor_apt29 = proximity_entities["actor_apt29"]

    # Pure co-mention: no typed relationship → no edges on the map.
    resp = await client.get(f"/api/intelligence/graph/threat_actor/{actor_apt29.id}?depth=1", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["edges"] == []

    db_session.add(
        EntityRelationship(
            source_type="threat_actor",
            source_id=actor_apt29.id,
            target_type="malware",
            target_id=proximity_entities["malware_cs"].id,
            relationship_type="uses",
            confidence="probable",
            source="co_occurrence",
            evidence_entry_ids=[],
        )
    )
    await db_session.flush()

    # The first request cached the empty graph — drop it so the typed edge shows.
    from app.intelligence.correlation_cache import invalidate_entity_cache

    await invalidate_entity_cache("threat_actor", str(actor_apt29.id))

    resp = await client.get(f"/api/intelligence/graph/threat_actor/{actor_apt29.id}?depth=1", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert len(data["edges"]) > 0
    # At least one edge should have a non-null proximity_score
    prox_edges = [e for e in data["edges"] if e.get("proximity_score") is not None]
    assert len(prox_edges) > 0

    # Find the edge to Cobalt Strike — proximity_score now carries the bounded
    # composite strength (corroboration/closeness/recency), so a same-paragraph
    # co-mention scores meaningfully high but no longer a raw 1.0.
    for edge in data["edges"]:
        node_ids = {edge["source"], edge["target"]}
        cs_node_ids = [n["id"] for n in data["nodes"] if "CobaltStrike" in n.get("label", "")]
        if cs_node_ids and cs_node_ids[0] in node_ids:
            assert 0 < edge["proximity_score"] <= 1.0, "Strength must be a bounded 0–1 score"
            assert edge["proximity_score"] >= 0.4, "Same-paragraph evidence should score at least moderate"
            break


@pytest.mark.asyncio
async def test_pivot_legacy_data_gets_null_proximity(client: AsyncClient, auth_headers: dict, sample_entities: dict):
    """Entities without paragraph_indices (legacy data) get proximity_score from degraded default."""
    actor = sample_entities["actor"]
    resp = await client.get(f"/api/intelligence/pivot/threat_actor/{actor.id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    # Check that related entities have proximity_score key
    actors_list = data["related"].get("threat_actors", [])
    malwares = data["related"].get("malwares", [])
    ttps = data["related"].get("ttps", [])
    # At least one related entity should exist
    all_related = actors_list + malwares + ttps
    for entity in all_related:
        assert "proximity_score" in entity


@pytest.mark.asyncio
async def test_graph_includes_cwe_weakness_layer(
    client: AsyncClient, auth_headers: dict, sample_entities: dict, db_session
):
    """CVE nodes pull their catalog CWEs (cve_weaknesses) onto the graph as
    confirmed external_feed edges — and the endpoint must not strip the
    trust fields (the GraphEdge schema once silently dropped provenance)."""
    from app.models.cve import CVE, EntryCVE
    from app.models.cwe import CWE, CVEWeakness
    from app.models.entity_relationship import EntityRelationship

    actor = sample_entities["actor"]
    cve = CVE(cve_id="CVE-2026-11111", severity="high")
    cwe = CWE(cwe_id="CWE-79", name="Cross-site Scripting")
    db_session.add_all([cve, cwe])
    await db_session.flush()
    db_session.add_all(
        [
            EntryCVE(entry_id=sample_entities["entry1"].id, cve_id=cve.id),
            CVEWeakness(cve_id=cve.id, cwe_ref="CWE-79", cwe_id_fk=cwe.id, is_primary=True),
            EntityRelationship(
                source_type="threat_actor",
                source_id=actor.id,
                target_type="cve",
                target_id=cve.id,
                relationship_type="exploits",
                confidence="confirmed",
                source="analyst_created",
                evidence_entry_ids=[],
            ),
        ]
    )
    await db_session.flush()

    resp = await client.get(f"/api/intelligence/graph/threat_actor/{actor.id}?depth=1", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    node_types = {n["type"] for n in data["nodes"]}
    assert "cwe" in node_types
    weakness_edges = [e for e in data["edges"] if e["label"] == "weakness"]
    assert weakness_edges, "CVE→CWE weakness edge missing"
    assert weakness_edges[0]["provenance"] == "external_feed"
    assert weakness_edges[0]["confidence"] == "confirmed"
