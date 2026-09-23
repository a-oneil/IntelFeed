"""Tests for ranked entity merge suggestions (app/intelligence/merge_suggestions.py)."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.merge_suggestions import (
    make_view,
    normalize_name,
    pair_key,
    score_pair,
    significant_tokens,
    suggest_merges,
)
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import ThreatActor
from app.models.tool import Tool


def _fake(name, aliases=None, entity_type="malware", article_count=0, entry_ids=None, rel_keys=None):
    class _E:
        pass

    e = _E()
    e.id = uuid.uuid4()
    e.name = name
    e.aliases = aliases or []
    e.article_count = article_count
    return make_view(entity_type, e, entry_ids=entry_ids, rel_keys=rel_keys)


# ── Normalization / suffix stripping ────────────────────────────────


def test_normalize_strips_generic_suffixes():
    assert normalize_name("Pegasus Spyware") == "pegasus"
    assert normalize_name("Clop Ransomware Gang") == "clop"
    assert normalize_name("Lazarus Group") == "lazarus"
    assert normalize_name("Sandworm Team") == "sandworm"


def test_normalize_never_strips_to_empty():
    assert normalize_name("APT Group") == "apt"
    assert normalize_name("Ransomware") == "ransomware"


def test_normalize_handles_punctuation_and_case():
    assert normalize_name("NSO-Group  Pegasus") == "nso group pegasus"
    assert normalize_name("LOCKBIT 3.0") == "lockbit 3 0"


def test_significant_tokens_drops_generic_filler():
    assert significant_tokens("nso group pegasus") == frozenset({"nso", "pegasus"})
    # All-generic names keep their tokens so comparison stays possible
    assert significant_tokens("apt") == frozenset({"apt"})


# ── Pair scoring ─────────────────────────────────────────────────────


def test_pegasus_vs_pegasus_spyware_scores_high():
    a = _fake("Pegasus", article_count=10)
    b = _fake("Pegasus Spyware", article_count=2)
    score, reasons = score_pair(a, b)
    assert score >= 0.6
    assert any("identical name after normalization" in r for r in reasons)


def test_nso_group_pegasus_containment():
    a = _fake("Pegasus")
    b = _fake("NSO Group Pegasus", entity_type="tool")
    score, reasons = score_pair(a, b)
    assert score >= 0.45
    assert any("containment" in r for r in reasons)


def test_alias_overlap_signal():
    a = _fake("Pegasus")
    b = _fake("Chrysaor", aliases=["Pegasus"])
    score, reasons = score_pair(a, b)
    assert score >= 0.5
    assert any("alias" in r for r in reasons)


def test_unrelated_names_score_zero():
    a = _fake("Emotet")
    b = _fake("LockBit")
    score, reasons = score_pair(a, b)
    assert score == 0.0
    assert reasons == []


def test_co_mentions_alone_do_not_create_candidates():
    shared_entries = {uuid.uuid4() for _ in range(10)}
    a = _fake("Emotet", entry_ids=shared_entries)
    b = _fake("LockBit", entry_ids=shared_entries)
    score, _ = score_pair(a, b)
    assert score == 0.0


def test_co_mentions_and_relationships_boost_name_match():
    shared_entries = {uuid.uuid4() for _ in range(5)}
    shared_rel = ("threat_actor", str(uuid.uuid4()))
    a = _fake("Pegasus", entry_ids=shared_entries, rel_keys={shared_rel})
    b = _fake("Pegasus Spyware", entry_ids=shared_entries, rel_keys={shared_rel})
    boosted, reasons = score_pair(a, b)
    bare, _ = score_pair(_fake("Pegasus"), _fake("Pegasus Spyware"))
    assert boosted > bare
    assert any("co-mentioned in 5" in r for r in reasons)
    assert any("shared relationship" in r for r in reasons)


def test_directly_related_pair_gets_boost():
    a = _fake("Pegasus")
    b = _fake("Pegasus Spyware")
    b_related = _fake("Pegasus Spyware")
    b_related.rel_keys = frozenset({(a.entity_type, str(a.id))})
    related_score, reasons = score_pair(a, b_related)
    plain_score, _ = score_pair(a, b)
    assert related_score > plain_score
    assert any("directly related" in r for r in reasons)


def test_score_capped_at_one():
    shared_entries = {uuid.uuid4() for _ in range(50)}
    rels = {("threat_actor", str(uuid.uuid4())) for _ in range(10)}
    a = _fake("Pegasus", aliases=["Chrysaor"], entry_ids=shared_entries, rel_keys=rels)
    b = _fake("Pegasus Spyware", aliases=["Chrysaor"], entry_ids=shared_entries, rel_keys=rels)
    score, _ = score_pair(a, b)
    assert score <= 1.0


def test_pair_key_is_order_independent():
    id_a, id_b = uuid.uuid4(), uuid.uuid4()
    assert pair_key("malware", id_a, "tool", id_b) == pair_key("tool", id_b, "malware", id_a)


# ── Service + endpoint (DB-backed) ──────────────────────────────────


@pytest.mark.asyncio
async def test_suggest_merges_finds_pegasus_pair(db_session: AsyncSession):
    db_session.add(MalwareFamily(name="Pegasus", article_count=10))
    db_session.add(MalwareFamily(name="Pegasus Spyware", article_count=2))
    db_session.add(MalwareFamily(name="Emotet", article_count=5))
    await db_session.flush()

    result = await suggest_merges(db_session, "malware")
    assert result["total"] == 1
    s = result["suggestions"][0]
    # Keeper is the higher-article-count entity
    assert s["keeper"]["name"] == "Pegasus"
    assert s["candidate"]["name"] == "Pegasus Spyware"
    assert s["score"] >= 0.6
    assert s["cross_type"] is False


@pytest.mark.asyncio
async def test_suggest_merges_flags_cross_type_tool_collision(db_session: AsyncSession):
    db_session.add(MalwareFamily(name="Pegasus", article_count=10))
    db_session.add(Tool(name="NSO Group Pegasus", article_count=1))
    await db_session.flush()

    result = await suggest_merges(db_session, "malware")
    cross = [s for s in result["suggestions"] if s["cross_type"]]
    assert len(cross) == 1
    assert any("possible cross-type duplicate" in r for r in cross[0]["reasons"])
    types = {cross[0]["keeper"]["entity_type"], cross[0]["candidate"]["entity_type"]}
    assert types == {"malware", "tool"}


@pytest.mark.asyncio
async def test_co_mention_reason_in_service(db_session: AsyncSession):
    feed = Feed(title="F", url="https://example.com/f.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(feed_id=feed.id, title="E", guid="g-1", url="https://example.com/1")
    m1 = MalwareFamily(name="Pegasus", article_count=1)
    m2 = MalwareFamily(name="Pegasus Spyware", article_count=1)
    db_session.add_all([entry, m1, m2])
    await db_session.flush()
    db_session.add(EntryMalware(entry_id=entry.id, malware_family_id=m1.id))
    db_session.add(EntryMalware(entry_id=entry.id, malware_family_id=m2.id))
    await db_session.flush()

    result = await suggest_merges(db_session, "malware")
    assert result["total"] == 1
    assert any("co-mentioned in 1 entry" in r for r in result["suggestions"][0]["reasons"])


@pytest.mark.asyncio
async def test_merge_suggestions_endpoint_and_dismissal(client, auth_headers, db_session: AsyncSession):
    db_session.add(ThreatActor(name="Scattered Spider", article_count=20))
    db_session.add(ThreatActor(name="Scattered Spider Group", article_count=1))
    await db_session.flush()

    resp = await client.get("/api/entities/threat_actor/merge-suggestions", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    suggestion = body["suggestions"][0]
    assert suggestion["keeper"]["name"] == "Scattered Spider"

    # Dismiss the pair (order-independent)
    resp = await client.post(
        "/api/entities/merge-suggestions/dismiss",
        headers=auth_headers,
        json={
            "entity_type_a": suggestion["candidate"]["entity_type"],
            "entity_id_a": suggestion["candidate"]["id"],
            "entity_type_b": suggestion["keeper"]["entity_type"],
            "entity_id_b": suggestion["keeper"]["id"],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["dismissed"] is True

    # Dismissed pair is excluded from subsequent responses
    resp = await client.get("/api/entities/threat_actor/merge-suggestions", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 0

    # Dismissing again is idempotent (unique constraint, do-nothing upsert)
    resp = await client.post(
        "/api/entities/merge-suggestions/dismiss",
        headers=auth_headers,
        json={
            "entity_type_a": suggestion["keeper"]["entity_type"],
            "entity_id_a": suggestion["keeper"]["id"],
            "entity_type_b": suggestion["candidate"]["entity_type"],
            "entity_id_b": suggestion["candidate"]["id"],
        },
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_merge_suggestions_endpoint_rejects_unknown_type(client, auth_headers):
    resp = await client.get("/api/entities/cve/merge-suggestions", headers=auth_headers)
    assert resp.status_code == 400
