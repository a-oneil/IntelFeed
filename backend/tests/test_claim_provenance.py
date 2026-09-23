"""Field-level provenance: recording claims, collapsing repeats, and reading them back.

The relationship trust ladder covers links between entities; these tests cover
the scalar facts on a profile — who asserted a motivation, a country, a
description, and whether that assertion still matches what the column says.
"""

import uuid

import pytest_asyncio
from sqlalchemy import func, select

from app import entity_types
from app.models.entity_field_claim import EntityFieldClaim
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.threat_actor import ThreatActor
from app.services.claim_provenance import (
    claim_key,
    get_entity_claims,
    record_claim,
    record_claims,
    render_value,
)


@pytest_asyncio.fixture
async def actor(db_session) -> ThreatActor:
    row = ThreatActor(name=f"Test Actor {uuid.uuid4().hex[:8]}", motivation="financial", country="Russia")
    db_session.add(row)
    await db_session.flush()
    return row


@pytest_asyncio.fixture
async def graded_entry(db_session) -> Entry:
    feed = Feed(
        title="Vendor Blog", url=f"https://v{uuid.uuid4().hex[:6]}.example/f", feed_type="rss", reliability_rating="B"
    )
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(
        feed_id=feed.id,
        title="Actor shifts to double extortion",
        guid=f"guid-{uuid.uuid4()}",
        url=f"https://example.com/{uuid.uuid4()}",
        content_text="body",
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


# ── value rendering ───────────────────────────────────────────────


def test_render_value_normalises_shapes():
    assert render_value(None) == ""
    assert render_value(["healthcare", "energy"]) == "healthcare, energy"
    assert render_value(9.80) == "9.8"
    assert render_value("  spaced  ") == "spaced"


def test_render_value_drops_empty_list_members():
    assert render_value(["a", None, "", "b"]) == "a, b"


# ── recording ─────────────────────────────────────────────────────


async def test_record_claim_writes_a_row(db_session, actor):
    assert await record_claim(
        db_session,
        entity_type=entity_types.THREAT_ACTOR,
        entity_id=actor.id,
        field="motivation",
        value="financial",
        source_kind="analyst",
    )
    rows = (await db_session.execute(select(EntityFieldClaim))).scalars().all()
    assert len(rows) == 1
    assert rows[0].value_text == "financial"


async def test_empty_values_are_not_claims(db_session, actor):
    for empty in (None, "", "   ", []):
        assert (
            await record_claim(
                db_session,
                entity_type=entity_types.THREAT_ACTOR,
                entity_id=actor.id,
                field="motivation",
                value=empty,
                source_kind="analyst",
            )
            is False
        )
    assert (await db_session.execute(select(func.count()).select_from(EntityFieldClaim))).scalar_one() == 0


async def test_same_source_reasserting_collapses(db_session, actor):
    """A nightly adapter re-scraping the same value is one claim, seen twice."""
    for _ in range(3):
        await record_claim(
            db_session,
            entity_type=entity_types.THREAT_ACTOR,
            entity_id=actor.id,
            field="country",
            value="Russia",
            source_kind="enrichment",
            source_ref="malpedia",
        )
    assert (await db_session.execute(select(func.count()).select_from(EntityFieldClaim))).scalar_one() == 1


async def test_different_sources_stay_separate(db_session, actor):
    """Two sources asserting the same value is corroboration, not a duplicate."""
    await record_claim(
        db_session,
        entity_type=entity_types.THREAT_ACTOR,
        entity_id=actor.id,
        field="country",
        value="Russia",
        source_kind="enrichment",
        source_ref="malpedia",
    )
    await record_claim(
        db_session,
        entity_type=entity_types.THREAT_ACTOR,
        entity_id=actor.id,
        field="country",
        value="Russia",
        source_kind="external_feed",
        source_ref="cybergeist",
    )
    assert (await db_session.execute(select(func.count()).select_from(EntityFieldClaim))).scalar_one() == 2


async def test_different_articles_stay_separate(db_session, actor, graded_entry):
    """Two articles asserting the same value are two pieces of evidence."""
    other = Entry(
        feed_id=graded_entry.feed_id,
        title="Second report",
        guid=f"guid-{uuid.uuid4()}",
        url=f"https://example.com/{uuid.uuid4()}",
        content_text="body",
    )
    db_session.add(other)
    await db_session.flush()
    for entry_id in (graded_entry.id, other.id):
        await record_claim(
            db_session,
            entity_type=entity_types.THREAT_ACTOR,
            entity_id=actor.id,
            field="motivation",
            value="financial",
            source_kind="ai_extraction",
            entry_id=entry_id,
        )
    assert (await db_session.execute(select(func.count()).select_from(EntityFieldClaim))).scalar_one() == 2


def test_claim_key_ignores_case_but_not_source():
    base = dict(
        entity_type=entity_types.THREAT_ACTOR,
        entity_id=uuid.UUID(int=1),
        field="motivation",
        source_kind="analyst",
        source_ref=None,
        entry_id=None,
    )
    assert claim_key(value_text="Financial", **base) == claim_key(value_text="financial", **base)
    assert claim_key(value_text="financial", **base) != claim_key(
        **{**base, "source_kind": "enrichment"}, value_text="financial"
    )


async def test_record_claims_skips_untracked_fields(db_session, actor):
    written = await record_claims(
        db_session,
        entity_type=entity_types.THREAT_ACTOR,
        entity_id=actor.id,
        values={"motivation": "financial", "wikipedia_url": "https://en.wikipedia.org/x"},
        source_kind="analyst",
    )
    assert written == 1


async def test_recording_never_breaks_the_write(db_session, actor, monkeypatch):
    """Provenance is an audit trail — a failure must not surface to the caller."""
    import app.services.claim_provenance as mod

    def boom(*_a, **_kw):
        raise RuntimeError("digest exploded")

    monkeypatch.setattr(mod, "claim_key", boom)
    assert (
        await record_claim(
            db_session,
            entity_type=entity_types.THREAT_ACTOR,
            entity_id=actor.id,
            field="motivation",
            value="financial",
            source_kind="analyst",
        )
        is False
    )


# ── reading back ──────────────────────────────────────────────────


async def test_claims_are_marked_against_the_live_value(db_session, actor):
    await record_claim(
        db_session,
        entity_type=entity_types.THREAT_ACTOR,
        entity_id=actor.id,
        field="motivation",
        value="financial",
        source_kind="analyst",
    )
    await record_claim(
        db_session,
        entity_type=entity_types.THREAT_ACTOR,
        entity_id=actor.id,
        field="motivation",
        value="espionage",
        source_kind="enrichment",
        source_ref="malpedia",
    )

    out = await get_entity_claims(db_session, entity_types.THREAT_ACTOR, actor.id, entity_row=actor)
    bucket = out["fields"]["motivation"]
    assert bucket["current_value"] == "financial"
    assert bucket["agreeing"] == 1
    assert bucket["conflicting"] == 1


async def test_populated_but_unclaimed_fields_are_reported(db_session, actor):
    """'Nothing on a profile should be unattributable' — so say when it isn't."""
    out = await get_entity_claims(db_session, entity_types.THREAT_ACTOR, actor.id, entity_row=actor)
    assert "motivation" in out["unsourced_fields"]
    assert "country" in out["unsourced_fields"]
    # An empty column isn't unsourced, it's just empty.
    assert "description" not in out["unsourced_fields"]


async def test_read_resolves_the_article_and_its_feed_grade(db_session, actor, graded_entry):
    await record_claim(
        db_session,
        entity_type=entity_types.THREAT_ACTOR,
        entity_id=actor.id,
        field="motivation",
        value="financial",
        source_kind="ai_extraction",
        entry_id=graded_entry.id,
        quote="The group is financially motivated.",
        confidence="high",
    )
    out = await get_entity_claims(db_session, entity_types.THREAT_ACTOR, actor.id, entity_row=actor)
    claim = out["fields"]["motivation"]["claims"][0]
    assert claim["entry"]["title"] == "Actor shifts to double extortion"
    assert claim["entry"]["feed_reliability"] == "B"
    assert claim["quote"] == "The group is financially motivated."
    assert claim["confidence"] == "high"
    assert claim["agrees"] is True


# ── end to end through the API ────────────────────────────────────


async def test_analyst_edit_records_a_claim(client, db_session, actor, auth_headers, test_user):
    res = await client.put(
        f"/api/entities/threat-actors/{actor.id}",
        json={"motivation": "espionage"},
        headers=auth_headers,
    )
    assert res.status_code == 200

    prov = await client.get(f"/api/entities/threat_actor/{actor.id}/provenance", headers=auth_headers)
    assert prov.status_code == 200
    claims = prov.json()["fields"]["motivation"]["claims"]
    assert len(claims) == 1
    assert claims[0]["source_kind"] == "analyst"
    assert claims[0]["analyst"] == test_user.username
    assert claims[0]["agrees"] is True


async def test_resaving_an_unchanged_value_records_nothing(client, db_session, actor, auth_headers):
    """A no-op save must not restamp the field as freshly asserted by whoever
    hit save — that would drown real provenance in noise."""
    body = {"motivation": actor.motivation}
    await client.put(f"/api/entities/threat-actors/{actor.id}", json=body, headers=auth_headers)
    await client.put(f"/api/entities/threat-actors/{actor.id}", json=body, headers=auth_headers)

    total = (await db_session.execute(select(func.count()).select_from(EntityFieldClaim))).scalar_one()
    assert total == 0


async def test_provenance_rejects_unknown_entity_types(client, actor, auth_headers):
    res = await client.get(f"/api/entities/banana/{actor.id}/provenance", headers=auth_headers)
    assert res.status_code == 400


async def test_provenance_404s_for_a_missing_entity(client, auth_headers):
    res = await client.get(f"/api/entities/threat_actor/{uuid.uuid4()}/provenance", headers=auth_headers)
    assert res.status_code == 404
