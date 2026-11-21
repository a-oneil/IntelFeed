"""The evidence behind a Review lens row: an entity's articles, with the
paragraph naming it."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.models.entry import Entry
from app.models.threat_actor import EntryThreatActor, ThreatActor


async def _entry(db, feed, text, days_ago=0):
    e = Entry(
        feed_id=feed.id,
        title=f"Report {uuid.uuid4().hex[:6]}",
        url=f"https://evidence.example/{uuid.uuid4()}",
        guid=str(uuid.uuid4()),
        content_text=text,
        published_at=datetime.now(UTC) - timedelta(days=days_ago),
    )
    db.add(e)
    await db.flush()
    return e


@pytest.mark.asyncio
async def test_entity_evidence_leads_with_the_creating_article(client, admin_headers, db_session, test_feed):
    tag = uuid.uuid4().hex[:6]
    origin = await _entry(db_session, test_feed, f"Intro.\n\nStorm-{tag} phished ministries.", days_ago=5)
    later = await _entry(db_session, test_feed, f"Roundup.\n\nAlso seen: Storm-{tag} again.", days_ago=1)
    actor = ThreatActor(name=f"Storm-{tag}", created_from_entry_id=origin.id)
    db_session.add(actor)
    await db_session.flush()
    db_session.add_all(
        [
            EntryThreatActor(entry_id=origin.id, threat_actor_id=actor.id, matched_names=[actor.name]),
            EntryThreatActor(entry_id=later.id, threat_actor_id=actor.id, matched_names=[actor.name]),
        ]
    )
    await db_session.flush()

    resp = await client.get(f"/api/engine/extraction/entities/threat_actor/{actor.id}/evidence", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert [a["entry_id"] for a in body] == [str(origin.id), str(later.id)]
    assert body[0]["paragraphs"] == [f"Storm-{tag} phished ministries."]
    assert actor.name in body[0]["highlight"]


@pytest.mark.asyncio
async def test_entity_evidence_is_for_admins(client, auth_headers, db_session):
    actor = ThreatActor(name=f"Quiet {uuid.uuid4().hex[:6]}")
    db_session.add(actor)
    await db_session.flush()
    resp = await client.get(f"/api/engine/extraction/entities/threat_actor/{actor.id}/evidence", headers=auth_headers)
    assert resp.status_code == 403
