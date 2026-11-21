"""Every hand unlink writes a ``removed`` link-log row that Restore can undo."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from app.intelligence.link_validation_apply import restore_from_log
from app.models.cve import CVE, EntryCVE
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.tools.curation import _bulk_unlink_entities


@pytest.fixture
async def entry(db_session):
    feed = Feed(title="Unlink Feed", url="https://example.com/unlink.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    e = Entry(feed_id=feed.id, title="LDAPNightmare", guid="unlink-1", published_at=datetime.now(UTC))
    db_session.add(e)
    await db_session.flush()
    return e


async def _log_rows(db_session, entity_id):
    q = select(EntityLinkValidationLog).where(EntityLinkValidationLog.entity_id == entity_id)
    return (await db_session.execute(q.order_by(EntityLinkValidationLog.created_at))).scalars().all()


async def test_an_article_page_unlink_is_logged_and_restorable(client, auth_headers, db_session, entry):
    cve = CVE(cve_id="CVE-2024-49112")
    db_session.add(cve)
    await db_session.flush()
    db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve.id, paragraph_indices=[3]))
    await db_session.commit()

    resp = await client.delete(f"/api/entries/{entry.id}/cves/{cve.id}", headers=auth_headers)
    assert resp.status_code == 204
    [row] = await _log_rows(db_session, cve.id)
    assert row.action == "removed" and row.entity_name_snapshot == "CVE-2024-49112"
    assert row.reason == "Unlinked by testuser from the article" and row.original_paragraph_indices == [3]

    assert await restore_from_log(db_session, row.id) == (True, "restored")
    await db_session.flush()
    link = (await db_session.execute(select(EntryCVE).where(EntryCVE.cve_id == cve.id))).scalar_one()
    assert link.paragraph_indices == [3]


async def test_autolinking_and_tool_unlinks_are_logged_and_decrement(
    client, auth_headers, db_session, entry, test_user
):
    actors = [ThreatActor(name=n, article_count=1) for n in ("Ray", "Kryptos")]
    db_session.add_all(actors)
    await db_session.flush()
    for a in actors:
        db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=a.id, source="ai", matched_names=[a.name]))
    await db_session.commit()
    ray, kryptos = actors

    resp = await client.post(
        "/api/entity-links/bulk-unlink",
        json={"items": [{"entity_type": "threat_actor", "entity_id": str(ray.id), "entry_id": str(entry.id)}]},
        headers=auth_headers,
    )
    assert resp.json()["deleted"] == 1
    item = {"entity_type": "threat_actor", "entity_id": str(kryptos.id), "entry_id": str(entry.id)}
    assert (await _bulk_unlink_entities(db_session, test_user.id, [item]))["deleted"] == 1
    await db_session.flush()

    [ray_row] = await _log_rows(db_session, ray.id)
    [kryptos_row] = await _log_rows(db_session, kryptos.id)
    assert ray_row.reason == "Unlinked by testuser in Engine › Autolinking (bulk)"
    assert kryptos_row.reason == "Unlinked by testuser with the bulk_unlink_entities tool"
    assert ray_row.original_source == "ai" and ray_row.original_matched_names == ["Ray"]
    for a in actors:
        await db_session.refresh(a)
        assert a.article_count == 0


async def test_history_lists_a_hand_unlink_under_no_origin(client, auth_headers, admin_headers, db_session, entry):
    actor = ThreatActor(name="MEGAcmd Crew", article_count=1)
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id, source="ai"))
    await db_session.commit()
    resp = await client.delete(f"/api/entries/{entry.id}/threat-actors/{actor.id}", headers=auth_headers)
    assert resp.status_code == 204

    params = {"mode": "apply", "entity_id": str(actor.id)}
    rows = (await client.get("/api/admin/hygiene/feed", params=params, headers=admin_headers)).json()["rows"]
    assert [(r["action"], r["origin"]) for r in rows] == [("removed", None)]
    params["origin"] = "adjudicator"
    rows = (await client.get("/api/admin/hygiene/feed", params=params, headers=admin_headers)).json()["rows"]
    assert rows == []
