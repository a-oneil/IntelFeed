"""Engine cleanup queues act per entity, and dismissals stick.

- Reclassify proposals are filed once per article; apply/dismiss settle every
  copy (both logs, any suggested type), and a dismissal stops new filings.
- "Not a duplicate" drops a pair from the likely-duplicate count.
- Held (pending) autolink matches can be listed and resolved by an analyst.
- Remove-link proposals group per entity; applying removes the links and
  clears the proposals, keeping clears them and leaves the links.
- Old proposals from the retired link validator expire.
"""

import uuid

import pytest
from sqlalchemy import func, select

from app.intelligence.link_validation_apply import LinkRow, log_reclassification
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.pending_autolink import PendingAutolinkMatch
from app.models.tool import EntryTool, Tool

pytestmark = pytest.mark.asyncio


async def _entries(db_session, feed, n):
    out = []
    for _ in range(n):
        e = Entry(feed_id=feed.id, title="t", url=f"https://example.com/{uuid.uuid4()}", guid=str(uuid.uuid4()))
        db_session.add(e)
        out.append(e)
    await db_session.flush()
    return out


async def _seed_reclassify(db_session, feed, malware):
    """Three articles' worth of "malware → threat_actor", one "→ tool", and one
    adjudicator copy in the maintenance log."""
    entries = await _entries(db_session, feed, 4)
    for e, sug in zip(entries, ["threat_actor", "threat_actor", "threat_actor", "tool"], strict=True):
        db_session.add(
            EntityLinkValidationLog(
                entry_id=e.id,
                entity_type="malware",
                entity_id=malware.id,
                entity_name_snapshot=malware.name,
                action="needs_reclassification",
                suggested_entity_type=sug,
                reason="it's a group",
            )
        )
    db_session.add(
        EntityMaintenanceLog(
            entity_type="malware",
            entity_id=malware.id,
            action="adjudication_reclassify",
            mode="shadow",
            before={"entry_id": str(entries[0].id), "entity": {"name": malware.name}},
            after={"suggested_type": "threat_actor", "reason": "group"},
            applied=False,
        )
    )
    await db_session.flush()
    return entries


async def _pending_reclassify_rows(db_session, entity_id) -> int:
    a = (
        await db_session.execute(
            select(func.count())
            .select_from(EntityLinkValidationLog)
            .where(
                EntityLinkValidationLog.entity_id == entity_id,
                EntityLinkValidationLog.action == "needs_reclassification",
            )
        )
    ).scalar_one()
    b = (
        await db_session.execute(
            select(func.count())
            .select_from(EntityMaintenanceLog)
            .where(
                EntityMaintenanceLog.entity_id == entity_id,
                EntityMaintenanceLog.action == "adjudication_reclassify",
                EntityMaintenanceLog.applied.is_(False),
            )
        )
    ).scalar_one()
    return a + b


async def test_reclassify_groups_fold_per_entity(client, admin_headers, db_session, test_feed):
    malware = MalwareFamily(name="Everest")
    db_session.add(malware)
    await db_session.flush()
    await _seed_reclassify(db_session, test_feed, malware)
    await db_session.commit()

    resp = await client.get("/api/admin/hygiene/reclassify-groups", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 1
    g = body["groups"][0]
    assert g["name"] == "Everest" and g["exists"] is True
    assert g["proposals"] == 5
    assert [s["type"] for s in g["suggestions"]] == ["threat_actor", "tool"]
    assert g["suggestions"][0]["count"] == 4

    stats = (await client.get("/api/admin/hygiene/stats", headers=admin_headers)).json()
    assert stats["pending_advisories"] == 1


async def test_dismiss_one_row_clears_every_copy_and_sticks(client, admin_headers, db_session, test_feed):
    malware = MalwareFamily(name="Everest")
    db_session.add(malware)
    await db_session.flush()
    entries = await _seed_reclassify(db_session, test_feed, malware)
    one = (
        (
            await db_session.execute(
                select(EntityLinkValidationLog.id).where(EntityLinkValidationLog.entity_id == malware.id)
            )
        )
        .scalars()
        .first()
    )
    await db_session.commit()

    resp = await client.delete(f"/api/admin/hygiene/feed/link_validator/{one}", headers=admin_headers)
    assert resp.status_code == 204, resp.text
    assert await _pending_reclassify_rows(db_session, malware.id) == 0

    # The next article's verdict isn't filed again.
    link = LinkRow(
        entity_key="malware",
        entity_type="malware",
        entity_id=malware.id,
        name="Everest",
        source="auto_link",
        confidence="high",
        matched_names=["Everest"],
        paragraph_indices=[0],
        extracted_at=None,
    )
    await log_reclassification(db_session, entries[0].id, link, "again", "threat_actor", None)
    await db_session.flush()
    assert await _pending_reclassify_rows(db_session, malware.id) == 0


async def test_apply_group_converts_and_clears_every_suggestion(client, admin_headers, db_session, test_feed):
    malware = MalwareFamily(name="Everest")
    db_session.add(malware)
    await db_session.flush()
    await _seed_reclassify(db_session, test_feed, malware)
    mid = malware.id
    await db_session.commit()

    resp = await client.post(
        "/api/admin/hygiene/reclassify-groups/apply",
        json={"items": [{"entity_type": "malware", "entity_id": str(mid), "target_type": "threat_actor"}]},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["entities"] == 1 and resp.json()["failed"] == 0
    # "→ tool" went too: the entity isn't malware any more.
    assert await _pending_reclassify_rows(db_session, mid) == 0
    db_session.expire_all()
    assert await db_session.get(MalwareFamily, mid) is None


async def test_not_duplicate_drops_the_pair(client, admin_headers, db_session):
    a = Tool(name="KillSecurity 2.0", created_via="ai_extraction")
    b = Tool(name="KillSecurity 3.0", created_via="ai_extraction")
    db_session.add_all([a, b])
    await db_session.flush()
    await db_session.commit()

    before = (await client.get("/api/engine/extraction/stats?window=all", headers=admin_headers)).json()
    listed = (await client.get("/api/engine/extraction/entities?status=dupe&window=all", headers=admin_headers)).json()
    assert before["likely_duplicates"] == 2
    row = next(r for r in listed["items"] if r["id"] == str(a.id))
    assert row["duplicate_of_id"] == str(b.id)

    resp = await client.post(
        "/api/engine/extraction/not-duplicate",
        json={"entity_type": "tool", "id": str(a.id), "other_id": str(b.id)},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    after = (await client.get("/api/engine/extraction/stats?window=all", headers=admin_headers)).json()
    assert after["likely_duplicates"] == 0


async def test_pending_matches_list_and_resolve(client, admin_headers, db_session, test_feed):
    royal = MalwareFamily(name="Royal")
    db_session.add(royal)
    await db_session.flush()
    entries = await _entries(db_session, test_feed, 2)
    for e in entries:
        db_session.add(
            PendingAutolinkMatch(
                entry_id=e.id,
                entity_type="malware",
                entity_id=royal.id,
                canonical_name="Royal",
                matched_names=["Royal"],
                paragraph_indices=[0],
                confidence="high",
            )
        )
    await db_session.commit()

    body = (await client.get("/api/entity-links/pending", headers=admin_headers)).json()
    assert body["total_matches"] == 2
    g = body["groups"][0]
    assert g["name"] == "Royal" and g["count"] == 2 and len(g["entries"]) == 2

    # Reject one by row id, link the rest by entity.
    resp = await client.post(
        "/api/entity-links/pending/resolve",
        json={"resolution": "reject", "ids": [g["entries"][0]["id"]]},
        headers=admin_headers,
    )
    assert resp.json() == {"promoted": 0, "rejected": 1}
    resp = await client.post(
        "/api/entity-links/pending/resolve",
        json={"resolution": "promote", "entity_type": "malware", "entity_id": str(royal.id)},
        headers=admin_headers,
    )
    assert resp.json() == {"promoted": 1, "rejected": 0}

    linked = (
        await db_session.execute(
            select(func.count()).select_from(EntryMalware).where(EntryMalware.malware_family_id == royal.id)
        )
    ).scalar_one()
    assert linked == 1
    assert (await client.get("/api/entity-links/pending", headers=admin_headers)).json()["total_matches"] == 0


async def _seed_unlinks(db_session, feed):
    """Malware linked to three articles with a shadow_remove each (link log),
    and a tool linked to one with an adjudication_unlink (maintenance log)."""
    malware = MalwareFamily(name="Linuxish", article_count=3)
    tool = Tool(name="python3", article_count=1)
    db_session.add_all([malware, tool])
    await db_session.flush()
    entries = await _entries(db_session, feed, 3)
    for e in entries:
        db_session.add(
            EntryMalware(entry_id=e.id, malware_family_id=malware.id, source="auto_link", confidence="medium")
        )
        db_session.add(
            EntityLinkValidationLog(
                entry_id=e.id,
                entity_type="malware",
                entity_id=malware.id,
                entity_name_snapshot=malware.name,
                action="shadow_remove",
                reason="the OS, not malware",
                original_matched_names=["Linuxish"],
            )
        )
    db_session.add(EntryTool(entry_id=entries[0].id, tool_id=tool.id))
    db_session.add(
        EntityMaintenanceLog(
            entity_type="tool",
            entity_id=tool.id,
            action="adjudication_unlink",
            mode="shadow",
            before={"entry_id": str(entries[0].id), "junction": {"matched_names": ["python3"]}},
            after={"reason": "the interpreter", "confidence": "high"},
            applied=False,
        )
    )
    await db_session.flush()
    return malware, tool, entries


async def _count(db_session, model, *where) -> int:
    return (await db_session.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


async def test_unlink_groups_list_apply_and_keep(client, admin_headers, db_session, test_feed):
    malware, tool, _entries_ = await _seed_unlinks(db_session, test_feed)
    mid, tid = malware.id, tool.id
    await db_session.commit()

    body = (await client.get("/api/admin/hygiene/unlink-groups", headers=admin_headers)).json()
    assert body["total"] == 2 and body["proposals"] == 4
    first = body["groups"][0]
    assert first["name"] == "Linuxish" and first["proposals"] == 3 and first["linked"] == 3
    assert first["matched_names"] == ["Linuxish"] and first["reason"] == "the OS, not malware"

    rows = (
        await client.get(
            f"/api/admin/hygiene/unlink-groups/rows?entity_type=malware&entity_id={mid}", headers=admin_headers
        )
    ).json()
    assert len(rows) == 3 and rows[0]["entry_title"] == "t"

    # Keep one article's link, remove the rest of the group.
    resp = await client.post(
        "/api/admin/hygiene/unlink-groups/keep", json={"row_ids": [rows[0]["id"]]}, headers=admin_headers
    )
    assert resp.json()["done"] == 1
    resp = await client.post(
        "/api/admin/hygiene/unlink-groups/apply",
        json={
            "items": [{"entity_type": "malware", "entity_id": str(mid)}, {"entity_type": "tool", "entity_id": str(tid)}]
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"done": 3, "failed": 0, "remaining": 0, "errors": []}

    assert await _count(db_session, EntryMalware, EntryMalware.malware_family_id == mid) == 1
    assert await _count(db_session, EntryTool, EntryTool.tool_id == tid) == 0
    assert (await client.get("/api/admin/hygiene/unlink-groups", headers=admin_headers)).json()["total"] == 0
    # Each removal left a restorable record.
    assert (
        await _count(
            db_session,
            EntityLinkValidationLog,
            EntityLinkValidationLog.entity_id == mid,
            EntityLinkValidationLog.action == "removed",
        )
        == 2
    )


async def test_legacy_link_proposals_expire(db_session, test_feed):
    from datetime import UTC, datetime, timedelta

    from app.services.proposal_dismissals import expire_legacy_link_proposals

    malware = MalwareFamily(name="Old")
    db_session.add(malware)
    await db_session.flush()
    entries = await _entries(db_session, test_feed, 2)
    for e, age in zip(entries, [40, 5], strict=True):
        db_session.add(
            EntityLinkValidationLog(
                entry_id=e.id,
                entity_type="malware",
                entity_id=malware.id,
                action="shadow_remove",
                created_at=datetime.now(UTC) - timedelta(days=age),
            )
        )
    await db_session.flush()
    assert await expire_legacy_link_proposals(db_session) == 1
    assert await _count(db_session, EntityLinkValidationLog, EntityLinkValidationLog.entity_id == malware.id) == 1


def test_only_ambiguous_country_names_are_held():
    from app.intelligence.autolinker import is_provisional_form

    assert is_provisional_form("country", "Turkey")
    assert is_provisional_form("country", "Jordan")
    assert not is_provisional_form("country", "Canada")
    assert not is_provisional_form("country", "Australia")
    assert is_provisional_form("malware", "Royal")
    assert not is_provisional_form("vendor", "Royal")
