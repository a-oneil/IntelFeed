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
from sqlalchemy import delete, func, select

from app.intelligence.link_validation_apply import LinkRow, log_reclassification
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.pending_autolink import PendingAutolinkMatch
from app.models.threat_actor import ThreatActor
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


async def test_reclassify_groups_drop_deleted_entities(client, admin_headers, db_session, test_feed):
    malware = MalwareFamily(name="Everest")
    db_session.add(malware)
    await db_session.flush()
    await _seed_reclassify(db_session, test_feed, malware)
    mid = malware.id
    await db_session.delete(malware)
    await db_session.commit()

    resp = await client.get("/api/admin/hygiene/reclassify-groups", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["total"] == 0
    assert await _pending_reclassify_rows(db_session, mid) == 0


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


async def test_names_that_differ_only_in_digits_are_not_duplicates(client, admin_headers, db_session):
    # Storm-3068 / Storm-3069 are two tracked clusters; a version bump is a variant
    db_session.add_all(
        [
            ThreatActor(name="Storm-3068", created_via="ai_extraction"),
            ThreatActor(name="Storm-3069", created_via="ai_extraction"),
            Tool(name="KillSecurity 2.0", created_via="ai_extraction"),
            Tool(name="KillSecurity 3.0", created_via="ai_extraction"),
        ]
    )
    await db_session.commit()
    stats = (await client.get("/api/engine/extraction/stats?window=all", headers=admin_headers)).json()
    assert stats["likely_duplicates"] == 0


async def test_not_duplicate_drops_the_pair(client, admin_headers, db_session):
    a = Tool(name="Cobalt Strike", created_via="ai_extraction")
    b = Tool(name="CobaltStrike", created_via="ai_extraction")
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


async def test_unlink_groups_drop_deleted_entities(client, admin_headers, db_session, test_feed):
    malware, tool, _entries_ = await _seed_unlinks(db_session, test_feed)
    mid, tid = malware.id, tool.id
    await db_session.execute(delete(EntryMalware).where(EntryMalware.malware_family_id == mid))
    await db_session.execute(delete(EntryTool).where(EntryTool.tool_id == tid))
    await db_session.delete(malware)
    await db_session.delete(tool)
    await db_session.commit()

    body = (await client.get("/api/admin/hygiene/unlink-groups", headers=admin_headers)).json()
    assert body["total"] == 0 and body["proposals"] == 0
    assert await _count(db_session, EntityLinkValidationLog, EntityLinkValidationLog.entity_id == mid) == 0
    assert await _count(db_session, EntityMaintenanceLog, EntityMaintenanceLog.entity_id == tid) == 0


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


# ---------------------------------------------------------------------------
# The Review tab's one queue: every pending proposal folded per entity
# ---------------------------------------------------------------------------


async def _seed_everything(db_session, feed):
    everest = MalwareFamily(name="Everest")
    db_session.add(everest)
    await db_session.flush()
    entries = await _seed_reclassify(db_session, feed, everest)
    linuxish, tool, _ = await _seed_unlinks(db_session, feed)
    edge_id = uuid.uuid4()
    db_session.add(
        EntityMaintenanceLog(
            entity_type="relationship",
            entity_id=edge_id,
            action="adjudication_edge_demote",
            mode="shadow",
            before={"entry_id": str(entries[0].id), "claim": "Everest uses Linuxish"},
            after={"reason": "never asserted", "confidence": "high"},
            applied=False,
        )
    )
    await db_session.flush()
    return everest, linuxish, tool, edge_id


async def test_review_groups_fold_every_kind_per_entity(client, admin_headers, db_session, test_feed):
    everest, linuxish, tool, edge_id = await _seed_everything(db_session, test_feed)
    await db_session.commit()

    resp = await client.get("/api/admin/hygiene/review-groups", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 4 and body["proposals"] == 10
    by_name = {g["name"]: g for g in body["groups"]}
    assert [g["name"] for g in body["groups"]][:2] == ["Everest", "Linuxish"]  # most proposals first

    ev = by_name["Everest"]
    assert ev["entity_id"] == str(everest.id) and ev["exists"] is True and ev["proposals"] == 5
    assert {k["action"]: k["count"] for k in ev["kinds"]} == {"needs_reclassification": 4, "adjudication_reclassify": 1}
    assert ev["reclassify_to"] == [{"type": "threat_actor", "count": 4}, {"type": "tool", "count": 1}]
    assert ev["origin"] == "mixed" and ev["domains"] == ["entities"]

    lx = by_name["Linuxish"]
    assert lx["kinds"] == [{"action": "shadow_remove", "count": 3}] and lx["linked"] == 3
    assert lx["matched_names"] == ["Linuxish"] and lx["reason"] == "the OS, not malware"
    assert lx["sample_entry_id"] and lx["domains"] == ["links"]

    py = next(g for g in body["groups"] if g["entity_id"] == str(tool.id))
    assert py["kinds"] == [{"action": "adjudication_unlink", "count": 1}] and py["matched_names"] == ["python3"]

    edge = next(g for g in body["groups"] if g["entity_type"] == "relationship")
    assert edge["entity_id"] == str(edge_id) and edge["subject"] == "Demote: Everest uses Linuxish"
    assert edge["name"] == "Everest uses Linuxish"  # an edge group is named by its claim
    assert edge["exists"] is True and edge["row_ids"] == []  # a pseudo type is never assumed gone

    # Facets narrow the same way the flat feed does.
    links = (await client.get("/api/admin/hygiene/review-groups?domain=links", headers=admin_headers)).json()
    assert {g["name"] for g in links["groups"]} == {"Linuxish", py["name"]}
    recl = (
        await client.get(
            "/api/admin/hygiene/review-groups?action=needs_reclassification,adjudication_reclassify",
            headers=admin_headers,
        )
    ).json()
    assert [g["name"] for g in recl["groups"]] == ["Everest"]
    found = (await client.get("/api/admin/hygiene/review-groups?q=linux", headers=admin_headers)).json()
    # the edge's claim names Linuxish too, so a name search finds its proposals
    assert [g["name"] for g in found["groups"]] == ["Linuxish", "Everest uses Linuxish"]
    adj = (await client.get("/api/admin/hygiene/review-groups?origin=adjudicator", headers=admin_headers)).json()
    assert {g["name"] for g in adj["groups"]} == {"Everest", py["name"], edge["name"]}
    assert next(g for g in adj["groups"] if g["name"] == "Everest")["proposals"] == 1

    # The expand: one entity's rows from the flat feed.
    rows = (
        await client.get(
            f"/api/admin/hygiene/feed?pending=true&entity_type=malware&entity_id={everest.id}", headers=admin_headers
        )
    ).json()["rows"]
    assert len(rows) == 5 and all(r["entity_id"] == str(everest.id) for r in rows)


async def test_review_groups_drop_deleted_entities(client, admin_headers, db_session, test_feed):
    everest, _lx, _tool, _edge = await _seed_everything(db_session, test_feed)
    eid = everest.id
    await db_session.delete(everest)
    await db_session.commit()

    body = (await client.get("/api/admin/hygiene/review-groups", headers=admin_headers)).json()
    assert "Everest" not in {g["name"] for g in body["groups"]} and body["total"] == 3
    # Hidden at once; the rows go with the nightly prune, not inside a GET.
    assert await _pending_reclassify_rows(db_session, eid) == 5
    from app.services.proposal_dismissals import purge_gone_entity_proposals

    assert await purge_gone_entity_proposals(db_session) == 5
    assert await _pending_reclassify_rows(db_session, eid) == 0
    assert await purge_gone_entity_proposals(db_session) == 0  # live entities' rows are untouched


async def test_review_groups_dismiss_settles_the_entity_and_sticks(client, admin_headers, db_session, test_feed):
    everest, linuxish, _tool, _edge = await _seed_everything(db_session, test_feed)
    body0 = (await client.get("/api/admin/hygiene/review-groups", headers=admin_headers)).json()
    edge = next(g for g in body0["groups"] if g["entity_type"] == "relationship")
    await db_session.commit()

    resp = await client.post(
        "/api/admin/hygiene/review-groups/dismiss",
        json={
            "items": [
                {"entity_type": "malware", "entity_id": str(everest.id)},
                {"entity_type": "malware", "entity_id": str(linuxish.id)},
                {"entity_type": "relationship", "entity_id": edge["entity_id"]},
            ]
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"entities": 3, "cleared_rows": 9}
    body = (await client.get("/api/admin/hygiene/review-groups", headers=admin_headers)).json()
    assert [g["kinds"][0]["action"] for g in body["groups"]] == ["adjudication_unlink"]
    # Links untouched, the type change won't be proposed again.
    assert await _count(db_session, EntryMalware, EntryMalware.malware_family_id == linuxish.id) == 3
    from app.services.proposal_dismissals import reclassify_dismissed

    assert await reclassify_dismissed(db_session, "malware", everest.id) is True
