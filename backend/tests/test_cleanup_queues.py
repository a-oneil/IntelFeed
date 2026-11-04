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
from sqlalchemy import func, select, update

from app.intelligence.link_validation_apply import LinkRow, log_reclassification
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
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


async def test_review_apply_and_dismiss_act_on_what_the_filters_show(client, admin_headers, db_session, test_feed):
    malware, tool, _entries_ = await _seed_unlinks(db_session, test_feed)
    mid, tid = malware.id, tool.id
    await db_session.commit()

    rows = (
        await client.get(
            f"/api/admin/hygiene/feed?pending=true&entity_type=malware&entity_id={mid}", headers=admin_headers
        )
    ).json()["rows"]
    assert len(rows) == 3
    # Keep one article's link: the dismissal is remembered for that article.
    source, _, log_id = rows[0]["id"].partition(":")
    assert (await client.delete(f"/api/admin/hygiene/feed/{source}/{log_id}", headers=admin_headers)).status_code == 204
    from app.services.proposal_dismissals import dismissed_verdicts

    kept_entry = uuid.UUID(rows[0]["payload"]["entry_id"])
    assert ("adjudication_unlink", "malware", mid) in await dismissed_verdicts(db_session, kept_entry)

    # Apply under a filter that shows only the link log's removals: the tool's
    # unlink (maintenance log) is outside it and stays pending.
    resp = await client.post(
        "/api/admin/hygiene/review-groups/apply",
        json={
            "action": "shadow_remove",
            "items": [
                {"entity_type": "malware", "entity_id": str(mid)},
                {"entity_type": "tool", "entity_id": str(tid)},
            ],
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"applied": 2, "skipped": 0, "failed": 0, "has_more": False, "unapplied": [], "errors": []}
    assert await _count(db_session, EntryMalware, EntryMalware.malware_family_id == mid) == 1
    assert await _count(db_session, EntryTool, EntryTool.tool_id == tid) == 1
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

    # Dismiss all under the tool's search clears only the tool's proposal.
    resp = await client.post("/api/admin/hygiene/review-groups/dismiss", json={"q": "python"}, headers=admin_headers)
    assert resp.json() == {"cleared_rows": 1}
    assert (await client.get("/api/admin/hygiene/review-groups", headers=admin_headers)).json()["total"] == 0
    assert await _count(db_session, EntryTool, EntryTool.tool_id == tid) == 1  # the link stays


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

    resp = await client.get("/api/admin/hygiene/review-groups?sort=count", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 4 and body["proposals"] == 10
    by_name = {g["name"]: g for g in body["groups"]}
    assert [g["name"] for g in body["groups"]][:2] == ["Everest", "Linuxish"]  # most proposals first
    assert body["facets"] == {
        "domains": {"entities": 5, "links": 4, "relationships": 1},
        "origins": {"adjudicator": 10},
    }

    ev = by_name["Everest"]
    assert ev["entity_id"] == str(everest.id) and ev["proposals"] == 5
    assert {k["action"]: k["count"] for k in ev["kinds"]} == {"needs_reclassification": 4, "adjudication_reclassify": 1}
    assert ev["reclassify_to"] == [{"type": "threat_actor", "count": 4}, {"type": "tool", "count": 1}]
    # the link log's proposals are the adjudicator's, the validator's leftovers included
    assert ev["origin"] == "adjudicator" and ev["domains"] == ["entities"]

    lx = by_name["Linuxish"]
    assert lx["kinds"] == [{"action": "shadow_remove", "count": 3}] and lx["linked"] == 3
    assert lx["matched_names"] == ["Linuxish"] and lx["reason"] == "the OS, not malware"
    assert lx["sample_entry_id"] and lx["domains"] == ["links"]

    py = next(g for g in body["groups"] if g["entity_id"] == str(tool.id))
    assert py["kinds"] == [{"action": "adjudication_unlink", "count": 1}] and py["matched_names"] == ["python3"]

    edge = next(g for g in body["groups"] if g["entity_type"] == "relationship")
    assert edge["entity_id"] == str(edge_id) and edge["subject"] == "Demote: Everest uses Linuxish"
    assert edge["name"] == "Everest uses Linuxish"  # an edge group is named by its claim
    assert edge["row_ids"] == []  # a pseudo type is never assumed gone

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
    scans = (await client.get("/api/admin/hygiene/review-groups?origin=scan", headers=admin_headers)).json()
    assert scans["total"] == 0 and scans["facets"]["origins"] == {"adjudicator": 10}
    # The default order is newest first: a proposal filed later leads.
    from datetime import UTC, datetime, timedelta

    await db_session.execute(
        update(EntityMaintenanceLog)
        .where(EntityMaintenanceLog.action == "adjudication_edge_demote")
        .values(created_at=datetime.now(UTC) + timedelta(hours=1))
    )
    await db_session.commit()
    newest = (await client.get("/api/admin/hygiene/review-groups", headers=admin_headers)).json()
    assert newest["groups"][0]["name"] == "Everest uses Linuxish"

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
    assert resp.json() == {"cleared_rows": 9}
    body = (await client.get("/api/admin/hygiene/review-groups", headers=admin_headers)).json()
    assert [g["kinds"][0]["action"] for g in body["groups"]] == ["adjudication_unlink"]
    # Links untouched, the type change won't be proposed again.
    assert await _count(db_session, EntryMalware, EntryMalware.malware_family_id == linuxish.id) == 3
    from app.services.proposal_dismissals import reclassify_dismissed

    assert await reclassify_dismissed(db_session, "malware", everest.id) is True


async def _seed_one_stuck_one_prunable(db_session, feed):
    """Two orphan-prune proposals: the older one's tool has a link again (its
    apply finds nothing to do), the newer one's is a real orphan."""
    from datetime import UTC, datetime, timedelta

    [entry] = await _entries(db_session, feed, 1)
    linked = Tool(name="Rclone", article_count=1)
    orphan = Tool(name="Ghost Tool", article_count=0)
    db_session.add_all([linked, orphan])
    await db_session.flush()
    db_session.add(EntryTool(entry_id=entry.id, tool_id=linked.id, confidence="high", source="ai"))
    now = datetime.now(UTC)
    for tool, at in ((linked, now - timedelta(hours=2)), (orphan, now)):
        db_session.add(
            EntityMaintenanceLog(
                entity_type="tool",
                entity_id=tool.id,
                action="orphan_prune",
                mode="shadow",
                before={"entity": {"name": tool.name}},
                after={},
                reasoning="no articles",
                applied=False,
                created_at=at,
            )
        )
    await db_session.flush()
    return linked, orphan


async def test_review_apply_never_retries_a_row_it_already_tried(client, admin_headers, db_session, test_feed):
    linked, orphan = await _seed_one_stuck_one_prunable(db_session, test_feed)
    orphan_id = orphan.id
    await db_session.commit()

    body = {"action": "orphan_prune", "limit": 1}
    first = (await client.post("/api/admin/hygiene/review-groups/apply", json=body, headers=admin_headers)).json()
    assert (first["applied"], first["skipped"], first["has_more"]) == (0, 1, True)
    [stuck] = first["unapplied"]
    assert stuck.startswith("entity_maintenance:")

    second = (
        await client.post(
            "/api/admin/hygiene/review-groups/apply", json={**body, "exclude": [stuck]}, headers=admin_headers
        )
    ).json()
    assert (second["applied"], second["has_more"], second["unapplied"]) == (1, False, [])
    db_session.expire_all()
    assert await _count(db_session, Tool, Tool.id == orphan_id) == 0

    third = (
        await client.post(
            "/api/admin/hygiene/review-groups/apply", json={**body, "exclude": [stuck]}, headers=admin_headers
        )
    ).json()
    assert (third["applied"], third["skipped"], third["has_more"]) == (0, 0, False)


async def test_apply_all_job_tries_each_row_once(db_session, test_feed, monkeypatch):
    from contextlib import asynccontextmanager

    from app.services import proposal_apply as svc
    from app.workers import proposal_apply_tasks as tasks

    await _seed_one_stuck_one_prunable(db_session, test_feed)

    @asynccontextmanager
    async def fake_session():
        yield db_session

    async def no_progress(job_id):
        return None

    async def flush_only():
        await db_session.flush()

    written: list[dict] = []
    monkeypatch.setattr(tasks, "worker_session", fake_session)
    monkeypatch.setattr(svc, "read_progress", no_progress)
    monkeypatch.setattr(svc, "write_progress_sync", lambda p: written.append(dict(p)))
    monkeypatch.setattr(db_session, "commit", flush_only)

    out = await tasks._bulk_apply("job1", {"action": "orphan_prune"}, limit=None)
    assert out == {"status": "done", "processed": 2, "applied": 1, "skipped": 1, "error_count": 0}


async def test_dismiss_all_works_through_the_queue_in_chunks(client, admin_headers, db_session, test_feed, monkeypatch):
    import app.api.hygiene as hygiene
    from app.models.proposal_dismissal import KIND_VERDICT, ProposalDismissal

    monkeypatch.setattr(hygiene, "_GROUPS_PER_CHUNK", 1)
    malware, tool, _entries_ = await _seed_unlinks(db_session, test_feed)
    await db_session.commit()
    resp = await client.post("/api/admin/hygiene/review-groups/dismiss", json={}, headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["cleared_rows"] == 4
    assert await _count(db_session, EntityLinkValidationLog, EntityLinkValidationLog.action == "shadow_remove") == 0
    # every article's verdict is remembered, in one insert per chunk
    assert await _count(db_session, ProposalDismissal, ProposalDismissal.kind == KIND_VERDICT) == 4


async def test_row_dismiss_takes_only_a_proposal(client, admin_headers, db_session):
    tool = Tool(name="Rclone", article_count=3)
    db_session.add(tool)
    await db_session.flush()
    audit = EntityMaintenanceLog(
        entity_type="tool",
        entity_id=tool.id,
        action="ai_enrich_filled",
        mode="apply",
        before={},
        after={},
        reasoning="",
        applied=False,
    )
    db_session.add(audit)
    await db_session.commit()
    resp = await client.delete(f"/api/admin/hygiene/feed/entity_maintenance/{audit.id}", headers=admin_headers)
    assert resp.status_code == 400
    assert await _count(db_session, EntityMaintenanceLog, EntityMaintenanceLog.id == audit.id) == 1
