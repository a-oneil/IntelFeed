"""The Review queue closes what can no longer be decided, and takes decisions in bulk.

- Deleting, merging away or reclassifying an entity closes its pending
  proposals (both logs) and the proposals that point at it.
- The pending feed and the counts leave out proposals about a gone entity,
  like the Review list does.
- An apply whose outcome is already reached closes the proposal.
- A vendor link to a gone vendor is not offered, and is purged.
- POST /admin/hygiene/decisions settles a batch, duplicates included.
- Feed rows carry a bounded article snippet.
- The adjudicator's alias trims count as adjudicator rows.
- Held autolink matches follow a converted or merged entity, and go with a
  deleted one.
"""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select

from app.api.hygiene import (
    FEED_CONTEXT_MAX,
    FeedRow,
    ProposalDecision,
    _claim_needles,
    _context_target,
    _maint_origin,
    _parse_decision,
    _snippet_around,
)
from app.intelligence.autolink_reconcile import promote_held, reconcile_pending_autolinks
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.pending_autolink import PendingAutolinkMatch
from app.models.product import Product
from app.models.tool import EntryTool, Tool
from app.models.vendor import Vendor
from app.services.proposal_apply import outcome_is_moot

# ---------------------------------------------------------------------------
# DB-free
# ---------------------------------------------------------------------------


def test_claim_needles_pull_names_out_of_an_edge_claim():
    assert _claim_needles("FIN7 uses AsyncRAT") == ["FIN7", "AsyncRAT"]
    assert _claim_needles("Earth Lusca exploits CVE-2024-1234") == ["Earth Lusca", "CVE-2024-1234"]


def test_snippet_is_bounded_and_centred_on_the_match():
    text = "x " * 400 + "Qilin hit a hospital. " + "y " * 400
    snip = _snippet_around([text], ["qilin"])
    assert "Qilin hit a hospital" in snip and len(snip) <= FEED_CONTEXT_MAX
    assert snip.startswith("…") and snip.endswith("…")
    assert _snippet_around(["nothing here"], ["Qilin"]) is None


def _row(source, payload, entity_name=None):
    return FeedRow(
        id=f"{source}:{uuid.uuid4()}",
        source=source,
        action="shadow_remove",
        when=datetime.now(UTC),
        mode="shadow",
        applied=False,
        entity_type="malware",
        entity_id=uuid.uuid4(),
        entity_name=entity_name,
        subject=None,
        reason=None,
        payload=payload,
        actions=[],
    )


def test_context_target_reads_both_logs():
    entry = uuid.uuid4()
    link = _row(
        "link_validator",
        {"entry_id": str(entry), "original_matched_names": ["Linux"], "original_paragraph_indices": [3]},
        entity_name="Linuxish",
    )
    assert _context_target(link) == (entry, ["Linux", "Linuxish"], [3])
    edge = _row("entity_maintenance", {"before": {"entry_id": str(entry), "claim": "FIN7 uses AsyncRAT"}, "after": {}})
    assert _context_target(edge) == (entry, ["FIN7", "AsyncRAT"], [])
    assert _context_target(_row("entity_maintenance", {"before": {}, "after": {}})) is None


def test_parse_decision():
    lid = uuid.uuid4()
    ok = _parse_decision(0, ProposalDecision(id=f"entity_maintenance:{lid}", decision="reclassify:tool"))
    assert ok.verb == "reclassify" and ok.target_type == "tool" and ok.log_id == lid
    assert _parse_decision(0, ProposalDecision(id=f"link_validator:{lid}", decision="apply")).verb == "apply"
    for bad in (
        ProposalDecision(id=f"nope:{lid}", decision="apply"),
        ProposalDecision(id="link_validator:not-a-uuid", decision="apply"),
        ProposalDecision(id=f"link_validator:{lid}", decision="reclassify:cve"),
        ProposalDecision(id=f"link_validator:{lid}", decision="maybe"),
    ):
        assert _parse_decision(0, bad).status == "error"


def test_moot_outcomes():
    unlink = EntityMaintenanceLog(action="adjudication_unlink")
    veto = EntityMaintenanceLog(action="adjudication_veto")
    demote = EntityMaintenanceLog(action="adjudication_edge_demote")
    assert outcome_is_moot(unlink, {"applied": False, "reason": "entry gone"})
    assert outcome_is_moot(demote, {"applied": False, "reason": "edge gone or analyst-rejected"})
    assert not outcome_is_moot(veto, {"applied": False, "reason": "entry gone"})  # the entity may still need to go
    assert not outcome_is_moot(unlink, {"applied": True})
    assert not outcome_is_moot(unlink, {"applied": False, "reason": "assessment flags are informational"})


def test_adjudicator_alias_trims_have_adjudicator_origin():
    assert _maint_origin("alias_collision", {"kind": "adjudicator", "bad_alias": "INC"}) == "adjudicator"
    assert _maint_origin("alias_collision", {"kind": "case_duplicate"}) == "scan"
    assert _maint_origin("adjudication_unlink", {}) == "adjudicator"


# ---------------------------------------------------------------------------
# DB-backed
# ---------------------------------------------------------------------------


async def _entry(db, feed, text="Everest ransomware hit a hospital.\n\nLinux servers were spared."):
    e = Entry(
        feed_id=feed.id,
        title="t",
        url=f"https://example.com/{uuid.uuid4()}",
        guid=str(uuid.uuid4()),
        content_text=text,
    )
    db.add(e)
    await db.flush()
    return e


def _unlink(entity_type, entity_id, entry, name="Everest"):
    return EntityMaintenanceLog(
        entity_type=entity_type,
        entity_id=entity_id,
        action="adjudication_unlink",
        mode="shadow",
        before={"entry_id": str(entry.id), "entity": {"name": name}},
        after={"reason": "not about it"},
        applied=False,
    )


async def _pending(db, entity_id) -> int:
    a = (
        await db.execute(
            select(func.count())
            .select_from(EntityLinkValidationLog)
            .where(
                EntityLinkValidationLog.entity_id == entity_id,
                EntityLinkValidationLog.action.in_(["shadow_remove", "needs_reclassification"]),
            )
        )
    ).scalar_one()
    b = (
        await db.execute(
            select(func.count())
            .select_from(EntityMaintenanceLog)
            .where(EntityMaintenanceLog.entity_id == entity_id, EntityMaintenanceLog.applied.is_(False))
        )
    ).scalar_one()
    return a + b


@pytest.mark.asyncio
async def test_deleting_an_entity_closes_its_proposals(client, admin_headers, db_session, test_feed):
    everest = MalwareFamily(name="Everest")
    db_session.add(everest)
    await db_session.flush()
    e = await _entry(db_session, test_feed)
    db_session.add(_unlink("malware", everest.id, e))
    db_session.add(
        EntityLinkValidationLog(
            entry_id=e.id,
            entity_type="malware",
            entity_id=everest.id,
            entity_name_snapshot="Everest",
            action="shadow_remove",
            reason="r",
        )
    )
    await db_session.commit()
    assert await _pending(db_session, everest.id) == 2

    resp = await client.delete(f"/api/entities/malware/{everest.id}", headers=admin_headers)
    assert resp.status_code == 204, resp.text
    assert await _pending(db_session, everest.id) == 0


@pytest.mark.asyncio
async def test_merge_moves_merge_proposals_to_the_keeper(client, admin_headers, db_session, test_feed):
    keeper, loser, other = MalwareFamily(name="NotPetya"), MalwareFamily(name="petrwrap"), MalwareFamily(name="nyetya")
    db_session.add_all([keeper, loser, other])
    await db_session.flush()
    e = await _entry(db_session, test_feed)
    db_session.add(_unlink("malware", loser.id, e, "petrwrap"))
    merge = EntityMaintenanceLog(
        entity_type="malware",
        entity_id=other.id,
        action="adjudication_merge",
        mode="shadow",
        before={"entity": {"name": "nyetya"}},
        after={"target_id": str(loser.id), "target_type": "malware", "merge_into": "petrwrap"},
        applied=False,
    )
    db_session.add(merge)
    await db_session.commit()

    resp = await client.post(
        "/api/entities/malware/merge",
        json={"keeper_id": str(keeper.id), "merge_ids": [str(loser.id)]},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert await _pending(db_session, loser.id) == 0
    await db_session.refresh(merge)
    assert merge.after["target_id"] == str(keeper.id) and merge.after["merge_into"] == "NotPetya"


def _held(entity_type, entity_id, entry, name):
    return PendingAutolinkMatch(
        entry_id=entry.id, entity_type=entity_type, entity_id=entity_id, canonical_name=name, matched_names=[name]
    )


async def _held_rows(db, entry_id):
    # Takes the id, not the Entry: the tests expire the session first, and an
    # expired attribute would lazy-load outside the greenlet (MissingGreenlet).
    return (
        (await db.execute(select(PendingAutolinkMatch).where(PendingAutolinkMatch.entry_id == entry_id)))
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_converting_an_entity_moves_its_held_matches(client, admin_headers, db_session, test_feed):
    blackwood = MalwareFamily(name="Blackwood")
    db_session.add(blackwood)
    await db_session.flush()
    e = await _entry(db_session, test_feed, "SHELBYC2 also deployed a tunneling utility called Blackwood.")
    db_session.add(_held("malware", blackwood.id, e, "Blackwood"))
    entry_id = e.id
    await db_session.commit()

    resp = await client.post(
        "/api/entities/convert",
        json={"entity_id": str(blackwood.id), "target_type": "tool"},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    [row] = await _held_rows(db_session, entry_id)
    assert (row.entity_type, str(row.entity_id), row.resolved_at) == ("tool", resp.json()["id"], None)

    # The moved row still links, now to the converted entity.
    await promote_held(db_session, row)
    await db_session.flush()
    tool_id = uuid.UUID(resp.json()["id"])
    linked = (await db_session.execute(select(EntryTool).where(EntryTool.entry_id == entry_id))).scalars().all()
    assert [j.tool_id for j in linked] == [tool_id]


@pytest.mark.asyncio
async def test_merging_into_a_keeper_with_its_own_held_match_drops_the_copy(
    client, admin_headers, db_session, test_feed
):
    keeper, loser = MalwareFamily(name="Royal"), MalwareFamily(name="Royal Locker")
    db_session.add_all([keeper, loser])
    await db_session.flush()
    e = await _entry(db_session, test_feed, "Royal hit a hospital.")
    db_session.add_all([_held("malware", keeper.id, e, "Royal"), _held("malware", loser.id, e, "Royal")])
    entry_id, keeper_id = e.id, keeper.id
    await db_session.commit()

    resp = await client.post(
        "/api/entities/malware/merge",
        json={"keeper_id": str(keeper.id), "merge_ids": [str(loser.id)]},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    assert [r.entity_id for r in await _held_rows(db_session, entry_id)] == [keeper_id]


@pytest.mark.asyncio
async def test_deleting_an_entity_deletes_its_held_matches(client, admin_headers, db_session, test_feed):
    jaguar = MalwareFamily(name="Jaguar")
    db_session.add(jaguar)
    await db_session.flush()
    e = await _entry(db_session, test_feed, "Jaguar Land Rover lost a month of production.")
    db_session.add(_held("malware", jaguar.id, e, "Jaguar"))
    entry_id = e.id
    await db_session.commit()

    resp = await client.delete(f"/api/entities/malware/{jaguar.id}", headers=admin_headers)
    assert resp.status_code == 204, resp.text
    db_session.expire_all()
    assert await _held_rows(db_session, entry_id) == []


@pytest.mark.asyncio
async def test_settling_a_held_match_whose_entity_is_gone_closes_it(db_session, test_feed):
    # Rows left behind before moves existed point at an id that no longer exists.
    e = await _entry(db_session, test_feed)
    row = _held("malware", uuid.uuid4(), e, "Blackwood")
    db_session.add(row)
    await db_session.flush()

    counts = await reconcile_pending_autolinks(db_session, e.id, {"malware": [{"name": "Blackwood"}]})
    assert counts == {"promoted": 0, "rejected": 1}
    assert row.resolution == "rejected"
    # nothing left for the adjudicator to check
    assert row.reviewed_at is not None


@pytest.mark.asyncio
async def test_feed_count_agrees_with_review_groups(client, admin_headers, db_session, test_feed):
    gone_id = uuid.uuid4()  # an entity deleted behind the queue's back (no row)
    live = MalwareFamily(name="Everest")
    db_session.add(live)
    await db_session.flush()
    e = await _entry(db_session, test_feed)
    db_session.add_all([_unlink("malware", gone_id, e, "Ghost"), _unlink("malware", live.id, e)])
    await db_session.commit()

    feed = (await client.get("/api/admin/hygiene/feed?pending=true&context=true", headers=admin_headers)).json()["rows"]
    groups = (await client.get("/api/admin/hygiene/review-groups", headers=admin_headers)).json()
    stats = (await client.get("/api/admin/hygiene/stats", headers=admin_headers)).json()
    assert [r["entity_id"] for r in feed] == [str(live.id)]
    assert groups["proposals"] == 1 == stats["pending_total"]
    # The snippet comes with the row when asked for, and only then.
    assert "Everest ransomware" in feed[0]["context"]
    plain = (await client.get("/api/admin/hygiene/feed?pending=true", headers=admin_headers)).json()["rows"]
    assert plain[0]["context"] is None


@pytest.mark.asyncio
async def test_moot_apply_closes_the_proposal(client, admin_headers, db_session, test_feed):
    edge_id = uuid.uuid4()  # no such relationship: already gone
    e = await _entry(db_session, test_feed)
    row = EntityMaintenanceLog(
        entity_type="relationship",
        entity_id=edge_id,
        action="adjudication_edge_demote",
        mode="shadow",
        before={"entry_id": str(e.id), "claim": "Everest uses Linux"},
        after={"reason": "never asserted"},
        applied=False,
    )
    db_session.add(row)
    await db_session.commit()
    rid = row.id

    resp = await client.post(f"/api/admin/hygiene/adjudication/{rid}/apply", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["applied"] is False and body["resolved"] is True
    db_session.expire_all()
    assert await db_session.get(EntityMaintenanceLog, rid) is None


@pytest.mark.asyncio
async def test_vendor_links_to_gone_vendors_are_hidden_and_purged(client, admin_headers, db_session):
    product = Product(name="Windows Server")
    db_session.add(product)
    await db_session.flush()
    db_session.add(
        EntityMaintenanceLog(
            entity_type="product",
            entity_id=product.id,
            action="vendor_autolink",
            mode="shadow",
            before={"entity": {"id": str(product.id), "name": "Windows Server"}},
            after={"proposed_vendor_id": str(uuid.uuid4()), "proposed_vendor_name": "Windows"},
            applied=False,
        )
    )
    await db_session.commit()

    stats = (await client.get("/api/admin/hygiene/stats", headers=admin_headers)).json()
    assert stats["vendor_autolinks_proposed"] == 0
    groups = (await client.get("/api/admin/hygiene/review-groups", headers=admin_headers)).json()
    assert groups["total"] == 0

    from app.services.proposal_dismissals import purge_gone_entity_proposals

    assert await purge_gone_entity_proposals(db_session) == 1


@pytest.mark.asyncio
async def test_vendor_scan_skips_vendors_that_are_products(client, admin_headers, db_session):
    db_session.add_all([Vendor(name="Windows"), Product(name="Windows"), Product(name="Windows Server")])
    await db_session.commit()
    resp = await client.post("/api/admin/hygiene/scan-vendor-autolink", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["proposed"] == 0


@pytest.mark.asyncio
async def test_bulk_decisions_settle_duplicates(client, admin_headers, db_session, test_feed):
    mimi = Tool(name="Everest")
    linuxish = MalwareFamily(name="Linuxish")
    db_session.add_all([mimi, linuxish])
    await db_session.flush()
    entries = [await _entry(db_session, test_feed) for _ in range(3)]
    copies = []
    for e in entries:
        r = EntityLinkValidationLog(
            entry_id=e.id,
            entity_type="tool",
            entity_id=mimi.id,
            entity_name_snapshot="Everest",
            action="needs_reclassification",
            suggested_entity_type="malware",
            reason="ransomware",
        )
        db_session.add(r)
        copies.append(r)
    db_session.add(EntryMalware(entry_id=entries[0].id, malware_family_id=linuxish.id, matched_names=["Linuxish"]))
    unlink = EntityLinkValidationLog(
        entry_id=entries[0].id,
        entity_type="malware",
        entity_id=linuxish.id,
        entity_name_snapshot="Linuxish",
        action="shadow_remove",
        reason="the OS",
    )
    keep = EntityLinkValidationLog(
        entry_id=entries[1].id,
        entity_type="malware",
        entity_id=linuxish.id,
        entity_name_snapshot="Linuxish",
        action="shadow_remove",
        reason="the OS",
    )
    db_session.add_all([unlink, keep])
    await db_session.commit()

    decisions = [
        {"id": f"link_validator:{copies[0].id}", "decision": "reclassify:malware"},
        {"id": f"link_validator:{copies[1].id}", "decision": "reclassify:malware"},
        {"id": f"link_validator:{copies[2].id}", "decision": "apply"},
        {"id": f"link_validator:{unlink.id}", "decision": "apply"},
        {"id": f"link_validator:{keep.id}", "decision": "dismiss"},
        {"id": f"link_validator:{uuid.uuid4()}", "decision": "apply"},
        {"id": "junk", "decision": "apply"},
    ]
    resp = await client.post("/api/admin/hygiene/decisions", json=decisions, headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    statuses = [r["status"] for r in body["results"]]
    assert statuses == ["reclassified", "settled", "settled", "applied", "dismissed", "gone", "error"]
    assert body["counts"] == {"reclassified": 1, "settled": 2, "applied": 1, "dismissed": 1, "gone": 1, "error": 1}
    assert await _pending(db_session, mimi.id) == 0 and await _pending(db_session, linuxish.id) == 0
    db_session.expire_all()
    assert (await db_session.execute(select(Tool).where(Tool.id == mimi.id))).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_decisions_are_admin_only(client, auth_headers):
    resp = await client.post(
        "/api/admin/hygiene/decisions",
        json=[{"id": f"link_validator:{uuid.uuid4()}", "decision": "apply"}],
        headers=auth_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_origin_filter_counts_adjudicator_alias_trims(client, admin_headers, db_session):
    actor = MalwareFamily(name="INC Ransom", aliases=["INC"])
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        EntityMaintenanceLog(
            entity_type="malware",
            entity_id=actor.id,
            action="alias_collision",
            mode="shadow",
            before={"entity": {"id": str(actor.id), "name": "INC Ransom"}},
            after={"kind": "adjudicator", "bad_alias": "INC", "reason": "company suffix"},
            applied=False,
        )
    )
    await db_session.commit()
    adj = (await client.get("/api/admin/hygiene/review-groups?origin=adjudicator", headers=admin_headers)).json()
    assert [g["name"] for g in adj["groups"]] == ["INC Ransom"] and adj["groups"][0]["origin"] == "adjudicator"
    scan = (await client.get("/api/admin/hygiene/review-groups?origin=scan", headers=admin_headers)).json()
    assert scan["total"] == 0


@pytest.mark.asyncio
async def test_id_scan_flags_implausible_cve_ids(client, admin_headers, db_session):
    from app.models.cve import CVE

    db_session.add_all([CVE(cve_id="CVE-2024-123459"), CVE(cve_id="CVE-2024-123459812"), CVE(cve_id="CVE-2024-01234")])
    await db_session.commit()
    resp = await client.post("/api/admin/hygiene/scan-id-hygiene", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    q = select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == "cve_malformed_id")
    rows = (await db_session.execute(q)).scalars().all()
    assert sorted(r.after["current_id"] for r in rows) == ["CVE-2024-01234", "CVE-2024-123459812"]
    assert all(r.after["proposed_id"] is None for r in rows)  # no safe fix: dismiss or delete
