"""Registry tools that work the ledger: promote / update / deny, the
actor→infrastructure pivot, and the filtered export."""

import json
import uuid

import pytest

from app.intelligence.observables import get_or_create_observable, record_sighting
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.observable import Observable
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.tools import ADMIN_TOOLS, MUTATING_TOOLS, execute_tool


async def _entry(db):
    feed = Feed(title="t", url=f"https://t.example/{uuid.uuid4()}", feed_type="rss")
    db.add(feed)
    await db.flush()
    e = Entry(feed_id=feed.id, guid=str(uuid.uuid4()), title="e", content_text="x")
    db.add(e)
    await db.flush()
    return e


def test_observable_tools_are_classified():
    assert {"promote_observable", "update_observable", "deny_observable"} <= MUTATING_TOOLS
    assert "deny_observable" in ADMIN_TOOLS
    assert "get_entity_infrastructure" not in MUTATING_TOOLS
    assert "export_observables" not in MUTATING_TOOLS


@pytest.mark.asyncio
async def test_promote_update_deny_round_trip(db_session, test_user):
    from sqlalchemy import select

    entry = await _entry(db_session)
    entry.observable_candidates = [
        {
            "kind": "domain",
            "value": "c2.example-bad.net",
            "origin": "ai",
            "role": "c2",
            "evidence": "The implant beacons to c2[.]example-bad[.]net",
            "confidence": "high",
            "was_defanged": True,
            "surface_form": "c2[.]example-bad[.]net",
        }
    ]
    await db_session.commit()

    out = json.loads(
        await execute_tool(
            "promote_observable",
            {"entry_id": str(entry.id), "kind": "domain", "value": "c2[.]example-bad[.]net"},
            db_session,
            test_user.id,
        )
    )
    assert out["status"] == "promoted", out
    assert out["observable"]["role"] == "c2" and out["observable"]["evidence"].startswith("The implant")
    assert out["observable"]["report_count"] == 1
    oid = out["observable"]["id"]

    junk = json.loads(
        await execute_tool(
            "promote_observable",
            {"entry_id": str(entry.id), "kind": "cmdline", "value": "whoami /priv"},
            db_session,
            test_user.id,
        )
    )
    assert "error" in junk and "plausible" in junk["error"]

    upd = json.loads(
        await execute_tool(
            "update_observable",
            {"observable_id": oid, "role": "delivery", "label": "stager host", "confidence_pinned": True},
            db_session,
            test_user.id,
        )
    )
    assert upd["observable"]["role"] == "delivery" and upd["observable"]["confidence_pinned"] is True

    den = json.loads(
        await execute_tool(
            "deny_observable",
            {"kind": "domain", "value": "benign.example-corp.com", "reason": "our own"},
            db_session,
            test_user.id,
        )
    )
    assert den["status"] == "denied"
    row = (
        await db_session.execute(select(Observable).where(Observable.value == "benign.example-corp.com"))
    ).scalar_one()
    assert row.is_denied and row.description == "our own"
    # A denied value refuses every later door.
    assert await get_or_create_observable(db_session, "domain", "benign.example-corp.com", via="ai_extraction") is None


@pytest.mark.asyncio
async def test_infrastructure_and_export_tools(db_session, test_user):
    entry = await _entry(db_session)
    actor = ThreatActor(name=f"UAT-{uuid.uuid4().hex[:6]}")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id, confidence="high", source="ai"))
    ip = await get_or_create_observable(db_session, "ipv4", "45.33.32.156", via="ai_extraction", role="c2")
    await record_sighting(db_session, entry.id, ip, source="ai")
    vpn = await get_or_create_observable(db_session, "ipv4", "185.199.108.153", via="ioc_list", infra_tag="vpn")
    await record_sighting(db_session, entry.id, vpn, source="feed")
    await db_session.commit()

    infra = json.loads(
        await execute_tool(
            "get_entity_infrastructure",
            {"entity_type": "threat_actor", "entity_id": str(actor.id)},
            db_session,
            test_user.id,
        )
    )
    assert [r["value"] for r in infra["reported_alongside"]] == ["45.33.32.156"]

    edl = json.loads(
        await execute_tool("export_observables", {"format": "edl", "kind": "ipv4"}, db_session, test_user.id)
    )
    assert edl["lines"] == ["45.33.32.156"]  # the VPN exit is dual-use and stays out by default
    both = json.loads(
        await execute_tool(
            "export_observables",
            {"format": "csv", "kind": "ipv4", "include_infra_tagged": True},
            db_session,
            test_user.id,
        )
    )
    assert both["count"] == 2 and both["csv"].startswith("kind,value,role")
    search = json.loads(
        await execute_tool(
            "search_observables", {"kind": "ipv4", "infra_tag": "none", "min_reports": 1}, db_session, test_user.id
        )
    )
    assert [o["value"] for o in search["observables"]] == ["45.33.32.156"]
    one = json.loads(await execute_tool("get_observable", {"observable": "45.33.32.156"}, db_session, test_user.id))
    assert one["report_count"] == 1 and one["claimed_by"] == []
