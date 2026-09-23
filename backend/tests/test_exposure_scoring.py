"""Tests for My Stack exposure scoring (app/services/exposure.py)."""

import uuid

import pytest
from sqlalchemy import select

from app.models.cve import CVE, EntryCVE
from app.models.cve_affected import CVEAffected
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.product import Product
from app.models.telemetry_source import TelemetrySource
from app.models.ttp import TTP, EntryTTP
from app.models.user_entity_watch import UserEntityWatch
from app.models.vendor import Vendor
from app.services.attack_visibility import cve_attack_visibility
from app.services.exposure import (
    EXPOSURE_BASE,
    KEV_MULT,
    enrich_exposure,
    exposure_lift_subquery,
    get_user_stack,
)

THRESH = 0.1


async def _feed(db):
    feed = Feed(title="Feed", url=f"https://ex.com/{uuid.uuid4()}.xml", feed_type="rss")
    db.add(feed)
    await db.flush()
    return feed


async def _entry(db, feed, title="Entry"):
    entry = Entry(feed_id=feed.id, title=title, guid=str(uuid.uuid4()))
    db.add(entry)
    await db.flush()
    return entry


async def _cve(db, cve_id, *, is_kev=False, epss=None, exploit=None):
    cve = CVE(cve_id=cve_id, is_kev=is_kev, epss_score=epss, exploit_availability=exploit)
    db.add(cve)
    await db.flush()
    return cve


async def _link_cve(db, entry, cve):
    db.add(EntryCVE(entry_id=entry.id, cve_id=cve.id))
    await db.flush()


async def _affect(db, cve, *, vendor=None, product=None):
    db.add(
        CVEAffected(
            cve_id=cve.id,
            cpe_vendor=(vendor.name.lower() if vendor else "x"),
            cpe_product=(product.name.lower() if product else "x"),
            vendor_id=vendor.id if vendor else None,
            product_id=product.id if product else None,
        )
    )
    await db.flush()


async def _stack(db, user, entity_type, entity_id):
    db.add(UserEntityWatch(created_by=user.id, entity_type=entity_type, entity_id=entity_id, mode="stack", boost=1.0))
    await db.flush()


async def _lift_for(db, entry, vendor_ids, product_ids):
    sq = exposure_lift_subquery(vendor_ids, product_ids, THRESH)
    if sq is None:
        return None
    row = (await db.execute(select(sq.c.lift).where(sq.c.entry_id == entry.id))).first()
    return row[0] if row else None


@pytest.mark.asyncio
async def test_get_user_stack_splits_vendor_and_product(db_session, test_user):
    vendor = Vendor(name="Fortinet")
    product = Product(name="FortiOS")
    db_session.add_all([vendor, product])
    await db_session.flush()
    await _stack(db_session, test_user, "vendor", vendor.id)
    await _stack(db_session, test_user, "product", product.id)
    # a non-stack watch must be ignored
    db_session.add(
        UserEntityWatch(created_by=test_user.id, entity_type="product", entity_id=uuid.uuid4(), mode="watch")
    )
    await db_session.flush()

    vendor_ids, product_ids = await get_user_stack(db_session, test_user.id)
    assert vendor_ids == [vendor.id]
    assert product_ids == [product.id]


@pytest.mark.asyncio
async def test_kev_cve_affecting_stack_product_gets_full_lift(db_session, test_user):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    product = Product(name="FortiOS")
    db_session.add(product)
    await db_session.flush()
    cve = await _cve(db_session, "CVE-2024-21762", is_kev=True)
    await _link_cve(db_session, entry, cve)
    await _affect(db_session, cve, product=product)

    lift = await _lift_for(db_session, entry, [], [product.id])
    assert lift == pytest.approx(EXPOSURE_BASE * KEV_MULT)  # 1.5 * 2.5 = 3.75


@pytest.mark.asyncio
async def test_low_severity_cve_gets_base_lift_only(db_session, test_user):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    product = Product(name="Confluence")
    db_session.add(product)
    await db_session.flush()
    cve = await _cve(db_session, "CVE-2023-0001", is_kev=False, epss=0.01)
    await _link_cve(db_session, entry, cve)
    await _affect(db_session, cve, product=product)

    lift = await _lift_for(db_session, entry, [], [product.id])
    assert lift == pytest.approx(EXPOSURE_BASE)  # 1.5


@pytest.mark.asyncio
async def test_cve_not_in_stack_produces_no_lift(db_session, test_user):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    in_stack = Product(name="FortiOS")
    other = Product(name="RandomApp")
    db_session.add_all([in_stack, other])
    await db_session.flush()
    cve = await _cve(db_session, "CVE-2024-9999", is_kev=True)
    await _link_cve(db_session, entry, cve)
    await _affect(db_session, cve, product=other)  # affects a product NOT in stack

    lift = await _lift_for(db_session, entry, [], [in_stack.id])
    assert lift is None


@pytest.mark.asyncio
async def test_empty_stack_subquery_is_none():
    assert exposure_lift_subquery([], [], THRESH) is None


@pytest.mark.asyncio
async def test_enrich_posture_defended_when_rule_and_telemetry_present(db_session, test_user):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    product = Product(name="FortiOS")
    db_session.add(product)
    await db_session.flush()
    cve = await _cve(db_session, "CVE-2024-21762", is_kev=True)
    await _link_cve(db_session, entry, cve)
    await _affect(db_session, cve, product=product)
    # a non-draft rule references the CVE and needs telemetry we collect
    db_session.add(
        DetectionRule(
            rule_type="sigma",
            title="FortiOS exploit",
            rule_content="detection: ...",
            source_cves=["CVE-2024-21762"],
            data_sources=["vpn_auth_log"],
            is_draft=False,
        )
    )
    db_session.add(
        TelemetrySource(name="VPN Auth", category="network_security", log_types=["vpn_auth_log"], enabled=True)
    )
    await db_session.flush()

    result = await enrich_exposure(db_session, [entry.id], [], [product.id], THRESH)
    exp = result[entry.id]
    assert exp["posture"] == "defended"
    assert exp["asset_name"] == "FortiOS"
    assert exp["asset_type"] == "product"
    assert exp["cve_ids"] == ["CVE-2024-21762"]
    assert exp["missing_data_sources"] == []
    assert exp["lift"] == pytest.approx(EXPOSURE_BASE * KEV_MULT)


@pytest.mark.asyncio
async def test_enrich_posture_blind_when_telemetry_missing(db_session, test_user):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    product = Product(name="FortiOS")
    db_session.add(product)
    await db_session.flush()
    cve = await _cve(db_session, "CVE-2024-21762", is_kev=True)
    await _link_cve(db_session, entry, cve)
    await _affect(db_session, cve, product=product)
    # rule exists but requires telemetry we do NOT collect → blind spot
    db_session.add(
        DetectionRule(
            rule_type="sigma",
            title="FortiOS exploit",
            rule_content="detection: ...",
            source_cves=["CVE-2024-21762"],
            data_sources=["vpn_auth_log"],
            is_draft=False,
        )
    )
    await db_session.flush()  # no telemetry sources

    result = await enrich_exposure(db_session, [entry.id], [], [product.id], THRESH)
    exp = result[entry.id]
    assert exp["posture"] == "blind"
    assert "vpn_auth_log" in exp["missing_data_sources"]


@pytest.mark.asyncio
async def test_enrich_posture_no_rule(db_session, test_user):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    product = Product(name="vCenter")
    db_session.add(product)
    await db_session.flush()
    cve = await _cve(db_session, "CVE-2023-34048", is_kev=True)
    await _link_cve(db_session, entry, cve)
    await _affect(db_session, cve, product=product)

    result = await enrich_exposure(db_session, [entry.id], [], [product.id], THRESH)
    exp = result[entry.id]
    assert exp["posture"] == "no_rule"


@pytest.mark.asyncio
async def test_enrich_empty_when_no_stack_overlap(db_session, test_user):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    stack_product = Product(name="FortiOS")
    other = Product(name="RandomApp")
    db_session.add_all([stack_product, other])
    await db_session.flush()
    cve = await _cve(db_session, "CVE-2024-0002", is_kev=True)
    await _link_cve(db_session, entry, cve)
    await _affect(db_session, cve, product=other)

    result = await enrich_exposure(db_session, [entry.id], [], [stack_product.id], THRESH)
    assert result == {}


# ── Watchlist "stack" mode API ──────────────────────────────────────


@pytest.mark.asyncio
async def test_watchlist_stack_mode_add_and_filter(client, db_session, auth_headers):
    product = Product(name="Palo Alto PAN-OS")
    db_session.add(product)
    await db_session.flush()

    resp = await client.put(
        "/api/intelligence/watchlist",
        headers=auth_headers,
        json={"entity_type": "product", "entity_id": str(product.id), "mode": "stack"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["mode"] == "stack"

    listed = await client.get("/api/intelligence/watchlist?mode=stack", headers=auth_headers)
    assert listed.status_code == 200
    body = listed.json()
    assert len(body) == 1
    assert body[0]["entity_id"] == str(product.id)
    assert body[0]["entity_name"] == "Palo Alto PAN-OS"


@pytest.mark.asyncio
async def test_watchlist_stack_mode_rejects_non_asset_entity(client, db_session, auth_headers):
    cve = await _cve(db_session, "CVE-2024-1111")
    resp = await client.put(
        "/api/intelligence/watchlist",
        headers=auth_headers,
        json={"entity_type": "cve", "entity_id": str(cve.id), "mode": "stack"},
    )
    assert resp.status_code == 422


# ── Exposure Board endpoint (Phase 6) ───────────────────────────────


# ── ATT&CK data-source visibility (Phase 7) ─────────────────────────


async def _ttp(db, technique_id, data_sources):
    ttp = TTP(technique_id=technique_id, technique_name=f"Technique {technique_id}", data_sources=data_sources)
    db.add(ttp)
    await db.flush()
    return ttp


async def _link_ttp(db, entry, ttp):
    db.add(EntryTTP(entry_id=entry.id, ttp_id=ttp.id))
    await db.flush()


@pytest.mark.asyncio
async def test_attack_visibility_detectable_when_telemetry_present(db_session, test_user):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    cve = await _cve(db_session, "CVE-2024-5555")
    await _link_cve(db_session, entry, cve)
    # A co-occurring technique whose ATT&CK data source maps to collected telemetry.
    ttp = await _ttp(db_session, "T1059", ["Process: Process Creation"])
    await _link_ttp(db_session, entry, ttp)
    db_session.add(TelemetrySource(name="EDR", category="endpoint_edr", log_types=["process_creation"], enabled=True))
    await db_session.flush()

    result = await cve_attack_visibility(db_session, {cve.id: cve.cve_id})
    vis = result["CVE-2024-5555"]
    assert vis["detectable"] is True
    assert "Process Creation" in vis["available"]
    assert vis["missing"] == []


@pytest.mark.asyncio
async def test_attack_visibility_not_detectable_without_telemetry(db_session, test_user):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    cve = await _cve(db_session, "CVE-2024-6666")
    await _link_cve(db_session, entry, cve)
    ttp = await _ttp(db_session, "T1071", ["Network Traffic: Network Connection Creation"])
    await _link_ttp(db_session, entry, ttp)
    await db_session.flush()  # no telemetry

    result = await cve_attack_visibility(db_session, {cve.id: cve.cve_id})
    vis = result["CVE-2024-6666"]
    assert vis["detectable"] is False
    assert "Network Connection Creation" in vis["missing"]


@pytest.mark.asyncio
async def test_attack_visibility_empty_when_no_techniques(db_session, test_user):
    feed = await _feed(db_session)
    entry = await _entry(db_session, feed)
    cve = await _cve(db_session, "CVE-2024-7777")
    await _link_cve(db_session, entry, cve)
    await db_session.flush()

    result = await cve_attack_visibility(db_session, {cve.id: cve.cve_id})
    assert result == {}


@pytest.mark.asyncio
async def test_exposure_board_empty_stack(client, auth_headers):
    resp = await client.get("/api/intelligence/exposure", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stack"]["count"] == 0
    assert body["items"] == []


@pytest.mark.asyncio
async def test_exposure_board_ranks_and_postures(client, db_session, test_user, auth_headers):
    product = Product(name="FortiOS")
    db_session.add(product)
    await db_session.flush()
    await _stack(db_session, test_user, "product", product.id)
    cve = await _cve(db_session, "CVE-2024-21762", is_kev=True, epss=0.9)
    await _affect(db_session, cve, product=product)
    # a rule exists but its telemetry is not collected → blind
    db_session.add(
        DetectionRule(
            rule_type="sigma",
            title="FortiOS exploit",
            rule_content="detection: ...",
            source_cves=["CVE-2024-21762"],
            data_sources=["vpn_auth_log"],
            is_draft=False,
        )
    )
    await db_session.flush()

    resp = await client.get("/api/intelligence/exposure", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stack"]["count"] == 1
    assert body["stack"]["products"] == ["FortiOS"]
    assert body["counts"]["affecting"] == 1
    assert body["counts"]["kev"] == 1
    assert body["counts"]["blind"] == 1
    assert body["matrix"].get("urgent_blind") == 1
    item = body["items"][0]
    assert item["cve_id"] == "CVE-2024-21762"
    assert item["posture"] == "blind"
    assert item["asset_name"] == "FortiOS"
    assert "vpn_auth_log" in item["missing_data_sources"]
    assert item["lift"] == pytest.approx(EXPOSURE_BASE * KEV_MULT)
