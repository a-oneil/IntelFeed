"""Observables in the automation engine (has_observable condition). The
enrichment write-back (reputation + dual-use infra tags) is covered in
test_entity_updater_field_map.py."""

import uuid

import pytest

from app.automation.conditions import _evaluate_single
from app.intelligence.observables import get_or_create_observable, record_sighting
from app.models.entry import Entry
from app.models.feed import Feed


async def _entry(db):
    feed = Feed(title="t", url=f"https://t.example/{uuid.uuid4()}", feed_type="rss")
    db.add(feed)
    await db.flush()
    e = Entry(feed_id=feed.id, guid=str(uuid.uuid4()), title="e", content_text="x")
    db.add(e)
    await db.flush()
    return e


@pytest.mark.asyncio
async def test_has_observable_condition_filters_kind_role_source_and_tag(db_session):
    entry = await _entry(db_session)
    c2 = await get_or_create_observable(db_session, "domain", "c2.example-bad.net", via="ai_extraction", role="c2")
    await record_sighting(db_session, entry.id, c2, source="ai")
    vpn = await get_or_create_observable(db_session, "ipv4", "185.199.108.153", via="ioc_list", infra_tag="vpn")
    await record_sighting(db_session, entry.id, vpn, source="feed")
    await db_session.commit()

    async def fires(config: dict) -> bool:
        return await _evaluate_single(db_session, entry, {"type": "has_observable", "config": config})

    assert await fires({})
    assert await fires({"kinds": "domain", "roles": "c2"})
    assert not await fires({"kinds": "sha256"})
    assert not await fires({"roles": ["delivery"]})
    assert await fires({"min_confidence": 0.5})
    assert not await fires({"min_confidence": 0.99})
    # The VPN row is feed-sighted and infra-tagged: invisible by default, visible when asked.
    assert not await fires({"kinds": "ipv4"})
    assert await fires({"kinds": "ipv4", "sources": "feed", "exclude_infra_tagged": "false"})


@pytest.mark.asyncio
async def test_observable_capture_trigger_fires_matching_rules_once(db_session, test_user, monkeypatch):
    from app.automation.engine import run_automations_for_observable_capture
    from app.models.automation_rule import AutomationRule

    entry = await _entry(db_session)
    c2 = await get_or_create_observable(db_session, "domain", "beacon.example-bad.net", via="ai_extraction", role="c2")
    await record_sighting(db_session, entry.id, c2, source="ai")
    c2_rule = AutomationRule(
        created_by=test_user.id,
        name="C2 captured",
        trigger_type="on_observable_captured",
        trigger_config={"roles": "c2"},
        conditions={},
        actions=[{"type": "add_tags", "config": {"tags": ["c2-captured"]}}],
    )
    hash_rule = AutomationRule(
        created_by=test_user.id,
        name="Hash captured",
        trigger_type="on_observable_captured",
        trigger_config={"kinds": ["sha256"]},
        conditions={},
        actions=[{"type": "add_tags", "config": {"tags": ["hash-captured"]}}],
    )
    db_session.add_all([c2_rule, hash_rule])
    await db_session.commit()

    logs = await run_automations_for_observable_capture(db_session, entry)
    await db_session.commit()
    assert [lg.rule_id for lg in logs] == [c2_rule.id]
    assert logs[0].trigger_type == "on_observable_captured" and logs[0].status == "success"

    # The publisher door landing on the same article later must not re-fire.
    assert await run_automations_for_observable_capture(db_session, entry) == []


@pytest.mark.asyncio
async def test_apply_ai_observables_queues_capture_runner_only_when_rows_land(db_session, monkeypatch):
    from app.services.entry_analysis import apply_ai_observables

    queued: list[str] = []
    monkeypatch.setattr(
        "app.workers.automation_tasks.dispatch_observable_capture_automations",
        lambda entry_id, **kw: queued.append(str(entry_id)),
    )
    entry = await _entry(db_session)
    iocs = [{"kind": "domain", "value": "stage.example-bad.net", "role": "delivery", "evidence": "x"}]
    shadow = await apply_ai_observables(db_session, entry.id, {"iocs": iocs}, mode="shadow")
    assert shadow.get("observables_shadow") and queued == []
    captured = await apply_ai_observables(
        db_session, entry.id, {"iocs": iocs}, mode="capture", capture_kinds={"domain"}
    )
    assert captured.get("observables") == 1 and queued == [str(entry.id)]
    # A replay backfill is silent.
    other = await _entry(db_session)
    await apply_ai_observables(
        db_session, other.id, {"iocs": iocs}, mode="capture", capture_kinds={"domain"}, fire_automations=False
    )
    assert queued == [str(entry.id)]


@pytest.mark.asyncio
async def test_add_to_campaign_can_attach_captured_observables(db_session, test_user):
    from sqlalchemy import select

    from app.automation.actions import _action_add_to_campaign
    from app.models.campaign import Campaign, CampaignEntity

    entry = await _entry(db_session)
    c2 = await get_or_create_observable(db_session, "ipv4", "203.0.113.77", via="ai_extraction", role="c2")
    await record_sighting(db_session, entry.id, c2, source="ai")
    vpn = await get_or_create_observable(db_session, "ipv4", "203.0.113.78", via="ai_extraction", infra_tag="vpn")
    await record_sighting(db_session, entry.id, vpn, source="ai")
    listed = await get_or_create_observable(db_session, "ipv4", "203.0.113.79", via="ioc_list")
    await record_sighting(db_session, entry.id, listed, source="feed")
    campaign = Campaign(name=f"Op-{uuid.uuid4().hex[:6]}", created_by=test_user.id)
    db_session.add(campaign)
    await db_session.commit()

    cfg = {"campaign_id": str(campaign.id), "link_observables": True, "observable_roles": "c2"}
    first = await _action_add_to_campaign(db_session, entry, cfg, test_user.id)
    assert first["status"] == "success" and first["observables_linked"] == 1
    rows = (
        (
            await db_session.execute(
                select(CampaignEntity.entity_id).where(
                    CampaignEntity.campaign_id == campaign.id, CampaignEntity.entity_type == "observable"
                )
            )
        )
        .scalars()
        .all()
    )
    assert rows == [c2.id]  # the VPN exit and the blocklist row stay out
    again = await _action_add_to_campaign(db_session, entry, cfg, test_user.id)
    assert again["status"] == "skipped"


@pytest.mark.asyncio
async def test_auto_enrich_fan_out_is_capped_per_entry(db_session, monkeypatch):
    from app.intelligence import observables as mod

    dispatched: list[str] = []

    async def fake_enqueue(session, obs):
        dispatched.append(obs.value)

    monkeypatch.setattr(mod, "_enqueue_auto_enrich", fake_enqueue)
    monkeypatch.setattr(mod, "_auto_enrich_queued", {})
    entry = await _entry(db_session)
    for i in range(mod.AUTO_ENRICH_PER_ENTRY_CAP + 10):
        await get_or_create_observable(
            db_session, "ipv4", f"198.51.100.{i + 1}", via="publisher_ioc", entry_id=entry.id
        )
    assert len(dispatched) == mod.AUTO_ENRICH_PER_ENTRY_CAP
    # The feed door never enriches, however many rows it writes.
    await get_or_create_observable(db_session, "ipv4", "198.51.100.250", via="ioc_list", entry_id=entry.id)
    assert len(dispatched) == mod.AUTO_ENRICH_PER_ENTRY_CAP


@pytest.mark.asyncio
async def test_relationship_target_resolves_host_kinds_through_normalizers(db_session):
    from app.intelligence.enrichment import _resolve_entity_id

    cmd = await get_or_create_observable(
        db_session, "cmdline", "powershell  -enc   SQBFAFgA  -w hidden", via="ai_extraction", role="execution"
    )
    assert cmd is not None and cmd.value == "powershell -enc SQBFAFgA -w hidden"
    await db_session.commit()
    # The model prints the command with its original spacing; the value-only
    # fallback used to miss the whitespace-collapsed row.
    assert await _resolve_entity_id(db_session, "observable", "powershell  -enc   SQBFAFgA  -w hidden") == cmd.id
    assert (
        await _resolve_entity_id(db_session, "observable", "powershell -enc SQBFAFgA -w hidden", kind="cmdline")
        == cmd.id
    )
    assert (
        await _resolve_entity_id(db_session, "observable", "powershell -enc SQBFAFgA -w hidden", kind="path") == cmd.id
    )
