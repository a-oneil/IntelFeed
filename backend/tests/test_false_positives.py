"""Tests for the false-positive reporting endpoint — reader feedback loop for autolinker noise."""

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entry import Entry
from app.models.false_positive_record import FalsePositiveRecord
from app.models.feed import Feed
from app.models.system_setting import SystemSettings
from app.models.threat_actor import EntryThreatActor, ThreatActor


@pytest_asyncio.fixture
async def fp_entry(db_session: AsyncSession) -> Entry:
    feed = Feed(title="FP Test Feed", url="https://fp-test.com/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(
        feed_id=feed.id,
        guid="fp-guid-001",
        url="https://fp-test.com/post/1",
        title="An article about a Widget campaign",
        published_at=datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC),
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest_asyncio.fixture
async def fp_actor_link(db_session: AsyncSession, fp_entry: Entry) -> tuple[ThreatActor, Entry]:
    actor = ThreatActor(name="Widget")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=fp_entry.id, threat_actor_id=actor.id, confidence="high", source="test"))
    await db_session.flush()
    return actor, fp_entry


@pytest.fixture(autouse=True)
def _reset_settings_cache(monkeypatch):
    """The settings cache is a process-global, not tied to db_session's rollback — force
    a clean slate before each test and let monkeypatch revert it after."""
    import app.services.system_settings as ss_mod

    monkeypatch.setattr(ss_mod, "_cache", None)
    monkeypatch.setattr(ss_mod, "_cache_ts", 0.0)
    yield


@pytest_asyncio.fixture(autouse=True)
async def _seed_system_settings_row(db_session: AsyncSession):
    """The db_session fixture creates tables via Base.metadata.create_all, which
    (unlike `alembic upgrade head`) skips the data migration that seeds the
    system_settings singleton row — update_settings() only ever UPDATEs id=1 and
    silently no-ops if it doesn't exist yet. Prod always has the row (migration
    044); seed it here so update_settings() behaves the same way in tests."""
    db_session.add(SystemSettings(id=1, settings={}, secrets={}))
    await db_session.flush()


@pytest.mark.asyncio
async def test_report_false_positive_entry_scope_unlinks_only_this_entry(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, fp_actor_link: tuple[ThreatActor, Entry]
):
    actor, entry = fp_actor_link

    resp = await client.post(
        "/api/false-positives",
        json={
            "entity_type": "threat_actor",
            "entity_id": str(actor.id),
            "entity_value": "Widget",
            "source_entry_id": str(entry.id),
            "scope": "entry",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["unlinked_from_entry"] is True
    assert data["added_to_autolinker_fp_list"] is False

    remaining = (
        await db_session.execute(
            select(EntryThreatActor).where(
                EntryThreatActor.entry_id == entry.id, EntryThreatActor.threat_actor_id == actor.id
            )
        )
    ).scalar_one_or_none()
    assert remaining is None

    record = (await db_session.execute(select(FalsePositiveRecord))).scalars().one()
    assert record.entity_value == "Widget"
    assert record.source_entry_id == entry.id


@pytest.mark.asyncio
async def test_report_false_positive_global_scope_updates_autolinker_and_rebuilds_vocab(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, fp_actor_link: tuple[ThreatActor, Entry]
):
    from app.intelligence.autolinker import _get_blocked_forms, scan_text
    from app.intelligence.correlation import ENTITY_CONFIG

    actor, entry = fp_actor_link

    resp = await client.post(
        "/api/false-positives",
        json={
            "entity_type": "threat_actor",
            "entity_id": str(actor.id),
            "entity_value": "Widget",
            "source_entry_id": str(entry.id),
            "scope": "global",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["unlinked_from_entry"] is True
    assert data["added_to_autolinker_fp_list"] is True

    assert "widget" in _get_blocked_forms()
    # Vocabulary was rebuilt inside the endpoint — a fresh scan should already skip it.
    assert scan_text("The Widget campaign was observed.") == []

    _, junction, fk_col = ENTITY_CONFIG["threat_actor"]
    remaining = (
        await db_session.execute(select(junction).where(junction.entry_id == entry.id, fk_col == actor.id))
    ).scalar_one_or_none()
    assert remaining is None


@pytest.mark.asyncio
async def test_report_false_positive_global_scope_is_idempotent(
    client: AsyncClient, auth_headers: dict, fp_actor_link: tuple[ThreatActor, Entry]
):
    actor, entry = fp_actor_link

    for _ in range(2):
        resp = await client.post(
            "/api/false-positives",
            json={
                "entity_type": "threat_actor",
                "entity_id": str(actor.id),
                "entity_value": "Widget",
                "source_entry_id": str(entry.id),
                "scope": "global",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 201

    from app.intelligence.autolinker import _get_blocked_forms

    assert "widget" in _get_blocked_forms()


@pytest.mark.asyncio
async def test_report_false_positive_rejects_unknown_entity_type(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/false-positives",
        json={
            "entity_type": "not_a_real_type",
            "entity_id": "00000000-0000-0000-0000-000000000000",
            "entity_value": "whatever",
            "scope": "entry",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_global_scope_blocks_vendor_names_too(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, fp_entry: Entry
):
    """Regression: vendor/product/tool/mitigation bypass the curated FP-name list
    (their real names are common brand words), so a global report used to write a
    setting that could never take effect — the toast claimed success and matching
    carried on. Analyst blocks land in a separate all-types list now."""
    from app.intelligence.autolinker import scan_text
    from app.models.vendor import EntryVendor, Vendor

    vendor = Vendor(name="Sprocket")
    db_session.add(vendor)
    await db_session.flush()
    db_session.add(EntryVendor(entry_id=fp_entry.id, vendor_id=vendor.id, confidence="high", source="test"))
    await db_session.flush()

    resp = await client.post(
        "/api/false-positives",
        json={
            "entity_type": "vendor",
            "entity_id": str(vendor.id),
            "entity_value": "Sprocket",
            "source_entry_id": str(fp_entry.id),
            "scope": "global",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["added_to_autolinker_fp_list"] is True
    assert scan_text("Sprocket published an advisory today.") == []


@pytest.mark.asyncio
async def test_alias_scope_drops_alias_and_unlinks_alias_only_entries(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, fp_entry: Entry
):
    feed_id = fp_entry.feed_id
    other = Entry(
        feed_id=feed_id,
        guid="fp-guid-002",
        url="https://fp-test.com/post/2",
        title="Second article",
        published_at=datetime(2025, 1, 16, 12, 0, 0, tzinfo=UTC),
    )
    db_session.add(other)
    await db_session.flush()

    actor = ThreatActor(name="Gadget Group", aliases=["Widget", "Doohickey"])
    db_session.add(actor)
    await db_session.flush()
    # Linked only via the bad alias — should go.
    db_session.add(
        EntryThreatActor(
            entry_id=fp_entry.id, threat_actor_id=actor.id, confidence="high", source="test", matched_names=["Widget"]
        )
    )
    # Also matched the real name — the link is still justified, so it stays.
    db_session.add(
        EntryThreatActor(
            entry_id=other.id,
            threat_actor_id=actor.id,
            confidence="high",
            source="test",
            matched_names=["Widget", "Gadget Group"],
        )
    )
    await db_session.flush()

    resp = await client.post(
        "/api/false-positives",
        json={
            "entity_type": "threat_actor",
            "entity_id": str(actor.id),
            "entity_value": "Widget",
            "scope": "alias",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["alias_removed"] is True
    assert data["links_removed"] == 1

    await db_session.refresh(actor)
    assert actor.aliases == ["Doohickey"]

    remaining = (
        (await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.threat_actor_id == actor.id)))
        .scalars()
        .all()
    )
    assert [r.entry_id for r in remaining] == [other.id]

    # The entity keeps matching under its real name.
    from app.intelligence.autolinker import scan_text

    assert scan_text("Widget was seen again.") == []
    assert [m["canonical_name"] for m in scan_text("Gadget Group was seen again.")] == ["Gadget Group"]


@pytest.mark.asyncio
async def test_alias_scope_rejects_the_entitys_primary_name(
    client: AsyncClient, auth_headers: dict, fp_actor_link: tuple[ThreatActor, Entry]
):
    actor, _ = fp_actor_link
    resp = await client.post(
        "/api/false-positives",
        json={
            "entity_type": "threat_actor",
            "entity_id": str(actor.id),
            "entity_value": "Widget",
            "scope": "alias",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422
    assert "primary name" in resp.text


@pytest.mark.asyncio
async def test_alias_scope_rejects_types_without_aliases(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/false-positives",
        json={
            "entity_type": "cve",
            "entity_id": "00000000-0000-0000-0000-000000000000",
            "entity_value": "CVE-2024-1234",
            "scope": "alias",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422
    assert "no aliases" in resp.text
