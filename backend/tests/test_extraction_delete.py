"""Deleting from the Engine's AI entities table must stick.

A plain entity delete leaves nothing behind, so the next article mentioning the
name re-mints it. POST /api/engine/extraction/delete also writes an
``analyst_delete`` denylist row, which the resolver and the CVE/TTP store paths
honour regardless of the entity-creation-gate mode.
"""

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.config import settings
from app.intelligence.cve import extract_and_store_cves
from app.intelligence.entity_resolution import (
    DO_NOT_RECREATE_SOURCE,
    is_name_denied,
    resolve_entity_creation,
)
from app.models.country import Country
from app.models.cve import CVE
from app.models.entity_index import EntityNameDenylist
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import MalwareFamily
from app.models.system_setting import SystemSettings
from app.models.threat_actor import ThreatActor
from app.models.tool import Tool

pytestmark = pytest.mark.asyncio


@pytest.fixture
def gates_off(monkeypatch):
    monkeypatch.setattr(settings, "entity_creation_gates", "off")


@pytest.fixture(autouse=True)
def _reset_settings_cache(monkeypatch):
    """The settings cache is a process-global, not tied to db_session's rollback."""
    import app.services.system_settings as ss_mod

    monkeypatch.setattr(ss_mod, "_cache", None)
    monkeypatch.setattr(ss_mod, "_cache_ts", 0.0)


@pytest_asyncio.fixture(autouse=True)
async def _seed_system_settings_row(db_session):
    """db_session builds the schema with create_all, which skips the data migration
    that seeds the system_settings singleton — update_settings() only UPDATEs id=1
    and silently no-ops without it (same shim as tests/test_false_positives.py)."""
    db_session.add(SystemSettings(id=1, settings={}, secrets={}))
    await db_session.flush()


async def _entry(db_session) -> uuid.UUID:
    feed = Feed(title="t", url=f"https://example.com/{uuid.uuid4()}.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(feed_id=feed.id, title="t", url=f"https://example.com/{uuid.uuid4()}", guid=str(uuid.uuid4()))
    db_session.add(entry)
    await db_session.flush()
    return entry.id


async def test_delete_denies_and_blocks_recreation(client, admin_headers, db_session, gates_off):
    malware = MalwareFamily(name="Prometheus", aliases=["PrometheusRAT"], created_via="ai_extraction")
    db_session.add(malware)
    await db_session.flush()
    malware_id = malware.id
    await db_session.commit()

    resp = await client.post(
        "/api/engine/extraction/delete",
        json={"entity_type": "malware", "ids": [str(malware_id)]},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["deleted"] == 1
    assert resp.json()["denied"] == 2  # name + alias

    assert await db_session.get(MalwareFamily, malware_id) is None
    rows = (
        (await db_session.execute(select(EntityNameDenylist).where(EntityNameDenylist.entity_type == "malware")))
        .scalars()
        .all()
    )
    assert {r.display_name for r in rows} == {"Prometheus", "PrometheusRAT"}
    assert all(r.source == DO_NOT_RECREATE_SOURCE and r.active for r in rows)

    # Enforced even with the heuristic gates off, and via the alias too. For
    # actor/malware the pre-existing fp_name guard (step 3b) can fire first —
    # the mirrored FP list catches the same name — so either reason is a block.
    decision = await resolve_entity_creation(db_session, "malware", "Prometheus")
    assert decision.action == "blocked"
    assert decision.reason in ("denylist_do_not_recreate", "fp_name")
    assert (await resolve_entity_creation(db_session, "malware", "PrometheusRAT")).action == "blocked"
    # The denylist row itself is type-scoped.
    assert await is_name_denied(db_session, "malware", "Prometheus") is not None
    assert await is_name_denied(db_session, "threat_actor", "Prometheus") is None
    # The manual UI keeps its own gate/override path.
    assert (await resolve_entity_creation(db_session, "malware", "Prometheus", source="manual")).action != "blocked"


async def test_deleted_cve_is_not_reextracted(client, admin_headers, db_session, gates_off):
    entry_id = await _entry(db_session)
    stored = await extract_and_store_cves(db_session, entry_id, "See CVE-2024-99999 for details.", enrich=False)
    assert [c.cve_id for c in stored] == ["CVE-2024-99999"]
    cve_id = stored[0].id
    await db_session.commit()

    resp = await client.post(
        "/api/engine/extraction/delete",
        json={"entity_type": "cve", "ids": [str(cve_id)]},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"deleted": 1, "denied": 1}
    assert await is_name_denied(db_session, "cve", "CVE-2024-99999") is not None

    entry2 = await _entry(db_session)
    assert await extract_and_store_cves(db_session, entry2, "Also CVE-2024-99999.", enrich=False) == []
    assert (await db_session.execute(select(CVE).where(CVE.cve_id == "CVE-2024-99999"))).scalar_one_or_none() is None


async def test_delete_without_deny_leaves_no_denylist_row(client, admin_headers, db_session, gates_off):
    malware = MalwareFamily(name="Keeper", aliases=[], created_via="ai_extraction")
    db_session.add(malware)
    await db_session.flush()
    malware_id = malware.id
    await db_session.commit()

    resp = await client.post(
        "/api/engine/extraction/delete",
        json={"entity_type": "malware", "ids": [str(malware_id)], "deny": False},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"deleted": 1, "denied": 0}
    assert await is_name_denied(db_session, "malware", "Keeper") is None


async def test_profile_deny_name_endpoint(client, auth_headers, db_session, gates_off):
    """The entity profile's delete popover denies first, then deletes."""
    actor = ThreatActor(name="Pretend Panda", aliases=["PP-42"])
    db_session.add(actor)
    await db_session.flush()
    actor_id = actor.id
    await db_session.commit()

    resp = await client.post(f"/api/entities/threat_actor/{actor_id}/deny-name", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"denied": 2, "names": ["Pretend Panda", "PP-42"]}

    # The entity itself is untouched — the caller deletes it separately.
    assert await db_session.get(ThreatActor, actor_id) is not None

    # Once it's gone, the name can't come back.
    resp = await client.delete(f"/api/entities/threat-actors/{actor_id}", headers=auth_headers)
    assert resp.status_code == 204, resp.text
    assert (await resolve_entity_creation(db_session, "threat_actor", "Pretend Panda")).action == "blocked"
    assert (await resolve_entity_creation(db_session, "threat_actor", "PP-42")).action == "blocked"


async def test_profile_deny_name_rejects_unenforced_types(client, auth_headers, db_session):
    country = Country(name="Testland", iso_code="TL")
    db_session.add(country)
    await db_session.flush()
    country_id = country.id
    await db_session.commit()

    resp = await client.post(f"/api/entities/country/{country_id}/deny-name", headers=auth_headers)
    assert resp.status_code == 422


async def test_denied_names_appear_in_autolinker_fp_list(client, admin_headers, db_session, gates_off):
    """The names must also show up in Engine → Autolink → False Positive Names,
    or the autolinker keeps matching them into the vocabulary."""
    from app.services.system_settings import get_setting

    tool = Tool(name="Nimbus Loader", aliases=["NimbusLdr"], created_via="ai_extraction")
    db_session.add(tool)
    await db_session.flush()
    tool_id = tool.id
    await db_session.commit()

    resp = await client.post(
        "/api/engine/extraction/delete",
        json={"entity_type": "tool", "ids": [str(tool_id)]},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text

    fp = str(await get_setting("autolinker_false_positive_names", db_session) or "")
    names = {n.strip() for n in fp.split(",")}
    assert {"nimbus loader", "nimbusldr"} <= names

    # The list surfaces the rows, and removing one lifts both the creation ban
    # and the autolinker exclusion.
    listing = await client.get("/api/engine/extraction/denylist?q=Nimbus", headers=admin_headers)
    assert listing.status_code == 200, listing.text
    items = listing.json()["items"]
    assert {i["display_name"] for i in items} == {"Nimbus Loader", "NimbusLdr"}
    assert all(i["source"] == DO_NOT_RECREATE_SOURCE for i in items)

    row_id = next(i["id"] for i in items if i["display_name"] == "Nimbus Loader")
    resp = await client.delete(f"/api/engine/extraction/denylist/{row_id}", headers=admin_headers)
    assert resp.status_code == 204, resp.text
    assert await is_name_denied(db_session, "tool", "Nimbus Loader") is None
    fp = str(await get_setting("autolinker_false_positive_names", db_session) or "")
    assert "nimbus loader" not in {n.strip() for n in fp.split(",")}


async def test_denylist_add_endpoint(client, admin_headers, db_session, gates_off):
    resp = await client.post(
        "/api/engine/extraction/denylist",
        json={"entity_type": "malware", "name": "Notamalware"},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["source"] == DO_NOT_RECREATE_SOURCE
    assert (await resolve_entity_creation(db_session, "malware", "Notamalware")).action == "blocked"

    bad = await client.post(
        "/api/engine/extraction/denylist",
        json={"entity_type": "country", "name": "Testland"},
        headers=admin_headers,
    )
    assert bad.status_code == 422


async def test_any_type_denylist_row_bans_every_type(client, admin_headers, db_session, gates_off):
    """A hand-added name defaults to 'any' — not scoped to one entity type."""
    resp = await client.post(
        "/api/engine/extraction/denylist",
        json={"entity_type": "any", "name": "Attackers"},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["entity_type"] == "any"

    for entity_type in ("threat_actor", "malware", "tool", "cve", "ttp"):
        assert await is_name_denied(db_session, entity_type, "Attackers") is not None
    assert (await resolve_entity_creation(db_session, "tool", "Attackers")).action == "blocked"


async def test_denylist_pages_do_not_repeat_rows(client, admin_headers, db_session, gates_off):
    """The 2026-08 seed shares one created_at, so the ordering needs tiebreakers
    or LIMIT/OFFSET repeats rows on every page."""
    stamp = datetime(2026, 8, 16, 16, 2, 15, tzinfo=UTC)
    for i in range(12):
        db_session.add(
            EntityNameDenylist(
                entity_type="threat_actor",
                normalized_name=f"seeded{i}",
                display_name=f"Seeded {i}",
                source="cleanup_2026_08",
                created_at=stamp,
            )
        )
    await db_session.commit()

    seen: list[str] = []
    for offset in (0, 5, 10):
        resp = await client.get(f"/api/engine/extraction/denylist?limit=5&offset={offset}", headers=admin_headers)
        assert resp.status_code == 200, resp.text
        seen.extend(i["id"] for i in resp.json()["items"])
    assert len(seen) == len(set(seen))


async def test_fp_names_table_endpoints(client, admin_headers, db_session):
    """Autolink → False Positive Names is one comma-separated setting; the panel
    reads and edits it a name at a time."""
    from app.intelligence.entity_resolution import sync_fp_names

    # The setting ships with ~150 env defaults, so assert on our own names only.
    await sync_fp_names(db_session, add=["Zoggle", "Zaggle"])
    await db_session.commit()

    resp = await client.get("/api/engine/autolink/fp-names?q=zaggle", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["items"] == ["zaggle"]

    added = await client.post("/api/engine/autolink/fp-names", json={"name": "Zprocket"}, headers=admin_headers)
    assert added.status_code == 201, added.text
    listing = await client.get("/api/engine/autolink/fp-names?q=z", headers=admin_headers)
    assert {"zoggle", "zaggle", "zprocket"} <= set(listing.json()["items"])

    removed = await client.delete("/api/engine/autolink/fp-names?name=zoggle", headers=admin_headers)
    assert removed.status_code == 204, removed.text
    names = set((await client.get("/api/engine/autolink/fp-names?q=z", headers=admin_headers)).json()["items"])
    assert "zoggle" not in names
    assert "zaggle" in names


# --- Observables in the AI entities table ----------------------------------
# Ledger rows the one-pass AI created are AI-created entities like any other, so
# they list here — but they deny by tombstone (is_denied), since an IOC value
# has no name to put on the entity denylist.


async def _ai_observable(db_session, kind: str, value: str, **kw):
    from app.models.observable import Observable

    obs = Observable(kind=kind, value=value, created_via="ai_extraction", needs_review=True, **kw)
    db_session.add(obs)
    await db_session.flush()
    obs_id = obs.id
    await db_session.commit()
    return obs_id


async def test_ai_observables_list_in_the_extraction_table(client, admin_headers, db_session):
    obs_id = await _ai_observable(db_session, "ipv4", "203.0.113.7", created_confidence="high")

    resp = await client.get(
        "/api/engine/extraction/entities?types=observable&window=all",
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    assert [i["id"] for i in items] == [str(obs_id)]
    assert items[0]["name"] == "203.0.113.7"
    assert items[0]["entity_type"] == "observable"
    # The kind rides along as the qualifier — a bare value is unreadable alone.
    assert items[0]["aliases"] == ["ipv4"]
    assert items[0]["status"] == "orphan"  # no sightings yet

    stats = await client.get("/api/engine/extraction/stats?window=all", headers=admin_headers)
    assert stats.json()["by_type"]["observable"] == 1


async def test_denied_observables_are_hidden_from_the_table(client, admin_headers, db_session):
    await _ai_observable(db_session, "domain", "denied.example", is_denied=True)

    resp = await client.get(
        "/api/engine/extraction/entities?types=observable&window=all",
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["items"] == []


async def test_delete_observable_tombstones_instead_of_removing(client, admin_headers, db_session):
    from app.models.observable import STATUS_EXPIRED, Observable

    obs_id = await _ai_observable(db_session, "ipv4", "198.51.100.9")

    resp = await client.post(
        "/api/engine/extraction/delete",
        json={"entity_type": "observable", "ids": [str(obs_id)]},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"deleted": 1, "denied": 1}

    row = await db_session.get(Observable, obs_id)
    assert row is not None  # the ledger keeps the tombstone
    assert row.is_denied is True
    assert row.status == STATUS_EXPIRED

    # And no name landed on the entity denylist — values don't go there.
    assert await is_name_denied(db_session, "observable", "198.51.100.9") is None


async def test_delete_observable_without_deny_removes_the_row(client, admin_headers, db_session):
    from app.models.observable import Observable

    obs_id = await _ai_observable(db_session, "sha256", "a" * 64)

    resp = await client.post(
        "/api/engine/extraction/delete",
        json={"entity_type": "observable", "ids": [str(obs_id)], "deny": False},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"deleted": 1, "denied": 0}
    assert await db_session.get(Observable, obs_id) is None


async def test_ttp_door_observables_list_in_the_extraction_table(client, admin_headers, db_session):
    """Host artifacts arrive via the TTP door (created_via='ttp_observable') —
    same model's judgment, same review table."""
    from app.models.observable import Observable

    obs = Observable(kind="cmdline", value="powershell -nop -enc AAA", created_via="ttp_observable", needs_review=True)
    db_session.add(obs)
    await db_session.flush()
    obs_id = obs.id
    await db_session.commit()

    resp = await client.get(
        "/api/engine/extraction/entities?types=observable&window=all",
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert [i["id"] for i in resp.json()["items"]] == [str(obs_id)]


async def test_delete_from_review_clears_pending_proposals_and_takes_vendors(
    client, admin_headers, db_session, gates_off
):
    """The review queues delete through the same endpoint: vendors and
    products are accepted, and the pending proposals about the deleted
    entity (both logs) go with it instead of lingering as 'gone' rows."""
    from app.models.entity_link_validation_log import EntityLinkValidationLog
    from app.models.entity_maintenance import EntityMaintenanceLog
    from app.models.vendor import Vendor

    entry_id = await _entry(db_session)
    vendor = Vendor(name="Acme Threat Group")
    db_session.add(vendor)
    await db_session.flush()
    vendor_id = vendor.id
    db_session.add(
        EntityLinkValidationLog(
            entry_id=entry_id,
            entity_type="vendor",
            entity_id=vendor_id,
            entity_name_snapshot="Acme Threat Group",
            action="needs_reclassification",
            suggested_entity_type="threat_actor",
        )
    )
    db_session.add(
        EntityMaintenanceLog(
            entity_type="vendor",
            entity_id=vendor_id,
            action="adjudication_unlink",
            mode="shadow",
            applied=False,
            before={"entry_id": str(entry_id)},
            after={"reason": "r"},
        )
    )
    db_session.add(
        EntityMaintenanceLog(
            entity_type="vendor",
            entity_id=vendor_id,
            action="reclassify",
            mode="apply",
            applied=True,
            before={},
            after={},
        )
    )
    await db_session.commit()

    resp = await client.post(
        "/api/engine/extraction/delete",
        json={"entity_type": "vendor", "ids": [str(vendor_id)]},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"deleted": 1, "denied": 1}
    assert await db_session.get(Vendor, vendor_id) is None
    assert (await db_session.execute(select(EntityLinkValidationLog))).scalars().all() == []
    left = (await db_session.execute(select(EntityMaintenanceLog))).scalars().all()
    # Applied history stays; only the pending proposal is cleared.
    assert [(r.action, r.applied) for r in left] == [("reclassify", True)]

    # A seeded catalogue is deleted but never denylisted.
    country = Country(name="Freedonia", iso_code="FD", aliases=[])
    db_session.add(country)
    await db_session.flush()
    country_id = country.id
    await db_session.commit()
    resp = await client.post(
        "/api/engine/extraction/delete",
        json={"entity_type": "country", "ids": [str(country_id)]},
        headers=admin_headers,
    )
    assert resp.json() == {"deleted": 1, "denied": 0}
    assert await db_session.get(Country, country_id) is None
