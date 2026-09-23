"""Cross-type resurrection guards: reclassify tombstones + junk-name filter.

Covers the gap where a folded entity (malware → same-named actor) would be
recreated by AI extraction or the daily Cybergeist sync, because each importer
only searches its own table.
"""

from sqlalchemy import func, select

from app.intelligence.autolinker import is_fp_entity_name
from app.intelligence.enrichment import store_malware, store_threat_actors
from app.models.entity_maintenance import EntityReclassifyTombstone
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor

# --- is_fp_entity_name (pure) ---


def test_fp_name_rejects_system_binaries():
    assert is_fp_entity_name("svchost.exe")
    assert is_fp_entity_name("python310.dll")
    assert is_fp_entity_name("driver.sys")
    assert is_fp_entity_name("SecurePDF Viewer.app")
    assert is_fp_entity_name("")
    assert is_fp_entity_name("   ")


def test_fp_name_allows_real_families():
    assert not is_fp_entity_name("Akira")
    assert not is_fp_entity_name("LockBit")
    assert not is_fp_entity_name("Cobalt Strike")


# --- tombstone suppression in AI extraction ---


async def _count_malware(db, name: str) -> int:
    return (
        await db.execute(
            select(func.count()).select_from(MalwareFamily).where(func.lower(MalwareFamily.name) == name.lower())
        )
    ).scalar() or 0


async def test_store_malware_suppressed_by_tombstone_links_actor(db_session, test_entry):
    """A malware name folded into an actor must not be recreated; the entry links
    to the surviving actor instead."""
    actor = ThreatActor(name="Akira", aliases=[])
    db_session.add(actor)
    await db_session.flush()

    db_session.add(
        EntityReclassifyTombstone(
            normalized_name="akira",
            source_type="malware",
            target_type="threat_actor",
            target_id=actor.id,
            active=True,
        )
    )
    await db_session.flush()

    stored = await store_malware(db_session, test_entry.id, [{"name": "Akira"}])

    assert stored == []  # no shadow malware returned
    assert await _count_malware(db_session, "Akira") == 0  # nothing recreated

    link = (
        await db_session.execute(
            select(EntryThreatActor).where(
                EntryThreatActor.entry_id == test_entry.id,
                EntryThreatActor.threat_actor_id == actor.id,
            )
        )
    ).scalar_one_or_none()
    assert link is not None  # entry linked to the survivor


async def test_store_malware_matches_tombstone_on_alias(db_session, test_entry):
    actor = ThreatActor(name="Cl0p", aliases=[])
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        EntityReclassifyTombstone(
            normalized_name="cl0p ransomware",
            source_type="malware",
            target_type="threat_actor",
            target_id=actor.id,
            active=True,
        )
    )
    await db_session.flush()

    # Incoming name differs; alias carries the tombstoned form.
    stored = await store_malware(db_session, test_entry.id, [{"name": "Clop", "aliases": ["Cl0p ransomware"]}])
    assert stored == []
    assert await _count_malware(db_session, "Clop") == 0


async def test_inactive_tombstone_does_not_suppress(db_session, test_entry):
    actor = ThreatActor(name="Hive", aliases=[])
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        EntityReclassifyTombstone(
            normalized_name="hive",
            source_type="malware",
            target_type="threat_actor",
            target_id=actor.id,
            active=False,  # analyst re-allowed the split
        )
    )
    await db_session.flush()

    stored = await store_malware(db_session, test_entry.id, [{"name": "Hive"}])
    assert len(stored) == 1
    assert await _count_malware(db_session, "Hive") == 1


async def test_store_malware_junk_name_skipped(db_session, test_entry):
    stored = await store_malware(db_session, test_entry.id, [{"name": "svchost.exe"}])
    assert stored == []
    assert await _count_malware(db_session, "svchost.exe") == 0


async def test_store_malware_creates_without_tombstone(db_session, test_entry):
    """Control: a legitimately distinct family with no tombstone is still created."""
    stored = await store_malware(db_session, test_entry.id, [{"name": "GreenLambert"}])
    assert len(stored) == 1
    assert await _count_malware(db_session, "GreenLambert") == 1


async def test_store_actor_suppressed_by_tombstone(db_session, test_entry):
    """Reverse direction: an actor name folded into a malware family."""
    malware = MalwareFamily(name="TRITON", aliases=[])
    db_session.add(malware)
    await db_session.flush()
    db_session.add(
        EntityReclassifyTombstone(
            normalized_name="triton actor",
            source_type="threat_actor",
            target_type="malware",
            target_id=malware.id,
            active=True,
        )
    )
    await db_session.flush()

    stored = await store_threat_actors(db_session, test_entry.id, [{"name": "triton actor"}])
    assert stored == []
    count = (
        await db_session.execute(
            select(func.count()).select_from(ThreatActor).where(ThreatActor.name == "triton actor")
        )
    ).scalar()
    assert count == 0
