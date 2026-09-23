"""POST /entities/convert — the generalized any-to-any entity type converter.

Covers the newly-supported pairs (vendor/product, →cve with an external id),
entry-link migration, the reclassify tombstone that stops the autolinker from
recreating the folded source, and the identifier/collision guards.
"""

from sqlalchemy import func, select

from app.models.cve import CVE, EntryCVE
from app.models.entity_maintenance import EntityReclassifyTombstone
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.product import Product
from app.models.tool import EntryTool, Tool
from app.models.vendor import Vendor


async def _tombstone_count(db, source_type: str, name: str) -> int:
    return (
        await db.execute(
            select(func.count())
            .select_from(EntityReclassifyTombstone)
            .where(
                EntityReclassifyTombstone.source_type == source_type,
                func.lower(EntityReclassifyTombstone.normalized_name) == name.lower(),
                EntityReclassifyTombstone.active.is_(True),
            )
        )
    ).scalar() or 0


async def test_convert_malware_to_tool_migrates_link_and_tombstones(client, db_session, test_entry, admin_headers):
    malware = MalwareFamily(name="Mimikatz", aliases=["mimi"])
    db_session.add(malware)
    await db_session.flush()
    db_session.add(EntryMalware(entry_id=test_entry.id, malware_family_id=malware.id, confidence="confirmed"))
    await db_session.flush()

    resp = await client.post(
        "/api/entities/convert",
        json={"entity_id": str(malware.id), "target_type": "tool"},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["target_type"] == "tool"
    assert body["migrated_entry_links"] == 1
    new_id = body["id"]

    # New tool exists, malware is gone, entry link moved to the tool.
    tool = (await db_session.execute(select(Tool).where(Tool.name == "Mimikatz"))).scalar_one_or_none()
    assert tool is not None
    assert (
        await db_session.execute(select(func.count()).select_from(MalwareFamily).where(MalwareFamily.id == malware.id))
    ).scalar() == 0
    link = (
        await db_session.execute(
            select(EntryTool).where(EntryTool.tool_id == tool.id, EntryTool.entry_id == test_entry.id)
        )
    ).scalar_one_or_none()
    assert link is not None
    assert str(tool.id) == new_id

    # Tombstone recorded under the CANONICAL source slug (malware), plus the alias.
    assert await _tombstone_count(db_session, "malware", "Mimikatz") == 1
    assert await _tombstone_count(db_session, "malware", "mimi") == 1


async def test_convert_vendor_to_product(client, db_session, admin_headers):
    vendor = Vendor(name="Fortinet")
    db_session.add(vendor)
    await db_session.flush()

    resp = await client.post(
        "/api/entities/convert",
        json={"entity_id": str(vendor.id), "target_type": "product"},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    product = (await db_session.execute(select(Product).where(Product.name == "Fortinet"))).scalar_one_or_none()
    assert product is not None
    assert (
        await db_session.execute(select(func.count()).select_from(Vendor).where(Vendor.id == vendor.id))
    ).scalar() == 0


async def test_convert_to_cve_requires_identifier(client, db_session, admin_headers):
    malware = MalwareFamily(name="ShadyBug", aliases=[])
    db_session.add(malware)
    await db_session.flush()

    # Missing identifier → 400.
    resp = await client.post(
        "/api/entities/convert",
        json={"entity_id": str(malware.id), "target_type": "cve"},
        headers=admin_headers,
    )
    assert resp.status_code == 400, resp.text

    # Bad format → 400.
    resp = await client.post(
        "/api/entities/convert",
        json={"entity_id": str(malware.id), "target_type": "cve", "target_identifier": "not-a-cve"},
        headers=admin_headers,
    )
    assert resp.status_code == 400, resp.text


async def test_convert_to_cve_creates_record_with_id(client, db_session, test_entry, admin_headers):
    malware = MalwareFamily(name="RegreSSHion", aliases=[])
    db_session.add(malware)
    await db_session.flush()
    db_session.add(EntryMalware(entry_id=test_entry.id, malware_family_id=malware.id, confidence="probable"))
    await db_session.flush()

    resp = await client.post(
        "/api/entities/convert",
        json={"entity_id": str(malware.id), "target_type": "cve", "target_identifier": "cve-2024-6387"},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "CVE-2024-6387"  # normalized upper-case

    cve = (await db_session.execute(select(CVE).where(CVE.cve_id == "CVE-2024-6387"))).scalar_one_or_none()
    assert cve is not None
    link = (
        await db_session.execute(select(EntryCVE).where(EntryCVE.cve_id == cve.id, EntryCVE.entry_id == test_entry.id))
    ).scalar_one_or_none()
    assert link is not None


async def test_convert_name_collision_conflicts(client, db_session, admin_headers):
    malware = MalwareFamily(name="Cobalt Strike", aliases=[])
    tool = Tool(name="Cobalt Strike", aliases=[])
    db_session.add_all([malware, tool])
    await db_session.flush()

    resp = await client.post(
        "/api/entities/convert",
        json={"entity_id": str(malware.id), "target_type": "tool"},
        headers=admin_headers,
    )
    assert resp.status_code == 409, resp.text


async def test_convert_same_type_rejected(client, db_session, admin_headers):
    vendor = Vendor(name="Cisco")
    db_session.add(vendor)
    await db_session.flush()
    resp = await client.post(
        "/api/entities/convert",
        json={"entity_id": str(vendor.id), "target_type": "vendor"},
        headers=admin_headers,
    )
    assert resp.status_code == 400, resp.text


# --- rename collision guard on the update endpoints ---


async def test_rename_to_existing_name_conflicts(client, db_session, admin_headers):
    keep = Vendor(name="Palo Alto Networks")
    rename_me = Vendor(name="PAN")
    db_session.add_all([keep, rename_me])
    await db_session.flush()

    resp = await client.put(
        f"/api/entities/vendors/{rename_me.id}",
        json={"name": "Palo Alto Networks"},
        headers=admin_headers,
    )
    assert resp.status_code == 409, resp.text


async def test_rename_happy_path(client, db_session, admin_headers):
    vendor = Vendor(name="Acme")
    db_session.add(vendor)
    await db_session.flush()

    resp = await client.put(
        f"/api/entities/vendors/{vendor.id}",
        json={"name": "Acme Corp"},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "Acme Corp"
