"""Mitigations are ATT&CK catalog rows only; an article's own advice is stored on the entry-mitigation link."""

import pytest
from sqlalchemy import func, select

from app.intelligence.mitigation import extract_mitigation_ids_regex, store_mitigations
from app.models.entry import Entry
from app.models.mitigation import EntryMitigation, Mitigation


def _catalog(mitre_id: str, name: str) -> Mitigation:
    return Mitigation(
        mitre_id=mitre_id,
        name=name,
        mitre_url=f"https://attack.mitre.org/mitigations/{mitre_id}",
        is_catalog=True,
        article_count=0,
    )


@pytest.fixture
async def catalog(db_session):
    rows = {
        "M1051": _catalog("M1051", "Update Software"),
        "M1047": _catalog("M1047", "Audit"),
        "M0947": _catalog("M0947", "Audit"),
    }
    db_session.add_all(rows.values())
    await db_session.flush()
    return rows


@pytest.fixture
async def entry(db_session, test_feed):
    e = Entry(feed_id=test_feed.id, title="advisory", guid="mit-cat", url="https://example.com/mit-cat")
    db_session.add(e)
    await db_session.flush()
    return e


async def _mitigation_count(db_session) -> int:
    return await db_session.scalar(select(func.count()).select_from(Mitigation))


async def _links(db_session, entry_id) -> dict:
    rows = await db_session.execute(
        select(Mitigation.mitre_id, EntryMitigation.detail)
        .join(EntryMitigation, EntryMitigation.mitigation_id == Mitigation.id)
        .where(EntryMitigation.entry_id == entry_id)
    )
    return dict(rows.all())


@pytest.mark.asyncio
async def test_store_links_catalog_and_creates_nothing(db_session, catalog, entry):
    before = await _mitigation_count(db_session)
    stored = await store_mitigations(
        db_session,
        entry.id,
        [
            {"mitre_id": "M1051", "name": "Update Software", "detail": "Upgrade Lara Dashboard to 1.3.2 or later"},
            {"mitre_id": "", "name": "Patch"},  # generic phrase, no catalog row
            {"mitre_id": "M1206", "name": "Update Proxmox VE"},  # invented M-ID
            {"mitre_id": "M-0001", "name": "Upgrade to @fastify/busboy version 3.2.1"},
        ],
    )
    assert [m.mitre_id for m, _ in stored] == ["M1051"]
    assert await _mitigation_count(db_session) == before
    assert await _links(db_session, entry.id) == {"M1051": "Upgrade Lara Dashboard to 1.3.2 or later"}
    assert catalog["M1051"].article_count == 1


@pytest.mark.asyncio
async def test_name_match_prefers_enterprise_and_keeps_first_detail(db_session, catalog, entry):
    await store_mitigations(db_session, entry.id, [{"name": "audit", "description": "Review admin logins weekly"}])
    # Re-analysis of the same article: the link stays, its first wording stays, no double count.
    await store_mitigations(db_session, entry.id, [{"mitre_id": "M1047", "name": "Audit", "detail": "Something else"}])
    assert await _links(db_session, entry.id) == {"M1047": "Review admin logins weekly"}
    assert catalog["M1047"].article_count == 1


@pytest.mark.asyncio
async def test_detail_drops_the_bare_catalog_name(db_session, catalog, entry):
    await store_mitigations(db_session, entry.id, [{"mitre_id": "M1051", "name": "Update Software"}])
    assert await _links(db_session, entry.id) == {"M1051": None}


@pytest.mark.asyncio
async def test_regex_mid_only_links_catalog(db_session, catalog, entry):
    items = extract_mitigation_ids_regex("Apply M1051 and M1999 now.")
    stored = await store_mitigations(db_session, entry.id, items)
    assert [m.mitre_id for m, _ in stored] == ["M1051"]


@pytest.mark.asyncio
async def test_non_catalog_row_with_same_id_is_ignored(db_session, entry):
    """An AI-written row with a real-looking M-ID is not the catalog."""
    db_session.add(Mitigation(mitre_id="M1087", name="Account Auditing", article_count=1))
    await db_session.flush()
    assert await store_mitigations(db_session, entry.id, [{"mitre_id": "M1087", "name": "Account Auditing"}]) == []


@pytest.mark.asyncio
async def test_manual_create_links_catalog_only(client, auth_headers, catalog, entry):
    ok = await client.post(
        "/api/entities/mitigations",
        json={"mitre_id": "M1051", "description": "Patch the VPN appliance", "entry_id": str(entry.id)},
        headers=auth_headers,
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["id"] == str(catalog["M1051"].id)

    refused = await client.post("/api/entities/mitigations", json={"name": "Patch"}, headers=auth_headers)
    assert refused.status_code == 400
