"""Tests for the research bundle export — multi-select entries and campaigns as a ZIP
of markdown + entities.md + iocs.csv + attack_layer.json."""

import io
import zipfile
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.campaign import Campaign, CampaignEntry
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP


@pytest_asyncio.fixture
async def bundle_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(title="Bundle Test Feed", url="https://bundle-test.example.com/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def bundle_entries(db_session: AsyncSession, bundle_feed: Feed):
    """Two entries: one with a linked actor + TTP + IOC-shaped content, one plain."""
    actor = ThreatActor(name="Bundle Test Actor")
    db_session.add(actor)
    await db_session.flush()

    ttp = TTP(technique_id="T1059.001", technique_name="PowerShell", tactic="execution")
    db_session.add(ttp)
    await db_session.flush()

    entry1 = Entry(
        feed_id=bundle_feed.id,
        title="Bundle Entry One",
        guid="bundle-entry-1",
        content_text="C2 server at 192.168.1.100 dropped a payload with hash d41d8cd98f00b204e9800998ecf8427e.",
        extracted_urls=[{"url": "https://evil.example.com/payload", "context": "dropped a payload"}],
        published_at=datetime(2026, 1, 10, tzinfo=UTC),
    )
    entry2 = Entry(
        feed_id=bundle_feed.id,
        title="Bundle Entry Two",
        guid="bundle-entry-2",
        content_text="Follow-up coverage.",
        published_at=datetime(2026, 1, 11, tzinfo=UTC),
    )
    db_session.add_all([entry1, entry2])
    await db_session.flush()

    db_session.add(EntryThreatActor(entry_id=entry1.id, threat_actor_id=actor.id, confidence="high", source="test"))
    db_session.add(EntryTTP(entry_id=entry1.id, ttp_id=ttp.id))
    await db_session.flush()

    # iocs.csv reads the observables ledger, so give entry1 judged rows: the
    # C2 IP and the payload hash. The private 192.168.1.100 in the prose must
    # NOT appear — prose is never swept into the export any more.
    from app.intelligence.observables import get_or_create_observable, record_sighting

    c2 = await get_or_create_observable(
        db_session, "ipv4", "45.155.204.119", via="ai_extraction", entry_id=entry1.id, role="c2"
    )
    await record_sighting(db_session, entry1.id, c2, source="ai")
    payload = await get_or_create_observable(
        db_session, "md5", "d41d8cd98f00b204e9800998ecf8427e", via="ai_extraction", entry_id=entry1.id
    )
    await record_sighting(db_session, entry1.id, payload, source="ai")
    await db_session.flush()

    return entry1, entry2, actor, ttp


@pytest.mark.asyncio
async def test_research_bundle_zip_structure(client: AsyncClient, auth_headers: dict, bundle_entries):
    entry1, entry2, actor, ttp = bundle_entries
    resp = await client.post(
        "/api/export/research-bundle",
        json={"entry_ids": [str(entry1.id), str(entry2.id)], "name": "Test Investigation"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = zf.namelist()
    assert any(n.startswith("entries/") and n.endswith(".md") for n in names)
    assert sum(1 for n in names if n.startswith("entries/")) == 2
    assert "entities.md" in names
    assert "iocs.csv" in names
    assert "attack_layer.json" in names
    assert "_manifest.txt" in names


@pytest.mark.asyncio
async def test_research_bundle_entities_md_lists_linked_entities(
    client: AsyncClient, auth_headers: dict, bundle_entries
):
    entry1, entry2, actor, ttp = bundle_entries
    resp = await client.post(
        "/api/export/research-bundle",
        json={"entry_ids": [str(entry1.id), str(entry2.id)]},
        headers=auth_headers,
    )
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    entities_md = zf.read("entities.md").decode()
    assert "Bundle Test Actor" in entities_md
    assert "T1059.001" in entities_md


@pytest.mark.asyncio
async def test_research_bundle_iocs_csv_extracts_indicators(client: AsyncClient, auth_headers: dict, bundle_entries):
    entry1, entry2, actor, ttp = bundle_entries
    resp = await client.post(
        "/api/export/research-bundle",
        json={"entry_ids": [str(entry1.id), str(entry2.id)]},
        headers=auth_headers,
    )
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    iocs_csv = zf.read("iocs.csv").decode()
    # Ledger rows are exported...
    assert "45.155.204.119" in iocs_csv
    assert "d41d8cd98f00b204e9800998ecf8427e" in iocs_csv
    # ...referenced URLs come along clearly labeled as references, not IOCs...
    assert "referenced_url,https://evil.example.com/payload" in iocs_csv
    # ...and the prose is never regex-swept: the private IP in the body of
    # entry1 must not be exported as an indicator (the v1 failure mode).
    assert "192.168.1.100" not in iocs_csv


@pytest.mark.asyncio
async def test_research_bundle_attack_layer_has_technique(client: AsyncClient, auth_headers: dict, bundle_entries):
    import json

    entry1, entry2, actor, ttp = bundle_entries
    resp = await client.post(
        "/api/export/research-bundle",
        json={"entry_ids": [str(entry1.id), str(entry2.id)]},
        headers=auth_headers,
    )
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    layer = json.loads(zf.read("attack_layer.json").decode())
    technique_ids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1059.001" in technique_ids


@pytest.mark.asyncio
async def test_research_bundle_handles_dict_shaped_extracted_urls(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, bundle_feed: Feed
):
    """extracted_urls holds {"url": ..., "context": ...} dicts in production, not bare
    strings (see schemas/entry.py) — regression test for a TypeError: unhashable type
    'dict' that only reproduced with real extracted_urls data, not a plain string list."""
    entry = Entry(
        feed_id=bundle_feed.id,
        title="Dict URL Entry",
        guid="dict-url-entry-1",
        content_text="No IOCs in the body.",
        extracted_urls=[{"url": "https://evil.example.com/payload", "context": "dropped a payload"}],
        published_at=datetime(2026, 1, 12, tzinfo=UTC),
    )
    db_session.add(entry)
    await db_session.flush()

    resp = await client.post(
        "/api/export/research-bundle",
        json={"entry_ids": [str(entry.id)]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    iocs_csv = zf.read("iocs.csv").decode()
    assert "https://evil.example.com/payload" in iocs_csv


@pytest.mark.asyncio
async def test_research_bundle_empty_entry_ids_rejected(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/export/research-bundle", json={"entry_ids": []}, headers=auth_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_campaign_bundle_export(
    client: AsyncClient, auth_headers: dict, test_user, db_session: AsyncSession, bundle_entries
):
    entry1, entry2, actor, ttp = bundle_entries
    campaign = Campaign(created_by=test_user.id, name="Bundle Test Campaign", status="active")
    db_session.add(campaign)
    await db_session.flush()
    db_session.add(CampaignEntry(campaign_id=campaign.id, entry_id=entry1.id, added_by=test_user.id))
    await db_session.flush()

    resp = await client.get(f"/api/export/campaigns/{campaign.id}/bundle", headers=auth_headers)
    assert resp.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = zf.namelist()
    assert sum(1 for n in names if n.startswith("entries/")) == 1
    entities_md = zf.read("entities.md").decode()
    assert "Bundle Test Actor" in entities_md


@pytest.mark.asyncio
async def test_campaign_bundle_not_found(client: AsyncClient, auth_headers: dict):
    import uuid

    resp = await client.get(f"/api/export/campaigns/{uuid.uuid4()}/bundle", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_campaign_bundle_no_entries(client: AsyncClient, auth_headers: dict, test_user, db_session: AsyncSession):
    campaign = Campaign(created_by=test_user.id, name="Empty Campaign", status="active")
    db_session.add(campaign)
    await db_session.flush()

    resp = await client.get(f"/api/export/campaigns/{campaign.id}/bundle", headers=auth_headers)
    assert resp.status_code == 400
