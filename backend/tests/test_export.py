import io
import zipfile

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entry import Entry
from app.models.feed import Feed
from app.models.note import Note
from app.models.user import User


@pytest_asyncio.fixture
async def test_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(title="Export Feed", url="https://example.com/export", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def test_entry(db_session: AsyncSession, test_feed: Feed) -> Entry:
    entry = Entry(
        feed_id=test_feed.id,
        title="Export Test Article",
        guid="export-guid",
        content_text="Article body content",
        author="Author Name",
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest.mark.asyncio
async def test_export_entry_markdown(
    client: AsyncClient,
    auth_headers: dict,
    test_entry: Entry,
):
    resp = await client.get(f"/api/export/entries/{test_entry.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert "text/markdown" in resp.headers["content-type"]
    content = resp.text
    assert "# Export Test Article" in content
    assert "**Source**: Export Feed" in content
    assert "**Author**: Author Name" in content
    assert "Article body content" in content
    assert "Exported from IntelFeed" in content


@pytest.mark.asyncio
async def test_export_note_markdown(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    db_session: AsyncSession,
):
    note = Note(created_by=test_user.id, title="Export Note", content_markdown="## Analysis\n\nDetails here")
    db_session.add(note)
    await db_session.flush()

    resp = await client.get(f"/api/export/notes/{note.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert "text/markdown" in resp.headers["content-type"]
    content = resp.text
    assert "# Export Note" in content
    assert "## Analysis" in content


@pytest.mark.asyncio
async def test_bulk_export_zip(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    test_entry: Entry,
    db_session: AsyncSession,
):
    note = Note(created_by=test_user.id, title="Zip Note", content_markdown="zip content")
    db_session.add(note)
    await db_session.flush()

    resp = await client.post(
        "/api/export/bulk",
        json={"entry_ids": [str(test_entry.id)], "note_ids": [str(note.id)]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"

    # Verify it's a valid zip
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = zf.namelist()
    assert any("entries/" in n for n in names)
    assert any("notes/" in n for n in names)


@pytest.mark.asyncio
async def test_export_entry_not_found(client: AsyncClient, auth_headers: dict):
    import uuid

    resp = await client.get(f"/api/export/entries/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 404


@pytest_asyncio.fixture
async def test_actor(db_session: AsyncSession, test_entry: Entry):
    from app.models.threat_actor import EntryThreatActor, ThreatActor

    actor = ThreatActor(
        name="APT-Export",
        aliases=["Export Bear"],
        country="Testland",
        motivation="espionage",
        description="An actor used in export tests.",
        article_count=1,
    )
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=test_entry.id, threat_actor_id=actor.id))
    await db_session.flush()
    return actor


@pytest.mark.asyncio
async def test_export_entity_profile_markdown(
    client: AsyncClient,
    auth_headers: dict,
    test_actor,
):
    resp = await client.get(f"/api/export/entities/threat_actor/{test_actor.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert "text/markdown" in resp.headers["content-type"]
    assert 'filename="APT-Export.md"' in resp.headers["content-disposition"]
    content = resp.text
    assert "# APT-Export" in content
    assert "**Type:** Threat Actor" in content
    assert "Export Bear" in content
    assert "An actor used in export tests." in content
    assert "## Linked Articles" in content
    assert "Export Test Article" in content


@pytest.mark.asyncio
async def test_export_entity_profile_invalid_type(
    client: AsyncClient,
    auth_headers: dict,
):
    import uuid

    resp = await client.get(f"/api/export/entities/bogus/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_export_entity_profile_not_found(
    client: AsyncClient,
    auth_headers: dict,
):
    import uuid

    resp = await client.get(f"/api/export/entities/threat_actor/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_bulk_export_entities_by_ids(
    client: AsyncClient,
    auth_headers: dict,
    test_actor,
):
    resp = await client.post(
        "/api/export/entities/bulk",
        json={"entity_type": "threat_actor", "entity_ids": [str(test_actor.id)]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = zf.namelist()
    assert "_manifest.txt" in names
    assert any(n.startswith("threat_actor/") and n.endswith(".md") for n in names)
    md_name = next(n for n in names if n.endswith(".md"))
    assert "# APT-Export" in zf.read(md_name).decode()


@pytest.mark.asyncio
async def test_bulk_export_entities_all(
    client: AsyncClient,
    auth_headers: dict,
    test_actor,
):
    resp = await client.post(
        "/api/export/entities/bulk",
        json={"entity_type": "threat_actor", "all": True},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    assert any(n.endswith("APT-Export.md") for n in zf.namelist())


@pytest.mark.asyncio
async def test_bulk_export_entities_empty(
    client: AsyncClient,
    auth_headers: dict,
):
    resp = await client.post(
        "/api/export/entities/bulk",
        json={"entity_type": "threat_actor", "entity_ids": []},
        headers=auth_headers,
    )
    assert resp.status_code == 400
