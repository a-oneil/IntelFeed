import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.note import Note
from app.models.user import User


@pytest_asyncio.fixture
async def test_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(title="Test Feed", url="https://example.com/feed", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def test_entry(db_session: AsyncSession, test_feed: Feed) -> Entry:
    entry = Entry(
        feed_id=test_feed.id,
        title="Test Entry",
        guid="test-guid-1",
        content_text="Some content here",
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest_asyncio.fixture
async def other_user(db_session: AsyncSession) -> User:
    user = User(
        username="otheruser",
        password_hash=hash_password("otherpassword"),
        role="user",
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def other_headers(other_user: User) -> dict:
    token = create_access_token(other_user.id, other_user.role)
    return {"Authorization": f"Bearer {token}"}


# --- Create standalone note ---


@pytest.mark.asyncio
async def test_create_standalone_note(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/notes",
        json={"title": "My Note", "content_markdown": "## Hello\n\nWorld"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "My Note"
    assert data["content_markdown"] == "## Hello\n\nWorld"
    assert data["content_html"] is not None
    assert "<h2" in data["content_html"]
    assert data["entry_id"] is None
    assert data["is_pinned"] is False
    assert data["tags"] == []
    assert data["id"] is not None
    assert data["created_at"] is not None
    assert data["updated_at"] is not None


@pytest.mark.asyncio
async def test_create_note_with_html_content(client: AsyncClient, auth_headers: dict):
    """Frontend TipTap editor sends HTML as content_markdown — must not crash."""
    resp = await client.post(
        "/api/notes",
        json={"title": "HTML Note", "content_markdown": "<p>Hi there</p>"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "HTML Note"
    assert data["content_html"] is not None


@pytest.mark.asyncio
async def test_create_note_minimal(client: AsyncClient, auth_headers: dict):
    """Only title is required; everything else should default."""
    resp = await client.post(
        "/api/notes",
        json={"title": "Minimal"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Minimal"
    assert data["content_markdown"] == ""
    assert data["is_pinned"] is False
    assert data["tags"] == []


@pytest.mark.asyncio
async def test_create_note_pinned(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/notes",
        json={"title": "Pinned", "content_markdown": "important", "is_pinned": True},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["is_pinned"] is True


@pytest.mark.asyncio
async def test_create_note_with_tags(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/notes",
        json={"title": "Tagged", "content_markdown": "content", "tags": ["cve", "malware"]},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    assert set(resp.json()["tags"]) == {"cve", "malware"}


@pytest.mark.asyncio
async def test_create_note_empty_title_rejected(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/notes",
        json={"title": "", "content_markdown": "content"},
        headers=auth_headers,
    )
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_create_note_missing_title_rejected(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/notes",
        json={"content_markdown": "no title"},
        headers=auth_headers,
    )
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_create_note_unauthenticated(client: AsyncClient):
    resp = await client.post(
        "/api/notes",
        json={"title": "Should fail"},
    )
    assert resp.status_code == 401


# --- Create entry note ---


@pytest.mark.asyncio
async def test_create_entry_note(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    resp = await client.post(
        f"/api/notes/entry/{test_entry.id}",
        json={"title": "Entry Analysis", "content_markdown": "Important finding"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["entry_id"] == str(test_entry.id)
    assert data["title"] == "Entry Analysis"


@pytest.mark.asyncio
async def test_create_entry_note_needs_no_subscription(client: AsyncClient, other_headers: dict, test_entry: Entry):
    """Feeds are shared, so any user can annotate any entry.

    Notes used to be gated on a per-user feed subscription; entries are now
    platform-wide, and the endpoint only checks that the entry exists.
    """
    resp = await client.post(
        f"/api/notes/entry/{test_entry.id}",
        json={"title": "Anyone can annotate", "content_markdown": "ok"},
        headers=other_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["entry_id"] == str(test_entry.id)


@pytest.mark.asyncio
async def test_create_entry_note_nonexistent_entry(client: AsyncClient, auth_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.post(
        f"/api/notes/entry/{fake_id}",
        json={"title": "Nope", "content_markdown": "nothing"},
        headers=auth_headers,
    )
    assert resp.status_code == 404


# --- Get single note ---


@pytest.mark.asyncio
async def test_get_note(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    note = Note(created_by=test_user.id, title="Fetch Me", content_markdown="body")
    db_session.add(note)
    await db_session.flush()

    resp = await client.get(f"/api/notes/{note.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["title"] == "Fetch Me"


@pytest.mark.asyncio
async def test_get_note_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/notes/{fake_id}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_note_created_by_another_user(
    client: AsyncClient, other_headers: dict, test_user: User, db_session: AsyncSession
):
    """Notes are a shared workspace; the creator is recorded but does not gate reads."""
    note = Note(created_by=test_user.id, title="Shared finding", content_markdown="detail")
    db_session.add(note)
    await db_session.flush()

    resp = await client.get(f"/api/notes/{note.id}", headers=other_headers)
    assert resp.status_code == 200
    assert resp.json()["title"] == "Shared finding"
    assert resp.json()["created_by"] == str(test_user.id)


# --- List notes ---


@pytest.mark.asyncio
async def test_list_notes(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    for i in range(3):
        note = Note(created_by=test_user.id, title=f"Note {i}", content_markdown=f"Content {i}")
        db_session.add(note)
    await db_session.flush()

    resp = await client.get("/api/notes", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3


@pytest.mark.asyncio
async def test_list_notes_pagination(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    for i in range(5):
        db_session.add(Note(created_by=test_user.id, title=f"Note {i}", content_markdown=""))
    await db_session.flush()

    resp = await client.get("/api/notes?limit=2&offset=0", headers=auth_headers)
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["total"] == 5
    assert data["has_more"] is True

    resp2 = await client.get("/api/notes?limit=2&offset=4", headers=auth_headers)
    data2 = resp2.json()
    assert len(data2["items"]) == 1
    assert data2["has_more"] is False


@pytest.mark.asyncio
async def test_list_notes_filter_pinned(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    db_session.add(Note(created_by=test_user.id, title="Pinned", content_markdown="", is_pinned=True))
    db_session.add(Note(created_by=test_user.id, title="Unpinned", content_markdown="", is_pinned=False))
    await db_session.flush()

    resp = await client.get("/api/notes?is_pinned=true", headers=auth_headers)
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["title"] == "Pinned"


@pytest.mark.asyncio
async def test_list_notes_filter_by_entry(
    client: AsyncClient, auth_headers: dict, test_user: User, test_entry: Entry, db_session: AsyncSession
):
    db_session.add(Note(created_by=test_user.id, entry_id=test_entry.id, title="Entry note", content_markdown=""))
    db_session.add(Note(created_by=test_user.id, title="Standalone", content_markdown=""))
    await db_session.flush()

    resp = await client.get(f"/api/notes?entry_id={test_entry.id}", headers=auth_headers)
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["title"] == "Entry note"


@pytest.mark.asyncio
async def test_list_notes_shows_notes_from_all_users(
    client: AsyncClient, other_headers: dict, test_user: User, db_session: AsyncSession
):
    """The note list is shared, and each row carries its creator for attribution."""
    db_session.add(Note(created_by=test_user.id, title="Written by someone else", content_markdown=""))
    await db_session.flush()

    resp = await client.get("/api/notes", headers=other_headers)
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["title"] == "Written by someone else"
    assert data["items"][0]["created_by"] == str(test_user.id)


@pytest.mark.asyncio
async def test_list_notes_includes_entry_and_feed_title(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    test_feed: Feed,
    test_entry: Entry,
    db_session: AsyncSession,
):
    db_session.add(Note(created_by=test_user.id, entry_id=test_entry.id, title="With entry", content_markdown=""))
    await db_session.flush()

    resp = await client.get("/api/notes", headers=auth_headers)
    item = resp.json()["items"][0]
    assert item["entry_title"] == "Test Entry"
    assert item["feed_title"] == "Test Feed"


# --- Update note ---


@pytest.mark.asyncio
async def test_update_note(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    note = Note(created_by=test_user.id, title="Original", content_markdown="original content")
    db_session.add(note)
    await db_session.flush()

    resp = await client.put(
        f"/api/notes/{note.id}",
        json={"title": "Updated", "content_markdown": "**bold** content"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "Updated"
    assert "<strong>" in data["content_html"]


@pytest.mark.asyncio
async def test_update_note_partial(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    """Partial update — only title, content stays the same."""
    note = Note(created_by=test_user.id, title="Old Title", content_markdown="keep this")
    db_session.add(note)
    await db_session.flush()

    resp = await client.put(
        f"/api/notes/{note.id}",
        json={"title": "New Title"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "New Title"
    assert data["content_markdown"] == "keep this"


@pytest.mark.asyncio
async def test_update_note_pin(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    note = Note(created_by=test_user.id, title="Pin Me", content_markdown="", is_pinned=False)
    db_session.add(note)
    await db_session.flush()

    resp = await client.put(
        f"/api/notes/{note.id}",
        json={"is_pinned": True},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["is_pinned"] is True


@pytest.mark.asyncio
async def test_update_note_tags(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    note = Note(created_by=test_user.id, title="Tag Me", content_markdown="")
    db_session.add(note)
    await db_session.flush()

    resp = await client.put(
        f"/api/notes/{note.id}",
        json={"tags": ["apt", "c2"]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert set(resp.json()["tags"]) == {"apt", "c2"}


@pytest.mark.asyncio
async def test_update_note_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.put(
        f"/api/notes/{fake_id}",
        json={"title": "Nope"},
        headers=auth_headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_note_created_by_another_user(
    client: AsyncClient, other_headers: dict, test_user: User, db_session: AsyncSession
):
    """Only the author (or an admin) may edit a note — another user gets 403."""
    note = Note(created_by=test_user.id, title="Draft", content_markdown="")
    db_session.add(note)
    await db_session.flush()

    resp = await client.put(
        f"/api/notes/{note.id}",
        json={"title": "Edited by a colleague"},
        headers=other_headers,
    )
    assert resp.status_code == 403

    # The note is unchanged (still readable by everyone)
    resp = await client.get(f"/api/notes/{note.id}", headers=other_headers)
    assert resp.status_code == 200
    assert resp.json()["title"] == "Draft"


@pytest.mark.asyncio
async def test_update_note_created_by_another_user_admin_allowed(
    client: AsyncClient, admin_headers: dict, test_user: User, db_session: AsyncSession
):
    """An admin may edit any note regardless of author."""
    note = Note(created_by=test_user.id, title="Draft", content_markdown="")
    db_session.add(note)
    await db_session.flush()

    resp = await client.put(
        f"/api/notes/{note.id}",
        json={"title": "Edited by an admin"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["title"] == "Edited by an admin"


# --- Delete note ---


@pytest.mark.asyncio
async def test_delete_note(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    note = Note(created_by=test_user.id, title="To Delete", content_markdown="")
    db_session.add(note)
    await db_session.flush()

    resp = await client.delete(f"/api/notes/{note.id}", headers=auth_headers)
    assert resp.status_code == 204

    # Verify it's gone
    resp2 = await client.get(f"/api/notes/{note.id}", headers=auth_headers)
    assert resp2.status_code == 404


@pytest.mark.asyncio
async def test_delete_note_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.delete(f"/api/notes/{fake_id}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_note_created_by_another_user(
    client: AsyncClient, other_headers: dict, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    """Only the author (or an admin) may delete a note — another user gets 403."""
    note = Note(created_by=test_user.id, title="Obsolete", content_markdown="")
    db_session.add(note)
    await db_session.flush()

    resp = await client.delete(f"/api/notes/{note.id}", headers=other_headers)
    assert resp.status_code == 403

    still_there = await client.get(f"/api/notes/{note.id}", headers=auth_headers)
    assert still_there.status_code == 200
    assert still_there.json()["title"] == "Obsolete"


# --- List entry notes ---


@pytest.mark.asyncio
async def test_list_entry_notes(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    test_entry: Entry,
    db_session: AsyncSession,
):
    note = Note(
        created_by=test_user.id,
        entry_id=test_entry.id,
        title="Entry Note",
        content_markdown="analysis",
    )
    db_session.add(note)
    await db_session.flush()

    resp = await client.get(f"/api/notes/entry/{test_entry.id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["title"] == "Entry Note"


@pytest.mark.asyncio
async def test_list_entry_notes_empty(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    resp = await client.get(f"/api/notes/entry/{test_entry.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []
