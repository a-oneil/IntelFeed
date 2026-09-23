import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entry import Entry
from app.models.feed import Feed
from app.models.tag import Tag
from app.models.user import User


@pytest_asyncio.fixture
async def test_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(title="Test Feed", url="https://example.com/feed2", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def test_entry(db_session: AsyncSession, test_feed: Feed) -> Entry:
    entry = Entry(feed_id=test_feed.id, title="Tag Test Entry", guid="tag-guid-1")
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest.mark.asyncio
async def test_create_tag(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/tags",
        json={"name": "critical-cve", "color": "#FF4444"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "critical-cve"
    assert data["color"] == "#FF4444"
    assert data["entry_count"] == 0


@pytest.mark.asyncio
async def test_create_duplicate_tag(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    tag = Tag(created_by=test_user.id, name="duplicate-tag", color="#000000")
    db_session.add(tag)
    await db_session.flush()

    resp = await client.post(
        "/api/tags",
        json={"name": "duplicate-tag"},
        headers=auth_headers,
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_list_tags(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    for name in ["alpha", "beta", "gamma"]:
        db_session.add(Tag(created_by=test_user.id, name=name))
    await db_session.flush()

    resp = await client.get("/api/tags", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 3
    names = [t["name"] for t in data]
    assert names == ["alpha", "beta", "gamma"]  # sorted


@pytest.mark.asyncio
async def test_update_tag(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    tag = Tag(created_by=test_user.id, name="old-name")
    db_session.add(tag)
    await db_session.flush()

    resp = await client.put(
        f"/api/tags/{tag.id}",
        json={"name": "new-name", "color": "#00FF00"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "new-name"
    assert data["color"] == "#00FF00"


@pytest.mark.asyncio
async def test_delete_tag(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    tag = Tag(created_by=test_user.id, name="to-delete")
    db_session.add(tag)
    await db_session.flush()

    resp = await client.delete(f"/api/tags/{tag.id}", headers=auth_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_add_tags_to_entry(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    test_entry: Entry,
    db_session: AsyncSession,
):
    tag = Tag(created_by=test_user.id, name="entry-tag")
    db_session.add(tag)
    await db_session.flush()

    resp = await client.post(
        f"/api/tags/entries/{test_entry.id}",
        json={"tag_ids": [str(tag.id)]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["added"] == 1


@pytest.mark.asyncio
async def test_remove_tag_from_entry(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    test_entry: Entry,
    db_session: AsyncSession,
):
    from app.models.tag import EntryTag

    tag = Tag(created_by=test_user.id, name="to-remove")
    db_session.add(tag)
    await db_session.flush()

    et = EntryTag(entry_id=test_entry.id, tag_id=tag.id)
    db_session.add(et)
    await db_session.flush()

    resp = await client.delete(
        f"/api/tags/entries/{test_entry.id}/{tag.id}",
        headers=auth_headers,
    )
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_bulk_tag(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    test_feed: Feed,
    db_session: AsyncSession,
):
    tag = Tag(created_by=test_user.id, name="bulk-tag")
    db_session.add(tag)
    e1 = Entry(feed_id=test_feed.id, title="E1", guid="bulk-1")
    e2 = Entry(feed_id=test_feed.id, title="E2", guid="bulk-2")
    db_session.add_all([e1, e2])
    await db_session.flush()

    resp = await client.post(
        "/api/tags/entries/bulk-tag",
        json={"entry_ids": [str(e1.id), str(e2.id)], "tag_ids": [str(tag.id)]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["added"] == 2


@pytest.mark.asyncio
async def test_bulk_untag(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    test_feed: Feed,
    db_session: AsyncSession,
):
    from app.models.tag import EntryTag

    tag = Tag(created_by=test_user.id, name="bulk-untag")
    e1 = Entry(feed_id=test_feed.id, title="U1", guid="untag-1")
    e2 = Entry(feed_id=test_feed.id, title="U2", guid="untag-2")
    db_session.add_all([tag, e1, e2])
    await db_session.flush()
    db_session.add_all(
        [
            EntryTag(entry_id=e1.id, tag_id=tag.id),
            EntryTag(entry_id=e2.id, tag_id=tag.id),
        ]
    )
    await db_session.flush()

    resp = await client.post(
        "/api/tags/entries/bulk-untag",
        json={"entry_ids": [str(e1.id), str(e2.id)], "tag_ids": [str(tag.id)]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["removed"] == 2

    tags_resp = await client.get(f"/api/tags/entries/{e1.id}", headers=auth_headers)
    assert tags_resp.json() == []


@pytest.mark.asyncio
async def test_merge_tags(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    test_feed: Feed,
    db_session: AsyncSession,
):
    from app.models.tag import EntryTag

    source = Tag(created_by=test_user.id, name="priority-critical")
    target = Tag(created_by=test_user.id, name="critical-cve")
    e1 = Entry(feed_id=test_feed.id, title="M1", guid="merge-1")
    e2 = Entry(feed_id=test_feed.id, title="M2", guid="merge-2")
    db_session.add_all([source, target, e1, e2])
    await db_session.flush()
    # e1 has only source; e2 has both (tests dedupe)
    db_session.add_all(
        [
            EntryTag(entry_id=e1.id, tag_id=source.id),
            EntryTag(entry_id=e2.id, tag_id=source.id),
            EntryTag(entry_id=e2.id, tag_id=target.id),
        ]
    )
    await db_session.flush()

    resp = await client.post(
        "/api/tags/merge",
        json={"source_ids": [str(source.id)], "target_id": str(target.id)},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "critical-cve"
    assert data["entry_count"] == 2  # e1 + e2, deduped

    # Source tag is gone
    list_resp = await client.get("/api/tags", headers=auth_headers)
    names = [t["name"] for t in list_resp.json()]
    assert "priority-critical" not in names
    assert "critical-cve" in names

    # e1 now carries the target tag
    e1_tags = await client.get(f"/api/tags/entries/{e1.id}", headers=auth_headers)
    assert [t["name"] for t in e1_tags.json()] == ["critical-cve"]
