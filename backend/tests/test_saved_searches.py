import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.saved_search import SavedSearch
from app.models.user import User


@pytest.mark.asyncio
async def test_create_saved_search(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/saved-searches",
        json={"name": "Critical CVEs", "query": "CVE", "filters": {"tags": ["critical"]}},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Critical CVEs"
    assert data["query"] == "CVE"
    assert data["filters"]["tags"] == ["critical"]


@pytest.mark.asyncio
async def test_list_saved_searches(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    db_session: AsyncSession,
):
    for i in range(3):
        db_session.add(SavedSearch(created_by=test_user.id, name=f"Search {i}", query=f"q{i}"))
    await db_session.flush()

    resp = await client.get("/api/saved-searches", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 3


@pytest.mark.asyncio
async def test_update_saved_search(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    db_session: AsyncSession,
):
    saved = SavedSearch(created_by=test_user.id, name="Old Name", query="old")
    db_session.add(saved)
    await db_session.flush()

    resp = await client.put(
        f"/api/saved-searches/{saved.id}",
        json={"name": "New Name", "query": "new"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "New Name"
    assert resp.json()["query"] == "new"


@pytest.mark.asyncio
async def test_delete_saved_search(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    db_session: AsyncSession,
):
    saved = SavedSearch(created_by=test_user.id, name="Delete Me", query="x")
    db_session.add(saved)
    await db_session.flush()

    resp = await client.delete(f"/api/saved-searches/{saved.id}", headers=auth_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_saved_search_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.put(
        f"/api/saved-searches/{fake_id}",
        json={"name": "whatever"},
        headers=auth_headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_counts_scan_each_distinct_query_once_and_fetch_ids_only(
    db_session: AsyncSession, test_user: User, admin_user: User, monkeypatch
):
    """Two people saving the same query cost one Meilisearch scan; the unread
    count is still each person's own."""
    from datetime import UTC, datetime

    from app.api.saved_searches import _compute_counts_inline
    from app.models.entry import Entry
    from app.models.entry_state import UserEntryState
    from app.models.feed import Feed
    from app.search import meili_builder

    feed = Feed(title="Counts feed", url="https://counts.example/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entries = []
    for i in range(2):
        e = Entry(
            feed_id=feed.id,
            guid=f"counts-{i}",
            url=f"https://counts.example/{i}",
            title=f"Widget story {i}",
            published_at=datetime(2025, 1, 15, 12, i, 0, tzinfo=UTC),
        )
        db_session.add(e)
        entries.append(e)
    await db_session.flush()
    db_session.add(UserEntryState(user_id=test_user.id, entry_id=entries[0].id, is_read=True))
    mine = SavedSearch(created_by=test_user.id, name="Widgets", query="widget")
    theirs = SavedSearch(created_by=admin_user.id, name="Widgets", query="widget")
    db_session.add_all([mine, theirs])
    await db_session.flush()

    calls: list[tuple] = []

    def _search(plan, constraint=None, limit=20, offset=0, attributes_to_retrieve=None):
        calls.append((limit, attributes_to_retrieve))
        return {"hits": [{"id": str(e.id)} for e in entries], "estimatedTotalHits": 2}

    monkeypatch.setattr(meili_builder, "execute_entry_search", _search)

    hit_lists: dict = {}
    mine_counts = await _compute_counts_inline([mine], test_user.id, db_session, hit_lists)
    theirs_counts = await _compute_counts_inline([theirs], admin_user.id, db_session, hit_lists)

    assert mine_counts[str(mine.id)] == {"unread": 1, "total": 2}
    assert theirs_counts[str(theirs.id)] == {"unread": 2, "total": 2}
    assert calls == [(5000, ["id"])]
