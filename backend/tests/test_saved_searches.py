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
