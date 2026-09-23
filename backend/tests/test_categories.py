import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.category import Category
from app.models.feed import Feed
from app.models.user import User


@pytest.mark.asyncio
async def test_list_categories_empty(client: AsyncClient, auth_headers: dict):
    response = await client.get("/api/categories", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data == []


@pytest.mark.asyncio
async def test_create_category(client: AsyncClient, auth_headers: dict):
    response = await client.post(
        "/api/categories",
        json={"name": "Security Blogs", "position": 1},
        headers=auth_headers,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Security Blogs"
    assert data["position"] == 1
    assert data["parent_id"] is None
    assert data["feed_count"] == 0
    assert "id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_update_category(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    category = Category(
        created_by=test_user.id,
        name="Old Name",
        position=0,
    )
    db_session.add(category)
    await db_session.flush()

    response = await client.put(
        f"/api/categories/{category.id}",
        json={"name": "New Name", "position": 5},
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "New Name"
    assert data["position"] == 5


@pytest.mark.asyncio
async def test_delete_category(client: AsyncClient, admin_headers: dict, test_user: User, db_session: AsyncSession):
    category = Category(
        created_by=test_user.id,
        name="To Delete",
        position=0,
    )
    db_session.add(category)
    await db_session.flush()

    response = await client.delete(f"/api/categories/{category.id}", headers=admin_headers)
    assert response.status_code == 204

    # Verify it no longer appears in the list
    response = await client.get("/api/categories", headers=admin_headers)
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_delete_category_moves_feeds(
    client: AsyncClient, admin_headers: dict, test_user: User, db_session: AsyncSession
):
    # Create a category with a feed attached
    category = Category(
        created_by=test_user.id,
        name="Doomed Category",
        position=0,
    )
    db_session.add(category)
    await db_session.flush()

    feed = Feed(
        title="Feed In Category",
        url="https://category-feed.com/rss",
        feed_type="rss",
        category_id=category.id,
    )
    db_session.add(feed)
    await db_session.flush()

    # Delete the category
    response = await client.delete(f"/api/categories/{category.id}", headers=admin_headers)
    assert response.status_code == 204

    # Verify the feed still exists but with category_id set to None
    response = await client.get("/api/feeds", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["category_id"] is None


@pytest.mark.asyncio
async def test_delete_category_requires_admin(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    """The folder tree is shared; only admins may delete a category."""
    category = Category(created_by=test_user.id, name="Keep Me")
    db_session.add(category)
    await db_session.flush()

    response = await client.delete(f"/api/categories/{category.id}", headers=auth_headers)
    assert response.status_code == 403
