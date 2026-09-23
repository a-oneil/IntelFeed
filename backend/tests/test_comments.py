"""Tests for BE-17: Comment system API."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.comment import Comment
from app.models.user import User


@pytest_asyncio.fixture
async def test_comment(db_session: AsyncSession, test_user: User) -> Comment:
    comment = Comment(
        commentable_type="entry",
        commentable_id=uuid.uuid4(),
        user_id=test_user.id,
        content="Test comment content",
    )
    db_session.add(comment)
    await db_session.flush()
    return comment


@pytest.mark.asyncio
async def test_create_comment(client: AsyncClient, auth_headers: dict):
    commentable_id = str(uuid.uuid4())
    resp = await client.post(
        "/api/comments",
        json={
            "commentable_type": "entry",
            "commentable_id": commentable_id,
            "content": "This is a test comment",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["content"] == "This is a test comment"
    assert data["commentable_type"] == "entry"
    assert data["commentable_id"] == commentable_id
    assert data["parent_id"] is None
    assert data["username"] == "testuser"


@pytest.mark.asyncio
async def test_create_threaded_comment(client: AsyncClient, auth_headers: dict, test_comment: Comment):
    resp = await client.post(
        "/api/comments",
        json={
            "commentable_type": test_comment.commentable_type,
            "commentable_id": str(test_comment.commentable_id),
            "content": "This is a reply",
            "parent_id": str(test_comment.id),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["parent_id"] == str(test_comment.id)


@pytest.mark.asyncio
async def test_list_comments(client: AsyncClient, auth_headers: dict, test_comment: Comment):
    resp = await client.get(
        f"/api/comments?commentable_type={test_comment.commentable_type}&commentable_id={test_comment.commentable_id}",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1


@pytest.mark.asyncio
async def test_update_own_comment(client: AsyncClient, auth_headers: dict, test_comment: Comment):
    resp = await client.patch(
        f"/api/comments/{test_comment.id}",
        json={"content": "Updated content"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["content"] == "Updated content"


@pytest.mark.asyncio
async def test_delete_own_comment(client: AsyncClient, auth_headers: dict, test_comment: Comment):
    resp = await client.delete(f"/api/comments/{test_comment.id}", headers=auth_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_delete_nonexistent_comment(client: AsyncClient, auth_headers: dict):
    resp = await client.delete(f"/api/comments/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_invalid_commentable_type(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/comments",
        json={
            "commentable_type": "invalid_type",
            "commentable_id": str(uuid.uuid4()),
            "content": "Test",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_comment_with_mention(client: AsyncClient, auth_headers: dict, test_user: User):
    resp = await client.post(
        "/api/comments",
        json={
            "commentable_type": "entry",
            "commentable_id": str(uuid.uuid4()),
            "content": f"Hey @{test_user.username} check this out",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_list_mentions(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/comments/mentions", headers=auth_headers)
    assert resp.status_code == 200
    assert "items" in resp.json()
