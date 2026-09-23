"""Tests for BE-14: Entity notes API."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entity_note import EntityNote
from app.models.user import User


@pytest_asyncio.fixture
async def test_entity_note(db_session: AsyncSession, test_user: User) -> EntityNote:
    note = EntityNote(
        entity_type="threat_actor",
        entity_id=uuid.uuid4(),
        user_id=test_user.id,
        content="Analysis of actor behavior",
        note_type="analysis",
    )
    db_session.add(note)
    await db_session.flush()
    return note


@pytest.mark.asyncio
async def test_create_entity_note(client: AsyncClient, auth_headers: dict):
    entity_id = str(uuid.uuid4())
    resp = await client.post(
        "/api/entity-notes",
        json={
            "entity_type": "cve",
            "entity_id": entity_id,
            "content": "This CVE affects our production environment",
            "note_type": "action_taken",
            "tags": ["production", "urgent"],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["content"] == "This CVE affects our production environment"
    assert data["note_type"] == "action_taken"
    assert data["tags"] == ["production", "urgent"]
    assert data["username"] == "testuser"


@pytest.mark.asyncio
async def test_list_entity_notes(client: AsyncClient, auth_headers: dict, test_entity_note: EntityNote):
    resp = await client.get(
        f"/api/entity-notes?entity_type={test_entity_note.entity_type}&entity_id={test_entity_note.entity_id}",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


@pytest.mark.asyncio
async def test_update_entity_note(client: AsyncClient, auth_headers: dict, test_entity_note: EntityNote):
    resp = await client.put(
        f"/api/entity-notes/{test_entity_note.id}",
        json={"content": "Updated analysis", "note_type": "context"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["content"] == "Updated analysis"
    assert resp.json()["note_type"] == "context"


@pytest.mark.asyncio
async def test_delete_entity_note(client: AsyncClient, auth_headers: dict, test_entity_note: EntityNote):
    resp = await client.delete(f"/api/entity-notes/{test_entity_note.id}", headers=auth_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_invalid_entity_type(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/entity-notes",
        json={
            "entity_type": "invalid",
            "entity_id": str(uuid.uuid4()),
            "content": "Test",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_filter_by_note_type(client: AsyncClient, auth_headers: dict, test_entity_note: EntityNote):
    resp = await client.get(
        f"/api/entity-notes?entity_type={test_entity_note.entity_type}&entity_id={test_entity_note.entity_id}&note_type=analysis",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
