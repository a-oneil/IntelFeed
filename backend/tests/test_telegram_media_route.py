"""Tests for the auth-gated /api/telegram-media route."""

import os

import pytest
from httpx import AsyncClient

from app.config import settings


@pytest.fixture
def media_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "telegram_media_dir", str(tmp_path), raising=False)
    return tmp_path


@pytest.mark.asyncio
async def test_unauthenticated_returns_401(client: AsyncClient, media_dir):
    response = await client.get("/api/telegram-media/-100123/42.jpg")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_authenticated_returns_file(client: AsyncClient, auth_headers: dict, media_dir):
    channel_dir = media_dir / "-100123"
    channel_dir.mkdir()
    target = channel_dir / "42.jpg"
    target.write_bytes(b"\xff\xd8\xff\xe0fake-jpeg-bytes")

    response = await client.get("/api/telegram-media/-100123/42.jpg", headers=auth_headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/jpeg")
    assert response.content.startswith(b"\xff\xd8\xff\xe0")


@pytest.mark.asyncio
async def test_authenticated_missing_file_returns_404(client: AsyncClient, auth_headers: dict, media_dir):
    response = await client.get("/api/telegram-media/-100123/9999.jpg", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_path_traversal_blocked(client: AsyncClient, auth_headers: dict, media_dir):
    # Path components that would escape via .. — also rejected by the regex validator
    response = await client.get("/api/telegram-media/..%2F..%2Fetc/passwd", headers=auth_headers)
    assert response.status_code in (400, 404)


@pytest.mark.asyncio
async def test_invalid_filename_returns_400(client: AsyncClient, auth_headers: dict, media_dir):
    response = await client.get("/api/telegram-media/-100123/not-a-message-id.txt", headers=auth_headers)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_thumbnail_path_allowed(client: AsyncClient, auth_headers: dict, media_dir):
    channel_dir = media_dir / "-100123"
    channel_dir.mkdir()
    target = channel_dir / "42.thumb.jpg"
    target.write_bytes(b"thumb-bytes")
    response = await client.get("/api/telegram-media/-100123/42.thumb.jpg", headers=auth_headers)
    assert response.status_code == 200
    assert response.content == b"thumb-bytes"


# Cleanup helper: avoid leaving stray dirs around if the fixture path-monkeypatched
# during a test doesn't survive teardown.
def _cleanup(_path):
    if os.path.isdir(_path):
        for root, _, files in os.walk(_path, topdown=False):
            for f in files:
                try:
                    os.remove(os.path.join(root, f))
                except OSError:
                    pass
