"""Tests for server-side read-aloud (Piper TTS): text normalization, cache keys,
the prepare endpoint, and cache eviction."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from app.config import settings
from app.models.tts_audio import TTSAudio
from app.services import tts
from app.services.tts_text import clean_for_speech, extract_paragraphs, normalize_plain_text, text_from_html

# ── text normalization ──────────────────────────────────────────────


def test_clean_for_speech_security_tokens():
    out = clean_for_speech(
        "CVE-2024-1234 at http://evil.com email a@b.com 8.8.8.8 hash deadbeefdeadbeefdeadbeefdeadbeef01 example.com"
    )
    assert "C V E 2024 1234" in out
    assert "link" in out
    assert "email address" in out
    assert "8 dot 8 dot 8 dot 8" in out
    assert "example dot com" in out
    assert "http" not in out and "evil.com" not in out


def test_extract_paragraphs_title_pre_and_dedup():
    html = "<h1>Heading</h1><p>Body one.</p><pre>malicious();</pre><ul><li>bullet item</li></ul>"
    paras = extract_paragraphs(html, "Article Title")
    assert paras[0] == "Article Title"
    assert "Code block." in paras  # <pre> is stubbed, not read literally
    assert any("Body one" in p for p in paras)
    assert any("bullet item" in p for p in paras)


def test_extract_paragraphs_plaintext_fallback():
    # No recognizable block tags → falls back to blank-line splitting.
    paras = extract_paragraphs("just some loose text", "T")
    assert paras[0] == "T"
    assert any("loose text" in p for p in paras)


def test_text_from_html_joins_with_blank_lines():
    text = text_from_html("<p>One.</p><p>Two.</p>", "Title")
    assert text.startswith("Title")
    assert "\n\n" in text


def test_normalize_plain_text():
    out = normalize_plain_text("Look at CVE-2023-0001\n\nand 1.2.3.4 too")
    assert "C V E 2023 0001" in out
    assert "1 dot 2 dot 3 dot 4" in out


# ── cache key ───────────────────────────────────────────────────────


def test_cache_key_stable_and_content_sensitive():
    a = tts.compute_cache_key("entry", "id1", "hello world", "v1")
    b = tts.compute_cache_key("entry", "id1", "hello world", "v1")
    c = tts.compute_cache_key("entry", "id1", "hello WORLD", "v1")
    d = tts.compute_cache_key("entry", "id1", "hello world", "v2")  # voice differs
    assert a == b
    assert a != c
    assert a != d
    assert len(a) == 64


def test_audio_path_is_sharded():
    key = "ab" + "c" * 62
    p = tts.audio_path(key)
    assert p.name == f"{key}.mp3"
    assert p.parent.name == "ab"


# ── prepare endpoint ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_prepare_entry_enqueues_and_returns_pending(client, auth_headers, test_entry):
    with patch("app.workers.tts_tasks.synthesize_tts.delay") as mock_delay:
        resp = await client.post(
            "/api/tts/prepare",
            json={"source": "entry", "id": str(test_entry.id)},
            headers=auth_headers,
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "pending"
    assert body["cache_key"] and len(body["cache_key"]) == 64
    mock_delay.assert_called_once()


@pytest.mark.asyncio
async def test_prepare_requires_auth(client, test_entry):
    resp = await client.post("/api/tts/prepare", json={"source": "entry", "id": str(test_entry.id)})
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_prepare_unknown_entry_404(client, auth_headers):
    import uuid

    with patch("app.workers.tts_tasks.synthesize_tts.delay"):
        resp = await client.post(
            "/api/tts/prepare",
            json={"source": "entry", "id": str(uuid.uuid4())},
            headers=auth_headers,
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_file_missing_returns_404(client, auth_headers):
    key = "0" * 64
    resp = await client.get(f"/api/tts/file/{key}.mp3", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_file_invalid_key_rejected(client, auth_headers):
    resp = await client.get("/api/tts/file/not-a-valid-key.mp3", headers=auth_headers)
    assert resp.status_code == 400


# ── eviction ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_evict_tts_cache_ttl_and_size(db_session, tmp_path, monkeypatch):
    from app.workers import maintenance

    monkeypatch.setattr(settings, "tts_media_dir", str(tmp_path))
    monkeypatch.setattr(settings, "tts_cache_ttl_days", 30)
    monkeypatch.setattr(settings, "tts_cache_max_bytes", 1000)

    # The eviction impl opens its own worker session; point it at the test session.
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _fake_session():
        yield db_session

    monkeypatch.setattr(maintenance, "_get_worker_session", _fake_session)

    def make(key, accessed_days_ago, size):
        path = tts.audio_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
        return TTSAudio(
            cache_key=key,
            source="entry",
            voice="v1",
            status="ready",
            byte_size=size,
            last_accessed_at=datetime.now(UTC) - timedelta(days=accessed_days_ago),
        )

    stale = make("a" * 64, 40, 500)  # past TTL → deleted
    hot_big = make("b" * 64, 0, 800)  # newest
    warm = make("c" * 64, 5, 800)  # older than hot_big, over cap → deleted by LRU
    db_session.add_all([stale, hot_big, warm])
    await db_session.flush()

    evicted = await maintenance._evict_tts_cache()

    assert evicted == 2
    assert not tts.audio_path("a" * 64).exists()  # TTL
    assert not tts.audio_path("c" * 64).exists()  # LRU (oldest surviving over cap)
    assert tts.audio_path("b" * 64).exists()  # newest kept
    assert await db_session.get(TTSAudio, "a" * 64) is None
    assert await db_session.get(TTSAudio, "b" * 64) is not None
