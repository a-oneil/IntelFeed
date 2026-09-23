"""Server-side read-aloud (Piper TTS) orchestration.

On-demand + cache: the first "Listen" for a given (source, ref, content, voice)
enqueues a Celery synthesis job and returns ``pending``; the frontend polls
until ``ready`` and then plays the cached MP3 via the existing audio player.
Subsequent requests hit the cache and return ``ready`` immediately.

The audio bytes live on the ``tts_media`` disk volume keyed by cache_key; the
``tts_audio`` table tracks status/duration and drives LRU eviction.
"""

import hashlib
from pathlib import Path

from sqlalchemy import func as safunc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.tts_audio import TTSAudio


def compute_cache_key(source: str, ref_id: str | None, text: str, voice: str) -> str:
    """Stable key over source + ref + content + voice.

    Content is hashed so edited articles re-synthesize, and the same entry text
    reused by the authed reader and a public share link maps to one cached file.
    """
    content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    canonical = "|".join([source, ref_id or "", voice, content_hash])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def audio_path(cache_key: str) -> Path:
    """On-disk MP3 path for a cache key (2-char shard to keep dirs small)."""
    return Path(settings.tts_media_dir) / cache_key[:2] / f"{cache_key}.mp3"


def _payload(row: TTSAudio) -> dict:
    return {
        "cache_key": row.cache_key,
        "status": row.status,
        "duration": row.duration_seconds,
        "error": row.error,
    }


def _enqueue(cache_key: str, text: str, voice: str) -> None:
    # Lazy import so the API process doesn't pull in the Celery app at import time.
    from app.workers.tts_tasks import synthesize_tts

    synthesize_tts.delay(cache_key, text, voice)


async def get_or_enqueue(
    db: AsyncSession,
    *,
    source: str,
    ref_id: str | None,
    text: str,
    voice: str | None = None,
    ttl_days: float | None = None,
) -> dict:
    """Return status for the audio, enqueuing synthesis on a cache miss.

    ``ttl_days`` sets a per-row eviction override on a fresh (or re-synthesized)
    row — e.g. share pre-generation passes ``1.0`` so the audio lapses after ~24h.
    It's only applied when a row is (re)created, so it never *extends* audio the
    reader already cached under the default TTL.
    """
    voice = voice or settings.piper_voice
    text = (text or "").strip()
    if not text:
        return {"cache_key": None, "status": "error", "duration": None, "error": "no readable text"}
    if len(text) > settings.tts_max_text_chars:
        text = text[: settings.tts_max_text_chars]

    key = compute_cache_key(source, ref_id, text, voice)
    row = await db.get(TTSAudio, key)

    if row is not None:
        if row.status == "ready" and audio_path(key).exists():
            row.last_accessed_at = safunc.now()
            await db.commit()
            return _payload(row)
        if row.status == "pending":
            return _payload(row)
        # error, or "ready" but the file was evicted → re-synthesize.
        row.status = "pending"
        row.error = None
        if ttl_days is not None:
            row.ttl_days = ttl_days
        await db.commit()
        _enqueue(key, text, voice)
        return _payload(row)

    row = TTSAudio(
        cache_key=key, source=source, ref_id=(ref_id or None), voice=voice, status="pending", ttl_days=ttl_days
    )
    db.add(row)
    try:
        await db.commit()
    except IntegrityError:
        # A concurrent request created the row first — treat as pending.
        await db.rollback()
        existing = await db.get(TTSAudio, key)
        if existing is not None:
            return _payload(existing)
        raise
    _enqueue(key, text, voice)
    return {"cache_key": key, "status": "pending", "duration": None, "error": None}


async def resolve_summary_speech_text(
    db: AsyncSession,
    day_key: str,
    filters: dict | None,
    user_id=None,
) -> str | None:
    """Resolve a daily summary's speech text from the cached AIResult.

    Used by BOTH the morning pre-generation (user_id=None → global scope) and the
    on-click prepare, so they derive identical text → identical cache key → the
    pre-generated audio is a cache hit. Mirrors GET /entries/daily-summary scoping.
    """
    from sqlalchemy import select

    from app.api.entries import GLOBAL_SUMMARY_USER, _daily_summary_target_id, _scope_user_id
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask
    from app.services.tts_text import text_from_markdown

    filters = filters or {"dedup": True}
    task_id = (await db.execute(select(AITask.id).where(AITask.name == "daily_summary"))).scalar_one_or_none()
    if not task_id:
        return None
    scope = _scope_user_id(user_id, filters) if user_id else GLOBAL_SUMMARY_USER
    target_id = _daily_summary_target_id(scope, day_key, filters)
    row = (
        await db.execute(
            select(AIResult)
            .where(
                AIResult.target_type == "daily_summary",
                AIResult.target_id == target_id,
                AIResult.task_id == task_id,
                AIResult.is_current == True,  # noqa: E712
            )
            .order_by(AIResult.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if not row or not row.parsed_result or "summary" not in (row.parsed_result or {}):
        return None
    return text_from_markdown(row.parsed_result["summary"], None)


async def get_status(db: AsyncSession, cache_key: str) -> dict | None:
    row = await db.get(TTSAudio, cache_key)
    return _payload(row) if row is not None else None


async def touch(db: AsyncSession, cache_key: str) -> None:
    """Bump last_accessed_at so eviction treats served files as hot."""
    row = await db.get(TTSAudio, cache_key)
    if row is not None:
        row.last_accessed_at = safunc.now()
        await db.commit()
