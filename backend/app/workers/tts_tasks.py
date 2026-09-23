"""Celery task: synthesize read-aloud audio via the Piper sidecar.

Runs on the default ``celery`` queue (CPU-bound, off the API request path — a
long article can take ~20s to synthesize and must not tie up a gunicorn worker).
Writes the MP3 to the shared tts_media volume atomically and flips the
``tts_audio`` row to ready/error for the frontend's status poll.
"""

import logging
import time

import httpx

from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.models.tts_audio import TTSAudio
from app.services.tts import audio_path
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)

# MP3 bitrate the piper sidecar encodes at; used to estimate duration. The
# player reads the true duration from the audio element on load, so this is
# only for pre-play display.
_MP3_BITRATE = 48000


# Transient piper unavailability (restart/OOM recovery window) surfaces as these
# httpx errors — retry with backoff and keep the row "pending" rather than failing.
_TRANSIENT = (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError, httpx.ReadError)


@celery_app.task(
    bind=True,
    name="app.workers.tts_tasks.synthesize_tts",
    max_retries=4,
    # Long daily summaries (~13 min audio) synthesize slowly under CPU contention;
    # this runs in the background (pre-gen or after the user has navigated on).
    soft_time_limit=900,
    time_limit=960,
)
def synthesize_tts(self, cache_key: str, text: str, voice: str):
    start = time.monotonic()
    try:
        run_async(_synthesize(cache_key, text, voice))
        CELERY_TASKS_TOTAL.labels(task_name="synthesize_tts", status="success").inc()
    except _TRANSIENT as exc:
        # Piper likely restarting — retry with backoff, leave row pending.
        logger.warning("TTS synthesis transient error for %s (retry %d): %s", cache_key, self.request.retries, exc)
        try:
            raise self.retry(exc=exc, countdown=min(2**self.request.retries, 30))
        except self.MaxRetriesExceededError:
            CELERY_TASKS_TOTAL.labels(task_name="synthesize_tts", status="error").inc()
            run_async(_mark_error(cache_key, f"piper unreachable: {str(exc)[:200]}"))
            raise
    except Exception as exc:
        CELERY_TASKS_TOTAL.labels(task_name="synthesize_tts", status="error").inc()
        run_async(_mark_error(cache_key, str(exc)[:400]))
        logger.warning("TTS synthesis failed for %s: %s", cache_key, exc)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="synthesize_tts").observe(time.monotonic() - start)


async def _synthesize(cache_key: str, text: str, voice: str) -> None:
    path = audio_path(cache_key)
    path.parent.mkdir(parents=True, exist_ok=True)

    async with httpx.AsyncClient(timeout=settings.piper_timeout_seconds) as client:
        resp = await client.post(f"{settings.piper_url}/synthesize", json={"text": text})
        resp.raise_for_status()
        audio = resp.content

    if not audio:
        raise ValueError("piper returned empty audio")

    # Atomic publish: write to a temp sibling then rename.
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(audio)
    tmp.replace(path)

    byte_size = len(audio)
    duration = round(byte_size * 8 / _MP3_BITRATE, 1) if byte_size else None

    async with worker_session() as db:
        row = await db.get(TTSAudio, cache_key)
        if row is not None:
            row.status = "ready"
            row.byte_size = byte_size
            row.duration_seconds = duration
            row.error = None
            await db.commit()


async def _mark_error(cache_key: str, message: str) -> None:
    async with worker_session() as db:
        row = await db.get(TTSAudio, cache_key)
        if row is not None:
            row.status = "error"
            row.error = message
            await db.commit()
