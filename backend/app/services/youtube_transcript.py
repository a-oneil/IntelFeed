"""Fetch YouTube video transcripts using the youtube-transcript-api library."""

import asyncio
import logging

from youtube_transcript_api import NoTranscriptFound, TranscriptsDisabled, YouTubeTranscriptApi

logger = logging.getLogger(__name__)

_ytt = YouTubeTranscriptApi()


def _fetch_transcript_sync(video_id: str) -> str | None:
    """Synchronous transcript fetch — run in executor."""
    try:
        transcript = _ytt.fetch(video_id, languages=["en", "en-US", "en-GB"])
        text = " ".join(snippet.text for snippet in transcript.snippets)
        return text.strip() if text.strip() else None
    except (TranscriptsDisabled, NoTranscriptFound):
        logger.debug("No transcript available for video %s", video_id)
        return None
    except Exception as e:
        logger.debug("Failed to fetch transcript for video %s: %s", video_id, e)
        return None


async def fetch_youtube_transcript(video_id: str) -> str | None:
    """Fetch transcript for a YouTube video. Returns plain text or None.

    Uses asyncio.to_thread since youtube-transcript-api is synchronous.
    """
    return await asyncio.to_thread(_fetch_transcript_sync, video_id)
