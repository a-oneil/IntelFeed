"""Fetch and parse podcast transcripts (SRT/VTT) into plain text."""

import logging
import re

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# Pattern to match SRT/VTT timestamp lines and sequence numbers
_TIMESTAMP_RE = re.compile(
    r"^\d{2}:\d{2}:\d{2}[.,]\d{3}\s*-->\s*\d{2}:\d{2}:\d{2}[.,]\d{3}.*$",
    re.MULTILINE,
)
_SEQUENCE_RE = re.compile(r"^\d+\s*$", re.MULTILINE)
_VTT_HEADER_RE = re.compile(r"^WEBVTT.*$", re.MULTILINE)
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def parse_transcript(text: str) -> str:
    """Parse SRT or VTT transcript text into plain text."""
    # Remove VTT header
    text = _VTT_HEADER_RE.sub("", text)
    # Remove timestamps
    text = _TIMESTAMP_RE.sub("", text)
    # Remove sequence numbers
    text = _SEQUENCE_RE.sub("", text)
    # Remove HTML tags (VTT can contain <c> tags etc.)
    text = _HTML_TAG_RE.sub("", text)
    # Clean up whitespace
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    # Deduplicate consecutive identical lines (common in VTT)
    deduped = []
    for line in lines:
        if not deduped or line != deduped[-1]:
            deduped.append(line)
    return " ".join(deduped)


async def fetch_transcript(url: str) -> str | None:
    """Fetch a transcript URL and parse SRT/VTT into plain text.

    Returns None if fetching or parsing fails.
    """
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=15.0,
            headers={"User-Agent": settings.user_agent},
        ) as client:
            response = await client.get(url)
            if response.status_code != 200:
                logger.debug(f"Transcript fetch returned {response.status_code}: {url}")
                return None

            text = response.text
            if not text or len(text) < 10:
                return None

            parsed = parse_transcript(text)
            return parsed if parsed else None

    except Exception as e:
        logger.debug(f"Transcript fetch failed for {url}: {e}")
        return None
