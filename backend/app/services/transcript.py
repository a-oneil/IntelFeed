"""Fetch and parse podcast transcripts (SRT/VTT) into plain text."""

import logging
import re

from app.config import settings
from app.core.safe_http import safe_async_client

logger = logging.getLogger(__name__)

# Pattern to match SRT/VTT timestamp lines and sequence numbers
_TIMESTAMP_RE = re.compile(
    r"^\d{2}:\d{2}:\d{2}[.,]\d{3}\s*-->\s*\d{2}:\d{2}:\d{2}[.,]\d{3}.*$",
    re.MULTILINE,
)
_SEQUENCE_RE = re.compile(r"^\d+\s*$", re.MULTILINE)
_VTT_HEADER_RE = re.compile(r"^WEBVTT.*$", re.MULTILINE)
_HTML_TAG_RE = re.compile(r"<[^>]+>")

# The URL comes from a feed (<podcast:transcript>), so it is fetched through the
# SSRF-guarded client, read only up to this size, and only kept when it is text.
_MAX_TRANSCRIPT_BYTES = 2 * 1024 * 1024
_TRANSCRIPT_TYPES = ("text/", "application/x-subrip", "application/srt", "application/vtt")


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
        async with safe_async_client(
            follow_redirects=True,
            timeout=15.0,
            headers={"User-Agent": str(settings.get("user_agent") or settings.user_agent)},
        ) as client:
            async with client.stream("GET", url) as response:
                if response.status_code != 200:
                    logger.debug(f"Transcript fetch returned {response.status_code}: {url}")
                    return None
                content_type = response.headers.get("content-type", "").lower()
                if content_type and not content_type.startswith(_TRANSCRIPT_TYPES):
                    logger.debug("Transcript at %s is %s, not text; skipped", url, content_type)
                    return None
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) > _MAX_TRANSCRIPT_BYTES:
                        logger.debug("Transcript at %s is over %d bytes; skipped", url, _MAX_TRANSCRIPT_BYTES)
                        return None
                text = body.decode(response.encoding or "utf-8", errors="replace")
            if not text or len(text) < 10:
                return None

            parsed = parse_transcript(text)
            return parsed if parsed else None

    except Exception as e:
        logger.debug(f"Transcript fetch failed for {url}: {e}")
        return None
