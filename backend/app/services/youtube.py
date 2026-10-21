"""YouTube-specific service utilities."""

import logging

import httpx

from app.config import settings
from app.services.rate_limiter import acquire_rate_limit

logger = logging.getLogger(__name__)


async def check_is_short(video_id: str) -> bool:
    """Check whether a YouTube video is a Short.

    Makes a HEAD request to https://www.youtube.com/shorts/{video_id}.
    YouTube returns 200 for Shorts and redirects (303) for regular videos.
    Fail-open: returns False on any error to avoid skipping real videos.
    """
    url = f"https://www.youtube.com/shorts/{video_id}"
    try:
        if not await acquire_rate_limit(url):
            logger.debug("Rate limited checking Shorts status for %s", video_id)
            return False

        async with httpx.AsyncClient(
            timeout=10.0,
            headers={"User-Agent": str(settings.get("user_agent") or settings.user_agent)},
            follow_redirects=False,
        ) as client:
            response = await client.head(url)
            return response.status_code == 200
    except Exception:
        logger.debug("Failed to check Shorts status for %s", video_id)
        return False


async def filter_shorts(video_ids: list[str]) -> set[str]:
    """Return the subset of video IDs that are YouTube Shorts.

    Checks sequentially to respect rate limiting against youtube.com.
    """
    shorts = set()
    for vid in video_ids:
        is_short = await check_is_short(vid)
        if is_short:
            shorts.add(vid)
    return shorts
