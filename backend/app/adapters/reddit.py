"""Reddit adapter — fetches /hot.rss for each subreddit.

Reddit blocked unauthenticated JSON API access, so we use the public RSS feed.
RSS gives us no engagement numbers, but `/hot.rss` is already ordered by Reddit's
hot algorithm, so we store the rank position as a synthetic `score` to keep the
digest's "top posts" sort working.
"""

import hashlib
import logging
import re
from datetime import UTC, datetime

import httpx

from app.adapters.base import ExtendedAdapter, ParsedEntry, ParsedFeedMeta

logger = logging.getLogger(__name__)

REDDIT_USER_AGENT = "IntelFeed/1.0 (RSS Aggregator; +https://github.com/intelfeed)"
DEFAULT_LIMIT = 50
MAX_LIMIT = 100


class RedditAdapter(ExtendedAdapter):
    """Fetches posts from a subreddit's /hot.rss feed."""

    async def fetch_entries(
        self,
        config: dict,
        since: datetime | None = None,
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        subreddit = (config.get("subreddit") or "").strip().lstrip("/")
        if not subreddit:
            logger.warning("Reddit adapter called with no subreddit in config")
            return ParsedFeedMeta(), []

        limit = min(int(config.get("limit") or DEFAULT_LIMIT), MAX_LIMIT)

        meta = ParsedFeedMeta(
            title=f"r/{subreddit}",
            description=f"Hot posts from r/{subreddit}",
            site_url=f"https://www.reddit.com/r/{subreddit}/",
        )

        url = f"https://www.reddit.com/r/{subreddit}/hot.rss?limit={limit}"
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=30.0,
            headers={"User-Agent": REDDIT_USER_AGENT},
        ) as client:
            response = await client.get(url)

        if response.status_code != 200:
            logger.warning("Reddit /hot.rss returned %d for r/%s", response.status_code, subreddit)
            return meta, []

        import feedparser

        parsed = feedparser.parse(response.text)
        entries: list[ParsedEntry] = []
        for idx, item in enumerate(parsed.entries):
            published = None
            if getattr(item, "published_parsed", None):
                published = datetime(*item.published_parsed[:6], tzinfo=UTC)
            elif getattr(item, "updated_parsed", None):
                published = datetime(*item.updated_parsed[:6], tzinfo=UTC)

            guid_raw = getattr(item, "id", "") or getattr(item, "link", "")
            if not guid_raw:
                continue

            content_html = ""
            if getattr(item, "content", None):
                content_html = item.content[0].get("value", "") or ""
            elif getattr(item, "summary", None):
                content_html = item.summary or ""

            link = getattr(item, "link", None)
            entries.append(
                ParsedEntry(
                    guid=hashlib.sha256(guid_raw.encode()).hexdigest()[:32],
                    url=link,
                    title=getattr(item, "title", "Untitled"),
                    author=_clean_author(getattr(item, "author", None)),
                    content_html=content_html,
                    published_at=published,
                    metadata={
                        "source": "reddit",
                        "subreddit": subreddit,
                        "reddit_url": link or "",
                        "hot_rank": idx + 1,
                        # Synthetic engagement proxy so the digest's score-desc sort
                        # picks the top of /hot.rss. Real score isn't available via RSS.
                        "score": max(limit - idx, 1),
                    },
                )
            )

        return meta, entries

    def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
        subreddit = (config.get("subreddit") or "unknown").strip().lstrip("/")
        return ParsedFeedMeta(
            title=f"r/{subreddit}",
            description=f"Hot posts from r/{subreddit}",
            site_url=f"https://www.reddit.com/r/{subreddit}/",
        )


_AUTHOR_PREFIX = re.compile(r"^/u/", re.IGNORECASE)


def _clean_author(raw: str | None) -> str | None:
    if not raw:
        return None
    return _AUTHOR_PREFIX.sub("", raw.strip()) or None
