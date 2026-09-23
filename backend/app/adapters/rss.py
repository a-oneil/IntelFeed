"""RSS/Atom feed adapter."""

import calendar
from datetime import UTC, datetime

import feedparser

from app.adapters.base import BaseAdapter, ParsedEntry, ParsedFeedMeta


class RSSAdapter(BaseAdapter):
    """Handles standard RSS and Atom feeds."""

    def parse_entries(self, feed_url: str, content: str) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        parsed = feedparser.parse(content)

        meta = ParsedFeedMeta(
            title=parsed.feed.get("title"),
            description=parsed.feed.get("description") or parsed.feed.get("subtitle"),
            site_url=parsed.feed.get("link"),
            icon_url=parsed.feed.get("image", {}).get("href") if hasattr(parsed.feed, "image") else None,
            language=parsed.feed.get("language"),
        )

        entries = []
        for item in parsed.entries:
            guid = item.get("id") or item.get("link") or item.get("title")
            if not guid:
                continue

            content_html = ""
            if item.get("content"):
                content_html = item.content[0].get("value", "")
            elif item.get("summary"):
                content_html = item.summary
            elif item.get("description"):
                content_html = item.description

            published_at = _parse_date(item)

            summary = item.get("summary", "")
            if summary and len(summary) > 500:
                summary = summary[:497] + "..."

            entry = ParsedEntry(
                guid=guid[:2000],
                url=item.get("link"),
                title=item.get("title", "Untitled")[:2000],
                author=item.get("author"),
                content_html=content_html,
                summary=summary[:5000] if summary else None,
                published_at=published_at,
            )
            entries.append(entry)

        return meta, entries


def _parse_date(item) -> datetime | None:
    """Parse date from a feedparser item."""
    for field in ("published_parsed", "updated_parsed"):
        parsed_time = item.get(field)
        if parsed_time:
            try:
                return datetime.fromtimestamp(calendar.timegm(parsed_time), tz=UTC)
            except (TypeError, ValueError, OverflowError):
                continue
    return None
