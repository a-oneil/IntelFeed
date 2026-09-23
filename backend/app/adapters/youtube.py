"""YouTube channel feed adapter."""

import re
import time
from datetime import UTC, datetime

import feedparser

from app.adapters.base import BaseAdapter, ParsedEntry, ParsedFeedMeta, ParsedMedia

# YouTube Atom namespace prefixes
YT_VIDEO_RE = re.compile(r"yt:video:(.+)")
YT_CHANNEL_RE = re.compile(r"yt:channel:(.+)")


class YouTubeAdapter(BaseAdapter):
    """Handles YouTube channel RSS/Atom feeds."""

    def parse_entries(self, feed_url: str, content: str) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        parsed = feedparser.parse(content)

        # Extract channel-level info
        channel_id = None
        channel_id_match = re.search(r"channel_id=([^&]+)", feed_url)
        if channel_id_match:
            channel_id = channel_id_match.group(1)

        meta = ParsedFeedMeta(
            title=parsed.feed.get("title"),
            description=parsed.feed.get("subtitle"),
            site_url=parsed.feed.get("link"),
        )

        entries = []
        for item in parsed.entries:
            guid = item.get("id") or item.get("link")
            if not guid:
                continue

            # Extract video ID
            video_id = None
            yt_videoid = item.get("yt_videoid")
            if yt_videoid:
                video_id = yt_videoid
            else:
                vid_match = YT_VIDEO_RE.match(guid)
                if vid_match:
                    video_id = vid_match.group(1)
                elif "watch?v=" in (item.get("link") or ""):
                    video_id = re.search(r"watch\?v=([^&]+)", item.get("link", "")).group(1)

            # Extract thumbnail and metadata from media namespace
            thumbnail_url = None
            view_count = None
            star_rating = None

            media_group = item.get("media_group") or {}
            if isinstance(media_group, list):
                media_group = media_group[0] if media_group else {}

            media_thumbnail = item.get("media_thumbnail")
            if media_thumbnail and isinstance(media_thumbnail, list):
                thumbnail_url = media_thumbnail[0].get("url")
            elif video_id:
                thumbnail_url = f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg"

            media_stats = item.get("media_statistics")
            if media_stats:
                view_count = int(media_stats.get("views", 0)) if media_stats.get("views") else None

            media_rating = item.get("media_starrating")
            if media_rating:
                star_rating = float(media_rating.get("average", 0)) if media_rating.get("average") else None

            # Build description
            description = item.get("summary") or ""
            media_desc = item.get("media_description")
            if media_desc:
                description = media_desc

            published_at = _parse_date(item)
            video_url = f"https://www.youtube.com/watch?v={video_id}" if video_id else item.get("link")

            entry_metadata = {
                "video_id": video_id,
                "channel_id": channel_id or item.get("yt_channelid"),
                "channel_name": item.get("author") or parsed.feed.get("title"),
                "view_count": view_count,
                "star_rating": star_rating,
                "embed_url": f"https://www.youtube.com/embed/{video_id}" if video_id else None,
            }

            media = (
                ParsedMedia(
                    media_type="video",
                    url=video_url or "",
                    mime_type="text/html",
                    thumbnail_url=thumbnail_url,
                    duration_seconds=None,  # Not available in RSS feed
                )
                if video_id
                else None
            )

            entry = ParsedEntry(
                guid=guid[:2000],
                url=video_url,
                title=item.get("title", "Untitled")[:2000],
                author=item.get("author") or parsed.feed.get("title"),
                content_html=_format_description(description) if description else None,
                summary=description[:500] if description else None,
                published_at=published_at,
                metadata=entry_metadata,
                media=media,
            )
            entries.append(entry)

        return meta, entries


_URL_RE = re.compile(r"(https?://[^\s<>\"')\]]+)")


def _format_description(text: str) -> str:
    """Convert plain-text YouTube description to HTML with linked URLs and preserved line breaks."""
    import html as html_mod

    escaped = html_mod.escape(text)
    # Convert URLs to clickable links
    linked = _URL_RE.sub(r'<a href="\1" target="_blank" rel="noopener noreferrer">\1</a>', escaped)
    # Convert newlines to <br> tags
    formatted = linked.replace("\n", "<br>\n")
    return f"<div>{formatted}</div>"


def _parse_date(item) -> datetime | None:
    for field in ("published_parsed", "updated_parsed"):
        parsed_time = item.get(field)
        if parsed_time:
            try:
                return datetime.fromtimestamp(time.mktime(parsed_time), tz=UTC)
            except (TypeError, ValueError, OverflowError):
                continue
    return None
