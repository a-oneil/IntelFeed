"""Podcast RSS feed adapter with iTunes/podcast namespace support."""

import time
from datetime import UTC, datetime

import feedparser

from app.adapters.base import BaseAdapter, ParsedEntry, ParsedFeedMeta, ParsedMedia


class PodcastAdapter(BaseAdapter):
    """Handles podcast RSS feeds with iTunes and Podcast 2.0 namespace extensions."""

    def parse_entries(self, feed_url: str, content: str) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        parsed = feedparser.parse(content)
        feed = parsed.feed

        # Extract show-level podcast metadata
        artwork_url = None
        itunes_image = getattr(feed, "image", None)
        if itunes_image and isinstance(itunes_image, dict):
            artwork_url = itunes_image.get("href")
        if not artwork_url:
            # Try itunes:image
            artwork_url = getattr(feed, "itunes_image", {}).get("href") if hasattr(feed, "itunes_image") else None

        podcast_categories = []
        if hasattr(feed, "tags"):
            for tag in feed.tags:
                if tag.get("term"):
                    podcast_categories.append(tag["term"])

        meta = ParsedFeedMeta(
            title=feed.get("title"),
            description=feed.get("description") or feed.get("subtitle"),
            site_url=feed.get("link"),
            language=feed.get("language"),
            podcast_author=getattr(feed, "itunes_author", None) or feed.get("author"),
            podcast_categories=podcast_categories,
            podcast_explicit=_parse_explicit(getattr(feed, "itunes_explicit", None)),
            podcast_type=getattr(feed, "itunes_type", "episodic") or "episodic",
            podcast_artwork_url=artwork_url,
        )

        entries = []
        for item in parsed.entries:
            guid = item.get("id") or item.get("link") or item.get("title")
            if not guid:
                continue

            # Extract audio enclosure
            audio_url = None
            audio_mime = None
            audio_size = None
            for enclosure in getattr(item, "enclosures", []):
                enc_type = enclosure.get("type", "")
                if enc_type.startswith("audio/") or enc_type in ("", "application/octet-stream"):
                    audio_url = enclosure.get("href") or enclosure.get("url")
                    audio_mime = enc_type if enc_type.startswith("audio/") else "audio/mpeg"
                    try:
                        audio_size = int(enclosure.get("length", 0)) or None
                    except (ValueError, TypeError):
                        audio_size = None
                    break

            # Parse duration from itunes:duration
            duration_str = getattr(item, "itunes_duration", None)
            duration_seconds = parse_duration(duration_str) if duration_str else None

            # Episode artwork
            episode_artwork = None
            item_image = getattr(item, "image", None)
            if item_image and isinstance(item_image, dict):
                episode_artwork = item_image.get("href")

            # Episode number/season
            episode_number = getattr(item, "itunes_episode", None)
            season_number = getattr(item, "itunes_season", None)
            episode_type = getattr(item, "itunes_episodetype", "full")

            # Transcript URL
            transcript_url = None
            podcast_transcript = getattr(item, "podcast_transcript", None)
            if podcast_transcript and isinstance(podcast_transcript, dict):
                transcript_url = podcast_transcript.get("url")

            # Content
            content_html = ""
            if item.get("content"):
                content_html = item.content[0].get("value", "")
            elif item.get("summary"):
                content_html = item.summary
            elif item.get("description"):
                content_html = item.description

            summary = item.get("summary") or item.get("subtitle", "")
            if summary and len(summary) > 500:
                summary = summary[:497] + "..."

            published_at = _parse_date(item)

            entry_metadata = {
                "episode_number": int(episode_number) if episode_number else None,
                "season_number": int(season_number) if season_number else None,
                "episode_type": episode_type,
                "is_explicit": _parse_explicit(getattr(item, "itunes_explicit", None)),
            }

            media = None
            if audio_url:
                media = ParsedMedia(
                    media_type="audio",
                    url=audio_url,
                    mime_type=audio_mime,
                    file_size=audio_size,
                    duration_seconds=duration_seconds,
                    thumbnail_url=episode_artwork or artwork_url,
                    transcript_url=transcript_url,
                )

            entry = ParsedEntry(
                guid=guid[:2000],
                url=item.get("link"),
                title=item.get("title", "Untitled")[:2000],
                author=getattr(item, "itunes_author", None) or item.get("author") or meta.podcast_author,
                content_html=content_html,
                summary=summary[:5000] if summary else None,
                published_at=published_at,
                metadata=entry_metadata,
                media=media,
            )
            entries.append(entry)

        return meta, entries


def parse_duration(duration_str: str) -> int | None:
    """Parse iTunes duration format to seconds.

    Accepts:
        - "HH:MM:SS"
        - "MM:SS"
        - "seconds" (plain integer)
    """
    if not duration_str:
        return None

    duration_str = duration_str.strip()

    # Plain seconds
    if duration_str.isdigit():
        return int(duration_str)

    # HH:MM:SS or MM:SS
    parts = duration_str.split(":")
    try:
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        elif len(parts) == 2:
            return int(parts[0]) * 60 + int(parts[1])
    except (ValueError, IndexError):
        pass

    return None


def _parse_explicit(value) -> bool:
    if value is None:
        return False
    return str(value).lower() in ("yes", "true", "1", "explicit")


def _parse_date(item) -> datetime | None:
    for field in ("published_parsed", "updated_parsed"):
        parsed_time = item.get(field)
        if parsed_time:
            try:
                return datetime.fromtimestamp(time.mktime(parsed_time), tz=UTC)
            except (TypeError, ValueError, OverflowError):
                continue
    return None
