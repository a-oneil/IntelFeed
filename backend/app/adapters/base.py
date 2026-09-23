"""Base adapter for feed source types."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ParsedEntry:
    """Normalized entry from any feed type."""

    guid: str
    url: str | None = None
    title: str = "Untitled"
    author: str | None = None
    content_html: str | None = None
    summary: str | None = None
    published_at: datetime | None = None
    metadata: dict = field(default_factory=dict)
    # Primary media attachment (if any)
    media: "ParsedMedia | None" = None
    # Extra attachments — only the Telegram adapter populates this today, when an
    # album of grouped messages collapses into a single entry. Kept as a separate
    # list so existing single-media adapters don't change shape.
    additional_media: list["ParsedMedia"] = field(default_factory=list)


@dataclass
class ParsedMedia:
    """Media attachment parsed from a feed entry."""

    media_type: str  # audio, video, image, document
    url: str
    mime_type: str | None = None
    file_size: int | None = None
    duration_seconds: int | None = None
    thumbnail_url: str | None = None
    transcript_url: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class ParsedFeedMeta:
    """Feed-level metadata returned after parsing."""

    title: str | None = None
    description: str | None = None
    site_url: str | None = None
    icon_url: str | None = None
    language: str | None = None
    # Podcast show-level metadata
    podcast_author: str | None = None
    podcast_categories: list[str] = field(default_factory=list)
    podcast_explicit: bool = False
    podcast_type: str = "episodic"
    podcast_artwork_url: str | None = None
    # Generic bag for adapter-specific state (e.g. GitHub head SHA)
    extra: dict = field(default_factory=dict)


class BaseAdapter(ABC):
    """Abstract base for feed source adapters.

    Each adapter knows how to parse a specific feed type and return
    normalized ParsedEntry objects.
    """

    @abstractmethod
    def parse_entries(self, feed_url: str, content: str) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        """Parse raw feed content and return (feed_metadata, entries).

        Args:
            feed_url: The URL this content was fetched from.
            content: Raw response body (XML, JSON, etc.).

        Returns:
            Tuple of (feed-level metadata, list of parsed entries).
        """

    @staticmethod
    def detect_feed_type(url: str, content: str) -> str:
        """Detect feed type from URL and content. Returns feed_type string."""
        import feedparser

        if "youtube.com" in url:
            return "youtube"

        parsed = feedparser.parse(content)

        # Check for podcast indicators
        feed = parsed.feed
        if hasattr(feed, "itunes_type") or hasattr(feed, "itunes_author"):
            return "podcast"

        for entry in parsed.entries[:5]:
            for enclosure in getattr(entry, "enclosures", []):
                if enclosure.get("type", "").startswith("audio/"):
                    return "podcast"

        if "atom" in getattr(parsed, "version", "").lower():
            return "atom"

        return "rss"


class ExtendedAdapter(ABC):
    """Base for API-based source adapters that fetch entries directly.

    Unlike BaseAdapter (which parses raw feed text), ExtendedAdapter
    makes its own HTTP requests to external APIs and returns parsed entries.
    """

    @abstractmethod
    async def fetch_entries(
        self, config: dict, since: datetime | None = None
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        """Fetch entries from the external source.

        Args:
            config: Adapter-specific configuration from the Feed model.
            since: Only fetch entries newer than this timestamp.

        Returns:
            Tuple of (feed-level metadata, list of parsed entries).
        """

    @abstractmethod
    def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
        """Return feed-level metadata for display without fetching entries."""
