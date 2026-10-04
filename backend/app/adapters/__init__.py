"""Feed source adapters."""

from app.adapters.base import BaseAdapter, ExtendedAdapter
from app.adapters.bluesky import BlueskyAdapter
from app.adapters.github import GitHubAdvisoriesAdapter, GitHubReleasesAdapter
from app.adapters.github_repo import GitHubRepoAdapter
from app.adapters.mastodon import MastodonAdapter
from app.adapters.nvd import NVDAdapter
from app.adapters.podcast import PodcastAdapter
from app.adapters.reddit import RedditAdapter
from app.adapters.rss import RSSAdapter
from app.adapters.telegram import TelegramAdapter
from app.adapters.web_scraper import WebScraperAdapter
from app.adapters.youtube import YouTubeAdapter

_ADAPTERS: dict[str, BaseAdapter] = {
    "rss": RSSAdapter(),
    "atom": RSSAdapter(),  # Atom uses same feedparser adapter
    "youtube": YouTubeAdapter(),
    "podcast": PodcastAdapter(),
}

_EXTENDED_ADAPTERS: dict[str, ExtendedAdapter] = {
    "reddit": RedditAdapter(),
    "github_releases": GitHubReleasesAdapter(),
    "github_advisories": GitHubAdvisoriesAdapter(),
    "github_repo": GitHubRepoAdapter(),
    "nvd": NVDAdapter(),
    "mastodon": MastodonAdapter(),
    "web_scraper": WebScraperAdapter(),
    "telegram": TelegramAdapter(),
    "bluesky": BlueskyAdapter(),
}


def get_adapter(feed_type: str) -> BaseAdapter:
    """Get the appropriate adapter for a feed type."""
    return _ADAPTERS.get(feed_type, _ADAPTERS["rss"])


def get_extended_adapter(feed_type: str) -> ExtendedAdapter | None:
    """Get an extended (API-based) adapter for a feed type, or None if not found."""
    return _EXTENDED_ADAPTERS.get(feed_type)


def is_extended_feed_type(feed_type: str) -> bool:
    """Check if a feed type uses an extended adapter."""
    return feed_type in _EXTENDED_ADAPTERS


def known_feed_types() -> frozenset[str]:
    """Every feed type that has an adapter behind it.

    The single source of truth for "is this a real feed type". Validators must
    derive their allowlist from this rather than keeping a hand-written copy:
    the update endpoint's own list had drifted to include `github` (no adapter —
    `get_adapter` silently fell back to RSS) while rejecting five types the
    registry serves, so the edit modal offered options the API refused.
    """
    return frozenset(_ADAPTERS) | frozenset(_EXTENDED_ADAPTERS)


__all__ = [
    "BaseAdapter",
    "ExtendedAdapter",
    "RSSAdapter",
    "YouTubeAdapter",
    "PodcastAdapter",
    "RedditAdapter",
    "GitHubReleasesAdapter",
    "GitHubAdvisoriesAdapter",
    "GitHubRepoAdapter",
    "NVDAdapter",
    "MastodonAdapter",
    "WebScraperAdapter",
    "TelegramAdapter",
    "BlueskyAdapter",
    "get_adapter",
    "get_extended_adapter",
    "is_extended_feed_type",
    "known_feed_types",
]
