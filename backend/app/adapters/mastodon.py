"""Mastodon adapter — fetches public posts from accounts or hashtag timelines."""

import hashlib
import logging
from datetime import datetime

import httpx

from app.adapters.base import ExtendedAdapter, ParsedEntry, ParsedFeedMeta

logger = logging.getLogger(__name__)


class MastodonAdapter(ExtendedAdapter):
    """Fetches public posts from a Mastodon instance."""

    async def fetch_entries(
        self, config: dict, since: datetime | None = None
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        instance_url = config.get("instance_url", "").rstrip("/")
        account_id = config.get("account_id")
        hashtags = config.get("hashtags", [])
        access_token = config.get("access_token")
        limit = min(config.get("limit", 40), 40)

        if not instance_url:
            return ParsedFeedMeta(), []

        headers = {"User-Agent": "IntelFeed/1.0"}
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"

        entries = []

        if account_id:
            entries = await self._fetch_account_posts(instance_url, account_id, headers, limit, since)
        elif hashtags:
            for tag in hashtags:
                tag_entries = await self._fetch_hashtag_timeline(instance_url, tag, headers, limit, since)
                entries.extend(tag_entries)
        else:
            return ParsedFeedMeta(title="Mastodon"), []

        # Build metadata
        if account_id:
            title = f"Mastodon: @{account_id}@{instance_url.replace('https://', '')}"
        else:
            title = f"Mastodon: #{', #'.join(hashtags)}"

        meta = ParsedFeedMeta(
            title=title,
            description=f"Posts from {instance_url}",
            site_url=instance_url,
        )

        return meta, entries

    async def _fetch_account_posts(
        self, instance_url: str, account_id: str, headers: dict, limit: int, since: datetime | None
    ) -> list[ParsedEntry]:
        url = f"{instance_url}/api/v1/accounts/{account_id}/statuses"
        params: dict = {"limit": limit, "exclude_replies": True, "exclude_reblogs": True}
        if since:
            params["since_id"] = "0"

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            response = await client.get(url, params=params)
            if response.status_code != 200:
                logger.warning(f"Mastodon API returned {response.status_code} for account {account_id}")
                return []

            statuses = response.json()

        return [self._status_to_entry(s, instance_url) for s in statuses if self._after_since(s, since)]

    async def _fetch_hashtag_timeline(
        self, instance_url: str, hashtag: str, headers: dict, limit: int, since: datetime | None
    ) -> list[ParsedEntry]:
        url = f"{instance_url}/api/v1/timelines/tag/{hashtag}"
        params: dict = {"limit": limit}

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            response = await client.get(url, params=params)
            if response.status_code != 200:
                logger.warning(f"Mastodon API returned {response.status_code} for #{hashtag}")
                return []

            statuses = response.json()

        return [self._status_to_entry(s, instance_url) for s in statuses if self._after_since(s, since)]

    def _status_to_entry(self, status: dict, instance_url: str) -> ParsedEntry:
        """Convert a Mastodon status to a ParsedEntry."""
        created = None
        if status.get("created_at"):
            try:
                created = datetime.fromisoformat(status["created_at"].replace("Z", "+00:00"))
            except ValueError:
                pass

        account = status.get("account", {})
        author = account.get("display_name") or account.get("username", "")
        acct = account.get("acct", "")

        # Use content (HTML) or fallback to plain text
        content_html = status.get("content", "")

        # Build title from first line of content (stripped of HTML)
        import re

        plain = re.sub(r"<[^>]+>", "", content_html).strip()
        title = plain[:120] + "..." if len(plain) > 120 else plain
        if not title:
            title = f"Post by @{acct}"

        return ParsedEntry(
            guid=hashlib.sha256(str(status.get("id", "")).encode()).hexdigest()[:32],
            url=status.get("url") or f"{instance_url}/@{acct}/{status.get('id', '')}",
            title=title,
            author=f"{author} (@{acct})" if author else f"@{acct}",
            content_html=content_html,
            published_at=created,
            metadata={
                "source": "mastodon",
                "instance": instance_url,
                "account": acct,
                "status_id": status.get("id"),
                "reblogs_count": status.get("reblogs_count", 0),
                "favourites_count": status.get("favourites_count", 0),
                "tags": [t.get("name") for t in status.get("tags", [])],
            },
        )

    def _after_since(self, status: dict, since: datetime | None) -> bool:
        if not since:
            return True
        created_str = status.get("created_at", "")
        if not created_str:
            return True
        try:
            created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            return created > since
        except ValueError:
            return True

    def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
        instance_url = config.get("instance_url", "")
        account_id = config.get("account_id")
        hashtags = config.get("hashtags", [])

        if account_id:
            title = f"Mastodon: @{account_id}"
        elif hashtags:
            title = f"Mastodon: #{', #'.join(hashtags)}"
        else:
            title = "Mastodon"

        return ParsedFeedMeta(
            title=title,
            description=f"Posts from {instance_url}",
            site_url=instance_url,
        )
