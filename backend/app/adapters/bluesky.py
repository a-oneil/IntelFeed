"""Bluesky adapter — fetches public posts via the AT Protocol XRPC API.

Supports three ingest modes:
- author: every post from a single Bluesky handle/DID.
- feed:   an algorithmic / curated feed (custom feed generator) by AT-URI.
- search: posts matching a query string.

Read-only. No auth required; an optional app-password lifts rate limits.
"""

from __future__ import annotations

import hashlib
import html as html_lib
import json
import logging
import time
from datetime import datetime
from typing import Any

import httpx

from app.adapters.base import ExtendedAdapter, ParsedEntry, ParsedFeedMeta, ParsedMedia
from app.core.encryption import decrypt_value

logger = logging.getLogger(__name__)


PUBLIC_BASE = "https://public.api.bsky.app/xrpc"
DEFAULT_PDS = "https://bsky.social"

USER_AGENT = "IntelFeed/1.0 (+https://github.com/intelfeed)"

AUTHOR_PAGE_SIZE = 50
FEED_PAGE_SIZE = 50
SEARCH_PAGE_SIZE = 25


def _stable_guid(cid: str) -> str:
    """Truncated SHA-256 of the post CID. CIDs are content-addressed, so this
    is stable across re-fetches even if the post is deleted."""
    return hashlib.sha256(cid.encode()).hexdigest()[:32]


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _rkey_from_uri(uri: str) -> str:
    if not uri:
        return ""
    return uri.rsplit("/", 1)[-1]


def _bsky_post_url(handle: str, uri: str) -> str:
    rkey = _rkey_from_uri(uri)
    if not handle or not rkey:
        return ""
    return f"https://bsky.app/profile/{handle}/post/{rkey}"


# Redis-backed JWT cache. Falls back to in-process dict if Redis is unavailable
# (e.g. unit tests). Key: bluesky:session:<feed_id>, value: JSON {jwt, refresh, exp}.
_REDIS_KEY = "bluesky:session:{feed_id}"
_SESSION_TTL_SECONDS = 90 * 60
_session_cache_local: dict[str, tuple[str, str, float]] = {}


async def _read_session(feed_id: str) -> tuple[str, str, float] | None:
    if not feed_id:
        return None
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        raw = await r.get(_REDIS_KEY.format(feed_id=feed_id))
        if raw:
            data = json.loads(raw)
            return data.get("jwt", ""), data.get("refresh", ""), float(data.get("exp", 0))
    except Exception:
        # Fall through to local cache
        pass
    return _session_cache_local.get(feed_id)


async def _write_session(feed_id: str, jwt: str, refresh: str, exp: float) -> None:
    if not feed_id:
        return
    _session_cache_local[feed_id] = (jwt, refresh, exp)
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        await r.set(
            _REDIS_KEY.format(feed_id=feed_id),
            json.dumps({"jwt": jwt, "refresh": refresh, "exp": exp}),
            ex=_SESSION_TTL_SECONDS,
        )
    except Exception:
        pass


async def _invalidate_session(feed_id: str) -> None:
    if not feed_id:
        return
    _session_cache_local.pop(feed_id, None)
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        await r.delete(_REDIS_KEY.format(feed_id=feed_id))
    except Exception:
        pass


class _RateLimited(Exception):
    pass


class _AuthError(Exception):
    pass


class BlueskyAdapter(ExtendedAdapter):
    """Fetches posts from Bluesky via the AT Protocol XRPC API."""

    PUBLIC_BASE = PUBLIC_BASE
    AUTH_BASE_DEFAULT = DEFAULT_PDS

    async def fetch_entries(
        self,
        config: dict,
        since: datetime | None = None,
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        mode = (config.get("mode") or "author").lower()
        if mode not in {"author", "feed", "search"}:
            logger.warning("Bluesky adapter: unknown mode %r, defaulting to author", mode)
            mode = "author"

        feed_id = str(config.get("_feed_id") or "")
        access_jwt = await self._ensure_session(config, feed_id)

        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if access_jwt:
            headers["Authorization"] = f"Bearer {access_jwt}"

        last_seen_cid = config.get("last_seen_cid")
        max_per_poll = int(config.get("max_per_poll") or 50)

        try:
            if mode == "author":
                handle = (config.get("handle") or "").strip()
                if not handle:
                    return ParsedFeedMeta(title="Bluesky"), []
                posts, _ = await self._fetch_author(
                    handle=handle,
                    headers=headers,
                    filter_=config.get("filter") or "posts_no_replies",
                    include_reposts=bool(config.get("include_reposts")),
                    max_items=max_per_poll,
                    last_seen_cid=last_seen_cid,
                    since=since,
                )
                title = f"Bluesky: @{handle}"
            elif mode == "feed":
                feed_uri = (config.get("feed_uri") or "").strip()
                if not feed_uri:
                    return ParsedFeedMeta(title="Bluesky"), []
                posts, _ = await self._fetch_feed_uri(
                    feed_uri=feed_uri,
                    headers=headers,
                    max_items=max_per_poll,
                    last_seen_cid=last_seen_cid,
                    since=since,
                )
                title = f"Bluesky feed: {feed_uri}"
            else:  # search
                query = (config.get("query") or "").strip()
                if not query:
                    return ParsedFeedMeta(title="Bluesky"), []
                posts, _ = await self._fetch_search(
                    query=query,
                    lang=config.get("lang"),
                    headers=headers,
                    max_items=min(max_per_poll, SEARCH_PAGE_SIZE * 4),
                    last_seen_cid=last_seen_cid,
                    since=since,
                )
                title = f"Bluesky search: {query}"
        except _RateLimited:
            logger.info("Bluesky adapter rate-limited; backing off until next poll")
            return (
                ParsedFeedMeta(title="Bluesky", description="Rate limited; will retry next poll"),
                [],
            )
        except _AuthError:
            await _invalidate_session(feed_id)
            logger.warning("Bluesky adapter authentication failed")
            return ParsedFeedMeta(title="Bluesky", description="Bluesky auth failed"), []

        entries: list[ParsedEntry] = []
        render_replies = bool(config.get("render_replies"))
        for raw in posts:
            try:
                entry = self._post_to_entry(raw, render_replies=render_replies)
            except Exception:
                logger.exception("Bluesky adapter: failed to parse post; skipping")
                continue
            if entry:
                entries.append(entry)

        # Track newest CID for next-poll short-circuit.
        adapter_state: dict[str, Any] = {}
        if posts:
            for raw in posts:
                cid = (raw.get("post") or {}).get("cid") if isinstance(raw, dict) else None
                if cid:
                    adapter_state["last_seen_cid"] = cid
                    break

        meta = ParsedFeedMeta(
            title=title,
            description=f"{mode} mode",
            site_url="https://bsky.app",
            extra={"_adapter_state": adapter_state} if adapter_state else {},
        )
        return meta, entries

    def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
        mode = (config.get("mode") or "author").lower()
        if mode == "author":
            handle = config.get("handle", "")
            return ParsedFeedMeta(
                title=f"Bluesky: @{handle}",
                description=f"Posts by @{handle}",
                site_url=f"https://bsky.app/profile/{handle}" if handle else "https://bsky.app",
            )
        if mode == "feed":
            feed_uri = config.get("feed_uri", "")
            return ParsedFeedMeta(
                title=f"Bluesky feed: {feed_uri}",
                description=feed_uri,
                site_url="https://bsky.app",
            )
        return ParsedFeedMeta(
            title=f"Bluesky search: {config.get('query', '')}",
            description="Search results",
            site_url="https://bsky.app",
        )

    # ----------------------------- HTTP helpers -----------------------------

    async def _request_json(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        params: dict | None = None,
    ) -> dict:
        url = f"{PUBLIC_BASE}/{endpoint}"
        response = await client.get(url, params=params or {})
        if response.status_code == 429:
            raise _RateLimited()
        if response.status_code == 401:
            raise _AuthError()
        if response.status_code >= 400:
            logger.warning(
                "Bluesky %s returned %d: %s",
                endpoint,
                response.status_code,
                (response.text or "")[:200],
            )
            return {}
        try:
            return response.json()
        except json.JSONDecodeError:
            return {}

    async def _fetch_author(
        self,
        handle: str,
        headers: dict,
        filter_: str,
        include_reposts: bool,
        max_items: int,
        last_seen_cid: str | None,
        since: datetime | None,
    ) -> tuple[list[dict], str | None]:
        results: list[dict] = []
        cursor: str | None = None
        async with httpx.AsyncClient(timeout=30.0, headers=headers, follow_redirects=True) as client:
            while len(results) < max_items:
                params: dict[str, Any] = {
                    "actor": handle,
                    "limit": min(AUTHOR_PAGE_SIZE, max_items - len(results)),
                    "filter": filter_,
                }
                if cursor:
                    params["cursor"] = cursor

                data = await self._request_json(client, "app.bsky.feed.getAuthorFeed", params)
                items = data.get("feed") or []
                if not items:
                    break

                stop = False
                for item in items:
                    if not include_reposts and item.get("reason"):
                        continue
                    post = item.get("post") or {}
                    cid = post.get("cid")
                    if not cid:
                        continue
                    if last_seen_cid and cid == last_seen_cid:
                        stop = True
                        break
                    if since:
                        record = post.get("record") or {}
                        published = _parse_iso(record.get("createdAt"))
                        if published and published <= since:
                            stop = True
                            break
                    results.append(item)
                    if len(results) >= max_items:
                        stop = True
                        break

                if stop:
                    break
                cursor = data.get("cursor")
                if not cursor:
                    break
        return results, cursor

    async def _fetch_feed_uri(
        self,
        feed_uri: str,
        headers: dict,
        max_items: int,
        last_seen_cid: str | None,
        since: datetime | None,
    ) -> tuple[list[dict], str | None]:
        results: list[dict] = []
        cursor: str | None = None
        async with httpx.AsyncClient(timeout=30.0, headers=headers, follow_redirects=True) as client:
            while len(results) < max_items:
                params: dict[str, Any] = {
                    "feed": feed_uri,
                    "limit": min(FEED_PAGE_SIZE, max_items - len(results)),
                }
                if cursor:
                    params["cursor"] = cursor
                data = await self._request_json(client, "app.bsky.feed.getFeed", params)
                items = data.get("feed") or []
                if not items:
                    break

                stop = False
                for item in items:
                    post = item.get("post") or {}
                    cid = post.get("cid")
                    if not cid:
                        continue
                    if last_seen_cid and cid == last_seen_cid:
                        stop = True
                        break
                    if since:
                        record = post.get("record") or {}
                        published = _parse_iso(record.get("createdAt"))
                        if published and published <= since:
                            stop = True
                            break
                    results.append(item)
                    if len(results) >= max_items:
                        stop = True
                        break

                if stop:
                    break
                cursor = data.get("cursor")
                if not cursor:
                    break
        return results, cursor

    async def _fetch_search(
        self,
        query: str,
        lang: str | None,
        headers: dict,
        max_items: int,
        last_seen_cid: str | None,
        since: datetime | None,
    ) -> tuple[list[dict], str | None]:
        max_items = min(max_items, SEARCH_PAGE_SIZE * 4)
        results: list[dict] = []
        cursor: str | None = None
        async with httpx.AsyncClient(timeout=30.0, headers=headers, follow_redirects=True) as client:
            while len(results) < max_items:
                params: dict[str, Any] = {
                    "q": query,
                    "limit": min(SEARCH_PAGE_SIZE, max_items - len(results)),
                    "sort": "latest",
                }
                if lang:
                    params["lang"] = lang
                if cursor:
                    params["cursor"] = cursor
                data = await self._request_json(client, "app.bsky.feed.searchPosts", params)
                items = data.get("posts") or []
                if not items:
                    break

                stop = False
                for post in items:
                    cid = post.get("cid") if isinstance(post, dict) else None
                    if not cid:
                        continue
                    if last_seen_cid and cid == last_seen_cid:
                        stop = True
                        break
                    record = post.get("record") or {}
                    if since:
                        published = _parse_iso(record.get("createdAt"))
                        if published and published <= since:
                            stop = True
                            break
                    results.append({"post": post})
                    if len(results) >= max_items:
                        stop = True
                        break
                if stop:
                    break
                cursor = data.get("cursor")
                if not cursor:
                    break
        return results, cursor

    # ----------------------------- Auth -----------------------------

    async def _ensure_session(self, config: dict, feed_id: str) -> str | None:
        identifier = (config.get("identifier") or "").strip()
        encrypted_pw = (config.get("app_password") or "").strip()
        if not identifier or not encrypted_pw:
            return None

        cached = await _read_session(feed_id)
        if cached:
            jwt, _refresh, expires_at = cached
            if time.time() < expires_at - 60:
                return jwt

        try:
            password = decrypt_value(encrypted_pw)
        except Exception:
            logger.exception("Bluesky adapter: failed to decrypt app password")
            return None

        pds = (config.get("pds_url") or DEFAULT_PDS).rstrip("/")
        url = f"{pds}/xrpc/com.atproto.server.createSession"
        async with httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
        ) as client:
            response = await client.post(url, json={"identifier": identifier, "password": password})
            if response.status_code != 200:
                logger.warning(
                    "Bluesky createSession returned %d: %s",
                    response.status_code,
                    (response.text or "")[:200],
                )
                return None
            data = response.json()

        access = data.get("accessJwt")
        refresh = data.get("refreshJwt") or ""
        if not access:
            return None

        # JWTs are short-lived (~2h). Cache for 90 min to be safe.
        await _write_session(feed_id, access, refresh, time.time() + _SESSION_TTL_SECONDS)
        return access

    # ----------------------------- Rendering -----------------------------

    def _post_to_entry(self, raw: dict, render_replies: bool = False) -> ParsedEntry | None:
        post = raw.get("post") or {}
        record = post.get("record") or {}
        author = post.get("author") or {}
        cid = post.get("cid")
        uri = post.get("uri", "")
        if not cid:
            return None

        handle = author.get("handle") or ""
        display = author.get("displayName") or handle or "Unknown"
        text = record.get("text") or ""
        created = _parse_iso(record.get("createdAt") or post.get("indexedAt"))

        body_parts: list[str] = []
        if render_replies and isinstance(record.get("reply"), dict):
            parent_uri = (record["reply"].get("parent") or {}).get("uri") or ""
            label = parent_uri or "another post"
            body_parts.append(f"<p><small>Reply to {html_lib.escape(label)}</small></p>")

        body_parts.append(self._render_facets(text, record.get("facets") or []))

        embed_html, primary_media = self._render_embed(post.get("embed") or {})
        if embed_html:
            body_parts.append(embed_html)

        content_html = "\n".join(p for p in body_parts if p)

        first_line = text.strip().splitlines()[0].strip() if text.strip() else ""
        title = (first_line[:117] + "...") if len(first_line) > 120 else first_line
        if not title:
            title = f"Post by @{handle}"

        author_str = f"{display} (@{handle})" if handle and handle != display else f"@{handle}"

        tags = self._extract_tags(record.get("facets") or [])

        plain_summary = text[:280] if text else None

        metadata: dict[str, Any] = {
            "source": "bluesky",
            "handle": handle,
            "did": author.get("did"),
            "cid": cid,
            "uri": uri,
            "rkey": _rkey_from_uri(uri),
            "like_count": post.get("likeCount", 0),
            "repost_count": post.get("repostCount", 0),
            "reply_count": post.get("replyCount", 0),
            "indexed_at": post.get("indexedAt"),
            "tags": tags,
        }
        langs = record.get("langs")
        if langs:
            metadata["langs"] = langs
        reply = record.get("reply") or {}
        parent = reply.get("parent") or {}
        if parent.get("uri"):
            metadata["in_reply_to"] = parent["uri"]

        return ParsedEntry(
            guid=_stable_guid(cid),
            url=_bsky_post_url(handle, uri),
            title=title or f"Post by @{handle}",
            author=author_str,
            content_html=content_html,
            summary=plain_summary,
            published_at=created,
            metadata=metadata,
            media=primary_media,
        )

    @staticmethod
    def _extract_tags(facets: list[dict]) -> list[str]:
        out: list[str] = []
        for facet in facets or []:
            for feature in facet.get("features", []) or []:
                if feature.get("$type") == "app.bsky.richtext.facet#tag":
                    tag = feature.get("tag")
                    if tag:
                        out.append(tag)
        return out

    def _render_facets(self, text: str, facets: list[dict]) -> str:
        """Render Bluesky text + byte-range facets into HTML.

        Bluesky facets index UTF-8 byte offsets. We slice the byte string,
        decode each segment, escape HTML, and wrap link/mention/tag features
        in <a>. Newlines become <br>.
        """
        if not text:
            return ""
        if not facets:
            return f"<p>{self._escape_with_breaks(text)}</p>"

        text_bytes = text.encode("utf-8")
        sorted_facets: list[dict] = []
        for facet in facets:
            idx = facet.get("index") or {}
            start = idx.get("byteStart")
            end = idx.get("byteEnd")
            if not isinstance(start, int) or not isinstance(end, int):
                continue
            if start < 0 or end > len(text_bytes) or start >= end:
                continue
            sorted_facets.append(facet)
        sorted_facets.sort(key=lambda f: f["index"]["byteStart"])

        out_parts: list[str] = []
        cursor = 0
        for facet in sorted_facets:
            idx = facet["index"]
            start = idx["byteStart"]
            end = idx["byteEnd"]
            if start < cursor:
                continue
            if start > cursor:
                segment = text_bytes[cursor:start].decode("utf-8", errors="replace")
                out_parts.append(self._escape_with_breaks(segment))
            target = text_bytes[start:end].decode("utf-8", errors="replace")
            out_parts.append(self._render_feature(target, facet.get("features") or []))
            cursor = end

        if cursor < len(text_bytes):
            tail = text_bytes[cursor:].decode("utf-8", errors="replace")
            out_parts.append(self._escape_with_breaks(tail))

        return "<p>" + "".join(out_parts) + "</p>"

    @staticmethod
    def _escape_with_breaks(text: str) -> str:
        return html_lib.escape(text).replace("\n", "<br>")

    @staticmethod
    def _render_feature(visible: str, features: list[dict]) -> str:
        escaped = html_lib.escape(visible).replace("\n", "<br>")
        for feat in features:
            t = feat.get("$type", "")
            if t == "app.bsky.richtext.facet#link":
                href = feat.get("uri") or ""
                if href:
                    return (
                        f'<a href="{html_lib.escape(href, quote=True)}" '
                        f'rel="noopener nofollow" target="_blank">{escaped}</a>'
                    )
            elif t == "app.bsky.richtext.facet#mention":
                handle = visible.lstrip("@")
                target = handle or feat.get("did") or ""
                if target:
                    return (
                        f'<a href="https://bsky.app/profile/{html_lib.escape(target, quote=True)}" '
                        f'rel="noopener nofollow" target="_blank">{escaped}</a>'
                    )
            elif t == "app.bsky.richtext.facet#tag":
                tag = feat.get("tag") or visible.lstrip("#")
                if tag:
                    return (
                        f'<a href="https://bsky.app/hashtag/{html_lib.escape(tag, quote=True)}" '
                        f'rel="noopener nofollow" target="_blank">{escaped}</a>'
                    )
        return escaped

    def _render_embed(self, embed: dict) -> tuple[str, ParsedMedia | None]:
        if not embed:
            return "", None
        embed_type = embed.get("$type") or ""
        if not embed_type.endswith("#view"):
            return "", None

        if "embed.images" in embed_type:
            return self._render_image_embed(embed)
        if "embed.external" in embed_type:
            return self._render_external_embed(embed), None
        if "embed.recordWithMedia" in embed_type:
            media_part = embed.get("media") or {}
            record_html = self._render_record_embed(embed.get("record") or {})
            media_html, primary = "", None
            mtype = media_part.get("$type", "")
            if "embed.images" in mtype:
                media_html, primary = self._render_image_embed(media_part)
            elif "embed.external" in mtype:
                media_html = self._render_external_embed(media_part)
            elif "embed.video" in mtype:
                media_html, primary = self._render_video_embed(media_part)
            return ("\n".join(p for p in (media_html, record_html) if p), primary)
        if "embed.record" in embed_type:
            return self._render_record_embed(embed), None
        if "embed.video" in embed_type:
            return self._render_video_embed(embed)

        return "", None

    @staticmethod
    def _render_image_embed(embed: dict) -> tuple[str, ParsedMedia | None]:
        images = embed.get("images") or []
        if not images:
            return "", None
        primary_img = images[0]
        primary_url = primary_img.get("fullsize") or primary_img.get("thumb") or ""
        primary: ParsedMedia | None = None
        if primary_url:
            primary = ParsedMedia(
                media_type="image",
                url=primary_url,
                mime_type="image/jpeg",
                thumbnail_url=primary_img.get("thumb"),
                metadata={"alt": primary_img.get("alt") or ""},
            )
        extra_html_parts: list[str] = []
        for img in images[1:]:
            url = img.get("fullsize") or img.get("thumb")
            if not url:
                continue
            alt = img.get("alt") or ""
            extra_html_parts.append(
                f'<p><img src="{html_lib.escape(url, quote=True)}" alt="{html_lib.escape(alt, quote=True)}" /></p>'
            )
        return "\n".join(extra_html_parts), primary

    @staticmethod
    def _render_external_embed(embed: dict) -> str:
        external = embed.get("external") or {}
        uri = external.get("uri") or ""
        if not uri:
            return ""
        title = external.get("title") or uri
        description = external.get("description") or ""
        thumb = external.get("thumb")
        parts = ['<blockquote class="bsky-external">']
        parts.append(
            f'<a href="{html_lib.escape(uri, quote=True)}" '
            f'rel="noopener nofollow" target="_blank">{html_lib.escape(title)}</a>'
        )
        if description:
            parts.append(f"<br>{html_lib.escape(description)}")
        if thumb:
            parts.append(f'<br><img src="{html_lib.escape(thumb, quote=True)}" alt="" />')
        parts.append("</blockquote>")
        return "".join(parts)

    @staticmethod
    def _render_record_embed(embed: dict) -> str:
        record = embed.get("record") or {}
        author = record.get("author") or {}
        handle = author.get("handle") or ""
        value = record.get("value") or {}
        text = value.get("text") or ""
        truncated = (text[:280] + "...") if len(text) > 280 else text
        link = ""
        uri = record.get("uri") or ""
        if handle and uri:
            link = (
                f' <a href="{html_lib.escape(_bsky_post_url(handle, uri), quote=True)}" '
                f'rel="noopener nofollow" target="_blank">[link]</a>'
            )
        if not handle and not text:
            return ""
        return (
            '<blockquote class="bsky-quote">'
            f"<strong>@{html_lib.escape(handle)}</strong>: {html_lib.escape(truncated)}"
            f"{link}"
            "</blockquote>"
        )

    @staticmethod
    def _render_video_embed(embed: dict) -> tuple[str, ParsedMedia | None]:
        playlist = embed.get("playlist") or ""
        thumb = embed.get("thumbnail")
        if not playlist:
            return "", None
        media = ParsedMedia(
            media_type="video",
            url=playlist,
            mime_type="application/vnd.apple.mpegurl",
            thumbnail_url=thumb,
            metadata={"source": "bluesky"},
        )
        html_thumb = ""
        if thumb:
            html_thumb = f'<p><img src="{html_lib.escape(thumb, quote=True)}" alt="video thumbnail" /></p>'
        return html_thumb, media
