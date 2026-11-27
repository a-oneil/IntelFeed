"""What a pasted link is, before anything is subscribed.

The Add Feed dialog takes one pasted link and has to say what it found — a
site with two feeds, a YouTube channel, a GitHub repo, a Bluesky account, a
Telegram channel, a Mastodon hashtag, or a page with no feed that the web
scraper could read — and offer the one or two choices that change what
arrives. This module answers that question; ``POST /feeds/preview`` serves it.

Nothing here writes to the database. GitHub, Bluesky and Telegram lookups are
best-effort: a repo the API won't describe still previews as a repo, it just
can't say whether it holds rules.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass, field
from html import unescape
from pathlib import PurePosixPath
from urllib.parse import parse_qs, unquote, urlparse

import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.safe_http import safe_async_client
from app.schemas.feed import FeedDiscoverResult

logger = structlog.get_logger("app.link_preview")

GITHUB_API = "https://api.github.com"
BSKY_API = "https://public.api.bsky.app/xrpc"

_GITHUB_REPO_RE = re.compile(r"^/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/.*)?$")
# github.com paths that are not repositories.
_GITHUB_RESERVED = frozenset(
    {"orgs", "users", "settings", "marketplace", "topics", "collections", "explore", "sponsors", "features", "about"}
)
_BSKY_FEED_RE = re.compile(r"^/profile/([^/]+)/feed/([^/?#]+)")
_BSKY_PROFILE_RE = re.compile(r"^/profile/([^/?#]+)/?$")
_TELEGRAM_RE = re.compile(r"^/(?:s/)?([A-Za-z0-9_]{4,})/?$")
_MASTODON_TAG_RE = re.compile(r"^/tags/([^/?#]+)/?$")
_OG_TITLE_RE = re.compile(r'<meta[^>]+property="og:title"[^>]+content="([^"]*)"', re.IGNORECASE)

# Rule formats the GitHub adapter turns into detection rules, as the dialog names them.
RULE_FORMAT_LABELS = {
    "sigma_rule": "Sigma rules",
    "elastic_rule": "Elastic rules",
    "splunk_detection": "Splunk detections",
    "splunk_story": "Splunk analytic stories",
    "sentinel_rule": "Sentinel rules",
    "anvilogic_rule": "Anvilogic rules",
    "yara_rule": "YARA rules",
    "kql_query": "KQL queries",
    "nuclei_template": "Nuclei templates",
    "panther_rule": "Panther rules",
    "lolbas_entry": "LOLBAS entries",
    "loobin_entry": "LOOBins entries",
    "loldriver_entry": "LOLDrivers entries",
    "atomic_test": "Atomic Red Team tests",
    "ioc_list": "IOC lists",
}
# Extensions that are a rule format on their own, no content needed.
_RULE_EXTENSIONS = {".yar": "yara_rule", ".yara": "yara_rule", ".kql": "kql_query"}
# Generic files sampled for a rule format when a repo isn't a known one.
_SNIFF_EXTENSIONS = {".yml": "yaml_file", ".yaml": "yaml_file", ".toml": "toml_file"}
_SNIFF_SAMPLE = 6


class PreviewError(Exception):
    """The link could not be read as anything the dialog can subscribe to."""


@dataclass
class LinkPreview:
    kind: str  # feed | github | bluesky | bluesky_feed | bluesky_search | telegram | mastodon_tag | page
    title: str
    feed_type: str
    url: str
    feeds: list[FeedDiscoverResult] = field(default_factory=list)
    github: dict | None = None
    bluesky: dict | None = None
    telegram: dict | None = None
    mastodon: dict | None = None
    page: dict | None = None
    warning: str | None = None
    suggested_category_id: uuid.UUID | None = None
    fetch_interval_minutes: int = 30


def normalize_link(raw: str) -> str:
    """A pasted link with a scheme: ``thedfirreport.com`` becomes ``https://thedfirreport.com``."""
    value = raw.strip()
    if not value:
        raise PreviewError("Paste a link.")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.IGNORECASE):
        value = "https://" + value.lstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or "." not in (parsed.hostname or ""):
        raise PreviewError("That doesn't look like a link.")
    return value


def _host(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


async def preview_link(raw_url: str, db: AsyncSession) -> LinkPreview:
    from app.api.feeds import _EXTENDED_FEED_DEFAULTS
    from app.services.feed_defaults import category_for_feed_type

    url = normalize_link(raw_url)
    preview = await _identify(url)
    preview.suggested_category_id = await category_for_feed_type(db, preview.feed_type)
    preview.fetch_interval_minutes = _EXTENDED_FEED_DEFAULTS.get(preview.feed_type, {}).get("interval", 30)
    if preview.feed_type == "github_repo":
        preview.fetch_interval_minutes = int(settings.github_repo_default_interval_minutes or 1440)
    return preview


async def _identify(url: str) -> LinkPreview:
    host = _host(url)
    path = urlparse(url).path or "/"

    if host == "github.com" and not path.endswith((".atom", ".rss", ".xml")):
        match = _GITHUB_REPO_RE.match(path)
        if match and match.group(1).lower() not in _GITHUB_RESERVED:
            return await _github(match.group(1), match.group(2))

    if host == "bsky.app":
        found = await _bluesky(url, path)
        if found:
            return found

    if host in ("t.me", "telegram.me"):
        match = _TELEGRAM_RE.match(path)
        if match:
            return await _telegram(match.group(1))

    tag = _MASTODON_TAG_RE.match(path)
    if tag:
        found = await _mastodon_tag(url, unquote(tag.group(1)))
        if found:
            return found

    return await _feeds_or_page(url)


async def _feeds_or_page(url: str) -> LinkPreview:
    from app.services.feed_discovery import discover_feeds

    feeds, page_html = await discover_feeds(url)
    if feeds:
        first = feeds[0]
        return LinkPreview(
            kind="feed",
            title=first.title or _host(url),
            feed_type=first.feed_type,
            url=first.url,
            feeds=feeds,
        )
    if page_html is None:
        raise PreviewError("Couldn't open this link, or it has no feed.")
    return _page(url, page_html)


def _page(url: str, page_html: str) -> LinkPreview:
    """A page with no feed: what the web scraper would find on it."""
    from app.adapters.web_scraper import WebScraperAdapter, _page_title

    links = WebScraperAdapter()._discover_links(page_html, url, urlparse(url).netloc, None, None)
    parsed = urlparse(url)
    label = (parsed.netloc.removeprefix("www.") + parsed.path.rstrip("/")) or url
    return LinkPreview(
        kind="page",
        title=_page_title(page_html) or label,
        feed_type="web_scraper",
        url=url,
        page={"article_links": len(links), "label": label},
    )


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------


def _github_headers() -> dict:
    from app.adapters.github_repo import _get_token

    headers = {"Accept": "application/vnd.github+json", "User-Agent": "IntelFeed/1.0"}
    token = _get_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _rule_dirs(paths: list[str]) -> list[str]:
    """``rules/**/*.yml`` → ``rules/``; a pattern with no folder → the repo root."""
    out: list[str] = []
    for pattern in paths:
        head = pattern.split("*", 1)[0]
        folder = head.rsplit("/", 1)[0] + "/" if "/" in head else ""
        if folder not in out:
            out.append(folder)
    return out


def _known_rules(owner: str, repo: str) -> dict | None:
    """Rules for a repo IntelFeed already knows: a detection template or a per-repo type rule."""
    from app.adapters.github_content_types import CONTENT_TYPE_RULES
    from app.services.github_repo_templates import DETECTION_REPO_TEMPLATES

    key = f"{owner}/{repo}".lower()
    for tmpl in DETECTION_REPO_TEMPLATES:
        if f"{tmpl['owner']}/{tmpl['repo']}".lower() == key:
            types = tmpl.get("content_types") or []
            return {
                "label": RULE_FORMAT_LABELS.get(types[0], "Detection rules") if types else "Detection rules",
                "paths": list(tmpl["paths"]),
                "branch": tmpl.get("branch"),
            }
    rows = [(glob, ctype) for repo_key, glob, ctype in CONTENT_TYPE_RULES if repo_key.lower() == key]
    rows = [(glob, ctype) for glob, ctype in rows if ctype in RULE_FORMAT_LABELS]
    if rows:
        return {"label": RULE_FORMAT_LABELS[rows[0][1]], "paths": [glob for glob, _ in rows], "branch": None}
    return None


async def _scan_rules(client: httpx.AsyncClient, owner: str, repo: str, branch: str) -> dict | None:
    """Look through the repo's file tree for a rule format the adapter parses."""
    from app.adapters.github_content_types import sniff_rule_format

    try:
        resp = await client.get(f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}", params={"recursive": "1"})
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    files = [item["path"] for item in resp.json().get("tree", []) if item.get("type") == "blob"]

    by_ext: dict[str, list[str]] = {}
    for path in files:
        ctype = _RULE_EXTENSIONS.get(PurePosixPath(path).suffix.lower())
        if ctype:
            by_ext.setdefault(ctype, []).append(path)
    if by_ext:
        ctype, matched = max(by_ext.items(), key=lambda kv: len(kv[1]))
        return {"label": RULE_FORMAT_LABELS[ctype], "paths": _globs_for(matched), "branch": branch}

    # Sample YAML/TOML from folders that sound like rules, then anywhere.
    candidates = [p for p in files if PurePosixPath(p).suffix.lower() in _SNIFF_EXTENSIONS]
    ruleish = [p for p in candidates if re.search(r"(^|/)(rules?|detections?|sigma|analytics)(/|$)", p, re.I)]
    sample = (ruleish or candidates)[:_SNIFF_SAMPLE]
    if not sample:
        return None

    async def sniff(path: str) -> tuple[str, str | None]:
        try:
            raw = await client.get(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}")
        except httpx.HTTPError:
            return path, None
        if raw.status_code != 200 or len(raw.content) > 256_000:
            return path, None
        return path, sniff_rule_format(raw.text, _SNIFF_EXTENSIONS[PurePosixPath(path).suffix.lower()])

    results = await asyncio.gather(*(sniff(p) for p in sample))
    hits = [(p, t) for p, t in results if t]
    if not hits:
        return None
    ctype = max({t for _, t in hits}, key=lambda t: sum(1 for _, x in hits if x == t))
    matched = [p for p, t in hits if t == ctype]
    return {"label": RULE_FORMAT_LABELS.get(ctype, "Detection rules"), "paths": _globs_for(matched), "branch": branch}


def _globs_for(paths: list[str]) -> list[str]:
    """One ``<top folder>/**/*<ext>`` glob per top folder and extension the matches share."""
    globs: list[str] = []
    for path in paths:
        p = PurePosixPath(path)
        top = p.parts[0] + "/**/" if len(p.parts) > 1 else "**/"
        glob = f"{top}*{p.suffix}"
        if glob not in globs:
            globs.append(glob)
    return globs


async def _github(owner: str, repo: str) -> LinkPreview:
    title = f"{owner}/{repo}"
    info: dict = {"owner": owner, "repo": repo, "default_branch": "main", "rules": None, "has_releases": None}
    async with safe_async_client(timeout=10.0, headers=_github_headers(), follow_redirects=True) as client:
        try:
            resp = await client.get(f"{GITHUB_API}/repos/{owner}/{repo}")
        except httpx.HTTPError:
            resp = None
        if resp is not None and resp.status_code == 404:
            raise PreviewError("GitHub has no public repository at this link.")
        if resp is not None and resp.status_code == 200:
            data = resp.json()
            # The canonical spelling: a feed keyed on the URL shouldn't duplicate on case.
            owner = data.get("owner", {}).get("login") or owner
            repo = data.get("name") or repo
            title = f"{owner}/{repo}"
            info.update(owner=owner, repo=repo, default_branch=data.get("default_branch") or "main")
            info["description"] = data.get("description")

        rules = _known_rules(owner, repo)
        if rules is None:
            rules = await _scan_rules(client, owner, repo, info["default_branch"])
        if rules is not None:
            rules["branch"] = rules.get("branch") or info["default_branch"]
            rules["folders"] = _rule_dirs(rules["paths"])
        info["rules"] = rules

        try:
            rel = await client.get(f"{GITHUB_API}/repos/{owner}/{repo}/releases", params={"per_page": 1})
            if rel.status_code == 200:
                info["has_releases"] = bool(rel.json())
        except httpx.HTTPError:
            pass

    return LinkPreview(
        kind="github", title=title, feed_type="github_repo", url=f"https://github.com/{owner}/{repo}", github=info
    )


# ---------------------------------------------------------------------------
# Bluesky
# ---------------------------------------------------------------------------


async def _bluesky(url: str, path: str) -> LinkPreview | None:
    parsed = urlparse(url)
    if path.rstrip("/") == "/search":
        query = (parse_qs(parsed.query).get("q") or [""])[0].strip()
        if query:
            return LinkPreview(
                kind="bluesky_search",
                title=f'Bluesky: "{query}"',
                feed_type="bluesky",
                url=url,
                bluesky={"mode": "search", "query": query},
            )
        return None

    feed = _BSKY_FEED_RE.match(path)
    if feed:
        handle, rkey = feed.group(1), feed.group(2)
        async with safe_async_client(timeout=10.0) as client:
            did = await _resolve_handle(client, handle)
            if not did:
                raise PreviewError(f"Bluesky couldn't find {handle}.")
            feed_uri = f"at://{did}/app.bsky.feed.generator/{rkey}"
            name = rkey
            try:
                resp = await client.get(f"{BSKY_API}/app.bsky.feed.getFeedGenerator", params={"feed": feed_uri})
                if resp.status_code == 200:
                    name = resp.json().get("view", {}).get("displayName") or rkey
            except httpx.HTTPError:
                pass
        return LinkPreview(
            kind="bluesky_feed",
            title=name,
            feed_type="bluesky",
            url=url,
            bluesky={"mode": "feed", "feed_uri": feed_uri, "handle": handle},
        )

    profile = _BSKY_PROFILE_RE.match(path)
    if profile:
        handle = profile.group(1).lstrip("@")
        display = None
        async with safe_async_client(timeout=10.0) as client:
            try:
                resp = await client.get(f"{BSKY_API}/app.bsky.actor.getProfile", params={"actor": handle})
                if resp.status_code == 400:
                    raise PreviewError(f"Bluesky has no account {handle}.")
                if resp.status_code == 200:
                    data = resp.json()
                    handle = data.get("handle") or handle
                    display = data.get("displayName")
            except httpx.HTTPError:
                pass
        return LinkPreview(
            kind="bluesky",
            title=display or f"@{handle}",
            feed_type="bluesky",
            url=url,
            bluesky={"mode": "author", "handle": handle, "display_name": display},
        )
    return None


async def _resolve_handle(client: httpx.AsyncClient, handle: str) -> str | None:
    if handle.startswith("did:"):
        return handle
    try:
        resp = await client.get(f"{BSKY_API}/com.atproto.identity.resolveHandle", params={"handle": handle})
    except httpx.HTTPError:
        return None
    return resp.json().get("did") if resp.status_code == 200 else None


# ---------------------------------------------------------------------------
# Telegram and Mastodon
# ---------------------------------------------------------------------------


def telegram_ready() -> bool:
    return bool(settings.telegram_api_id and settings.telegram_api_hash)


async def _telegram(channel: str) -> LinkPreview:
    title = None
    async with safe_async_client(timeout=10.0, follow_redirects=True) as client:
        try:
            resp = await client.get(f"https://t.me/{channel}")
            if resp.status_code == 200:
                match = _OG_TITLE_RE.search(resp.text)
                title = unescape(match.group(1)).strip() if match else None
        except httpx.HTTPError:
            pass
    return LinkPreview(
        kind="telegram",
        title=title or f"@{channel}",
        feed_type="telegram",
        url=f"https://t.me/{channel}",
        telegram={"channel": channel},
        warning=None
        if telegram_ready()
        else "Telegram isn't connected on this server yet. An admin connects it once in Settings.",
    )


async def _mastodon_tag(url: str, tag: str) -> LinkPreview | None:
    """``https://<server>/tags/<tag>`` on a server that answers Mastodon's instance API."""
    parsed = urlparse(url)
    instance = f"{parsed.scheme}://{parsed.netloc}"
    async with safe_async_client(timeout=8.0) as client:
        try:
            resp = await client.get(f"{instance}/api/v1/instance")
        except httpx.HTTPError:
            return None
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    if not isinstance(data, dict) or not (data.get("uri") or data.get("domain")):
        return None
    host = parsed.netloc.removeprefix("www.")
    return LinkPreview(
        kind="mastodon_tag",
        title=f"#{tag} on {host}",
        feed_type="mastodon",
        url=url,
        mastodon={"instance_url": instance, "hashtag": tag},
    )
