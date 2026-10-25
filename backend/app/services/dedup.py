import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def compute_content_hash(title: str, content_text: str | None = None) -> str:
    """Compute SHA256 hash for cross-feed deduplication.

    Uses normalized title + first 500 chars of content_text.
    """
    normalized = _normalize_text(title)
    if content_text:
        normalized += " " + _normalize_text(content_text[:500])
    return hashlib.sha256(normalized.encode()).hexdigest()


def _normalize_text(text: str) -> str:
    """Normalize text for dedup comparison."""
    text = text.lower().strip()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[^\w\s]", "", text)
    return text


# ── Same-feed URL identity ───────────────────────────────
#
# Some feeds mint a fresh guid for the same post on every fetch (CrowdStrike's
# <guid isPermaLink="false">https://www.crowdstrike.com/?p=612853</guid> is a
# random number per render; its <link> is the stable post URL). The guid check
# then misses, and the cross-feed content hash misses too whenever the body
# drifts, so each fetch added another copy. Within one feed, the link plus the
# title identify an article; only the guid churns. These helpers build that
# identity. Only the link is normalised; the guid is never parsed.

# Query parameters that carry campaign/click tracking, never content. Matched
# case-insensitively; a trailing "*" is a prefix match.
_TRACKING_PARAMS = (
    "utm_*",
    "mc_*",
    "hsa_*",
    "fbclid",
    "gclid",
    "dclid",
    "gbraid",
    "wbraid",
    "msclkid",
    "yclid",
    "igshid",
    "twclid",
    "_hsenc",
    "_hsmi",
    "mkt_tok",
    "ref_src",
    "wt.mc_id",
    "oly_anon_id",
    "oly_enc_id",
    "vero_id",
)


def _is_tracking_param(name: str, value: str) -> bool:
    name = name.lower()
    for pattern in _TRACKING_PARAMS:
        if pattern.endswith("*"):
            if name.startswith(pattern[:-1]):
                return True
        elif name == pattern:
            return True
    # Medium and some WordPress feeds tag every link with ?source=rss-…
    return name == "source" and value.lower().startswith("rss")


def normalize_url(url: str | None) -> str | None:
    """A comparable form of an article link, or None if it isn't an absolute http(s) URL.

    Drops the fragment and tracking parameters (``utm_*``, ``fbclid``, ``gclid``,
    ``mc_*`` …), folds http into https, lowercases the host, drops a default
    port and a trailing slash, and sorts the remaining parameters. Every other
    parameter is kept, because it can be what identifies the page (``?p=123``,
    ``?v=…``, ``?id=…``).
    """
    if not url:
        return None
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower()
    if port and port not in (80, 443):
        host = f"{host}:{port}"
    path = parts.path or "/"
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    query = sorted((k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if not _is_tracking_param(k, v))
    return urlunsplit(("https", host, path, urlencode(query), ""))


def url_lookup_pattern(normalized: str) -> str:
    """An ILIKE pattern that finds every stored spelling of a normalised URL.

    Matches on host + path (no scheme, query or trailing slash), so it is a
    superset; callers re-normalise each hit and compare exactly.
    """
    parts = urlsplit(normalized)
    stem = (parts.netloc + parts.path).rstrip("/")
    escaped = stem.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _enclosure_path(url: str | None) -> str | None:
    """A media URL without its query: podcast hosts append ?updated=… on re-upload."""
    if not url:
        return None
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    return (parts.netloc.lower() + parts.path) or None


def item_key(url: str | None, title: str | None, enclosure_url: str | None = None) -> tuple | None:
    """The same-feed identity of an item: (normalised link, normalised title, enclosure path).

    None when the item has no usable link, so it never matches anything. The
    title is part of the key because some feeds point several items at one
    page (CyberWire episodes sharing a show-notes URL, feeds whose every <link>
    is the site root); the enclosure is part of it so two podcast episodes with
    the same title but different audio stay apart.
    """
    normalized = normalize_url(url)
    if normalized is None:
        return None
    return (normalized, _normalize_text(title or ""), _enclosure_path(enclosure_url))
