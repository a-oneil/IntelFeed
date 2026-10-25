"""What the fetcher has learned about a feed, kept in ``adapter_config``.

Three facts live under ``adapter_config["fetch_health"]``, a key only the
server writes (PUT /feeds/{id} and OPML import drop it from what a client
sends):

``client``
    ``"curl_cffi"`` when the publisher refuses the plain httpx client but
    answers curl_cffi impersonating Chrome (CISA blocks Python's TLS
    handshake whatever the headers). The fetcher goes straight to the
    remembered client and falls back to the other one if it stops working.
    Absent means httpx.

``paused``
    Why the health check paused the feed: the error, its status, how long the
    streak ran and when. A feed with ``auto_paused_at`` set and no snapshot (paused
    before the snapshot existed) is described from ``last_error`` and
    ``error_since``, which stay put while a feed is paused.

``empty``
    The feed answers 200 but parses to zero items: since when, and where the
    request ended up if it was redirected. A feed URL that redirects to a page
    with no items is unhealthy at once; one that keeps answering with an empty
    feed is unhealthy after ``EMPTY_UNHEALTHY_DAYS``.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

FETCH_HEALTH_KEY = "fetch_health"

CLIENT_HTTPX = "httpx"
CLIENT_CURL = "curl_cffi"

#: Days a feed may answer with zero items before it reads as unhealthy. A
#: redirect to somewhere that isn't a feed is unhealthy immediately.
EMPTY_UNHEALTHY_DAYS = 3

_HTTP_STATUS = re.compile(r"^HTTP (\d{3})\b")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def get_health(feed) -> dict:
    cfg = feed.adapter_config if isinstance(feed.adapter_config, dict) else {}
    health = cfg.get(FETCH_HEALTH_KEY)
    return dict(health) if isinstance(health, dict) else {}


def _set_health(feed, health: dict) -> None:
    """Write back with a new dict so SQLAlchemy sees the JSONB change."""
    cfg = dict(feed.adapter_config) if isinstance(feed.adapter_config, dict) else {}
    if health:
        cfg[FETCH_HEALTH_KEY] = health
    else:
        cfg.pop(FETCH_HEALTH_KEY, None)
    feed.adapter_config = cfg


def strip_client_keys(adapter_config: dict | None) -> dict | None:
    """Drop the server-owned key from a client-supplied adapter_config."""
    if not isinstance(adapter_config, dict) or FETCH_HEALTH_KEY not in adapter_config:
        return adapter_config
    return {k: v for k, v in adapter_config.items() if k != FETCH_HEALTH_KEY}


# --- which HTTP client works ------------------------------------------------


def preferred_client(feed) -> str:
    return CLIENT_CURL if get_health(feed).get("client") == CLIENT_CURL else CLIENT_HTTPX


def remember_client(feed, client: str) -> None:
    health = get_health(feed)
    current = health.get("client") or CLIENT_HTTPX
    if current == client:
        return
    if client == CLIENT_HTTPX:
        health.pop("client", None)
        health.pop("client_since", None)
    else:
        health["client"] = client
        health["client_since"] = _now_iso()
    _set_health(feed, health)


# --- why a feed was paused ----------------------------------------------------


def _status_of(message: str | None) -> int | None:
    m = _HTTP_STATUS.match(message or "")
    return int(m.group(1)) if m else None


def record_auto_pause(feed, *, reason: str = "http_4xx") -> None:
    now = datetime.now(UTC)
    since = feed.error_since
    health = get_health(feed)
    health["paused"] = {
        "reason": reason,
        "last_error": feed.last_error,
        "status": _status_of(feed.last_error),
        "failures": feed.error_count,
        "error_since": since.isoformat() if since else None,
        "days": (now - since).days if since else None,
        "client": health.get("client") or CLIENT_HTTPX,
        "paused_at": now.isoformat(),
    }
    _set_health(feed, health)


def clear_pause(feed) -> None:
    health = get_health(feed)
    if "paused" in health:
        health.pop("paused")
        _set_health(feed, health)


def pause_reason(feed) -> dict | None:
    """Why the health check paused this feed, or None if a person did (or it
    is running)."""
    if feed.is_active or not feed.auto_paused_at:
        return None
    snap = get_health(feed).get("paused")
    if isinstance(snap, dict):
        return snap
    since = feed.error_since
    return {
        "reason": "http_4xx",
        "last_error": feed.last_error,
        "status": _status_of(feed.last_error),
        "failures": feed.error_count,
        "error_since": since.isoformat() if since else None,
        "days": (feed.auto_paused_at - since).days if since else None,
        "client": get_health(feed).get("client") or CLIENT_HTTPX,
        "paused_at": feed.auto_paused_at.isoformat(),
    }


# --- reachable but empty ------------------------------------------------------


def _same_location(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.hostname or "").lower().removeprefix("www.") == (pb.hostname or "").lower().removeprefix(
        "www."
    ) and pa.path.rstrip("/") == pb.path.rstrip("/")


def note_items(feed, item_count: int, *, final_url: str | None = None, content_type: str | None = None) -> None:
    """Record whether a 200 response held any items."""
    health = get_health(feed)
    if item_count > 0:
        if "empty" in health:
            health.pop("empty")
            _set_health(feed, health)
        return
    redirected_to = None
    if final_url and final_url.startswith(("http://", "https://")) and not _same_location(final_url, feed.url):
        redirected_to = final_url
    previous = health.get("empty") if isinstance(health.get("empty"), dict) else {}
    health["empty"] = {
        "since": previous.get("since") or _now_iso(),
        "checked_at": _now_iso(),
        "redirected_to": redirected_to,
        "content_type": content_type or None,
    }
    _set_health(feed, health)


def health_warning(feed) -> dict | None:
    """A reachable feed that has stopped delivering items, or None."""
    if not feed.is_active:
        return None
    empty = get_health(feed).get("empty")
    if not isinstance(empty, dict):
        return None
    since = _parse_iso(empty.get("since"))
    days = (datetime.now(UTC) - since).days if since else 0
    if not empty.get("redirected_to") and days < EMPTY_UNHEALTHY_DAYS:
        return None
    return {
        "kind": "redirected_no_items" if empty.get("redirected_to") else "no_items",
        "since": empty.get("since"),
        "days": days,
        "redirected_to": empty.get("redirected_to"),
        "content_type": empty.get("content_type"),
    }
