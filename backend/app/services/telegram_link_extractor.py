"""Extract Telegram channel/invite/message URLs from entry content.

Patterns we care about:
  - https://t.me/<channel>
  - https://t.me/<channel>/<msg_id>
  - https://t.me/+<invite_hash>             (private channel invite)
  - https://t.me/joinchat/<invite_hash>     (legacy invite form)
  - https://telegram.me/<channel>           (older alias)
  - https://t.me/s/<channel>                (web preview, points to same channel)
  - tg://resolve?domain=<channel>           (deep link occasionally seen in code/articles)

Patterns we explicitly reject:
  - https://t.me/share, https://t.me/iv, https://t.me/proxy etc. — Telegram service paths
  - bare @handles in prose — too noisy and ambiguous (could be mastodon, twitter, etc.)
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

# Service-style paths that should never be treated as channel handles.
_TG_RESERVED_PATHS = {
    "share",
    "iv",
    "proxy",
    "addstickers",
    "joinchat",
    "addtheme",
    "addemoji",
    "setlanguage",
    "confirmphone",
    "login",
    "wallpaper",
    "bg",
    "contact",
    "premium",
    "msg_url",
    "telegram",
    "telegrampremium",
}

_TG_HOSTS = {"t.me", "www.t.me", "telegram.me", "www.telegram.me", "telegram.dog"}

_HANDLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,31}$")
_INVITE_RE = re.compile(r"^[A-Za-z0-9_-]{16,}$")


@dataclass(frozen=True)
class TelegramLink:
    """One extracted reference to a Telegram resource."""

    url: str  # canonical https://t.me/<handle>[/msg] form
    handle: str  # lowercased channel username, or "invite:<hash>" for invite-only links
    display_handle: str  # original case
    link_type: str  # channel | message | invite | deep_link
    message_id: int | None = None
    invite_hash: str | None = None


def extract_links(html_or_text: str) -> list[TelegramLink]:
    """Find every Telegram URL in the input. Deduplicated by canonical URL."""
    if not html_or_text:
        return []

    seen_urls: set[str] = set()
    out: list[TelegramLink] = []

    # Pull every URL-shaped substring; cheaper than HTML parsing and works for both
    # raw text and HTML (URLs in href="" or in body text both look the same here).
    for raw in _URL_RE.findall(html_or_text):
        link = _classify(raw)
        if link is None:
            continue
        if link.url in seen_urls:
            continue
        seen_urls.add(link.url)
        out.append(link)

    return out


# Match http(s) URLs and tg: deep links. Stop at whitespace, quote, angle bracket, or
# common HTML/punctuation terminators. Don't trip on closing parens that are part of
# Markdown link syntax.
_URL_RE = re.compile(
    r"""
    (
        (?:https?://[^\s<>"'\)\]]+)
        |
        (?:tg://resolve\?domain=[A-Za-z0-9_]+)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _classify(raw_url: str) -> TelegramLink | None:
    cleaned = raw_url.rstrip(".,;:!?\"'")
    # tg://resolve?domain=...
    if cleaned.lower().startswith("tg://resolve"):
        parsed = urlparse(cleaned)
        query = parse_qs(parsed.query)
        domain = (query.get("domain") or [""])[0]
        if not _HANDLE_RE.match(domain) or domain.lower() in _TG_RESERVED_PATHS:
            return None
        return TelegramLink(
            url=f"https://t.me/{domain}",
            handle=domain.lower(),
            display_handle=domain,
            link_type="deep_link",
        )

    # http(s)://t.me/...
    parsed = urlparse(cleaned)
    if parsed.hostname is None or parsed.hostname.lower() not in _TG_HOSTS:
        return None
    path = parsed.path.strip("/")
    if not path:
        return None
    parts = path.split("/")

    first = parts[0]

    # Invite link: t.me/+HASH or t.me/joinchat/HASH
    if first.startswith("+"):
        invite = first[1:]
        if not _INVITE_RE.match(invite):
            return None
        return TelegramLink(
            url=f"https://t.me/+{invite}",
            handle=f"invite:{invite}",
            display_handle=f"+{invite}",
            link_type="invite",
            invite_hash=invite,
        )
    if first.lower() == "joinchat" and len(parts) >= 2:
        invite = parts[1]
        if not _INVITE_RE.match(invite):
            return None
        return TelegramLink(
            url=f"https://t.me/+{invite}",
            handle=f"invite:{invite}",
            display_handle=f"+{invite}",
            link_type="invite",
            invite_hash=invite,
        )

    # Web preview: t.me/s/<channel> or t.me/s/<channel>/<msg>
    if first.lower() == "s" and len(parts) >= 2:
        parts = parts[1:]
        first = parts[0]

    # Reserved service path
    if first.lower() in _TG_RESERVED_PATHS:
        return None
    if not _HANDLE_RE.match(first):
        return None

    handle = first.lower()
    display = first

    # Channel-only or message-link?
    if len(parts) >= 2 and parts[1].isdigit():
        msg_id = int(parts[1])
        return TelegramLink(
            url=f"https://t.me/{display}/{msg_id}",
            handle=handle,
            display_handle=display,
            link_type="message",
            message_id=msg_id,
        )

    return TelegramLink(
        url=f"https://t.me/{display}",
        handle=handle,
        display_handle=display,
        link_type="channel",
    )


def unique_handles(links: Iterable[TelegramLink]) -> dict[str, TelegramLink]:
    """Reduce a list of links to one representative per handle (most specific wins)."""
    out: dict[str, TelegramLink] = {}
    rank = {"invite": 0, "channel": 1, "deep_link": 1, "message": 2}
    for link in links:
        existing = out.get(link.handle)
        if existing is None or rank[link.link_type] > rank[existing.link_type]:
            out[link.handle] = link
    return out
