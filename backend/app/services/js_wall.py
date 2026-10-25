"""Detect JavaScript-only and bot-challenge pages in fetched article text.

Full-text extraction runs readability over whatever HTML the article URL
returns. A single-page app (NCSC, Europol, MSRC) serves a shell whose only
text is its ``<noscript>`` notice, and a bot wall (Cloudflare, FortiGuard)
serves a challenge page — readability extracts that message and it would
replace the feed's own description as the article body. These pages are
short and carry a recognisable phrase, so a length cap plus a phrase list
separates them from real articles that merely mention JavaScript.
"""

import html
import re

from app.services.sanitizer import html_to_text

# A real article body is longer than this; wall pages run 70-200 chars.
MAX_WALL_TEXT_CHARS = 1000

# One of these alone marks a wall page.
_STRONG_PATTERNS = [
    r"\b(?:enable|turn on|activate|allow) (?:your )?javascript\b",
    r"\bjavascript (?:is|must be) (?:required|disabled|enabled|turned off|switched off|not enabled)\b",
    r"\brequires? javascript\b",
    r"\bjavascript to run this app\b",
    r"\bjavascript (?:and|&) cookies\b",
    r"\bchecking (?:if the site connection is secure|your browser|that your connection)\b",
    r"\bverify(?:ing)? (?:you are|you're) (?:a )?human\b",
    r"\bverifying (?:your )?connection\b",
    r"\battention required\b",
    r"\bddos protection by\b",
]

# These need a second hit (weak or strong): "just a moment" alone appears in
# ordinary prose.
_WEAK_PATTERNS = [
    r"\bjust a moment\b",
    r"\bplease wait\b",
    r"\bloading application\b",
    r"\bsecurity check\b",
    r"\bcheck(?:ing)? your connection\b",
]

_STRONG_RE = [re.compile(p, re.IGNORECASE) for p in _STRONG_PATTERNS]
_WEAK_RE = [re.compile(p, re.IGNORECASE) for p in _WEAK_PATTERNS]

# Postgres prefilter for the backfill script (case-insensitive ``~*``); the
# Python check above makes the final call.
SQL_PREFILTER = (
    r"(javascript|just a moment|checking your browser|verify you are|verifying (your )?connection"
    r"|attention required|ddos protection)"
)


def _normalize(content: str) -> str:
    # html_to_text escapes entities; some feeds double-escape their markup.
    text = html_to_text(content) if "<" in content else content
    text = html.unescape(html.unescape(text))
    return re.sub(r"\s+", " ", text).strip()


def looks_like_js_wall(content: str | None) -> bool:
    """True when ``content`` (HTML or plain text) is a JS-required or bot-check page."""
    if not content:
        return False
    text = _normalize(content)
    if not text or len(text) > MAX_WALL_TEXT_CHARS:
        return False
    if any(r.search(text) for r in _STRONG_RE):
        return True
    return sum(1 for r in _WEAK_RE if r.search(text)) >= 2
