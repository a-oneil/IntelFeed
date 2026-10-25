"""Per-feed exclude-title filter.

A feed's ``exclude_title_patterns`` is a list of plain phrases, one per line.
An incoming article whose title contains any of them (case-insensitive, runs of
whitespace treated as one space) is dropped before it is saved, so it never
reaches tagging, the AI, scoring or search. Every adapter goes through it: the
RSS/Atom/YouTube/podcast path and the extended-adapter path in
``workers/feed_tasks.py`` both call :func:`partition_by_title`.

Plain substrings rather than regular expressions, deliberately. The patterns
this exists for are literal title prefixes ("ISC Stormcast For", "Chromium
CVE-"); a phrase list is something an analyst can type without escaping a dot,
and a substring test cannot be made to backtrack for minutes on a hostile title.
There is no include mode: a filter that only removes can never hide a source
behind a typo.
"""

import re

from app.core.exceptions import AppError

MAX_PATTERNS = 50
MAX_PATTERN_LENGTH = 200
# One or two characters would match nearly every title; the preview would show
# it, but a save should not be able to empty a feed by accident either.
MIN_PATTERN_LENGTH = 3

_WS_RE = re.compile(r"\s+")


def _fold(text: str) -> str:
    return _WS_RE.sub(" ", text).strip().casefold()


def parse_patterns(raw: str | None) -> list[str]:
    """The stored text as a list of folded phrases. Anything not a str is no filter."""
    if not isinstance(raw, str):
        return []
    seen: dict[str, None] = {}
    for line in raw.splitlines():
        folded = _fold(line)
        if folded:
            seen.setdefault(folded, None)
    return list(seen)


def normalize_patterns(raw: str | None) -> str | None:
    """Validate what a client sent and return the text to store.

    Blank lines and duplicates (ignoring case) are dropped, each line is
    trimmed, and the analyst's own capitalisation is kept for display. ``None``
    or an all-blank value clears the filter. Raises a 422 ``AppError`` naming
    the first bad line.
    """
    if raw is None:
        return None
    kept: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        shown = _WS_RE.sub(" ", line).strip()
        if not shown:
            continue
        folded = shown.casefold()
        if folded in seen:
            continue
        if len(shown) < MIN_PATTERN_LENGTH:
            raise AppError(
                code="invalid_title_filter",
                message=f'"{shown}" is too short to filter on: use at least {MIN_PATTERN_LENGTH} characters',
                status_code=422,
            )
        if len(shown) > MAX_PATTERN_LENGTH:
            raise AppError(
                code="invalid_title_filter",
                message=f"A title filter line is longer than {MAX_PATTERN_LENGTH} characters",
                status_code=422,
            )
        seen.add(folded)
        kept.append(shown)
    if len(kept) > MAX_PATTERNS:
        raise AppError(
            code="invalid_title_filter",
            message=f"A feed can have at most {MAX_PATTERNS} title filters",
            status_code=422,
        )
    return "\n".join(kept) or None


def matching_pattern(title: str | None, patterns: list[str]) -> str | None:
    """The first phrase ``title`` contains, or None. ``patterns`` come from parse_patterns."""
    if not patterns or not title:
        return None
    folded = _fold(title)
    return next((p for p in patterns if p in folded), None)


def partition_by_title(parsed_entries: list, raw_patterns: str | None) -> tuple[list, list]:
    """Split parsed entries into (kept, dropped) by the feed's exclude list."""
    patterns = parse_patterns(raw_patterns)
    if not patterns:
        return list(parsed_entries), []
    kept, dropped = [], []
    for parsed in parsed_entries:
        (dropped if matching_pattern(getattr(parsed, "title", None), patterns) else kept).append(parsed)
    return kept, dropped
