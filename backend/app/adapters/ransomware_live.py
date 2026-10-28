"""Ransomware leak-site collector adapters (planning/ransomware-victim-tracker.md §5.1).

Structurally mirrors nvd.py: an ``ExtendedAdapter`` that polls an external API and
returns ``ParsedEntry`` objects carrying a rich ``metadata`` dict. Unlike NVD these
entries are NOT persisted as ``Entry`` rows — the sync path
(app/intelligence/ransomware_sync.py) reads ``metadata`` and upserts
``RansomwareVictim`` + ``VictimDisclosure`` instead (Option A: dedicated worker path).

Source-pluggable by design: each source is one ``ExtendedAdapter`` subclass with a
distinct ``SOURCE`` string. ransomware.live is implemented and verified; additional
sources (eCrime.ch, broker channels) slot in as sibling subclasses once their schema
is confirmed, and the sync fn simply iterates over the enabled adapters.
"""

import hashlib
import logging
from datetime import UTC, datetime, timedelta

import httpx

from app.adapters.base import ExtendedAdapter, ParsedEntry, ParsedFeedMeta
from app.enrichment.gateway import SourceGateway

logger = logging.getLogger(__name__)

RANSOMWARE_LIVE_RECENT_URL = "https://api.ransomware.live/v2/recentvictims"
# First poll (no stored high-water mark) looks back this far.
_INITIAL_LOOKBACK_DAYS = 7


def _parse_dt(value: str | None) -> datetime | None:
    """Parse ransomware.live ISO-8601 timestamps ("2026-08-19T00:54:08.345165+00:00").

    Falls back to the older space-separated form and treats naive stamps as UTC.
    """
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00").replace(" ", "T", 1))
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def make_disclosure_guid(source: str, group: str, victim: str, discovered: str) -> str:
    """Stable cross-run dedup id for a posting event (plan §5.1)."""
    key = f"{source}|{(group or '').lower()}|{(victim or '').lower()}|{discovered or ''}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


class RansomwareLiveAdapter(ExtendedAdapter):
    """Polls ransomware.live v2 for recent leak-site victim postings.

    The v2 ``/recentvictims`` endpoint returns the most recent postings across all
    tracked groups with no server-side ``since`` filter, so incremental polling is
    done client-side against ``discovered``.
    """

    SOURCE = "ransomware.live"

    def __init__(self, gateway: SourceGateway):
        self.gateway = gateway

    async def fetch_entries(
        self, config: dict, since: datetime | None = None
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        meta = self.get_feed_meta(config)
        cutoff = since or (datetime.now(UTC) - timedelta(days=_INITIAL_LOOKBACK_DAYS))

        try:
            async with self.gateway.client(timeout=60.0, headers={"Accept": "application/json"}) as client:
                resp = await client.get(RANSOMWARE_LIVE_RECENT_URL)
        except httpx.HTTPError as exc:
            logger.warning("ransomware.live fetch failed: %s", exc)
            return meta, []

        if resp.status_code != 200:
            logger.warning("ransomware.live returned %s", resp.status_code)
            return meta, []

        try:
            rows = resp.json()
        except ValueError:
            logger.warning("ransomware.live returned non-JSON body")
            return meta, []
        if not isinstance(rows, list):
            rows = rows.get("victims", rows.get("data", []))

        entries: list[ParsedEntry] = []
        for raw in rows:
            entry = self._parse_victim(raw, cutoff)
            if entry is not None:
                entries.append(entry)

        logger.info("ransomware.live: %d/%d postings newer than %s", len(entries), len(rows), cutoff.isoformat())
        return meta, entries

    def _parse_victim(self, raw: dict, cutoff: datetime) -> ParsedEntry | None:
        if not isinstance(raw, dict):
            return None
        victim = (raw.get("victim") or "").strip()
        group = (raw.get("group") or raw.get("group_name") or "").strip()
        discovered_raw = raw.get("discovered") or raw.get("attackdate") or ""
        posted_at = _parse_dt(discovered_raw)
        if not victim or posted_at is None:
            return None
        # Client-side incremental filter (endpoint has no `since`).
        if posted_at <= cutoff:
            return None

        domain = (raw.get("domain") or raw.get("website") or "").strip() or None
        country = (raw.get("country") or "").strip() or None
        activity = (raw.get("activity") or raw.get("sector") or "").strip() or None
        claim_url = (raw.get("claim_url") or raw.get("url") or raw.get("post_url") or "").strip() or None

        return ParsedEntry(
            guid=make_disclosure_guid(self.SOURCE, group, victim, discovered_raw),
            url=claim_url,
            title=f"{group or 'Unknown group'} listed {victim}",
            published_at=posted_at,
            metadata={
                "source": self.SOURCE,
                "victim": victim,
                "group": group or None,
                "discovered": discovered_raw or None,
                "attackdate": raw.get("attackdate") or None,
                "published": raw.get("published") or None,
                "country": country,
                "activity": activity,
                "domain": domain,
                "claim_url": claim_url,
                "claimed_data": (raw.get("description") or "").strip() or None,
            },
        )

    def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
        return ParsedFeedMeta(
            title="Ransomware.live leak-site tracker",
            description="Recent ransomware leak-site victim postings",
            site_url="https://www.ransomware.live/",
        )
