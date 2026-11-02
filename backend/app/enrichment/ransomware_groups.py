"""ransomware.live group profiles for the ransomware groups the leak-site sync
already tracks.

The victim sync (``app/intelligence/ransomware_sync.py``) ties each
ransomware.live group slug to a threat actor on the disclosures it records;
this job reads those pairs, so it asks only about groups IntelFeed has and
needs no matching of its own. An actor several slugs fold into (lockbit2,
lockbit3) is looked up by the slug that posted most recently.

ransomware.live allows about a call a minute, and the source's bucket also
serves the victim sync, so each run looks up a few groups — those with no
profile yet, then the stalest — and a profile is good for a week.

A profile claims the ATT&CK techniques the group uses (with ransomware.live's
note on how, as evidence) and the tools it lists (``app/enrichment/relations.py``),
and shows its description, its tools by category and whether each leak site
and chat is up. The sites' onion addresses are never kept.
"""

from __future__ import annotations

import html
import logging
import re
import time
from datetime import UTC, datetime
from urllib.parse import quote

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.enrichment.base import EnrichmentData
from app.enrichment.gateway import SOURCE_REFUSALS, SourceGateway

logger = logging.getLogger(__name__)

GROUP_URL = "https://api.ransomware.live/v2/group/{}"
SOURCE_TYPE = "ransomware_live"
#: The disclosures' ``source`` for ransomware.live postings.
DISCLOSURE_SOURCE = "ransomware.live"
#: Groups looked up per run; six runs a day refresh about 300 groups a week.
GROUPS_PER_RUN = 10
#: A run stops starting lookups after this long, well inside its time limit.
RUN_SECONDS = 600
TTL_HOURS = 168

_BREAK = re.compile(r"<br\s*/?>", re.IGNORECASE)
_TAG = re.compile(r"<[^>]+>")


def _text(raw) -> str | None:
    """ransomware.live's HTML description as plain paragraphs."""
    if not isinstance(raw, str):
        return None
    text = html.unescape(_TAG.sub("", _BREAK.sub("\n", raw)))
    paragraphs = [" ".join(p.split()) for p in re.split(r"\n\s*\n|\n", text)]
    return "\n\n".join(p for p in paragraphs if p) or None


def group_facts(group: dict) -> dict:
    """A /v2/group/{slug} answer as the source's parsed_data."""
    techniques = [
        {
            "technique_id": t.get("technique_id"),
            "technique_name": t.get("technique_name"),
            "technique_details": t.get("technique_details"),
        }
        for tactic in group.get("ttps") or []
        if isinstance(tactic, dict)
        for t in tactic.get("techniques") or []
        if isinstance(t, dict) and isinstance(t.get("technique_id"), str)
    ]
    # ``tools`` is a list of {category: [names]} objects.
    by_category: dict[str, list[str]] = {}
    for block in group.get("tools") or []:
        for category, names in block.items() if isinstance(block, dict) else ():
            for name in names if isinstance(names, list) else []:
                if isinstance(name, str) and name.strip():
                    by_category.setdefault(category, []).append(name.strip())
    sites = [
        {"type": (loc.get("type") or "site").strip() or "site", "status": "up" if loc.get("available") else "down"}
        for loc in group.get("locations") or []
        if isinstance(loc, dict)
    ]
    page = group.get("url")
    return {
        "found": True,
        "description": _text(group.get("description")),
        "techniques": techniques,
        "tools": [{"name": n, "category": c} for c, names in by_category.items() for n in names],
        "tools_by_category": [{"category": c, "tools": names} for c, names in by_category.items()],
        "leak_sites": sites,
        "page": {"url": page, "label": "ransomware.live"} if isinstance(page, str) else None,
    }


async def _groups_due(db: AsyncSession, limit: int) -> list[tuple]:
    """(actor id, slug) for tracked groups with no fresh profile: never looked
    up first, then the stalest."""
    from app.models.enrichment import EnrichmentResult
    from app.models.ransomware import VictimDisclosure

    latest = (
        select(
            VictimDisclosure.group_id.label("actor_id"),
            VictimDisclosure.group_name_raw.label("slug"),
            func.row_number()
            .over(partition_by=VictimDisclosure.group_id, order_by=func.max(VictimDisclosure.posted_at).desc())
            .label("n"),
        )
        .where(
            VictimDisclosure.source == DISCLOSURE_SOURCE,
            VictimDisclosure.group_id.isnot(None),
            VictimDisclosure.group_name_raw.isnot(None),
        )
        .group_by(VictimDisclosure.group_id, VictimDisclosure.group_name_raw)
        .subquery()
    )
    profiled = (
        select(EnrichmentResult.entity_id, func.max(EnrichmentResult.expires_at).label("expires_at"))
        .where(
            EnrichmentResult.source_type == SOURCE_TYPE,
            EnrichmentResult.entity_type == entity_types.THREAT_ACTOR,
            EnrichmentResult.status == "success",
        )
        .group_by(EnrichmentResult.entity_id)
        .subquery()
    )
    rows = await db.execute(
        select(latest.c.actor_id, latest.c.slug)
        .outerjoin(profiled, profiled.c.entity_id == latest.c.actor_id)
        .where(latest.c.n == 1, (profiled.c.expires_at.is_(None)) | (profiled.c.expires_at <= datetime.now(UTC)))
        .order_by(profiled.c.expires_at.asc().nulls_first(), latest.c.slug)
        .limit(limit)
    )
    return list(rows.all())


async def sync_group_profiles(db: AsyncSession, gateway: SourceGateway, limit: int = GROUPS_PER_RUN) -> dict:
    """Look up the groups due and apply their profiles. A group ransomware.live
    doesn't know is stored as not found; a failed lookup costs that group only;
    a refusal stops the run and keeps what it did."""
    from app.enrichment.pipeline import apply_catalog_result

    stats = {"looked_up": 0, "found": 0, "updated": 0, "failed": 0, "stopped": None}
    deadline = time.monotonic() + RUN_SECONDS
    async with gateway.client(timeout=60.0) as client:
        for actor_id, slug in await _groups_due(db, limit):
            if time.monotonic() >= deadline:
                stats["stopped"] = "out_of_time"
                break
            try:
                resp = await client.get(GROUP_URL.format(quote(slug, safe="")))
                if resp.status_code == 404:
                    facts = {"found": False}
                else:
                    resp.raise_for_status()
                    body = resp.json()
                    if not isinstance(body, dict):
                        raise ValueError("not a group object")
                    facts = group_facts(body)
            except SOURCE_REFUSALS as e:
                logger.warning("ransomware.live group profiles stopping: %s", e)
                stats["stopped"] = e.status
                break
            except (httpx.HTTPError, ValueError) as e:
                logger.warning("ransomware.live group %s failed: %s", slug, e)
                stats["failed"] += 1
                continue
            stats["looked_up"] += 1
            stats["found"] += bool(facts["found"])
            # The raw answer would keep the sites' onion addresses; only the slug is kept.
            data = EnrichmentData(raw_response={"slug": slug}, parsed_data=facts, ttl_hours=TTL_HOURS)
            if await apply_catalog_result(db, entity_types.THREAT_ACTOR, actor_id, SOURCE_TYPE, data):
                stats["updated"] += 1
            await db.commit()
    return stats
