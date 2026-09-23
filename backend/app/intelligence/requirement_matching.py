"""Automated requirement matching engine.

Matches new entries against active intelligence requirements based on
linked entities (actors/malware/CVEs/TTPs extracted from the entry) and
keyword presence in entry text, with tiered relevance:

- high:   entity match, or keyword found in the title
- medium: two or more keywords found in the body
- low:    a single keyword found in the body

Machine-record content (rule-repo files, NVD vuln records) is excluded from
auto-matching — those entries are categories of data, not reporting signal.
"""

import logging
import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE, EntryCVE
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP
from app.services.content_classification import is_reporting_content

logger = logging.getLogger(__name__)

RELEVANCE_RANK = {"low": 0, "medium": 1, "high": 2}

# Keys used in IntelligenceRequirement.linked_entities
LINKED_ENTITY_KEYS = ("threat_actors", "malware", "cves", "ttps")


def _keyword_in(keyword: str, text: str) -> bool:
    """Whole-word boundary keyword check against lowercase text."""
    pattern = r"(?<!\w)" + re.escape(keyword.lower()) + r"(?!\w)"
    return re.search(pattern, text) is not None


async def _load_entry_entities(db: AsyncSession, entry_id: uuid.UUID) -> dict[str, dict[str, str]]:
    """Load entities linked to an entry as {key: {entity_id_str: display_name}}."""
    entities: dict[str, dict[str, str]] = {key: {} for key in LINKED_ENTITY_KEYS}

    actor_rows = await db.execute(
        select(ThreatActor.id, ThreatActor.name)
        .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
        .where(EntryThreatActor.entry_id == entry_id)
    )
    for eid, name in actor_rows.all():
        entities["threat_actors"][str(eid)] = name

    malware_rows = await db.execute(
        select(MalwareFamily.id, MalwareFamily.name)
        .join(EntryMalware, EntryMalware.malware_family_id == MalwareFamily.id)
        .where(EntryMalware.entry_id == entry_id)
    )
    for eid, name in malware_rows.all():
        entities["malware"][str(eid)] = name

    cve_rows = await db.execute(
        select(CVE.id, CVE.cve_id).join(EntryCVE, EntryCVE.cve_id == CVE.id).where(EntryCVE.entry_id == entry_id)
    )
    for eid, cve_id in cve_rows.all():
        entities["cves"][str(eid)] = cve_id

    ttp_rows = await db.execute(
        select(TTP.id, TTP.technique_id, TTP.technique_name)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .where(EntryTTP.entry_id == entry_id)
    )
    for eid, technique_id, technique_name in ttp_rows.all():
        label = f"{technique_id} {technique_name}".strip() if technique_name else technique_id
        entities["ttps"][str(eid)] = label

    return entities


def _match_linked_entities(linked_entities: dict, entry_entities: dict[str, dict[str, str]]) -> str | None:
    """Return the display name of the first PIR-linked entity present on the entry."""
    for key in LINKED_ENTITY_KEYS:
        for ref in (linked_entities or {}).get(key, []) or []:
            ref_id = str(ref.get("id", "")) if isinstance(ref, dict) else str(ref)
            hit = entry_entities.get(key, {}).get(ref_id)
            if hit:
                return hit
    return None


def _evaluate_requirement(
    req: IntelligenceRequirement,
    title_text: str,
    body_text: str,
    entry_entities: dict[str, dict[str, str]] | None,
) -> tuple[str, str, str] | None:
    """Evaluate one requirement against an entry.

    Returns (match_type, matched_on, relevance) or None if no match / below
    the requirement's minimum relevance.
    """
    match_type = None
    matched_on = None
    relevance = None

    # Entity match — strongest signal
    if entry_entities is not None:
        entity_hit = _match_linked_entities(req.linked_entities, entry_entities)
        if entity_hit:
            match_type, matched_on, relevance = "entity", entity_hit, "high"

    # Keyword match — title hits outweigh body hits
    if match_type is None and req.keywords:
        title_hits = [kw for kw in req.keywords if _keyword_in(kw, title_text)]
        body_hits = [kw for kw in req.keywords if _keyword_in(kw, body_text)]
        if title_hits:
            match_type, matched_on, relevance = "keyword", title_hits[0], "high"
        elif len(body_hits) >= 2:
            match_type, matched_on, relevance = "keyword", body_hits[0], "medium"
        elif len(body_hits) == 1:
            match_type, matched_on, relevance = "keyword", body_hits[0], "low"

    if match_type is None:
        return None

    # Per-PIR minimum relevance gate (None = keep all, backwards compatible)
    if req.min_relevance and RELEVANCE_RANK.get(relevance, 0) < RELEVANCE_RANK.get(req.min_relevance, 0):
        return None

    return match_type, matched_on, relevance


async def match_entry_against_requirements(db: AsyncSession, entry_id: uuid.UUID) -> list[dict]:
    """Match an entry against all active auto-match requirements.

    Checks linked entities and keyword presence in entry text.
    Returns list of match info dicts.
    """
    # Load entry
    entry = await db.get(Entry, entry_id)
    if not entry:
        logger.warning("Entry %s not found for requirement matching", entry_id)
        return []

    # Skip machine-record content (rule-repo files, NVD vuln records) —
    # these pollute PIR matches with category-level noise.
    feed = await db.get(Feed, entry.feed_id)
    if not is_reporting_content(feed.feed_type if feed else None, entry.metadata_):
        logger.debug("Skipping requirement matching for non-reporting entry %s", entry_id)
        return []

    title_text = (entry.title or "").lower()
    body_text = " ".join(filter(None, [entry.summary, entry.content_text])).lower()

    # Load active auto-match requirements
    result = await db.execute(
        select(IntelligenceRequirement).where(
            IntelligenceRequirement.status == "active",
            IntelligenceRequirement.auto_match == True,  # noqa: E712
        )
    )
    requirements = result.scalars().all()
    if not requirements:
        return []

    # Load the entry's extracted entities only if some requirement links entities
    entry_entities = None
    if any((req.linked_entities or {}).get(key) for req in requirements for key in LINKED_ENTITY_KEYS):
        entry_entities = await _load_entry_entities(db, entry_id)

    matches = []
    for req in requirements:
        # Check feed filter
        if req.linked_feed_ids and entry.feed_id not in req.linked_feed_ids:
            continue

        # Check for existing match
        existing = await db.execute(
            select(RequirementMatch).where(
                RequirementMatch.requirement_id == req.id,
                RequirementMatch.entry_id == entry_id,
            )
        )
        if existing.scalar_one_or_none():
            continue

        evaluated = _evaluate_requirement(req, title_text, body_text, entry_entities)
        if not evaluated:
            continue
        match_type, matched_on, relevance = evaluated

        match = RequirementMatch(
            requirement_id=req.id,
            entry_id=entry_id,
            match_type=match_type,
            matched_on=matched_on,
            relevance=relevance,
        )
        db.add(match)

        req.match_count += 1
        req.last_matched_at = datetime.now(UTC)

        matches.append(
            {
                "requirement_id": str(req.id),
                "requirement_title": req.title,
                "entry_id": str(entry_id),
                "match_type": match_type,
                "matched_on": matched_on,
                "relevance": relevance,
            }
        )

    if matches:
        await db.flush()
        logger.info("Matched entry %s against %d requirements", entry_id, len(matches))

        # Create correlation events for each match
        from app.intelligence.correlation_events import create_requirement_match_event

        for m in matches:
            await create_requirement_match_event(
                db,
                entry_id=entry_id,
                requirement_id=uuid.UUID(m["requirement_id"]),
                requirement_title=m["requirement_title"],
                matched_on=m["matched_on"],
            )

    return matches


async def check_requirement_expiry(db: AsyncSession) -> int:
    """Expire requirements past their expires_at date. Returns count expired."""
    now = datetime.now(UTC)
    result = await db.execute(
        select(IntelligenceRequirement).where(
            IntelligenceRequirement.status == "active",
            IntelligenceRequirement.expires_at.isnot(None),
            IntelligenceRequirement.expires_at < now,
        )
    )
    expired_reqs = result.scalars().all()
    for req in expired_reqs:
        req.status = "expired"

    if expired_reqs:
        await db.flush()
        logger.info("Expired %d intelligence requirements", len(expired_reqs))

    return len(expired_reqs)
