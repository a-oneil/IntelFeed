"""ETDA Threat Group Cards: ThaiCERT's threat actor encyclopedia, matched to the
threat actors IntelFeed already tracks.

The weekly job downloads the whole encyclopedia in one request (the export,
about 2 MB of JSON for some 500 cards; the per-name card API no longer answers
by name). A card matches an actor by its MITRE ATT&CK group id, else by an
exact name or alias (the resolver's normalized form) — one card to one actor,
never by a fuzzy match, and no actor is ever created. A card that names
several actors, or an actor several cards name, is skipped.

A matched card fills the actor's blank country, motivation and MITRE id, adds
its names as aliases through the alias gate, claims the sectors and countries
it targets and the tools it uses (``app/enrichment/relations.py``), and shows
its sponsor, first sighting, operations and counter-operations on the profile.
An actor whose card stopped matching has those claims and that context
withdrawn.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import quote

from sqlalchemy import select, union
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.enrichment.base import EnrichmentData, Source
from app.enrichment.gateway import SOURCE_REFUSALS, SourceGateway
from app.enrichment.manifest import Column, Context, Display, Egress, Job, License, Policy, Quota, Relation

logger = logging.getLogger(__name__)

EXPORT_URL = "https://apt.etda.or.th/cgi-bin/getcard.cgi?g=all&o=j"
CARD_URL = "https://apt.etda.or.th/cgi-bin/showcard.cgi?g={}&n=1"
#: Two weekly runs, so one missed week doesn't mark the cards stale.
TTL_HOURS = 336
#: Actors applied per commit.
BATCH = 50

_GROUP_ID = re.compile(r"/groups/(G\d{4})\b")
_URL = re.compile(r"https?://\S+")

#: ETDA's sector names the shared vocabulary (``app/intelligence/sectors.py``)
#: doesn't already fold. A name neither maps is not a sector IntelFeed tracks
#: (construction, mining, real estate) and is left out.
SECTORS = {
    "high-tech": "technology",
    "online video game companies": "technology",
    "industrial": "manufacturing",
    "petrochemical": "energy",
    "shipping and logistics": "transportation",
    "maritime and shipbuilding": "transportation",
    "casinos and gambling": "hospitality",
    "biotechnology": "healthcare",
    "diplomatic missions": "government",
    "intelligence agencies": "government",
    "intelligence organizations": "government",
    "bitcoin exchanges": "cryptocurrency",
    "legal and professional services": "professional-services",
    "business-to-business it service providers": "msp",
}


class ETDASource(Source):
    source_type = "etda"
    display_name = "ETDA Threat Group Cards"
    applies_to = {"threat_actor": None}
    # One 2 MB download a week.
    quota = Quota(10, 3600, daily_budget=20)
    egress = Egress.NONE
    # The export and https://apt.etda.or.th/cgi-bin/aptgroups.cgi: "published
    # under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0
    # International License. Copyright © Electronic Transactions Development
    # Agency" (checked 2026-10-28).
    license = License(
        "CC BY-NC-SA 4.0",
        attribution="Threat Group Cards: A Threat Actor Encyclopedia, ETDA / ThaiCERT",
        commercial_ok=False,
    )
    jobs = (
        Job(
            "etda-sync",
            "app.workers.enrichment_tasks.run_etda_sync",
            {"type": "crontab", "minute": "15", "hour": "4", "day_of_week": "2"},
            "Match ETDA Threat Group Cards to tracked actors: aliases, origin, targets, tools and operations",
        ),
    )
    outputs = (
        Column("aliases", "threat_actor.aliases", Policy.UNION, rank=3, filter="aliases"),
        Column("country", "threat_actor.country", resolve="country"),
        Column("country", "threat_actor.origin_country_id", resolve="country_id"),
        Column("motivation", "threat_actor.motivation"),
        Column("mitre_id", "threat_actor.mitre_id", Policy.RANK, rank=3),
        Relation("sectors", "targets", (entity_types.SECTOR,)),
        Relation("countries", "targets", (entity_types.COUNTRY,)),
        Relation("tools", "uses", (entity_types.MALWARE, entity_types.TOOL)),
        Context("sponsor", "Sponsor", Display.FACT),
        Context("first_seen", "First seen", Display.FACT),
        Context("operations", "Operations", Display.TIMELINE, item={"date": "date", "text": "text"}),
        Context("counter_operations", "Counter operations", Display.TIMELINE, item={"date": "date", "text": "text"}),
        Context("card_changed", "Card changed", Display.FACT),
        Context("card", "Threat Group Card", Display.LINK),
    )


# ── Reading a card ───────────────────────────────────────────────────


def _strings(value) -> list[str]:
    return [v.strip() for v in value if isinstance(v, str) and v.strip()] if isinstance(value, list) else []


def card_names(card: dict) -> list[str]:
    names = [n.get("name") for n in card.get("names") or [] if isinstance(n, dict)]
    return list(dict.fromkeys(n.strip() for n in names if isinstance(n, str) and n.strip()))


def card_group_ids(card: dict) -> list[str]:
    """The MITRE ATT&CK group ids the card links to (``…/groups/G0016/``)."""
    return list(dict.fromkeys(m for url in _strings(card.get("mitre-attack")) for m in _GROUP_ID.findall(url)))


def _sector(name: str) -> str | None:
    from app.intelligence.sectors import normalize_sector

    return normalize_sector(name) or SECTORS.get(name.strip().lower())


def _events(value) -> list[dict]:
    """``[{date, activity}]`` → ``[{date, text}]``: the activity's first line,
    with the first link it cites."""
    events = []
    for row in value if isinstance(value, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get("activity"), str):
            continue
        lines = [line.strip() for line in row["activity"].splitlines() if line.strip()]
        text = next((line for line in lines if not _URL.fullmatch(line)), None)
        url = next((m.group(0) for line in lines if (m := _URL.search(line))), None)
        if text and url and url not in text:
            text = f"{text} ({url})"
        if text := text or url:
            events.append({"date": str(row.get("date") or "").strip() or None, "text": text})
    return events


def card_facts(card: dict) -> dict:
    """What a card says, as the source's parsed_data (aliases still ungated)."""
    from app.intelligence.actor_attributes import coerce_motivation

    names = card_names(card)
    countries = [c for c in _strings(card.get("country")) if not c.startswith("[")]
    actor = (card.get("actor") or "").strip()
    return {
        "found": True,
        "names": names,
        "aliases": names,
        "country": countries[0] if countries else None,
        "motivation": next((m for m in map(coerce_motivation, _strings(card.get("motivation"))) if m), None),
        "mitre_id": next(iter(card_group_ids(card)), None),
        "sectors": list(dict.fromkeys(s for s in map(_sector, _strings(card.get("observed-sectors"))) if s)),
        "countries": _strings(card.get("observed-countries")),
        "tools": list(dict.fromkeys(_strings(card.get("tools")))),
        "sponsor": (card.get("sponsor") or "").strip() or None,
        "first_seen": (card.get("first-seen") or "").strip() or None,
        "operations": _events(card.get("operations")),
        "counter_operations": _events(card.get("counter-operations")),
        "card_changed": (card.get("last-card-change") or "").strip() or None,
        "card": {"url": CARD_URL.format(quote(actor)), "label": actor} if actor else None,
    }


# ── Matching cards to actors ─────────────────────────────────────────


async def match_cards(db: AsyncSession, cards: list[dict]) -> tuple[dict, dict]:
    """Actor id → its card, and counts of what didn't match.

    A card's MITRE group id picks the actor holding that id; failing that, its
    names must resolve, through the resolver's alias index, to exactly one
    actor, and not to one whose MITRE id the card contradicts. When several
    cards land on one actor, a card matched by its group id beats name
    matches, and a tie skips the actor."""
    from app.intelligence.entity_resolution import normalize_entity_name
    from app.models.entity_index import EntityAliasIndex
    from app.models.threat_actor import ThreatActor

    by_norm: dict[str, set] = {}
    for actor_id, norm in await db.execute(
        select(EntityAliasIndex.entity_id, EntityAliasIndex.normalized).where(
            EntityAliasIndex.entity_type == entity_types.THREAT_ACTOR
        )
    ):
        by_norm.setdefault(norm, set()).add(actor_id)
    mitre_of = {
        actor_id: mitre_id.strip().upper()
        for actor_id, mitre_id in await db.execute(
            select(ThreatActor.id, ThreatActor.mitre_id).where(ThreatActor.mitre_id.isnot(None))
        )
        if mitre_id and mitre_id.strip()
    }
    by_mitre: dict[str, set] = {}
    for actor_id, mitre_id in mitre_of.items():
        by_mitre.setdefault(mitre_id, set()).add(actor_id)

    stats = {"cards": len(cards), "ambiguous": 0, "unmatched": 0}
    claims: dict = {}  # actor id → [(strength, card)]
    for card in cards:
        gids = card_group_ids(card)
        by_gid = set().union(*(by_mitre.get(g, set()) for g in gids))
        if len(by_gid) == 1:
            claims.setdefault(next(iter(by_gid)), []).append((2, card))
            continue
        if by_gid:
            stats["ambiguous"] += 1
            continue
        hits = set().union(
            *(
                by_norm.get(normalize_entity_name(n, entity_types.THREAT_ACTOR).norm_exact, set())
                for n in card_names(card)
            )
        )
        # No actor holds the card's group id, so one holding another id is a different group.
        hits = {a for a in hits if not (gids and a in mitre_of)}
        if len(hits) == 1:
            claims.setdefault(next(iter(hits)), []).append((1, card))
        else:
            stats["ambiguous" if hits else "unmatched"] += 1

    matches = {}
    for actor_id, found in claims.items():
        best = max(strength for strength, _ in found)
        top = [card for strength, card in found if strength == best]
        if len(top) == 1:
            matches[actor_id] = top[0]
        else:
            stats["ambiguous"] += len(found)
    return matches, stats


# ── The job ──────────────────────────────────────────────────────────


async def _gated_aliases(db: AsyncSession, actor, names: list[str]) -> list[str]:
    """The card's names the actor doesn't carry yet that pass the alias gate,
    which drops any another actor already owns."""
    from app.intelligence.entity_resolution import gate_aliases, normalize_entity_name

    def norm(n):
        return normalize_entity_name(n, entity_types.THREAT_ACTOR).norm_exact

    held = {norm(n) for n in [actor.name, *(actor.aliases or [])]}
    new = [n for n in names if norm(n) not in held]
    if not new:
        return []
    return await gate_aliases(
        db, entity_types.THREAT_ACTOR, actor.name, new, entity_id=actor.id, source=ETDASource.source_type
    )


async def _previously_matched(db: AsyncSession) -> set:
    """Actors holding this source's context or relation claims."""
    from app.models.enrichment import EntityContext, EntityRelationClaim

    rows = await db.execute(
        union(
            select(EntityContext.entity_id).where(
                EntityContext.source_type == ETDASource.source_type,
                EntityContext.entity_type == entity_types.THREAT_ACTOR,
            ),
            select(EntityRelationClaim.entity_id).where(
                EntityRelationClaim.source_type == ETDASource.source_type,
                EntityRelationClaim.entity_type == entity_types.THREAT_ACTOR,
            ),
        )
    )
    return set(rows.scalars())


async def sync_etda(db: AsyncSession, gateway: SourceGateway) -> dict:
    """Download the cards, match them and apply each match; withdraw what an
    actor whose card no longer matches was given. A refusal stops the run
    before anything changes; an error status raises."""
    from app.enrichment.pipeline import apply_catalog_result
    from app.models.threat_actor import ThreatActor

    stats = {"cards": 0, "matched": 0, "updated": 0, "ambiguous": 0, "unmatched": 0, "withdrawn": 0, "stopped": None}
    try:
        async with gateway.client(timeout=120.0) as client:
            resp = await client.get(EXPORT_URL)
            resp.raise_for_status()
            payload = resp.json()
    except SOURCE_REFUSALS as e:
        logger.warning("ETDA sync stopping: %s", e)
        stats["stopped"] = e.status
        return stats

    cards = [c for c in (payload.get("values") or []) if isinstance(c, dict)] if isinstance(payload, dict) else []
    if not cards:
        # An export with no cards is a broken download, not ETDA dropping every group.
        stats["stopped"] = "empty_export"
        return stats
    matches, counts = await match_cards(db, cards)
    stats.update(counts, matched=len(matches))
    now_found = set(matches)

    for n, (actor_id, card) in enumerate(sorted(matches.items(), key=lambda kv: str(kv[0]))):
        actor = await db.get(ThreatActor, actor_id)
        if actor is None:
            continue
        facts = card_facts(card)
        facts["aliases"] = await _gated_aliases(db, actor, facts["names"])
        data = EnrichmentData(raw_response={"uuid": card.get("uuid")}, parsed_data=facts, ttl_hours=TTL_HOURS)
        if await apply_catalog_result(db, entity_types.THREAT_ACTOR, actor_id, ETDASource.source_type, data):
            stats["updated"] += 1
        if n % BATCH == BATCH - 1:
            await db.commit()

    for actor_id in await _previously_matched(db) - now_found:
        data = EnrichmentData(raw_response={}, parsed_data={"found": False}, ttl_hours=TTL_HOURS)
        await apply_catalog_result(db, entity_types.THREAT_ACTOR, actor_id, ETDASource.source_type, data)
        stats["withdrawn"] += 1
    await db.commit()
    return stats
