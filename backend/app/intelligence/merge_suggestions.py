"""Ranked entity merge suggestions.

Complements the manual Find Duplicates endpoint (substring/alias grouping in
``app/api/entity_profiles.py``) with scored pair suggestions that combine:

  - normalized-name similarity (generic-suffix stripping, token containment
    like "Pegasus" ⊂ "Pegasus Spyware", token overlap)
  - alias overlap (one entity's name is another's alias, shared aliases)
  - shared entity relationships (both related to the same third entity, or
    directly related to each other — a common symptom of undetected dupes)
  - co-mention frequency (entities that co-occur in the same entries AND have
    similar names are strong merge candidates)

Also flags cross-type tool-vs-malware name collisions as "possible cross-type
duplicate" without offering auto-merge (those need reclassify, not merge).

Pairs the analyst dismissed are persisted in
``entity_merge_suggestion_dismissals`` and excluded from future responses.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from dataclasses import dataclass

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.country import Country, EntryCountry
from app.models.entity_maintenance import EntityMergeSuggestionDismissal
from app.models.entity_relationship import EntityRelationship
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.product import EntryProduct, Product
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.vendor import EntryVendor, Vendor

# entity_type (API slug, matches MERGE_CONFIG in app/api/entity_profiles.py)
# -> (model, junction model, junction FK attribute)
SUGGESTION_CONFIG: dict[str, tuple] = {
    "threat_actor": (ThreatActor, EntryThreatActor, "threat_actor_id"),
    "malware": (MalwareFamily, EntryMalware, "malware_family_id"),
    "country": (Country, EntryCountry, "country_id"),
    "tool": (Tool, EntryTool, "tool_id"),
    "vendor": (Vendor, EntryVendor, "vendor_id"),
    "product": (Product, EntryProduct, "product_id"),
}

# Cross-type collision partners: the actor/malware/tool trio share a namespace
# in the wild. Tool names duplicate malware names ("NSO Group Pegasus" tool vs
# "Pegasus" malware), and every ransomware brand duplicates itself across actor
# and malware ("Qilin" the gang vs "Qilin" the payload) — the single biggest
# source of same-name pairs in Hot Correlations. Flag, never auto-merge: these
# need reclassify (cross-type fold), not merge.
CROSS_TYPE_PARTNERS: dict[str, tuple[str, ...]] = {
    "threat_actor": ("malware", "tool"),
    "malware": ("tool", "threat_actor"),
    "tool": ("malware", "threat_actor"),
}

# Trailing tokens that carry no identity — "Pegasus Spyware" and "Pegasus"
# are the same thing, as are "Clop Ransomware Gang" and "Clop".
GENERIC_SUFFIX_TOKENS = frozenset(
    {
        "spyware",
        "malware",
        "ransomware",
        "group",
        "apt",
        "team",
        "gang",
        "botnet",
        "trojan",
        "stealer",
        "backdoor",
        "worm",
        "rat",
        "loader",
        "actor",
        "actors",
        "threat",
    }
)

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def normalize_name(name: str) -> str:
    """Lowercase, strip punctuation, and drop trailing generic suffix tokens.

    Never strips down to nothing — a name that is *only* generic tokens keeps
    its last token ("APT Group" -> "apt").
    """
    tokens = [t for t in _TOKEN_SPLIT_RE.split((name or "").lower()) if t]
    while len(tokens) > 1 and tokens[-1] in GENERIC_SUFFIX_TOKENS:
        tokens.pop()
    return " ".join(tokens)


def significant_tokens(normalized: str) -> frozenset[str]:
    """Token set of a normalized name with generic filler tokens removed.

    Falls back to the full token set when every token is generic, so a name
    like "APT Group" still has something to compare.
    """
    tokens = frozenset(normalized.split())
    significant = frozenset(t for t in tokens if t not in GENERIC_SUFFIX_TOKENS)
    return significant or tokens


@dataclass
class EntityView:
    """Precomputed comparison view of one entity."""

    entity_type: str
    id: uuid.UUID
    name: str
    aliases: list[str]
    article_count: int
    norm: str
    sig_tokens: frozenset[str]
    alias_norms: frozenset[str]  # normalized aliases (canonical name excluded)
    entry_ids: frozenset  # entry UUIDs linked via the junction table
    rel_keys: frozenset  # {(entity_type, entity_id_str)} relationship endpoints


def make_view(
    entity_type: str,
    entity,
    entry_ids: set | None = None,
    rel_keys: set | None = None,
) -> EntityView:
    norm = normalize_name(entity.name)
    return EntityView(
        entity_type=entity_type,
        id=entity.id,
        name=entity.name,
        aliases=list(entity.aliases or []),
        article_count=getattr(entity, "article_count", 0) or 0,
        norm=norm,
        sig_tokens=significant_tokens(norm),
        alias_norms=frozenset(n for n in (normalize_name(a) for a in (entity.aliases or [])) if n and n != norm),
        entry_ids=frozenset(entry_ids or ()),
        rel_keys=frozenset(rel_keys or ()),
    )


def _name_signal(a: EntityView, b: EntityView) -> tuple[float, list[str]]:
    """Similarity of canonical names. Returns (score, reasons)."""
    if a.norm and a.norm == b.norm:
        return 0.6, [f"identical name after normalization ('{a.norm}')"]
    if a.sig_tokens and b.sig_tokens and a.sig_tokens != b.sig_tokens:
        small, big = sorted((a.sig_tokens, b.sig_tokens), key=len)
        # Containment: "pegasus" ⊂ {"nso", "pegasus"}. Require the contained
        # name to have some substance so 2-3 letter fragments don't match.
        if small <= big and len("".join(small)) >= 4:
            contained = a.name if small == a.sig_tokens else b.name
            container = b.name if contained == a.name else a.name
            return 0.45, [f"name containment: '{contained}' within '{container}'"]
        overlap = len(a.sig_tokens & b.sig_tokens)
        if overlap:
            jaccard = overlap / len(a.sig_tokens | b.sig_tokens)
            if jaccard >= 0.5:
                return round(0.3 * jaccard, 3), [f"name token overlap ({jaccard:.0%})"]
    return 0.0, []


def _alias_signal(a: EntityView, b: EntityView) -> tuple[float, list[str]]:
    """Overlap between names and alias sets. Returns (score, reasons)."""
    score = 0.0
    reasons: list[str] = []
    if (b.norm and b.norm in a.alias_norms) or (a.norm and a.norm in b.alias_norms):
        score = 0.5
        reasons.append("one entity's name is an alias of the other")
    shared = a.alias_norms & b.alias_norms
    if shared:
        score = max(score, 0.45)
        reasons.append(f"shared aliases: {', '.join(sorted(shared)[:3])}")
    return score, reasons


def score_pair(a: EntityView, b: EntityView) -> tuple[float, list[str]]:
    """Score one candidate pair. Returns (score 0..1, reasons).

    A pair is only a candidate when a name or alias signal fires; shared
    relationships and co-mentions then boost the rank. This keeps unrelated
    entities that merely co-occur in busy articles out of the list.
    """
    name_score, name_reasons = _name_signal(a, b)
    alias_score, alias_reasons = _alias_signal(a, b)
    base = max(name_score, alias_score)
    if base <= 0:
        return 0.0, []

    reasons = name_reasons + alias_reasons
    score = base
    if name_score > 0 and alias_score > 0:
        score += 0.1  # independent signals corroborating each other

    self_keys = {(a.entity_type, str(a.id)), (b.entity_type, str(b.id))}
    if (b.entity_type, str(b.id)) in a.rel_keys or (a.entity_type, str(a.id)) in b.rel_keys:
        score += 0.05
        reasons.append("directly related to each other")
    shared_rels = (a.rel_keys & b.rel_keys) - self_keys
    if shared_rels:
        score += min(len(shared_rels), 5) * 0.04
        reasons.append(f"{len(shared_rels)} shared relationship(s)")

    co_mentions = len(a.entry_ids & b.entry_ids)
    if co_mentions:
        score += min(co_mentions, 10) * 0.02
        reasons.append(f"co-mentioned in {co_mentions} entr{'y' if co_mentions == 1 else 'ies'}")

    return min(round(score, 3), 1.0), reasons


def pair_key(
    type_a: str, id_a: uuid.UUID | str, type_b: str, id_b: uuid.UUID | str
) -> tuple[tuple[str, str], tuple[str, str]]:
    """Canonical, order-independent key for a suggestion pair."""
    p1 = (type_a, str(id_a))
    p2 = (type_b, str(id_b))
    return (p1, p2) if p1 <= p2 else (p2, p1)


async def _load_views(db: AsyncSession, entity_type: str) -> list[EntityView]:
    model, junction, fk_attr = SUGGESTION_CONFIG[entity_type]
    entities = (await db.execute(select(model))).scalars().all()
    if not entities:
        return []

    fk_col = getattr(junction, fk_attr)
    entry_map: dict[uuid.UUID, set] = defaultdict(set)
    for eid, entry_id in (await db.execute(select(fk_col, junction.entry_id))).all():
        entry_map[eid].add(entry_id)

    rel_map: dict[uuid.UUID, set] = defaultdict(set)
    rel_rows = await db.execute(
        select(
            EntityRelationship.source_type,
            EntityRelationship.source_id,
            EntityRelationship.target_type,
            EntityRelationship.target_id,
        ).where(
            or_(
                EntityRelationship.source_type == entity_type,
                EntityRelationship.target_type == entity_type,
            )
        )
    )
    for s_type, s_id, t_type, t_id in rel_rows.all():
        if s_type == entity_type:
            rel_map[s_id].add((t_type, str(t_id)))
        if t_type == entity_type:
            rel_map[t_id].add((s_type, str(s_id)))

    return [make_view(entity_type, e, entry_map.get(e.id), rel_map.get(e.id)) for e in entities]


async def _load_dismissed_keys(db: AsyncSession) -> set[tuple]:
    rows = (await db.execute(select(EntityMergeSuggestionDismissal))).scalars().all()
    return {pair_key(r.entity_type_a, r.entity_id_a, r.entity_type_b, r.entity_id_b) for r in rows}


def _entity_payload(v: EntityView) -> dict:
    return {
        "id": str(v.id),
        "entity_type": v.entity_type,
        "name": v.name,
        "aliases": v.aliases,
        "article_count": v.article_count,
    }


def _build_suggestion(a: EntityView, b: EntityView, score: float, reasons: list[str], cross_type: bool) -> dict:
    # Keeper = the entity with more linked articles (tie: alphabetical name so
    # the ordering is deterministic). For cross-type pairs there is no merge,
    # but the ordering still gives the UI a stable presentation.
    keeper, candidate = (a, b) if (a.article_count, b.name) >= (b.article_count, a.name) else (b, a)
    return {
        "keeper": _entity_payload(keeper),
        "candidate": _entity_payload(candidate),
        "score": score,
        "reasons": reasons,
        "cross_type": cross_type,
    }


async def suggest_merges(db: AsyncSession, entity_type: str, limit: int = 50) -> dict:
    """Produce ranked duplicate-pair suggestions for one entity type.

    Includes cross-type tool-vs-malware collisions (flagged ``cross_type``)
    when the requested type is malware or tool. Dismissed pairs are excluded.
    """
    if entity_type not in SUGGESTION_CONFIG:
        raise ValueError(f"unsupported entity_type: {entity_type}")

    views = await _load_views(db, entity_type)
    dismissed = await _load_dismissed_keys(db)
    suggestions: list[dict] = []

    for i, a in enumerate(views):
        for b in views[i + 1 :]:
            if pair_key(a.entity_type, a.id, b.entity_type, b.id) in dismissed:
                continue
            score, reasons = score_pair(a, b)
            if score <= 0:
                continue
            suggestions.append(_build_suggestion(a, b, score, reasons, cross_type=False))

    for partner_type in CROSS_TYPE_PARTNERS.get(entity_type, ()):
        partner_views = await _load_views(db, partner_type)
        for a in views:
            for b in partner_views:
                if pair_key(a.entity_type, a.id, b.entity_type, b.id) in dismissed:
                    continue
                score, reasons = score_pair(a, b)
                if score <= 0:
                    continue
                reasons = [f"possible cross-type duplicate ({entity_type} vs {partner_type})"] + reasons
                suggestions.append(_build_suggestion(a, b, score, reasons, cross_type=True))

    suggestions.sort(key=lambda s: s["score"], reverse=True)
    return {"suggestions": suggestions[:limit], "total": len(suggestions)}
