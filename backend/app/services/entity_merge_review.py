"""Catalogue-wide duplicate review: an AI task that judges likely-duplicate pairs.

The adjudicate stage only merges an entity minted by the article it is
reviewing, so two entries that both already exist ("APT29" and "Cozy Bear
Group", or "Qakbot" and "QBot") are never put side by side. This job does
that. It is deterministic about *which* pairs to ask about and leaves the
*answer* to the model:

  candidates   — same-type pairs of actors, malware and tools that look alike
                 by one of three signals: a trigram-similar name, a shared
                 alias (one side's name or alias equals the other's), or
                 co-occurrence in the same articles. Pairs an analyst marked
                 "not a duplicate", pairs with a pending merge proposal and
                 pairs judged recently are skipped.
  review       — the pairs go to the ``entity_merge_review`` AI task a few at
                 a time, with both profiles and the signals printed.
  file         — a "same" verdict becomes an ``adjudication_merge`` proposal
                 in the maintenance log (the loser is the entity, the keeper
                 the target), which the Review tab shows as a Merge row with
                 Apply / Dismiss. Nothing is merged without a person. A
                 "different" or "unsure" verdict is logged as
                 ``merge_review_distinct`` so the pair is not asked again for
                 a while.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.entity_types import MALWARE, THREAT_ACTOR, TOOL
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool

logger = logging.getLogger(__name__)

TASK_NAME = "entity_merge_review"
ACTION_DISTINCT = "merge_review_distinct"
ORIGIN = "merge_review"

# What a filed proposal's ``after.origin`` says, so the queue can tell these
# rows from the adjudicate stage's own merges.
_TYPES: dict[str, tuple[type, type, str, str]] = {
    THREAT_ACTOR: (ThreatActor, EntryThreatActor, "threat_actor_id", "threat_actors"),
    MALWARE: (MalwareFamily, EntryMalware, "malware_family_id", "malware_families"),
    TOOL: (Tool, EntryTool, "tool_id", "tools"),
}
REVIEWABLE_TYPES = tuple(_TYPES)

_CONF_RANK = {"high": 3, "medium": 2, "low": 1}

# Pairs that only share articles (no name or alias signal) need this many
# before they are worth a question: the names differ, so co-occurrence alone
# is usually two different things in the same report.
_MIN_SHARED_ONLY = 3

# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------

# Name-similar pairs (trigram index) and alias-sharing pairs, in one query per
# type. Excluded: pairs an analyst marked not-duplicate, pairs with a pending
# merge proposal either way, and pairs judged within the retry window.
_CANDIDATES_SQL = """
WITH pairs AS (
    SELECT a.id AS a_id, b.id AS b_id,
           similarity(a.normalized_name, b.normalized_name) AS sim,
           EXISTS (
             SELECT 1
             FROM unnest(array_append(coalesce(a.aliases, ARRAY[]::text[]), a.name)) x
             JOIN unnest(array_append(coalesce(b.aliases, ARRAY[]::text[]), b.name)) y
               ON lower(x) = lower(y)
           ) AS alias_hit
    FROM {table} a
    JOIN {table} b ON a.id < b.id
    WHERE (
        (a.normalized_name IS NOT NULL AND b.normalized_name IS NOT NULL
         AND a.normalized_name % b.normalized_name
         AND similarity(a.normalized_name, b.normalized_name) >= :min_sim)
        OR EXISTS (
             SELECT 1
             FROM unnest(array_append(coalesce(a.aliases, ARRAY[]::text[]), a.name)) x
             JOIN unnest(array_append(coalesce(b.aliases, ARRAY[]::text[]), b.name)) y
               ON lower(x) = lower(y)
        )
    )
)
SELECT a_id, b_id, sim, alias_hit
FROM pairs p
WHERE NOT EXISTS (
    SELECT 1 FROM proposal_dismissals d
    WHERE d.kind = 'not_duplicate' AND d.entity_type = :etype
      AND ((d.entity_id = p.a_id AND d.other_key = p.b_id::text)
        OR (d.entity_id = p.b_id AND d.other_key = p.a_id::text))
)
AND NOT EXISTS (
    SELECT 1 FROM entity_maintenance_log m
    WHERE m.entity_type = :etype
      AND ((m.entity_id = p.a_id AND m.after->>'target_id' = p.b_id::text)
        OR (m.entity_id = p.b_id AND m.after->>'target_id' = p.a_id::text))
      AND ((m.action = 'adjudication_merge' AND m.applied = false)
        OR (m.action = 'merge_review_distinct'
            AND m.created_at > now() - make_interval(days => :retry_days)))
)
"""

# Pairs that co-occur in articles, whatever their names: the same entity under
# two names tends to be linked from the same reporting. Same exclusions.
_COOCCUR_SQL = """
WITH pairs AS (
    SELECT x.{fk} AS a_id, y.{fk} AS b_id, count(*) AS shared
    FROM {junction} x
    JOIN {junction} y ON x.entry_id = y.entry_id AND x.{fk} < y.{fk}
    GROUP BY 1, 2
    HAVING count(*) >= :min_shared
)
SELECT a_id, b_id, shared
FROM pairs p
WHERE NOT EXISTS (
    SELECT 1 FROM proposal_dismissals d
    WHERE d.kind = 'not_duplicate' AND d.entity_type = :etype
      AND ((d.entity_id = p.a_id AND d.other_key = p.b_id::text)
        OR (d.entity_id = p.b_id AND d.other_key = p.a_id::text))
)
AND NOT EXISTS (
    SELECT 1 FROM entity_maintenance_log m
    WHERE m.entity_type = :etype
      AND ((m.entity_id = p.a_id AND m.after->>'target_id' = p.b_id::text)
        OR (m.entity_id = p.b_id AND m.after->>'target_id' = p.a_id::text))
      AND ((m.action = 'adjudication_merge' AND m.applied = false)
        OR (m.action = 'merge_review_distinct'
            AND m.created_at > now() - make_interval(days => :retry_days)))
)
ORDER BY shared DESC
LIMIT :cap
"""


@dataclass
class Candidate:
    entity_type: str
    a_id: uuid.UUID
    b_id: uuid.UUID
    similarity: float = 0.0
    alias_hit: bool = False
    shared_entries: int = 0
    score: float = 0.0
    pair_id: str = ""
    a: dict = field(default_factory=dict)
    b: dict = field(default_factory=dict)
    sample_titles: list[str] = field(default_factory=list)

    @property
    def signals(self) -> dict:
        return {
            "similarity": round(self.similarity, 3),
            "alias_hit": self.alias_hit,
            "shared_entries": self.shared_entries,
            "score": round(self.score, 3),
        }


def _score(c: Candidate) -> float:
    return c.similarity + (0.35 if c.alias_hit else 0.0) + min(c.shared_entries, 5) * 0.04


async def _shared_entries(db: AsyncSession, entity_type: str, a: uuid.UUID, b: uuid.UUID) -> int:
    _model, junction, fk, _table = _TYPES[entity_type]
    x = junction.__table__.alias("x")
    y = junction.__table__.alias("y")
    q = select(func.count()).select_from(x.join(y, x.c.entry_id == y.c.entry_id)).where(x.c[fk] == a, y.c[fk] == b)
    return int((await db.execute(q)).scalar_one())


async def find_merge_candidates(
    db: AsyncSession,
    *,
    limit: int,
    min_similarity: float,
    retry_days: int,
    types: tuple[str, ...] = REVIEWABLE_TYPES,
) -> list[Candidate]:
    """The ``limit`` most likely duplicate pairs across the reviewable types,
    scored by name similarity, a shared alias and shared articles."""
    found: dict[tuple[str, uuid.UUID, uuid.UUID], Candidate] = {}
    for etype in types:
        if etype not in _TYPES:
            continue
        _model, junction, fk, table = _TYPES[etype]
        rows = (
            await db.execute(
                text(_CANDIDATES_SQL.format(table=table)).bindparams(
                    etype=etype, min_sim=min_similarity, retry_days=retry_days
                )
            )
        ).all()
        for a_id, b_id, sim, alias_hit in rows:
            found[(etype, a_id, b_id)] = Candidate(
                entity_type=etype, a_id=a_id, b_id=b_id, similarity=float(sim or 0.0), alias_hit=bool(alias_hit)
            )
        rows = (
            await db.execute(
                text(_COOCCUR_SQL.format(junction=junction.__tablename__, fk=fk)).bindparams(
                    etype=etype, min_shared=_MIN_SHARED_ONLY, retry_days=retry_days, cap=max(limit * 3, 50)
                )
            )
        ).all()
        for a_id, b_id, shared in rows:
            key = (etype, a_id, b_id)
            if key in found:
                found[key].shared_entries = int(shared)
            else:
                found[key] = Candidate(entity_type=etype, a_id=a_id, b_id=b_id, shared_entries=int(shared))
    # Name/alias pairs did not count shared articles yet: cheap per pair.
    for c in found.values():
        if c.shared_entries == 0 and (c.similarity or c.alias_hit):
            c.shared_entries = await _shared_entries(db, c.entity_type, c.a_id, c.b_id)
        c.score = _score(c)
    ranked = sorted(found.values(), key=lambda c: -c.score)[:limit]
    for i, c in enumerate(ranked, 1):
        c.pair_id = f"p{i}"
    await _load_profiles(db, ranked)
    return ranked


async def _load_profiles(db: AsyncSession, cands: list[Candidate]) -> None:
    for c in cands:
        model, junction, fk, _table = _TYPES[c.entity_type]
        for side in ("a", "b"):
            obj = await db.get(model, getattr(c, f"{side}_id"))
            setattr(c, side, _profile(obj))
        if c.shared_entries:
            x = junction.__table__.alias("x")
            y = junction.__table__.alias("y")
            titles = (
                await db.execute(
                    select(Entry.title)
                    .select_from(x.join(y, x.c.entry_id == y.c.entry_id).join(Entry, Entry.id == x.c.entry_id))
                    .where(x.c[fk] == c.a_id, y.c[fk] == c.b_id)
                    .order_by(Entry.published_at.desc().nullslast())
                    .limit(3)
                )
            ).scalars()
            c.sample_titles = [t for t in titles if t]


def _profile(obj) -> dict:
    if obj is None:
        return {}
    desc = (getattr(obj, "description", None) or "").strip().replace("\n", " ")
    if len(desc) > 320:
        desc = desc[:317] + "…"
    first = getattr(obj, "first_seen_at", None)
    return {
        "id": str(obj.id),
        "name": obj.name,
        "aliases": list(getattr(obj, "aliases", None) or [])[:12],
        "description": desc,
        "article_count": int(getattr(obj, "article_count", 0) or 0),
        "created_via": getattr(obj, "created_via", None),
        "first_seen": first.date().isoformat() if first else None,
        "subtype": getattr(obj, "actor_type", None)
        or getattr(obj, "malware_type", None)
        or getattr(obj, "tool_type", None),
    }


# ---------------------------------------------------------------------------
# Prompt block
# ---------------------------------------------------------------------------


def _side(label: str, p: dict) -> str:
    if not p:
        return f"  {label}: (deleted)"
    aliases = ", ".join(p["aliases"]) if p["aliases"] else "none"
    origin = "created by AI extraction" if p.get("created_via") == "ai_extraction" else "catalogue entry"
    line = f'  {label}: id={p["id"]}  name="{p["name"]}"  aliases=[{aliases}]  articles={p["article_count"]}  {origin}'
    if p.get("subtype"):
        line += f"  type={p['subtype']}"
    if p.get("first_seen"):
        line += f"  first_seen={p['first_seen']}"
    if p.get("description"):
        line += f'\n     description: "{p["description"]}"'
    return line


def pairs_block(cands: list[Candidate]) -> str:
    lines: list[str] = []
    for c in cands:
        signals: list[str] = []
        if c.similarity:
            signals.append(f"name similarity {c.similarity:.2f}")
        if c.alias_hit:
            signals.append("one side's name or alias equals the other's")
        if c.shared_entries:
            signals.append(f"{c.shared_entries} shared article{'s' if c.shared_entries != 1 else ''}")
        lines.append(f"pair_id={c.pair_id}  type={c.entity_type}")
        lines.append(_side("A", c.a))
        lines.append(_side("B", c.b))
        lines.append(f"  signals: {' · '.join(signals) or 'none'}")
        if c.sample_titles:
            lines.append("  shared article titles: " + " | ".join(f'"{t[:90]}"' for t in c.sample_titles))
        lines.append("")
    return "\n".join(lines).rstrip()


# ---------------------------------------------------------------------------
# Verdicts → log rows
# ---------------------------------------------------------------------------


def _keeper(c: Candidate, keep: str | None) -> tuple[str, str]:
    """Which side survives: the model's pick, else the more established one."""
    if keep in ("a", "b"):
        return keep, "b" if keep == "a" else "a"
    a_n, b_n = c.a.get("article_count", 0), c.b.get("article_count", 0)
    a_ai, b_ai = c.a.get("created_via") == "ai_extraction", c.b.get("created_via") == "ai_extraction"
    if a_ai != b_ai:
        return ("b", "a") if a_ai else ("a", "b")
    return ("a", "b") if a_n >= b_n else ("b", "a")


async def file_verdicts(
    db: AsyncSession,
    cands: list[Candidate],
    decisions: list[dict],
    *,
    min_confidence: str = "medium",
    ai_result_id: uuid.UUID | None = None,
) -> dict[str, int]:
    """Turn the model's decisions into log rows. Returns counts by outcome."""
    from app.services.entry_adjudication import ACTION_MERGE, _entity_snapshot

    by_pair = {c.pair_id: c for c in cands}
    floor = _CONF_RANK.get(min_confidence, 2)
    counts = {"proposed": 0, "distinct": 0, "unsure": 0, "ignored": 0}
    seen: set[str] = set()
    for d in decisions:
        if not isinstance(d, dict):
            continue
        c = by_pair.get(str(d.get("pair_id") or ""))
        if c is None or c.pair_id in seen or not c.a or not c.b:
            counts["ignored"] += 1
            continue
        seen.add(c.pair_id)
        verdict = str(d.get("verdict") or "unsure").lower()
        confidence = str(d.get("confidence") or "low").lower()
        if confidence not in _CONF_RANK:
            confidence = "low"
        reason = str(d.get("reason") or "")[:500]
        if verdict == "same" and _CONF_RANK[confidence] >= floor:
            keep, lose = _keeper(c, str(d.get("keep") or "").lower() or None)
            keeper, loser = getattr(c, keep), getattr(c, lose)
            loser_id = uuid.UUID(loser["id"])
            snapshot = await _entity_snapshot(db, c.entity_type, loser_id) or {"id": loser["id"], "name": loser["name"]}
            db.add(
                EntityMaintenanceLog(
                    entity_type=c.entity_type,
                    entity_id=loser_id,
                    action=ACTION_MERGE,
                    mode="shadow",
                    before={"entity": snapshot, "pair": {"a": c.a, "b": c.b, "signals": c.signals}},
                    after={
                        "target_id": keeper["id"],
                        "target_type": c.entity_type,
                        "merge_into": keeper["name"],
                        "confidence": confidence,
                        "reason": reason,
                        "origin": ORIGIN,
                    },
                    reasoning=reason,
                    ai_result_id=ai_result_id,
                    applied=False,
                )
            )
            counts["proposed"] += 1
            continue
        # different, unsure, or a same verdict under the floor: remember the
        # answer so the pair is not asked again until the retry window passes.
        outcome = "distinct" if verdict == "different" else "unsure"
        db.add(
            EntityMaintenanceLog(
                entity_type=c.entity_type,
                entity_id=c.a_id,
                action=ACTION_DISTINCT,
                mode="apply",
                before={"pair": {"a": c.a, "b": c.b, "signals": c.signals}},
                after={
                    "target_id": str(c.b_id),
                    "other_name": c.b.get("name"),
                    "verdict": verdict,
                    "confidence": confidence,
                    "origin": ORIGIN,
                },
                reasoning=reason,
                ai_result_id=ai_result_id,
                applied=True,
            )
        )
        counts[outcome] += 1
    # Pairs the model skipped: ask again next run (no row).
    await db.flush()
    return counts
