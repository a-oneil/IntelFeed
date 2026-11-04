"""Catalogue-wide duplicate review: an AI task that judges likely-duplicate pairs.

The adjudicate stage only merges an entity minted by the article it is
reviewing, so two entries that both already exist ("APT29" and "Cozy Bear
Group", or "Qakbot" and "QBot") are never put side by side. This job does
that. It is deterministic about *which* pairs to ask about and leaves the
*answer* to the model:

  candidates   — same-type pairs of actors, malware and tools that look alike
                 by name: a trigram-similar name, or a shared alias (one
                 side's name or alias equals the other's). Shared articles
                 are counted per pair and shown to the model, but never make
                 a pair on their own: two famous things reported together is
                 the normal case, not a duplicate. Pairs an analyst marked
                 "not a duplicate", pairs with a pending merge proposal, pairs
                 judged recently and pairs whose MITRE IDs differ are skipped.
                 Each shared name is shown with where it came from: an alias
                 with no recorded source is usually one AI extraction added,
                 and a wrong one makes two unrelated entities look identical.
  review       — the pairs go to the ``entity_merge_review`` AI task a few at
                 a time, with both profiles and the signals printed.
  file         — a "same" verdict becomes an ``adjudication_merge`` proposal
                 in the maintenance log (the loser is the entity, the keeper
                 the target), which the Review tab shows as a Merge row with
                 Apply / Dismiss. Nothing is merged without a person. A
                 "different" or "unsure" verdict is logged as
                 ``merge_review_distinct`` so the pair is not asked again for
                 a while. A merge that contradicts another pending one (the
                 loser already proposed into a third entity, or a chain) files
                 neither: both pairs go back as unsure. An alias the model
                 names as wrong becomes an alias-trim proposal.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field

from sqlalchemy import func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.entity_types import MALWARE, THREAT_ACTOR, TOOL
from app.models.entity_field_claim import EntityFieldClaim
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.services.entry_adjudication import ACTION_MERGE as ACTION_MERGE_FILED

logger = logging.getLogger(__name__)

TASK_NAME = "entity_merge_review"
ACTION_DISTINCT = "merge_review_distinct"
# What a filed proposal's ``after.origin`` says, so the queue can tell these
# rows from the adjudicate stage's own merges.
ORIGIN = "merge_review"
# One run at a time: the daily job and the Review tab's button can coincide,
# and two runs only see each other's rows once committed.
LOCK_KEY = "merge_review:lock"
LOCK_TTL_SECONDS = 1800

# model, entry junction, junction FK, table name — per reviewable type.
_TYPES: dict[str, tuple[type, type, str, str]] = {
    THREAT_ACTOR: (ThreatActor, EntryThreatActor, "threat_actor_id", "threat_actors"),
    MALWARE: (MalwareFamily, EntryMalware, "malware_family_id", "malware_families"),
    TOOL: (Tool, EntryTool, "tool_id", "tools"),
}
REVIEWABLE_TYPES = tuple(_TYPES)

_CONF_RANK = {"high": 3, "medium": 2, "low": 1}
# Alias claims that say where an alias came from. AI extraction records none,
# so an alias without one of these is unsourced, and is treated as a hint.
_SOURCED_ALIAS_KINDS = ("analyst", "enrichment", "external_feed", "seed")
# The alias-trim action the Review queue already applies (api/hygiene.py).
ACTION_ALIAS = "alias_collision"

# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------

# Two queries, one per signal, so each uses its own index: a single OR'd WHERE
# loses the trigram index. Both share the exclusions: pairs an analyst marked
# not-duplicate, pairs with a pending merge proposal either way, pairs
# judged within the retry window, and pairs MITRE files as two entries.
_EXCLUSIONS_SQL = """
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
AND NOT EXISTS (
    SELECT 1 FROM {table} ma JOIN {table} mb ON mb.id = p.b_id
    WHERE ma.id = p.a_id
      AND btrim(coalesce(ma.mitre_id, '')) <> '' AND btrim(coalesce(mb.mitre_id, '')) <> ''
      AND upper(btrim(ma.mitre_id)) <> upper(btrim(mb.mitre_id))
)
"""

# Trigram-similar names: `%` walks the GIN index on normalized_name.
_NAME_SQL = (
    """
WITH pairs AS (
    SELECT a.id AS a_id, b.id AS b_id, similarity(a.normalized_name, b.normalized_name) AS sim
    FROM {table} a
    JOIN {table} b ON a.id < b.id
    WHERE a.normalized_name IS NOT NULL AND b.normalized_name IS NOT NULL
      AND a.normalized_name % b.normalized_name
      AND similarity(a.normalized_name, b.normalized_name) >= :min_sim
)
SELECT a_id, b_id, sim
FROM pairs p
"""
    + _EXCLUSIONS_SQL
)

# A shared name or alias: every row's forms (name plus aliases, lower-cased)
# laid flat once, then joined on the form. A hash join, not a nested loop.
_ALIAS_SQL = (
    """
WITH forms AS (
    SELECT e.id, lower(btrim(f)) AS form
    FROM {table} e
    CROSS JOIN unnest(array_append(coalesce(e.aliases, ARRAY[]::text[]), e.name)) AS f
    WHERE f IS NOT NULL AND btrim(f) <> ''
),
pairs AS (
    SELECT DISTINCT x.id AS a_id, y.id AS b_id
    FROM forms x
    JOIN forms y ON y.form = x.form AND x.id < y.id
)
SELECT p.a_id, p.b_id, similarity(a.normalized_name, b.normalized_name) AS sim
FROM pairs p
JOIN {table} a ON a.id = p.a_id
JOIN {table} b ON b.id = p.b_id
"""
    + _EXCLUSIONS_SQL
)


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
    # Each name the two sides share, with what it is on each side:
    # [{"form", "a": "name" | "alias", "b": ..., "a_source", "b_source"}].
    shared_names: list[dict] = field(default_factory=list)

    @property
    def signals(self) -> dict:
        return {
            "similarity": round(self.similarity, 3),
            "alias_hit": self.alias_hit,
            "shared_entries": self.shared_entries,
            "score": round(self.score, 3),
            "shared_names": self.shared_names,
        }


def _score(c: Candidate) -> float:
    """Name similarity first, a shared alias on top; shared articles only
    break ties between pairs that already look alike."""
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
    """The ``limit`` most likely duplicate pairs across the reviewable types:
    pairs with a trigram-similar name or a shared alias, ranked by how alike
    they look, with their shared-article count as a tie-breaker and context."""
    found: dict[tuple[str, uuid.UUID, uuid.UUID], Candidate] = {}
    for etype in types:
        if etype not in _TYPES:
            continue
        _model, _junction, _fk, table = _TYPES[etype]
        params = {"etype": etype, "retry_days": retry_days}
        rows = (
            await db.execute(text(_NAME_SQL.format(table=table)).bindparams(min_sim=min_similarity, **params))
        ).all()
        for a_id, b_id, sim in rows:
            found[(etype, a_id, b_id)] = Candidate(
                entity_type=etype, a_id=a_id, b_id=b_id, similarity=float(sim or 0.0)
            )
        rows = (await db.execute(text(_ALIAS_SQL.format(table=table)).bindparams(**params))).all()
        for a_id, b_id, sim in rows:
            key = (etype, a_id, b_id)
            c = found.get(key)
            if c is None:
                c = found[key] = Candidate(entity_type=etype, a_id=a_id, b_id=b_id, similarity=float(sim or 0.0))
            c.alias_hit = True
    # Shared articles: one small index lookup per pair, for the model to see
    # and to order pairs that look equally alike.
    for c in found.values():
        c.shared_entries = await _shared_entries(db, c.entity_type, c.a_id, c.b_id)
        c.score = _score(c)
    ranked = sorted(found.values(), key=lambda c: -c.score)[:limit]
    for i, c in enumerate(ranked, 1):
        c.pair_id = f"p{i}"
    await _load_profiles(db, ranked)
    return ranked


async def _alias_sources(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> dict[str, str]:
    """lower-cased alias → who recorded it (``mitre_attack``, ``analyst``…),
    for the aliases a non-AI source asserted on this entity."""
    rows = (
        await db.execute(
            select(EntityFieldClaim.value_text, EntityFieldClaim.source_kind, EntityFieldClaim.source_ref).where(
                EntityFieldClaim.entity_type == entity_type,
                EntityFieldClaim.entity_id == entity_id,
                EntityFieldClaim.field == "aliases",
                EntityFieldClaim.source_kind.in_(_SOURCED_ALIAS_KINDS),
            )
        )
    ).all()
    out: dict[str, str] = {}
    for value_text, kind, ref in rows:
        for alias in (value_text or "").split(", "):
            if alias.strip():
                out.setdefault(alias.strip().lower(), ref or kind)
    return out


def _forms(obj) -> dict[str, str]:
    """lower-cased form → "name" | "alias"."""
    out = {a.strip().lower(): "alias" for a in (getattr(obj, "aliases", None) or []) if a and a.strip()}
    out[obj.name.strip().lower()] = "name"
    return out


async def _shared_names(db: AsyncSession, c: Candidate, a_obj, b_obj) -> list[dict]:
    fa, fb = _forms(a_obj), _forms(b_obj)
    shared = sorted(set(fa) & set(fb))
    if not shared:
        return []
    sources = {
        "a": await _alias_sources(db, c.entity_type, c.a_id),
        "b": await _alias_sources(db, c.entity_type, c.b_id),
    }
    out = []
    for form in shared:
        row: dict = {"form": form, "a": fa[form], "b": fb[form]}
        for side in ("a", "b"):
            if row[side] == "alias":
                row[f"{side}_source"] = sources[side].get(form)
        out.append(row)
    return out


async def _load_profiles(db: AsyncSession, cands: list[Candidate]) -> None:
    for c in cands:
        model, junction, fk, _table = _TYPES[c.entity_type]
        objs = {}
        for side in ("a", "b"):
            objs[side] = await db.get(model, getattr(c, f"{side}_id"))
            setattr(c, side, _profile(objs[side]))
        if c.alias_hit and objs["a"] is not None and objs["b"] is not None:
            c.shared_names = await _shared_names(db, c, objs["a"], objs["b"])
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
        "mitre_id": (getattr(obj, "mitre_id", None) or "").strip() or None,
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
    if p.get("mitre_id"):
        line += f"  mitre_id={p['mitre_id']}"
    if p.get("first_seen"):
        line += f"  first_seen={p['first_seen']}"
    if p.get("description"):
        line += f'\n     description: "{p["description"]}"'
    return line


def _shared_on(n: dict, side: str) -> str:
    label = side.upper()
    if n[side] == "name":
        return f"{label}'s name"
    source = n.get(f"{side}_source")
    return f"{label}'s alias, from {source}" if source else f"{label}'s alias, UNSOURCED"


def pairs_block(cands: list[Candidate]) -> str:
    lines: list[str] = []
    for c in cands:
        signals: list[str] = []
        if c.similarity:
            signals.append(f"name similarity {c.similarity:.2f}")
        if c.alias_hit:
            signals.append("one side's name or alias equals the other's")
        if c.a.get("mitre_id") and c.a.get("mitre_id", "").upper() == (c.b.get("mitre_id") or "").upper():
            signals.append(f"same MITRE ID {c.a['mitre_id'].upper()}")
        if c.shared_entries:
            signals.append(f"{c.shared_entries} shared article{'s' if c.shared_entries != 1 else ''}")
        lines.append(f"pair_id={c.pair_id}  type={c.entity_type}")
        lines.append(_side("A", c.a))
        lines.append(_side("B", c.b))
        lines.append(f"  signals: {' · '.join(signals) or 'none'}")
        for n in c.shared_names:
            lines.append(f'  shared name "{n["form"]}": ' + "; ".join(_shared_on(n, side) for side in ("a", "b")))
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


async def _pending_merge_conflicts(
    db: AsyncSession, entity_type: str, loser_id: uuid.UUID, keeper_id: uuid.UUID
) -> list[EntityMaintenanceLog]:
    """Pending merges that cannot all be right if loser → keeper is: the loser
    already proposed into another entity, the loser itself a merge target (a
    chain), or the keeper proposed into something else."""
    loser, keeper = str(loser_id), str(keeper_id)
    target = EntityMaintenanceLog.after["target_id"].astext
    rows = (
        await db.execute(
            select(EntityMaintenanceLog).where(
                EntityMaintenanceLog.action == ACTION_MERGE_FILED,
                EntityMaintenanceLog.applied.is_(False),
                EntityMaintenanceLog.entity_type == entity_type,
                or_(
                    (EntityMaintenanceLog.entity_id == loser_id) & (target != keeper),
                    target == loser,
                    EntityMaintenanceLog.entity_id == keeper_id,
                ),
            )
        )
    ).scalars()
    return list(rows)


async def _bad_alias_row(
    db: AsyncSession, c: Candidate, side: str, alias: str, reason: str, ai_result_id: uuid.UUID | None
) -> EntityMaintenanceLog | None:
    """An alias-trim proposal for an alias the model says does not belong, or
    None when it is not an alias of that side (any more) or already proposed."""
    model = _TYPES[c.entity_type][0]
    entity_id = c.a_id if side == "a" else c.b_id
    entity = await db.get(model, entity_id)
    aliases = list(getattr(entity, "aliases", None) or [])
    found = next((a for a in aliases if a.strip().lower() == alias.strip().lower()), None)
    if entity is None or found is None:
        return None
    pending = (
        await db.execute(
            select(EntityMaintenanceLog.id).where(
                EntityMaintenanceLog.action == ACTION_ALIAS,
                EntityMaintenanceLog.applied.is_(False),
                EntityMaintenanceLog.entity_type == c.entity_type,
                EntityMaintenanceLog.entity_id == entity_id,
                EntityMaintenanceLog.after["bad_alias"].astext == found,
            )
        )
    ).first()
    if pending is not None:
        return None
    return EntityMaintenanceLog(
        entity_type=c.entity_type,
        entity_id=entity_id,
        action=ACTION_ALIAS,
        mode="shadow",
        before={"entity": {"id": str(entity.id), "name": entity.name, "aliases": aliases}},
        after={"kind": ORIGIN, "bad_alias": found, "reason": reason, "origin": ORIGIN},
        reasoning=reason,
        ai_result_id=ai_result_id,
        applied=False,
    )


def _distinct_row(
    c: Candidate,
    *,
    verdict: str,
    model_verdict: str,
    confidence: str,
    reason: str,
    ai_result_id: uuid.UUID | None,
    extra: dict | None = None,
) -> EntityMaintenanceLog:
    return EntityMaintenanceLog(
        entity_type=c.entity_type,
        entity_id=c.a_id,
        action=ACTION_DISTINCT,
        mode="apply",
        before={"pair": {"a": c.a, "b": c.b, "signals": c.signals}},
        after={
            "target_id": str(c.b_id),
            "other_name": c.b.get("name"),
            "verdict": verdict,
            "model_verdict": model_verdict,
            "confidence": confidence,
            "origin": ORIGIN,
            **(extra or {}),
        },
        reasoning=reason,
        ai_result_id=ai_result_id,
        applied=True,
    )


async def _withdraw(db: AsyncSession, row: EntityMaintenanceLog, reason: str) -> None:
    """Take back one of this review's own pending merges that a later verdict
    contradicts: the pair is remembered as unsure, like the new one."""
    after = row.after or {}
    db.add(
        EntityMaintenanceLog(
            entity_type=row.entity_type,
            entity_id=row.entity_id,
            action=ACTION_DISTINCT,
            mode="apply",
            before=row.before,
            after={
                "target_id": after.get("target_id"),
                "other_name": after.get("merge_into"),
                "verdict": "unsure",
                "model_verdict": "same",
                "confidence": after.get("confidence"),
                "origin": ORIGIN,
                "conflict": reason,
            },
            reasoning=row.reasoning,
            ai_result_id=row.ai_result_id,
            applied=True,
        )
    )
    await db.delete(row)


async def file_verdicts(
    db: AsyncSession,
    cands: list[Candidate],
    decisions: list[dict],
    *,
    min_confidence: str = "medium",
    ai_result_id: uuid.UUID | None = None,
) -> dict[str, int]:
    """Turn the model's decisions into log rows. Returns counts by outcome."""
    from app.services.entry_adjudication import _entity_snapshot

    by_pair = {c.pair_id: c for c in cands}
    floor = _CONF_RANK.get(min_confidence, 2)
    counts = {"proposed": 0, "distinct": 0, "unsure": 0, "ignored": 0, "conflicts": 0, "bad_aliases": 0}
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
            loser_id, keeper_id = uuid.UUID(loser["id"]), uuid.UUID(keeper["id"])
            conflicts = await _pending_merge_conflicts(db, c.entity_type, loser_id, keeper_id)
            if conflicts:
                # Two merges that cannot both be right mean the aliases behind
                # them are suspect: neither is filed. Other filers' rows stay.
                note = f"conflicts with a pending merge of {loser['name']} / {keeper['name']}"
                for row in conflicts:
                    if (row.after or {}).get("origin") == ORIGIN:
                        await _withdraw(db, row, note)
                db.add(
                    _distinct_row(
                        c,
                        verdict="unsure",
                        model_verdict=verdict,
                        confidence=confidence,
                        reason=reason,
                        ai_result_id=ai_result_id,
                        extra={"conflict": note},
                    )
                )
                await db.flush()
                counts["conflicts"] += 1
                continue
            snapshot = await _entity_snapshot(db, c.entity_type, loser_id) or {"id": loser["id"], "name": loser["name"]}
            db.add(
                EntityMaintenanceLog(
                    entity_type=c.entity_type,
                    entity_id=loser_id,
                    action=ACTION_MERGE_FILED,
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
            # Flushed now so the next verdict's conflict check sees it.
            await db.flush()
            counts["proposed"] += 1
            continue
        # different, unsure, or a same verdict under the floor: remember the
        # answer so the pair is not asked again until the retry window passes.
        # A "same" the floor refused is stored as unsure — the row says what
        # happened to the pair, and keeps the model's own word beside it.
        outcome, stored = ("distinct", "different") if verdict == "different" else ("unsure", "unsure")
        row = _distinct_row(
            c, verdict=stored, model_verdict=verdict, confidence=confidence, reason=reason, ai_result_id=ai_result_id
        )
        db.add(row)
        counts[outcome] += 1
        # The alias that made the pair look alike, named as wrong: a trim the
        # Review queue applies, so the next run and the autolinker stop using it.
        bad, side = str(d.get("bad_alias") or "").strip(), str(d.get("bad_alias_side") or "").lower()
        if bad and side in ("a", "b"):
            row = await _bad_alias_row(db, c, side, bad, reason, ai_result_id)
            if row is not None:
                db.add(row)
                await db.flush()
                counts["bad_aliases"] += 1
    # Pairs the model skipped: ask again next run (no row).
    await db.flush()
    return counts
