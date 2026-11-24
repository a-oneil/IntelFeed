"""Hunt packs: hypotheses, SIEM queries, and ATHF hunt files, for the board and the profile.

A hunt pack is a starting point, not a record. The AI drafts hunt hypotheses
in the shape the Agentic Threat Hunting Framework (ATHF,
github.com/Nebulock-Inc/agentic-threat-hunting-framework) uses, each with a
query in the analyst's preferred query language and the telemetry it needs.
The telemetry is checked against the enabled inventory at read time, so a
hypothesis the analyst cannot run yet says so instead of handing over a query
that returns nothing.

One service, two scopes. A Threats board row drafts from its window (7d, 14d,
30d): the window's articles, the techniques extracted from them and the
sentences they were read from — "what is this threat doing right now", one to
three hypotheses. A profile drafts from everything reported (scope ``all``):
the entity's claimed techniques and tools, every technique in its articles
ranked techniques-without-a-rule first, and the rules already linked to it so
the model does not rewrite coverage that exists — "what does this threat do",
up to five hypotheses. Both are cached in ``ai_results`` keyed by entity,
scope and query language, so the board's 14-day pack and the profile's pack
never overwrite each other.

What happens next is not IntelFeed's business. The analyst copies a query, or
downloads a hypothesis as an ATHF hunt file — ``H-XXXX-<slug>.md``, YAML
frontmatter plus the LOCK body (Learn / Observe / Check / Keep) with Keep left
for the hunt itself — and drops it in the ATHF workspace. One file per
hypothesis: each is its own hunt there.

Drafting runs on the ``ai`` Celery queue (``app.workers.hunt_pack_tasks``):
a local model writing five queries takes minutes, and the analyst should be
able to leave the page. The draft's progress lives in a short-lived Redis key
beside the cached pack.
"""

import json
import re
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.ai import engine as ai_engine
from app.ai.caller import Caller
from app.ai.query_language import language, prompt_variables
from app.services.detection_coverage import (
    CANONICAL_LOG_TYPES,
    STATUS_COVERED,
    STATUS_LIBRARY_ONLY,
    classify_data_sources,
    classify_techniques,
    get_available_telemetry,
)
from app.services.threat_board import WINDOW_HOURS
from app.services.threat_brief import collect_brief_entries, collect_cve_facts
from app.telemetry_platforms import ANY, covers, default_platforms

TASK_NAME = "hunt_pack"
TARGET_TYPE = "hunt_pack"

# A profile drafts from everything reported; the board from its window.
PROFILE_SCOPE = "all"
SCOPES = (*WINDOW_HOURS, PROFILE_SCOPE)
# Types a pack can be drafted for. The board only ranks the first three; a
# technique and a campaign get packs from their profiles.
HUNT_TYPES = (
    entity_types.THREAT_ACTOR,
    entity_types.MALWARE,
    entity_types.CVE,
    entity_types.TTP,
    "campaign",  # not in entity_types: a curated list, not an extracted type
)

MAX_HYPOTHESES = 3
MAX_PROFILE_HYPOTHESES = 5
# Draft more appends to a pack; past this many there is little left the
# evidence supports that isn't already a hunt.
MAX_PACK_HYPOTHESES = 20
# Behaviours the prompt sees. Board: new-this-window first, then the most
# reported. Profile: techniques without a rule first.
BEHAVIOUR_CAP = 12
PROFILE_BEHAVIOUR_CAP = 15
PROFILE_ENTRY_CAP = 12
LINKED_RULE_CAP = 25

# Quote texts that are bookkeeping, not article sentences: the linker's and
# the reclassifier's notes, and mappings copied off a detection rule. A model
# handed one as "evidence" hunts for the note.
_JUNK_QUOTE_PREFIXES = ("auto_link:", "reclassified from", "att&ck mapping from")
# Ransomware leak-site posts name the actor and carry nothing to hunt from.
LEAK_SITE_TITLE = "%published a new victim%"


def max_hypotheses(scope: str) -> int:
    return MAX_PROFILE_HYPOTHESES if scope == PROFILE_SCOPE else MAX_HYPOTHESES


def is_junk_quote(text_: str | None) -> bool:
    return not text_ or text_.strip().lower().startswith(_JUNK_QUOTE_PREFIXES)


_PACK_NS = uuid.UUID("2d3c9a4e-7f61-4b0a-9c8d-5e1f2a3b4c5d")


def pack_target_id(entity_type: str, entity_key: str, scope: str, lang: str) -> uuid.UUID:
    """Stable UUID for the (entity, scope, language) cache key in ai_results.

    ``entity_key`` is the canonical key (see ``ResolvedEntity.coverage_key``):
    a profile addresses a CVE by uuid and the board by CVE id, and both must
    land on the same pack.
    """
    return uuid.uuid5(_PACK_NS, f"{entity_type}:{entity_key}:{scope}:{lang}")


async def resolve(db: AsyncSession, entity_type: str, entity_key: str):
    """The entity a path key names, or None. Profiles pass uuids, the board canonical ids."""
    from app.services.coverage_workspace import resolve_entity

    if entity_type not in HUNT_TYPES:
        return None
    return await resolve_entity(db, entity_type, entity_key)


# ── inputs ───────────────────────────────────────────────────────────────────


def _behaviour_dict(b, *, rule_status: str | None = None, claimed: bool = False) -> dict:
    out = {
        "technique_id": b.technique_id,
        "technique_name": b.technique_name,
        "tactic": b.tactic,
        "is_new": b.is_new,
        "entry_count": b.entry_count,
        # Collected or not, so the model can prefer hunts that run today.
        "telemetry_collected": b.tier is not None,
        "channels": [c for c, _tier in b.channels][:6],
        "quotes": [
            {
                "text": q.text[:400],
                "observable_type": q.observable_type,
                "observable_value": q.observable_value,
            }
            for q in b.quotes
            if not is_junk_quote(q.text)
        ],
    }
    if rule_status is not None:
        out["rule_status"] = rule_status
        out["claimed"] = claimed
    return out


async def evidence_entry_ids(db: AsyncSession, entity_type: str, row_id: str) -> list[uuid.UUID]:
    """Articles cited as evidence for the entity's confirmed or probable relationships."""
    rows = (
        await db.execute(
            text("""
                SELECT DISTINCT unnest(evidence_entry_ids)
                FROM entity_relationships
                WHERE ((source_type = :t AND source_id = :rid) OR (target_type = :t AND target_id = :rid))
                  AND confidence IN ('confirmed', 'probable')
            """),
            {"t": entity_type, "rid": uuid.UUID(row_id)},
        )
    ).scalars()
    return [r for r in rows if r]


# Entries for a profile pack, or a window pack for a type the brief does not
# cover. The articles naming the entity in their title come first, then the
# ones a claim rests on (an evidence list also carries other groups'
# profiles that mention it in passing), then the most techniques: a roundup that mentions a
# group once and lists thirty techniques from other intrusions is not about it,
# and a leak-site post carries nothing to hunt from at all.
_ENTRIES_SQL = """
SELECT e.id, e.title, e.summary, e.published_at, f.title AS source,
       coalesce((SELECT array_agg(DISTINCT t.technique_id || ' ' || t.technique_name)
                 FROM entry_ttps j JOIN ttps t ON t.id = j.ttp_id
                 WHERE j.entry_id = e.id), '{{}}') AS techniques,
       coalesce((SELECT (array_agg(j.source_text))[1:3]
                 FROM entry_ttps j
                 WHERE j.entry_id = e.id AND j.source_text IS NOT NULL
                   AND j.source_text NOT LIKE 'auto_link:%'
                   AND lower(j.source_text) NOT LIKE 'reclassified from%'
                   AND lower(j.source_text) NOT LIKE 'att&ck mapping from%'), '{{}}') AS quotes,
       (SELECT count(*) FROM entry_ttps j WHERE j.entry_id = e.id) AS n_techniques
FROM entries e
JOIN feeds f ON f.id = e.feed_id
WHERE e.id IN (SELECT entry_id FROM {junction} WHERE {fk} = :row_id)
  AND e.published_at > :since
  AND e.title NOT ILIKE :leak
ORDER BY (e.title ILIKE :named) DESC, (e.id = ANY(:evidence)) DESC, n_techniques DESC,
         e.published_at DESC NULLS LAST
LIMIT :limit
"""


def title_pattern(label: str) -> str:
    """ILIKE pattern for an article title that names the entity."""
    return "%" + label.replace("\\", "").replace("%", "").replace("_", "\\_") + "%"


async def _ranked_entries(
    db: AsyncSession, entity_type: str, row_id: str, label: str, since: datetime, limit: int
) -> list[dict]:
    from app.services.coverage_workspace import ENTITY_SOURCES

    junction, fk = ENTITY_SOURCES[entity_type]
    rows = (
        await db.execute(
            text(_ENTRIES_SQL.format(junction=junction, fk=fk)),  # noqa: S608 — table names are literals
            {
                "row_id": uuid.UUID(row_id),
                "since": since,
                "leak": LEAK_SITE_TITLE,
                "limit": limit,
                "evidence": await evidence_entry_ids(db, entity_type, row_id),
                "named": title_pattern(label),
            },
        )
    ).all()
    return [
        {
            "entry_id": str(r.id),
            "title": r.title,
            "source": r.source,
            "published_at": r.published_at.isoformat() if r.published_at else None,
            "summary": (r.summary or "")[:1200] or None,
            "techniques": list(r.techniques or [])[:12],
            "quotes": [q[:400] for q in (r.quotes or [])],
        }
        for r in rows
    ]


async def _claimed(db: AsyncSession, entity_type: str, row_id: str) -> list[dict]:
    """The entity's claimed techniques, tools, malware and CVEs, with their names.

    Confirmed and probable typed relationships only: a co-mention is not a
    claim, and "possible" is the AI's first guess before anyone checked it.
    """
    from app.intelligence.correlation import ENTITY_CONFIG, _get_manual_relationships

    rels = await _get_manual_relationships(db, entity_type, uuid.UUID(row_id))
    wanted = {entity_types.TTP, entity_types.TOOL, entity_types.MALWARE, entity_types.CVE, entity_types.THREAT_ACTOR}
    rels = [r for r in rels if r["entity_type"] in wanted and r["confidence"] in ("confirmed", "probable")]
    names: dict[tuple[str, str], str] = {}
    for etype in {r["entity_type"] for r in rels}:
        model = ENTITY_CONFIG[etype][0]
        ids = [r["entity_id"] for r in rels if r["entity_type"] == etype]
        if etype == entity_types.TTP:
            cols = (model.id, model.technique_id + " " + model.technique_name)
        elif etype == entity_types.CVE:
            cols = (model.id, model.cve_id)
        else:
            cols = (model.id, model.name)
        for rid, name in (await db.execute(select(*cols).where(model.id.in_(ids)))).all():
            names[(etype, str(rid))] = name
    out = []
    for r in rels:
        name = names.get((r["entity_type"], str(r["entity_id"])))
        if not name:
            continue
        out.append(
            {
                "type": r["entity_type"],
                "name": name,
                "verb": r["relationship_type"],
                "direction": r["direction"],
                "confidence": r["confidence"],
                "description": (r.get("description") or "")[:240] or None,
            }
        )
    # Confirmed first, then by type so the prompt reads as a list per kind.
    out.sort(key=lambda c: (c["confidence"] != "confirmed", c["type"], c["name"]))
    return out


async def linked_rules(db: AsyncSession, entity_type: str, resolved, limit: int = LINKED_RULE_CAP) -> list[dict]:
    """Rules written for this entity: attributed to it, or extracted from its articles.

    The same two roads the profile's Detection count takes, minus library
    rules that merely share a technique — those say nothing about this threat.
    """
    from sqlalchemy import or_, type_coerce
    from sqlalchemy.dialects.postgresql import JSONB

    from app.models.detection_rule import DetectionRule
    from app.services.coverage_workspace import ENTITY_SOURCES

    junction, fk = ENTITY_SOURCES[entity_type]
    row_id = uuid.UUID(resolved.row_id)
    entry_ids = select(text("entry_id")).select_from(text(junction)).where(text(f"{fk} = :rid"))
    filters = [DetectionRule.entry_id.in_(entry_ids)]
    if entity_type == entity_types.THREAT_ACTOR:
        filters.append(DetectionRule.source_actors.any(row_id))
    elif entity_type == "campaign":
        filters.append(DetectionRule.source_campaigns.any(row_id))
    elif entity_type == entity_types.CVE:
        filters.append(DetectionRule.source_cves.op("@>")(type_coerce([resolved.coverage_key], JSONB)))
    elif entity_type == entity_types.TTP:
        filters.append(DetectionRule.source_ttps.op("@>")(type_coerce([resolved.coverage_key], JSONB)))
    rows = (
        await db.execute(
            select(
                DetectionRule.id,
                DetectionRule.title,
                DetectionRule.rule_type,
                DetectionRule.rule_content,
                DetectionRule.severity,
                DetectionRule.source_ttps,
            )
            .where(or_(*filters))
            .order_by(DetectionRule.created_at.desc())
            .limit(limit),
            {"rid": row_id},
        )
    ).all()
    return [
        {
            "id": str(r.id),
            "title": r.title,
            "rule_type": r.rule_type,
            "content": r.rule_content,
            "severity": r.severity,
            "techniques": list(r.source_ttps or []),
        }
        for r in rows
    ]


async def telemetry_inventory(db: AsyncSession) -> list[dict]:
    """The enabled telemetry sources, grouped by category, for the prompt.

    The query language only says where a query runs; this says what is in
    it. Without it a model writing CQL reaches for Falcon sensor events by
    habit, including on a vCenter appliance no sensor runs on. One line per
    category — source names and the log types between them — keeps a
    177-source inventory to a couple of thousand tokens.
    """
    from app.models.telemetry_source import TelemetrySource

    rows = (
        await db.execute(
            select(TelemetrySource).where(TelemetrySource.enabled.is_(True)).order_by(TelemetrySource.name)
        )
    ).scalars()
    by_cat: dict[str, dict] = {}
    for src in rows:
        cat = by_cat.setdefault(
            src.category or "other", {"category": src.category or "other", "sources": [], "log_types": set()}
        )
        # Platforms only when they narrow it: "Any" sources see every host.
        plats = default_platforms(src.category, src.name)
        label = src.name + (f" [{', '.join(plats)}]" if ANY not in plats else "")
        label += f" (into {src.ingested_into})" if src.ingested_into else ""
        cat["sources"].append(label)
        cat["log_types"].update(src.log_types_canonical or [])
    return [
        {"category": c["category"], "sources": c["sources"], "log_types": sorted(c["log_types"])}
        for c in sorted(by_cat.values(), key=lambda c: c["category"])
    ]


async def enabled_sources(db: AsyncSession) -> list[tuple[str, set[str], list[str]]]:
    """(lower-cased name, canonical log types, platforms covered) per enabled source."""
    from app.models.telemetry_source import TelemetrySource

    rows = (await db.execute(select(TelemetrySource).where(TelemetrySource.enabled.is_(True)))).scalars()
    return [
        (src.name.strip().lower(), set(src.log_types_canonical or []), default_platforms(src.category, src.name))
        for src in rows
        if src.name
    ]


def _source_key(name: str | None) -> str:
    """An inventory name as the model may echo it, without the prompt's [platforms] or (into …)."""
    bare = re.sub(r"\s*\(into [^)]*\)\s*$", "", name or "")
    return re.sub(r"\s*\[[^\]]*\]\s*$", "", bare).strip().lower()


async def collect_hunt_inputs(db: AsyncSession, entity_type: str, entity_key: str, scope: str) -> dict | None:
    """Everything the prompt may use for one entity and scope, and nothing else.

    Returns None when the entity cannot be resolved. A resolved entity with no
    articles and no behaviours comes back with empty lists, and the caller
    decides there is nothing to draft from.
    """
    from app.services.coverage_workspace import build_workspace

    resolved = await resolve(db, entity_type, entity_key)
    if resolved is None:
        return None
    key = resolved.coverage_key
    facts = await collect_cve_facts(db, key) if entity_type == entity_types.CVE else {}

    if scope != PROFILE_SCOPE:
        hours = WINDOW_HOURS.get(scope, WINDOW_HOURS["14d"])
        ws = await build_workspace(db, entity_type, key, window=scope, article_limit=BEHAVIOUR_CAP)
        if ws is None:
            return None
        if entity_type in (entity_types.THREAT_ACTOR, entity_types.MALWARE, entity_types.CVE):
            entries = await collect_brief_entries(db, entity_type, key, hours)
        else:
            since = datetime.now(UTC) - timedelta(hours=hours)
            entries = await _ranked_entries(db, entity_type, resolved.row_id, ws.label, since, BEHAVIOUR_CAP)
        behaviours = sorted(ws.behaviours, key=lambda b: (not b.is_new, -b.entry_count))[:BEHAVIOUR_CAP]
        return {
            "key": key,
            "label": ws.label,
            "entries": entries,
            "behaviours": [_behaviour_dict(b) for b in behaviours],
            "facts": facts,
            "claimed": [],
            "linked_rules": [],
            "telemetry": await telemetry_inventory(db),
        }

    ws = await build_workspace(db, entity_type, key, window=PROFILE_SCOPE, article_limit=PROFILE_ENTRY_CAP)
    if ws is None:
        return None
    claimed = await _claimed(db, entity_type, resolved.row_id)
    claimed_ttps = {c["name"].split(" ", 1)[0] for c in claimed if c["type"] == entity_types.TTP}
    status = await classify_techniques(db, [b.technique_id for b in ws.behaviours])
    rank = {None: 0, "no_rule": 0, STATUS_LIBRARY_ONLY: 1, STATUS_COVERED: 2}

    def _status(b) -> str:
        return (status.get(b.technique_id) or {}).get("status") or "no_rule"

    # A claimed technique outranks one an article merely mentions; among
    # those, the ones no rule covers come first, then the most reported.
    ranked = sorted(
        ws.behaviours,
        key=lambda b: (b.technique_id not in claimed_ttps, rank.get(_status(b), 0), -b.entry_count),
    )[:PROFILE_BEHAVIOUR_CAP]
    entries = await _ranked_entries(
        db, entity_type, resolved.row_id, ws.label, datetime(1970, 1, 1, tzinfo=UTC), PROFILE_ENTRY_CAP
    )
    rules = await linked_rules(db, entity_type, resolved)
    return {
        "key": key,
        "label": ws.label,
        "entries": entries,
        "behaviours": [
            _behaviour_dict(b, rule_status=_status(b), claimed=b.technique_id in claimed_ttps) for b in ranked
        ],
        "facts": facts,
        "claimed": [c for c in claimed if c["type"] != entity_types.TTP],
        "linked_rules": [
            {"title": r["title"], "rule_type": r["rule_type"], "techniques": r["techniques"][:6]} for r in rules
        ],
        "article_total": ws.article_total,
        "telemetry": await telemetry_inventory(db),
    }


# ── cache ────────────────────────────────────────────────────────────────────


def _clean_hypothesis(raw: object, index: int) -> dict | None:
    """One hypothesis as the API shape, or None when the model's item is unusable."""
    if not isinstance(raw, dict):
        return None
    # hunting_query since the schema rename (see the hunt_pack task's
    # output_schema); query from packs drafted before it.
    query = raw.get("hunting_query") or raw.get("query")
    hypothesis = raw.get("hypothesis")
    if not isinstance(query, str) or not query.strip() or not isinstance(hypothesis, str) or not hypothesis.strip():
        return None

    def _s(key: str) -> str:
        v = raw.get(key)
        return v.strip() if isinstance(v, str) else ""

    def _list(key: str) -> list[str]:
        v = raw.get(key)
        return [x.strip() for x in v if isinstance(x, str) and x.strip()] if isinstance(v, list) else []

    return {
        "id": f"H{index}",
        "title": _s("title") or hypothesis.strip()[:80],
        "hypothesis": hypothesis.strip(),
        "tactic": _s("tactic") or None,
        "techniques": _list("techniques")[:4],
        "platform": _s("platform") or None,
        # Only ids from the canonical axis survive: anything else cannot be
        # matched against the telemetry inventory, so it would always read as
        # missing.
        "data_sources": [d for d in _list("data_sources") if d in CANONICAL_LOG_TYPES][:6],
        "query": query.strip(),
        "query_notes": _s("query_notes") or None,
        "false_positives": _s("false_positives") or None,
        "evidence": _s("evidence") or None,
        # The log the query reads, in words, and which inventory source holds
        # it ("" when none does: the hunt then needs that log first).
        "log_source": _s("log_source") or None,
        "source_name": "" if _s("source_name").lower() in ("", "none", "n/a") else _s("source_name"),
    }


def normalize_pack(parsed: dict | None, cap: int = MAX_HYPOTHESES) -> list[dict]:
    """The model's hypotheses, cleaned and capped. Empty when nothing usable came back."""
    if not isinstance(parsed, dict):
        return []
    raw = parsed.get("hypotheses")
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for item in raw:
        cleaned = _clean_hypothesis(item, len(out) + 1)
        if cleaned is not None:
            out.append(cleaned)
        if len(out) >= cap:
            break
    return out


async def _task_id(db: AsyncSession) -> uuid.UUID | None:
    from app.models.ai_task import AITask

    return (await db.execute(select(AITask.id).where(AITask.name == TASK_NAME))).scalar_one_or_none()


async def _current_result(db: AsyncSession, target_id: uuid.UUID):
    from app.models.ai_result import AIResult

    return (
        await db.execute(
            select(AIResult)
            .where(
                AIResult.target_type == TARGET_TYPE,
                AIResult.target_id == target_id,
                AIResult.is_current == True,  # noqa: E712
            )
            .order_by(AIResult.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


# Pipe languages: one stage per line reads as a query; one line of 400
# characters is a scrollbar. Sigma is YAML and SQL has no pipes.
_PIPED = {"kql", "spl", "esql", "eql", "cql", "yaral", "aql", "sumo"}


def format_query(query: str, lang: str) -> str:
    """A one-line pipe query broken into one stage per line; anything with newlines is left alone.

    Splits only outside string literals: a newline inside "a | b" would
    change what the copied query matches.
    """
    if "\n" in query or lang not in _PIPED:
        return query
    out: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(query):
        ch = query[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(query):
                out.append(query[i + 1])
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
            out.append(ch)
        elif ch == "|" and i > 0 and query[i - 1] == " " and query[i + 1 : i + 2] == " ":
            while out and out[-1] == " ":
                out.pop()
            out.append("\n|")
        elif ch == ";" and lang == "kql" and query[i + 1 : i + 2] == " ":
            out.append(";\n")
            while i + 1 < len(query) and query[i + 1] == " ":
                i += 1
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _pack_from_result(row, entity_type: str, entity_key: str, scope: str, lang: str) -> dict | None:
    parsed = row.parsed_result if isinstance(row.parsed_result, dict) else {}
    hypotheses = parsed.get("hypotheses_clean")
    if not isinstance(hypotheses, list) or not hypotheses:
        return None
    # Formatted at read time so packs drafted before this read the same way.
    hypotheses = [{**h, "query": format_query(h.get("query") or "", lang)} for h in hypotheses]
    return {
        "entity_type": entity_type,
        "entity_key": entity_key,
        "label": parsed.get("label") or entity_key,
        "window": scope,
        "language": lang,
        "language_name": language(lang).name,
        "generated_at": row.created_at.isoformat() if row.created_at else None,
        "model": row.model_name,
        "entry_ids": [str(e) for e in parsed.get("entry_ids", []) if e],
        "hypotheses": hypotheses,
    }


async def get_cached_pack(db: AsyncSession, entity_type: str, entity_key: str, scope: str, lang: str) -> dict | None:
    """The current pack for this entity, scope and language, or None."""
    resolved = await resolve(db, entity_type, entity_key)
    if resolved is None:
        return None
    key = resolved.coverage_key
    row = await _current_result(db, pack_target_id(entity_type, key, scope, lang))
    if row is None:
        return None
    return _pack_from_result(row, entity_type, key, scope, lang)


# ── generation ───────────────────────────────────────────────────────────────


class NothingToHunt(Exception):
    """The entity resolved but its scope holds nothing a hypothesis could rest on."""


async def generate_hunt_pack(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_key: str,
    scope: str,
    lang: str,
    timeout_seconds: float = 300.0,
    caller: Caller | None = None,
    append: bool = False,
) -> dict | None:
    """Draft the pack for one entity and scope now, replacing any cached one.

    ``append`` (Draft more) keeps the cached hypotheses: the model is shown
    them and asked for different ones, which are added after them and
    numbered on (H6, H7…), so ids already downloaded as ATHF files keep
    meaning the same hunt.

    Returns the pack, or None when the task has no provider assigned or the
    model returned nothing usable (nothing new, when appending). Raises NothingToHunt when the scope has no
    articles and no extracted behaviours; LookupError when the entity does
    not resolve.
    """
    inputs = await collect_hunt_inputs(db, entity_type, entity_key, scope)
    if inputs is None:
        raise LookupError(entity_key)
    if not inputs["entries"] and not inputs["behaviours"]:
        raise NothingToHunt(entity_key)

    key = inputs["key"]
    target_id = pack_target_id(entity_type, key, scope, lang)
    cap = max_hypotheses(scope)
    # run_task demotes the current pack before it stores the new answer; a
    # redraft that comes back unusable must not cost the analyst the last
    # good pack.
    previous = await _current_result(db, target_id)
    has_pack = previous is not None and _pack_from_result(previous, entity_type, key, scope, lang) is not None
    previous_id = previous.id if has_pack else None
    existing: list[dict] = []
    kept_entry_ids: list[str] = []
    if append and has_pack:
        kept = _pack_from_result(previous, entity_type, key, scope, lang) or {}
        existing, kept_entry_ids = kept.get("hypotheses", []), kept.get("entry_ids", [])
    if len(existing) >= MAX_PACK_HYPOTHESES:
        return None
    parsed = await ai_engine.run_task(
        db,
        user_id,
        TASK_NAME,
        variables={
            "threat_name": inputs["label"],
            "entity_type": entity_type,
            "window": scope,
            "scope": "profile" if scope == PROFILE_SCOPE else "window",
            "max_hypotheses": cap,
            **prompt_variables(lang),
            "entries": inputs["entries"],
            "entry_count": len(inputs["entries"]),
            "article_total": inputs.get("article_total"),
            "behaviours": inputs["behaviours"],
            "facts": inputs["facts"],
            "claimed": inputs["claimed"],
            "linked_rules": inputs["linked_rules"],
            "telemetry_inventory": inputs["telemetry"],
            "existing_hunts": [
                {"title": h["title"], "hypothesis": h["hypothesis"], "techniques": h.get("techniques", [])}
                for h in existing
            ],
            "log_types": sorted(CANONICAL_LOG_TYPES),
        },
        target_type=TARGET_TYPE,
        target_id=target_id,
        force=True,
        timeout_seconds=timeout_seconds,
        caller=caller or Caller.user(user_id),
    )
    if parsed is None:
        return None
    hypotheses = normalize_pack(parsed, cap)
    if existing:
        # A new hunt with an existing title is a repeat, whatever the prompt said.
        seen = {h["title"].strip().lower() for h in existing}
        fresh = [h for h in hypotheses if h["title"].strip().lower() not in seen]
        fresh = fresh[: MAX_PACK_HYPOTHESES - len(existing)]
        for i, h in enumerate(fresh, start=len(existing) + 1):
            h["id"] = f"H{i}"
        hypotheses = [*existing, *fresh] if fresh else []
    if not hypotheses:
        # Keep run_task's row (raw response, tokens) so the failure can be
        # read in Settings › AI results, but put the last good pack back as
        # the current one.
        if previous_id is not None:
            from app.models.ai_result import AIResult

            failed = await _current_result(db, target_id)
            if failed is not None and failed.id != previous_id:
                failed.is_current = False
            restored = await db.get(AIResult, previous_id)
            if restored is not None:
                restored.is_current = True
        await db.commit()
        return None

    # run_task stored the raw parsed_result; add the cleaned pack and its
    # audit trail beside it so the cache is self-describing.
    stored = await _current_result(db, target_id)
    if stored is not None:
        stored.parsed_result = {
            **(stored.parsed_result or {}),
            "hypotheses_clean": hypotheses,
            "label": inputs["label"],
            "entry_ids": list(dict.fromkeys([*kept_entry_ids, *(e["entry_id"] for e in inputs["entries"])])),
            "window": scope,
            "language": lang,
        }
        await db.commit()
        return _pack_from_result(stored, entity_type, key, scope, lang)
    return {
        "entity_type": entity_type,
        "entity_key": key,
        "label": inputs["label"],
        "window": scope,
        "language": lang,
        "language_name": language(lang).name,
        "generated_at": datetime.now(UTC).isoformat(),
        "model": None,
        "entry_ids": [e["entry_id"] for e in inputs["entries"]],
        "hypotheses": hypotheses,
    }


# ── drafting in the background ───────────────────────────────────────────────

# A draft's state between the click and the cached pack. Drafting expires on
# its own after the worker's hard time limit, so a killed worker cannot leave
# a spinner behind for good; a failure stays readable for an hour.
DRAFT_TTL_SECONDS = 15 * 60
FAILED_TTL_SECONDS = 60 * 60
DRAFT_TASK = "app.workers.hunt_pack_tasks.draft_hunt_pack"


def _draft_key(target_id: uuid.UUID) -> str:
    return f"hunt_pack:draft:{target_id}"


async def draft_state(target_id: uuid.UUID) -> dict | None:
    """``{"state": "drafting" | "failed", ...}`` while a draft is in flight or just failed."""
    from app.services.redis_client import get_redis

    raw = await (await get_redis()).get(_draft_key(target_id))
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


async def set_draft_state(target_id: uuid.UUID, state: str, **extra) -> None:
    from app.services.redis_client import get_redis

    ttl = DRAFT_TTL_SECONDS if state == "drafting" else FAILED_TTL_SECONDS
    payload = {"state": state, "at": datetime.now(UTC).isoformat(), **extra}
    await (await get_redis()).set(_draft_key(target_id), json.dumps(payload), ex=ttl)


async def clear_draft_state(target_id: uuid.UUID) -> None:
    from app.services.redis_client import get_redis

    await (await get_redis()).delete(_draft_key(target_id))


class NotConfigured(Exception):
    """No provider answers the hunt_pack task for this person."""


class EngineStopped(Exception):
    """The engine switch is off: the AI worker takes nothing off its queue."""


async def start_draft(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_key: str,
    scope: str,
    lang: str,
    append: bool = False,
) -> uuid.UUID:
    """Queue a draft on the AI worker and mark it drafting. Returns the cache target id.

    Checks up front what would make the worker fail or never run — an
    unknown entity (LookupError), the engine stopped (EngineStopped), no
    provider (NotConfigured), nothing to hunt from (NothingToHunt) — so the
    click gets its answer now rather than a failed state later.
    """
    from app.workers.celery_app import celery_app

    resolved = await resolve(db, entity_type, entity_key)
    if resolved is None:
        raise LookupError(entity_key)
    target_id = pack_target_id(entity_type, resolved.coverage_key, scope, lang)
    current = await draft_state(target_id)
    if current and current.get("state") == "drafting":
        return target_id
    from app.services.engine_switch import is_stopped_async

    # A queued draft would sit until the engine starts, and the drafting
    # state would expire before it ran: say so now instead.
    if await is_stopped_async():
        raise EngineStopped()
    if await ai_engine.resolve_assignment(db, Caller.user(user_id), TASK_NAME, allowance=False) is None:
        raise NotConfigured(TASK_NAME)
    inputs = await collect_hunt_inputs(db, entity_type, resolved.coverage_key, scope)
    if inputs is None:
        raise LookupError(entity_key)
    if not inputs["entries"] and not inputs["behaviours"]:
        raise NothingToHunt(entity_key)

    await set_draft_state(target_id, "drafting", started_at=datetime.now(UTC).isoformat())
    celery_app.send_task(
        DRAFT_TASK,
        kwargs={
            "user_id": str(user_id),
            "entity_type": entity_type,
            "entity_key": resolved.coverage_key,
            "scope": scope,
            "lang": lang,
            "append": append,
        },
        queue="ai",
    )
    return target_id


async def pack_status(db: AsyncSession, entity_type: str, entity_key: str, scope: str, lang: str) -> dict:
    """``{"status": none|drafting|ready|failed, "pack", "started_at", "error"}`` for the API."""
    resolved = await resolve(db, entity_type, entity_key)
    if resolved is None:
        raise LookupError(entity_key)
    key = resolved.coverage_key
    row = await _current_result(db, pack_target_id(entity_type, key, scope, lang))
    pack = _pack_from_result(row, entity_type, key, scope, lang) if row is not None else None
    state = await draft_state(pack_target_id(entity_type, key, scope, lang))
    if state and state.get("state") == "drafting":
        status = "drafting"
    elif state and state.get("state") == "failed":
        status = "failed"
    else:
        status = "ready" if pack else "none"
    return {
        "status": status,
        "pack": pack,
        "started_at": (state or {}).get("started_at"),
        "error": (state or {}).get("error"),
    }


# ── telemetry check ──────────────────────────────────────────────────────────


async def annotate_telemetry(db: AsyncSession, pack: dict) -> dict:
    """Mark each hypothesis's data sources collected or not, against the live inventory.

    Done at read time rather than stored: a source ticked in Settings must
    flip the chip without a redraft.
    """
    profile = await get_available_telemetry(db)
    sources = await enabled_sources(db)
    platforms_by_name = {name: plats for name, _types, plats in sources}
    for h in pack["hypotheses"]:
        platform = h.get("platform")

        def _have(ds: str, tier: str | None) -> bool:
            if tier is None:
                return False
            # Per platform: some source must give this log type AND see the
            # hunt's target. Falcon's process creation is no use on ESXi. A
            # type no source lists canonically (a legacy free-text match)
            # keeps the old answer.
            givers = [plats for _n, types, plats in sources if ds in types]
            return not givers or any(covers(plats, platform) for plats in givers)

        h["telemetry"] = [
            {"source": ds, "have": _have(ds, tier)} for ds, tier in classify_data_sources(h["data_sources"], profile)
        ]
        h["runnable"] = all(t["have"] for t in h["telemetry"]) if h["telemetry"] else True
        # Packs drafted before the log_source field have none: judged by log
        # type alone, as they always were.
        if h.get("log_source"):
            plats = platforms_by_name.get(_source_key(h.get("source_name")))
            have = plats is not None and covers(plats, platform)
            h["source_have"] = have
            h["runnable"] = h["runnable"] and have
    return pack


async def annotate_techniques(db: AsyncSession, pack: dict) -> dict:
    """Give each hypothesis its techniques' names and profile ids, for links.

    Read time, like the telemetry check: a technique renamed in the catalog
    reads right without a redraft. An id the catalog doesn't have keeps no
    name and no link.
    """
    from app.models.ttp import TTP

    wanted = {t for h in pack["hypotheses"] for t in h.get("techniques", [])}
    found = {}
    if wanted:
        rows = await db.execute(
            select(TTP.technique_id, TTP.technique_name, TTP.id).where(TTP.technique_id.in_(wanted))
        )
        found = {tid: (name, str(rid)) for tid, name, rid in rows.all()}
    for h in pack["hypotheses"]:
        h["technique_refs"] = [
            {"technique_id": t, "name": found.get(t, (None, None))[0], "id": found.get(t, (None, None))[1]}
            for t in h.get("techniques", [])
        ]
    return pack


# ── the ATHF hunt file ───────────────────────────────────────────────────────


_YAML_PLAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _./+()-]*$")


def _yaml_scalar(value: str) -> str:
    """A frontmatter value: bare when YAML reads it as one word run, quoted otherwise.

    A title like "Scattered Spider: 2 hunt hypotheses" is a mapping to YAML
    unless quoted — athf hunt validate rejects the file.
    """
    return value if _YAML_PLAIN.match(value) else json.dumps(value)


def _yaml_list(items: list[str]) -> str:
    return "[" + ", ".join(_yaml_scalar(i) for i in items) + "]"


def _words(slug: str, limit: int) -> str:
    """A slug cut to ``limit`` characters at a word boundary."""
    if len(slug) <= limit:
        return slug
    return slug[: limit + 1].rsplit("-", 1)[0].strip("-") or slug[:limit]


def _slug(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:48] or "hunt"


PLACEHOLDER_HUNT_ID = "H-XXXX"
HUNT_ID_PATTERN = r"^H-\d{4}$"


def hunt_filename(pack: dict, hunt_id: str = PLACEHOLDER_HUNT_ID) -> str:
    """``H-XXXX-<entity>.md``, or ``H-XXXX-<entity>-<hypothesis>.md`` for a one-hypothesis pack."""
    hyps = pack.get("hypotheses") or []
    full = re.sub(r"[^a-z0-9]+", "-", hyps[0]["title"].lower()).strip("-") if len(hyps) == 1 else ""
    tail = f"-{_words(full, 48)}" if full else ""
    return f"{hunt_id}-{_slug(pack['label'])}{tail}.md"


def single_hypothesis(pack: dict, hypothesis_id: str) -> dict | None:
    """The pack narrowed to one hypothesis — what one ATHF hunt file holds."""
    for h in pack["hypotheses"]:
        if h["id"] == hypothesis_id:
            return {**pack, "hypotheses": [h]}
    return None


def scope_phrase(scope: str) -> str:
    """How the file says where the pack came from: the board's window or the profile."""
    if scope == PROFILE_SCOPE:
        return "profile, all reporting"
    return f"Threats board, {scope} window"


async def _articles_for(db: AsyncSession, entry_ids: list[str]) -> list[dict]:
    if not entry_ids:
        return []
    ids = [uuid.UUID(e) for e in entry_ids if _is_uuid(e)]
    if not ids:
        return []
    rows = (
        await db.execute(
            text(
                """
                SELECT e.id, e.title, e.url, e.published_at,
                       lower(coalesce(
                           nullif(regexp_replace(coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
                           f.title)) AS source
                FROM entries e JOIN feeds f ON f.id = e.feed_id
                WHERE e.id = ANY(:ids)
                ORDER BY e.published_at DESC NULLS LAST
                """
            ),
            {"ids": ids},
        )
    ).all()
    return [
        {
            "title": r.title,
            "url": r.url,
            "source": r.source,
            "published_at": r.published_at.date().isoformat() if r.published_at else None,
        }
        for r in rows
    ]


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def render_athf_markdown(
    pack: dict,
    *,
    hunter: str,
    articles: list[dict],
    facts: dict | None = None,
    today: datetime | None = None,
    hunt_id: str = PLACEHOLDER_HUNT_ID,
) -> str:
    """The hunt file ATHF's CLI, MCP server and AI assistants read.

    Frontmatter follows ``athf/data/templates/HUNT_LOCK.md``; the body carries
    the LOCK sections with Learn, Observe and Check filled from the pack and
    Keep left empty. ``athf hunt validate`` passes once the id is real:
    ``hunt_id`` defaults to the template's ``H-XXXX`` placeholder because the
    workspace owns the numbering, and a caller who knows the next number
    passes it so the file validates as exported.
    """
    day = (today or datetime.now(UTC)).date().isoformat()
    hyps = pack["hypotheses"]
    label = pack["label"]
    lang = language(pack["language"])
    techniques = sorted({t for h in hyps for t in h.get("techniques", [])})
    tactics = sorted({h["tactic"] for h in hyps if h.get("tactic")})
    platforms = sorted({h["platform"] for h in hyps if h.get("platform")})
    title = f"{label}: {hyps[0]['title']}" if len(hyps) == 1 else f"{label}: {len(hyps)} hunt hypotheses"
    tags = ["intelfeed", pack["entity_type"].replace("_", "-"), _slug(label)]

    lines: list[str] = [
        "---",
        f"hunt_id: {hunt_id}",
        f"title: {_yaml_scalar(title)}",
        "status: planning",
        f"date: {day}",
        f"hunter: {_yaml_scalar(hunter)}",
        "hunt_type: hypothesis",
        f"platform: {_yaml_list(platforms)}",
        f"tactics: {_yaml_list(tactics)}",
        f"techniques: {_yaml_list(techniques)}",
        f"data_sources: {_yaml_list([lang.platform])}",
        "related_hunts: []",
        "findings_count: 0",
        "findings: []",
        "ruled_out: []",
        "customer_deliverables: []",
        f"tags: {_yaml_list(tags)}",
        "---",
        "",
        f"# {hunt_id}: {title}",
        "",
        "## Hunt Metadata",
        f"- **Date:** {day}",
        f"- **Hunter:** {hunter}",
        "- **Status:** Planning",
        f"- **MITRE ATT&CK:** {', '.join(techniques) if techniques else 'n/a'}",
        f"- **Source:** IntelFeed {scope_phrase(pack['window'])}: {label} (exported {day})",
        "",
        "## LEARN: Prepare the Hunt",
        "",
        "### Hypothesis Statement",
    ]
    for h in hyps:
        lines.append(f"{h['id']}. **{h['title']}** — {h['hypothesis']}")
    lines += [
        "",
        "### Threat Context",
        "",
        f"{label} on IntelFeed ({scope_phrase(pack['window'])}): {len(articles)} article"
        f"{'' if len(articles) == 1 else 's'} behind this pack"
        + (f", techniques {', '.join(techniques)}." if techniques else "."),
        "",
        "### ABLE Scoping",
        "",
        "| Hypothesis | Actor | Behavior | Location | Evidence |",
        "|---|---|---|---|---|",
    ]
    actor = label if pack["entity_type"] in (entity_types.THREAT_ACTOR, entity_types.MALWARE) else "(any)"
    for h in hyps:
        evidence = ", ".join(h.get("data_sources") or []) or "(see query)"
        location = h.get("platform") or "(environment)"
        lines.append(f"| {h['id']} | {actor} | {h['hypothesis']} | {location} | {evidence} |")
    lines += ["", "### Threat Intel & Research", ""]
    if techniques:
        lines.append(f"- **ATT&CK techniques:** {', '.join(techniques)}")
    for h in hyps:
        if h.get("evidence"):
            lines.append(f"- **Why {h['id']}:** {h['evidence']}")
    if facts:
        bits = []
        if facts.get("affected"):
            bits.append("affected: " + ", ".join(facts["affected"][:6]))
        if facts.get("is_kev"):
            bits.append("on CISA KEV" + (f" since {facts['kev_date_added']}" if facts.get("kev_date_added") else ""))
        if facts.get("exploit_status"):
            bits.append(f"exploit status: {facts['exploit_status']}")
        if facts.get("cvss_score") is not None:
            bits.append(f"CVSS {facts['cvss_score']}")
        if facts.get("epss_score") is not None:
            bits.append(f"EPSS {facts['epss_score']}")
        if bits:
            lines.append("- **Vulnerability facts:** " + " · ".join(bits))
    lines.append("- **CTI sources (the articles the pack was drafted from):**")
    for a in articles:
        when = f" ({a['published_at']})" if a.get("published_at") else ""
        link = f"[{a['title']}]({a['url']})" if a.get("url") else a["title"]
        lines.append(f"  - {link} — {a.get('source') or 'unknown source'}{when}")
    if not articles:
        lines.append("  - (none recorded)")
    lines += [
        "",
        "### Related Tickets",
        "",
        "| Type | Ticket | Notes |",
        "|---|---|---|",
        "| SOC/IR | | |",
        "| Threat Intel | | |",
        "| Detection Engineering | | |",
        "",
        "## OBSERVE: Expected Behaviors",
        "",
        "### What Normal Looks Like",
    ]
    for h in hyps:
        normal = h.get("false_positives") or "Not described. Establish the baseline before the hunt."
        lines.append(f"- {h['id']}: {normal}")
    lines += ["", "### What Suspicious Looks Like"]
    for h in hyps:
        lines.append(f"- {h['id']}: {h['hypothesis']}")
    lines += ["", "### Expected Observables"]
    for h in hyps:
        lines.append(
            f"- {h['id']}: {', '.join(h.get('data_sources') or []) or 'see query'}"
            + (f" — {h['query_notes']}" if h.get("query_notes") else "")
        )
    lines += [
        "",
        "## CHECK: Execute & Analyze",
        "",
        "### Data Source Information",
        f"- **Platform:** {lang.platform} ({lang.name})",
        *[
            f"- **Log source ({h['id']}):** {h['log_source']}"
            + ("" if h.get("source_have", True) else " — not in the telemetry inventory when exported")
            for h in hyps
            if h.get("log_source")
        ],
        "- **Time Range:** last 7 days first; widen once the baseline is understood",
        "- **Events Analyzed:** ",
        "- **Data Quality:** [Good | Fair | Poor]",
    ]
    missing = sorted({t["source"] for h in hyps for t in h.get("telemetry", []) if not t["have"]})
    if missing:
        lines.append(f"- **Telemetry not collected when exported:** {', '.join(missing)}")
    lines += ["", "### Hunting Queries"]
    fence = lang.fence
    for h in hyps:
        lines += ["", f"#### {h['id']} — {h['title']}", "", f"```{fence}", h["query"], "```"]
        if h.get("query_notes"):
            lines += ["", f"**Query Notes:** {h['query_notes']}"]
    lines += [
        "",
        "### Visualization & Analytics",
        "",
        "",
        "### Query Performance",
        "- **What Worked:** ",
        "- **What Didn't:** ",
        "- **Iterations:** ",
        "",
        "## KEEP: Findings & Response",
        "",
        "### Executive Summary",
        "",
        "_Fill in after the hunt._",
        "",
        "### Findings",
        "",
        "| Verdict | Subject | Ticket | Evidence | Independent Confirmation |",
        "|---|---|---|---|---|",
        "",
        "### Ruled Out",
        "",
        "| Verdict | Subject | What Closed It |",
        "|---|---|---|",
        "",
        "**Counts:** `confirmed` 0 · `suspected` 0 · `attempted_not_vulnerable` 0 · `benign` 0 · `inconclusive` 0",
        "",
        "### Detection Logic",
        "",
        "### Lessons Learned",
        "",
        "### Follow-up Actions",
        "- [ ] ",
        "",
        "### Follow-up Hunts",
        "",
        "",
        "---",
        "**Hunt Completed:** [Date] · **Next Review:** [Date or N/A]",
        "",
    ]
    return "\n".join(lines)


async def build_hunt_file(db: AsyncSession, pack: dict, hunter: str, hunt_id: str = PLACEHOLDER_HUNT_ID) -> str:
    """The exported file for a cached pack: articles and CVE facts re-read live."""
    articles = await _articles_for(db, pack.get("entry_ids", []))
    facts = await collect_cve_facts(db, pack["entity_key"]) if pack["entity_type"] == entity_types.CVE else None
    return render_athf_markdown(pack, hunter=hunter, articles=articles, facts=facts, hunt_id=hunt_id)
