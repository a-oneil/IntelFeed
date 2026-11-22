"""Hunt packs for threat-board rows: hypotheses, SIEM queries, and the ATHF hunt file.

A hunt pack is a starting point, not a record. From one row's window — its
articles, the techniques extracted from them, the observable sentences those
techniques were read from, and for a CVE its exploitation facts — the AI
drafts one to three hunt hypotheses in the shape the Agentic Threat Hunting
Framework (ATHF, github.com/Nebulock-Inc/agentic-threat-hunting-framework)
uses, each with a query in the analyst's preferred query language and the telemetry it
needs. The telemetry is checked against the enabled inventory at read time, so
a hypothesis the analyst cannot run yet says so instead of handing over a
query that returns nothing.

What happens next is not IntelFeed's business. The analyst copies a query, or
exports the pack as an ATHF hunt file — ``H-XXXX.md``, YAML frontmatter plus
the LOCK body (Learn / Observe / Check / Keep) with Learn, Observe and Check
filled from the row and Keep left for the hunt itself — and drops it in the
ATHF workspace. Running the hunt, findings, verdicts and tickets live there
and in the SIEM. The only thing stored here is the drafted pack, cached in
``ai_results`` the way the board's story line is, keyed by row, window and
query language, so a second open costs nothing and a redraft is explicit.

Generated on request, synchronously, from the API: the board is a working
surface and the analyst asked for this pack now. The brief's nightly fan-out
would spend a model call on every row for packs most of them never open.
"""

import json
import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.ai import engine as ai_engine
from app.ai.caller import Caller
from app.ai.query_language import language, prompt_variables
from app.services.detection_coverage import (
    CANONICAL_LOG_TYPES,
    classify_data_sources,
    get_available_telemetry,
)
from app.services.threat_board import WINDOW_HOURS
from app.services.threat_brief import collect_brief_entries, collect_cve_facts

TASK_NAME = "hunt_pack"
TARGET_TYPE = "hunt_pack"

MAX_HYPOTHESES = 3
# Behaviours the prompt sees: new-this-window first, then the most reported.
BEHAVIOUR_CAP = 12

_PACK_NS = uuid.UUID("2d3c9a4e-7f61-4b0a-9c8d-5e1f2a3b4c5d")


def pack_target_id(entity_type: str, entity_key: str, window: str, lang: str) -> uuid.UUID:
    """Stable UUID for the (row, window, language) cache key in ai_results."""
    return uuid.uuid5(_PACK_NS, f"{entity_type}:{entity_key}:{window}:{lang}")


# ── inputs ───────────────────────────────────────────────────────────────────


async def collect_hunt_inputs(db: AsyncSession, entity_type: str, entity_key: str, window: str) -> dict | None:
    """Everything the prompt may use: the row's window, and nothing else.

    Returns None when the row cannot be resolved. A resolved row with no
    articles and no behaviours is returned with empty lists, and the caller
    decides there is nothing to draft from.
    """
    from app.services.coverage_workspace import build_workspace

    hours = WINDOW_HOURS.get(window, WINDOW_HOURS["14d"])
    ws = await build_workspace(db, entity_type, entity_key, window=window, article_limit=BEHAVIOUR_CAP)
    if ws is None:
        return None
    entries = await collect_brief_entries(db, entity_type, entity_key, hours)
    behaviours = sorted(ws.behaviours, key=lambda b: (not b.is_new, -b.entry_count))[:BEHAVIOUR_CAP]
    facts = await collect_cve_facts(db, entity_key) if entity_type == entity_types.CVE else {}
    return {
        "label": ws.label,
        "entries": entries,
        "behaviours": [
            {
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
                ],
            }
            for b in behaviours
        ],
        "facts": facts,
    }


# ── cache ────────────────────────────────────────────────────────────────────


def _clean_hypothesis(raw: object, index: int) -> dict | None:
    """One hypothesis as the API shape, or None when the model's item is unusable."""
    if not isinstance(raw, dict):
        return None
    query = raw.get("query")
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
    }


def normalize_pack(parsed: dict | None) -> list[dict]:
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
        if len(out) >= MAX_HYPOTHESES:
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


def _pack_from_result(row, entity_type: str, entity_key: str, window: str, lang: str) -> dict | None:
    parsed = row.parsed_result if isinstance(row.parsed_result, dict) else {}
    hypotheses = parsed.get("hypotheses_clean")
    if not isinstance(hypotheses, list) or not hypotheses:
        return None
    return {
        "entity_type": entity_type,
        "entity_key": entity_key,
        "label": parsed.get("label") or entity_key,
        "window": window,
        "language": lang,
        "language_name": language(lang).name,
        "generated_at": row.created_at.isoformat() if row.created_at else None,
        "model": row.model_name,
        "entry_ids": [str(e) for e in parsed.get("entry_ids", []) if e],
        "hypotheses": hypotheses,
    }


async def get_cached_pack(db: AsyncSession, entity_type: str, entity_key: str, window: str, lang: str) -> dict | None:
    """The current pack for this row, window and language, or None."""
    row = await _current_result(db, pack_target_id(entity_type, entity_key, window, lang))
    if row is None:
        return None
    return _pack_from_result(row, entity_type, entity_key, window, lang)


# ── generation ───────────────────────────────────────────────────────────────


class NothingToHunt(Exception):
    """The row resolved but its window holds nothing a hypothesis could rest on."""


async def generate_hunt_pack(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_key: str,
    window: str,
    lang: str,
    timeout_seconds: float = 300.0,
) -> dict | None:
    """Draft the pack for one row now, replacing any cached one.

    Returns the pack, or None when the task has no provider assigned (the
    caller turns that into a 422). Raises NothingToHunt when the window has
    no articles and no extracted behaviours; LookupError when the row does
    not resolve.
    """
    inputs = await collect_hunt_inputs(db, entity_type, entity_key, window)
    if inputs is None:
        raise LookupError(entity_key)
    if not inputs["entries"] and not inputs["behaviours"]:
        raise NothingToHunt(entity_key)

    target_id = pack_target_id(entity_type, entity_key, window, lang)
    parsed = await ai_engine.run_task(
        db,
        user_id,
        TASK_NAME,
        variables={
            "threat_name": inputs["label"],
            "entity_type": entity_type,
            "window": window,
            **prompt_variables(lang),
            "entries": inputs["entries"],
            "entry_count": len(inputs["entries"]),
            "behaviours": inputs["behaviours"],
            "facts": inputs["facts"],
            "log_types": sorted(CANONICAL_LOG_TYPES),
        },
        target_type=TARGET_TYPE,
        target_id=target_id,
        force=True,
        timeout_seconds=timeout_seconds,
        caller=Caller.user(user_id),
    )
    if parsed is None:
        return None
    hypotheses = normalize_pack(parsed)

    # run_task stored the raw parsed_result; add the cleaned pack and its
    # audit trail beside it so the cache is self-describing.
    stored = await _current_result(db, target_id)
    if stored is not None:
        stored.parsed_result = {
            **(stored.parsed_result or {}),
            "hypotheses_clean": hypotheses,
            "label": inputs["label"],
            "entry_ids": [e["entry_id"] for e in inputs["entries"]],
            "window": window,
            "language": lang,
        }
        await db.commit()
        return _pack_from_result(stored, entity_type, entity_key, window, lang)
    if not hypotheses:
        return None
    return {
        "entity_type": entity_type,
        "entity_key": entity_key,
        "label": inputs["label"],
        "window": window,
        "language": lang,
        "language_name": language(lang).name,
        "generated_at": datetime.now(UTC).isoformat(),
        "model": None,
        "entry_ids": [e["entry_id"] for e in inputs["entries"]],
        "hypotheses": hypotheses,
    }


# ── telemetry check ──────────────────────────────────────────────────────────


async def annotate_telemetry(db: AsyncSession, pack: dict) -> dict:
    """Mark each hypothesis's data sources collected or not, against the live inventory.

    Done at read time rather than stored: a source ticked in Settings must
    flip the chip without a redraft.
    """
    profile = await get_available_telemetry(db)
    for h in pack["hypotheses"]:
        h["telemetry"] = [
            {"source": ds, "have": tier is not None} for ds, tier in classify_data_sources(h["data_sources"], profile)
        ]
        h["runnable"] = all(t["have"] for t in h["telemetry"]) if h["telemetry"] else True
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


def _slug(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:48] or "hunt"


PLACEHOLDER_HUNT_ID = "H-XXXX"
HUNT_ID_PATTERN = r"^H-\d{4}$"


def hunt_filename(pack: dict, hunt_id: str = PLACEHOLDER_HUNT_ID) -> str:
    return f"{hunt_id}-{_slug(pack['label'])}.md"


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
        f"- **Source:** IntelFeed threat board, {label} ({pack['window']} window, exported {day})",
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
        f"{label} on the IntelFeed threat board, {pack['window']} window: {len(articles)} article"
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
    lines.append("- **CTI sources (the window's articles):**")
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
