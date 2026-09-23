"""Nightly story lines for threat-board rows.

The board's counts say how much happened; the brief says what happened. It is
generated under a narrow contract so accuracy is the default:

- Inputs are the row's own window entries and nothing else — no model memory of
  the actor, no world knowledge. If it isn't in the window's articles, it isn't
  in the brief.
- Two to three sentences; victims/sector, access vector, tooling or artefact
  when the window documents one; uncertainty markers ("claims", "reportedly")
  preserved from the sources; counts forbidden (the row renders those itself).
- Vulnerability rows are written by their own prompt (``cve_brief``) against the
  same contract, because a CVE row is read to answer different questions: what
  the bug is, whether it is being exploited *or* merely disclosed, and what the
  vector reaches. That prompt also gets a facts block (KEV, EPSS, CVSS,
  affected products) as grounding — never to restate, since the row prints it.
- The cache key includes a hash of the window's entry set, so a new article
  invalidates the brief and an unchanged week costs nothing. The input entry
  ids are stored beside the text as its audit trail.

Never called on a request path. The nightly rank task fans this out for open
rows; the API only reads the cache and falls back to the lead headline.
"""

import hashlib
import logging
import uuid
from types import SimpleNamespace

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types

logger = logging.getLogger(__name__)

# The brief's inputs, per entity: the window's entries with their extracted
# techniques and any real observable quotes. Capped and truncated — the brief is
# two sentences, not a survey; twelve articles of context is plenty.
# Articles the prompt sees, and the candidate pool folded down to reach it.
# The cap used to be applied in SQL, before anything knew which articles were
# one story — so a wave of eight re-reports took eight of the twelve slots and
# the model saw four other stories at most.
BRIEF_ENTRY_CAP = 12
BRIEF_CANDIDATE_CAP = 24

_BRIEF_ENTRIES_SQL = text(
    """
WITH linked AS (
    SELECT e.id, e.title, e.summary, e.published_at,
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text)) AS source
    FROM entries e
    JOIN feeds f ON f.id = e.feed_id
    WHERE e.published_at > now() - make_interval(hours => :hours)
      AND f.title !~* 'rules|signatures|templates|detections|security content'
      AND (
        (:entity_type = 'threat_actor' AND EXISTS (
            SELECT 1 FROM entry_threat_actors x WHERE x.entry_id = e.id AND x.threat_actor_id::text = :entity_key))
        OR
        (:entity_type = 'malware' AND EXISTS (
            SELECT 1 FROM entry_malware x WHERE x.entry_id = e.id AND x.malware_family_id::text = :entity_key))
      )
    ORDER BY (SELECT count(*) FROM entry_ttps j WHERE j.entry_id = e.id) DESC, e.published_at DESC
    LIMIT :candidates
)
SELECT l.id, l.title, l.summary, l.published_at, l.source,
       coalesce((SELECT array_agg(DISTINCT t.technique_id || ' ' || t.technique_name)
                 FROM entry_ttps j JOIN ttps t ON t.id = j.ttp_id
                 WHERE j.entry_id = l.id), '{}')                       AS techniques,
       coalesce((SELECT (array_agg(j.source_text))[1:3]
                 FROM entry_ttps j
                 WHERE j.entry_id = l.id AND j.source_text IS NOT NULL
                   AND j.source_text NOT LIKE 'auto_link:%'), '{}')    AS quotes
FROM linked l
ORDER BY l.published_at DESC
"""
)


# CVE rows are keyed by cve_id (the string), not the row uuid, so they join
# through cves rather than matching a junction column directly. Ordering differs
# too: for a vulnerability the write-up that names the CVE in its title beats a
# technique-dense roundup that merely links it — the same preference
# _CVE_EVIDENCE_SQL uses to pick the row's lead article.
_CVE_BRIEF_ENTRIES_SQL = text(
    """
WITH linked AS (
    SELECT e.id, e.title, e.summary, e.published_at,
           (position(lower(c.cve_id) in lower(coalesce(e.title, ''))) > 0) AS names_cve,
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text)) AS source
    FROM cves c
    JOIN entry_cves ec ON ec.cve_id = c.id
    JOIN entries e ON e.id = ec.entry_id
    JOIN feeds f ON f.id = e.feed_id
    WHERE c.cve_id = :entity_key
      AND e.published_at > now() - make_interval(hours => :hours)
      AND f.title !~* 'rules|signatures|templates|detections|security content'
    ORDER BY names_cve DESC,
             (SELECT count(*) FROM entry_ttps j WHERE j.entry_id = e.id) DESC,
             e.published_at DESC
    LIMIT :candidates
)
SELECT l.id, l.title, l.summary, l.published_at, l.source,
       coalesce((SELECT array_agg(DISTINCT t.technique_id || ' ' || t.technique_name)
                 FROM entry_ttps j JOIN ttps t ON t.id = j.ttp_id
                 WHERE j.entry_id = l.id), '{}')                       AS techniques,
       coalesce((SELECT (array_agg(j.source_text))[1:3]
                 FROM entry_ttps j
                 WHERE j.entry_id = l.id AND j.source_text IS NOT NULL
                   AND j.source_text NOT LIKE 'auto_link:%'), '{}')    AS quotes
FROM linked l
ORDER BY l.published_at DESC
"""
)

# The exploitation facts a vulnerability brief has to reason against. Passed to
# the prompt as context to ground claims, not to be restated — the row already
# renders the scores beside the sentence.
_CVE_FACTS_SQL = text(
    """
SELECT c.cve_id, c.description, c.severity, c.cvss_score, c.epss_score, c.is_kev,
       c.kev_date_added, c.exploit_status, c.exploit_availability,
       coalesce((SELECT (array_agg(DISTINCT coalesce(p.name, v.name))
                         FILTER (WHERE coalesce(p.name, v.name) IS NOT NULL))[1:5]
                 FROM cve_affected ca
                 LEFT JOIN products p ON p.id = ca.product_id
                 LEFT JOIN vendors v ON v.id = ca.vendor_id
                 WHERE ca.cve_id = c.id), '{}') AS affected
FROM cves c
WHERE c.cve_id = :entity_key
"""
)


async def collect_cve_facts(db: AsyncSession, cve_id: str) -> dict:
    """Exploitation state + affected products for a vulnerability brief."""
    row = (await db.execute(_CVE_FACTS_SQL, {"entity_key": cve_id})).first()
    if row is None:
        return {}
    return {
        "description": (row.description or "")[:1200] or None,
        "severity": row.severity,
        # cvss_score is Numeric — float it so the variables stay JSON-plain.
        "cvss_score": float(row.cvss_score) if row.cvss_score is not None else None,
        "epss_score": float(row.epss_score) if row.epss_score is not None else None,
        "is_kev": bool(row.is_kev),
        "kev_date_added": row.kev_date_added.isoformat() if row.kev_date_added else None,
        "exploit_status": row.exploit_status,
        "exploit_availability": row.exploit_availability,
        "affected": list(row.affected or []),
    }


async def _fold_to_one_per_story(db: AsyncSession, rows: list[dict]) -> list[dict]:
    """One article per story, with what it folded recorded on it.

    Twelve articles where eight are the same advisory spend most of the model's
    attention saying that advisory eight times, and the brief comes back
    reading like the pile it was built from. Threads already know which ones
    are one story, so the batch is folded before the prompt is built — the same
    treatment the daily briefing gives its input.

    An article no thread holds passes through as itself, and carries no
    coverage fields: nothing knows what it is part of. A story is represented
    by its first member in the caller's order, skipping any the thread folded
    as an echo — an echo is a re-report of the article it would be standing in
    for.
    """
    if not rows:
        return rows
    members = {
        str(m.entry_id): m
        for m in (
            await db.execute(
                text(
                    """
                    SELECT ste.entry_id, ste.role, t.id AS thread_id, t.source_count
                    FROM story_thread_entries ste
                    JOIN story_threads t ON t.id = ste.thread_id
                    WHERE ste.entry_id = ANY(:ids)
                    """
                ),
                {"ids": [uuid.UUID(r["entry_id"]) for r in rows]},
            )
        ).all()
    }
    if not members:
        return rows

    order: list[object] = []
    groups: dict[object, list[dict]] = {}
    for row in rows:
        member = members.get(row["entry_id"])
        key = member.thread_id if member is not None else ("entry", row["entry_id"])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(row)

    kept: list[dict] = []
    for key in order:
        group = groups[key]
        representative = next(
            (r for r in group if (members.get(r["entry_id"]) or SimpleNamespace(role="")).role != "echo"),
            group[0],
        )
        member = members.get(representative["entry_id"])
        if member is not None:
            representative["outlet_count"] = int(member.source_count or 0)
            representative["also_reported_by"] = len(group) - 1
        kept.append(representative)
    return kept


async def collect_brief_entries(db: AsyncSession, entity_type: str, entity_key: str, hours: int) -> list[dict]:
    """The window's entries for one threat, shaped for the brief prompt."""
    if entity_type == entity_types.CVE:
        sql, params = _CVE_BRIEF_ENTRIES_SQL, {"entity_key": entity_key, "hours": hours}
    else:
        sql = _BRIEF_ENTRIES_SQL
        params = {"entity_type": entity_type, "entity_key": entity_key, "hours": hours}
    params["candidates"] = BRIEF_CANDIDATE_CAP
    rows = (await db.execute(sql, params)).all()
    folded = await _fold_to_one_per_story(
        db,
        [
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
        ],
    )
    return folded[:BRIEF_ENTRY_CAP]


TASK_NAME = "threat_brief"
# A vulnerability row answers a different question than an actor row — what the
# bug is, whether it is actually being exploited, what the vector reaches — so
# it gets its own prompt rather than the actor-framed one. The cache namespace
# stays shared: brief_target_id already keys on entity_type, so the two tasks
# cannot collide on a target id.
CVE_TASK_NAME = "cve_brief"
TARGET_TYPE = "threat_brief"

# Task names that write a board story line, for the bulk cache read.
BRIEF_TASK_NAMES = (TASK_NAME, CVE_TASK_NAME)


def task_name_for(entity_type: str) -> str:
    """The brief prompt this row's entity type is written by."""
    return CVE_TASK_NAME if entity_type == entity_types.CVE else TASK_NAME


# Briefs are generated for the board's default window only. Other windows fall
# back to the headline — 3x the nightly spend for the occasional 7d/30d view is
# not worth it.
BRIEF_WINDOW = "14d"

_BRIEF_NS = uuid.UUID("7b1f0d9e-3c65-4f27-9f0a-2f6f4f5f9b1a")

# System user for beat-scheduled generation, mirroring the daily summary.
SYSTEM_USER = uuid.UUID(int=0)


def brief_target_id(entity_type: str, entity_key: str, window: str = BRIEF_WINDOW) -> uuid.UUID:
    """Stable UUID for the (entity, window) cache key in ai_results."""
    return uuid.uuid5(_BRIEF_NS, f"{entity_type}:{entity_key}:{window}")


def entry_set_hash(entry_ids: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(entry_ids)).encode()).hexdigest()[:16]


async def get_cached_briefs(
    db: AsyncSession,
    keys: list[tuple[str, str]],
    window: str = BRIEF_WINDOW,
) -> dict[tuple[str, str], tuple[str, list[str]]]:
    """Bulk-read current briefs for board rows: (brief text, source entry ids).

    Returns only rows with a usable brief; callers render the headline for the
    rest. Staleness is tolerated between nightly runs — the drawer's article
    column is always the live evidence.
    """
    if not keys:
        return {}
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    # Both brief tasks write into the same target_type; a row's entity type
    # decides which one authored it, so the read accepts either.
    task_ids = (await db.execute(select(AITask.id).where(AITask.name.in_(BRIEF_TASK_NAMES)))).scalars().all()
    if not task_ids:
        return {}

    target_ids = {brief_target_id(et, ek, window): (et, ek) for et, ek in keys}
    rows = (
        await db.execute(
            select(AIResult)
            .where(
                AIResult.target_type == TARGET_TYPE,
                AIResult.target_id.in_(list(target_ids)),
                AIResult.task_id.in_(list(task_ids)),
                AIResult.is_current == True,  # noqa: E712
            )
            .order_by(AIResult.created_at.desc())
        )
    ).scalars()

    out: dict[tuple[str, str], tuple[str, list[str]]] = {}
    for row in rows:
        key = target_ids.get(row.target_id)
        parsed = row.parsed_result if isinstance(row.parsed_result, dict) else {}
        brief = parsed.get("brief")
        if key is None or key in out or not isinstance(brief, str) or not brief.strip():
            continue
        entry_ids = [str(e) for e in parsed.get("entry_ids", []) if e]
        out[key] = (brief.strip(), entry_ids)
    return out


async def ensure_threat_brief(
    db: AsyncSession,
    entity_type: str,
    entity_key: str,
    label: str,
    entries: list[dict],
    window: str = BRIEF_WINDOW,
    timeout_seconds: float = 120.0,
    facts: dict | None = None,
) -> dict:
    """Generate the brief for one row unless the cached one is still current.

    ``entries`` rows: {entry_id, title, source, published_at, summary,
    techniques, quotes}. ``facts`` is the CVE exploitation context from
    ``collect_cve_facts`` — ignored by the actor/malware prompt, which has no
    equivalent row-level state. Returns
    {"status": "cached" | "generated" | "skipped"}.
    """
    from app.ai.engine import run_task
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    if not entries:
        return {"status": "skipped", "reason": "no_entries"}

    task_name = task_name_for(entity_type)
    entry_ids = [str(e["entry_id"]) for e in entries]
    current_hash = entry_set_hash(entry_ids)
    target_id = brief_target_id(entity_type, entity_key, window)

    task_id = (await db.execute(select(AITask.id).where(AITask.name == task_name))).scalar_one_or_none()
    if task_id is not None:
        cached = (
            await db.execute(
                select(AIResult)
                .where(
                    AIResult.target_type == TARGET_TYPE,
                    AIResult.target_id == target_id,
                    AIResult.task_id == task_id,
                    AIResult.is_current == True,  # noqa: E712
                )
                .order_by(AIResult.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if (
            cached is not None
            and isinstance(cached.parsed_result, dict)
            and cached.parsed_result.get("entry_hash") == current_hash
            and cached.parsed_result.get("brief")
        ):
            return {"status": "cached"}

    result = await run_task(
        db,
        SYSTEM_USER,
        task_name,
        variables={
            "threat_name": label,
            "entity_type": entity_type,
            "window": window,
            "entries": entries,
            "entry_count": len(entries),
            "facts": facts or {},
        },
        target_type=TARGET_TYPE,
        target_id=target_id,
        force=True,
        timeout_seconds=timeout_seconds,
    )
    if not result or not isinstance(result.get("brief"), str) or not result["brief"].strip():
        return {"status": "skipped", "reason": "no_result"}

    # run_task stored the model's parsed_result; append the audit fields so the
    # cache is self-describing (staleness hash + the entries it was built from).
    if task_id is None:
        task_id = (await db.execute(select(AITask.id).where(AITask.name == task_name))).scalar_one_or_none()
    stored = (
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
    if stored is not None:
        stored.parsed_result = {
            **(stored.parsed_result or {}),
            "entry_hash": current_hash,
            "entry_ids": entry_ids,
            "window": window,
        }
        await db.commit()
    return {"status": "generated"}
