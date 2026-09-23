"""Intelligence Extraction tools."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entry import Entry
from app.tools import _tool


def _entry_to_dict(entry: Entry) -> dict:
    """Serialize an entry for AI prompt variables.

    Mirrors app.api.intelligence._entry_to_dict — prompt templates render
    ``{{ entry.content_text }}`` / ``{{ entry.feed_title }}`` etc., and the
    regex TTP layer reads ``content_text``.
    """
    return {
        "title": entry.title,
        "content_text": entry.content_text or "",
        "content_html": entry.content_html,
        "summary": entry.summary,
        "author": entry.author,
        "url": entry.url,
        "published_at": str(entry.published_at) if entry.published_at else "",
        "feed_title": "",
    }


@_tool(
    name="extract_ttps",
    description=(
        "Extract MITRE ATT&CK techniques (TTPs) from an entry. Always runs regex matching; use_ai adds the "
        "ttp_mapping AI task (its result is cached per entry — reruns reuse the current AIResult). Stores links."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID"},
            "use_ai": {"type": "boolean", "default": True},
        },
        "required": ["entry_id"],
    },
)
async def _extract_ttps(db: AsyncSession, user_id: uuid.UUID, entry_id: str, use_ai: bool = True) -> dict:
    from app.intelligence.ttp import extract_ttps, store_ttps

    eid = uuid.UUID(entry_id)
    result = await db.execute(select(Entry).where(Entry.id == eid))
    entry = result.scalar_one_or_none()
    if not entry:
        return {"error": "Entry not found"}

    ttps_list, status, error = await extract_ttps(db, user_id, eid, _entry_to_dict(entry), use_ai=use_ai)
    stored = await store_ttps(db, eid, ttps_list)

    out = {
        "entry_id": entry_id,
        "ttps_found": len(ttps_list),
        "new_ttps": sum(1 for _, is_new in stored if is_new),
        "status": status,
        "ttps": [
            {
                "technique_id": t["technique_id"],
                "name": t.get("technique_name", ""),
                "confidence": t.get("confidence", "medium"),
            }
            for t in ttps_list[:30]
        ],
    }
    if error:
        out["error"] = error
    return out


@_tool(
    name="extract_cves",
    description="Extract CVE references from an entry and optionally enrich from NVD. Stores results.",
    input_schema={
        "properties": {"entry_id": {"type": "string", "description": "Entry UUID"}},
        "required": ["entry_id"],
    },
)
async def _extract_cves(db: AsyncSession, user_id: uuid.UUID, entry_id: str) -> dict:
    from app.intelligence.cve import extract_and_store_cves

    eid = uuid.UUID(entry_id)
    result = await db.execute(select(Entry).where(Entry.id == eid))
    entry = result.scalar_one_or_none()
    if not entry:
        return {"error": "Entry not found"}

    text = entry.content_text or entry.content_html or ""
    cves = await extract_and_store_cves(db, eid, text, enrich=True)
    return {
        "entry_id": entry_id,
        "cves_found": len(cves),
        "cves": [{"cve_id": c.cve_id, "cvss": c.cvss_score, "severity": c.severity} for c in cves],
    }


@_tool(
    name="extract_threat_actors",
    description=(
        "Identify threat actors in an entry via the consolidated entry_analysis AI task (may return the cached "
        "ingest-time analysis instead of a fresh AI call). Creates or links threat actor entities."
    ),
    input_schema={
        "properties": {"entry_id": {"type": "string", "description": "Entry UUID"}},
        "required": ["entry_id"],
    },
)
async def _extract_threat_actors(db: AsyncSession, user_id: uuid.UUID, entry_id: str) -> dict:
    from app.intelligence.enrichment import extract_threat_actors

    eid = uuid.UUID(entry_id)
    result = await db.execute(select(Entry).where(Entry.id == eid))
    entry = result.scalar_one_or_none()
    if not entry:
        return {"error": "Entry not found"}

    actors, status, error = await extract_threat_actors(db, user_id, eid, _entry_to_dict(entry))
    out = {
        "entry_id": entry_id,
        "status": status,
        "actors_found": len(actors),
        "actors": [{"id": str(a.id), "name": a.name, "is_new": is_new} for a, is_new in actors],
    }
    if error:
        out["error"] = error
    return out


@_tool(
    name="extract_malware",
    description=(
        "Identify malware families in an entry via the consolidated entry_analysis AI task (may return the cached "
        "ingest-time analysis instead of a fresh AI call). Creates or links malware entities."
    ),
    input_schema={
        "properties": {"entry_id": {"type": "string", "description": "Entry UUID"}},
        "required": ["entry_id"],
    },
)
async def _extract_malware(db: AsyncSession, user_id: uuid.UUID, entry_id: str) -> dict:
    from app.intelligence.enrichment import extract_malware

    eid = uuid.UUID(entry_id)
    result = await db.execute(select(Entry).where(Entry.id == eid))
    entry = result.scalar_one_or_none()
    if not entry:
        return {"error": "Entry not found"}

    families, status, error = await extract_malware(db, user_id, eid, _entry_to_dict(entry))
    out = {
        "entry_id": entry_id,
        "status": status,
        "malware_found": len(families),
        "malware": [{"id": str(m.id), "name": m.name, "is_new": is_new} for m, is_new in families],
    }
    if error:
        out["error"] = error
    return out


@_tool(
    name="run_ai_task",
    description=(
        "Run a registered AI task against an entry (e.g. article_summary, threat_assessment, detection_rules, "
        "entry_analysis). Returns the current cached AIResult when one exists for this entry+task; pass force=true "
        "to re-run and replace it. The 'cached' field reports which happened."
    ),
    input_schema={
        "properties": {
            "task_name": {
                "type": "string",
                "description": "AI task name (e.g. article_summary, threat_assessment, detection_rules)",
            },
            "entry_id": {"type": "string", "description": "Entry UUID to run the task on"},
            "force": {
                "type": "boolean",
                "default": False,
                "description": "Re-run even if a cached result exists (marks the old result not current)",
            },
        },
        "required": ["task_name", "entry_id"],
    },
)
async def _run_ai_task(
    db: AsyncSession, user_id: uuid.UUID, task_name: str, entry_id: str, force: bool = False
) -> dict:
    from app.ai.engine import run_task
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    eid = uuid.UUID(entry_id)
    result = await db.execute(select(Entry).where(Entry.id == eid))
    entry = result.scalar_one_or_none()
    if not entry:
        return {"error": "Entry not found"}

    # run_task returns the current cached AIResult when one exists (dedup guard);
    # detect that up front so the response can say cached vs fresh.
    cached = False
    if not force:
        task_row = await db.execute(select(AITask.id).where(AITask.name == task_name))
        task_id = task_row.scalar_one_or_none()
        if task_id:
            existing = await db.execute(
                select(AIResult.id)
                .where(
                    AIResult.target_type == "entry",
                    AIResult.target_id == eid,
                    AIResult.task_id == task_id,
                    AIResult.is_current == True,  # noqa: E712
                )
                .limit(1)
            )
            cached = existing.scalar_one_or_none() is not None

    entry_dict = _entry_to_dict(entry)
    variables = {
        "title": entry.title,
        "content_text": entry_dict["content_text"],
        "url": entry.url or "",
        "entry": entry_dict,
    }

    ai_result = await run_task(
        db=db, user_id=user_id, task_name=task_name, variables=variables, entry_id=eid, force=force
    )
    if ai_result is None:
        return {"error": f"No AI task assignment found for '{task_name}'. Configure it in Settings > AI."}
    return {"task_name": task_name, "cached": cached, "result": ai_result}
