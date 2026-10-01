"""Entity assessment (AI summary) generation.

Shared by the profile "AI refresh" endpoint
(POST /entities/{type}/{id}/ai-summary) and the assessment-backfill worker so
both produce identical results: the entity's linked reporting is rendered into
a dossier, run through the `article_summary` AI task, and saved to the
entity's description.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.correlation_cache import invalidate_entity_cache
from app.models.country import Country, EntryCountry
from app.models.cve import CVE, EntryCVE
from app.models.entry import Entry
from app.models.entry_sector import EntrySector
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.observable import EntryObservable, Observable
from app.models.product import EntryProduct, Product
from app.models.sector import Sector
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.models.vendor import EntryVendor, Vendor

# (model, entry junction, junction FK attr) per summarizable entity type.
ENTITY_MODEL_MAP = {
    "threat_actor": (ThreatActor, EntryThreatActor, "threat_actor_id"),
    "malware": (MalwareFamily, EntryMalware, "malware_family_id"),
    "ttp": (TTP, EntryTTP, "ttp_id"),
    "cve": (CVE, EntryCVE, "cve_id"),
    "country": (Country, EntryCountry, "country_id"),
    "tool": (Tool, EntryTool, "tool_id"),
    "vendor": (Vendor, EntryVendor, "vendor_id"),
    "product": (Product, EntryProduct, "product_id"),
    "observable": (Observable, EntryObservable, "observable_id"),
    "sector": (Sector, EntrySector, "sector_id"),
}


async def generate_entity_assessment(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_id: uuid.UUID,
    only_if_empty: bool = False,
) -> dict:
    """Generate an AI assessment for an entity and save it to its description.

    Returns a status dict rather than raising, so worker callers can branch on
    outcomes (notably provider_paused) without exception plumbing:
      {"status": "updated", "summary": ...}
      {"status": "unsupported_type" | "not_found" | "no_description_field"
                 | "already_has_assessment" | "no_ai"}
      {"status": "provider_paused", "pause_until": iso-str | None}
    """
    if entity_type not in ENTITY_MODEL_MAP:
        return {"status": "unsupported_type"}

    model_cls, junction_cls, fk_attr = ENTITY_MODEL_MAP[entity_type]

    result = await db.execute(select(model_cls).where(model_cls.id == entity_id))
    entity = result.scalar_one_or_none()
    if not entity:
        return {"status": "not_found"}

    if not hasattr(entity, "description") and not hasattr(entity, "context"):
        return {"status": "no_description_field"}

    if only_if_empty:
        current = getattr(entity, "description", None) or getattr(entity, "context", None)
        if current and current.strip():
            return {"status": "already_has_assessment"}

    entity_name = (
        getattr(entity, "name", None)
        or getattr(entity, "value", None)
        or getattr(entity, "cve_id", None)
        or getattr(entity, "technique_id", None)
        or str(entity_id)
    )

    # Load linked articles (most recent 20)
    fk_col = getattr(junction_cls, fk_attr)
    articles_result = await db.execute(
        select(Entry.title, Entry.published_at, Entry.summary)
        .join(junction_cls, junction_cls.entry_id == Entry.id)
        .where(fk_col == entity_id)
        .order_by(Entry.published_at.desc().nullslast())
        .limit(20)
    )
    articles = articles_result.all()

    article_lines = []
    for title, pub_at, summary in articles:
        date_str = pub_at.strftime("%Y-%m-%d") if pub_at else "unknown date"
        article_lines.append(f"- [{date_str}] {title}")
        if summary:
            article_lines.append(f"  {summary[:200]}")

    meta_parts = []
    for attr in [
        "aliases",
        "country",
        "motivation",
        "malware_type",
        "technique_name",
        "tactic",
        "cvss_score",
        "severity",
        "targeted_sectors",
    ]:
        val = getattr(entity, attr, None)
        if val:
            meta_parts.append(f"{attr}: {val}")

    context = f"""Entity type: {entity_type}
Entity name: {entity_name}
{chr(10).join(meta_parts)}

Recent articles ({len(articles)} most recent):
{chr(10).join(article_lines) if article_lines else "No linked articles."}"""

    from app.ai.engine import run_task

    # The shared article_summary prompt renders `entry.*`; present the entity
    # dossier as a synthetic "entry" so the template resolves. Flat
    # content/title are kept for any legacy custom prompt still using them.
    entry_title = f"Entity profile: {entity_name}"
    ai_result = await run_task(
        db,
        user_id,
        "article_summary",
        variables={
            "entry": {
                "title": entry_title,
                "feed_title": "IntelFeed entity dossier",
                "content_text": context,
            },
            "content": context,
            "title": entry_title,
        },
        # Attribute the call to the entity so it shows up under
        # /api/ai/results/{entity_type}/{id} (profile AI tab), lands in the cost
        # breakdown, and gives the backfill worker a durable record of which
        # entities were attempted and how they turned out.
        target_type=entity_type,
        target_id=entity_id,
        # force: run_task's dedup guard would otherwise return the previous
        # is_current AIResult forever — including a stored parse_error, which
        # would permanently pin an entity to its first failed attempt.
        force=True,
    )

    if isinstance(ai_result, dict):
        extraction_status = ai_result.get("_extraction_status", "success")
        if extraction_status == "provider_paused":
            # run_task only flushes the AIResult and the provider's paused_until
            # UPDATE; worker_session closes without committing, so both are
            # rolled back unless we commit here.
            await db.commit()
            return {"status": "provider_paused", "pause_until": ai_result.get("_pause_until")}
        # parse_error / provider_error must never be saved as the assessment
        # (Ollama in particular fails this way — repetition loops and
        # max_tokens overflows come back as parse_error with raw output).
        if extraction_status != "success":
            # Persist the failed attempt: find_assessment_backfill_candidates
            # reads these AIResult rows to enforce its retry window, and a
            # rolled-back failure would let the same entity be re-picked daily.
            await db.commit()
            return {"status": "ai_error", "ai_status": extraction_status}
        summary_text = ai_result.get("summary", str(ai_result))
    elif ai_result and isinstance(ai_result, str):
        summary_text = ai_result
    else:
        return {"status": "no_ai"}

    if hasattr(entity, "description"):
        entity.description = summary_text
        written_field = "description"
    else:
        entity.context = summary_text
        written_field = "context"

    db.add(entity)

    # Sign the write. Every other path that fills a profile field records who
    # asserted it (enrichment adapters, the gap-fill pass, analyst edits); the
    # assessment did not, so an AI-written description showed on the profile as
    # unsourced and nothing downstream could tell it apart from an import.
    # record_claims filters to PROVENANCE_FIELDS, so types that don't track the
    # field (observables' `context`) are skipped rather than special-cased here.
    from app.services.claim_provenance import record_claims

    await record_claims(
        db,
        entity_type=entity_type,
        entity_id=entity_id,
        values={written_field: summary_text},
        source_kind="ai_assessment",
        source_ref="entity_assessment",
    )

    await db.flush()
    await db.refresh(entity)
    await invalidate_entity_cache(entity_type, str(entity_id))
    await db.commit()

    return {"status": "updated", "summary": summary_text}
