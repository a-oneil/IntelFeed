"""TTP extraction and MITRE ATT&CK mapping — regex (Layer 1) + AI (Layer 2)."""

import logging
import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.engine import run_task
from app.models.ttp import TTP, EntryTTP

logger = logging.getLogger(__name__)

# Valid ATT&CK sub-techniques are .001+; ".000" is invalid, so a lookahead rejects
# it and the match falls back to the parent technique (e.g. "T1059.000" -> "T1059").
TTP_PATTERN = re.compile(r"\bT\d{4}(?:\.(?!000\b)\d{3})?\b")


def normalize_technique_id(technique_id: str) -> str:
    """Strip an invalid ".000" sub-technique suffix back to the parent technique."""
    if technique_id.endswith(".000"):
        return technique_id[:-4]
    return technique_id


def _normalize_name(name: str) -> str:
    """Casefold to alphanumerics + single spaces for tolerant name comparison."""
    return " ".join(re.sub(r"[^a-z0-9]+", " ", name.lower()).split())


def name_contradicts_catalog(claimed_name: str, canonical_name: str, technique_id: str) -> bool:
    """True when an extracted ``technique_name`` contradicts the catalog's name.

    Models reliably emit *syntactically valid* technique IDs while mispairing
    them with the wrong technique — e.g. labelling T1562.004 ("Disable or
    Modify System Firewall") as "Clear Windows Event Logs". The ID survives
    validation, so the bad mapping lands silently. Because the catalog already
    supplies the authoritative name, the model's own name is a free second
    opinion: disagreement means it was not describing the technique it named.

    Measured accuracy is bimodal — ~82% correct on advisories that print the
    ATT&CK IDs (the model copies them) versus ~33% when it must recall the
    mapping from memory, which is most vendor reporting. So this fires
    predominantly on the recalled cases, exactly where the risk lives.

    Comparison is substring-based in both directions because models often
    prefix the parent technique ("Impair Defenses: Disable or Modify Tools")
    while the catalog stores the sub-technique name alone.
    """
    claimed = (claimed_name or "").strip()
    canonical = (canonical_name or "").strip()
    # The regex layer emits technique_name == technique_id; that asserts no
    # name, and an un-hydrated catalog stub carries none either. No signal.
    if not claimed or claimed.upper() == technique_id.upper():
        return False
    if not canonical or canonical.upper() == technique_id.upper():
        return False
    a, b = _normalize_name(claimed), _normalize_name(canonical)
    if not a or not b:
        return False
    return a not in b and b not in a


def extract_ttp_ids_regex(text: str) -> list[dict]:
    """Layer 1: Extract MITRE ATT&CK technique IDs from text using regex (free, no AI)."""
    if not text:
        return []
    matches = set(TTP_PATTERN.findall(text))
    return [
        {
            "technique_id": tid,
            "technique_name": tid,
            "confidence": "medium",
            "source": "regex",
        }
        for tid in sorted(matches)
    ]


async def extract_ttps(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_id: uuid.UUID,
    entry_data: dict,
    use_ai: bool = True,
) -> tuple[list[dict], str, str | None]:
    """Extract TTPs — always runs regex, optionally runs AI, merges results.

    Returns (items, status, error_message).
    """
    # Layer 1: Regex (free)
    text = f"{entry_data.get('title', '')} {entry_data.get('content_text', '')}"
    regex_ttps = extract_ttp_ids_regex(text)

    # Layer 2: AI (optional)
    ai_ttps = []
    ai_status = "success"
    ai_error = None
    if use_ai:
        from app.intelligence.telemetry_context import get_telemetry_for_prompt

        telemetry_sources = await get_telemetry_for_prompt(db, user_id)
        result = await run_task(
            db=db,
            user_id=user_id,
            task_name="ttp_mapping",
            variables={"entry": entry_data, "telemetry_sources": telemetry_sources},
            entry_id=entry_id,
        )
        if result is None:
            ai_status = "ai_not_configured"
        elif isinstance(result, dict) and result.get("_extraction_status") == "provider_error":
            ai_status = "provider_error"
            ai_error = result.get("_error")
        elif isinstance(result, dict) and result.get("_extraction_status") == "parse_error":
            ai_status = "parse_error"
        elif result and "ttps" in result:
            ai_ttps = result["ttps"]

    # Merge: AI results take precedence (richer data)
    merged = {t["technique_id"]: t for t in regex_ttps}
    for t in ai_ttps:
        tid = normalize_technique_id(t.get("technique_id", "").strip())
        if tid:
            merged[tid] = {**t, "technique_id": tid}

    # If AI was not used, status is always success (regex-only)
    status = "success" if not use_ai else ai_status
    return list(merged.values()), status, ai_error


async def _entry_context_text(db: AsyncSession, entry_id: uuid.UUID) -> str:
    """Fetch entry title + content for catalog context checks (e.g. ICS gating)."""
    from app.models.entry import Entry

    result = await db.execute(select(Entry.title, Entry.summary, Entry.content_text).where(Entry.id == entry_id))
    row = result.one_or_none()
    if not row:
        return ""
    return " ".join(part for part in row if part)


async def store_ttps(
    db: AsyncSession,
    entry_id: uuid.UUID,
    ttps: list[dict],
    context_text: str | None = None,
) -> list[tuple[TTP, bool]]:
    """Store TTPs in the database, upserting existing ones and linking to entry.

    Technique IDs are validated against the hydrated ATT&CK catalog first:
    unknown IDs are dropped, revoked ones map to their replacement, and
    ICS-matrix techniques require ICS/OT entry context. Valid IDs always have
    a hydrated catalog row, so new rows with technique_name == technique_id
    are only ever created in the pre-hydration fallback.

    Returns list of (TTP, is_new) tuples where is_new=True means the TTP was newly created.
    """
    from app.intelligence.attack_catalog import resolve_technique_ids

    # Normalize + dedupe candidates (first occurrence wins, AI entries are
    # already merged over regex ones by extract_ttps)
    candidates: dict[str, dict] = {}
    for ttp_data in ttps:
        technique_id = normalize_technique_id(ttp_data.get("technique_id", "").strip())
        if technique_id and technique_id not in candidates:
            candidates[technique_id] = ttp_data

    if not candidates:
        return []

    if context_text is None:
        context_text = await _entry_context_text(db, entry_id)
    resolution = await resolve_technique_ids(db, list(candidates), context_text)

    stored: list[tuple[TTP, bool]] = []
    seen_resolved: set[str] = set()
    for candidate_id, ttp_data in candidates.items():
        technique_id = resolution.get(candidate_id)
        if not technique_id or technique_id in seen_resolved:
            continue  # unknown/gated id, or two candidates resolved to the same replacement
        seen_resolved.add(technique_id)

        result = await db.execute(select(TTP).where(TTP.technique_id == technique_id))
        existing = result.scalar_one_or_none()

        # Second opinion: if the extractor named a different technique than the
        # one its ID points at, it was confused about which technique it meant.
        # The link still stands (the ID is valid and may be right) but it is no
        # longer trustworthy enough to carry a high confidence downstream.
        confidence = ttp_data.get("confidence")
        if existing and name_contradicts_catalog(
            ttp_data.get("technique_name", ""), existing.technique_name, technique_id
        ):
            logger.info(
                "TTP %s: extracted name %r contradicts catalog name %r — downgrading confidence %s -> low",
                technique_id,
                ttp_data.get("technique_name", ""),
                existing.technique_name,
                confidence or "unset",
            )
            confidence = "low"

        if existing:
            existing.last_seen_at = datetime.now(UTC)
            existing.article_count += 1
            # Fill in missing profile data (e.g., regex found ID only, AI now provides details)
            new_name = ttp_data.get("technique_name", "").strip()
            if new_name and new_name != technique_id and existing.technique_name == technique_id:
                existing.technique_name = new_name
            if not existing.tactic and ttp_data.get("tactic"):
                existing.tactic = ttp_data["tactic"]
            if not existing.description and ttp_data.get("description"):
                existing.description = ttp_data["description"]
            ttp_obj = existing
            is_new = False
        else:
            # An analyst deleted this technique from the AI entities table —
            # don't mint it again (TTPs bypass resolve_entity_creation).
            from app.intelligence.entity_resolution import is_name_denied

            if await is_name_denied(db, "ttp", technique_id):
                logger.info("Skipping TTP %s: on the analyst do-not-recreate list", technique_id)
                continue

            ttp_obj = TTP(
                technique_id=technique_id,
                technique_name=ttp_data.get("technique_name", technique_id),
                tactic=ttp_data.get("tactic"),
                description=ttp_data.get("description"),
                created_via="ai_extraction",
                created_from_entry_id=entry_id,
                created_confidence=ttp_data.get("confidence"),
            )
            db.add(ttp_obj)
            await db.flush()
            is_new = True

        # Link to entry (atomic upsert — prevents duplicates under concurrency).
        # On conflict the AI pass's evidence must still land: the autolinker
        # usually creates the link first with an `auto_link:` marker, and
        # do_nothing() silently dropped every real quote the analysis produced
        # for an already-linked technique — the exact substance rules are
        # written from. A real sentence overwrites a NULL or marker value and
        # never the other way around.
        incoming_text = (ttp_data.get("source_text") or "").strip() or None
        incoming_is_real = bool(incoming_text and not incoming_text.startswith("auto_link:"))
        stmt = pg_insert(EntryTTP).values(
            entry_id=entry_id,
            ttp_id=ttp_obj.id,
            confidence=confidence,
            source_text=incoming_text,
            observable_type=(ttp_data.get("observable_type") or "").strip() or None,
            observable_value=(ttp_data.get("observable_value") or "").strip() or None,
            telemetry=(ttp_data.get("telemetry") or "").strip() or None,
        )
        if incoming_is_real:
            stmt = stmt.on_conflict_do_update(
                index_elements=["entry_id", "ttp_id"],
                set_={
                    "source_text": stmt.excluded.source_text,
                    "confidence": func.coalesce(stmt.excluded.confidence, EntryTTP.confidence),
                    "observable_type": func.coalesce(stmt.excluded.observable_type, EntryTTP.observable_type),
                    "observable_value": func.coalesce(stmt.excluded.observable_value, EntryTTP.observable_value),
                    "telemetry": func.coalesce(stmt.excluded.telemetry, EntryTTP.telemetry),
                },
                where=or_(EntryTTP.source_text.is_(None), EntryTTP.source_text.like("auto\\_link:%")),
            )
        else:
            stmt = stmt.on_conflict_do_nothing()
        await db.execute(stmt)

        stored.append((ttp_obj, is_new))

    await db.flush()

    # Queue enrichment for newly created TTPs
    from app.enrichment.queue import enqueue

    for ttp_obj, is_new in stored:
        if is_new:
            await enqueue(db, "ttp", ttp_obj.id, ttp_obj.technique_id)

    return stored


def generate_navigator_layer(
    ttps: list[dict],
    title: str = "TTPs",
) -> dict:
    """Generate an ATT&CK Navigator layer JSON from TTPs."""
    techniques = []
    confidence_colors = {
        "high": "#ff6666",
        "medium": "#ffcc66",
        "low": "#ffff99",
    }

    for ttp in ttps:
        technique_id = ttp.get("technique_id", "")
        confidence = ttp.get("confidence", "medium")
        techniques.append(
            {
                "techniqueID": technique_id,
                "tactic": ttp.get("tactic", "").replace(" ", "-").lower(),
                "color": confidence_colors.get(confidence, "#ffcc66"),
                "comment": ttp.get("source_text", ttp.get("technique_name", "")),
                "score": {"high": 100, "medium": 75, "low": 50}.get(confidence, 75),
                "enabled": True,
            }
        )

    return {
        "name": f"TTPs from: {title}",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ffcc66", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
    }
