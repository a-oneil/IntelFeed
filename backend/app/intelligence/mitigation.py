"""Mitigation / Course-of-Action extraction — regex (Layer 1) + AI (Layer 2).

Both layers link articles to ATT&CK catalog mitigations only; see store_mitigations.
"""

import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import case, func, literal_column, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.engine import run_task
from app.models.mitigation import EntryMitigation, Mitigation, TTPMitigation
from app.models.ttp import TTP

# MITRE ATT&CK M-ID pattern (e.g. M1038, M1045)
MITIGATION_PATTERN = re.compile(r"\bM1\d{3}\b")


def extract_mitigation_ids_regex(text: str) -> list[dict]:
    """Layer 1: Extract MITRE ATT&CK M-IDs from text (free, no AI)."""
    if not text:
        return []
    matches = set(MITIGATION_PATTERN.findall(text))
    return [
        {
            "mitre_id": mid,
            "name": mid,  # Will be enriched by AI or ATT&CK data
            "confidence": "medium",
            "source": "regex",
        }
        for mid in sorted(matches)
    ]


async def extract_mitigations(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_id: uuid.UUID,
    entry_data: dict,
    use_ai: bool = True,
) -> tuple[list[dict], str, str | None]:
    """Extract mitigations — always runs regex, optionally runs AI, merges results.

    Returns (items, status, error_message).
    """
    text = f"{entry_data.get('title', '')} {entry_data.get('content_text', '')}"
    regex_mitigations = extract_mitigation_ids_regex(text)

    ai_mitigations = []
    ai_status = "success"
    ai_error = None
    if use_ai:
        from app.intelligence.telemetry_context import get_telemetry_for_prompt

        telemetry_sources = await get_telemetry_for_prompt(db, user_id)
        result = await run_task(
            db=db,
            user_id=user_id,
            task_name="mitigation_extraction",
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
        elif result and "mitigations" in result:
            ai_mitigations = result["mitigations"]

    # Merge: M-ID is the dedup key; AI results take precedence (richer data)
    merged: dict[str, dict] = {}
    for m in regex_mitigations:
        merged[m["mitre_id"]] = m
    for m in ai_mitigations:
        key = m.get("mitre_id") or m.get("name", "").strip()
        if key:
            merged[key] = m

    status = "success" if not use_ai else ai_status
    return list(merged.values()), status, ai_error


_DETAIL_MAX = 500


async def resolve_catalog_mitigation(db: AsyncSession, mitre_id: str | None, name: str | None) -> Mitigation | None:
    """The ATT&CK catalog mitigation an extracted item refers to, or None.

    By M-ID first, then by exact catalog name. Enterprise and ICS share names
    ("Audit" is M1047 and M0947), so a name-only match prefers Enterprise.
    """
    mitre_id = (mitre_id or "").strip().upper()
    if mitre_id:
        found = await db.scalar(
            select(Mitigation).where(Mitigation.is_catalog.is_(True), Mitigation.mitre_id == mitre_id)
        )
        if found is not None:
            return found
    name = (name or "").strip()
    if not name:
        return None
    return await db.scalar(
        select(Mitigation)
        .where(Mitigation.is_catalog.is_(True), func.lower(Mitigation.name) == name.lower())
        .order_by(case((Mitigation.mitre_id.like("M1%"), 0), else_=1), Mitigation.mitre_id)
        .limit(1)
    )


def _link_detail(m_data: dict, catalog: Mitigation) -> str | None:
    """The article's own wording, kept on the link: the AI's `detail`, else its
    description, else the name it gave when that isn't the catalog name."""
    name = (m_data.get("name") or "").strip()
    for text in (m_data.get("detail"), m_data.get("description"), name):
        text = (text or "").strip()
        if text and text.lower() not in (catalog.name.lower(), (catalog.mitre_id or "").lower()):
            return text[:_DETAIL_MAX]
    return None


async def store_mitigations(
    db: AsyncSession,
    entry_id: uuid.UUID,
    mitigations: list[dict],
) -> list[tuple[Mitigation, bool]]:
    """Link the entry to the ATT&CK catalog mitigations the items map to.

    Only catalog rows are mitigation entities: an item that maps to none (a
    one-off "upgrade X to 1.3.2", a generic "Patch", an invented M-ID) creates
    nothing and stays in the article's AI analysis. The article's wording rides
    on the link as `detail`. Returns (Mitigation, is_new) pairs; is_new is
    always False since nothing is created, kept for the callers' shape.
    """
    stored: list[tuple[Mitigation, bool]] = []
    seen: set[uuid.UUID] = set()

    for m_data in mitigations:
        mit_obj = await resolve_catalog_mitigation(db, m_data.get("mitre_id"), m_data.get("name"))
        if mit_obj is None or mit_obj.id in seen:
            continue
        seen.add(mit_obj.id)

        stmt = pg_insert(EntryMitigation).values(
            entry_id=entry_id,
            mitigation_id=mit_obj.id,
            confidence=m_data.get("confidence"),
            source=m_data.get("source", "ai"),
            detail=_link_detail(m_data, mit_obj),
        )
        inserted = await db.scalar(
            stmt.on_conflict_do_update(
                index_elements=[EntryMitigation.entry_id, EntryMitigation.mitigation_id],
                set_={"detail": func.coalesce(EntryMitigation.detail, stmt.excluded.detail)},
            ).returning(literal_column("xmax = 0"))
        )
        mit_obj.last_seen_at = datetime.now(UTC)
        if inserted:
            mit_obj.article_count = (mit_obj.article_count or 0) + 1

        # Link to TTPs mentioned in the same extraction result
        for ttp_id_str in m_data.get("applies_to_ttps", []):
            ttp_result = await db.execute(select(TTP).where(TTP.technique_id == ttp_id_str))
            ttp = ttp_result.scalar_one_or_none()
            if ttp:
                await db.execute(
                    pg_insert(TTPMitigation).values(ttp_id=ttp.id, mitigation_id=mit_obj.id).on_conflict_do_nothing()
                )

        stored.append((mit_obj, False))

    await db.flush()
    return stored
