"""Mitigation / Course-of-Action extraction — regex (Layer 1) + AI (Layer 2)."""

import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
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


async def store_mitigations(
    db: AsyncSession,
    entry_id: uuid.UUID,
    mitigations: list[dict],
) -> list[tuple[Mitigation, bool]]:
    """Upsert mitigations and link to entry. Returns list of (Mitigation, is_new)."""
    stored: list[tuple[Mitigation, bool]] = []

    for m_data in mitigations:
        mitre_id = (m_data.get("mitre_id") or "").strip() or None
        name = (m_data.get("name") or "").strip()
        if not name:
            continue

        # Lookup: prefer M-ID match, fall back to name
        existing = None
        if mitre_id:
            result = await db.execute(select(Mitigation).where(Mitigation.mitre_id == mitre_id))
            existing = result.scalar_one_or_none()
        if not existing:
            result = await db.execute(select(Mitigation).where(func.lower(Mitigation.name) == name.lower()))
            existing = result.scalar_one_or_none()

        if existing:
            existing.last_seen_at = datetime.now(UTC)
            existing.article_count += 1
            if mitre_id and not existing.mitre_id:
                existing.mitre_id = mitre_id
            if not existing.description and m_data.get("description"):
                existing.description = m_data["description"]
            if m_data.get("cis_controls"):
                existing_set = set(existing.cis_controls or [])
                merged_cis = list(existing.cis_controls or [])
                for c in m_data["cis_controls"]:
                    if c not in existing_set:
                        merged_cis.append(c)
                        existing_set.add(c)
                existing.cis_controls = merged_cis
            if m_data.get("nist_controls"):
                existing_set = set(existing.nist_controls or [])
                merged_nist = list(existing.nist_controls or [])
                for c in m_data["nist_controls"]:
                    if c not in existing_set:
                        merged_nist.append(c)
                        existing_set.add(c)
                existing.nist_controls = merged_nist
            mit_obj = existing
            is_new = False
        else:
            mit_obj = Mitigation(
                mitre_id=mitre_id,
                name=name if name != mitre_id else mitre_id,
                description=m_data.get("description"),
                mitre_url=m_data.get("mitre_url"),
                cis_controls=m_data.get("cis_controls", []),
                nist_controls=m_data.get("nist_controls", []),
            )
            db.add(mit_obj)
            await db.flush()
            is_new = True

        await db.execute(
            pg_insert(EntryMitigation)
            .values(
                entry_id=entry_id,
                mitigation_id=mit_obj.id,
                confidence=m_data.get("confidence"),
                source=m_data.get("source", "ai"),
            )
            .on_conflict_do_nothing()
        )

        # Link to TTPs mentioned in the same extraction result
        for ttp_id_str in m_data.get("applies_to_ttps", []):
            ttp_result = await db.execute(select(TTP).where(TTP.technique_id == ttp_id_str))
            ttp = ttp_result.scalar_one_or_none()
            if ttp:
                await db.execute(
                    pg_insert(TTPMitigation).values(ttp_id=ttp.id, mitigation_id=mit_obj.id).on_conflict_do_nothing()
                )

        stored.append((mit_obj, is_new))

    await db.flush()
    return stored
