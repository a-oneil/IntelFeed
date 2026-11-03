"""Offensive tool extraction — AI-only (dual-use tools distinct from malware families)."""

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.engine import run_task
from app.intelligence.entity_dedup import link_entry_to_entity
from app.intelligence.entity_resolution import (
    coerce_tool_type,
    defender_operated,
    evidence_names,
    gate_aliases,
    resolve_entity_creation,
)
from app.models.tool import EntryTool, Tool
from app.services.system_settings import get_setting

logger = logging.getLogger(__name__)


async def extract_tools(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_id: uuid.UUID,
    entry_data: dict,
) -> tuple[list[tuple[Tool, bool]], str, str | None]:
    """Extract offensive tools from entry using AI.

    Returns (items, status, error_message).
    """
    # Routed through the consolidated entry_analysis task (tool_extraction is
    # deprecated); shares one cached AI call with the other per-type extracts.
    result = await run_task(
        db=db,
        user_id=user_id,
        task_name="entry_analysis",
        variables={"entry": entry_data},
        entry_id=entry_id,
        target_type="entry",
        target_id=entry_id,
    )

    if result is None:
        return [], "ai_not_configured", None
    if isinstance(result, dict) and result.get("_extraction_status") == "provider_error":
        return [], "provider_error", result.get("_error")
    if isinstance(result, dict) and result.get("_extraction_status") == "parse_error":
        return [], "parse_error", None
    if not result or "tools" not in result:
        return [], "success", None

    stored = await store_tools(db, entry_id, result["tools"])
    return stored, "success", None


async def store_tools(
    db: AsyncSession,
    entry_id: uuid.UUID,
    tools_data: list[dict],
    *,
    allow_create: bool = True,
) -> list[tuple[Tool, bool]]:
    """Persist AI-extracted offensive tools + entry links (shared with entry_analysis).

    ``allow_create=False`` is link-only: names that resolve to an existing tool
    (or to a cross-type survivor) are linked as usual, but no new tool row is
    minted. The feed's "create records for new tools" switch drives it.
    """
    stored: list[tuple[Tool, bool]] = []

    # Evidence door (2026-09): a tool is software WIELDED during an intrusion,
    # so the payload has to name an operator and quote the sentence showing
    # them using it. Small models comply with a field they must fill far
    # better than with a list of things not to do — this is what drains the
    # advisory-driven flood of dependency and vulnerable-package names. The
    # setting is the escape hatch if a provider stops filling the fields at
    # all. See planning/tool-extraction-cleanup.md.
    evidence_required = bool(await get_setting("ai_tool_evidence_required", db))
    dropped_no_evidence = 0

    for tool_data in tools_data:
        name = (tool_data.get("name") or "").strip()
        if not name:
            continue

        if evidence_required and not (
            (tool_data.get("evidence") or "").strip() and (tool_data.get("wielded_by") or "").strip()
        ):
            dropped_no_evidence += 1
            continue

        # Only attacker tools are created. Software that just defenders,
        # researchers or users operate, or whose evidence sentence is about
        # something else, still links to an existing row but mints nothing.
        may_create = allow_create
        if evidence_required and (
            defender_operated(tool_data.get("wielded_by"))
            or not evidence_names(tool_data.get("evidence"), name, tool_data.get("aliases"))
        ):
            may_create = False

        # Resolver: exact + normalized matching, cross-type tombstones, and the
        # creation gates — F13 code-artifact/technique/physical-object names
        # never become tools (planning/entity-creation-guardrails.md).
        decision = await resolve_entity_creation(
            db, "tool", name, tool_data.get("aliases"), source="ai", entry_id=entry_id, link_only=not may_create
        )
        if decision.action == "tombstone":
            tombstone = decision.tombstone
            await link_entry_to_entity(db, entry_id, tombstone.target_type, tombstone.target_id, matched_name=name)
            continue
        if decision.action in ("blocked", "held"):
            # Cross-type hold: link the entry to the survivor rather than
            # losing the mention along with the suppressed profile.
            if decision.link_target:
                await link_entry_to_entity(db, entry_id, *decision.link_target, matched_name=name)
            continue

        existing = decision.entity

        if existing:
            existing.last_seen_at = datetime.now(UTC)
            existing.article_count += 1
            # Merge aliases without duplicating
            new_aliases = await gate_aliases(db, "tool", existing.name, tool_data.get("aliases"), entity_id=existing.id)
            if new_aliases:
                existing_set = {a.lower() for a in (existing.aliases or [])}
                existing_set.add(existing.name.lower())
                merged = list(existing.aliases or [])
                for alias in new_aliases:
                    if alias.lower() not in existing_set:
                        merged.append(alias)
                        existing_set.add(alias.lower())
                if len(merged) != len(existing.aliases or []):
                    existing.aliases = merged
            if not existing.tool_type and tool_data.get("tool_type"):
                coerced, raw = coerce_tool_type(tool_data["tool_type"])
                existing.tool_type = coerced
                if raw:
                    existing.metadata_ = {**(existing.metadata_ or {}), "raw_tool_type": raw}
            if not existing.description and tool_data.get("description"):
                existing.description = tool_data["description"]
            if tool_data.get("detection_artifacts"):
                # Merge detection artifacts dict
                artifacts = dict(existing.detection_artifacts or {})
                artifacts.update(tool_data["detection_artifacts"])
                existing.detection_artifacts = artifacts
            tool_obj = existing
            is_new = False
        else:
            coerced, raw = coerce_tool_type(tool_data.get("tool_type"))
            tool_obj = Tool(
                name=name,
                aliases=await gate_aliases(db, "tool", name, tool_data.get("aliases")),
                description=tool_data.get("description"),
                tool_type=coerced,
                platforms=tool_data.get("platforms", []),
                malpedia_url=tool_data.get("malpedia_url"),
                github_url=tool_data.get("github_url"),
                detection_artifacts=tool_data.get("detection_artifacts", {}),
                metadata_={"raw_tool_type": raw} if raw else {},
                created_via="ai_extraction",
                created_from_entry_id=entry_id,
                created_confidence=tool_data.get("confidence"),
                needs_review=bool(decision.shadow_reason),
            )
            db.add(tool_obj)
            await db.flush()
            is_new = True

        await db.execute(
            pg_insert(EntryTool)
            .values(
                entry_id=entry_id,
                tool_id=tool_obj.id,
                confidence=tool_data.get("confidence"),
                source="ai",
                matched_names=[name] if name else None,
            )
            .on_conflict_do_nothing()
        )

        stored.append((tool_obj, is_new))

    if dropped_no_evidence:
        logger.info(
            "Tool evidence gate dropped %d of %d candidates for entry %s",
            dropped_no_evidence,
            len(tools_data),
            entry_id,
        )

    await db.flush()

    # Refresh auto-linker vocabulary for newly created tools
    if any(is_new for _, is_new in stored):
        try:
            from app.workers.intel_feed_tasks import refresh_autolinker_vocabulary

            refresh_autolinker_vocabulary.delay()
        except Exception:
            pass

    return stored
