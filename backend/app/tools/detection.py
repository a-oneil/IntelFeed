"""Detection Engineering tools."""

import re
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.detection import RULE_TYPE_ABBREV
from app.models.entry import Entry
from app.models.ttp import TTP
from app.schemas.intelligence import RULE_TYPE_PATTERN
from app.tools import _tool
from app.tools.extraction import _entry_to_dict

#: Formats rule *generation* supports (the detection_rules AI task).
GENERATABLE_RULE_TYPES = sorted(RULE_TYPE_ABBREV)

#: All formats rule *validation* supports — derived from the canonical rule-type pattern.
VALIDATABLE_RULE_TYPES = sorted(re.sub(r"[\^\$\(\)]", "", RULE_TYPE_PATTERN).split("|"))


@_tool(
    name="generate_detection_rules",
    description=(
        "Generate detection rules from an entry's TTPs via the detection_rules AI task and store them as drafts. "
        f"Supported formats: {', '.join(GENERATABLE_RULE_TYPES)}."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID to generate rules from"},
            "rule_types": {
                "type": "array",
                "items": {"type": "string", "enum": GENERATABLE_RULE_TYPES},
                "description": "Which rule formats to generate",
            },
        },
        "required": ["entry_id", "rule_types"],
    },
    # Persists (stored links / AI results / draft rules): a write, whatever it reads.
    mutating=True,
)
async def _generate_detection_rules(db: AsyncSession, user_id: uuid.UUID, entry_id: str, rule_types: list[str]) -> dict:
    from app.intelligence.detection import generate_detection_rules
    from app.models.ttp import EntryTTP

    eid = uuid.UUID(entry_id)
    result = await db.execute(select(Entry).where(Entry.id == eid))
    entry = result.scalar_one_or_none()
    if not entry:
        return {"error": "Entry not found"}

    ttps_q = await db.execute(select(TTP).join(EntryTTP).where(EntryTTP.entry_id == eid))
    ttps = [{"technique_id": t.technique_id, "technique_name": t.technique_name} for t in ttps_q.scalars()]

    rules = await generate_detection_rules(db, user_id, eid, _entry_to_dict(entry), ttps, rule_types)
    return {
        "rules_generated": len(rules),
        "rules": [
            {"id": str(r.id), "title": r.title, "rule_type": r.rule_type, "rule_content": r.rule_content} for r in rules
        ],
    }


@_tool(
    name="validate_detection_rule",
    description=(
        "Validate detection rule syntax. Returns validation errors, warnings, and suggestions. "
        f"Supported formats: {', '.join(VALIDATABLE_RULE_TYPES)}."
    ),
    input_schema={
        "properties": {
            "rule_type": {"type": "string", "enum": VALIDATABLE_RULE_TYPES},
            "rule_content": {"type": "string", "description": "The rule content to validate"},
        },
        "required": ["rule_type", "rule_content"],
    },
)
async def _validate_detection_rule(db: AsyncSession, user_id: uuid.UUID, rule_type: str, rule_content: str) -> dict:
    from app.intelligence.rule_validation import validate_rule

    vr = validate_rule(rule_type, rule_content)
    return {
        "valid": vr.valid,
        "errors": [
            {"line": e.line, "column": e.column, "severity": e.severity, "message": e.message} for e in vr.errors
        ],
        "suggestions": vr.suggestions,
    }


@_tool(
    name="build_detection_summary",
    description=(
        "Full detection engineering analysis: gathers all intelligence context for entries and produces "
        "comprehensive attack chain analysis and detection gaps. Optional focus steers the analysis angle; "
        "include_existing controls whether existing detection rules are folded into the context."
    ),
    input_schema={
        "properties": {
            "entry_ids": {"type": "array", "items": {"type": "string"}, "description": "Entry UUIDs to analyze"},
            "rule_formats": {
                "type": "array",
                "items": {"type": "string", "enum": GENERATABLE_RULE_TYPES},
                "description": "Rule formats to include in the summary",
            },
            "focus": {
                "type": "string",
                # keep in sync with the focus Field pattern in app/schemas/intelligence.py
                "enum": ["campaign", "vulnerability", "malware", "actor"],
                "default": "campaign",
                "description": "Analysis angle for the summary",
            },
            "include_existing": {
                "type": "boolean",
                "default": True,
                "description": "Include existing detection rules for the entries' TTPs in the analysis context",
            },
        },
        "required": ["entry_ids", "rule_formats"],
    },
)
async def _build_detection_summary(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_ids: list[str],
    rule_formats: list[str],
    focus: str = "campaign",
    include_existing: bool = True,
) -> dict:
    from app.intelligence.detection_summary import build_detection_summary

    eids = [uuid.UUID(eid) for eid in entry_ids]
    result = await build_detection_summary(
        db, user_id, eids, rule_formats, focus=focus, include_existing=include_existing
    )
    if result is None:
        return {"error": "No entries found or AI task not configured"}
    return result
