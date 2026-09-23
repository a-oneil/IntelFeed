"""Workspace tools — detection-rule lifecycle, intel reports, requirements (16 tools).

Mirrors the detection-rules section of app/api/intelligence.py plus
app/api/intel_reports.py and app/api/requirements.py.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.models.detection_rule import DetectionRule
from app.models.detection_rule_version import DetectionRuleVersion
from app.models.entry import Entry
from app.models.intel_report import IntelReport, IntelReportVersion
from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch
from app.schemas.intelligence import RULE_TYPE_PATTERN
from app.schemas.tlp import TLP_VALUES, normalize_tlp
from app.tools import _tool
from app.tools.delete import _make_token, _verify_token

# Detection rule formats — derived from the API's validation pattern.
_RULE_TYPES = sorted(RULE_TYPE_PATTERN.removeprefix("^(").removesuffix(")$").split("|"))

# Report lifecycle states — mirrors IntelReportUpdate's status pattern and the model comment.
_REPORT_STATUSES = ["draft", "published", "archived"]

# Fields the PUT /detection-rules/{id} router applies (DetectionRuleUpdate schema).
_RULE_UPDATE_FIELDS = {
    "title",
    "description",
    "rule_content",
    "rule_type",
    "severity",
    "tags",
    "is_draft",
    "log_sources",
    "mitre_tactics",
    "data_sources",
    "notes",
    "source_ttps",
    "source_entries",
    "source_actors",
    "source_campaigns",
    "change_description",
    "metadata",
}

# Fields the PUT /intel-reports/{id} router applies (IntelReportUpdate schema).
_REPORT_UPDATE_FIELDS = {
    "title",
    "tlp_marking",
    "status",
    "content",
    "summary",
    "entry_ids",
    "entity_ids",
    "tags",
    "change_description",
}


def _serialize_rule(rule: DetectionRule, include_content: bool = True) -> dict:
    data = {
        "id": str(rule.id),
        "title": rule.title,
        "rule_type": rule.rule_type,
        "severity": rule.severity,
        "description": rule.description,
        "status": "draft" if rule.is_draft else "published",
        "is_draft": rule.is_draft,
        "tags": rule.tags or [],
        "mitre_tactics": rule.mitre_tactics or [],
        "data_sources": rule.data_sources or [],
        "log_sources": rule.log_sources,
        "notes": rule.notes,
        "source_ttps": rule.source_ttps or [],
        "source_cves": rule.source_cves or [],
        "source_entries": [str(e) for e in (rule.source_entries or [])],
        "source_actors": [str(a) for a in (rule.source_actors or [])],
        "source_campaigns": [str(c) for c in (rule.source_campaigns or [])],
        "entry_id": str(rule.entry_id) if rule.entry_id else None,
        # Provenance
        "references": rule.references or [],
        "license": rule.license,
        "source_repo": rule.source_repo,
        "source_author": rule.source_author,
        "is_authored_local": rule.is_authored_local,
        "upstream_updated_at": str(rule.upstream_updated_at) if rule.upstream_updated_at else None,
        "created_at": str(rule.created_at),
        "updated_at": str(rule.updated_at),
    }
    if include_content:
        data["rule_content"] = rule.rule_content
    return data


def _serialize_report(report: IntelReport, include_content: bool = True) -> dict:
    data = {
        "id": str(report.id),
        "title": report.title,
        "template_type": report.template_type,
        "tlp_marking": report.tlp_marking,
        "status": report.status,
        "version": report.version,
        "summary": report.summary,
        "tags": report.tags or [],
        "entry_ids": [str(e) for e in (report.entry_ids or [])],
        "entity_ids": report.entity_ids or {},
        "created_at": str(report.created_at),
        "updated_at": str(report.updated_at),
        "published_at": str(report.published_at) if report.published_at else None,
    }
    if include_content:
        data["content"] = report.content or {}
    else:
        data["sections"] = sorted((report.content or {}).get("sections", {}).keys())
    return data


def _serialize_requirement(req: IntelligenceRequirement) -> dict:
    return {
        "id": str(req.id),
        "title": req.title,
        "description": req.description,
        "priority": req.priority,
        "status": req.status,
        "category": req.category,
        "keywords": req.keywords or [],
        "auto_match": req.auto_match,
        "match_count": req.match_count,
        "last_matched_at": str(req.last_matched_at) if req.last_matched_at else None,
        "fulfilled_by_report_id": str(req.fulfilled_by_report_id) if req.fulfilled_by_report_id else None,
    }


async def _get_rule(db: AsyncSession, rule_id: str) -> DetectionRule | None:
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == uuid.UUID(rule_id)))
    return result.scalar_one_or_none()


async def _snapshot_rule_version(
    db: AsyncSession, rule: DetectionRule, user_id: uuid.UUID, change_description: str | None
) -> int:
    """Snapshot the rule's current content as the next version; returns the new version number."""
    ver_result = await db.execute(
        select(func.coalesce(func.max(DetectionRuleVersion.version_number), 0)).where(
            DetectionRuleVersion.rule_id == rule.id
        )
    )
    next_ver = (ver_result.scalar() or 0) + 1
    db.add(
        DetectionRuleVersion(
            rule_id=rule.id,
            version_number=next_ver,
            rule_content=rule.rule_content,
            rule_type=rule.rule_type,
            change_description=change_description,
            changed_by=user_id,
        )
    )
    return next_ver


# ---------------------------------------------------------------------------
# Detection rule lifecycle
# ---------------------------------------------------------------------------


@_tool(
    name="get_detection_rule",
    description=(
        "Get a single detection rule with full rule content, provenance (source repo/author/license/"
        "references), draft/published status, telemetry feasibility against the enabled Telemetry "
        "Sources inventory, and a syntax-validation summary."
    ),
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "Detection rule UUID"},
        },
        "required": ["rule_id"],
    },
    mutating=False,
)
async def _get_detection_rule(db: AsyncSession, user_id: uuid.UUID, rule_id: str) -> dict:
    rule = await _get_rule(db, rule_id)
    if not rule:
        return {"error": "Detection rule not found"}

    from app.intelligence.rule_validation import validate_rule
    from app.services.detection_coverage import get_available_telemetry, rule_telemetry_coverage

    data = _serialize_rule(rule)
    data["telemetry"] = rule_telemetry_coverage(rule, await get_available_telemetry(db))
    vr = validate_rule(rule.rule_type, rule.rule_content)
    data["validation"] = {
        "valid": vr.valid,
        "errors": [{"line": e.line, "severity": e.severity, "message": e.message} for e in vr.errors],
        "suggestions": vr.suggestions,
    }
    return data


@_tool(
    name="update_detection_rule",
    description=(
        "Update fields of a detection rule. Updatable keys: title, description, rule_content, rule_type "
        f"({', '.join(_RULE_TYPES)}), severity, tags, is_draft, log_sources, mitre_tactics, data_sources, "
        "notes, source_ttps, source_entries, source_actors, source_campaigns, metadata, change_description. "
        "Changing rule_content snapshots the previous content as a new version; content or type changes "
        "re-extract rule metadata into unset fields (same as the API PUT)."
    ),
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "Detection rule UUID"},
            "updates": {
                "type": "object",
                "description": "Fields to change. Unknown keys are rejected. UUID-list fields take string UUIDs.",
            },
        },
        "required": ["rule_id", "updates"],
    },
    mutating=True,
)
async def _update_detection_rule(db: AsyncSession, user_id: uuid.UUID, rule_id: str, updates: dict) -> dict:
    rule = await _get_rule(db, rule_id)
    if not rule:
        return {"error": "Detection rule not found"}

    unknown = set(updates) - _RULE_UPDATE_FIELDS
    if unknown:
        return {"error": f"Unknown fields: {sorted(unknown)}; updatable: {sorted(_RULE_UPDATE_FIELDS)}"}
    new_type = updates.get("rule_type")
    if new_type is not None and new_type not in _RULE_TYPES:
        return {"error": f"invalid rule_type '{new_type}'; valid: {_RULE_TYPES}"}
    if "rule_content" in updates and not (updates["rule_content"] or "").strip():
        return {"error": "rule_content cannot be empty"}

    content_changed = updates.get("rule_content") is not None and updates["rule_content"] != rule.rule_content
    type_changed = new_type is not None and new_type != rule.rule_type

    snapshot_version = None
    if content_changed:
        snapshot_version = await _snapshot_rule_version(db, rule, user_id, updates.get("change_description"))
        rule.rule_content = updates["rule_content"]

    changed: list[str] = ["rule_content"] if content_changed else []
    for field in (
        "title",
        "description",
        "rule_type",
        "severity",
        "tags",
        "is_draft",
        "log_sources",
        "mitre_tactics",
        "data_sources",
        "notes",
        "source_ttps",
    ):
        if updates.get(field) is not None:
            setattr(rule, field, updates[field])
            changed.append(field)
    for field in ("source_entries", "source_actors", "source_campaigns"):
        if updates.get(field) is not None:
            setattr(rule, field, [uuid.UUID(str(v)) for v in updates[field]])
            changed.append(field)

    if content_changed or type_changed or updates.get("metadata") is not None:
        from app.intelligence.rule_metadata import extract_and_apply

        if updates.get("metadata") is not None:
            rule.metadata_ = updates["metadata"]
            changed.append("metadata")
        explicit_fields = {k for k, v in updates.items() if v is not None}
        extract_and_apply(rule, explicit_fields)

    db.add(rule)
    await db.flush()
    result = {"updated": True, "rule_id": rule_id, "fields_updated": changed}
    if snapshot_version is not None:
        result["previous_content_saved_as_version"] = snapshot_version
    return result


@_tool(
    name="delete_detection_rule",
    description=(
        "Delete a detection rule permanently; its version history is removed with it. REQUIRES user "
        "confirmation: the first call returns a confirmation prompt and token — present it to the user "
        "and only call again with confirmation_token after they explicitly approve."
    ),
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "Detection rule UUID"},
            "confirmation_token": {
                "type": "string",
                "description": "Token from a previous call. Only provide after the user confirms.",
            },
        },
        "required": ["rule_id"],
    },
    mutating=True,
)
async def _delete_detection_rule(
    db: AsyncSession, user_id: uuid.UUID, rule_id: str, confirmation_token: str | None = None
) -> dict:
    rule = await _get_rule(db, rule_id)
    if not rule:
        return {"error": "Detection rule not found"}

    if not confirmation_token:
        return {
            "status": "confirmation_required",
            "message": "Are you sure you want to delete this detection rule?",
            "rule_id": rule_id,
            "rule_title": rule.title,
            "rule_type": rule.rule_type,
            "confirmation_token": _make_token("detection_rule", rule_id, user_id),
            "warning": "This action is permanent. The rule and its full version history will be deleted.",
        }
    if not _verify_token(confirmation_token, "detection_rule", rule_id, user_id):
        return {"error": "Invalid or expired confirmation token. Please request a new confirmation."}

    title = rule.title
    await db.delete(rule)
    await db.flush()
    return {"status": "deleted", "rule_id": rule_id, "message": f"Detection rule '{title}' has been deleted."}


@_tool(
    name="set_detection_rule_status",
    description=(
        "Set a detection rule's lifecycle status: 'draft' or 'published' (mirrors the API's is_draft "
        "toggle — detection rules have no other states)."
    ),
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "Detection rule UUID"},
            "status": {"type": "string", "enum": ["draft", "published"]},
        },
        "required": ["rule_id", "status"],
    },
    mutating=True,
)
async def _set_detection_rule_status(db: AsyncSession, user_id: uuid.UUID, rule_id: str, status: str) -> dict:
    rule = await _get_rule(db, rule_id)
    if not rule:
        return {"error": "Detection rule not found"}
    rule.is_draft = status == "draft"
    db.add(rule)
    await db.flush()
    return {"updated": True, "rule_id": rule_id, "status": status, "is_draft": rule.is_draft}


@_tool(
    name="convert_detection_rule",
    description=(
        "Convert a detection rule to a different rule language using the AI provider assigned to the "
        f"detection_rules task. Target formats: {', '.join(_RULE_TYPES)}. Returns the converted content "
        "without changing the source rule. With save=true, the conversion is stored on the rule's "
        "metadata under rule_conversions (same place the UI keeps saved conversions)."
    ),
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "Source detection rule UUID"},
            "target_format": {"type": "string", "enum": _RULE_TYPES},
            "save": {
                "type": "boolean",
                "default": False,
                "description": "Persist the conversion on the rule's metadata (rule_conversions).",
            },
        },
        "required": ["rule_id", "target_format"],
    },
    mutating=True,
)
async def _convert_detection_rule(
    db: AsyncSession, user_id: uuid.UUID, rule_id: str, target_format: str, save: bool = False
) -> dict:
    from app.ai.engine import _estimate_cost, _get_provider_instance, get_task_assignment
    from app.api.intelligence import RULE_TYPE_LABELS

    rule = await _get_rule(db, rule_id)
    if not rule:
        return {"error": "Detection rule not found"}
    if rule.rule_type == target_format:
        return {"error": "Source and target rule types are the same"}

    assignment_data = await get_task_assignment(db, user_id, "detection_rules")
    if not assignment_data:
        return {"error": "No AI provider assigned for detection rules. Configure one in Settings > AI."}
    assignment, task, provider_model = assignment_data
    provider = _get_provider_instance(provider_model)

    source_label = RULE_TYPE_LABELS.get(rule.rule_type, rule.rule_type)
    target_label = RULE_TYPE_LABELS.get(target_format, target_format)

    prompt = f"""Convert the following {source_label} detection rule to {target_label} format.

SOURCE RULE ({source_label}):
```
{rule.rule_content}
```

RULE CONTEXT:
- Title: {rule.title}
- Description: {rule.description or "N/A"}
- Severity: {rule.severity or "N/A"}
- MITRE Tactics: {", ".join(rule.mitre_tactics) if rule.mitre_tactics else "N/A"}
- Data Sources: {", ".join(rule.data_sources) if rule.data_sources else "N/A"}

CONVERSION INSTRUCTIONS:
1. Produce a complete, syntactically valid {target_label} rule — not pseudocode
2. Map field names correctly between formats (SIGMA 'Image' → Splunk 'process_name' → Elastic 'process.executable')
3. Translate log source references to the target platform's conventions
4. Preserve the detection logic, severity, and MITRE ATT&CK mappings
5. If certain features cannot be directly translated, add a comment explaining the limitation
6. Include appropriate metadata/headers for the target format

Return ONLY the converted rule content — no explanation, no markdown fences, just the raw rule text."""

    config = {**provider_model.config, **assignment.config}
    system_prompt = "You are an expert detection engineer. Convert detection rules between formats with perfect syntax."
    try:
        response = await provider.complete(
            prompt=prompt,
            system=system_prompt,
            temperature=config.get("temperature", 0.1),
            max_tokens=config.get("max_tokens", 4096),
            model=assignment.model_name,
        )
    except Exception as e:  # provider/network failure is user-visible, not a crash
        return {"error": f"AI conversion failed: {e}"}

    converted_content = response.content.strip()
    if converted_content.startswith("```"):
        lines = converted_content.split("\n")[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        converted_content = "\n".join(lines)

    cost = _estimate_cost(response.model, response.tokens_input, response.tokens_output)
    result = {
        "converted_content": converted_content,
        "source_type": rule.rule_type,
        "target_type": target_format,
        "model": response.model,
        "tokens_used": response.tokens_input + response.tokens_output,
        "cost": float(cost),
        "saved": False,
    }

    if save:
        meta = dict(rule.metadata_ or {})
        conversions = dict(meta.get("rule_conversions") or {})
        conversions[target_format] = {
            "content": converted_content,
            "converted_at": datetime.now(UTC).isoformat(),
            "model": response.model,
            "tokens_used": response.tokens_input + response.tokens_output,
            "cost": float(cost),
        }
        meta["rule_conversions"] = conversions
        rule.metadata_ = meta
        flag_modified(rule, "metadata_")
        db.add(rule)
        await db.flush()
        result["saved"] = True
    return result


@_tool(
    name="get_detection_rule_versions",
    description=(
        "List a detection rule's saved versions, newest first. Versions are snapshots taken whenever "
        "rule_content changed or a rollback occurred."
    ),
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "Detection rule UUID"},
        },
        "required": ["rule_id"],
    },
    mutating=False,
)
async def _get_detection_rule_versions(db: AsyncSession, user_id: uuid.UUID, rule_id: str) -> dict:
    rule = await _get_rule(db, rule_id)
    if not rule:
        return {"error": "Detection rule not found"}
    result = await db.execute(
        select(DetectionRuleVersion)
        .where(DetectionRuleVersion.rule_id == rule.id)
        .order_by(DetectionRuleVersion.version_number.desc())
    )
    return {
        "rule_id": rule_id,
        "current_rule_type": rule.rule_type,
        "versions": [
            {
                "id": str(v.id),
                "version_number": v.version_number,
                "rule_type": v.rule_type,
                "change_description": v.change_description,
                "created_at": str(v.created_at),
                "rule_content": v.rule_content,
            }
            for v in result.scalars().all()
        ],
    }


@_tool(
    name="rollback_detection_rule",
    description=(
        "Restore a detection rule's content (and type) from a saved version, identified by its version "
        "number (see get_detection_rule_versions). The current content is snapshotted as a new version "
        "first, so a rollback is itself reversible."
    ),
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "Detection rule UUID"},
            "version": {"type": "integer", "description": "Version number to restore"},
        },
        "required": ["rule_id", "version"],
    },
    mutating=True,
)
async def _rollback_detection_rule(db: AsyncSession, user_id: uuid.UUID, rule_id: str, version: int) -> dict:
    rule = await _get_rule(db, rule_id)
    if not rule:
        return {"error": "Detection rule not found"}
    ver_result = await db.execute(
        select(DetectionRuleVersion).where(
            DetectionRuleVersion.rule_id == rule.id,
            DetectionRuleVersion.version_number == version,
        )
    )
    target_version = ver_result.scalar_one_or_none()
    if not target_version:
        return {"error": f"Version {version} not found"}

    snapshot_number = await _snapshot_rule_version(
        db, rule, user_id, f"Snapshot before rollback to v{target_version.version_number}"
    )
    rule.rule_content = target_version.rule_content
    if target_version.rule_type:
        rule.rule_type = target_version.rule_type
    db.add(rule)
    await db.flush()
    return {
        "rolled_back": True,
        "rule_id": rule_id,
        "restored_version": version,
        "previous_content_saved_as_version": snapshot_number,
        "rule_type": rule.rule_type,
    }


# ---------------------------------------------------------------------------
# Intel reports
# ---------------------------------------------------------------------------


@_tool(
    name="list_intel_reports",
    description=(
        "List intel reports, newest-updated first, optionally filtered by status "
        f"({', '.join(_REPORT_STATUSES)}) or template_type slug. Rows are lightweight — section names "
        "only, no section content (use get_intel_report for the full report)."
    ),
    input_schema={
        "properties": {
            "status": {"type": "string", "enum": _REPORT_STATUSES},
            "template_type": {"type": "string", "description": "Filter by template slug (e.g. flash_alert)"},
            "limit": {"type": "integer", "default": 25},
            "offset": {"type": "integer", "default": 0},
        },
    },
    mutating=False,
)
async def _list_intel_reports(
    db: AsyncSession,
    user_id: uuid.UUID,
    status: str | None = None,
    template_type: str | None = None,
    limit: int = 25,
    offset: int = 0,
) -> dict:
    limit = max(1, min(limit, 100))
    base = select(IntelReport)
    count_q = select(func.count()).select_from(IntelReport)
    if status:
        base = base.where(IntelReport.status == status)
        count_q = count_q.where(IntelReport.status == status)
    if template_type:
        base = base.where(IntelReport.template_type == template_type)
        count_q = count_q.where(IntelReport.template_type == template_type)

    total = (await db.execute(count_q)).scalar() or 0
    result = await db.execute(base.order_by(IntelReport.updated_at.desc()).limit(limit).offset(max(0, offset)))
    reports = result.scalars().all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "reports": [_serialize_report(r, include_content=False) for r in reports],
    }


@_tool(
    name="get_intel_report",
    description="Get a single intel report including its full content (all sections, metadata, references).",
    input_schema={
        "properties": {
            "report_id": {"type": "string", "description": "Intel report UUID"},
        },
        "required": ["report_id"],
    },
    mutating=False,
)
async def _get_intel_report(db: AsyncSession, user_id: uuid.UUID, report_id: str) -> dict:
    report = await db.get(IntelReport, uuid.UUID(report_id))
    if not report:
        return {"error": "Report not found"}
    return _serialize_report(report)


@_tool(
    name="update_intel_report",
    description=(
        "Update fields of an intel report. Updatable keys: title, tlp_marking (TLP 2.0; legacy TLP:WHITE "
        f"is normalized to TLP:CLEAR), status ({', '.join(_REPORT_STATUSES)}), content (full content dict "
        "including sections), summary, entry_ids, entity_ids, tags, change_description. Changing content "
        "snapshots the previous content as a version and increments the version number; setting status "
        "to published stamps published_at."
    ),
    input_schema={
        "properties": {
            "report_id": {"type": "string", "description": "Intel report UUID"},
            "updates": {
                "type": "object",
                "description": "Fields to change. Unknown keys are rejected. entry_ids take string UUIDs.",
            },
        },
        "required": ["report_id", "updates"],
    },
    mutating=True,
)
async def _update_intel_report(db: AsyncSession, user_id: uuid.UUID, report_id: str, updates: dict) -> dict:
    report = await db.get(IntelReport, uuid.UUID(report_id))
    if not report:
        return {"error": "Report not found"}

    unknown = set(updates) - _REPORT_UPDATE_FIELDS
    if unknown:
        return {"error": f"Unknown fields: {sorted(unknown)}; updatable: {sorted(_REPORT_UPDATE_FIELDS)}"}
    if updates.get("status") is not None and updates["status"] not in _REPORT_STATUSES:
        return {"error": f"invalid status '{updates['status']}'; valid: {_REPORT_STATUSES}"}
    if updates.get("tlp_marking") is not None:
        tlp = normalize_tlp(updates["tlp_marking"])
        if tlp not in TLP_VALUES:
            return {"error": f"invalid tlp_marking '{updates['tlp_marking']}'; valid: {list(TLP_VALUES)}"}
        updates = {**updates, "tlp_marking": tlp}

    changed: list[str] = []
    new_version = None
    if updates.get("content") is not None and updates["content"] != report.content:
        db.add(
            IntelReportVersion(
                report_id=report.id,
                version=report.version,
                content=report.content,
                change_description=updates.get("change_description"),
                created_by=user_id,
            )
        )
        report.version += 1
        new_version = report.version

    if updates.get("status") == "published" and report.status != "published":
        report.published_at = datetime.now(UTC)

    for field in ("title", "tlp_marking", "status", "content", "summary", "entity_ids", "tags"):
        if updates.get(field) is not None:
            setattr(report, field, updates[field])
            if field in ("content", "entity_ids"):
                flag_modified(report, field)
            changed.append(field)
    if updates.get("entry_ids") is not None:
        report.entry_ids = [uuid.UUID(str(e)) for e in updates["entry_ids"]]
        changed.append("entry_ids")

    db.add(report)
    await db.flush()
    result = {"updated": True, "report_id": report_id, "fields_updated": changed, "status": report.status}
    if new_version is not None:
        result["version"] = new_version
    return result


@_tool(
    name="delete_intel_report",
    description=(
        "Delete a draft intel report permanently (published or archived reports cannot be deleted — "
        "archive instead). REQUIRES user confirmation: the first call returns a confirmation prompt and "
        "token — present it to the user and only call again with confirmation_token after they "
        "explicitly approve."
    ),
    input_schema={
        "properties": {
            "report_id": {"type": "string", "description": "Intel report UUID"},
            "confirmation_token": {
                "type": "string",
                "description": "Token from a previous call. Only provide after the user confirms.",
            },
        },
        "required": ["report_id"],
    },
    mutating=True,
)
async def _delete_intel_report(
    db: AsyncSession, user_id: uuid.UUID, report_id: str, confirmation_token: str | None = None
) -> dict:
    report = await db.get(IntelReport, uuid.UUID(report_id))
    if not report:
        return {"error": "Report not found"}
    if report.status != "draft":
        return {"error": f"Only draft reports can be deleted (this report is {report.status})"}

    if not confirmation_token:
        return {
            "status": "confirmation_required",
            "message": "Are you sure you want to delete this intel report?",
            "report_id": report_id,
            "report_title": report.title,
            "confirmation_token": _make_token("intel_report", report_id, user_id),
            "warning": "This action is permanent. The report and its version history will be deleted.",
        }
    if not _verify_token(confirmation_token, "intel_report", report_id, user_id):
        return {"error": "Invalid or expired confirmation token. Please request a new confirmation."}

    title = report.title
    await db.delete(report)
    await db.flush()
    return {"status": "deleted", "report_id": report_id, "message": f"Intel report '{title}' has been deleted."}


@_tool(
    name="archive_intel_report",
    description="Archive an intel report (status becomes 'archived'; the report is retained, not deleted).",
    input_schema={
        "properties": {
            "report_id": {"type": "string", "description": "Intel report UUID"},
        },
        "required": ["report_id"],
    },
    mutating=True,
)
async def _archive_intel_report(db: AsyncSession, user_id: uuid.UUID, report_id: str) -> dict:
    report = await db.get(IntelReport, uuid.UUID(report_id))
    if not report:
        return {"error": "Report not found"}
    if report.status == "archived":
        return {"error": "Report is already archived"}
    report.status = "archived"
    db.add(report)
    await db.flush()
    return {"archived": True, "report_id": report_id, "title": report.title}


# ---------------------------------------------------------------------------
# Intelligence requirements
# ---------------------------------------------------------------------------


@_tool(
    name="delete_requirement",
    description=(
        "Delete an intelligence requirement (PIR) permanently, along with its entry matches. REQUIRES "
        "user confirmation: the first call returns a confirmation prompt and token — present it to the "
        "user and only call again with confirmation_token after they explicitly approve."
    ),
    input_schema={
        "properties": {
            "requirement_id": {"type": "string", "description": "Intelligence requirement UUID"},
            "confirmation_token": {
                "type": "string",
                "description": "Token from a previous call. Only provide after the user confirms.",
            },
        },
        "required": ["requirement_id"],
    },
    mutating=True,
)
async def _delete_requirement(
    db: AsyncSession, user_id: uuid.UUID, requirement_id: str, confirmation_token: str | None = None
) -> dict:
    from sqlalchemy.orm import selectinload

    result = await db.execute(
        select(IntelligenceRequirement)
        .where(IntelligenceRequirement.id == uuid.UUID(requirement_id))
        .options(selectinload(IntelligenceRequirement.matches))
    )
    requirement = result.scalar_one_or_none()
    if not requirement:
        return {"error": "Requirement not found"}

    if not confirmation_token:
        return {
            "status": "confirmation_required",
            "message": "Are you sure you want to delete this intelligence requirement?",
            "requirement_id": requirement_id,
            "requirement_title": requirement.title,
            "match_count": requirement.match_count,
            "confirmation_token": _make_token("intelligence_requirement", requirement_id, user_id),
            "warning": "This action is permanent. The requirement and all its entry matches will be deleted.",
        }
    if not _verify_token(confirmation_token, "intelligence_requirement", requirement_id, user_id):
        return {"error": "Invalid or expired confirmation token. Please request a new confirmation."}

    title = requirement.title
    await db.delete(requirement)
    await db.flush()
    return {
        "status": "deleted",
        "requirement_id": requirement_id,
        "message": f"Requirement '{title}' has been deleted.",
    }


@_tool(
    name="fulfill_requirement",
    description=(
        "Mark an intelligence requirement fulfilled, optionally linking the intel report that fulfilled it (report_id)."
    ),
    input_schema={
        "properties": {
            "requirement_id": {"type": "string", "description": "Intelligence requirement UUID"},
            "report_id": {"type": "string", "description": "Optional UUID of the fulfilling intel report"},
        },
        "required": ["requirement_id"],
    },
    mutating=True,
)
async def _fulfill_requirement(
    db: AsyncSession, user_id: uuid.UUID, requirement_id: str, report_id: str | None = None
) -> dict:
    requirement = await db.get(IntelligenceRequirement, uuid.UUID(requirement_id))
    if not requirement:
        return {"error": "Requirement not found"}

    rid = None
    if report_id:
        rid = uuid.UUID(report_id)
        report = await db.get(IntelReport, rid)
        if not report:
            return {"error": "Report not found"}

    requirement.status = "fulfilled"
    requirement.fulfilled_by_report_id = rid
    db.add(requirement)
    await db.flush()
    await db.refresh(requirement)
    return {"fulfilled": True, **_serialize_requirement(requirement)}


@_tool(
    name="add_requirement_match",
    description=(
        "Manually match an entry to an intelligence requirement (match_type 'manual'). Increments the "
        "requirement's match count and stamps last_matched_at. Errors if the entry is already matched. "
        "Relevance: high, medium, or low."
    ),
    input_schema={
        "properties": {
            "requirement_id": {"type": "string", "description": "Intelligence requirement UUID"},
            "entry_id": {"type": "string", "description": "Entry UUID to match"},
            "relevance": {"type": "string", "enum": ["high", "medium", "low"], "default": "medium"},
        },
        "required": ["requirement_id", "entry_id"],
    },
    mutating=True,
)
async def _add_requirement_match(
    db: AsyncSession, user_id: uuid.UUID, requirement_id: str, entry_id: str, relevance: str = "medium"
) -> dict:
    requirement = await db.get(IntelligenceRequirement, uuid.UUID(requirement_id))
    if not requirement:
        return {"error": "Requirement not found"}
    entry = await db.get(Entry, uuid.UUID(entry_id))
    if not entry:
        return {"error": "Entry not found"}
    if relevance not in ("high", "medium", "low"):
        return {"error": f"invalid relevance '{relevance}'; valid: high, medium, low"}

    existing = await db.execute(
        select(RequirementMatch).where(
            RequirementMatch.requirement_id == requirement.id,
            RequirementMatch.entry_id == entry.id,
        )
    )
    if existing.scalar_one_or_none():
        return {"error": "Entry already matched to this requirement"}

    db.add(
        RequirementMatch(
            requirement_id=requirement.id,
            entry_id=entry.id,
            match_type="manual",
            matched_on="Manually matched by analyst",
            relevance=relevance,
        )
    )
    requirement.match_count += 1
    requirement.last_matched_at = datetime.now(UTC)
    await db.flush()
    return {
        "matched": True,
        "requirement_id": requirement_id,
        "entry_id": entry_id,
        "entry_title": entry.title,
        "match_count": requirement.match_count,
    }


@_tool(
    name="remove_requirement_match",
    description=(
        "Remove a matched entry from an intelligence requirement and decrement its match count. "
        "Reversible (the entry can be re-matched), so no confirmation is needed."
    ),
    input_schema={
        "properties": {
            "requirement_id": {"type": "string", "description": "Intelligence requirement UUID"},
            "entry_id": {"type": "string", "description": "Entry UUID of the match to remove"},
        },
        "required": ["requirement_id", "entry_id"],
    },
    mutating=True,
)
async def _remove_requirement_match(db: AsyncSession, user_id: uuid.UUID, requirement_id: str, entry_id: str) -> dict:
    requirement = await db.get(IntelligenceRequirement, uuid.UUID(requirement_id))
    if not requirement:
        return {"error": "Requirement not found"}
    result = await db.execute(
        select(RequirementMatch).where(
            RequirementMatch.requirement_id == requirement.id,
            RequirementMatch.entry_id == uuid.UUID(entry_id),
        )
    )
    match = result.scalar_one_or_none()
    if not match:
        return {"error": "Match not found"}

    if requirement.match_count > 0:
        requirement.match_count -= 1
    await db.delete(match)
    await db.flush()
    return {
        "removed": True,
        "requirement_id": requirement_id,
        "entry_id": entry_id,
        "match_count": requirement.match_count,
    }
