"""Delete tools with confirmation guardrails (1 tool).

The CLI cannot delete anything without explicit user approval.
On first call, the tool returns a confirmation prompt with a token.
The client must present this to the user and only call again with the
token after the user confirms.
"""

import hashlib
import time
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.tools import _tool

# Confirmation tokens expire after 5 minutes
_CONFIRMATION_TTL = 300


def _make_token(entity_type: str, entity_id: str, user_id: uuid.UUID) -> str:
    """Generate a short-lived confirmation token."""
    # Include a time bucket so tokens expire (~5 min granularity)
    bucket = int(time.time()) // _CONFIRMATION_TTL
    raw = f"{entity_type}:{entity_id}:{user_id}:{bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _verify_token(token: str, entity_type: str, entity_id: str, user_id: uuid.UUID) -> bool:
    """Verify a confirmation token (checks current and previous time bucket)."""
    for offset in (0, -1):
        bucket = int(time.time()) // _CONFIRMATION_TTL + offset
        raw = f"{entity_type}:{entity_id}:{user_id}:{bucket}"
        expected = hashlib.sha256(raw.encode()).hexdigest()[:16]
        if token == expected:
            return True
    return False


# Map of deletable entity types to (model_class_path, display_name, has_user_scope)
_DELETABLE_ENTITIES = {
    "feed": ("app.models.feed:Feed", "feed", False),
    "entry": ("app.models.entry:Entry", "entry", False),
    "note": ("app.models.note:Note", "note", False),
    "detection_rule": ("app.models.detection_rule:DetectionRule", "detection rule", False),
    "campaign": ("app.models.campaign:Campaign", "campaign", False),
    "automation_rule": ("app.models.automation_rule:AutomationRule", "automation rule", False),
    "intelligence_requirement": (
        "app.models.intelligence_requirement:IntelligenceRequirement",
        "intelligence requirement",
        False,
    ),
    "intel_report": ("app.models.intel_report:IntelReport", "intel report", False),
    "ttp": ("app.models.ttp:TTP", "TTP", False),
    "threat_actor": ("app.models.threat_actor:ThreatActor", "threat actor", False),
    "malware": ("app.models.malware_family:MalwareFamily", "malware family", False),
    "tag": ("app.models.tag:Tag", "tag", False),
    "cve": ("app.models.cve:CVE", "CVE", False),
    "country": ("app.models.country:Country", "country", False),
    "tool": ("app.models.tool:Tool", "tool", False),
    "vendor": ("app.models.vendor:Vendor", "vendor", False),
    "product": ("app.models.product:Product", "product", False),
    "mitigation": ("app.models.mitigation:Mitigation", "mitigation", False),
    "observable": ("app.models.observable:Observable", "observable", False),
}

# Intelligence entity types that need the canonical cleanup the API delete
# endpoints perform (entry junction rows, entity relationships, search doc).
_INTEL_ENTITY_TYPES = frozenset(
    {"threat_actor", "malware", "cve", "ttp", "country", "tool", "vendor", "product", "mitigation", "observable"}
)


async def _cleanup_intel_entity(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> None:
    """Mirror the canonical API delete path (app/api/entity_profiles.py) for an
    intelligence entity: remove entry junction rows and entity relationships
    before the row itself goes; the search doc and cache are handled after."""
    from sqlalchemy import delete as sa_delete

    from app.api.entity_profiles import ENTITY_MODEL_MAP, _delete_entity_relationships

    if entity_type == "mitigation":
        from app.models.mitigation import EntryMitigation, TTPMitigation

        await db.execute(sa_delete(EntryMitigation).where(EntryMitigation.mitigation_id == entity_id))
        await db.execute(sa_delete(TTPMitigation).where(TTPMitigation.mitigation_id == entity_id))
    else:
        _, junction, fk_attr = ENTITY_MODEL_MAP[entity_type]
        await db.execute(sa_delete(junction).where(getattr(junction, fk_attr) == entity_id))
    await _delete_entity_relationships(db, entity_type, entity_id)


def _load_model(model_path: str):
    """Dynamically import a model class from 'module:Class' path."""
    module_path, class_name = model_path.split(":")
    import importlib

    mod = importlib.import_module(module_path)
    return getattr(mod, class_name)


@_tool(
    name="delete_entity",
    description=(
        "Delete a record: feed, entry, note, detection rule, campaign, automation rule, "
        "intelligence requirement, intel report, tag, or any intelligence entity (threat actor, "
        "malware, CVE, TTP, country, tool, vendor, product, mitigation, observable), by id or, for an "
        "intelligence entity, by name. Intelligence entities get "
        "the same cleanup as the API delete endpoints: entry links, entity relationships and pending Review "
        "proposals are removed and the search-index document is dropped. No tombstone is written — the autolinker/"
        "extraction pipeline may re-create the entity from future articles; use the false-positive "
        "workflow if the name must stay gone (an observable's equivalent is the never-capture tombstone). "
        "REQUIRES user confirmation. First call returns a "
        "confirmation prompt — present it to the user. Only call again with the confirmation_token "
        "after the user explicitly approves."
    ),
    input_schema={
        "properties": {
            "entity_type": {
                "type": "string",
                "enum": list(_DELETABLE_ENTITIES.keys()),
                "description": "Type of entity to delete",
            },
            "entity_id": {
                "type": "string",
                "description": "UUID of the entity to delete",
            },
            "name": {
                "type": "string",
                "description": "Instead of entity_id, for an intelligence entity: its name (or unique alias; "
                "a CVE id, ATT&CK technique id or observable value)",
            },
            "confirmation_token": {
                "type": "string",
                "description": "Confirmation token from a previous call. Only provide after user confirms.",
            },
        },
        "required": ["entity_type"],
    },
)
async def _delete_entity(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_id: str | None = None,
    name: str | None = None,
    confirmation_token: str | None = None,
) -> dict:
    if entity_type not in _DELETABLE_ENTITIES:
        return {"error": f"Cannot delete entity type: {entity_type}"}
    if not entity_id:
        if not name or entity_type not in _INTEL_ENTITY_TYPES or entity_type == "mitigation":
            return {"error": "give entity_id (name lookup covers intelligence entities except mitigations)"}
        from app.tools.write import resolve_entity_ref

        found, err = await resolve_entity_ref(db, entity_type, name)
        if err:
            return err
        entity_id = str(found.id)

    model_path, display_name, has_user_scope = _DELETABLE_ENTITIES[entity_type]
    Model = _load_model(model_path)
    eid = uuid.UUID(entity_id)

    # Look up the entity first (for both confirm and execute paths)
    query = select(Model).where(Model.id == eid)
    if has_user_scope:
        query = query.where(Model.user_id == user_id)
    result = await db.execute(query)
    entity = result.scalar_one_or_none()

    if not entity:
        return {"error": f"{display_name.title()} not found (id: {entity_id})"}

    # Build a human-readable description of what will be deleted
    entity_label = (
        getattr(entity, "title", None)
        or getattr(entity, "name", None)
        or getattr(entity, "technique_name", None)  # TTPs
        or getattr(entity, "cve_id", None)  # CVEs
        or getattr(entity, "value", None)
        or str(eid)
    )

    # --- Phase 1: No token → return confirmation prompt ---
    if not confirmation_token:
        token = _make_token(entity_type, entity_id, user_id)
        return {
            "status": "confirmation_required",
            "message": f"Are you sure you want to delete this {display_name}?",
            "entity_type": entity_type,
            "entity_id": entity_id,
            "entity_label": str(entity_label),
            "confirmation_token": token,
            "warning": "This action is permanent and cannot be undone. Related data may also be deleted via cascade.",
        }

    # --- Phase 2: Token provided → verify and execute ---
    if not _verify_token(confirmation_token, entity_type, entity_id, user_id):
        return {"error": "Invalid or expired confirmation token. Please request a new confirmation."}

    if entity_type in _INTEL_ENTITY_TYPES:
        await _cleanup_intel_entity(db, entity_type, eid)

    tagged_entries: list = []
    if entity_type == "tag":
        # Deleting a tag definition cascades everyone's assignments of it; the
        # search index must drop the name too, as the API's DELETE /tags does.
        from app.models.tag import EntryTag

        rows = await db.execute(select(EntryTag.entry_id).where(EntryTag.tag_id == eid))
        tagged_entries = [r[0] for r in rows.all()]

    await db.delete(entity)
    await db.flush()

    if tagged_entries:
        from app.services.entry_tags import sync_entry_tags_to_search

        await sync_entry_tags_to_search(db, tagged_entries)

    if entity_type in _INTEL_ENTITY_TYPES:
        from app.intelligence.correlation_cache import invalidate_entity_cache
        from app.services.entity_indexer import delete_entity_document
        from app.services.proposal_dismissals import settle_gone_entity

        await settle_gone_entity(db, entity_type, eid, gone=True)
        delete_entity_document(entity_type, eid)
        await invalidate_entity_cache(entity_type, entity_id)

    return {
        "status": "deleted",
        "entity_type": entity_type,
        "entity_id": entity_id,
        "entity_label": str(entity_label),
        "message": f"{display_name.title()} '{entity_label}' has been deleted.",
    }
