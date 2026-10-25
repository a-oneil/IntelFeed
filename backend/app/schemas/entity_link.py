"""Schemas for the Autolinking admin surface (Settings → Engine → Autolinking).

These describe entry→entity *autolinks* — the junction rows the autolinker and
AI extraction write across the seven entry_* tables. Entity→entity edges are
served separately by the entity-relationships router; this module only covers
the link (edge-to-entry) half.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EntityLinkResponse(BaseModel):
    """One entry↔entity autolink row, normalized across all junction tables."""

    entity_type: str
    entity_id: uuid.UUID
    entity_name: str | None = None
    entry_id: uuid.UUID
    entry_title: str | None = None
    # Absent on the CVE junction; free-form ("high"/"medium"/"low") elsewhere.
    confidence: str | None = None
    # Provenance: auto_link | ai | ai_reconcile | auto_extracted | manual.
    # Null on the TTP/CVE junctions, which don't record a source.
    source: str | None = None
    # Surface forms that triggered the link ("Cozy Bear", "APT29"). Null on
    # the TTP/CVE junctions.
    matched_names: list[str] | None = None
    paragraph_indices: list[int] | None = None
    extracted_at: datetime


class LinkRef(BaseModel):
    """Identifies a single junction row (composite key — no surrogate id)."""

    entity_type: str
    entity_id: uuid.UUID
    entry_id: uuid.UUID


class BulkUnlinkRequest(BaseModel):
    items: list[LinkRef]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "items": [
                    {
                        "entity_type": "malware",
                        "entity_id": "3f9d2a1b-8c7e-4f6a-b5d4-0e1c2a3b4d5f",
                        "entry_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                    }
                ]
            }
        }
    )


class BulkUnlinkResponse(BaseModel):
    deleted: int


class EntityLinkStats(BaseModel):
    total: int
    by_source: dict[str, int]
    by_type: dict[str, int]
    # Held dictionary-word matches awaiting AI/analyst confirmation
    # (pending_autolink_matches), NOT the same as the Extraction tab's
    # "unreviewed entities".
    pending: int
    pending_ready: int
    # Dictionary-word matches dropped in the last 30 days instead of held,
    # because the entry's feed gets no AI analysis to confirm them.
    pending_dropped_ai_off: int = 0
    relationships_total: int
