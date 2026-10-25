"""Schemas for the Autolinking admin surface (Settings → Engine → Autolinking).

These describe entry→entity *autolinks* — the junction rows the autolinker and
AI extraction write across the seven entry_* tables. Entity→entity edges are
served separately by the entity-relationships router; this module only covers
the link (edge-to-entry) half.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


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


class PendingMatchEntry(BaseModel):
    id: uuid.UUID  # pending_autolink_matches row id
    entry_id: uuid.UUID
    entry_title: str
    published_at: datetime | None
    matched_names: list[str]
    confidence: str | None


class PendingMatchGroup(BaseModel):
    entity_type: str
    entity_id: uuid.UUID
    name: str
    count: int
    high: int  # how many of them the autolinker rated high confidence
    entries: list[PendingMatchEntry]  # newest first, capped at 50


class PendingMatchesResponse(BaseModel):
    groups: list[PendingMatchGroup]
    total_matches: int


class ResolvePendingRequest(BaseModel):
    resolution: str = Field(..., pattern="^(promote|reject)$", description="promote = link it; reject = not a match.")
    entity_type: str | None = Field(None, description="With entity_id: resolve every held match for this entity.")
    entity_id: uuid.UUID | None = None
    ids: list[uuid.UUID] = Field(default_factory=list, max_length=500, description="Or: these pending rows only.")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "resolution": "promote",
                "entity_type": "threat_actor",
                "entity_id": "d5b2c8f0-3e4a-4b6c-9d1e-7f8a9b0c1d2e",
            }
        }
    )


class ResolvePendingResponse(BaseModel):
    promoted: int
    rejected: int
