import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

_ENTITY_TYPE_PATTERN = r"^(ttp|cve|threat_actor|malware|campaign|country|tool|vendor|product|mitigation)$"


class EntityRelationshipCreate(BaseModel):
    source_type: str = Field(pattern=_ENTITY_TYPE_PATTERN)
    source_id: uuid.UUID
    target_type: str = Field(pattern=_ENTITY_TYPE_PATTERN)
    target_id: uuid.UUID
    relationship_type: str = Field(
        pattern=r"^(uses|exploits|targets|attributed_to|variant_of|communicates_with|delivers|drops|hosts|related_to)$"
    )
    confidence: str = Field(default="possible", pattern=r"^(confirmed|probable|possible)$")
    description: str | None = None
    evidence_entry_ids: list[uuid.UUID] = []

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source_type": "threat_actor",
                "source_id": "d5b2c8f0-3e4a-4b6c-9d1e-7f8a9b0c1d2e",
                "target_type": "malware",
                "target_id": "3f9d2a1b-8c7e-4f6a-b5d4-0e1c2a3b4d5f",
                "relationship_type": "uses",
                "confidence": "probable",
                "description": "Reported deploying this malware family in recent intrusions.",
                "evidence_entry_ids": ["a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"],
            }
        }
    )


class EntityRelationshipUpdate(BaseModel):
    relationship_type: str | None = Field(
        default=None,
        pattern=r"^(uses|exploits|targets|attributed_to|variant_of|communicates_with|delivers|drops|hosts|related_to)$",
    )
    confidence: str | None = Field(default=None, pattern=r"^(confirmed|probable|possible)$")
    description: str | None = None
    evidence_entry_ids: list[uuid.UUID] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "confidence": "confirmed",
                "description": "Confirmed by multiple vendor reports.",
            }
        }
    )


class EntityRelationshipResponse(BaseModel):
    id: uuid.UUID
    source_type: str
    source_id: uuid.UUID
    source_name: str | None = None
    target_type: str
    target_id: uuid.UUID
    target_name: str | None = None
    relationship_type: str
    confidence: str
    source: str
    description: str | None
    evidence_entry_ids: list[uuid.UUID]
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RelationClaimSource(BaseModel):
    source_type: str
    label: str
    linked: int = Field(description="Claims from this source that matched an entity")


class HeldRelationClaim(BaseModel):
    source_type: str
    source_label: str
    relation: str
    target_name: str
    target_type: str | None
    held_reason: str | None = Field(description="unknown (matched no entity) or ambiguous (matched several)")
    evidence: str | None


class RelationClaimsResponse(BaseModel):
    entity_type: str
    entity_id: str
    sources: list[RelationClaimSource] = Field(description="Linked claims per source, most first")
    by_target: dict[str, list[str]] = Field(
        description="<type>-<id> of each connected entity to the sources whose claim names it"
    )
    held: list[HeldRelationClaim]
    held_count: int

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "threat_actor",
                "entity_id": "3f9c2b1a-5d6e-4f70-8a9b-c0d1e2f3a4b5",
                "sources": [{"source_type": "mitre_attack", "label": "MITRE ATT&CK", "linked": 14}],
                "by_target": {"malware-9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d": ["mitre_attack", "malpedia"]},
                "held": [
                    {
                        "source_type": "malpedia",
                        "source_label": "Malpedia",
                        "relation": "uses",
                        "target_name": "win.unknown_loader",
                        "target_type": "malware",
                        "held_reason": "unknown",
                        "evidence": None,
                    }
                ],
                "held_count": 1,
            }
        }
    )
