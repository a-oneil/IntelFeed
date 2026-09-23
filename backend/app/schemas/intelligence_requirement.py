import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

LINKED_ENTITY_KEYS = {"threat_actors", "malware", "cves", "ttps"}


class LinkedEntityRef(BaseModel):
    id: uuid.UUID
    name: str = Field(min_length=1, max_length=500)


def _validate_linked_entity_keys(value: dict | None) -> dict | None:
    if value:
        unknown = set(value.keys()) - LINKED_ENTITY_KEYS
        if unknown:
            raise ValueError(f"Unknown linked entity types: {sorted(unknown)}")
    return value


class RequirementCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    description: str | None = None
    priority: str = Field(pattern=r"^(critical|high|medium|low)$")
    status: str = Field(default="active", pattern=r"^(active|fulfilled|expired|draft)$")
    category: str = Field(default="operational", pattern=r"^(strategic|operational|tactical|technical)$")
    keywords: list[str] = []
    linked_feed_ids: list[uuid.UUID] = []
    linked_entities: dict[str, list[LinkedEntityRef]] = {}
    min_relevance: str | None = Field(default=None, pattern=r"^(high|medium|low)$")
    auto_match: bool = True
    expires_at: datetime | None = None

    _check_linked_entities = field_validator("linked_entities")(_validate_linked_entity_keys)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "title": "Ransomware targeting US healthcare",
                "description": "Track ransomware operations impacting hospital and clinic systems",
                "priority": "high",
                "status": "active",
                "category": "operational",
                "keywords": ["ransomware", "hospital", "healthcare"],
                "linked_entities": {"malware": [{"id": "8f3c2b1a-6d5e-4f7a-9b8c-2e1d3c4b5a6f", "name": "LockBit"}]},
                "min_relevance": "medium",
                "auto_match": True,
            }
        }
    )


class RequirementUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=500)
    description: str | None = None
    priority: str | None = Field(default=None, pattern=r"^(critical|high|medium|low)$")
    status: str | None = Field(default=None, pattern=r"^(active|fulfilled|expired|draft)$")
    category: str | None = Field(default=None, pattern=r"^(strategic|operational|tactical|technical)$")
    keywords: list[str] | None = None
    linked_feed_ids: list[uuid.UUID] | None = None
    linked_entities: dict[str, list[LinkedEntityRef]] | None = None
    min_relevance: str | None = Field(default=None, pattern=r"^(high|medium|low)$")
    auto_match: bool | None = None
    expires_at: datetime | None = None

    _check_linked_entities = field_validator("linked_entities")(_validate_linked_entity_keys)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "priority": "critical",
                "keywords": ["ransomware", "hospital", "double extortion"],
            }
        }
    )


class RequirementResponse(BaseModel):
    id: uuid.UUID
    created_by: uuid.UUID | None
    title: str
    description: str | None
    priority: str
    status: str
    category: str
    keywords: list[str]
    linked_feed_ids: list[uuid.UUID]
    linked_entities: dict[str, list[LinkedEntityRef]] = {}
    min_relevance: str | None = None
    auto_match: bool
    match_count: int
    last_matched_at: datetime | None
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None
    fulfilled_by_report_id: uuid.UUID | None = None

    model_config = {"from_attributes": True}


class RequirementMatchResponse(BaseModel):
    requirement_id: uuid.UUID
    entry_id: uuid.UUID
    match_type: str
    matched_on: str
    matched_at: datetime
    relevance: str | None
    entry_title: str | None = None
    entry_url: str | None = None
    entry_published_at: datetime | None = None

    model_config = {"from_attributes": True}


class RequirementManualMatchRequest(BaseModel):
    entry_id: uuid.UUID
    relevance: str = Field(default="medium", pattern=r"^(high|medium|low)$")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entry_id": "d5b2f1c8-3a4e-4b6d-9c2f-8e7a1b3c5d4e",
                "relevance": "high",
            }
        }
    )


class RequirementFulfillRequest(BaseModel):
    report_id: uuid.UUID | None = None

    model_config = ConfigDict(json_schema_extra={"example": {"report_id": "4b8d2f6a-1c3e-4a5b-9d7f-6e2c8a0b4d1e"}})


class RequirementCoverageBrief(BaseModel):
    id: uuid.UUID
    title: str
    priority: str
    status: str
    match_count: int
    last_matched_at: datetime | None
    linked_feeds: int

    model_config = {"from_attributes": True}


class RequirementCoverageSummary(BaseModel):
    total_requirements: int
    active: int
    fulfilled: int
    expired: int
    draft: int
    by_priority: dict[str, int]
    by_category: dict[str, int]
    with_recent_matches: int
    stale: int
    needs_review: list[RequirementCoverageBrief] = []
    requirements: list[RequirementCoverageBrief] = []
