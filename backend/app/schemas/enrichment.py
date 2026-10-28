import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EnrichmentSourceResponse(BaseModel):
    id: uuid.UUID
    source_type: str
    display_name: str
    is_enabled: bool
    trigger_mode: str
    has_api_key: bool = False
    requires_api_key: bool = False
    shared_key_group: str | None = None
    rate_limit_config: dict
    min_confidence_threshold: str = "low"
    daily_budget: int | None = None
    daily_budget_used: int = 0
    supported_entity_types: list[str] = []
    last_synced_at: datetime | None
    health_status: str
    config: dict
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class EnrichmentSourceUpdate(BaseModel):
    is_enabled: bool | None = None
    trigger_mode: str | None = Field(default=None, pattern=r"^(auto|manual)$")
    api_key: str | None = None
    rate_limit_config: dict | None = None
    config: dict | None = None
    min_confidence_threshold: str | None = Field(default=None, pattern=r"^(high|medium|low)$")
    daily_budget: int | None = None
    clear_daily_budget: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "is_enabled": True,
                "trigger_mode": "auto",
                "api_key": "nvd-api-key-0123456789abcdef",
                "rate_limit_config": {"requests_per_period": 50, "period_seconds": 30},
                "min_confidence_threshold": "medium",
                "daily_budget": 200,
            }
        }
    )


class UserEnrichmentOverrideResponse(BaseModel):
    id: uuid.UUID
    source_id: uuid.UUID
    has_api_key: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


class UserEnrichmentOverrideCreate(BaseModel):
    api_key: str | None = None

    model_config = ConfigDict(json_schema_extra={"example": {"api_key": "vt-user-api-key-0123456789abcdef"}})


class EnrichmentResultResponse(BaseModel):
    id: uuid.UUID
    entity_type: str
    entity_id: uuid.UUID
    source_type: str
    parsed_data: dict
    enriched_at: datetime
    expires_at: datetime
    status: str

    model_config = {"from_attributes": True}


class EnrichmentPauseRequest(BaseModel):
    paused: bool

    model_config = ConfigDict(json_schema_extra={"example": {"paused": True}})


class EnrichmentBackfillRequest(BaseModel):
    entity_type: str | None = Field(None, description="Entity type (default: its first column's)")
    limit: int | None = Field(None, ge=1, description="Most lookups to queue (default 1,000, at most 50,000)")

    model_config = ConfigDict(json_schema_extra={"example": {"entity_type": "cve", "limit": 5000}})


class EnrichEntityRequest(BaseModel):
    entity_type: str = Field(pattern=r"^(cve|threat_actor|malware|ttp|observable)$")
    entity_id: uuid.UUID
    source_types: list[str] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "cve",
                "entity_id": "9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
                "source_types": ["nvd", "epss"],
            }
        }
    )
