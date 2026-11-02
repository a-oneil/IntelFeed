import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app import entity_types


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
                "rate_limit_config": {"requests_per_period": 50, "period_seconds": 30},
                "min_confidence_threshold": "medium",
                "daily_budget": 200,
            }
        }
    )


class EnrichmentKeyUpdate(BaseModel):
    api_key: str | None = Field(None, description="The key; empty or null removes it")

    model_config = ConfigDict(json_schema_extra={"example": {"api_key": "nvd-api-key-0123456789abcdef"}})


class EnrichmentPauseRequest(BaseModel):
    paused: bool

    model_config = ConfigDict(json_schema_extra={"example": {"paused": True}})


class EnrichmentBackfillRequest(BaseModel):
    entity_type: str | None = Field(None, description="Entity type (default: its first column's)")
    limit: int | None = Field(None, ge=1, description="Most lookups to queue (default 1,000, at most 50,000)")

    model_config = ConfigDict(json_schema_extra={"example": {"entity_type": "cve", "limit": 5000}})


_ENRICHABLE_PATTERN = (
    "^("
    + "|".join(
        sorted(
            (
                entity_types.THREAT_ACTOR,
                entity_types.MALWARE,
                entity_types.CVE,
                entity_types.CWE,
                entity_types.TTP,
                entity_types.COUNTRY,
                entity_types.TOOL,
                entity_types.VENDOR,
                entity_types.PRODUCT,
                entity_types.MITIGATION,
                entity_types.OBSERVABLE,
                entity_types.RANSOMWARE_VICTIM,
            )
        )
    )
    + ")$"
)


class EnrichEntityRequest(BaseModel):
    # Every type with an entity model the field map can write to.
    entity_type: str = Field(pattern=_ENRICHABLE_PATTERN)
    entity_id: uuid.UUID
    source_types: list[str] | None = None
    #: Look the entity up again even where a stored result is still fresh.
    refresh: bool = False
    #: A person's request runs in the manual lane, ahead of new, refresh and
    #: backfill work; a refused source is queued there. The only lane a request
    #: may name.
    lane: Literal["manual"] = "manual"

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "cve",
                "entity_id": "9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
                "source_types": ["nvd", "epss"],
            }
        }
    )


# --- Console responses (Settings → Engine → Enrichment) ---


class SourceRef(BaseModel):
    source_type: str
    label: str


class CoverageSourceRef(SourceRef):
    enabled: bool


class BackfillAction(BaseModel):
    kind: Literal["backfill"]
    source: str = Field(description="The lookup source a backfill runs through")
    count: int = Field(description="Entities the backfill would look up")


class AIAction(BaseModel):
    kind: Literal["ai"]
    field: str = Field(description="The AI research field that fills the column")


class EnrichmentCoverageField(BaseModel):
    entity_type: str
    entity_label: str
    field: str
    label: str
    filled: int
    total: int
    filled_pct: float | None
    sources: list[CoverageSourceRef]
    action: BackfillAction | AIAction | None = Field(description="What to do about the rest; null when jobs fill it")
    cadence: str | None = Field(description="How often the field's jobs run, when nothing else is to be done")


class EnrichmentCoverageResponse(BaseModel):
    fields: list[EnrichmentCoverageField]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "fields": [
                    {
                        "entity_type": "cve",
                        "entity_label": "CVE",
                        "field": "epss_score",
                        "label": "EPSS score",
                        "filled": 41230,
                        "total": 58012,
                        "filled_pct": 71.1,
                        "sources": [{"source_type": "epss", "label": "EPSS", "enabled": True}],
                        "action": {"kind": "backfill", "source": "epss", "count": 16782},
                        "cadence": None,
                    }
                ]
            }
        }
    )


class EnrichmentLaneActivity(BaseModel):
    lane: str
    waiting: int = Field(description="Queued or running rows")
    deferred: int = Field(description="Queued rows a source put off (rate limit, budget, breaker)")


class EnrichmentFailedSource(SourceRef):
    count: int
    last_error: str | None


class EnrichmentSourceRequests(SourceRef):
    requests: int


class EnrichmentActivityResponse(BaseModel):
    lanes: list[EnrichmentLaneActivity]
    backfill_share: float = Field(description="Share of a source's daily budget the backfill lane may use")
    failed: list[EnrichmentFailedSource]
    requests: list[EnrichmentSourceRequests] | None = Field(description="Last 24 hours; null when Redis can't say")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "lanes": [
                    {"lane": "manual", "waiting": 0, "deferred": 0},
                    {"lane": "new", "waiting": 12, "deferred": 3},
                    {"lane": "refresh", "waiting": 40, "deferred": 0},
                    {"lane": "backfill", "waiting": 1800, "deferred": 1800},
                ],
                "backfill_share": 0.25,
                "failed": [{"source_type": "greynoise", "label": "GreyNoise", "count": 2, "last_error": "HTTP 500"}],
                "requests": [{"source_type": "nvd", "label": "NVD", "requests": 310}],
            }
        }
    )


class EnrichmentRetryResponse(BaseModel):
    queued: int = Field(description="Lookups queued again")

    model_config = ConfigDict(json_schema_extra={"example": {"queued": 2}})


class EnrichmentKeyResponse(BaseModel):
    id: str
    label: str
    note: str = Field(description="What the key does, in one sentence")
    required: bool
    sources: list[SourceRef]
    also_used_by: str | None = Field(description="A user of the key outside enrichment")
    status: Literal["set", "rejected", "missing", "optional"]
    message: str | None = Field(description="Why the source rejected the key, when it did")
    mine: bool = Field(description="The caller has an own key, used for the lookups they start")
    personal_allowed: bool
    signup_url: str | None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "nvd_api_key",
                "label": "NVD API key",
                "note": "Raises NVD's rate limit from 5 to 50 requests per 30 seconds.",
                "required": False,
                "sources": [{"source_type": "nvd", "label": "NVD"}],
                "also_used_by": None,
                "status": "set",
                "message": None,
                "mine": False,
                "personal_allowed": True,
                "signup_url": "https://nvd.nist.gov/developers/request-an-api-key",
            }
        }
    )
