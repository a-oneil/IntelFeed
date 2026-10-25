import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FeedCreateRequest(BaseModel):
    url: str
    category_id: uuid.UUID | None = None
    custom_title: str | None = None
    fetch_interval_minutes: int | None = None
    feed_type: str | None = None
    adapter_config: dict | None = None
    intel_extraction_mode: str | None = Field(default=None, pattern=r"^(full|selective|manual|none)$")
    auto_extract_on_ingest: bool | None = None
    extract_detection_rules: bool | None = None
    extract_tools: bool | None = None
    ai_analysis_enabled: bool | None = None
    exclude_title_patterns: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "url": "https://www.bleepingcomputer.com/feed/",
                "category_id": "d5b2c8a1-4f3e-4b7a-9c6d-2e8f1a0b3c4d",
                "custom_title": "BleepingComputer",
                "fetch_interval_minutes": 30,
                "intel_extraction_mode": "selective",
                "auto_extract_on_ingest": False,
                "extract_detection_rules": False,
                "extract_tools": True,
            }
        }
    )


class FeedUpdateRequest(BaseModel):
    url: str | None = None
    custom_title: str | None = None
    category_id: uuid.UUID | None = None
    fetch_interval_minutes: int | None = None
    is_muted: bool | None = None
    is_active: bool | None = None
    exclude_shorts: bool | None = None
    feed_type: str | None = None
    retention_days: int | None = None
    reliability_rating: str | None = Field(default=None, pattern=r"^[A-F]$")
    timeliness_rating: str | None = Field(default=None, pattern=r"^(excellent|good|fair|poor)$")
    relevance_rating: str | None = Field(default=None, pattern=r"^(high|medium|low)$")
    analyst_notes: str | None = None
    intel_extraction_mode: str | None = Field(default=None, pattern=r"^(full|selective|manual|none)$")
    ai_analysis_enabled: bool | None = None
    auto_extract_on_ingest: bool | None = None
    extract_detection_rules: bool | None = None
    extract_tools: bool | None = None
    # Plain phrases, one per line; an article whose title contains one is
    # dropped at ingest. "" or null clears it.
    exclude_title_patterns: str | None = None
    adapter_config: dict | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "custom_title": "BleepingComputer (curated)",
                "fetch_interval_minutes": 15,
                "is_muted": False,
                "reliability_rating": "B",
                "timeliness_rating": "good",
                "relevance_rating": "high",
                "analyst_notes": "Strong ransomware coverage; fast on new CVE exploitation.",
                "intel_extraction_mode": "full",
            }
        }
    )


class FeedResponse(BaseModel):
    id: uuid.UUID
    title: str
    url: str
    feed_type: str
    site_url: str | None
    icon_url: str | None
    description: str | None
    language: str | None
    last_fetched_at: datetime | None
    fetch_interval_minutes: int
    error_count: int
    last_error: str | None
    is_active: bool
    adapter_config: dict = {}
    reliability_rating: str | None = None
    timeliness_rating: str | None = None
    relevance_rating: str | None = None
    analyst_notes: str | None = None
    last_reviewed_at: datetime | None = None
    intel_extraction_mode: str = "selective"
    ai_analysis_enabled: bool = True
    auto_extract_on_ingest: bool = False
    extract_detection_rules: bool = False
    extract_tools: bool = True
    exclude_title_patterns: str | None = None
    category_id: uuid.UUID | None = None
    custom_title: str | None = None
    is_muted: bool = False
    retention_days: int | None = None
    unread_count: int = 0
    # True when per-user subscriptions are on: is_muted is the caller's own
    # state and "unsubscribe" only affects them.
    per_user: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("adapter_config", mode="before")
    @classmethod
    def _mask_secrets(cls, v):
        """Mask credential fields so ciphertext never reaches the client."""
        if not isinstance(v, dict):
            return v
        masked = dict(v)
        if masked.get("app_password"):
            masked["app_password"] = "••••••••"
        return masked


class FeedAIUsageResponse(BaseModel):
    feed_id: uuid.UUID
    days: int
    runs: int
    tokens_input: int
    tokens_output: int
    last_run_at: datetime | None = None
    ai_analysis_enabled: bool


class TitleFilterPreviewRequest(BaseModel):
    exclude_title_patterns: str | None = None

    model_config = ConfigDict(json_schema_extra={"example": {"exclude_title_patterns": "ISC Stormcast For"}})


class TitleFilterPreviewResponse(BaseModel):
    checked: int
    dropped: int
    examples: list[str]


class BulkExcludeShortsRequest(BaseModel):
    exclude_shorts: bool

    model_config = ConfigDict(json_schema_extra={"example": {"exclude_shorts": True}})


class FeedPushRequest(BaseModel):
    """Who to subscribe to a feed. Omit user_ids to push to every human account."""

    user_ids: list[uuid.UUID] | None = None

    model_config = ConfigDict(json_schema_extra={"example": {"user_ids": ["3f1c8b2e-7a44-4d1e-9c6b-2f0a5d8e1b33"]}})


class FeedDiscoverRequest(BaseModel):
    url: str

    model_config = ConfigDict(json_schema_extra={"example": {"url": "https://www.bleepingcomputer.com/"}})


class FeedDiscoverResult(BaseModel):
    url: str
    title: str | None
    feed_type: str
    description: str | None


class BulkIntelModeRequest(BaseModel):
    intel_extraction_mode: str = Field(pattern=r"^(full|selective|manual|none)$")

    model_config = ConfigDict(json_schema_extra={"example": {"intel_extraction_mode": "selective"}})


class BulkCategoryUpdateRequest(BaseModel):
    fetch_interval_minutes: int | None = None
    retention_days: int | None = Field(default=None)
    clear_retention: bool = False
    reliability_rating: str | None = Field(default=None, pattern=r"^[A-F]$")
    timeliness_rating: str | None = Field(default=None, pattern=r"^(excellent|good|fair|poor)$")
    relevance_rating: str | None = Field(default=None, pattern=r"^(high|medium|low)$")
    # Deliberately no analyst_notes. One value applied across a category would
    # replace the per-source judgement on every feed in it, with nothing to undo
    # — notes are written one feed at a time, in the feed modal.
    intel_extraction_mode: str | None = Field(default=None, pattern=r"^(full|selective|manual|none)$")
    ai_analysis_enabled: bool | None = None
    auto_extract_on_ingest: bool | None = None
    extract_detection_rules: bool | None = None
    extract_tools: bool | None = None
    # Change the feeds in the category now (the default). Off, with
    # save_as_category_default on, edits only the defaults.
    apply_to_feeds: bool = True
    # Also store the pipeline fields above as the category's defaults, which
    # feeds added to it later start with.
    save_as_category_default: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "fetch_interval_minutes": 60,
                "retention_days": 90,
                "clear_retention": False,
                "reliability_rating": "B",
                "intel_extraction_mode": "selective",
                "auto_extract_on_ingest": True,
            }
        }
    )
