import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CategoryCreateRequest(BaseModel):
    name: str
    parent_id: uuid.UUID | None = None
    position: int = 0

    model_config = ConfigDict(
        json_schema_extra={"example": {"name": "Threat Research", "parent_id": None, "position": 0}}
    )


class CategoryFeedDefaults(BaseModel):
    """Pipeline settings a feed added to the category starts with; null = global default."""

    intel_extraction_mode: str | None = Field(default=None, pattern=r"^(full|selective|manual|none)$")
    ai_analysis_enabled: bool | None = None
    extract_tools: bool | None = None
    auto_extract_on_ingest: bool | None = None
    extract_detection_rules: bool | None = None


class CategoryUpdateRequest(BaseModel):
    name: str | None = None
    parent_id: uuid.UUID | None = None
    position: int | None = None
    # Replaces the whole set (admin only); {} clears it.
    feed_defaults: CategoryFeedDefaults | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Vendor Blogs",
                "position": 2,
                "feed_defaults": {"ai_analysis_enabled": False, "extract_tools": False},
            }
        }
    )


class CategoryResponse(BaseModel):
    id: uuid.UUID
    name: str
    parent_id: uuid.UUID | None
    position: int
    created_at: datetime
    children: list["CategoryResponse"] = []
    feed_count: int = 0
    feed_defaults: dict = {}

    model_config = {"from_attributes": True}


class CategoryReorderRequest(BaseModel):
    items: list[dict]  # [{"id": uuid, "position": int, "parent_id": uuid | None}]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "items": [
                    {"id": "d5b2f1a4-3c6e-4b8a-9f21-7e5a2c9d1b34", "position": 0, "parent_id": None},
                    {
                        "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                        "position": 1,
                        "parent_id": "d5b2f1a4-3c6e-4b8a-9f21-7e5a2c9d1b34",
                    },
                ]
            }
        }
    )
