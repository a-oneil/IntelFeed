import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class TagCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    color: str = Field(default="#6B7280", pattern=r"^#[0-9A-Fa-f]{6}$")
    display_as_chip: bool = Field(default=False, description="Render in the entry's badge row as a chip")
    description: str | None = Field(default=None, max_length=255, description="Chip tooltip")
    is_global: bool = Field(
        default=False,
        description="Global: one shared assignment per entry that everyone sees. "
        "Personal (default): each user's assignments are their own.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "customer-a",
                "color": "#EF4444",
                "display_as_chip": True,
                "description": "Touches Customer A's estate",
                "is_global": False,
            }
        }
    )


class TagUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    color: str | None = Field(default=None, pattern=r"^#[0-9A-Fa-f]{6}$")
    display_as_chip: bool | None = None
    # An empty string clears the description; omitted leaves it alone.
    description: str | None = Field(default=None, max_length=255)
    # Changing scope re-homes every existing assignment: to global collapses
    # everyone's rows into one shared row per entry; to personal hands the
    # shared row to every human account as their own.
    is_global: bool | None = None

    model_config = ConfigDict(json_schema_extra={"example": {"name": "ransomware-ops", "color": "#F59E0B"}})


class TagResponse(BaseModel):
    id: uuid.UUID
    name: str
    color: str
    display_as_chip: bool = False
    description: str | None = None
    is_global: bool = False
    # Entries carrying the tag as the caller sees them: their own assignments
    # for a personal tag, everyone's for a global one.
    entry_count: int = 0
    created_at: datetime

    model_config = {"from_attributes": True}


class BulkTagRequest(BaseModel):
    entry_ids: list[uuid.UUID]
    tag_ids: list[uuid.UUID]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entry_ids": [
                    "d5b2f1a4-3c6e-4b8a-9f21-7e5a2c9d1b34",
                    "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                ],
                "tag_ids": ["f7e6d5c4-b3a2-4918-a7b6-c5d4e3f2a1b0"],
            }
        }
    )


class EntryTagsRequest(BaseModel):
    tag_ids: list[uuid.UUID]

    model_config = ConfigDict(json_schema_extra={"example": {"tag_ids": ["f7e6d5c4-b3a2-4918-a7b6-c5d4e3f2a1b0"]}})


class TagMergeRequest(BaseModel):
    """Fold one or more source tags into a target tag (which is kept)."""

    source_ids: list[uuid.UUID] = Field(min_length=1)
    target_id: uuid.UUID

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source_ids": ["a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"],
                "target_id": "f7e6d5c4-b3a2-4918-a7b6-c5d4e3f2a1b0",
            }
        }
    )
