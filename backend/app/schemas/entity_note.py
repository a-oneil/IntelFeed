import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EntityNoteCreate(BaseModel):
    # Mirrors the ck_entity_notes_entity_type CHECK constraint.
    entity_type: str = Field(
        pattern=r"^(ioc|ttp|cve|threat_actor|malware|campaign|country|mitigation|tool|vendor|product|sector)$"
    )
    entity_id: uuid.UUID
    title: str | None = Field(default=None, max_length=500)
    content: str = Field(min_length=1, max_length=50000)
    note_type: str = Field(default="annotation", pattern=r"^(annotation|analysis|action_taken|false_positive|context)$")
    tags: list[str] = []

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "threat_actor",
                "entity_id": "d5b2c8f0-3e4a-4b6c-9d1e-7f8a9b0c1d2e",
                "title": "Attribution assessment",
                "content": "Infrastructure overlaps with APT29 reporting; attribution probable, not confirmed.",
                "note_type": "analysis",
                "tags": ["attribution", "apt29"],
            }
        }
    )


class EntityNoteUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=500)
    content: str | None = Field(default=None, min_length=1, max_length=50000)
    note_type: str | None = Field(default=None, pattern=r"^(annotation|analysis|action_taken|false_positive|context)$")
    tags: list[str] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "content": "Attribution upgraded to confirmed after the second vendor report.",
                "note_type": "analysis",
                "tags": ["attribution", "apt29", "confirmed"],
            }
        }
    )


class EntityNoteResponse(BaseModel):
    id: uuid.UUID
    entity_type: str
    entity_id: uuid.UUID
    user_id: uuid.UUID
    title: str | None = None
    content: str
    note_type: str
    tags: list[str]
    created_at: datetime
    updated_at: datetime
    username: str | None = None
    entity_name: str | None = None

    model_config = {"from_attributes": True}
