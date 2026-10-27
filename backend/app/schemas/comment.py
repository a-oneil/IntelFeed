import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CommentCreate(BaseModel):
    commentable_type: str = Field(
        pattern=r"^(detection_rule|intel_report|campaign|entry|threat_actor|malware|cve|ttp)$"
    )
    commentable_id: uuid.UUID
    content: str = Field(min_length=1, max_length=10000)
    parent_id: uuid.UUID | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "commentable_type": "detection_rule",
                "commentable_id": "d5b2c8a1-4f3e-4b7a-9c6d-2e8f1a0b3c4d",
                "content": "This Sigma rule needs a filter for legit admin use of PsExec.",
            }
        }
    )


class CommentUpdate(BaseModel):
    content: str = Field(min_length=1, max_length=10000)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"content": "Updated: filter added for SYSTEM-initiated PsExec, ready for review."}
        }
    )


class CommentResponse(BaseModel):
    id: uuid.UUID
    commentable_type: str
    commentable_id: uuid.UUID
    user_id: uuid.UUID
    content: str
    parent_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    username: str | None = None
    reply_count: int = 0
    mentions: list[uuid.UUID] = []

    model_config = {"from_attributes": True}
