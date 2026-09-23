import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class MessageIn(BaseModel):
    role: str
    content: str
    meta: dict | None = None


class Message(BaseModel):
    role: str
    content: str
    created_at: str
    meta: dict | None = None


class AIConversation(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    title: str | None = None
    scope_type: str
    scope_id: str | None = None
    entry_ids: list[str] | None = None
    messages: list[Message] = []
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AIConversationSummary(BaseModel):
    id: uuid.UUID
    title: str | None = None
    scope_type: str
    scope_id: str | None = None
    message_count: int
    updated_at: datetime

    model_config = {"from_attributes": True}


class AIConversationCreate(BaseModel):
    scope_type: str
    scope_id: str | None = None
    entry_ids: list[str] | None = None
    title: str | None = Field(default=None, max_length=200)
    messages: list[MessageIn] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "scope_type": "entry",
                "scope_id": "0f8e7d6c-5b4a-4392-8170-6e5d4c3b2a19",
                "title": "APT29 phishing article questions",
                "messages": [
                    {"role": "user", "content": "What TTPs does this article describe?"},
                ],
            }
        }
    )


class AIConversationUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=200)
    append_messages: list[MessageIn] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "title": "APT29 phishing article questions",
                "append_messages": [
                    {"role": "user", "content": "Which of these TTPs lack detection coverage?"},
                    {"role": "assistant", "content": "T1566.001 has no active Sigma rule in your workbench."},
                ],
            }
        }
    )
