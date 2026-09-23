import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class NoteCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    content_markdown: str = ""
    tags: list[str] = []
    is_pinned: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "title": "APT29 phishing wave — tracking",
                "content_markdown": "Spearphishing (T1566.001) against EU ministries. Watch for **LockBit** follow-on.",
                "tags": ["apt29", "phishing"],
                "is_pinned": False,
            }
        }
    )


class NoteUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=500)
    content_markdown: str | None = None
    tags: list[str] | None = None
    is_pinned: bool | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "title": "APT29 phishing wave — confirmed",
                "content_markdown": "Campaign confirmed by two sources; CVE-2024-3400 exploited for initial access.",
                "is_pinned": True,
            }
        }
    )


class NoteResponse(BaseModel):
    id: uuid.UUID
    created_by: uuid.UUID | None = None
    entry_id: uuid.UUID | None
    title: str
    content_markdown: str
    content_html: str | None
    tags: list[str]
    is_pinned: bool
    created_at: datetime
    updated_at: datetime

    # Author info
    creator_username: str | None = None

    # Attached entry info (populated when listing)
    entry_title: str | None = None
    feed_title: str | None = None

    model_config = {"from_attributes": True}
