"""Request/response shapes for manual ingest: the one-item doors and batches."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class IngestURLRequest(BaseModel):
    url: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"url": "https://www.bleepingcomputer.com/news/security/lockbit-returns-with-new-encryptor/"}
        }
    )


class IngestResponse(BaseModel):
    id: uuid.UUID
    title: str
    url: str | None
    word_count: int | None
    feed_id: uuid.UUID
    content_hash: str | None
    message: str


class IngestBatchCreate(BaseModel):
    label: str | None = Field(None, max_length=200, description="Optional name for the drop, shown in the reader")
    source: str = Field("ui", pattern="^(ui|api|tool)$")


class IngestURLsRequest(BaseModel):
    urls: list[str] = Field(
        ..., min_length=1, max_length=500, description="One URL per entry; GitHub repo links expand"
    )
    is_ioc_list: bool = Field(False, description="Treat each fetched body as a curated indicator list")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "urls": [
                    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-290a",
                    "https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation",
                ],
                "is_ioc_list": False,
            }
        }
    )


class IngestTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5_000_000)
    title: str | None = Field(None, max_length=2000)
    source_url: str | None = Field(None, max_length=4000, description="Where the text came from, if anywhere")
    is_ioc_list: bool = Field(False, description="One indicator per line: route through the curated-list door")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "text": "On 2026-10-21 the helpdesk received three calls from a caller claiming to be a contractor...",
                "title": "Helpdesk vishing, internal writeup",
                "is_ioc_list": False,
            }
        }
    )


class IngestFileInfo(BaseModel):
    id: uuid.UUID
    filename: str
    content_type: str
    size_bytes: int
    retained: bool
    download_url: str


class IngestItemResponse(BaseModel):
    id: uuid.UUID
    batch_id: uuid.UUID
    parent_item_id: uuid.UUID | None = None
    position: int
    kind: str
    status: str
    # created items only: "analyzing" until the one-pass AI analysis lands, then "done"
    phase: str | None = None
    filename: str | None = None
    content_type: str | None = None
    size_bytes: int | None = None
    title: str | None = None
    source_url: str | None = None
    is_ioc_list: bool = False
    entry_id: uuid.UUID | None = None
    entry_title: str | None = None
    error: str | None = None
    attempts: int = 0
    retryable: bool = False
    file: IngestFileInfo | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None


class IngestBatchSummary(BaseModel):
    total: int
    active: int
    created: int
    duplicate: int
    failed: int
    status: str
    by_status: dict[str, int]


class IngestBatchResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID | None
    label: str | None
    source: str
    created_at: datetime
    summary: IngestBatchSummary
    items: list[IngestItemResponse] = []


class IngestBatchListItem(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID | None
    label: str | None
    source: str
    created_at: datetime
    summary: IngestBatchSummary


class IngestCapabilities(BaseModel):
    """What the ingest door accepts right now — the modal reads this for its hint text."""

    extensions: list[str]
    max_file_mb: int
    max_batch_items: int
    zip_max_members: int
