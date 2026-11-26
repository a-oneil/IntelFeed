"""Request/response shapes for manual ingest: single items, the browser extension's endpoints, and batches."""

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


class IngestPageRequest(BaseModel):
    """A page as the sender's browser rendered it (sent by the browser extension).

    With ``html`` the server does not fetch the URL; the HTML is extracted and
    sanitized the same way as a fetched page. Without it, the URL is fetched as
    ``/ingest/url`` does, and the tags and note are applied the same way.
    """

    url: str = Field(..., max_length=4000)
    title: str | None = Field(None, max_length=2000)
    html: str | None = Field(
        None, max_length=2_000_000, description="The page's rendered DOM (document.documentElement.outerHTML)"
    )
    selection: str | None = Field(
        None, max_length=20_000, description="Text the sender had selected: kept as the excerpt"
    )
    published_at: datetime | None = Field(
        None, description="From the page's <meta> / JSON-LD; ignored when before 1995 or in the future"
    )
    author: str | None = Field(None, max_length=500)
    tag_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    note: str | None = Field(None, max_length=10_000, description="Saved as the sender's Note on the entry")
    client: str | None = Field(
        None, max_length=100, description="Sending client and version, e.g. intelfeed-extension/1.0.0"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-290a",
                "title": "AA24-290A: Iranian Cyber Actors' Brute Force",
                "html": "<html><head><title>…</title></head><body><article>…</article></body></html>",
                "selection": "The actors used password spraying against Citrix NetScaler…",
                "published_at": "2024-10-16T00:00:00Z",
                "note": "Matches what we saw on the VPN logs",
                "client": "intelfeed-extension/1.0.0",
            }
        }
    )


class IngestPageResponse(IngestResponse):
    created: bool = Field(..., description="False when the page was already collected; the entry is the existing one")


class StoryThreadRef(BaseModel):
    slug: str
    title: str
    entry_count: int
    source_count: int = Field(description="Distinct outlets, not feed rows")


class EntryByURLResponse(BaseModel):
    id: uuid.UUID
    title: str
    url: str | None
    feed_id: uuid.UUID
    feed_title: str | None
    published_at: datetime | None
    fetched_at: datetime | None
    thread: StoryThreadRef | None = Field(None, description="The story thread the entry belongs to, if any")


class NamedRef(BaseModel):
    id: uuid.UUID
    name: str


class CVERef(BaseModel):
    id: uuid.UUID
    cve_id: str
    cvss_score: float | None


class TTPRef(BaseModel):
    id: uuid.UUID
    technique_id: str
    name: str


class EntryResultsResponse(BaseModel):
    """What the pipeline found in one entry, for a client that sent it and is waiting."""

    entry_id: uuid.UUID
    state: str = Field(
        description="processing (stages still to run, or a new entry waiting for its first stage), done, "
        "errored (a stage failed; the other results will not change), "
        "or unknown (no pipeline record on an entry older than 30 minutes)"
    )
    actors: list[NamedRef] = []
    malware: list[NamedRef] = []
    tools: list[NamedRef] = []
    cves: list[CVERef] = []
    ttps: list[TTPRef] = []
    rule_count: int = 0
    observable_count: int = 0
    thread: StoryThreadRef | None = None


class CoverageEntry(BaseModel):
    id: uuid.UUID
    title: str
    feed_title: str | None
    published_at: datetime | None


class PageCoverageResponse(BaseModel):
    """Recent entries that tell the same story as a page not yet in IntelFeed."""

    outlet_count: int = Field(description="Distinct sites among the matches")
    entries: list[CoverageEntry] = Field(description="Up to five matches, best first")
    thread: StoryThreadRef | None = Field(None, description="The story thread most matches belong to")
