import uuid
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field


class CampaignCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    status: str = Field(default="active", pattern=r"^(active|monitoring|closed|historical)$")
    tlp_marking: str = Field(default="TLP:GREEN", pattern=r"^TLP:(CLEAR|GREEN|AMBER|AMBER\+STRICT|RED)$")
    start_date: date | None = None
    end_date: date | None = None
    tags: list[str] = []
    entry_ids: list[uuid.UUID] | None = None
    pivot_entity: dict | None = None  # {"type": "threat_actor"|"malware", "id": "uuid"}

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "LockBit Healthcare Wave",
                "description": "Tracking LockBit 3.0 activity against US healthcare providers",
                "status": "active",
                "tlp_marking": "TLP:AMBER",
                "start_date": "2026-07-01",
                "tags": ["ransomware", "healthcare"],
            }
        }
    )


class CampaignUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    status: str | None = Field(default=None, pattern=r"^(active|monitoring|closed|historical)$")
    tlp_marking: str | None = Field(default=None, pattern=r"^TLP:(CLEAR|GREEN|AMBER|AMBER\+STRICT|RED)$")
    start_date: date | None = None
    end_date: date | None = None
    tags: list[str] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "closed",
                "end_date": "2026-08-15",
                "tags": ["ransomware", "healthcare", "wrapped-up"],
            }
        }
    )


class CampaignResponse(BaseModel):
    id: uuid.UUID
    created_by: uuid.UUID | None
    name: str
    description: str | None
    status: str
    tlp_marking: str
    start_date: date | None
    end_date: date | None
    tags: list[str]
    created_at: datetime
    updated_at: datetime
    entry_count: int = 0
    entity_count: int = 0
    first_activity_at: datetime | None = Field(
        None, description="Publish date of the campaign's oldest article — when its coverage actually begins"
    )
    last_activity_at: datetime | None = Field(
        None, description="Publish date of the campaign's newest article — what 'gone quiet' is measured from"
    )

    model_config = {"from_attributes": True}


class CampaignEntryAdd(BaseModel):
    entry_id: uuid.UUID
    notes: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entry_id": "d5b2f1c8-3a4e-4b6d-9c2f-8e7a1b3c5d4e",
                "notes": "Details the initial access vector (phishing, T1566.001)",
            }
        }
    )


class CampaignEntityAdd(BaseModel):
    entity_type: str = Field(pattern=r"^(ttp|cve|threat_actor|malware)$")
    entity_id: uuid.UUID
    role: str = Field(default="related", pattern=r"^(primary|secondary|related)$")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "malware",
                "entity_id": "8f3c2b1a-6d5e-4f7a-9b8c-2e1d3c4b5a6f",
                "role": "primary",
            }
        }
    )


class CampaignTimelineEntry(BaseModel):
    entry_id: uuid.UUID
    title: str
    url: str | None
    published_at: datetime | None
    notes: str | None
    thread_id: uuid.UUID | None = Field(
        None, description="Story thread this article belongs to, when the sweeper has folded it into one"
    )
    thread_slug: str | None = None
    thread_title: str | None = None
    thread_role: str | None = Field(None, description="origin | beat | echo — the article's part in its story")

    model_config = {"from_attributes": True}


class CampaignSuggestion(BaseModel):
    entry_id: uuid.UUID
    title: str
    url: str | None
    published_at: datetime | None
    overlap_count: int
    overlapping_entities: list[dict] = []
    reason: str = Field(
        "shared_entities",
        description="same_story when the campaign already holds part of this story; shared_entities otherwise",
    )
    thread_id: uuid.UUID | None = None
    thread_slug: str | None = None
    thread_title: str | None = None
    thread_role: str | None = None
    thread_article_count: int | None = Field(None, description="Articles in the story, campaign membership aside")
    thread_in_campaign: int | None = Field(None, description="How many of them the campaign already holds")


class CampaignEntriesAdd(BaseModel):
    entry_ids: list[uuid.UUID] = Field(..., description="Entries to add; ones already in the campaign are skipped")
    notes: str | None = None


class CampaignEntriesAddResult(BaseModel):
    added: int
    skipped: int = Field(description="Already in the campaign")

    model_config = {"from_attributes": True}


class CampaignSavedSearchAdd(BaseModel):
    saved_search_id: uuid.UUID
    auto_sync: bool = True

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "saved_search_id": "3a9e7d1b-5c2f-4e8a-b6d4-1f0c9e8b7a2d",
                "auto_sync": True,
            }
        }
    )


class CampaignSavedSearchUpdate(BaseModel):
    auto_sync: bool

    model_config = ConfigDict(json_schema_extra={"example": {"auto_sync": False}})


class CampaignSavedSearchResponse(BaseModel):
    id: uuid.UUID
    campaign_id: uuid.UUID
    saved_search_id: uuid.UUID
    saved_search_name: str = ""
    saved_search_query: str | None = None
    auto_sync: bool
    last_synced_at: datetime | None
    entries_added: int
    created_at: datetime

    model_config = {"from_attributes": True}


class CampaignSavedSearchSyncResult(BaseModel):
    saved_search_id: uuid.UUID
    new_entries_added: int
    total_entries: int


class CampaignEntityResponse(BaseModel):
    id: uuid.UUID
    campaign_id: uuid.UUID
    entity_type: str
    entity_id: uuid.UUID
    entity_name: str
    role: str
    added_at: datetime

    model_config = {"from_attributes": True}


class CampaignSourceAdd(BaseModel):
    kind: str = Field(
        description=(
            "entity — follow an actor/malware/CVE and take every article carrying it; "
            "story — follow a thread and take its later waves; "
            "query — take everything matching a query-language string, campaign-owned "
            "rather than tucked inside one analyst's saved searches"
        )
    )
    entity_type: str | None = Field(None, description="Entity type slug; required when kind is entity")
    ref_id: uuid.UUID | None = Field(
        None, description="The entity's UUID or the story thread's UUID. Omitted when kind is query."
    )
    query: str | None = Field(
        None,
        max_length=2000,
        description="Query-language string; required when kind is query, forbidden otherwise.",
    )
    auto_sync: bool = True

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "kind": "entity",
                    "entity_type": "threat_actor",
                    "ref_id": "e5049c67-51bf-4dc9-9a78-fb23d6a7bbd7",
                    "auto_sync": True,
                },
                {"kind": "query", "query": 'threat_actor:"Scattered Spider" AND tag:ransomware', "auto_sync": True},
            ]
        }
    )


class CampaignSourceUpdate(BaseModel):
    auto_sync: bool | None = Field(None, description="Pause or resume without losing the link or its history")
    query: str | None = Field(
        None,
        max_length=2000,
        description=(
            "Rewrite a query source's query, keeping the row and its history. "
            "Only valid when the source's kind is query."
        ),
    )


class CampaignSourcePreviewRequest(BaseModel):
    """A source that does not exist yet, asked what it would add."""

    kind: str = Field(description="entity, story, or query")
    entity_type: str | None = Field(None, description="Entity type slug; required when kind is entity")
    ref_id: uuid.UUID | None = Field(None, description="Target UUID; omitted when kind is query")
    query: str | None = Field(None, max_length=2000, description="Query-language string; required when kind is query")

    model_config = ConfigDict(
        json_schema_extra={"example": {"kind": "query", "query": 'malware:"Akira" AND date:>30d'}}
    )


class CampaignSourcePreviewEntry(BaseModel):
    entry_id: uuid.UUID
    title: str | None = None
    published_at: datetime | None = None


class CampaignSourcePreview(BaseModel):
    """A dry run: what following this would pull in, before the row exists."""

    kind: str
    entity_type: str | None = None
    ref_id: uuid.UUID | None = None
    query: str | None = None
    label: str = Field("", description="What the source would be called once created")
    would_add: int = Field(description="Articles it claims that the campaign does not already hold")
    already_held: int = Field(description="Articles it claims that the campaign already has — overlap, not waste")
    preview: list[CampaignSourcePreviewEntry] = Field(
        default_factory=list, description="The newest few it would add, by name"
    )
    error: str | None = Field(None, description="Why the query could not be run, when it could not be parsed")
    unknown_fields: list[str] = Field(
        default_factory=list,
        description=(
            "Field names the query language does not have. Not fatal — they become text terms — "
            "but on a standing source a typo'd field answers plausibly forever."
        ),
    )


class CampaignSourceOptions(BaseModel):
    """What the campaign page's intake pickers are allowed to offer."""

    kinds: list[str] = Field(description="Every source kind the API accepts")
    followable_entity_types: list[str] = Field(
        description="Entity types that own articles — a source on anything else would never add any"
    )
    pickable_entity_types: list[str] = Field(
        description="Followable types that are also findable by name through /api/intelligence/search"
    )


class CampaignSourceResponse(BaseModel):
    id: uuid.UUID
    campaign_id: uuid.UUID
    kind: str
    entity_type: str | None
    ref_id: uuid.UUID | None = Field(None, description="Null for a query source, which targets no single row")
    query: str | None = Field(None, description="The query-language string, when kind is query")
    label: str = Field(description="The target's name at link time — stays readable if it is later renamed")
    auto_sync: bool
    last_synced_at: datetime | None
    entries_added: int
    created_at: datetime

    model_config = {"from_attributes": True}
