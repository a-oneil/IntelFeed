import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SearchQuery(BaseModel):
    q: str = ""
    feed_id: list[uuid.UUID] | None = None
    category_id: list[uuid.UUID] | None = None
    feed_type: list[str] | None = None
    tags: list[str] | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    is_read: bool | None = None
    is_starred: bool | None = None
    is_bookmarked: bool | None = None
    has_notes: bool | None = None
    media_type: str | None = None
    sort: str = Field(default="relevance", pattern="^(relevance|newest|oldest|title_asc|title_desc)$")
    limit: int = Field(default=20, ge=1, le=500)
    offset: int = Field(default=0, ge=0)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "q": "LockBit ransomware",
                "feed_type": ["rss"],
                "tags": ["ransomware"],
                "date_from": "2026-08-01T00:00:00Z",
                "is_read": False,
                "sort": "newest",
                "limit": 20,
                "offset": 0,
            }
        }
    )


class SearchHit(BaseModel):
    model_config = {"extra": "allow"}

    id: str
    title: str
    content_text: str | None = None
    author: str | None = None
    feed_title: str | None = None
    feed_id: str | None = None
    feed_type: str | None = None
    published_at: str | None = None
    url: str | None = None
    tags: list[str] = []


class SearchResponse(BaseModel):
    hits: list[dict]
    query: str
    processingTimeMs: int = 0
    estimatedTotalHits: int = 0
    facetDistribution: dict | None = None
    searchUnavailable: bool = False


# ── Unified search schemas ─────────────────────────────


class UnifiedSearchQuery(BaseModel):
    q: str = ""
    limit: int = Field(default=20, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
    # How many entities the intelligence half may return in total. The default
    # matches what the workbench's own /intelligence/search asks for, so the two
    # surfaces can no longer disagree about how much of the graph matched.
    entity_limit: int = Field(default=200, ge=0, le=500)
    # Rows rendered per entity type before the UI's "show all" takes over.
    # Applied AFTER `counts` is computed, so the per-type totals stay honest
    # even though the payload is trimmed.
    entity_group_limit: int = Field(default=25, ge=1, le=500)
    # Drop the entries this user has already read, and count only the rest.
    # Not `is:unread`, which filters on the index's own read flag: that flag is
    # one value shared by every user, while this is the caller's own state.
    hide_read: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "q": "threat_actor:APT29 cve.severity:critical date:>2026-01-01",
                "limit": 20,
                "offset": 0,
                "entity_limit": 200,
                "entity_group_limit": 25,
                "hide_read": False,
            }
        }
    )


class ParsedFilterSchema(BaseModel):
    field: str
    value: str
    exact: bool = False
    negated: bool = False
    raw: str = ""


class EntrySearchResults(BaseModel):
    hits: list[dict] = []
    estimatedTotalHits: int = 0
    facetDistribution: dict | None = None


class EntitySearchResults(BaseModel):
    items: list[dict] = []
    counts: dict[str, int] = Field(default_factory=dict)


class UnifiedSearchResponse(BaseModel):
    entries: EntrySearchResults = Field(default_factory=EntrySearchResults)
    entities: EntitySearchResults = Field(default_factory=EntitySearchResults)
    query: str = ""
    parsed_filters: list[ParsedFilterSchema] = []
    # A corrected query, when the one submitted looks like a multi-word value that
    # split — `country:North Korea` proposing `country:"North Korea"`. Only set when
    # the extended value is a real value for that field, so it stays quiet on a
    # deliberate filter-plus-search-term like `threat_actor:APT29 ransomware`.
    did_you_mean: str | None = None
    # Field names that parsed as `name:value` but are not in the vocabulary —
    # usually a typo like `titel:`. Their values were searched as free text, and
    # saying so beats leaving the user with unexplained results.
    unknown_fields: list[str] = []
    processingTimeMs: int = 0


class SavedSearchCreate(BaseModel):
    """
    A saved search is its query plus the search UI state the query cannot say.

    Unread/total counts are computed from `query` alone. `filters` is opaque to
    the backend and carries what the search page's facet rail owns, so reopening
    a saved search reproduces the view it was saved from:

    * ``scope`` — "feeds" | "workbench" | "everything" (the "Search in" radio)
    * ``entity_type`` — entity type the intelligence results are narrowed to
    * ``match_kinds`` — subset of ["direct", "mention"]
    * ``tags`` — structured tag list, folded into ``tag:`` query tokens on open
    """

    name: str = Field(min_length=1, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    query: str | None = None
    filters: dict = Field(default_factory=dict)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "kev-ransomware",
                "display_name": "KEV Ransomware",
                "query": "ransomware cve.severity:critical is:unread",
                "filters": {
                    "scope": "everything",
                    "entity_type": None,
                    "match_kinds": ["direct", "mention"],
                },
            }
        }
    )


class SavedSearchUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    query: str | None = None
    filters: dict | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "display_name": "Ransomware (KEV only)",
                "query": "ransomware cve.severity:critical",
            }
        }
    )


class SavedSearchResponse(BaseModel):
    id: uuid.UUID
    name: str
    display_name: str | None = None
    query: str | None
    filters: dict
    unread_count: int = 0
    total_count: int = 0
    created_at: datetime

    model_config = {"from_attributes": True}
