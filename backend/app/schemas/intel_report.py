import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class IntelReportCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    template_type: str = Field(pattern=r"^[a-z][a-z0-9_]{1,49}$")
    tlp_marking: str = Field(default="TLP:GREEN", pattern=r"^TLP:(CLEAR|GREEN|AMBER|AMBER\+STRICT|RED)$")
    content: dict = {}
    summary: str | None = None
    entry_ids: list[uuid.UUID] = []
    entity_ids: dict = {}
    tags: list[str] = []

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "title": "Flash Alert: CVE-2024-3400 active exploitation",
                "template_type": "flash_alert",
                "tlp_marking": "TLP:AMBER",
                "summary": "Active exploitation of Palo Alto GlobalProtect (CVE-2024-3400) observed in the wild",
                "entry_ids": ["d5b2f1c8-3a4e-4b6d-9c2f-8e7a1b3c5d4e"],
                "tags": ["cve", "exploitation"],
            }
        }
    )


class IntelReportUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=500)
    tlp_marking: str | None = Field(default=None, pattern=r"^TLP:(CLEAR|GREEN|AMBER|AMBER\+STRICT|RED)$")
    status: str | None = Field(default=None, pattern=r"^(draft|published|archived)$")
    content: dict | None = None
    summary: str | None = None
    entry_ids: list[uuid.UUID] | None = None
    entity_ids: dict | None = None
    tags: list[str] | None = None
    change_description: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "published",
                "summary": "Final version after peer review",
                "change_description": "Incorporated review feedback and updated IOC table",
            }
        }
    )


class IntelReportResponse(BaseModel):
    id: uuid.UUID
    created_by: uuid.UUID | None
    title: str
    template_type: str
    tlp_marking: str
    status: str
    content: dict
    summary: str | None
    version: int
    entry_ids: list[uuid.UUID]
    entity_ids: dict
    tags: list[str]
    created_at: datetime
    updated_at: datetime
    published_at: datetime | None

    model_config = {"from_attributes": True}


class IntelReportVersionResponse(BaseModel):
    id: uuid.UUID
    report_id: uuid.UUID
    version: int
    content: dict
    change_description: str | None
    created_by: uuid.UUID
    created_at: datetime

    model_config = {"from_attributes": True}


class IntelReportFullGenerate(BaseModel):
    source_type: Literal["entry", "entries", "search", "saved_search"]
    entry_id: uuid.UUID | None = None
    entry_ids: list[uuid.UUID] | None = None
    search_query: str | None = None
    saved_search_id: uuid.UUID | None = None
    search_limit: int = Field(default=50, ge=1, le=200)

    template_type: str = Field(pattern=r"^[a-z][a-z0-9_]{1,49}$")
    title: str | None = Field(default=None, min_length=1, max_length=500)
    tlp_marking: str = Field(default="TLP:GREEN", pattern=r"^TLP:(CLEAR|GREEN|AMBER|AMBER\+STRICT|RED)$")
    focus: str | None = Field(default=None, max_length=1000)
    audience: str | None = Field(default=None, max_length=500)
    tags: list[str] = []

    @model_validator(mode="after")
    def validate_source(self):
        if self.source_type == "entry" and not self.entry_id:
            raise ValueError("entry_id is required when source_type is 'entry'")
        if self.source_type == "entries" and (not self.entry_ids or len(self.entry_ids) == 0):
            raise ValueError("entry_ids is required and must not be empty when source_type is 'entries'")
        if self.source_type == "search" and not self.search_query:
            raise ValueError("search_query is required when source_type is 'search'")
        if self.source_type == "saved_search" and not self.saved_search_id:
            raise ValueError("saved_search_id is required when source_type is 'saved_search'")
        return self

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source_type": "search",
                "search_query": "LockBit healthcare",
                "search_limit": 50,
                "template_type": "campaign_tracker",
                "title": "LockBit Healthcare Campaign Tracker",
                "tlp_marking": "TLP:AMBER",
                "focus": "Initial access vectors and extortion timeline",
                "audience": "SOC analysts",
                "tags": ["ransomware", "healthcare"],
            }
        }
    )


class IntelReportGenerate(BaseModel):
    template_type: str = Field(pattern=r"^[a-z][a-z0-9_]{1,49}$")
    entry_ids: list[uuid.UUID] = []
    entity_ids: dict = {}
    title: str | None = Field(default=None, min_length=1, max_length=500)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "template_type": "actor_profile",
                "entry_ids": ["d5b2f1c8-3a4e-4b6d-9c2f-8e7a1b3c5d4e"],
                "entity_ids": {"actors": ["7c1e9a3b-2d4f-4a6c-8e0b-5f3d1c9a7e2b"]},
                "title": "APT29 Actor Profile",
            }
        }
    )


class IntelReportExposureGenerate(BaseModel):
    """Build an exposure report from a saved intel profile plus the analyst's
    keep/drop curation of the matched threat surface."""

    profile_id: uuid.UUID
    title: str | None = Field(default=None, max_length=500)
    tlp_marking: str = Field(default="TLP:AMBER", pattern=r"^TLP:(CLEAR|GREEN|AMBER|AMBER\+STRICT|RED)$")
    actor_ids: list[uuid.UUID] = []
    malware_ids: list[uuid.UUID] = []
    dropped_actor_ids: list[uuid.UUID] = []
    dropped_malware_ids: list[uuid.UUID] = []
    tags: list[str] = []

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "profile_id": "d5b2f1c8-3a4e-4b6d-9c2f-8e7a1b3c5d4e",
                "title": "Exposure — FinServ & Healthcare portfolio · Sep",
                "tlp_marking": "TLP:AMBER",
                "actor_ids": ["0b9a4c2d-1e3f-4a5b-8c7d-9e0f1a2b3c4d"],
            }
        }
    )


class IntelReportAttach(BaseModel):
    """Append evidence to an existing report (send-to-report / report tray)."""

    entry_ids: list[uuid.UUID] = []
    entity_ids: dict = {}
    note: str | None = Field(
        None,
        max_length=4000,
        description=(
            "Prose to seed the detections section body — the sender's commentary on the "
            "evidence, e.g. a coverage set's skipped rules rendered as known gaps. "
            "Never overwrites a body an analyst has already written."
        ),
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entry_ids": ["d5b2f1c8-3a4e-4b6d-9c2f-8e7a1b3c5d4e"],
                "entity_ids": {
                    "actors": ["0b9a4c2d-1e3f-4a5b-8c7d-9e0f1a2b3c4d"],
                    "detection_rules": ["3421400a-30cb-4f0c-b05e-86289a2e5fcc"],
                },
                "note": "Known gaps: 4 rules skipped — no scanner in the inventory.",
            }
        }
    )
