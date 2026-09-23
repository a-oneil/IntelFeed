import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

NIST_CSF_CATEGORIES = {"govern", "identify", "protect", "detect", "respond", "recover"}

NIST_CSF_COLORS = {
    "govern": "#6366f1",
    "identify": "#3b82f6",
    "protect": "#22c55e",
    "detect": "#f59e0b",
    "respond": "#ef4444",
    "recover": "#8b5cf6",
}


class TechnologyRef(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    url: str | None = Field(default=None, max_length=2000)


class GlossaryTermCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    category: str = Field(min_length=1, max_length=50)
    maturity: str | None = Field(default=None, pattern=r"^(emerging|trending|mature)$")
    description: str = Field(min_length=1, max_length=2000)
    long_description: str | None = Field(default=None, max_length=10000)
    technologies: list[TechnologyRef] = Field(default_factory=list)
    search_terms: list[str] = Field(default_factory=list)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "EDR",
                "category": "detect",
                "maturity": "mature",
                "description": "Endpoint telemetry collection with detection and response capabilities.",
                "technologies": [{"name": "CrowdStrike Falcon", "url": "https://www.crowdstrike.com/platform/"}],
                "search_terms": ["endpoint detection and response"],
            }
        }
    )


class GlossaryTermUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    category: str | None = Field(default=None, min_length=1, max_length=50)
    maturity: str | None = Field(default=None, pattern=r"^(emerging|trending|mature)$")
    description: str | None = Field(default=None, min_length=1, max_length=2000)
    long_description: str | None = Field(default=None, max_length=10000)
    technologies: list[TechnologyRef] | None = None
    search_terms: list[str] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "maturity": "trending",
                "search_terms": ["endpoint detection and response", "endpoint detection & response"],
            }
        }
    )


class GlossaryTermResponse(BaseModel):
    id: uuid.UUID
    name: str
    category: str
    maturity: str | None
    description: str
    long_description: str | None
    technologies: list[TechnologyRef]
    search_terms: list[str]
    is_system: bool
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class GlossaryMatchResponse(BaseModel):
    term: GlossaryTermResponse
    match_count: int


class DetectRequest(BaseModel):
    entry_id: uuid.UUID

    model_config = ConfigDict(json_schema_extra={"example": {"entry_id": "d5b2f1c8-3a4e-4b6d-9c2f-8e7a1b3c5d4e"}})


class GlossaryCategoryResponse(BaseModel):
    name: str
    is_nist: bool
    color: str
