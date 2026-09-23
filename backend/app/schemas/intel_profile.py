import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class IntelProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    country_ids: list[uuid.UUID] = []
    sectors: list[str] = []
    window_days: int = Field(default=90, ge=1, le=730)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "FinServ & Healthcare portfolio",
                "description": "US/DE/SG clients in financial services and healthcare",
                "country_ids": ["d5b2f1c8-3a4e-4b6d-9c2f-8e7a1b3c5d4e"],
                "sectors": ["financial-services", "healthcare"],
                "window_days": 90,
            }
        }
    )


class IntelProfileUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    country_ids: list[uuid.UUID] | None = None
    sectors: list[str] | None = None
    window_days: int | None = Field(default=None, ge=1, le=730)


class IntelProfileResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    country_ids: list[uuid.UUID]
    countries: list[dict] = []  # [{id, name}] resolved for display
    sectors: list[str]
    sector_labels: list[str] = []
    window_days: int
    curation: dict
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ThreatSurfaceRequest(BaseModel):
    """Preview a threat surface for an ad-hoc scope (no saved profile needed)."""

    country_ids: list[uuid.UUID] = []
    sectors: list[str] = []
    window_days: int = Field(default=90, ge=1, le=730)
    limit: int = Field(default=25, ge=1, le=100)
