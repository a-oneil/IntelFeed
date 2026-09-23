"""Schemas for the Atlas calendar + map analytical views."""

from __future__ import annotations

import uuid
from datetime import date

from pydantic import BaseModel


class CalendarEntityCount(BaseModel):
    type: str
    id: uuid.UUID
    name: str
    count: int


class CalendarBucket(BaseModel):
    date: date
    entry_count: int
    top_entities: list[CalendarEntityCount] | None = None


class MapBucket(BaseModel):
    country_id: uuid.UUID
    iso_code: str | None = None
    country_name: str
    region: str | None = None
    entry_count: int
    role_breakdown: dict[str, int]
