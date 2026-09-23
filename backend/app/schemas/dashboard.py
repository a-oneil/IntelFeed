import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class DashboardCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    is_default: bool = False

    model_config = ConfigDict(json_schema_extra={"example": {"name": "Threat Landscape", "is_default": True}})


class DashboardUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    is_default: bool | None = None

    model_config = ConfigDict(json_schema_extra={"example": {"name": "Ransomware Watch", "is_default": False}})


class WidgetCreate(BaseModel):
    widget_type: str = Field(min_length=1, max_length=50)
    title: str | None = None
    config: dict = Field(default_factory=dict)
    position_x: int = 0
    position_y: int = 0
    width: int = 4
    height: int = 3

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "widget_type": "trending-cves",
                "title": "Trending CVEs",
                "config": {"limit": 10},
                "position_x": 0,
                "position_y": 0,
                "width": 6,
                "height": 4,
            }
        }
    )


class WidgetUpdate(BaseModel):
    title: str | None = None
    config: dict | None = None
    position_x: int | None = None
    position_y: int | None = None
    width: int | None = None
    height: int | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"title": "Trending CVEs (30d)", "config": {"limit": 20}, "width": 8, "height": 4}
        }
    )


class WidgetPositionItem(BaseModel):
    id: uuid.UUID
    position_x: int
    position_y: int
    width: int
    height: int


class LayoutUpdate(BaseModel):
    items: list[WidgetPositionItem] = Field(min_length=1)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "items": [
                    {
                        "id": "d5b2c3a4-1f2e-4a5b-9c8d-7e6f5a4b3c2d",
                        "position_x": 0,
                        "position_y": 0,
                        "width": 6,
                        "height": 4,
                    }
                ]
            }
        }
    )


class WidgetResponse(BaseModel):
    id: uuid.UUID
    dashboard_id: uuid.UUID
    widget_type: str
    title: str | None
    config: dict
    position_x: int
    position_y: int
    width: int
    height: int

    model_config = {"from_attributes": True}


class DashboardResponse(BaseModel):
    id: uuid.UUID
    created_by: uuid.UUID | None
    name: str
    is_default: bool
    sort_order: int = 0
    created_at: datetime
    widgets: list[WidgetResponse] = []

    model_config = {"from_attributes": True}
