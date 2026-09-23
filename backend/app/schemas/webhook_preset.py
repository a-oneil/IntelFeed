import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class WebhookPresetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    preset_type: str = "webhook"
    url: str = ""
    payload: str = "{}"
    headers: dict = {}
    config: dict = {}

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "SOC Slack channel",
                "preset_type": "webhook",
                "url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
                "payload": '{"text": "{title} — {url}"}',
                "headers": {"Content-Type": "application/json"},
                "config": {},
            }
        }
    )


class WebhookPresetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    preset_type: str | None = None
    url: str | None = None
    payload: str | None = None
    headers: dict | None = None
    config: dict | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "SOC Slack channel (urgent)",
                "payload": '{"text": ":rotating_light: {title} — {url}"}',
            }
        }
    )


class WebhookPresetResponse(BaseModel):
    id: uuid.UUID
    created_by: uuid.UUID | None
    name: str
    preset_type: str
    url: str
    payload: str
    headers: dict
    config: dict
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
