import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ThemeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    css_variables: dict

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Midnight Analyst",
                "css_variables": {
                    "--bg-primary": "#0d1117",
                    "--bg-secondary": "#161b22",
                    "--text-primary": "#e6edf3",
                    "--accent-primary": "#58a6ff",
                },
            }
        }
    )


class ThemeUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    css_variables: dict | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Midnight Analyst v2",
                "css_variables": {"--bg-primary": "#0d1117", "--accent-primary": "#79c0ff"},
            }
        }
    )


class ThemeDuplicate(BaseModel):
    name: str = Field(min_length=1, max_length=100)

    model_config = ConfigDict(json_schema_extra={"example": {"name": "Midnight Analyst (copy)"}})


class ThemeResponse(BaseModel):
    id: uuid.UUID
    name: str
    css_variables: dict
    is_system: bool
    is_default: bool = False
    created_by: uuid.UUID | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ThemePreferenceUpdate(BaseModel):
    theme_id: uuid.UUID | None = None
    custom_css: str | None = None
    # Clear the user's own theme so the instance default applies to them
    clear_theme: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "theme_id": "d5b2f1c4-8a3e-4b6d-9c2f-7e1a5d4b3c2a",
                "custom_css": ":root { --font-size-base: 15px; }",
                "clear_theme": False,
            }
        }
    )
