import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,30}$")


def _validate_password_strength(password: str) -> str:
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters")
    return password


class RegisterRequest(BaseModel):
    username: str
    password: str = Field(..., min_length=6)
    invite_code: str | None = None

    model_config = ConfigDict(
        json_schema_extra={"example": {"username": "analyst1", "password": "hunter2secure", "invite_code": "TEAM-2026"}}
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not USERNAME_RE.match(v):
            raise ValueError("Username must be 3-30 characters, alphanumeric and underscores only")
        return v.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password_strength(v)


class LoginRequest(BaseModel):
    username: str
    password: str

    model_config = ConfigDict(json_schema_extra={"example": {"username": "analyst1", "password": "hunter2secure"}})

    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        return v.lower()


class RefreshRequest(BaseModel):
    refresh_token: str

    model_config = ConfigDict(
        json_schema_extra={"example": {"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkNWIyIn0.sig"}}
    )


class LogoutRequest(BaseModel):
    refresh_token: str | None = None

    model_config = ConfigDict(
        json_schema_extra={"example": {"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkNWIyIn0.sig"}}
    )


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    role: str
    is_active: bool
    settings: dict = {}
    theme_id: uuid.UUID | None = None
    custom_css: str | None = None
    last_login: datetime | None = None
    created_at: datetime
    # Populated by the admin users list; 0 elsewhere (not worth the join).
    feed_count: int = 0
    muted_feed_count: int = 0

    model_config = {"from_attributes": True}

    @field_validator("settings", mode="before")
    @classmethod
    def coerce_settings(cls, v: dict | None) -> dict:
        return v if v is not None else {}


class UserUpdateRequest(BaseModel):
    settings: dict | None = None

    model_config = ConfigDict(
        json_schema_extra={"example": {"settings": {"default_view": "unread", "collapse_read_entries": True}}}
    )


class UserSettingsPatch(BaseModel):
    """Partial update of the settings blob — only the top-level keys sent are touched."""

    settings: dict

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"settings": {"table_layouts": {"entries": {"columnOrder": ["title", "feed"]}}}}
        }
    )


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6)

    model_config = ConfigDict(
        json_schema_extra={"example": {"current_password": "hunter2secure", "new_password": "correct-horse-battery"}}
    )

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return _validate_password_strength(v)


class AdminUserUpdateRequest(BaseModel):
    username: str | None = None
    role: str | None = Field(None, pattern=r"^(user|admin)$")
    is_active: bool | None = None
    password: str | None = Field(None, min_length=6)

    model_config = ConfigDict(
        json_schema_extra={"example": {"username": "analyst1", "role": "admin", "is_active": True}}
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str | None) -> str | None:
        if v is not None and not USERNAME_RE.match(v):
            raise ValueError("Username must be 3-30 characters, alphanumeric and underscores only")
        return v.lower() if v else v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str | None) -> str | None:
        if v is not None and v not in ("user", "admin"):
            raise ValueError("Role must be 'user' or 'admin'")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_password_strength(v)
        return v
