import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AutomationRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    trigger_type: str = Field(
        pattern=r"^(on_new_entry|on_schedule|on_keyword_match"
        r"|on_cve_detected|on_manual|on_correlation_event|on_entry_scored|on_observable_captured)$"
    )
    trigger_config: dict = {}
    conditions: dict = {}
    actions: list[dict] = Field(min_length=1)
    labels: list[str] = []
    is_enabled: bool = True

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Flag LockBit coverage",
                "description": "Tag and prioritize new entries mentioning LockBit",
                "trigger_type": "on_keyword_match",
                "trigger_config": {"pattern": "LockBit", "is_regex": False},
                "conditions": {},
                "actions": [
                    {"type": "add_tags", "config": {"tags": ["ransomware"]}},
                    {"type": "mark_priority", "config": {}},
                ],
                "labels": ["ransomware"],
                "is_enabled": True,
            }
        }
    )


class AutomationRuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    trigger_type: str | None = Field(
        default=None,
        pattern=r"^(on_new_entry|on_schedule|on_keyword_match"
        r"|on_cve_detected|on_manual|on_correlation_event|on_entry_scored|on_observable_captured)$",
    )
    trigger_config: dict | None = None
    conditions: dict | None = None
    actions: list[dict] | None = None
    labels: list[str] | None = None
    is_enabled: bool | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "description": "Tag and prioritize new entries mentioning LockBit or its affiliates",
                "is_enabled": False,
            }
        }
    )


class AutomationRuleResponse(BaseModel):
    id: uuid.UUID
    created_by: uuid.UUID | None
    name: str
    description: str | None
    is_enabled: bool
    trigger_type: str
    trigger_config: dict
    conditions: dict
    actions: list
    labels: list[str]
    last_triggered_at: datetime | None
    run_count: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @model_validator(mode="before")
    @classmethod
    def _coerce_actions(cls, data):
        """Ensure actions is always a list (handles ORM JSON column)."""
        if hasattr(data, "__getattr__"):
            # ORM model — let from_attributes handle it
            return data
        if isinstance(data, dict):
            actions = data.get("actions")
            if actions is None:
                data["actions"] = []
        return data


class AutomationRunResponse(BaseModel):
    logs: list["AutomationLogResponse"]
    entries_evaluated: int
    entries_matched: int
    message: str


class AutomationLogResponse(BaseModel):
    id: uuid.UUID
    rule_id: uuid.UUID
    entry_id: uuid.UUID | None
    trigger_type: str
    status: str
    actions_executed: list
    error_message: str | None
    executed_at: datetime
    rule_name: str | None = None

    model_config = {"from_attributes": True}


# --- Import / Export ---


VALID_TRIGGER_TYPES = {
    "on_new_entry",
    "on_schedule",
    "on_keyword_match",
    "on_cve_detected",
    "on_manual",
    "on_correlation_event",
    "on_entry_scored",
    "on_observable_captured",
}

VALID_ACTION_TYPES = {
    "run_ai_task",
    "use_daily_summary",
    "add_tags",
    "remove_tags",
    "send_notification",
    "send_email",
    "run_webhook",
    "mark_priority",
    "mark_read",
    "star_entry",
    "bookmark_entry",
    "hide_entry",
    "create_note",
    "extract_ttps",
    "extract_cves",
    "extract_threat_actors",
    "extract_malware",
    "generate_detection_rules",
    "add_to_campaign",
    "create_intel_report",
    "chain_rule",
    "track_on_threat_board",
    "branch",
}


class RuleExportItem(BaseModel):
    name: str
    description: str | None = None
    trigger_type: str
    trigger_config: dict = {}
    conditions: dict = {}
    actions: list[dict] = []
    labels: list[str] = []


class RuleExportMetadata(BaseModel):
    version: int = 1
    exported_at: datetime
    source_instance: str | None = None


class RuleExportPayload(BaseModel):
    intelfeed_rule_export: RuleExportMetadata
    rules: list[RuleExportItem] = Field(min_length=1)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "intelfeed_rule_export": {
                    "version": 1,
                    "exported_at": "2026-08-27T12:00:00Z",
                    "source_instance": None,
                },
                "rules": [
                    {
                        "name": "Flag LockBit coverage",
                        "description": "Tag and prioritize new entries mentioning LockBit",
                        "trigger_type": "on_keyword_match",
                        "trigger_config": {"pattern": "LockBit", "is_regex": False},
                        "conditions": {},
                        "actions": [{"type": "add_tags", "config": {"tags": ["ransomware"]}}],
                        "labels": ["ransomware"],
                    }
                ],
            }
        }
    )


class RuleImportResponse(BaseModel):
    imported: int
    skipped: int
    errors: list[str]
    warnings: list[str] = []
    rules: list[AutomationRuleResponse]
