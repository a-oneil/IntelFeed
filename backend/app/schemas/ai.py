import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# --- AI Provider Schemas ---


class AIProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    provider_type: str = Field(default="claude", pattern=r"^(claude|ollama|openai_compatible)$")
    base_url: str | None = None
    api_key: str | None = None  # plaintext, encrypted before storage
    config: dict = {}

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Local Ollama",
                "provider_type": "ollama",
                "base_url": "http://ollama:11434",
                "api_key": None,
                "config": {},
            }
        }
    )

    @model_validator(mode="after")
    def _openai_compatible_requires_base_url(self) -> "AIProviderCreate":
        if self.provider_type == "openai_compatible" and not (self.base_url and self.base_url.strip()):
            raise ValueError("openai_compatible provider requires a non-empty base_url")
        return self


class AIProviderUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    base_url: str | None = None
    api_key: str | None = None
    is_active: bool | None = None
    config: dict | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Anthropic Claude",
                "api_key": "sk-ant-api03-EXAMPLE-KEY",
                "is_active": True,
            }
        }
    )


class AIProviderResponse(BaseModel):
    id: uuid.UUID
    name: str
    provider_type: str
    base_url: str | None
    models: list
    is_active: bool
    config: dict
    # Whether this provider type can execute tool calls (agent harness).
    supports_tools: bool = False
    paused_until: datetime | None = None
    paused_reason: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AIProviderTestResult(BaseModel):
    success: bool
    message: str
    models: list[str] = []


# --- AI Task Schemas ---


class AITaskCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    display_name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    category: str | None = None
    default_prompt_template: str = Field(min_length=1)
    default_system_template: str | None = None
    output_schema: dict | None = None
    variables: list[str] = Field(default_factory=list)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "ransomware_victim_summary",
                "display_name": "Ransomware Victim Summary",
                "description": "Summarize ransomware victimology described in an article.",
                "category": "custom",
                "default_prompt_template": (
                    "Summarize the ransomware victims described in this article:\n\n{{ entry.content }}"
                ),
                "default_system_template": "You are a threat intelligence analyst.",
                "output_schema": {
                    "type": "object",
                    "properties": {
                        "summary": {"type": "string"},
                        "victim_sectors": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["summary"],
                },
                "variables": ["entry"],
            }
        }
    )


class AITaskResponse(BaseModel):
    is_deprecated: bool = False
    id: uuid.UUID
    name: str
    display_name: str
    description: str | None
    category: str | None
    variables: list[str]
    # Structured-output contract: the shipped default and the UI-set override
    # (None = using the default). Providers use override ?? default.
    output_schema: dict | None = None
    output_schema_override: dict | None = None
    is_system: bool
    # Agentic tasks that only work on a tool-capable provider (claude_code).
    requires_tools: bool = False
    show_in_entry_actions: bool = True
    entry_action_order: int | None = None
    show_in_entity_actions: bool = True
    created_at: datetime

    model_config = {"from_attributes": True}


class AITaskUpdate(BaseModel):
    """Partial update for reader AI-panel presentation of a task."""

    show_in_entry_actions: bool | None = None
    entry_action_order: int | None = None
    show_in_entity_actions: bool | None = None
    # Regrouping is only offered for custom tasks in the UI; the API enforces it.
    category: str | None = Field(default=None, max_length=50)
    # Custom tasks only: their schema is user-owned and edited in place
    # (explicit null makes the task free-form). 403 for system tasks.
    output_schema: dict | None = None
    # Explicit null clears the override (back to the shipped default);
    # omitting the field leaves it untouched (exclude_unset distinguishes).
    output_schema_override: dict | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "show_in_entry_actions": True,
                "entry_action_order": 2,
                "show_in_entity_actions": False,
            }
        }
    )


# --- AI Task Assignment Schemas ---


class AITaskAssignmentCreate(BaseModel):
    provider_id: uuid.UUID
    model_name: str = Field(min_length=1, max_length=100)
    is_enabled: bool = True
    # None = leave the stored config untouched on upsert. Callers that omit
    # config (enable toggles, model swaps) must not wipe keys like max_tokens
    # or copilot's allowed_tools.
    config: dict | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "provider_id": "d5b2c8a4-3f1e-4b6a-9c2d-8e7f6a5b4c3d",
                "model_name": "qwen3.5:9b",
                "is_enabled": True,
                "config": {"max_tokens": 4096},
            }
        }
    )


class AITaskAssignmentResponse(BaseModel):
    id: uuid.UUID
    created_by: uuid.UUID | None
    task_id: uuid.UUID
    provider_id: uuid.UUID
    model_name: str
    is_enabled: bool
    config: dict
    # Populated fields
    task_name: str | None = None
    provider_name: str | None = None

    model_config = {"from_attributes": True}


# --- AI Prompt Template Schemas ---


class AIPromptTemplateUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    template_text: str | None = Field(default=None, min_length=1)
    # Pass an empty string to clear the system block; omit (None) to leave
    # whatever's currently stored unchanged.
    system_text: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "TTP Extraction v2",
                "template_text": (
                    "Extract MITRE ATT&CK techniques (e.g. T1566.001) from this article:\n\n{{ entry.content }}"
                ),
                "system_text": "You are a detection engineer mapping reports to ATT&CK.",
            }
        }
    )


class AIPromptPreviewRequest(BaseModel):
    # Templates come from the live editor so unsaved edits preview too.
    # Both optional so either block can be previewed alone.
    system_text: str | None = None
    template_text: str | None = None
    # Render `entry` from a specific entry instead of the most recent one.
    entry_id: uuid.UUID | None = None
    # Force the built-in placeholder entry even when real entries exist.
    use_sample: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "system_text": "You are a threat intelligence analyst.",
                "template_text": "Summarize this article:\n\n{{ entry.content }}",
                "entry_id": "0f8e7d6c-5b4a-4392-8170-6e5d4c3b2a19",
                "use_sample": False,
            }
        }
    )


class AIPromptPreviewResponse(BaseModel):
    rendered_system: str | None = None
    rendered_user: str | None = None
    sample_source: str  # "entry" | "placeholder"
    # On a Jinja error these are populated instead of the rendered fields.
    error: str | None = None
    line: int | None = None


class AIPromptTemplateResponse(BaseModel):
    id: uuid.UUID
    task_id: uuid.UUID
    created_by: uuid.UUID | None
    name: str
    template_text: str
    system_text: str | None = None
    variables: list
    is_active: bool
    version: int
    created_at: datetime

    model_config = {"from_attributes": True}


# --- AI Result / Cost Schemas ---


class AIResultResponse(BaseModel):
    id: uuid.UUID
    entry_id: uuid.UUID | None
    target_type: str | None = None
    target_id: uuid.UUID | None = None
    is_current: bool = True
    task_id: uuid.UUID
    task_name: str | None = None
    provider_id: uuid.UUID | None
    model_name: str | None
    parsed_result: dict | None
    tokens_input: int | None
    tokens_output: int | None
    cost_estimate: Decimal | None
    processing_time_ms: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AIRunRequest(BaseModel):
    entry_id: uuid.UUID
    force: bool = False


class AIRunEntityRequest(BaseModel):
    task_name: str = Field(min_length=1)
    force: bool = False
    focus: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_name": "entity_overview",
                "force": False,
                "focus": "recent ransomware activity in Europe",
            }
        }
    )


class AIRunBatchRequest(BaseModel):
    entry_ids: list[uuid.UUID] = Field(min_length=1, max_length=25)


class AICostSummary(BaseModel):
    total_cost_30d: Decimal
    cost_by_provider: dict[str, Decimal]
    cost_by_task: dict[str, Decimal]
    total_requests_30d: int
    total_tokens_30d: dict[str, int]


# --- Extended Cost Breakdown Schemas ---


class AICostBreakdownRow(BaseModel):
    """One grouped row of spend over the trailing 30 days."""

    label: str  # task display name or model name
    requests: int
    tokens_input: int
    tokens_output: int
    cost: Decimal


class AITaskBudgetRow(BaseModel):
    """Per-task-assignment budget vs. current 30d spend."""

    task_id: uuid.UUID
    task_name: str
    display_name: str
    provider_name: str | None = None
    model_name: str | None = None
    max_budget_usd: Decimal | None = None
    spend_30d: Decimal
    requests_30d: int
    # Fraction of budget consumed (0..∞), or None when no budget is set.
    percent_of_budget: float | None = None


class AICostBreakdown(BaseModel):
    total_cost_30d: Decimal
    total_requests_30d: int
    total_tokens_30d: dict[str, int]
    by_task: list[AICostBreakdownRow]
    by_model: list[AICostBreakdownRow]
    budgets: list[AITaskBudgetRow]
