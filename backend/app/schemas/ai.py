import uuid
from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# --- AI Provider Schemas ---


def _check_provider_config(config: dict | None) -> dict | None:
    """Reject config the provider would choke on at call time instead of save time.

    ``extra_body`` is merged into every request with ``dict.update``: an array or
    a string saves fine and then fails every completion on that provider.
    """
    if not config:
        return config
    scopes = [("config", config)]
    overrides = config.get("model_overrides")
    if overrides is not None and not isinstance(overrides, dict):
        raise ValueError("config.model_overrides must be a JSON object keyed by model name")
    scopes += [(f"config.model_overrides[{name!r}]", o) for name, o in (overrides or {}).items() if isinstance(o, dict)]
    for where, scope in scopes:
        for key in ("extra_body", "extra_headers"):
            if scope.get(key) is not None and not isinstance(scope[key], dict):
                raise ValueError(f"{where}.{key} must be a JSON object")
    return config


class AIProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    # claude_code is accepted by the schema so the route can say why it is
    # refused (one CLI sign-in for the whole instance) instead of a bare 422.
    provider_type: str = Field(default="claude", pattern=r"^(claude|claude_code|ollama|openai_compatible)$")
    base_url: str | None = None
    api_key: str | None = None  # plaintext, encrypted before storage
    config: dict = {}
    # A personal key: owned by the caller, routed only by them. Non-admins
    # can only create these; an admin picks.
    personal: bool = False

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

    _config_shape = field_validator("config")(_check_provider_config)

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

    _config_shape = field_validator("config")(_check_provider_config)

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
    # None = the instance's provider. Set = a personal key, the caller's own
    # unless this came from the admin's user-keys listing.
    user_id: uuid.UUID | None = None
    owner_username: str | None = None
    # Whether this provider type can execute tool calls (agent harness).
    supports_tools: bool = False
    paused_until: datetime | None = None
    paused_reason: str | None = None
    # Outcome of the last connectivity test; error None = it passed.
    last_tested_at: datetime | None = None
    last_test_error: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AIProviderTestResult(BaseModel):
    success: bool
    message: str
    models: list[str] = []


class AIProviderCommissionResult(BaseModel):
    """The outcome of making a provider the one that actually runs the AI tasks."""

    success: bool
    # Straight from the provider: a real connectivity check ran, so a failure
    # here can say what went wrong instead of guessing at the cause.
    message: str
    models: list[str] = []
    # The model the assignments were given, resolved against the live model list.
    model: str | None = None
    tasks_assigned: int = 0
    tasks_reassigned: int = 0
    # Agentic tasks left where they were because this provider can't run tools.
    # Not a failure — a plain chat provider would return merges it never applied.
    tasks_skipped_agentic: list[str] = []


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
    # Whether a person's own key may answer this task, and whether the admin
    # can change that (pipeline tasks are locked to the instance's providers).
    allows_user_provider: bool = False
    user_provider_locked: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


class AITaskUpdate(BaseModel):
    """Partial update for reader AI-panel presentation of a task."""

    show_in_entry_actions: bool | None = None
    entry_action_order: int | None = None
    show_in_entity_actions: bool | None = None
    # Open or close the task to personal keys. 403 on a locked task.
    allows_user_provider: bool | None = None
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
    # Who asked and who answered. provider_name survives the provider row;
    # key_owner_id set = a personal key paid for this result.
    caller_kind: str | None = None
    user_id: uuid.UUID | None = None
    key_owner_id: uuid.UUID | None = None
    provider_name: str | None = None
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


class AICallerCostRow(BaseModel):
    """Spend over the trailing 30 days for one principal.

    One row per person (``caller_kind == "user"``), plus one each for the
    pipeline, automation rules and share links, which never bill a person.
    Rows written before attribution existed are one ``unattributed`` row.
    """

    caller_kind: str  # user | system | automation | share | unattributed
    user_id: uuid.UUID | None = None
    username: str | None = None
    requests: int
    tokens_input: int
    tokens_output: int
    # Spend on the instance's own providers (key_owner_id IS NULL) — what the
    # operator pays — versus on a personal key, which the operator does not.
    instance_cost: Decimal
    own_key_cost: Decimal
    # Calls on a personal key, so a person on an unpriced key (Ollama) still
    # shows as using one when the dollar figure is zero.
    own_key_requests: int = 0
    # Calls today on the instance's own providers: what the per-user daily
    # allowance (site_ai_user_daily_requests) counts.
    requests_today: int = 0


class AICostBreakdown(BaseModel):
    total_cost_30d: Decimal
    total_requests_30d: int
    total_tokens_30d: dict[str, int]
    # The headline split: the operator's bill versus spend on users' own keys.
    instance_cost_30d: Decimal = Decimal("0")
    user_key_cost_30d: Decimal = Decimal("0")
    # Requests that came in at $0 (Ollama, unpriced endpoints), so a low
    # dollar figure isn't mistaken for low usage.
    unpriced_requests_30d: int = 0
    # The per-user daily allowance each person's requests_today is measured
    # against; 0 = unlimited.
    site_allowance_per_user: int = 0
    by_task: list[AICostBreakdownRow]
    by_model: list[AICostBreakdownRow]
    by_caller: list[AICallerCostRow] = []
    budgets: list[AITaskBudgetRow]


# --- Personal AI (Settings → My AI) ---


class UserAIRouteUpsert(BaseModel):
    """Point one task, or every allowed task (task_id null), at one of my keys.

    A per-task route with ``provider_id`` null sends that task back to the
    instance's provider even though a default key exists.
    """

    task_id: uuid.UUID | None = None
    provider_id: uuid.UUID | None = None
    model_name: str | None = Field(default=None, min_length=1, max_length=100)
    config: dict = {}

    # Same shape rules as a provider's config: the two are merged at call time.
    _config_shape = field_validator("config")(_check_provider_config)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_id": None,
                "provider_id": "d5b2c8a4-3f1e-4b6a-9c2d-8e7f6a5b4c3d",
                "model_name": "anthropic/claude-sonnet-4.6",
                "config": {},
            }
        }
    )


class UserAIRouteResponse(BaseModel):
    id: uuid.UUID
    task_id: uuid.UUID | None
    task_name: str | None = None
    # Both null = this task is routed to the instance's provider by choice.
    provider_id: uuid.UUID | None
    provider_name: str | None = None
    model_name: str | None
    config: dict
    updated_at: datetime

    model_config = {"from_attributes": True}


class UserAIPreferencesUpdate(BaseModel):
    fallback_to_site: bool | None = None
    # The person's own monthly cap on their keys' spend; the admin sets none.
    # Explicit null = no cap. Must be a real cap: zero would read as
    # "unlimited" too, so it is refused rather than stored.
    monthly_cap_usd: Decimal | None = Field(default=None, gt=0)


class UserAIPolicy(BaseModel):
    """What the admin allows, as the My AI page needs it."""

    allow_user_ai_providers: bool
    require_user_ai_provider: bool
    provider_types: list[str]
    allow_private_endpoints: bool
    daily_request_cap: int
    site_allowance_per_user: int


class UserAIPolicyStatus(UserAIPolicy):
    """The policy plus whether this person has set up any routing.

    What a reader panel needs to decide whether personal keys can touch
    the tasks it shows, before it pays for the full overview.
    """

    has_routes: bool


class UserAIKeyUsage(BaseModel):
    provider_id: uuid.UUID
    provider_name: str
    provider_type: str
    month_cost: Decimal
    month_requests: int


class UserAIUsage(BaseModel):
    """This person's AI spend, split by whose provider answered."""

    month_cost: Decimal
    monthly_cap_usd: Decimal
    requests_today: int
    daily_request_cap: int
    site_requests_today: int
    site_allowance_per_user: int
    month_resets_at: datetime
    by_key: list[UserAIKeyUsage] = []


class UserAITaskRow(BaseModel):
    """One task a person may route, with where it runs now."""

    task_id: uuid.UUID
    task_name: str
    display_name: str
    category: str | None
    requires_tools: bool
    site_provider_name: str | None
    site_model_name: str | None
    route: UserAIRouteResponse | None
    month_cost: Decimal
    # What a click would do right now, by the same rule as the lookup: the
    # person's key answers ("user"), the instance's provider does ("site",
    # with ``blocked_reason`` set when a key of theirs could not), or the
    # call is refused ("refused": Required policy, or fallback turned off).
    will_run_on: Literal["user", "site", "refused"] = "site"
    blocked_reason: str | None = None


class UserAIOverview(BaseModel):
    policy: UserAIPolicy
    fallback_to_site: bool
    monthly_cap_usd: Decimal | None
    usage: UserAIUsage
    tasks: list[UserAITaskRow]
    # The person's default key (task_id null), listed on its own because a
    # task row only carries it when the task has no route of its own.
    default_route: UserAIRouteResponse | None = None
