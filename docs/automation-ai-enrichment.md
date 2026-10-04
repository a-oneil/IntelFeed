# Automation, AI Providers, and Enrichment

## Overview

IntelFeed's backend integrates three closely-related subsystems that work together to automate intelligence workflows, leverage AI for content analysis, and augment entity data with external threat intelligence:

1. **Automation Engine** — User-defined rules that trigger actions when entries match conditions
2. **AI Provider System** — Pluggable LLM abstraction supporting multiple providers (Anthropic Claude API, Claude Code CLI, Ollama, custom HTTP)
3. **Enrichment Pipeline** — Pulls additional context from 10 external threat intel sources and merges results into entity profiles

All three share configuration patterns, use JSONB for flexible configs, and integrate with the async task queue (Celery) and caching layer (Redis).

---

## Part 1: Automation Engine

### Data Model

The automation engine is rooted in the `AutomationRule` model (`backend/app/models/automation_rule.py:11-31`), which defines executable intelligence workflows:

```python
class AutomationRule(Base):
    id: UUID                        # Primary key
    created_by: UUID | None         # User who created this rule
    name: str                        # Display name
    description: str | None         # Long description
    is_enabled: bool = True         # Enable/disable toggle
    trigger_type: str               # on_new_entry, on_keyword_match, on_cve_detected, on_correlation_event
    trigger_config: dict            # Trigger-specific params (pattern, min_severity, etc.)
    conditions: dict                # Nested AND/OR logic tree
    actions: list[dict]             # Sequential actions to execute
    labels: list                    # Custom tags for organization
    last_triggered_at: datetime     # Stats: last execution time
    run_count: int = 0              # Total executions
    created_at, updated_at: datetime # Audit fields
```

Key design:
- **Flexible JSONB storage** — Conditions and actions are unversioned, allowing evolution without migrations
- **Per-rule execution stats** — Track when rules fire and how often
- **Creator tracking** — Linked to user via foreign key for multi-tenant scenarios

### Trigger Types

Rules fire based on four trigger mechanisms (`backend/app/automation/engine.py:180-254`):

| Trigger Type | Fires When | Entry Context | Example |
|------|---|---|---|
| `on_new_entry` | Entry ingested from any feed | Always available | "Tag all RSS entries as read" |
| `on_keyword_match` | Title/content matches regex or substring | Checks entry text | "Alert when 'zero-day' appears" |
| `on_cve_detected` | Entry contains CVEs above CVSS threshold | Requires CVE extraction | "Notify on critical CVEs (CVSS>9)" |
| `on_correlation_event` | Correlation engine detects event | Event payload provided | "Block rules when new TTP detected for APT29" |
| `on_entry_scored` | Signal engine finished scoring the entry | Priority score and signals populated | "Notify on KEV adds" |
| `on_observable_captured` | A judgment door wrote observables for the entry (one-pass AI, article IOC table, analyst promote — never the indicator-feed door) | `trigger_config` = `{kinds, roles, min_confidence, exclude_infra_tagged, sources}`, same shape as `has_observable` | "Notify on new C2 infrastructure" |

Implementation notes:
- `on_new_entry` and `on_keyword_match` fire immediately during entry ingestion (synchronous)
- `on_cve_detected` requires prior CVE extraction; uses threshold logic (`engine.py:192-211`)
- `on_correlation_event` runs asynchronously when correlation events are published (`run_automations_for_correlation_event`, `engine.py:329`)
- `on_observable_captured` runs asynchronously (`run_automations_for_observable_capture`) from a Celery task the capturing door queues after its commit (`dispatch_observable_capture_automations`). It fires **once per rule per entry**: the AI door and the article-IOC-table door can both land on one article, and a rule that already logged a run for that entry is skipped. The replay backfill script never fires it.

### Condition Language

Conditions evaluate entry properties using a nested AND/OR algebra (`backend/app/automation/conditions.py`). The evaluator supports:

**Operators:**
- `AND` — All sub-conditions must be true
- `OR` — At least one sub-condition must be true
- Nesting — Groups compose recursively

**Available Conditions:**

| Condition Type | Config | Matches When |
|---|---|---|
| `feed_matches` | `feed_ids[]`, `category_ids[]` | Entry's feed is in the list |
| `content_contains` | `pattern: str`, `is_regex: bool` | Title/content/summary contains text |
| `severity_above` | `min_cvss: float` | Linked CVE exceeds CVSS threshold |
| `author_matches` | `authors: list[str]` | Entry author is in the list |
| `tag_matches` | `tags: list[str]` | Entry has at least one of the tags |
| `feed_type_matches` | `types: list[str]` | Feed type (rss, youtube, nvd, etc.) |
| `is_read` | — | Entry marked read by user |
| `is_starred` | — | Entry starred by user |
| `is_bookmarked` | — | Entry bookmarked by user |
| `has_note` | — | Entry has any user notes |

**Example condition (JSON):**
```json
{
  "operator": "AND",
  "conditions": [
    {
      "type": "feed_type_matches",
      "config": { "types": ["rss"] }
    },
    {
      "operator": "OR",
      "conditions": [
        {
          "type": "content_contains",
          "config": { "pattern": "ransomware", "is_regex": false }
        },
        {
          "type": "severity_above",
          "config": { "min_cvss": 8.0 }
        }
      ]
    }
  ]
}
```

Implementation: `evaluate_conditions()` at `conditions.py:22-53` recursively evaluates nested logic. Each condition type delegates to a handler function (`_eval_*`) which queries the DB as needed (e.g., tag_matches joins EntryTag/Tag tables).

### Actions

Actions execute sequentially and share a mutable context dict. Earlier actions can write outputs that later actions read. Key implementation: `execute_action()` at `backend/app/automation/actions.py:171`.

**Available Actions:**

| Action | Config | Effect |
|---|---|---|
| `run_ai_task` | `task_id: str` | Execute AI task; store result in context |
| `use_daily_summary` | `day: yesterday\|today = yesterday`, `on_missing: generate\|skip = generate` | Reuse the shared day-divider briefing as `{ai_summary}` instead of generating a second one (batch only) |
| `add_tags` | `tags: list[str \| {name, color, description, chip}]` | Add tags to entry. The object form sets a new tag's colour, tooltip and chip promotion — on create only; an existing tag keeps its own look. A chip tag is stamped for the rule's owner alone (only they see it); a plain tag is shared |
| `remove_tags` | `tags: list[str]` | Remove the shared tag and the rule owner's own chip stamp; other users' stamps stay |
| `send_notification` | `platform, webhook_url, channel, message_template, include_embeds` | POST to Slack/Discord/custom webhook |
| `run_webhook` | `url: str, headers: dict, payload: str` | POST custom JSON to URL |
| `mark_priority` | `level: str` | Add priority tag (priority-{level}) |
| `mark_read` | — | Mark as read for creator user |
| `star_entry` | — | Star entry |
| `bookmark_entry` | — | Bookmark entry |
| `hide_entry` | — | Hide from user's view |
| `create_note` | `title, content` | Create analyst note (supports {template_vars}) |
| `extract_ttps` | `use_ai: bool = true` | Run TTP extraction; store in context |
| `extract_cves` | — | Extract CVE references |
| `extract_threat_actors` | — | AI-identify threat actors |
| `extract_malware` | — | AI-identify malware families |
| `generate_detection_rules` | `rule_types: list[str]` | Generate SIGMA/Splunk/KQL rules from TTPs |
| `add_to_campaign` | `campaign_id: UUID, notes: str` | Link entry to campaign |
| `create_intel_report` | `title, template_type, tlp_marking, summary` | Generate intelligence report |
| `chain_rule` | `rule_id: UUID` | Trigger another rule on the same entry |
| `branch` | `condition, then_actions, else_actions` | Conditional branching (see below) |

**Context Flow Example:**
```python
# Action 1: Run AI summary task
{
  "type": "run_ai_task",
  "config": { "task_id": "article_summary" }
  # Stores context["ai_summary"] = "AI-generated text..."
  # Stores context["ai_results"]["article_summary"] = {...parsed output...}
}

# Action 2: Send notification using AI summary from Action 1
{
  "type": "send_notification",
  "config": {
    "platform": "slack",
    "webhook_url": "...",
    "message_template": "New Intel: {title}\n{ai_summary}"
    # {ai_summary} is replaced from context
  }
}
```

### Branch Actions

Branch actions enable conditional routing within a rule (handled in `_execute_action_chain`, `engine.py:27`; batch mode at `actions.py:297`):

```json
{
  "type": "branch",
  "config": {
    "condition": { "type": "severity_above", "config": { "min_cvss": 9.0 } },
    "then_actions": [
      { "type": "add_tags", "config": { "tags": ["critical"] } }
    ],
    "else_actions": [
      { "type": "add_tags", "config": { "tags": ["medium"] } }
    ]
  }
}
```

Both the branch condition and sub-action chains share the context, so outputs flow through whichever branch is taken.

### Execution Flow

**New Entry Workflow:**

```
Feed Poll → Entry Created → run_automations_for_entry()
  ↓ (async)
  Query AutomationRule where trigger_type IN ('on_new_entry', 'on_keyword_match', 'on_cve_detected')
  ↓
  For each enabled rule:
    1. Check trigger-specific condition:
       - on_new_entry: always true
       - on_keyword_match: _check_keyword_trigger(entry, rule.trigger_config)
       - on_cve_detected: _check_cve_trigger(db, entry, rule.trigger_config)
    2. If trigger matches:
       a. evaluate_conditions(db, entry, rule.conditions)
       b. If conditions pass:
          - _execute_action_chain(db, entry, rule.actions)
          - Store AutomationLog(status="success", actions_executed=[...])
       c. Else:
          - Store AutomationLog(status="skipped")
    3. Update rule.last_triggered_at, rule.run_count
  ↓
  All logs committed to DB
```

Code reference: `engine.py:213-253` implements `run_automations_for_entry()`.

**Dry-Run Mode:**

Rules can be tested without committing changes:
```python
log = await execute_automation(db, entry, rule, dry_run=True)
# log is created but NOT added to session; actions_executed show what would run
# Useful for rule preview in UI
```

**Batch Mode (Scheduled/Manual Runs):**

When running rules against multiple entries (e.g., scheduled digest at 9am), actions split into phases:

1. **Per-entry actions** — Execute on each entry individually:
   - `add_tags`, `extract_ttps`, `extract_cves`, etc.
   - Called inside a loop over `entries`

2. **Batch actions** — Execute once with all entries:
   - `send_notification` → single digest email with all entries
   - `run_ai_task` → single AI prompt covering 30 articles (e.g., morning briefing).
     **The batch is folded to one article per story first** — see below.
   - `use_daily_summary` → reads the day's already-generated briefing instead of prompting again
   - `run_webhook` → one POST with aggregated data

Reference: `actions.py:268` (`execute_actions_batch()`).

#### One article per story

A morning briefing over 30 articles where 8 are the same PaperCut story spends
most of the model's attention — and most of the reader's — saying that story
eight times. The model cannot know they are one event; it sees eight titles.

So both briefing paths fold their input through [story
threads](story-threads.md) before building the prompt (`fold_by_thread`,
`intelligence/story_threads.py`): one article per story, the **strongest** one (a
folded re-report never represents the story it re-reports), and the rest dropped.

- **`run_ai_task` in batch mode** — folds the matched entries. Opt out per rule
  with `fold_threads: false`.
- **The daily briefing** (`_fetch_day_entries`) — folds the day's articles, which
  is what `use_daily_summary` rules and the in-app day-divider summaries read.
  This is the path the shipped *Weekday Morning Briefing* rule actually runs
  through; it reads the cached briefing rather than prompting again.

Each surviving item carries what was folded away:

| Field | Meaning |
|---|---|
| `entry.thread_title` | The name of the unfolding story (empty when no thread holds it) |
| `entry.outlet_count` | Independent outlets covering that story |
| `entry.also_reported_by` | Articles in this batch folded into this one |
| `article_count` | What the batch held before folding, alongside the post-fold `entry_count` (batch actions only) |

The daily-briefing payload carries the same coverage as `entry.outlet_count` and
`entry.also_reported_by`, and its prompt renders the first as a **Corroboration**
line.

The action result reports `stories` and `folded` next to `entries_processed`, so
a run that collapsed 30 articles into 12 says so in the automation log. Set
`fold_threads: false` in the action config to send every article as before.

Folding only reaches what the sweeper can thread: an article under
`thread_min_body_chars` — a Reddit link post, an NVD stub — is never threaded and
so never folds, even when it points at a story already in the batch. Expect the
fold rate to track how much of the window is threaded.

### Logging & Audit

Execution logs are stored in `AutomationLog` (`models/automation_log.py:11-25`):

```python
class AutomationLog(Base):
    id: UUID
    rule_id: UUID                    # Which rule fired
    entry_id: UUID | None           # Which entry (null for correlation events)
    trigger_type: str               # on_new_entry, on_keyword_match, etc.
    status: str                     # success, error, skipped
    actions_executed: list[dict]    # Detailed results for each action
    error_message: str | None       # If status=error
    executed_at: datetime           # When it ran
```

Fields `actions_executed` is a list of dictionaries capturing the outcome of each action:
```json
{
  "type": "run_ai_task",
  "status": "success",
  "task": "article_summary"
}
```

This enables audit trails and debugging.

### Webhook Presets

Webhook URLs can be configured as reusable presets (stored in config or environment). The `send_notification` action supports three platform types:

- **Slack** — Block Kit formatting, `#channel` support, `mrkdwn` text
- **Discord** — Rich embeds, colored fields, `username` override
- **Custom** — Flat JSON payload with entry metadata

Validation (`_validate_webhook_url`, `actions.py:50-80`) prevents SSRF attacks:
- Rejects `file://`, `ftp://`, etc.
- Blocks private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, localhost) unless `webhook_allow_private_networks=true`
- Optional: hostname resolution could be added

Example Slack payload:
```json
{
  "text": "New Intel: Article Title",
  "username": "IntelFeed",
  "icon_emoji": ":shield:",
  "channel": "#threat-intel",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*<url|Article Title>*"
      }
    },
    {
      "type": "section",
      "text": { "type": "mrkdwn", "text": "AI summary here..." }
    }
  ]
}
```

---

## Part 2: AI Provider System

### Provider Abstraction

IntelFeed uses a pluggable provider interface (`backend/app/ai/providers/base.py`) allowing swappable LLM backends:

```python
class AIProvider(ABC):
    async def complete(
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        response_format: dict | None = None,
    ) -> AIResponse:
        """Execute a completion request; return structured response."""

    async def stream_complete(...):
        """Yield text chunks (default: falls back to complete())."""

    async def check_health() -> bool:
        """Verify provider is reachable and credentials valid."""

    async def list_models() -> list[str]:
        """List available models from this provider."""
```

Three providers are implemented (`backend/app/ai/providers/`): `ClaudeProvider` (Anthropic API; also the fallback used for `openai`/`custom` provider types), `ClaudeCodeProvider` (the Claude Code CLI under an OAuth session — see [copilot.md](copilot.md)), and `OllamaProvider` (real Ollama support with a native `/api/chat` function-calling loop against the backend tool registry in `app/tools/`).

Tool capability is gated centrally in `backend/app/ai/capabilities.py`: `TOOL_CAPABLE_PROVIDER_TYPES = {"claude_code", "ollama"}` and `TOOL_REQUIRED_TASKS` (copilot, entity_merge_maintenance, entity_enrichment_research) together prevent assigning an agentic task to a provider that can't execute tools.

### Model Configuration

The `AIProvider` database model (`models/ai_provider.py:11-27`) stores provider definitions:

```python
class AIProvider(Base):
    id: UUID
    name: str                       # "My Claude Instance"
    provider_type: str              # "claude", "openai", "ollama", "custom"
    base_url: str | None            # API endpoint (for ollama/custom)
    api_key_encrypted: str | None   # AES-256 encrypted secret
    models: list[dict]              # Available models
    is_active: bool = True
    config: dict                    # {temperature, max_tokens, etc.}
    created_at, updated_at: datetime
```

Example:
```json
{
  "name": "Claude Production",
  "provider_type": "claude",
  "api_key_encrypted": "encrypted_secret...",
  "models": [
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-haiku-4-5-20251001"
  ],
  "config": {
    "temperature": 0.0,
    "max_tokens": 4096
  }
}
```

### AI Tasks

Built-in tasks are defined in the `AITask` model (`models/ai_task.py:11-28`):

```python
class AITask(Base):
    id: UUID
    name: str                       # "article_summary", "ttp_mapping", etc. (UNIQUE)
    display_name: str               # "Entry Summarization"
    description: str | None
    category: str | None            # "extraction", "analysis", "generation", "custom"
    default_prompt_template: str    # Jinja2 template
    output_schema: dict | None      # JSON schema for structured output
    variables: list[str]            # {{entry.title}}, {{entry.content_text}}, etc.
    is_system: bool = True
    created_at: datetime
```

**Built-in Tasks (seeded from `backend/app/ai/prompts/defaults.py`):**

| Task Name | Category | Input | Purpose |
|---|---|---|---|
| `article_summary` | analysis | Entry content | Per-entry summary |
| `ttp_mapping` | extraction | Entry text | MITRE ATT&CK technique extraction |
| `detection_rules` | generation | Entry + TTPs | Detection rule generation |
| `entry_analysis` | extraction | Entry content | One-pass consolidated extraction (see below) |
| `daily_summary` / `intelligence_briefing` / `threat_assessment` | analysis | Multiple entries | Batch briefings |
| `detection_engineering_summary` | analysis | Multiple entries | Detection-focused briefing with coverage gaps |
| `video_transcript_summary` / `reddit_digest` / `report_section` | analysis / generation | Source-specific | Adapter/report helpers |
| `entry_qa` | analysis | User question + article | Per-entry "Ask Agent" chat |
| `copilot` | analysis | Question + ambient context | Global streaming copilot ([copilot.md](copilot.md)) |
| `entity_link_validation`, `entity_merge_maintenance`, `actor_profile_refresh`, `entity_name_normalization`, `hygiene_proposal_review`, `entity_enrichment_research`, `relationship_adjudication` | validation / maintenance | Entities/links | Agentic maintenance tasks (CLI or Ollama tool loop) |

The legacy per-entry extraction tasks (`threat_actor_id`, `malware_id`, `tool_extraction`, `country_id`, `sector_id`, `article_metadata`, `mitigation_extraction`, `cve_extraction`) still exist but are flagged `deprecated` — see "One-Pass Entry Analysis" below.

Tasks are invoked via `run_task()` in `backend/app/ai/engine.py:230`.

### Task Assignment & Routing

The `AITaskAssignment` model (`models/ai_task_assignment.py:10-27`) binds tasks to providers:

```python
class AITaskAssignment(Base):
    id: UUID
    created_by: UUID | None         # User (not used for filtering, only audit)
    task_id: UUID                   # Foreign key to AITask
    provider_id: UUID               # Foreign key to AIProvider
    model_name: str                 # Specific model (e.g., "claude-opus-4-6")
    is_enabled: bool = True
    execution_mode: str = "api"     # "api" or "agent" (agent = managed agent pool)
    config: dict                    # Override {temperature, max_tokens, etc.}

    __table_args__ = (UniqueConstraint("task_id"),)  # One provider per task
```

**Key design:** One-to-one task→provider mapping (enforced by unique constraint on `task_id`). This means "Run article_summary on Claude" but "Run entry_analysis on Ollama" are configured at the assignment level.

When `run_task(task_name="article_summary")` is called:
1. Query `AITaskAssignment` where `task_id.name == "article_summary"`
2. Load the assigned `AIProvider` and its config
3. Get or create the provider instance via `_get_provider_instance()`
4. Execute via `provider.complete()`

Reference: `ai/engine.py:165` (`get_task_assignment()`).

### Prompt Templates

The `AIPromptTemplate` model (`models/ai_prompt_template.py:11-26`) supports versioning and user customization:

```python
class AIPromptTemplate(Base):
    id: UUID
    task_id: UUID
    created_by: UUID | None         # NULL = system default; UUID = user override
    name: str                        # Template name
    template_text: str              # Jinja2 template
    variables: list                 # Metadata: {{entry.title}}, {{entries}}, etc.
    is_active: bool = True
    version: int = 1
    created_at: datetime
```

**Prompt Resolution** (`get_active_prompt`, `ai/engine.py:196`):
1. User-specific template (highest priority): where `created_by == user_id` AND `is_active` AND highest `version`
2. System default template: where `created_by IS NULL` AND `is_active` AND highest `version`
3. Task's `default_prompt_template` field (fallback)

Example prompt (Jinja2):
```jinja2
You are a cybersecurity analyst. Summarize the following article in 100 words.

Title: {{ entry.title }}
Content: {{ entry.content_text }}

Provide output as JSON:
{
  "summary": "...",
  "key_points": ["...", "..."],
  "threat_level": "high|medium|low"
}
```

For batch AI tasks (e.g., morning briefing), the `entries` variable is a list:
```jinja2
Summarize these {{ entry_count }} articles into a threat briefing.

{% for entry in entries %}
---
Title: {{ entry.title }}
Summary: {{ entry.summary }}
{% endfor %}

Produce a single JSON object with overall briefing and coverage gaps.
```

Rendering uses Jinja2 at `render_prompt`, `ai/engine.py:159`.

### Task Execution & Results

When `run_task()` executes:

```python
async def run_task(
    db: AsyncSession,
    user_id: UUID,
    task_name: str,
    variables: dict,          # {"entry": {...}} or {"entries": [...]}
    entry_id: UUID | None = None,
    target_type: str = None,  # "entry", "campaign", etc.
    target_id: UUID | None = None,
    force: bool = False,
) -> dict | None:
    # 1. Look up assignment
    # 2. Check for cached result (dedup via target_id)
    # 3. Get prompt template
    # 4. Render prompt with variables
    # 5. Execute provider
    # 6. Parse JSON response
    # 7. Store AIResult
    # 8. Return parsed_result
```

The `AIResult` model (`models/ai_result.py:12-38`) captures execution:

```python
class AIResult(Base):
    id: UUID
    entry_id: UUID | None           # Which entry triggered this (for backlinks)
    target_type: str | None         # "entry", "campaign", "custom"
    target_id: UUID | None          # ID of the target (for dedup)
    is_current: bool = True         # Dedup: mark old results as not_current on re-run
    task_id: UUID
    provider_id: UUID
    model_name: str                 # Actual model used
    prompt_used: str                # Full rendered prompt (for debugging)
    raw_response: str               # Unprocessed provider output
    parsed_result: dict             # Parsed JSON or extraction result
    tokens_input: int
    tokens_output: int
    cost_estimate: Decimal          # Calculated from cost_table
    processing_time_ms: int
    created_at: datetime

    __table_args__ = (
        Index("ix_ai_results_target_task_current",
              "target_type", "target_id", "task_id", "is_current"),
    )
```

**Deduplication:** If a task is run twice on the same target (entry), the first result is returned (cached) unless `force=True`. When `force=True`, prior results for that target/task are marked `is_current=False` and a new result is computed. This prevents re-running expensive AI tasks.

**Cost Tracking:**

```python
COST_TABLE: dict[str, tuple[float, float]] = {
    "claude-opus-4-6": (15.0, 75.0),           # $15 per 1M input, $75 per 1M output
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (0.80, 4.0),
}

# Cost calculation:
cost = (tokens_in / 1_000_000) * rate_input + (tokens_out / 1_000_000) * rate_output
```

Costs are tracked in Prometheus metrics and summed in the `AI_COST_TOTAL` counter. When the provider reports a real dollar figure (the Claude Code CLI's `total_cost_usd`), that is recorded instead of the token-table estimate; Anthropic Message Batches submissions apply the 50% batch discount.

### Error Handling & Retries

Failed completions store error in `parsed_result`:

```python
# If provider raises exception:
ai_result = AIResult(
    ...,
    parsed_result={"_error": str(e), "_extraction_status": "provider_error"}
)

# If response is not valid JSON:
parsed_result = {"raw": response.content, "_extraction_status": "parse_error"}

# On success:
parsed_result = {...user_data..., "_extraction_status": "success"}
```

Automation actions check `_extraction_status` to handle errors gracefully.

### Streaming

The base class provides a `stream_complete()` method for real-time streaming. The default implementation falls back to `complete()` and yields the full response. Provider subclasses (like ClaudeProvider) override to yield chunks.

---

## Part 3: Enrichment Pipeline

### Architecture Overview

The enrichment system augments entities (IOCs, CVEs, threat actors, etc.) with external context. It's composed of:

1. **Adapter Pattern** — Base class + 10 concrete implementations (NVD, CISA KEV, EPSS, Malpedia, Wikipedia, etc.). There are no IOC-reputation adapters (VirusTotal, AbuseIPDB, Shodan, OTX, GreyNoise, ThreatFox, URLhaus, MalBazaar, urlscan) — indicator lookups are left to external tooling
2. **Rate Limiting** — Redis-backed token bucket per source
3. **Budget Tracking** — Daily quota enforcement
4. **Caching** — TTL-based result deduplication
5. **User Overrides** — Per-user API key and trigger mode customization

### Data Models

**EnrichmentSource** (`models/enrichment.py:11-44`):

```python
class EnrichmentSource(Base):
    id: UUID
    source_type: str                # "nvd", "epss", "malpedia", etc. (UNIQUE)
    display_name: str               # "NVD API 2.0"
    is_enabled: bool = False
    trigger_mode: str               # "auto", "scheduled", "manual"
    api_key_encrypted: str | None
    rate_limit_config: dict         # {"requests_per_period": 50, "period_seconds": 604800}
    last_synced_at: datetime | None
    health_status: str              # "healthy", "degraded", "down", "unknown"
    config: dict                    # Adapter-specific config
    min_confidence_threshold: str   # "high", "medium", "low"
    daily_budget: int | None        # Max API calls/day; None = unlimited
    daily_budget_used: int = 0      # Synced from Redis for display
    schedule_interval_hours: int = 24
    next_scheduled_at: datetime | None
    created_at, updated_at: datetime
```

**UserEnrichmentOverride** (`models/enrichment.py:48`):

```python
class UserEnrichmentOverride(Base):
    id: UUID
    created_by: UUID | None
    source_id: UUID
    api_key_encrypted: str | None   # User's own API key (overrides global)
    trigger_mode_override: str | None  # User can override e.g. "manual" → "auto"
    created_at: datetime

    __table_args__ = (
        UniqueConstraint("source_id"),  # One override per user per source
    )
```

**EnrichmentResult** (`models/enrichment.py:69`):

```python
class EnrichmentResult(Base):
    id: UUID
    entity_type: str                # "ioc", "cve", "threat_actor", "malware", "ttp"
    entity_id: UUID
    source_type: str
    raw_response: dict              # Full API response (for debugging)
    parsed_data: dict               # Normalized/extracted fields
    enriched_at: datetime
    expires_at: datetime            # Cache TTL expiration
    status: str                     # "success", "error", "rate_limited", "not_found", "budget_exhausted", "skipped_low_confidence"

    __table_args__ = (
        Index("ix_enrichment_entity", "entity_type", "entity_id"),
        Index("ix_enrichment_source_entity", "source_type", "entity_type", "entity_id"),
    )
```

### Adapter Registry

The registry (`backend/app/enrichment/registry.py`) maps `source_type` strings to adapter classes:

```python
ADAPTER_REGISTRY: dict[str, type[EnrichmentAdapter]] = {
    "epss": EPSSAdapter,
    "nvd": NVDAdapter,
    "cisa_kev": CISAKEVAdapter,
    "mitre_attack": MITREAttackAdapter,
    "vulncheck": VulnCheckAdapter,
    "osv": OSVAdapter,
    "malpedia": MalpediaAdapter,
    "github_poc": GitHubPoCAdapter,
    "cvedetails": CVEDetailsAdapter,
    "wikipedia": WikipediaAdapter,
}
```

Each adapter registers with a default trigger mode and rate limit:

```python
DEFAULT_SOURCES = [
    {
        "source_type": "epss",
        "display_name": "FIRST EPSS",
        "default_trigger_mode": "scheduled",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 100, "period_seconds": 60},
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "nvd",
        "display_name": "NVD API 2.0",
        "default_trigger_mode": "auto",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 50, "period_seconds": 30},
        "default_min_confidence_threshold": "low",
    },
    # ... 8 more sources (registry.py:31-113)
]
```

### Adapter Base Class

All adapters inherit from `EnrichmentAdapter` (`backend/app/enrichment/base.py:17-54`):

```python
class EnrichmentAdapter(ABC):
    source_type: str
    display_name: str
    supported_entity_types: list[str]  # ["ioc_domain", "ioc_ipv4", "ioc_md5", ...]
    requires_api_key: bool = False
    default_trigger_mode: str = "manual"
    default_rate_limit: dict = {"requests_per_period": 100, "period_seconds": 86400}
    shared_key_group: str | None = None  # e.g. "abuse_ch" (ThreatFox, URLhaus, MalBazaar share key)

    @abstractmethod
    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        """Enrich a single entity; return normalized data."""

    async def bulk_sync(self) -> list[EnrichmentData]:
        """For scheduled sources (e.g., EPSS, MITRE ATT&CK). Override in subclasses."""

    async def check_health() -> bool:
        """Verify API key and connectivity."""

    def supports_entity(self, entity_type: str) -> bool:
        """Check if this adapter enriches the given entity type."""

    def get_cache_ttl(self) -> timedelta:
        """Return cache TTL (default: 24 hours)."""
```

**Example Adapter: GitHub PoC** (`backend/app/enrichment/adapters/github_poc.py`):

```python
class GitHubPoCAdapter(EnrichmentAdapter):
    source_type = "github_poc"
    display_name = "GitHub PoC"
    supported_entity_types = ["cve"]
    requires_api_key = False          # optional Bearer PAT for higher rate limits
    default_trigger_mode = "scheduled"

    _api_url = "https://api.github.com/search/repositories"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        # Search GitHub for "<CVE-ID> poc exploit", sorted by stars
        resp = await client.get(self._api_url, params={"q": query, "sort": "stars", ...})

        if resp.status_code == 403:
            # Rate limited — cache the miss briefly and retry later
            return EnrichmentData(
                raw_response={"error": "rate_limited"},
                parsed_data={"found": False, "error": "GitHub API rate limited"},
                ttl_hours=1,
            )

        items = resp.json().get("items", [])
        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "found": True,
                "cve_id": entity_value,
                "has_public_poc": bool(items),
                "poc_count": len(items),
                # top repos, stars, urls ...
            },
        )
```

### Trigger Modes

Enrichment fires based on the source's `trigger_mode`:

| Mode | When | Use Case |
|------|------|----------|
| `auto` | On entity extraction | Per-entity lookups: NVD, OSV, CVEDetails, Wikipedia |
| `scheduled` | Periodic bulk sync | EPSS scores, CISA KEV, MITRE ATT&CK, VulnCheck, Malpedia, GitHub PoC scanner |
| `manual` | User-initiated via UI | Any source the operator flips to manual to conserve quota |

Implementation: `pipeline.py:134-289` (`enrich_entity()`).

### Pipeline Flow

```
User/Automation triggers enrich_entity()
  ↓
  Get enabled sources matching trigger_mode
  ↓
  For each source:
    1. Resolve API key (user override > global > shared key group)
    2. Get adapter instance: get_adapter(source.source_type, api_key=...)
    3. Check confidence threshold (auto mode only)
    4. Check cache (fresh result?):
       - YES: return cached parsed_data (no budget used)
       - NO: proceed to step 5
    5. Check daily budget:
       - Over limit: status="budget_exhausted", skip
       - OK: proceed to step 6
    6. Check rate limit (Redis token bucket):
       - Allowed: proceed
       - Throttled: status="rate_limited", skip
    7. Call adapter.enrich(entity_type, entity_value)
    8. Store EnrichmentResult
    9. Append to results list
  ↓
  Return results: [{"source_type": "vt", "status": "success", "parsed_data": {...}}, ...]
```

Reference code: `pipeline.py:134-289`.

### API Key Resolution

Multi-level fallback chain (`resolve_api_key`, `pipeline.py:54`):

```python
async def resolve_api_key(
    source: EnrichmentSource,
    user_id: UUID | None,
    db: AsyncSession,
) -> str | None:
    # 1. Check user override for this specific source
    if user_id:
        override = await db.query(UserEnrichmentOverride).filter(
            UserEnrichmentOverride.source_id == source.id,
            UserEnrichmentOverride.created_by == user_id,
        ).first()
        if override and override.api_key_encrypted:
            return decrypt_value(override.api_key_encrypted)

    # 2. Check global key on source
    if source.api_key_encrypted:
        return decrypt_value(source.api_key_encrypted)

    # 3. Shared key group fallback
    # (adapters that set shared_key_group share one key across sibling sources)
    adapter_cls = ADAPTER_REGISTRY.get(source.source_type)
    shared_group = getattr(adapter_cls, "shared_key_group", None)
    if shared_group:
        # Check user overrides for sibling sources
        # Check global keys on sibling sources
        # Return first found
        ...

    return None
```

This allows:
- Team-wide key (e.g. VulnCheck, CVEDetails) + user's personal key for higher quota
- Per-user overrides for any source

Note: no current adapter sets `shared_key_group` — the mechanism exists (`base.py:26`, `SHARED_KEY_GROUPS` in `registry.py:115-121`) but the map is empty since the Abuse.ch-family IOC adapters were removed.

### Confidence Thresholds

IOCs can have confidence levels (high/medium/low or numeric 0-1). The source's `min_confidence_threshold` controls which entities get enriched:

```python
_CONFIDENCE_LEVELS = {"high": 3, "medium": 2, "low": 1}
_CONFIDENCE_FLOAT_THRESHOLDS = {"high": 0.7, "medium": 0.4, "low": 0.0}

def _passes_confidence_threshold(
    source: EnrichmentSource,
    entity_confidence: str | None,
    entity_base_confidence: float | None,
) -> bool:
    threshold = source.min_confidence_threshold
    if threshold == "low":
        return True  # Enrich everything

    # Check string confidence level (e.g., "high" >= "medium"?)
    # Check numeric confidence (e.g., 0.65 >= 0.4?)
    # Return True if entity meets threshold
```

Thresholds prevent wasting budget on low-confidence indicators. For example:
- NVD / EPSS / Wikipedia (default "low") enrich everything
- VulnCheck / CVEDetails (default "medium") only enrich medium/high confidence entities

### Caching & TTL

Results are cached in the DB with expiry:

```python
async def get_cached_result(
    db: AsyncSession,
    entity_type: str,
    entity_id: UUID,
    source_type: str,
) -> EnrichmentResult | None:
    # Query for the latest successful result
    result = await db.query(EnrichmentResult).filter(
        EnrichmentResult.entity_type == entity_type,
        EnrichmentResult.entity_id == entity_id,
        EnrichmentResult.source_type == source_type,
        EnrichmentResult.status == "success",
    ).order_by(EnrichmentResult.enriched_at.desc()).first()

    # Check if result.expires_at > now()
    if result and result.expires_at > datetime.now(timezone.utc):
        return result

    return None
```

Each adapter specifies `ttl_hours` (default 24) via the `EnrichmentData` return object. This allows:
- Static data (MITRE ATT&CK, Malpedia) to cache for weeks
- Live data (NVD scores, GitHub PoC hits) to cache for hours
- Negative results ("not found", rate-limited misses) to cache briefly

### Rate Limiting

Redis-backed token bucket per source (`enrichment/rate_limiter.py`):

```python
class RedisRateLimiter:
    def __init__(self, source_type: str, config: dict):
        self.source_type = source_type
        self.requests_per_period = config.get("requests_per_period", 100)
        self.period_seconds = config.get("period_seconds", 86400)

    async def check(self) -> bool:
        """Check if we have capacity; return True/False."""
        # Lua script: decrement token bucket, return allowed
```

Example configs from registry:
- NVD: 50 requests/30s
- MITRE ATT&CK: 10 requests/3600s
- VulnCheck: 1000 requests/60s
- Malpedia: 30 requests/60s
- GitHub PoC / Wikipedia: 10 requests/60s

### Daily Budgets

Soft cap on API calls (`pipeline.py:204-216`):

```python
if source.daily_budget is not None:
    budget_tracker = RedisBudgetTracker(source.source_type)
    within_budget = await budget_tracker.check_and_increment(source.daily_budget)
    if not within_budget:
        status="budget_exhausted"
        skip enrichment
```

Useful for keyed sources (VulnCheck, CVEDetails) to prevent runaway quota burn. Set to `None` for unlimited.

### Scheduled Enrichment

The Celery Beat scheduler runs periodic enrichment for sources with `trigger_mode='scheduled'`:

| Source | Beat cadence | Reason |
|--------|--------------|--------|
| EPSS | Daily at 06:30 UTC | Updated exploitation-probability scores |
| MITRE ATT&CK | Weekly Sunday 03:00 UTC | Full framework sync |
| Malpedia | Weekly Sunday 03:30 UTC | Malware family updates |
| GitHub PoC | Daily at 05:00 UTC | New public exploits |
| NVD refresh / backfill | Daily 12:00 / 01:30 UTC | CVSS changes; missing CVE data |

Implementation: Celery tasks call `adapter.bulk_sync()`, which handles pagination and large datasets. The Malpedia sync passes `alt_names` through `filter_aliases()` (`intelligence/autolinker.py`) so junk aliases from Malpedia never enter entity `aliases` arrays.

---

## Integration: How Three Systems Work Together

### Automation Triggering Enrichment

When an automation action extracts an IOC, enrichment can be triggered immediately:

```python
# Action: extract_iocs from entry text
iocs = await extract_and_store_iocs(db, entry.id, entry.content_text)

# Then auto-enrich (if sources have trigger_mode='auto')
for ioc in iocs:
    results = await enrich_entity_auto(
        entity_type="ioc",
        entity_id=ioc.id,
        entity_value=ioc.value,
        db=db,
        entity_confidence=ioc.confidence,  # Threshold filtering
    )

# Entity now has enrichment results from the enabled auto-mode sources
# (NVD, OSV, CVEDetails, Wikipedia, ...)
```

### AI Task Extracting Intelligence for Detection Rules

An automation rule can chain AI tasks:

```python
{
  "type": "run_ai_task",
  "config": { "task_id": "extract_ttps" }
}
→ context["extraction_results"]["ttps"] = [...]

{
  "type": "generate_detection_rules",
  "config": { "rule_types": ["sigma", "splunk_spl"] }
}
→ Uses TTPs from context to generate rules
```

### Automation Sending Enriched Data via Webhook

A notification action can include enrichment results:

```python
{
  "type": "send_notification",
  "config": {
    "webhook_url": "...",
    "message_template": "CVE: {url}\nKEV status: {context.kev_status}"
  }
}
```

(Note: Full context passing for webhook actions requires extensions to the template system.)

---

## Execution Diagrams

### Automation Rule Trigger → Action Execution

```
┌─────────────────────────────────────────────────────────┐
│ New Entry Ingested                                      │
│ id=uuid, feed_id=uuid, content_text=...                │
└─────────────┬───────────────────────────────────────────┘
              │
              ↓
┌─────────────────────────────────────────────────────────┐
│ run_automations_for_entry(db, entry, feed_id)           │
│ (async from entry creation task)                        │
└─────────────┬───────────────────────────────────────────┘
              │
              ↓ Query enabled rules
┌─────────────────────────────────────────────────────────┐
│ SELECT * FROM automation_rules                          │
│ WHERE is_enabled=true                                   │
│ AND trigger_type IN ('on_new_entry', ...)               │
└─────────────┬───────────────────────────────────────────┘
              │
              ↓ For each rule
         ┌────┴────────────────┬──────────────────┐
         │                     │                  │
         ↓                     ↓                  ↓
    (on_new_entry        (on_keyword_match  (on_cve_detected
     always true)         regex check)       CVSS threshold)
         │                     │                  │
         └────────────┬────────┴──────────────────┘
                      ↓
         Should this rule fire? (check trigger-specific logic)
                      │
              ┌───────┴───────┐
              ↓               ↓
             YES             NO (skip to next rule)
              │
              ↓
    ┌─────────────────────────────────────────┐
    │ evaluate_conditions(db, entry, {AND/OR})│  Evaluate nested conditions
    └─────────────┬───────────────────────────┘
                  │
          ┌───────┴────────┐
          ↓                ↓
        PASS              FAIL (log as skipped)
          │
          ↓
    ┌─────────────────────────────────────────────┐
    │ _execute_action_chain(                      │
    │   db, entry, rule.actions,                  │
    │   user_id, context={}, dry_run=False        │
    │ )                                           │
    └────────┬────────────────────────────────────┘
             │
             ↓ For each action
        ┌────────────────────────────────┐
        │ action.type                    │
        └────┬─────────────────────┬─────┘
             │                     │
        ┌────┴────┐          ┌─────┴────────┐
        │          │          │              │
        ↓ branch   ↓ normal   ↓ ...
    ┌───────┐ ┌──────────────────┐
    │Eval   │ │execute_action()  │
    │branch │ │per entry         │
    │cond   │ │(tag, AI, etc.)   │
    └───┬───┘ └────────┬─────────┘
        │              │
    ┌───┴────┐         │
    ↓        ↓         │
then    else      action
sub     sub      result
chain   chain     dict
    │    │         │
    └────┴─────────┘
         │
         ↓ All results collected
    actions_executed = [
      {"type": "tag", "status": "success", ...},
      {"type": "notify", "status": "success", ...},
      ...
    ]
         │
         ↓
    ┌─────────────────────────────────────┐
    │ Create AutomationLog                │
    │ status="success"                    │
    │ actions_executed=[...]              │
    │ rule.last_triggered_at = now()      │
    │ rule.run_count += 1                 │
    └─────────────┬───────────────────────┘
                  ↓
            Flush & commit to DB
```

### AI Task Execution Pipeline

```
┌────────────────────────────────────────────────────┐
│ Automation Action / Manual Request                 │
│ run_ai_task(task_id="article_summary", entry_id=..) │
└────────┬───────────────────────────────────────────┘
         │
         ↓
┌────────────────────────────────────────────────────┐
│ run_task(task_name, variables, entry_id)           │
│ (backend/app/ai/engine.py:230)                     │
└────────┬───────────────────────────────────────────┘
         │
         ↓
┌────────────────────────────────────────────────────┐
│ get_task_assignment(user_id, task_name)            │
│ Query AITaskAssignment.task_id.name == task_name   │
└────────┬───────────────────────────────────────────┘
         │
    ┌────┴─────┐
    ↓          ↓
Found?      Not Found
    │          └──→ return None (skip)
    ↓
┌────────────────────────────────────────────────────┐
│ Check dedup: is_current result for (target, task)? │
│ (skip if fresh, unless force=True)                 │
└────────┬───────────────────────────────────────────┘
         │
         ↓
┌────────────────────────────────────────────────────┐
│ get_active_prompt(task_id, user_id)                │
│ User template? → System template? → Default?       │
└────────┬───────────────────────────────────────────┘
         │
         ↓
┌────────────────────────────────────────────────────┐
│ render_prompt(template_text, variables)            │
│ Jinja2({{entry.title}}, {{entry.content}}, ...)    │
└────────┬───────────────────────────────────────────┘
         │
         ↓
┌────────────────────────────────────────────────────┐
│ provider.complete(                                 │
│   prompt=rendered_prompt,                          │
│   temperature=config.temperature,                  │
│   max_tokens=config.max_tokens,                    │
│   response_format=task.output_schema               │
│ )                                                  │
│ → AIResponse(content, tokens_input, tokens_output) │
└────────┬───────────────────────────────────────────┘
         │
    ┌────┴──────────────┐
    ↓                   ↓
Success             Exception
    │                   └──→ Store error result
    ↓
┌────────────────────────────────────────────────────┐
│ Parse JSON from response.content                   │
│ If invalid: extract from ```json...``` block       │
│ Tag with _extraction_status="success" (if valid)   │
└────────┬───────────────────────────────────────────┘
         │
         ↓
┌────────────────────────────────────────────────────┐
│ Estimate cost: tokens → $$$ (from COST_TABLE)      │
│ Update Prometheus: AI_COST_TOTAL, AI_TOKENS_TOTAL  │
└────────┬───────────────────────────────────────────┘
         │
         ↓
┌────────────────────────────────────────────────────┐
│ Create AIResult                                    │
│ - entry_id, task_id, provider_id                   │
│ - parsed_result (JSON dict)                        │
│ - cost_estimate, tokens_*, processing_time_ms      │
│ - is_current=True (mark old as not_current)        │
└────────┬───────────────────────────────────────────┘
         │
         ↓
    ┌────────────────────────────────────┐
    │ Store to DB                        │
    │ Publish SSE event (ai_task_complete)│
    └────┬───────────────────────────────┘
         │
         ↓
    Return parsed_result dict
    (available in automation context)
```

### Enrichment Job → Merge

```
┌───────────────────────────────────────────────────┐
│ Entity extracted (IOC, CVE, actor, etc.)          │
│ id=uuid, value=..., confidence=...                │
└───────┬───────────────────────────────────────────┘
        │
        ↓ trigger='auto' (optional)
┌───────────────────────────────────────────────────┐
│ enrich_entity(                                    │
│   entity_type, entity_id, entity_value,           │
│   db, user_id, trigger='auto',                    │
│   entity_confidence=...                           │
│ )                                                 │
└───────┬───────────────────────────────────────────┘
        │
        ↓
┌───────────────────────────────────────────────────┐
│ Query: EnrichmentSource where                     │
│   is_enabled=true AND trigger_mode=trigger        │
└───────┬───────────────────────────────────────────┘
        │
        ↓ For each source
    ┌───┴──────────────────────────────────────┐
    │                                          │
    ↓                                          ↓
┌──────────────────────────┐           ┌──────────────────────────┐
│ resolve_api_key()        │           │ next source              │
│ user override            │           └──────────────────────────┘
│ → global key             │
│ → shared group sibling   │
└──────┬───────────────────┘
       │
       ↓
┌──────────────────────────────────────────────────┐
│ Get adapter instance                             │
│ get_adapter(source.source_type, api_key, config) │
└──────┬───────────────────────────────────────────┘
       │
       ↓ (trigger='auto' only)
┌──────────────────────────────────────────────────┐
│ _passes_confidence_threshold()?                  │
│ entity.confidence >= source.min_threshold?       │
└────┬─────┐
     │     │
    YES   NO → append {"status": "skipped_low_confidence"}
     │          continue to next source
     ↓
┌──────────────────────────────────────────────────┐
│ get_cached_result()                              │
│ Is there a fresh (not expired) result?           │
└──────┬───────────────────────────────────────────┘
       │
    ┌──┴──┐
    ↓     ↓
Found    Not Found
    │        │
   YES      NO → proceed to API call
    └──┘
       └──→ append {"status": "cached", "parsed_data": {...}}
           continue to next source
             (no budget/rate limit check needed)
             │
             ↓
┌──────────────────────────────────────────────────┐
│ Check daily_budget                               │
│ budget_used >= budget_limit?                     │
└──────┬───────────────────────────────────────────┘
       │
       ↓ if exceeded
    append {"status": "budget_exhausted"}
    continue
       │
       ↓ if OK
┌──────────────────────────────────────────────────┐
│ RedisRateLimiter.check()                         │
│ Have tokens in bucket?                           │
└──────┬───────────────────────────────────────────┘
       │
       ↓ if throttled
    append {"status": "rate_limited"}
    continue
       │
       ↓ if allowed
┌──────────────────────────────────────────────────┐
│ adapter.enrich(entity_type, entity_value)        │
│ Make actual API call                             │
│ Return EnrichmentData(raw, parsed, ttl_hours)    │
└──────┬───────────────────────────────────────────┘
       │
       ↓
┌──────────────────────────────────────────────────┐
│ Create EnrichmentResult                          │
│ - entity_type, entity_id, source_type            │
│ - raw_response, parsed_data                      │
│ - status="success"                               │
│ - expires_at = now + ttl_hours                   │
└──────┬───────────────────────────────────────────┘
       │
       ↓
   append {"status": "success", "parsed_data": {...}}


┌──────────────────────────────────────────────────┐
│ All sources complete                             │
│ results = [                                      │
│   {"source": "nvd", "status": "success", ...},   │
│   {"source": "epss", "status": "cached"},        │
│   {"source": "github_poc", "status": "rate_limited"},│
│   ...                                            │
│ ]                                                │
└──────┬───────────────────────────────────────────┘
       │
       ↓
   Flush & commit DB (new EnrichmentResult records)
       │
       ↓
   Return results to caller
```

---

## Configuration and Extensibility

### Adding a New Enrichment Adapter

1. Create class in `backend/app/enrichment/adapters/myapi.py`:
```python
class MyAPIAdapter(EnrichmentAdapter):
    source_type = "myapi"
    display_name = "My API Service"
    supported_entity_types = ["ioc_ipv4", "ioc_domain"]
    requires_api_key = True
    default_trigger_mode = "manual"
    shared_key_group = None  # or "groupname" to share a key

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        # Make API request
        # Parse response
        # Return EnrichmentData(raw, parsed, ttl_hours)

    async def check_health(self) -> bool:
        # Ping API to verify connectivity
```

2. Register in `registry.py`:
```python
from app.enrichment.adapters import MyAPIAdapter

ADAPTER_REGISTRY["myapi"] = MyAPIAdapter

DEFAULT_SOURCES.append({
    "source_type": "myapi",
    "display_name": "My API Service",
    ...
})
```

3. Adapter is now available in the UI for configuration.

### Adding a New AI Task

1. Create task record via API or CLI:
```python
AITask(
    name="my_analysis",
    display_name="My Custom Analysis",
    category="analysis",
    default_prompt_template="Analyze: {{entry.content_text}}",
    output_schema={"type": "object", "properties": {...}},
)
```

2. Assign to provider via API:
```python
AITaskAssignment(
    task_id=task.id,
    provider_id=provider.id,
    model_name="claude-opus-4-6",
    is_enabled=True,
    config={"temperature": 0.5, "max_tokens": 2048},
)
```

3. Use in automation:
```json
{
  "type": "run_ai_task",
  "config": { "task_id": "my_analysis" }
}
```

### Adding a New Automation Action

1. Implement handler in `backend/app/automation/actions.py`:
```python
async def _action_my_action(
    db: AsyncSession,
    entry: Entry,
    config: dict,
    user_id: UUID,
    context: dict,
) -> dict:
    # Logic here
    return {"status": "success", "result": "..."}
```

2. Add case to `execute_action()` match statement
3. Optionally add to `PER_ENTRY_ACTIONS` or `BATCH_ACTIONS` if supporting batch execution
4. Action now available in rule builder UI

---

## Testing & Debugging

### Dry-Run Automation Rules

Test rules without side effects:
```python
log = await execute_automation(db, entry, rule, dry_run=True)
# log.status = "success" (if conditions pass)
# log.actions_executed shows what would run
# No tags added, no webhooks sent, no DB changes
```

### AI Task Cost Estimation

Review estimated costs before running:
```python
# In UI or API response:
AIResult.cost_estimate  # Decimal: $0.001234
```

Aggregate across time:
```
Prometheus: AI_COST_TOTAL{provider="claude"} = $123.45
```

### Enrichment Budget Tracking

Monitor daily spend:
```python
RedisBudgetTracker("cvedetails").check_budget()  # Returns remaining calls
```

Manual reset:
```python
RedisBudgetTracker("cvedetails").reset()
```

---

## Summary

IntelFeed's three subsystems are tightly integrated:

1. **Automation Engine** provides flexible rule-based triggering with sequential action execution, branching, and shared context flow.

2. **AI Provider System** abstracts LLM backends with pluggable providers, versioned prompt templates, deduplication, and cost tracking.

3. **Enrichment Pipeline** orchestrates 10 external threat intel sources with rate limiting, budgets, caching, and user customization.

Together, they enable sophisticated intelligence automation workflows: extract CVEs/entities from articles → auto-enrich with NVD/EPSS/KEV context → if critical, generate detection rules via AI → send Slack alert with summary.

## One-Pass Entry Analysis (engine phase 4)

The per-entry AI extraction tasks (`threat_actor_id`, `malware_id`, `tool_extraction`, `country_id`, `sector_id`, `article_metadata`, `mitigation_extraction`, `cve_extraction`) are **deprecated** — kept in the DB so their ai_results history survives, hidden from run pickers, assignments force-disabled by the seeder. Their replacement is one consolidated `entry_analysis` task (Haiku, combined output schema) whose parsed payload fans out to the same store functions (`app/services/entry_analysis.py::store_entry_analysis`).

Ingest flow (flag `ai_one_pass_enabled`): `score_entry_task` → `enqueue_entry_analysis` (dedup via AIResult is_current → feed policy → relevance junk gate → **echo-reuse**: near-duplicates copy the original's analysis at $0) → `ai_analysis_requests` queue. Hourly `ai-analysis-batch-submit` self-heals missed enqueues, clamps to the daily budget (`ai_daily_budget_usd`), orders by `entries.priority_score`, and submits via the **Anthropic Message Batches API** (50% discount; falls back to sequential `run_entry_analysis_task` calls when the provider uses an OAuth token). `ai-analysis-batch-poll` (10-min) ingests ended batches idempotently via `store_external_result`. Status: `GET /api/engine/extraction/status`.

The one-pass `entry_analysis` payload also adjudicates **pending autolinks** — dictionary-word autolinker matches are held in a pending tier until the AI confirms or rejects them (requires `ai_one_pass_enabled`) — and asserts entity relationships at ingest. Manual per-type extraction endpoints and `run_ai_task` automation actions still work — `extract_threat_actors`/`extract_malware`/etc. now route through `entry_analysis`, and run_task's dedup means successive per-type calls on one entry share a single AI call. The AI-extraction store path (`intelligence/enrichment.py`) also guards entity quality: new aliases are dropped if `is_junk_alias()` flags them, new entity names are rejected by `is_fp_entity_name()` (FP denylist + `*.exe`/`*.dll`/`*.sys` filenames), and cross-type reclassify tombstones redirect would-be shadow entities to the surviving canonical entity (see `docs/intelligence-engine.md`, "Cross-Type Resurrection Guard"). The daily digest receives per-article signal explanations (`priority_signals`) so briefings say why an article matters.

### Signal-engine automation (engine phase 7)

Automation rules can react to what the pipeline learned: condition types `priority_score_above` (entry's signal-engine score), `has_signal` (specific signal types, e.g. kev_added / novel_entity / under_reported), and `entity_watchlisted` (entry links an entity the rule creator watches). The "Signal Engine" template category ships recipes for both. `has_observable` fires when the entry carries a captured observable (config: `kinds`, `roles`, `min_confidence`, `exclude_infra_tagged` — default true — and `sources`, which defaults to every door but the indicator-feed one, so "new C2 captured" means reporting, not a blocklist mirror). Notification and webhook templates can cite them with `{observables_count}` and `{observables}` (defanged, one per line as `kind value (role)`). The `on_observable_captured` trigger takes the same config as the condition, so a rule can be narrow at the trigger ("C2 only") and keep its conditions for everything else about the entry. `add_to_campaign` gains `link_observables` (with optional `observable_kinds` / `observable_roles`): besides linking the entry it attaches the entry's reporting-door observables as `campaign_entities` rows of type `observable`, dual-use infra excluded. Two templates ship for this: "Notify on New C2 Infrastructure" and "Add an Actor's New Infrastructure to Its Campaign". Radar items accept ▲/▼ feedback (`entry_signal_feedback`); the nightly rates job converts 30 days of feedback into bounded ±10% per-family weight nudges applied on top of the admin-set multipliers.
