# Automation, AI Providers, and Enrichment

For contributors and operators. After reading this you will know how automation rules fire and what they can do, how IntelFeed decides which AI model answers a task, and how entities get extra data from outside sources.

**Contents**

- [Overview](#overview)
- [Part 1: Automation Engine](#part-1-automation-engine)
  - [Data Model](#data-model)
  - [Trigger Types](#trigger-types)
  - [Condition Language](#condition-language)
  - [Actions](#actions)
  - [Template Variables](#template-variables)
  - [Branch Actions](#branch-actions)
  - [Execution Flow](#execution-flow)
  - [One article per story](#one-article-per-story)
  - [Logging & Audit](#logging--audit)
  - [Webhook Presets](#webhook-presets)
- [Part 2: AI Provider System](#part-2-ai-provider-system)
  - [Provider Abstraction](#provider-abstraction)
  - [Model Configuration](#model-configuration)
  - [AI Tasks](#ai-tasks)
  - [Task Assignment & Routing](#task-assignment--routing)
  - [The `ai` queue](#the-ai-queue)
  - [Callers: Who Is Asking](#callers-who-is-asking)
  - [Personal Keys & The Lookup](#personal-keys--the-lookup)
  - [Allowances & Caps](#allowances--caps)
  - [Prompt Templates](#prompt-templates)
  - [Task Execution & Results](#task-execution--results)
  - [Error Handling & Retries](#error-handling--retries)
  - [Streaming](#streaming)
  - [One-Pass Entry Analysis](#one-pass-entry-analysis-engine-phase-4)
- [Part 3: Enrichment Pipeline](#part-3-enrichment-pipeline)
  - [Architecture Overview](#architecture-overview)
  - [Data Models](#data-models)
  - [Source Registry](#source-registry)
  - [Field Map](#field-map)
  - [Trigger Modes](#trigger-modes)
  - [Pipeline Flow](#pipeline-flow)
  - [API Key Resolution](#api-key-resolution)
  - [Confidence Thresholds](#confidence-thresholds)
  - [Caching & TTL](#caching--ttl)
  - [Source Gateway](#source-gateway)
  - [Daily Budgets](#daily-budgets)
  - [Enrichment Console](#enrichment-console)
  - [Source Jobs](#source-jobs)
- [Configuration and Extensibility](#configuration-and-extensibility)
- [Testing & Debugging](#testing--debugging)

## Overview

Three backend subsystems act on intelligence without a person clicking:

1. **Automation engine** (`backend/app/automation/`): rules you write. When an entry matches, the rule runs a list of actions (tag it, notify Slack, run an AI task, and so on).
2. **AI provider system** (`backend/app/ai/`): one interface over several model backends. A *task* (for example "summarize an article") is assigned to a *provider* (for example your Ollama server). A provider does nothing until a task is assigned to it.
3. **Enrichment pipeline** (`backend/app/enrichment/`): pulls extra facts about entities (CVEs, actors, malware, IP addresses) from 18 outside sources and stores the results.

---

## Part 1: Automation Engine

### Data Model

A rule is one row in `automation_rules` (`backend/app/models/automation_rule.py`):

| Field | What it holds |
|---|---|
| `created_by` | The rule's owner. A rule with no owner never fires. |
| `name`, `description`, `labels` | Display and grouping |
| `is_enabled` | On/off switch |
| `trigger_type`, `trigger_config` | When the rule fires (see below) |
| `conditions` | Optional AND/OR filter tree (JSONB) |
| `actions` | Ordered list of actions (JSONB) |
| `last_triggered_at`, `run_count` | Run stats |

Conditions and actions are plain JSON, so adding a new condition or action type needs no migration.

Rules run as their owner. Per-user state (read, starred, watchlist, personal tags) is the owner's.

### Trigger Types

The API accepts eight trigger types (`backend/app/schemas/automation.py`):

| Trigger | Fires when | `trigger_config` |
|---|---|---|
| `on_new_entry` | An entry is ingested | — |
| `on_keyword_match` | Title, content or summary matches a pattern | `pattern`, `is_regex` (default `true`, case-insensitive) |
| `on_cve_detected` | The entry has linked CVEs | `min_severity`: `low` / `medium` / `high` / `critical` (CVSS ≥ 0.1 / 4.0 / 7.0 / 9.0). Empty = any linked CVE |
| `on_entry_scored` | The signal engine has scored the entry | — |
| `on_observable_captured` | A judgment door (one-pass AI, a publisher's IOC table, an analyst promote) wrote observables for the entry. The indicator-feed door never fires it | Same shape as the `has_observable` condition: `kinds`, `roles`, `min_confidence`, `exclude_infra_tagged`, `sources` |
| `on_correlation_event` | The correlation engine records an event | `event_types`, `entity_filters` (`threat_actor_names`, `malware_names`) |
| `on_schedule` | A cron time arrives | `cron` (5 fields, UTC), `entry_filter`, `max_entries` (default 200), `execution_mode` |
| `on_manual` | Only when someone presses **Run now** | Same as `on_schedule`, minus `cron` |

How each one is dispatched:

- **`on_new_entry`, `on_keyword_match`, `on_cve_detected`**: the fetch loop queues `run_entry_automations` for each new entry. That calls `run_automations_for_entry` (`backend/app/automation/engine.py:242`). This runs alongside the rest of the pipeline, so CVE links and the priority score may not exist yet.
- **`on_entry_scored`**: `score_entry_task` queues `run_scored_entry_automations` after it saves the score, so `priority_score_above` and `has_signal` see real values. It fires on the first scoring only, never on rescores or backfills.
- **`on_observable_captured`**: the door that captured observables queues `dispatch_observable_capture_automations` after its commit. It fires **once per rule per entry**: a rule that already has a non-skipped log for the entry is skipped (`run_automations_for_observable_capture`, `backend/app/automation/engine.py:322`). The replay backfill script never fires it.
- **`on_correlation_event`**: runs from `run_correlation_automations` (`run_automations_for_correlation_event`, `backend/app/automation/engine.py:412`). An event with no entry is logged as `skipped`.
- **`on_schedule`**: the `run-scheduled-automations` beat job checks every 60 seconds. A rule fires once for the latest cron slot it has not run yet, looking back up to 48 hours, so a late worker catches up once instead of skipping. A brand-new rule fires only if its slot was within the last 10 minutes. The slot is claimed before the actions run, so two workers never fire the same slot, and a failed run does not retry.

### Condition Language

Conditions filter entries after the trigger matches (`evaluate_conditions`, `backend/app/automation/conditions.py:23`). A condition is either one check, `{"type": ..., "config": {...}}`, or a group, `{"operator": "AND" | "OR", "conditions": [...]}`. Groups nest. An empty block always passes.

| Condition | Config | True when |
|---|---|---|
| `feed_matches` | `feed_ids[]`, `category_ids[]` | The entry's feed is listed, or is in a listed category |
| `content_contains` | `pattern`, `is_regex` (default `false`) | Title, content or summary contains the text (case-insensitive) |
| `severity_above` | `min_cvss` | A linked CVE has CVSS ≥ `min_cvss` |
| `author_matches` | `authors[]` | The author contains one of the names |
| `tag_matches` | `tags[]` | The entry has one of the tags (as the owner sees them) |
| `feed_type_matches` | `types[]` | The feed type is listed (`rss`, `youtube`, `nvd`, ...) |
| `is_read`, `is_starred`, `is_bookmarked`, `has_note` | — | The owner has read / starred / bookmarked / noted the entry |
| `priority_score_above` | `min` (default 1.0) | The 0–10 priority score is ≥ `min` |
| `has_signal` | `types[]` (empty = any) | The entry carries one of these signals (`kev_added`, `novel_entity`, `under_reported`, ...) |
| `entity_watchlisted` | — | The entry links an entity the owner watches |
| `has_observable` | `kinds`, `roles`, `min_confidence`, `exclude_infra_tagged` (default `true`), `sources` | The entry has a matching captured observable. `sources` defaults to every door except the indicator feed, so "new C2" means reporting, not a blocklist mirror |

An unknown condition type, or one that raises an error, evaluates to `false`.

```json
{
  "operator": "AND",
  "conditions": [
    { "type": "feed_type_matches", "config": { "types": ["rss"] } },
    {
      "operator": "OR",
      "conditions": [
        { "type": "content_contains", "config": { "pattern": "ransomware" } },
        { "type": "severity_above", "config": { "min_cvss": 8.0 } }
      ]
    }
  ]
}
```

### Actions

Actions run in order (`execute_action`, `backend/app/automation/actions.py:221`). They share a `context` dict, so a later action can use what an earlier one produced. A failed action records `status: "error"` and the next action still runs.

| Action | Config | What it does |
|---|---|---|
| `run_ai_task` | `task_id` (a task name), `fold_threads` (batch only, default `true`) | Runs an AI task and stores the parsed result in `context["ai_results"][task]` |
| `use_daily_summary` | `day`: `yesterday` (default) / `today`; `on_missing`: `generate` (default) / `skip`; `links`: `original` (default) / `app` | Reuses the shared day-divider briefing as `{ai_summary}` instead of paying for a second one. Batch mode only. `links: original` rewrites in-app links to the articles' own URLs |
| `add_tags` | `tags`: names, or `{name, color, description, chip, global}` objects | Adds tags. The object form styles a tag only when it is created. The assignment belongs to the rule owner unless the tag is global. A rule with no owner skips personal tags |
| `remove_tags` | `tags[]` | Removes the owner's assignment (or the shared one for a global tag) |
| `mark_priority` | `level` (default `medium`) | Adds the tag `priority-{level}` through `add_tags` |
| `mark_read`, `star_entry`, `bookmark_entry`, `hide_entry` | — | Sets that state for the owner |
| `create_note` | `title` (default `Auto-note: {title}`), `content` (default `{summary}`) | Writes a note. Both fields take template variables |
| `send_notification` | `platform` (`discord` default, `slack`, `custom`), `webhook_url`, `channel`, `username`, `message_template`, `include_embeds` | Posts to a chat webhook |
| `send_email` | `to`, `cc` (comma-separated, 20 addresses at most), `subject_template`, `body_template`, `body_format` (`markdown` default, `html`, `text`) | Emails through the instance mail server (`smtp_*`, **Settings → System**). Markdown is sent as HTML with a plain-text copy. In an `html` body, entry values are HTML-escaped and an AI summary is rendered to HTML. At most `smtp_max_per_hour` emails go out per clock hour across the instance; more fail with an error in the run log |
| `run_webhook` | `url`, `headers`, `payload` (JSON string with template variables) | Posts JSON to any URL |
| `extract_ttps` | `use_ai` (default `true`) | Extracts ATT&CK techniques; stores them in `context["extraction_results"]["ttps"]` |
| `extract_cves` | — | Extracts CVE IDs and links them |
| `extract_threat_actors`, `extract_malware` | — | AI extraction, routed through the one-pass `entry_analysis` task |
| `generate_detection_rules` | `rule_types` (default `["sigma"]`) | Builds rules from the TTPs in context, or the entry's stored TTPs |
| `add_to_campaign` | `campaign_id`, `notes`, `link_observables`, `observable_kinds`, `observable_roles` | Links the entry to a campaign. With `link_observables`, also attaches the entry's reporting-door observables (dual-use infrastructure excluded) |
| `create_intel_report` | `title`, `template_type` (default `flash_alert`), `tlp_marking` (default `TLP:GREEN`), `summary` | Creates a report from the entry and the context |
| `track_on_threat_board` | — | Pins the entry's linked actors and malware onto the Threats board as tracked. It never overrides a threat a person already handled or muted |
| `chain_rule` | `rule_id` | Runs another rule on the same entry. The other rule must have the same owner (or the owner is an admin). Loops are refused and chains stop at 5 deep (`MAX_CHAIN_DEPTH`, `backend/app/automation/actions.py:1560`) |
| `branch` | `condition`, `then_actions`, `else_actions` | See [Branch Actions](#branch-actions) |

AI-calling actions always run as an `automation` caller, so they never spend the owner's personal AI key ([Callers](#callers-who-is-asking)).

**What `{ai_summary}` holds.** `run_ai_task` fills it with the result's main text (the first non-empty of `summary`, `text`, `briefing`, `report`, `raw`, `markdown`, `content`, `output`, `body`), in both per-entry and batch mode. The full result is also in `ai_results`.

```json
[
  { "type": "use_daily_summary", "config": { "day": "yesterday" } },
  {
    "type": "send_notification",
    "config": {
      "platform": "slack",
      "webhook_url": "https://hooks.slack.com/services/...",
      "message_template": "Daily briefing\n{ai_summary}"
    }
  }
]
```

### Template Variables

There are two separate variable systems. `backend/app/automation/variables.py` defines both, and the rule builder reads them from `GET /api/automation/variable-contexts`.

**Message templates** use single braces: `{title}`. They work in `send_notification`, `send_email`, `run_webhook`, `create_note` and `create_intel_report`:

`{title}`, `{url}`, `{app_url}` (the article's IntelFeed link), `{author}`, `{summary}` (the AI summary if one exists, else the first 500 characters of the entry summary), `{published_at}`, `{ai_summary}`, `{feed_name}`, `{observables_count}`, `{observables}` (the entry's reporting-door observables, defanged, one per line as `kind value (role)`), `{entry_count}` (entries in a batch run; `1` per entry).

**AI prompt templates** use Jinja2 double braces: `{{ entry.title }}`. They are used by `run_ai_task`:

- Per-entry mode: `entry.id`, `entry.title`, `entry.content_text`, `entry.content_html`, `entry.summary`, `entry.author`, `entry.url`, `entry.app_url`, `entry.published_at`.
- Batch mode: `entries` (a list with the fields above plus `feed_title`, `thread_title`, `outlet_count`, `also_reported_by`), `entry_count` (after folding), `article_count` (before folding), and `entry` (the first item).

### Branch Actions

A `branch` action checks a condition and runs one of two action lists (`_execute_action_chain`, `backend/app/automation/engine.py:27`). The condition uses the same language as the rule's conditions. Both lists share the rule's context.

```json
{
  "type": "branch",
  "config": {
    "condition": { "type": "severity_above", "config": { "min_cvss": 9.0 } },
    "then_actions": [{ "type": "add_tags", "config": { "tags": ["critical"] } }],
    "else_actions": [{ "type": "add_tags", "config": { "tags": ["medium"] } }]
  }
}
```

In a dry run, both branches are listed and neither runs.

### Execution Flow

**One entry** (event triggers):

1. The trigger check passes (keyword, CVE severity, observable filter, ...).
2. `execute_automation` skips the rule if it has no owner.
3. The conditions are evaluated. If they fail, an `AutomationLog` with `status: "skipped"` is written.
4. The context is seeded with `observables_count` / `observables`, then the actions run in order.
5. The log is written with `status: "success"` and the per-action results; `last_triggered_at` and `run_count` are updated. An unexpected exception writes `status: "error"`.

**Many entries** (`on_schedule`, `on_manual`, and Run now): the rule picks entries first.

- **Scheduled runs** select entries with `trigger_config.entry_filter`: `since` (for example `"-24h"`), `since_field` (`fetched_at` default, or `published_at`), `feed_ids`, `category_ids`, capped by `max_entries`. Scheduled runs do **not** evaluate the rule's conditions; the entry filter is the only filter. With no `entry_filter`, only `send_notification` and `run_webhook` run, with no entry.
- **Run now** (`POST /api/automation/rules/{id}/run?hours=24&limit=50`) looks back over recent entries (the rule's `entry_filter.since` and `max_entries` apply when the query parameters are left at their defaults), applies the trigger check and the conditions, then runs the actions.

`execution_mode` in `trigger_config` decides how the actions run over those entries:

- `per_entry` (default): every entry runs the whole action list.
- `batch` (`execute_actions_batch`, `backend/app/automation/actions.py:347`): `send_notification`, `send_email`, `run_webhook`, `run_ai_task` and `use_daily_summary` run **once** over all entries (one digest message or email, one AI prompt). Every other action still runs on each entry.

**Dry run**: `POST /api/automation/rules/{id}/test?entry_id=...` runs the rule against one entry without saving anything. Conditions are evaluated; actions are listed as `dry_run` and not executed.

### One article per story

A morning briefing over 30 articles where 8 cover the same story would spend most of the model's attention, and the reader's, on that one story. So both briefing paths fold their input through [story threads](story-threads.md) first (`fold_by_thread`, `backend/app/intelligence/story_threads.py:926`): one article per story, keeping the **strongest** one, and dropping the rest.

- **`run_ai_task` in batch mode** folds the matched entries. Set `fold_threads: false` in the action config to send every article.
- **The daily briefing** (`_fetch_day_entries`, `backend/app/api/entries.py:1644`) folds the day's articles. This is what `use_daily_summary` and the in-app day-divider summaries read.

Each kept item carries what was folded into it:

| Field | Meaning |
|---|---|
| `entry.thread_title` | The story's name (empty when no thread holds the article) |
| `entry.outlet_count` | Independent outlets covering the story |
| `entry.also_reported_by` | Articles in this batch folded into this one |
| `article_count` | How many articles the batch had before folding (next to the post-fold `entry_count`) |

The daily-briefing prompt shows `outlet_count` as a **Corroboration** line. The action result reports `stories` and `folded` next to `entries_processed`, so the automation log shows how much was collapsed.

Folding only reaches articles the thread sweeper can place. An article shorter than `thread_min_body_chars` (default 400), such as a Reddit link post or an NVD stub, is never threaded, so it never folds.

### Logging & Audit

Every run writes an `AutomationLog` (`backend/app/models/automation_log.py`): `rule_id`, `entry_id` (null when there is no entry), `trigger_type`, `status` (`success` / `error` / `skipped`), `actions_executed` (one result dict per action), `error_message`, `executed_at`.

```json
{ "type": "run_ai_task", "status": "success", "task": "article_summary" }
```

Read logs with `GET /api/automation/rules/{id}/logs` or `GET /api/automation/logs`.

### Webhook Presets

Saved destinations live in the `webhook_presets` table, managed at `/api/webhook-presets`. `preset_type` says which action a preset fills in: `webhook` (URL, payload, headers), `notification` (URL plus platform, channel, bot name and message template in `config`) or `email` (`to`, `cc`, `subject_template`, `body_template` and `body_format` in `config`; no URL). Only the owner or an admin may edit or delete one. The rule builder uses them to fill in an action.

A preset's URL, headers and email recipients show as `<REDACTED>` to anyone who isn't its owner or an admin, so the rule builder only offers your own presets (all of them to an admin). Email recipients in a rule, like webhook URLs and headers, are hidden the same way from anyone who isn't the rule's owner or an admin. An exported rule without secrets imports with a warning for each redacted field, and those actions fail until the fields are filled in.

`send_notification` formats for three platforms:

- **Slack**: Block Kit blocks, `mrkdwn` text, optional `#channel`.
- **Discord**: embeds (long text is split across several), `username` override.
- **Custom**: flat JSON with the entry's fields.

Every webhook URL is checked before the call, including from scheduled rules (`_validate_webhook_url` in `backend/app/automation/actions.py`, built on `backend/app/core/outbound.py`). The hostname is resolved and every address it maps to is checked:

- Only `http` and `https` are allowed.
- Private and shared ranges (10/8, 172.16/12, 192.168/16, 100.64/10 and other non-public ranges) are allowed only while `webhook_allow_private_networks` is `true`, which is the default.
- Loopback, `localhost`, `0.0.0.0`, link-local (169.254/16, where cloud metadata lives; `fe80::/10`) and `fd00:ec2::254` are always blocked.

The HTTP client enforces the same rule on the connection itself and does not follow redirects, so a hostname that changes after the check cannot redirect the request.

---

## Part 2: AI Provider System

### Provider Abstraction

Every backend implements `AIProvider` (`backend/app/ai/providers/base.py`): `complete()` (one prompt in, one `AIResponse` out with text, token counts, latency and an optional provider-reported cost), `stream_complete()` (text chunks; the default calls `complete()` once), `check_health()`, `list_models()`, and the optional `embed()`.

There are four provider types (`backend/app/ai/providers/`):

| `provider_type` | Class | What it talks to | Tools? |
|---|---|---|---|
| `claude` | `ClaudeProvider` | The Anthropic API (API key) | Yes, a Messages API tool-use loop over the backend tool registry |
| `claude_code` | `ClaudeCodeProvider` | The Claude Code CLI under an OAuth sign-in, run in `celery-worker-ai` (see [copilot.md](copilot.md)) | Yes, through the IntelFeed MCP server |
| `ollama` | `OllamaProvider` | An Ollama server (`base_url`, default `http://localhost:11434`) | Yes, a native `/api/chat` tool loop over the backend tool registry |
| `openai_compatible` | `OpenAICompatibleProvider` | Any `/v1/chat/completions` server: OpenAI, LM Studio, vLLM, llama.cpp, LiteLLM, OpenRouter, Groq. `base_url` is required | Yes, a `tools` / `tool_calls` loop, unless the row sets `tools_enabled: false` |

Some tasks only work with tools. `TOOL_REQUIRED_TASKS` (`copilot`, `entity_enrichment_research`) and `provider_type_supports_tools` in `backend/app/ai/capabilities.py` stop you from assigning those tasks to a provider that cannot run tools: today that is only an `openai_compatible` row with tool calling turned off. Background agentic tasks get read-only tools; only the copilot proposes writes, and the user confirms each one (see [copilot.md](copilot.md#the-tool-layer-one-gate-for-every-provider)).

Useful `config` keys by type (provider row, overridable per assignment):

- All: `timeout_seconds`.
- `claude_code`: `cli_path`, `cli_retries`, `allowed_tools`, `max_budget_usd`, `extra_args`, `mcp_server_path`, `agent_api_url`.
- `ollama`: `default_model`, `keep_alive`, `model_overrides`.
- `openai_compatible`: `default_model`, `model_overrides`, `model_filter`, `extra_headers`, `embedding_dimensions`, `pricing` (`input_per_mtok`, `output_per_mtok`), `tools_enabled` (default `true`).
- Agentic tasks on `claude`, `ollama` or `openai_compatible`, per assignment: `agent_tools` (the tool allowlist) and `agent_tools_read_only` (default `true`). `ollama_tools` / `ollama_tools_read_only` are their old names and still work.

### Model Configuration

Providers are rows in `ai_providers` (`backend/app/models/ai_provider.py`):

| Field | Meaning |
|---|---|
| `name`, `provider_type`, `base_url` | Identity and address |
| `api_key_encrypted` | Secret, encrypted with the instance's `ENCRYPTION_KEY` |
| `models`, `config` | Available models and provider settings |
| `is_active` | Off = never used |
| `user_id` | NULL = an instance provider. Set = one person's own key (`is_personal`) |
| `paused_until`, `paused_reason` | Set automatically when the provider reports a quota or rate limit |
| `last_tested_at`, `last_test_error` | Last connection test (`last_test_error` empty = passed) |

An **instance provider** is registered by an admin and is the only kind a site task assignment, the startup seeder, onboarding, embeddings and backup use. A **personal key** belongs to one person and only their own routes use it.

The providers API lists the instance's providers plus your own keys. Someone else's key is a 404 for anything that would use it (test, model list, assignment). The admin may disable, resume or delete any key from the User keys tab, but not rename or repoint it: a `PUT` on someone else's key accepts only `is_active` and answers 403 to any other field (`_owned`, `backend/app/api/ai_providers.py:59`).

```json
{
  "name": "Claude Production",
  "provider_type": "claude",
  "models": ["claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
  "config": { "timeout_seconds": 120 }
}
```

### AI Tasks

A task is a named job with a prompt and an optional JSON output schema, stored in `ai_tasks` (`backend/app/models/ai_task.py`). Key fields: `name` (unique), `display_name`, `category`, `default_system_template` and `default_prompt_template` (Jinja2), `output_schema` (plus an admin `output_schema_override`), `variables` (a hint for the prompt editor only), `is_system`, `is_deprecated`, `allows_user_provider`, and the menu flags `show_in_entry_actions` / `show_in_entity_actions`.

Built-in tasks are seeded at startup from `backend/app/ai/prompts/defaults.py`:

| Task | Category | What it does |
|---|---|---|
| `entry_analysis` | extraction | One-pass analysis of each new article (see [below](#one-pass-entry-analysis-engine-phase-4)). Default `max_tokens` 10000 |
| `entry_adjudication` | extraction | Reviews what `entry_analysis` wrote (links, new entities, relationships, observables) and returns only the verdicts it would change. Runs as the `adjudicate` pipeline stage, no tools, `max_tokens` 4096 |
| `ttp_mapping` | extraction | Maps text to MITRE ATT&CK techniques |
| `article_summary` | analysis | Summary of one entry |
| `threat_assessment` | analysis | Quick assessment and recommended actions |
| `daily_summary`, `intelligence_briefing`, `detection_engineering_summary` | analysis | Briefings over many entries |
| `threat_brief`, `cve_brief` | analysis | The two-sentence story lines on the Threats board |
| `story_thread_spine` | analysis | The narrative spine of a story thread ([story-threads.md](story-threads.md)) |
| `video_transcript_summary`, `reddit_digest` | analysis | Source-specific summaries |
| `entry_qa` | analysis | The per-entry "Ask Agent" chat |
| `copilot` | analysis | The global copilot ([copilot.md](copilot.md)) |
| `detection_rules` | generation | Detection rules from an entry and its TTPs |
| `report_section` and `report_section_{exposure, flash_alert, actor_profile, campaign_tracker, landscape, detection}` | generation | Report sections, one task per report family |
| `actor_profile_refresh`, `entity_name_normalization`, `entity_enrichment_research` | maintenance | Entity maintenance (`backend/app/workers/entity_maintenance_tasks.py`). Seeded for the `claude_code` provider; `entity_enrichment_research` needs a tool-capable provider |

Eight older per-type extraction tasks (`threat_actor_id`, `malware_id`, `tool_extraction`, `country_id`, `sector_id`, `article_metadata`, `mitigation_extraction`, `cve_extraction`) are marked deprecated. They stay in the database so their old results remain readable, they are hidden from run pickers, and the seeder keeps their assignments disabled.

Default models when the seeder creates an assignment: extraction tasks use Haiku, analysis tasks Sonnet, `detection_rules` and `entry_qa` Opus (`DEFAULT_MODEL_ASSIGNMENTS`).

### Task Assignment & Routing

An assignment links one task to one provider and model (`ai_task_assignments`, `backend/app/models/ai_task_assignment.py`): `task_id`, `provider_id`, `model_name`, `is_enabled`, `execution_mode` (`api` or `agent`), and `config` (merged over the provider's config, for example `max_tokens` or `allowed_tools`). A unique constraint on `task_id` means each task has at most one site provider. An assignment may only point at an instance provider; the API refuses a personal key.

Two functions decide who answers:

- `get_task_assignment()` (`backend/app/ai/engine.py:821`) returns the site's enabled assignment whose provider is active and not paused. Background work uses this.
- `resolve_assignment(db, caller, task_name)` (`backend/app/ai/engine.py:609`) is what everything else calls. It returns a `Resolved` (task, provider, model, merged config, and `source`: `"site"` or `"user"`), or `None` when nothing can answer. For any caller that is not a signed-in person, or while personal keys are off, it is just the site assignment. For a person with personal keys on, it adds their own key on top ([Personal Keys](#personal-keys--the-lookup)).

`run_task()` resolves first, then checks for a cached answer, then calls the provider. Code that streams (copilot, rule chat) or calls a provider directly (the shared Ask Agent, rule conversion, the workspace tool) resolves the same way. Report generation runs the lookup when the report is queued (`preflight_report`, `backend/app/ai/engine.py:727`), so a refusal comes back as the request's error before anything is written.

### The `ai` queue

Every Celery task that calls an AI provider is routed to the `ai` queue (`task_routes` in `backend/app/workers/celery_app.py`): entry analysis, adjudication and its backfill, actor profile refresh, name normalization, AI gap enrichment, thread spines, copilot turns, and the two Claude sign-in tasks. Only the `celery-worker-ai` service reads that queue, at concurrency 1 (`CLAUDE_CODE_CONCURRENCY`). This keeps AI calls one at a time, which paces a single Ollama GPU and protects the Claude CLI's OAuth session. It is also the only container that mounts the CLI credentials.

**A new task that calls a provider must be added to `task_routes`.** Left on the default queue, a slow AI call can fill the default worker and stop feed polling.

The enrichment dispatcher has a queue of its own, `enrichment`, read only by `celery-worker-enrichment` at concurrency 1 (see [Enrichment Job Queue](#enrichment-job-queue)).

### Callers: Who Is Asking

Every AI call runs for a `Caller` (`backend/app/ai/caller.py:41`): a *kind* plus the user it is charged to.

| Kind | Used by | `user_id` means | Personal key? | Site allowance? |
|---|---|---|---|---|
| `user` | An API route a signed-in person called | That person | Yes | Yes, when the site's provider answers |
| `system` | Pipeline stages, maintenance jobs, shared output (daily summary, thread spines, briefs) | The `system` account, or nothing | No | No |
| `automation` | The automation engine | The rule's owner | No | No |
| `share` | The public share routes | The person who shared | No | No (the link has its own limit) |

When `run_task` gets no `caller=`, it uses the one set by `caller_scope()` (`backend/app/ai/caller.py:97`), or derives one from `user_id` (`derive_caller`, `backend/app/ai/engine.py:388`): a real person is a `user`; the `system` account, the all-zero id some workers pass, and a deleted account are `system`. The automation engine wraps every action in `caller_scope(Caller.automation(owner))`, so a new action cannot spend its owner's key by mistake.

The kind is saved in `ai_results.caller_kind`. The cost dashboard's By-user table groups on it.

### Personal Keys & The Lookup

An admin can let people register their own AI keys and have the tasks *they* start run on them. Seven settings in the `ai` group control this (Settings → AI Configuration → User keys; defaults in `backend/app/config.py:88-106`):

| Setting | Default | What it does |
|---|---|---|
| `allow_user_ai_providers` | `false` | The main switch. Off = every call uses the site assignment. Saved keys and routes stay but are ignored |
| `require_user_ai_provider` | `false` | With the switch on: refuse an interactive task instead of falling back to the instance's providers |
| `user_ai_provider_types` | `claude,openai_compatible` | Key types a person may register. `ollama` may be added. `claude_code` is never allowed (`PERSONAL_PROVIDER_TYPES`, `backend/app/ai/capabilities.py:74`) |
| `user_ai_allow_private_endpoints` | `false` | Let a personal key point at a private address (a LAN Ollama). Keep it off on a public instance: the server calls whatever URL people enter |
| `user_ai_daily_request_cap` | `300` | Daily call limit on one person's keys. It counts calls, not dollars, because Ollama and unpriced models report $0. `0` = unlimited |
| `site_ai_user_daily_requests` | `0` | Daily requests one person may make on the *instance's* providers. `0` = unlimited. See [Allowances & Caps](#allowances--caps) |
| `share_ai_daily_requests` | `20` | Daily AI calls one share link may make |

A person's routing lives in two tables (`backend/app/models/user_ai_route.py`):

- `user_ai_routes`: one row per `(user, task)`, plus at most one default row (`task_id` NULL). A route names one of the person's own keys, a model, and optional config. A per-task row with no provider sends that task back to the instance's provider even when a default key exists (the picker calls it "Instance default").
- `user_ai_preferences`: `fallback_to_site` (default `true`) and `monthly_cap_usd` (the person's own dollar cap; NULL = none).

**Which tasks may use a personal key** is a per-task flag, `ai_tasks.allows_user_provider`. The rule: does the result belong to the person who clicked? Copilot turns, rule drafts, summaries and report sections do. Entity links, adjudication verdicts, briefs and thread spines are read by everyone, so they always use the instance's providers. `USER_PROVIDER_ELIGIBLE_TASKS` (`backend/app/ai/capabilities.py:53`) lists the 14 tasks that may use one. The admin can turn the flag off for any of them, or on for a custom task, but not on for a task outside that set (`PATCH /api/ai/tasks/{id}` answers 400 `task_site_only`; the task API shows the lock as `user_provider_locked`).

**The lookup**, for a `user` caller with the switch on (`resolve_assignment`, `backend/app/ai/engine.py:609`):

1. Read the site assignment. If the task does not allow personal keys, that is the answer.
2. Find the person's route: the per-task row, else the default row (`_user_route`, `backend/app/ai/engine.py:549`). An opt-out row, a row pointing at a key that is not theirs, or no row means no key.
3. Check the key can answer now (`_route_blocked`, `backend/app/ai/engine.py:571`), in this order: `key_disabled`, `key_paused`, `type_not_allowed`, `endpoint_blocked`, `monthly_cap`, `daily_cap`. The base URL is resolved on every call. An `ollama` or `openai_compatible` key with no address is blocked too, because the empty default would be the server's own localhost.
4. A usable key answers: `source = "user"`, no site allowance, and the result records `key_owner_id`.
5. Otherwise, if the policy is Required, or the person has a key and turned fallback off, raise `UserKeyRequired`: HTTP 403, code `user_ai_key_required`, `details.reason` set to one of the codes above or `no_key`, and a message from `FALLBACK_REASONS`. Under the Optional policy with no key, the site answers silently.
6. Otherwise the site's provider answers. `fallback_reason` is set only when the person *had* a key that could not answer. The site allowance applies. If the site has no provider for the task and the person's key is blocked, the refusal names the reason instead of saying the task is unassigned.

Caps are checked before the call, not reserved, so a burst of parallel requests can go a little over.

The person-facing API is `/api/ai/me` (`backend/app/api/user_ai.py`): `GET /policy`, `GET /overview` (policy, fallback, cap, this month's spend by source and key, and where each task runs), `PATCH /preferences`, `GET`/`PUT /routes`, `DELETE /routes/{id}`. With the switch on, anyone may add a personal key with `POST /api/ai/providers` (personal is implied for non-admins; `?test=true` tests the provider first and saves only if it answers). Admins list everyone's keys at `GET /api/ai/providers/user-keys`. The UIs are Settings → My AI and the User keys tab ([frontend.md](frontend.md)).

### Allowances & Caps

Three limits, each counting something different. All read from `ai_results`, so there is no second ledger. Days reset at midnight UTC.

- **Site allowance** (`site_ai_user_daily_requests`; `enforce_site_allowance`, `backend/app/ai/engine.py:366`): how many requests one *person* may make per day on the *instance's* providers. It counts rows with `caller_kind = user` and no `key_owner_id`. Failed calls count, so a broken provider cannot be retried for free. A cached answer costs nothing: `run_task` enforces the allowance after its cache check. Over the limit is HTTP 429 `ai_allowance_exceeded`. A report checks its whole section count up front; if the allowance still runs out between sections, the worker stops at that section, keeps the earlier ones, and says why. The pipeline, automation and share links are never counted here, and neither is a person's own key.
- **Personal caps**: the person's own `monthly_cap_usd` (the admin sets no ceiling, since it is the person's money) and the operator's `user_ai_daily_request_cap` (how hard this server will drive a personal key). Both count rows with `key_owner_id = that person`. A capped key falls back or refuses as above. The dollar figure is whatever the provider reports or its `config.pricing` says. Because a person sets their own OpenAI-compatible pricing, the request cap is the one limit they cannot price away.
- **Share limit** (`share_ai_daily_requests`): one budget per share link per day, across `POST /api/shared/{token}/run-ai-task` and `.../ask-agent`. Both report `remaining_today`. Both also sit under the per-minute `ai` rate-limit bucket, keyed on the client IP behind the proxy (the first `X-Forwarded-For` hop, or the header named in `TRUSTED_CLIENT_IP_HEADER` when an edge such as Cloudflare fronts the origin). Share traffic always uses the instance's providers.

Prompts run on a personal key are still the instance's templates. The result records `_prompt_version` so the "Who answered" card can say which version ran.

### Prompt Templates

Admins edit prompts at Settings → AI Configuration → Prompts. Overrides are rows in `ai_prompt_templates` (`backend/app/models/ai_prompt_template.py`): `task_id`, `created_by`, `name`, `system_text`, `template_text`, `variables`, `is_active`, `version`.

**Which prompt runs** (`get_active_prompt_versioned`, `backend/app/ai/engine.py:862`): the newest active override for the task (highest `version`) wins for everyone, workers included, whoever saved it. With no active override, the task's `default_system_template` and `default_prompt_template` are used. The system half may be empty.

Prompts are Jinja2, rendered in a sandbox (`render_prompt`, `backend/app/ai/engine.py:815`). Per-entry prompts see `entry`; batch prompts see `entries`:

```jinja2
Summarize these {{ entry_count }} articles into a threat briefing.

{% for entry in entries %}
---
Title: {{ entry.title }}
Summary: {{ entry.summary }}
{% endfor %}
```

A task's `variables` list only feeds the editor's sidebar. Rendering never checks it.

### Task Execution & Results

`run_task()` (`backend/app/ai/engine.py:900`) takes `user_id`, `task_name`, `variables`, and optionally `entry_id` (shorthand for target `entry`), `target_type`/`target_id`, `force`, `timeout_seconds` and `caller`. It:

1. Resolves the provider for the caller. Returns `None` when nothing can answer.
2. Returns the current result for the same target and task, if there is one (unless `force`). A stored provider error does not count as an answer, so a retry after an outage really retries.
3. Enforces the site allowance when the site's provider answers a person.
4. With `force`, marks older results for the target as not current.
5. Picks the prompt and renders it.
6. Calls the provider. `max_tokens` comes from the assignment config, else 16384 for `entry_analysis` and 8192 for everything else. For Ollama, tool-required tasks get the tool registry (read-only by default; non-admin users never get admin tools).
7. Parses the JSON (`parse_ai_json`, `backend/app/ai/engine.py:161`). It recovers JSON from a code fence, repairs illegal backslash escapes, and salvages the complete part of a cut-off response (marked `_truncated: true`).
8. Saves an `AIResult` and publishes an `ai_task_complete` event to the user over SSE.
9. Returns the parsed dict.

Results live in `ai_results` (`backend/app/models/ai_result.py`):

| Field | Meaning |
|---|---|
| `entry_id`, `target_type`, `target_id` | What the result is about. `(target, task, is_current)` is indexed |
| `is_current` | Only the newest result for a target and task is current |
| `task_id`, `provider_id` (SET NULL on delete), `provider_name`, `model_name` | Who answered. `provider_name` survives a deleted provider |
| `prompt_used`, `raw_response`, `parsed_result` | What was sent and what came back |
| `tokens_input`, `tokens_output`, `cost_estimate`, `processing_time_ms` | Usage |
| `caller_kind`, `user_id`, `key_owner_id` | Who asked, and whose key paid (`key_owner_id` set = a personal key) |

`attribution_fields()` (`backend/app/ai/engine.py:72`) fills the last group on every row, error rows included. Calls made outside `run_task` (copilot, rule chat, rule conversion, the shared Ask Agent, the workspace tool) write their own ledger row; most use `record_direct_result()` (`backend/app/ai/engine.py:266`), which writes a spend record that is never current and never served as a cached answer. Two keys may ride in `parsed_result`: `_fallback_reason` (the person's key could not answer and the site did) and `_prompt_version` (an override ran).

**Cost.** When the provider reports a dollar figure (the Claude Code CLI's `total_cost_usd`, an OpenAI-compatible `pricing` block), that is saved. Otherwise the cost comes from `COST_TABLE` (`backend/app/ai/engine.py:36`), dollars per million tokens:

```python
COST_TABLE = {
    "claude-opus-4-6": (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (0.80, 4.0),
}
```

Models not in the table cost $0. Anthropic Message Batches submissions get the 50% batch discount. Every call also updates the Prometheus counters `AI_REQUESTS_TOTAL`, `AI_TOKENS_TOTAL` and `AI_COST_TOTAL`.

`GET /api/ai/cost-breakdown` (admin) covers the last 30 days. It splits what the operator pays (`instance_cost_30d`, no `key_owner_id`) from spend on people's own keys (`user_key_cost_30d`), counts the requests that cost $0 (`unpriced_requests_30d`, so a low bill is not mistaken for low use), and adds `by_caller`: one row per person plus one each for the pipeline, automation and share links, with today's count against `site_allowance_per_user`. The Cost Dashboard renders it.

### Error Handling & Retries

`run_task` returns a dict either way, and `_extraction_status` says what happened:

| Outcome | Saved `parsed_result` | Returned |
|---|---|---|
| Success | The model's JSON plus `_extraction_status: "success"` | Same |
| Not JSON | `{"raw": <text>, "_extraction_status": "parse_error"}` | Same |
| Provider error | `{"_error": <message>}` (current, so the UI shows the failure) | `{"_extraction_status": "provider_error", "_error": ...}` |
| Quota or rate limit | `{"_error", "_extraction_status": "provider_paused"}` (not current) | Adds `_pause_until` |

On a quota error the provider is paused until the reset time the provider gave (or one hour). Celery tasks that see `provider_paused` re-queue themselves for that time. A provider-type mismatch or missing `base_url` is recorded as a provider error instead of crashing the worker.

### Streaming

`stream_complete()` yields text. The default implementation calls `complete()` once; providers override it to stream real chunks.

A stream has no `AIResponse` to price, so each provider saves its stream's usage in `last_stream_usage` (`backend/app/ai/providers/base.py`): the Anthropic SDK's final message, Ollama's `done` chunk, or an OpenAI-compatible server's trailing usage chunk when it sends one. Copilot and rule chat read it after the stream ends and record the turn with real token counts (priced from the cost table when there is no dollar figure), so a streamed turn on a personal key counts toward its monthly cap.

### One-Pass Entry Analysis (engine phase 4)

One `entry_analysis` call per article replaces the old per-type extraction tasks. Its output (summary, actors, malware, tools, TTPs, CVEs, countries, sectors, observables, relationships and more) is fanned out to the same store functions (`store_entry_analysis`, `backend/app/services/entry_analysis.py`).

How an article gets analyzed (switch: `ai_one_pass_enabled`, default on):

1. `score_entry_task` calls `enqueue_entry_analysis`, which checks, in order: an existing result, the feed's AI policy, the relevance junk gate, and **echo reuse** (a near-duplicate copies the original's analysis for $0). A passing entry gets a row in `ai_analysis_requests`.
2. The `ai-analysis-batch-submit` job (every 30 minutes) picks up missed entries, orders the queue by `entries.priority_score`, and stops at the daily budget (`ai_daily_budget_usd`, default $2). On the `claude` provider with an API key and `ai_use_batches` on, it submits through the **Anthropic Message Batches API** (50% cheaper). Otherwise (Ollama, the CLI, an OAuth token, or batches off) it queues `run_entry_analysis_task` per entry on the `ai` queue.
3. `ai-analysis-batch-poll` (every 10 minutes) collects finished batches through `store_external_result`. It is safe to re-run.
4. When the analysis lands, the `adjudicate` stage may review it ([engine.md](engine.md)).

Status: `GET /api/engine/extraction/status`.

The same payload also confirms or rejects **pending autolinks** (dictionary-word matches the autolinker holds until the AI agrees) and asserts entity relationships. The manual per-type extraction endpoints and the `extract_threat_actors` / `extract_malware` automation actions route through `entry_analysis` too, and the result cache means several per-type calls on one entry share one AI call.

The store path (`backend/app/intelligence/enrichment.py`) guards entity quality: it drops new aliases that `is_junk_alias()` flags, rejects new names that `is_fp_entity_name()` flags (the false-positive denylist plus `*.exe` / `*.dll` / `*.sys` file names), and sends would-be duplicates of a reclassified entity to the surviving one (see [intelligence-engine.md](intelligence-engine.md)). The daily digest gets each article's signal explanations (`priority_signals`), so a briefing can say why an article matters.

---

## Part 3: Enrichment Pipeline

### Architecture Overview

Enrichment adds outside facts to entities: a CVE's CVSS score and EPSS probability, an actor's Wikipedia article, an IP address's open ports. The pieces:

1. **Sources**: one class per source, carrying its manifest: 19 that look up one entity at a time and 13 catalog sources that only run scheduled jobs (see [Source Registry](#source-registry)).
2. **The [source gateway](#source-gateway)**: rate limit, cap on requests at once, daily budget, circuit breaker and rejected-key check on every HTTP request, from an adapter or a scheduled job.
3. **Daily budgets**: a per-source cap on requests per UTC day, with a default for each source.
4. **The [job queue](#enrichment-job-queue)**: lookups wait in `enrichment_jobs` until their source allows them.
5. **Caching**: results expire after a TTL the adapter or its manifest sets; a fresh result is reused.
6. **Per-admin API keys**: an admin can store their own key for a source, used for the lookups they start.
7. **The [console](#enrichment-console)**: one admin page for every source's status, limits, queue, fill rates and jobs, plus a global pause.

Sources are configured at Settings → Engine → Enrichment (`/api/enrichment/sources`). After a queued lookup, `apply_enrichment_results_to_entity` (`backend/app/enrichment/entity_updater.py`) writes the fields each source declares onto the entity itself ([Field Map](#field-map)), and each lookup stores what the source says for the profile in `entity_context` ([Source Context](#source-context)). Scheduled jobs hand each answer to the same code (`apply_source_result`), so a job and a lookup write an entity the same way.

### Data Models

All five tables are in `backend/app/models/enrichment.py`.

**`enrichment_sources`**: one row per source. `source_type` (unique), `display_name`, `is_enabled` (a new row starts on when the source has jobs or its manifest sets `default_enabled`; while off, the source is looked up by nothing, its jobs skip and its queued lookups wait), `trigger_mode` (`auto` / `manual`; a `shares_ioc` source's new row is `manual` unless its manifest says `auto`), `api_key_encrypted`, `rate_limit_config` (`requests_per_period`, `period_seconds`), `config`, `min_confidence_threshold` (`low` / `medium` / `high`), `daily_budget` (NULL = unlimited; new rows get the manifest quota's budget), `last_synced_at`, `health_status`. The gateway counts each day's requests in Redis.

**`user_enrichment_overrides`**: a person's own `api_key_encrypted` for a source, one row per user per source, set from the Keys view ([API Keys](#api-keys)). The pipeline uses it in place of the shared key for that person's enrichments.

**`enrichment_results`**: `entity_type`, `entity_id`, `source_type`, `raw_response`, `parsed_data`, `enriched_at`, `expires_at`, `status`. Only `success` and `error` rows are stored; the other outcomes (`cached`, `skipped_low_confidence` and the gateway refusals `rate_limited`, `budget_exhausted`, `backfill_share`, `breaker_open`, `paused`, `auth_failed`, `needs_key`, `gateway_unavailable`) appear only in the list `enrich_entity()` returns. A lookup or a job adds a `success` row only when its `parsed_data` differs from the latest one; otherwise it moves that row's `enriched_at` and `expires_at` forward. The EPSS sync does the same in bulk: it writes only the CVEs whose score changed or whose percentile moved by at least one point, 0.01 (the `cves` row, the result row and its context). A percentile ranks a CVE against all the others, so it drifts a little for nearly every CVE every day; following that drift would rewrite the whole catalog daily, and its rows last 30 days, renewed in bulk once they are within two days of expiring. Its `parsed_data` uses the lookup's keys (`cve`, `epss`, `percentile`, `date`). EPSS records no claims.

**`entity_context`**: what one source says about one entity, one row per declared `Context` output, keyed (`entity_type`, `entity_id`, `source_type`, `key`). `value` (JSONB, shaped for its display), `observed_at`, `expires_at`. See [Source Context](#source-context).

**`enrichment_jobs`**: one pending lookup of one entity at one source, unique on (`entity_type`, `entity_id`, `source_type`). `lane` and its `priority`, `status` (`queued` / `running` / `failed`), `due_at`, `claimed_at`, `attempts`, `last_status` (why it last waited), `last_error`, `requested_by` (whose key a manual job uses), and the entity confidence the threshold check needs. `GROUP BY source_type, lane, status, last_status` shows what is waiting and why.

### Source Registry

Each source is a class that carries its own manifest (`backend/app/enrichment/manifest.py`): the entity types it `applies_to` (for observables, the kinds it handles), what it `requires` (`Key()` for its own API key, `Key("abuse_ch")` for a shared one), its `quota` (rate, period, daily budget, ceiling, `concurrency`: requests in flight at once, 2 unless it says otherwise, and a `keyed` quota used with a key), its `egress` (`none`: downloads a whole catalog; `low`: sends public identifiers such as a CVE id or a group name; `shares_ioc`: sends an observable's value to a third party), its `license`, its scheduled `jobs`, and its `outputs`. An `applies_to` entry can be a `Match(kinds, column)` when the source needs more than the type's usual lookup: `kinds` narrows observables to the kinds it handles, and `column` names the entity column that is looked up instead of the usual one (a ransomware victim by `domain`, a vendor by its `wikipedia_url` for Wikidata). A plain kinds tuple or `None` means the entity's own value (a CVE id, an IP, a hash) or name. An answer stays fresh for the `ttl_hours` the adapter's result sets (24 when it doesn't).

A `scope` (column → values) narrows the entities a source looks up on its own: Team Cymru, RDAP, Shodan, GreyNoise and the three abuse.ch sources set `{"status": ("active",)}`, so aged and expired observables are never queued by the `new` or `backfill` lanes, nor counted in its fill rate or backfill gap. `Source.scope_filter()` turns the kinds and the scope into one SQL condition that `enqueue()` and the console share; a person's request (`manual` lane, the Enrich button) looks up any entity the source applies to. Lookup sources extend `EnrichmentAdapter` (`backend/app/enrichment/base.py`) and look up one entity per `enrich()` call; catalog sources (`backend/app/enrichment/catalogs.py`, and `wikidata.py`, `endoflife.py`, `capec.py`, `ctid.py` and `d3fend.py`, `etda.py` beside it) only have jobs.

`SOURCE_REGISTRY` (`backend/app/enrichment/registry.py`) lists them all; `ADAPTER_REGISTRY` holds the lookup sources. Generated from the manifests:

- `DEFAULT_SOURCES`, the rows the API seeds at startup for any source that has none. A new row takes the quota's rate and budget and the manifest's trigger mode (`seed_trigger_mode()`); it starts on if the source has jobs or sets `default_enabled = True`, off otherwise (`seed_enabled()`). A source that is on only so its jobs run starts `manual`. A `shares_ioc` source starts `manual` unless its manifest says `auto`: Shodan and GreyNoise do, because the ledger's IPs come from published reporting and both only answer from their own scans of the internet.
- The source's entries in `JOB_REGISTRY` ([below](#source-jobs)).
- Its gateway's limits when it has no row yet, and the keyed rate when an API key is in use (see the table).

| `source_type` | Display name | Kind | Entity types | Default trigger | Key? | Default rate | Ceiling | Egress |
|---|---|---|---|---|---|---|---|---|
| `epss` | FIRST EPSS | lookup | cve | manual | No | 100 / 60 s | — | low |
| `nvd` | NVD API 2.0 | lookup | cve | auto | No (optional) | 5 / 30 s; 50 / 30 s with a key; one request at a time | the same | low |
| `cisa_kev` | CISA KEV | lookup | cve | manual | No | 100 / 60 s | — | none |
| `mitre_attack` | MITRE ATT&CK | lookup | ttp, threat_actor, malware, tool, mitigation | manual | No | 10 / 3600 s | — | none |
| `vulncheck` | VulnCheck KEV | lookup | cve | manual | Yes | 1000 / 60 s | 1000 / 60 s | low |
| `osv` | OSV | lookup | cve | auto | No | 100 / 60 s | — | low |
| `malpedia` | Malpedia | lookup | malware, tool, threat_actor | manual | No (optional) | 30 / 60 s | — | low |
| `github_poc` | GitHub PoC | lookup | cve | manual | No (optional token) | 10 / 60 s; 30 / 60 s with a token | the same | low |
| `cvedetails` | CVEDetails | lookup | cve | auto | Yes | 60 / 60 s | — | low |
| `cvelist` | CVE List (cvelistV5) | lookup | cve | manual | No | 30 / 60 s | — | none |
| `wikipedia` | Wikipedia | lookup | threat_actor, malware, tool, country, vendor, product, ttp, mitigation, cve, cwe | auto | No | 20 / 60 s | — | low |
| `virustotal` | VirusTotal v3 | lookup | observable (ipv4, domain, md5, sha1, sha256) | manual | Yes | 4 / 60 s | — | shares_ioc |
| `greynoise` | GreyNoise Community | lookup | observable (ipv4; active) | auto | No (optional key) | 10 / 3600 s | — | shares_ioc |
| `shodan` | Shodan InternetDB | lookup | observable (ipv4; active) | auto | No | 30 / 60 s | — | shares_ioc |
| `cymru` | Team Cymru | lookup + bulk job | observable (ipv4, ipv6; active) | auto | No | 60 / 60 s | — | low |
| `rdap` | RDAP | lookup | observable (domain; active), ransomware_victim (by domain) | auto | No | 1 / 1 s | 1 / 1 s | low |
| `threatfox` | abuse.ch ThreatFox | lookup + export job | observable (ipv4, ipv6, domain, url, md5, sha1, sha256; active) | manual | Yes (abuse.ch, shared) | 10 / 60 s | — | shares_ioc (lookups; the job sends nothing) |
| `urlhaus` | abuse.ch URLhaus | lookup + export job | observable (url, domain, ipv4; active) | manual | Yes (abuse.ch, shared) | 10 / 60 s | — | shares_ioc (lookups; the job sends nothing) |
| `malwarebazaar` | abuse.ch MalwareBazaar | lookup | observable (md5, sha1, sha256; active) | manual | Yes (abuse.ch, shared) | 10 / 60 s | — | shares_ioc |
| `misp_galaxy` | MISP Galaxy | catalog | threat_actor | manual | No | 10 / 3600 s | — | none |
| `metasploit` | Metasploit modules | catalog | cve | manual | No | 10 / 3600 s | — | none |
| `mitre_cwe` | MITRE CWE | catalog | cwe | manual | No | 10 / 3600 s | — | none |
| `ransomware_live` | ransomware.live | catalog | threat_actor | manual | No | 2 / 60 s | 2 / 60 s | none |
| `cybergeist` | Cybergeist | catalog | threat_actor, malware | manual | No | 10 / 3600 s | — | none |
| `wikidata` | Wikidata | catalog | vendor, product, country, ransomware_victim | manual | No | 30 / 60 s | — | low |
| `endoflife` | endoflife.date | catalog | product | manual | No | 1 / 1 s | — | none |
| `tranco` | Tranco | catalog | observable (domain), ransomware_victim | manual | No | 1 / 1 s | 1 / 1 s | none |
| `capec` | MITRE CAPEC | catalog | ttp, cwe | manual | No | 10 / 3600 s | — | none |
| `ctid` | CTID control mappings | catalog | ttp | manual | No | 10 / 3600 s | — | none |
| `d3fend` | MITRE D3FEND | catalog | ttp | manual | No | 10 / 3600 s | — | none |
| `etda` | ETDA Threat Group Cards | catalog | threat_actor | manual | No | 10 / 3600 s | — | none |
| `github_repo` | GitHub repository | catalog | tool | manual | No (optional token) | 60 / 3600 s; 5000 / 3600 s with a token | 60 / 3600 s | low |

The ceiling is the most the source documents it allows; `PUT /api/enrichment/sources/{id}` refuses a `rate_limit_config` above it with a 400 (`rate_above_ceiling`). Each manifest's comment cites the documented limit. A keyed rate (GitHub PoC) applies when the source has a key and its row's rate is still the keyless default, so an admin's own rate stands. The gateway also holds every rate to the ceiling of the quota in use (keyed with a key, keyless without), so a stored rate above that ceiling (one saved under a key that is since gone, for example) never runs above what the source allows: it runs at the ceiling's rate over the row's own period. A catalog source has no lookup: it lists no entity types for manual enrichment, and its test button answers 400.

An adapter sets `default_trigger_mode`, and optionally `shared_key_group` and `throttle_statuses` (the HTTP statuses that mean "slow down"; default 429 and 503). It implements `enrich(entity_type, value) -> EnrichmentData(raw_response, parsed_data, ttl_hours=...)` and may override `check_health()`. A source that makes writes its outputs can't declare (NVD's record and affected products, a CVE record's affected versions) gives them in an `apply_record` hook, which runs for its lookups and its jobs alike. `claim_refs` names the part of an answer a column's claims come from (cvelist's `cvelist:cna` and `cvelist:adp` scores). Adapters make every HTTP request through `self.http(timeout=...)`, a client on the source's [gateway](#source-gateway); none builds its own `httpx` client. A test (`test_enrichment_code_never_builds_its_own_client` in `backend/tests/test_enrichment_gateway.py`) scans every module under `app/enrichment`, `app/workers` and `app/intelligence` and fails on any direct `httpx`, `requests`, `aiohttp` or `urllib` call outside a short allow list. `check_health()` calls the same endpoint as `enrich()`. `supported_entity_types` and `requires_api_key` read the manifest.

### Field Map

A source's `outputs` are `Column`, `Context` and `Relation` entries. A `Column` says which `parsed_data` key is written onto which entity column (`<entity_type>.<column>`, or `<entity_type>.<column>.<key>` for a key inside a JSON column), and how:

| Policy | Writes |
|---|---|
| `fill_blank` | Only into a blank column |
| `rank` | The lowest `rank` wins. A source fills a blank column, replaces a value held by a lower-ranked source, and may update or clear its own value; a "not found" answer clears it only when the output `clears` (Shodan's and GreyNoise's `infra_tag`). A value an analyst set, or one no claim backs, stays |
| `union` | Adds the list items the column doesn't hold yet, outputs in `rank` order |
| `newer_wins` | Replaces what the column holds. An answer without a value leaves the column alone, unless the output `clears` |

A column that `follows` a target is written with it, empty or not, whenever its source writes that target.

For a `rank` column, the holder of the current value is read from its claims: the best rank among the enrichment sources whose claim matches the value. A value only an AI or a reference feed claims holds at no rank, so any source replaces it. Every value a source gives is recorded as a claim, the ones that lose on rank too, so the profile can show each source's answer ("NVD 9.8 · CNA 9.8").

A `filter` transforms the value first: `aliases` runs `filter_aliases()` (`backend/app/intelligence/autolinker.py`), so junk aliases never reach the autolinker vocabulary; `date` turns an ISO date string into a date; `timestamp` turns an ISO date into a datetime for a timestamp column; `country_code` keeps a two-letter code, upper-cased; `asn` keeps a valid AS number (up to 4,294,967,295); `ids` keeps the other ids for a CVE (GHSA, distro ids) without the CVE's own. A `resolve` looks the value up in the database and writes what it finds: `vendor` turns a developer (`{label, enwiki}`) into the id of an existing vendor, the one whose Wikipedia article is that title, else one whose name or alias is the label. It never creates a vendor; with no match nothing is written. `country` and `country_id` turn a country name, alias or ISO code into an existing country's name or id; a placeholder such as "[Unknown]" matches nothing. `apply_enrichment_results_to_entity` (`backend/app/enrichment/entity_updater.py`) applies every output for the entity's type and records a claim (`entity_field_claims`, `source_kind = enrichment`, `source_ref` = the source, or the part its `claim_refs` names) for each value a source gives. What the sources write:

- **Wikipedia**: `wikipedia_url` (newer wins), with `wikipedia_content` and `wikipedia_image_url` following it, so a new article never keeps the old one's image; `description` from `first_paragraph`, rank 1 (rank 2 for a CVE).
- **MITRE ATT&CK**: `description` rank 2, `mitre_id`, `aliases` (union, first), `platforms` (ttp, tool).
- **Malpedia**: `description` rank 3, `malpedia_url` (malware, tool), `github_url` (a tool's first github.com reference), `aliases` (union, after MITRE), actor `country`. A family's attribution becomes `malware attributed_to threat_actor` [relations](#relations); a tool's stays context.
- **VirusTotal, GreyNoise, Shodan**: keys of `Observable.reputation` (`vt_ratio`, `vt_malicious`, `vt_threat_label`, `vt_tags`; `gn_noise`, `gn_riot`, `gn_name`; `ports`, `hostnames`, `shodan_tags`, `vulns`), newest wins, empty values skipped; `reputation.enriched_at` is stamped whenever one of them answers. `infra_tag` is ranked: a Shodan `vpn` / `proxy` / `tor` / `scanner` tag first (in that order), else `benign_service` for GreyNoise RIOT. An IP Shodan newly tags `scanner`, or GreyNoise newly classes as benign mass-scanning noise, gets `needs_review = true` (the two `apply_record` hooks, `backend/app/enrichment/review.py`): it is most likely a research crawler, not attacker infrastructure. The flag is raised only when the signal first appears, so an analyst who cleared it isn't asked again, and a denied row is never flagged. GreyNoise writes `noise_class` (`malicious`, `benign` or `unknown` when it has seen the IP mass-scanning), newest wins; an IP it hasn't seen scanning empties the column, since GreyNoise gives no class for it. VirusTotal writes only its `vt_*` reputation keys; its AS and country show as context, not columns. Shodan's `vulns` also become `exposes` [relations](#relations) to CVEs IntelFeed tracks (one it doesn't track is dropped, not held).
- **Team Cymru**: the observable's network columns, newest wins: `asn`, `asn_org` (the AS name) and `geo_country` (`country_code`). Each fact has one home; none is kept in `reputation`.
- **RDAP**: `registered_at` (newest wins, `timestamp`), the registration date of the registrable domain.
- **Tranco**: `popularity_rank`, newest wins; it `clears`, so a domain that leaves the list loses it. The daily job applies each listed domain's rank, and a "not found" answer for each domain that left, through the field map ([below](#tranco)).
- **MISP Galaxy**: actor `country` (resolved to an existing country), `motivation` (folded onto the motivation vocabulary by the `motivation` filter) and `description` rank 4, into blank columns only, and the cluster's target sectors as `threat_actor targets sector` [relations](#relations). Its synonyms stay resolution knowledge (`known_alias_map`), never profile aliases.
- **Metasploit modules**: CVE `metasploit_module` (newest wins) and the module list as context; its `apply_record` adds Metasploit to the CVE's `exploit_sources`. The job raises `exploit_availability` to `weaponized` itself (never over KEV's `active_exploitation` or an analyst's value) and records that claim with `source_ref = metasploit`.
- **EPSS**: `epss_score` and `epss_percentile`, newest wins, for a single lookup. The daily job writes the same columns set-based and records no claims: a claim per changed score would grow without bound.
- **ThreatFox, URLhaus, MalwareBazaar**: the observable's `role`, into a blank column only: ThreatFox's `threat_type` (`botnet_cc` → `c2`, `payload_delivery` → `delivery`, `payload` → `payload`), `delivery` for a URLhaus malware URL, `payload` for a MalwareBazaar sample ([below](#abusech)).

- **NVD**: `cvss_score` rank 1, with `severity` following it, so NVD's score replaces a CNA's or CISA's; `description` rank 1 (Wikipedia's is rank 2 for a CVE). Its `apply_record` writes the record (`nvd_data`), affected products, references and their `cve_affected` and `cve_weaknesses` links. The NVD jobs apply their answers the same way (`apply_nvd`, `backend/app/intelligence/cve.py`). Article extraction and the KEV sync don't call NVD: they queue the CVE, and NVD answers from the queue while it is switched on.
- **CVE List (cvelistV5)**: `cvss_score` from the CNA's metric rank 2 and from CISA-ADP's rank 3, with `severity` following the score it wrote (so a score never sits beside extraction's `UNKNOWN`); their claims are `cvelist:cna` and `cvelist:adp`. `description` rank 1, since NVD republishes the CNA's text; `ssvc_exploitation`, `ssvc_automatable` and `ssvc_technical_impact`, newer wins; `kev_date_added` from CISA-ADP's KEV entry, into a blank column only. CVSS 3.1 is preferred, then 3.0, then 4.0. Its `apply_record` links the record's CWE ids (`cve_weaknesses`) and writes `cve_affected` rows from the CNA's `affected` list (`source = cna`, with the version range) and CISA-ADP's CPEs (`source = cisa_adp`, no versions).
- **OSV**: `aliases` (union): the GHSA and distro ids for the same CVE. A new CVE is looked up once; after that the hourly `osv-delta-sync` job applies only the records that changed, so an answer stands 30 days between refreshes.
- **Wikidata**: vendor `website` and `country_id`, product `vendor_id` (resolved to an existing vendor), country `region` and `iso_code`, ransomware victim `country_id`, all into blank columns only. A vendor's industries become `vendor operates_in sector` [relations](#relations) where they map onto the sector vocabulary; the rest are dropped.
- **endoflife.date**: product `support_status` and `next_eol`, newer wins; both `clear`, so `next_eol` empties when no end date is left, and a product that stops matching an endoflife.date product loses both (the sync answers it "not found" after a run that went through).
- **CTID control mappings**: technique `nist_controls` and `cis_controls`, newer wins; both `clear`, so a technique the mappings drop loses its controls.
- **ETDA Threat Group Cards**: actor `aliases` (union, after MITRE and Malpedia, through the alias gate first), `country` and `origin_country_id` (both resolved to an existing country), `motivation`, and `mitre_id` rank 3, all into blank columns only.

A `Context` (key, label, display: `fact`, `chips`, `table`, `timeline`, `link` or `badge`) is a value for the entity's profile rather than a column; the adapters declare them (Shodan ports and tags, GreyNoise's class, Team Cymru's announced prefix, registry and allocation date, RDAP's registrar, expiry, status and nameservers, OSV affected packages, Malpedia references, and so on). `entity_types` limits one to some of the source's types.

A `Relation` (key, relation, target types, and an optional `item` naming each row's `name`, `evidence` and `aliases` keys; a name that matches nothing is tried under its aliases, as ThreatFox's `malware_alias` list is) turns a `parsed_data` list into claims that the entity is connected to other entities. See [Relations](#relations).

### Source Context

Each lookup in `enrich_entity()`, fresh or cached, writes the source's `Context` outputs for the entity into `entity_context` (`store_context`, `backend/app/enrichment/context.py`): one row per output that has a value, `observed_at` the result's time and `expires_at` its expiry. A key the new result lacks is deleted, so a source that stops reporting something stops showing it. Scheduled jobs store each entity's answer the same way (`apply_source_result`, `backend/app/enrichment/pipeline.py`): the result row (a new one only when the answer changed), its context, the source's `apply_record` writes, then its columns and relations through the field map. It reports whether the answer `changed` and whether the entity was `written`, which the jobs count. Values are stored shaped for their display:

| Display | Stored value |
|---|---|
| `fact` | A string or number; `true`/`false` as `yes`/`no`, a list joined with commas |
| `chips` | A list of strings; a comma-separated string is split, repeats dropped |
| `table` | `{columns, rows}`: `item` maps each column to a key of every listed row (`None` takes the row itself, for a list of plain values); cells are a string, number or null |
| `timeline` | `[{date, text}]`, from the `date` and `text` keys `item` names |
| `link` | `{url}` or `{url, label}`; only `http(s)` URLs |
| `badge` | The raw value. `tones` maps a value to its tone, and only those values become a badge |

`GET /api/entities/{entity_type}/{entity_id}/context` (`backend/app/api/entity_context.py`) serves the profile's Context panel and header badges:

- `sources`: each enabled source that applies to the entity (for an observable, to its kind) and declares context for it, sorted by name, with `label`, `license`, `observed_at`, `stale` (past `expires_at`) and its `items` (`key`, `label`, `display`, `value`). A source with nothing stored yet is listed with empty `items` and `observed_at: null`.
- `badges`: the badge items whose value has a tone, labelled `"<label> · <value>"` (just the label for `true`). A badge whose key the source also writes to a column carries `field` (GreyNoise's class: `noise_class`), so the header shows that column's provenance.
- `unavailable`: for admins only, enabled sources missing a requirement (`needs: "api_key"`). Such a source is in `sources` only while it has stored items.
- `can_enrich`: false for visitors.

The panel's Refresh and "Enrich now" buttons name every source in `sources` in `source_types`, so auto-mode sources such as NVD run too; ↻ on a block names that one source.

In public read-only mode a visitor never sees a source whose `egress` is `shares_ioc` or whose license has `commercial_ok = False`, and gets a 404 for an entity the visitor filter hides.

#### Context columns in the entity tables

The `fact`, `badge` and `chips` outputs also show as columns in the workbench entity tables (threat actors, malware, tools, vendors, CVEs, techniques, observables), hidden until picked in the Columns menu (`backend/app/enrichment/context_columns.py`). Each column is named `ctx:<source_type>:<key>`, for example `ctx:epss:epss`.

- `GET /api/entities/{entity_type}/context-columns` lists the columns of each enabled source, by the same visitor rule as the panel.
- `POST /api/entities/{entity_type}/context-values` with `{"ids": [...]}` returns `{entity_id: {column: value}}`, at most 1000 ids per request. The table sends one request per page of 100 rows as it loads, as it does for relationship signals, so every row it scrolls to fills in.
- The type's list endpoint sorts on a column with `sort_by=ctx:…` (rows with no value last, either direction; lists sort by length first) and filters with `ctx:…=<filter>`: text matches anywhere in the value; `>N`, `>=N`, `<N`, `<=N`, `=N` compare numbers, or a list's length; any other operand compares as text, so `>2025-06` works on ISO dates; `*` means has a value and `!` means has none. A column the user can't see is a 400.

When an entity is merged into another of its type, its context rows move to the survivor with it (`rehome_context`, `backend/app/enrichment/context.py`), one source at a time: a source that already has rows on the survivor keeps its own. Reclassified into another type, the rows are dropped and the next lookup fills them.

`prune-entity-context` (maintenance, daily 02:45 UTC, `prune_entity_context` in `backend/app/workers/maintenance.py`) deletes rows that expired more than 30 days ago and rows whose entity no longer exists, and withdraws relation claims whose entity no longer exists, by the same rules as a source's withdrawal, so their connections go with them. It belongs to no source, so it is a maintenance job rather than one in a manifest.

### Trigger Modes

| Mode | When it runs |
|---|---|
| `auto` | When an entity is created: the autolinker, TTP and CVE extraction, the KEV sync, the observables ledger and GitHub rule import add a `new`-lane [job](#enrichment-job-queue) for each such source |
| `manual` | A person asks: `POST /api/enrichment/enrich`, or an "Enrich" button. It runs at once, in the `manual` lane; naming `source_types` runs those sources whatever their mode. A source the gateway refuses gets a `manual`-lane job, listed in the response's `queued` |

A source that sends an observable to a third party (`shares_ioc`: VirusTotal, GreyNoise, Shodan, the abuse.ch lookups) is never queued on the automatic lanes unless its row is `auto`. Shodan and GreyNoise start `auto`; VirusTotal and the abuse.ch lookups start `manual`.

### Pipeline Flow

`enrich_entity()` (`backend/app/enrichment/pipeline.py:282`) loops over the enabled sources whose `trigger_mode` matches (or the named `source_types`). For each source:

1. Skip it if it is a catalog source or does not apply to the entity type.
2. Resolve the API key ([below](#api-key-resolution)).
3. **Auto mode only**: skip it if the entity's confidence is below the source's minimum (`skipped_low_confidence`).
4. If a fresh `success` result exists, return it (`cached`). No budget is used.
5. Call `adapter.enrich()` and store a `success` row that expires after `ttl_hours` (or re-date the latest row when `parsed_data` is unchanged), and write the source's [context](#source-context). If the adapter raises, store an `error` row that expires after 1 hour.
6. If the source's gateway refuses a request, report why (`rate_limited`, `budget_exhausted`, `backfill_share`, `breaker_open`, `paused`, `auth_failed`, `needs_key` or `gateway_unavailable`) and store nothing; the job queue tries again later.

### Enrichment Job Queue

Waiting enrichment work lives in `enrichment_jobs` (`backend/app/enrichment/queue.py`), so a lookup a source refuses is put off, never lost.

`enqueue()` writes one row per applicable source: enabled and handling the entity type, and for the `new` lane also `trigger_mode='auto'`. Any lane may name sources. A `shares_ioc` source is queued on the automatic lanes (`new`, `refresh`) only when its row is `auto`. Queueing the same entity and source again updates the row: it keeps the higher lane (and that lane's requester) and the earlier `due_at`, and a `failed` row goes back to `queued`. A row the source put off (rate limit, breaker, budget, backfill share, rejected key, pause) keeps its `due_at`: asking again doesn't bring it forward. It runs in a savepoint, so a failure never costs the caller its transaction.

| Lane | Priority | Queued by |
|---|---|---|
| `manual` | 0 (first) | `POST /api/enrichment/enrich`, for each source the gateway refused |
| `new` | 1 | A new entity (the `auto` trigger), including the CVEs article extraction and the KEV sync add |
| `refresh` | 2 | Reserved for re-checks of known entities; no caller queues it |
| `backfill` | 3 | `POST /api/enrichment/sources/{source_type}/backfill`, the console's Backfill button |

`dispatch_enrichment_jobs` runs every 30 seconds on the `enrichment` queue, which only `celery-worker-enrichment` reads, one task at a time. Each tick works for at most 25 seconds. Engine → Jobs records a tick only when it ran or settled something, or failed (`record_idle: False` in its registry entry), so an empty queue doesn't fill `job_runs`. It claims due rows of enabled sources with `FOR UPDATE SKIP LOCKED`, ten at a time, by priority and then `due_at`, marks them `running`, and runs each through `enrich_entity(..., source_types=[source])`. A `new`-lane job is held to the source's confidence threshold; the other lanes are not. A `manual`-lane job runs with `refresh`, because a person asked for that lookup and the source refused it, so the stored result is not the answer. Results are written onto the entity with `apply_enrichment_results_to_entity`. Then the row is settled:

| Outcome | Row |
|---|---|
| `success`, `cached`, `skipped_low_confidence`, `needs_key`, or the source no longer applies | Deleted |
| `rate_limited`, `breaker_open` | Due again after `retry_after`; attempts unchanged |
| `budget_exhausted`, `backfill_share` | Due at the next UTC midnight |
| `auth_failed` | Due again in an hour; attempts unchanged |
| `source_disabled` (switched off mid-run) | Put back as it was; it waits until the source is on again |
| `paused` | Due again in 60 seconds; attempts unchanged, and the rest of the tick's batch waits the same way |
| `gateway_unavailable` | Put back as it was, and the tick ends |
| `error` | `attempts` + 1, due again after 5 minutes doubled per attempt; `failed` after 5 attempts (the row stays, and is not claimed again until it is queued anew) |

When a source refuses one job (`rate_limited`, `breaker_open`, `budget_exhausted`, `auth_failed`), the tick holds that credential (the source and the job's requester) without asking the source again. One UPDATE moves all of the credential's other due rows, the rest of the batch included, past the refusal, one request interval of the source's rate apart (for VirusTotal at 4 a minute, 15 seconds), so a backlog comes due one row at a time rather than all at once. The tick claims none of the credential's rows while the hold lasts, and goes on with other sources.

A row queued again while it runs (a person asks for it mid-run) is not deleted or rescheduled by the run's outcome: it goes back to `queued` as that enqueue left it (the higher-priority lane and that lane's requester, the earlier `due_at`), and runs again. The upsert stamps `updated_at` with the clock and the claim stamps `claimed_at` and `updated_at` with its own transaction time, so settling tells the two apart.

A `backfill` job runs only while its source has used less than 60% of its `daily_budget` today (when it has one); otherwise it waits for the next UTC day (`last_status = backfill_share`). Its requests also run in the gateway's backfill lane, so the 60% holds per request, the same cap the scheduled backfill jobs get. The other lanes are not capped by this.

A disabled source's rows wait in the queue: the dispatcher doesn't claim them, and switching the source back on picks them up.

While enrichment is [paused](#enrichment-console), a tick claims nothing. A `running` row claimed more than 10 minutes ago is claimable again, so a worker that dies mid-tick strands nothing. A row is marked `started` (`last_status`) when its run begins, so a reclaim counts an attempt (`last_status = lease_expired`) only for the row that was running; the rest of the dead worker's batch is claimed again as it was. A row whose lease expires on its fifth attempt is marked `failed`, so a job that kills or outlasts its worker stops coming back. When every row a claim took is failed that way, the tick claims again (up to five times) rather than ending with work due. A tick still waiting when the next one is due is dropped (`expires` 30 seconds), so a restarted worker does not run a backlog of ticks.

### API Key Resolution

`resolve_api_key()` (`backend/app/enrichment/pipeline.py:72`) tries, in order:

1. The calling user's override for this source.
2. The source's own key.
3. A key on a sibling source in the same `shared_key_group` (the user's override first, then the sibling's own key).
4. The instance setting the source names as its `key_setting`: `nvd_api_key` for NVD, `github_token` for GitHub PoC and GitHub repository.

Scheduled jobs resolve their key through the same function (`gateway_for`), so a job and a per-entity lookup with the same key always share one gateway allowance.

ThreatFox, URLhaus and MalwareBazaar set `shared_key_group = "abuse_ch"` (`SHARED_KEY_GROUPS`, `backend/app/enrichment/registry.py:121`): one abuse.ch key serves all three, and they draw on one gateway allowance for it. Queued jobs run in a worker with no user, so they use the shared key, except a `manual`-lane job, which uses the key of the person who asked.

### API Keys

Settings → Engine → Enrichment → **Keys** is the one place enrichment keys are set (`backend/app/enrichment/keys.py`). It lists one row per **credential**, which is what one key unlocks:

- a shared key group (`abuse_ch`: ThreatFox, URLhaus, MalwareBazaar),
- an instance setting a source names as its `key_setting` (`nvd_api_key` for NVD; `github_token` for GitHub PoC, GitHub repository and GitHub repository feeds),
- a single source's own key (VirusTotal, VulnCheck, CVEDetails, and GreyNoise, whose `optional_key` raises its limit).

Each row says which sources use the key, whether the shared key is set, missing (and needed), optional, or rejected (a member that is on has a recorded auth failure), and whether you have your own key. Where each key is stored:

- A setting credential stores its key in the setting. A key left on a member's source row is cleared, so the setting is the only copy.
- A group or single-source credential stores the key on every member's row.
- Your own key is an override on every member's row. It replaces the shared key for the lookups you start.

| Method | Path | What it does |
|---|---|---|
| GET | `/api/enrichment/keys` | The rows above. Keys are never returned |
| PUT | `/api/enrichment/keys/{id}` | Set the shared key (`{"api_key": "…"}`); an empty key removes it |
| PUT | `/api/enrichment/keys/{id}/mine` | Set or remove your own key (admin) |
| POST | `/api/enrichment/keys/{id}/test` | Probe the shared key through a member with a lookup: `ok`, `rejected` (the source turned the key down), `unreachable` (it did not answer), `missing` or `untestable`. A probe the gateway refuses answers 429 or 503 and says nothing about the key |

`PATCH /api/settings` and `DELETE /api/settings/{key}` refuse `nvd_api_key` and `github_token` (400 `set_in_enrichment_keys`), and `PUT /api/enrichment/sources/{id}` takes no key.

### Confidence Thresholds

A source's `min_confidence_threshold` stops cheap or low-value indicators from using up a paid quota (`_passes_confidence_threshold`, `backend/app/enrichment/pipeline.py:40`):

- `low` (or empty) enriches everything.
- An entity with no confidence value at all (most non-observable entities) always passes.
- Otherwise the entity passes if its text level (`high` 3 / `medium` 2 / `low` 1) meets the threshold, or its numeric confidence meets `high` 0.7 / `medium` 0.4.

Only auto enrichment (`new`-lane jobs) checks this. Manual enrichment skips it.

### Relations

A `Relation` output says "this entity is connected to the entities this list names". ransomware.live's `Relation("techniques", "uses", ("ttp",), item={"name": "technique_id", "evidence": "technique_details"})` means: each row of `techniques` names a technique the group uses, and `technique_details` says how. `apply_relations` (`backend/app/enrichment/relations.py`) runs for every source result that `apply_enrichment_results_to_entity` applies, so a lookup and a catalog job (`apply_catalog_result`) handle relations the same way. No source has its own code there.

For each name the source lists:

1. **Resolve, never create.** The name is matched to an entity IntelFeed already has, in each target type the output names: a technique by its id, a sector through the sector vocabulary (`normalize_sector`), a country by name, alias or ISO code, and a threat actor, malware family, tool, vendor or product by its exact name or alias in the resolver's normalized form (`entity_alias_index`). Nothing is ever created.
2. **Check the matrix.** The triple (entity type, relation, target type) must be in the relationship matrix (`backend/app/intelligence/relationship_matrix.py`). An output with no allowed triple never runs, and a name that resolves to a type the matrix doesn't connect that way gives no claim.
3. **Claim.** Each name is one row in `entity_relation_claims`: entity, source, output, the name, the resolved target, and the evidence. A re-run with the same list changes nothing.
4. **Connect.** A resolved claim makes the connection exist where IntelFeed keeps that kind of fact. A target sector of an actor or malware family goes in the target-sector junction (`threat_actor_target_sectors` / `malware_target_sectors`, source `enrichment`), so the sector chips show it. Anything else goes in `entity_relationships`: a new row is source `enrichment`, confidence `probable` (reported, not corroborated), and its description is the evidence, or the source's name when there is none. A co-occurrence row for the same triple is taken over and lifted to `probable` only while it is `possible` with no adjudication verdict, and keeps its own description, so a withdrawal can hand it back exactly as it was. A co-occurrence row that corroboration or the adjudicator already raised (or ruled coincidental), and a row from any other path (AI extraction, MITRE, an analyst, a rejection), is left exactly as it is; the claim is still recorded. The adjudicate stage reviews only `co_occurrence` and `auto_extracted` rows, so it never relabels an `enrichment` row.
5. **Hold.** A name that matches nothing (`held_reason = unknown`), or more than one entity (`ambiguous`, such as a tool and a malware family with the same name), is stored with no target. The source's next answer resolves it again, so it links once the entity exists. The console's source detail counts the held claims per output.
6. **Withdraw.** A name the source no longer lists loses its claim. Its connection goes too, but only when no other claim (from any source) still holds it and it is one this path made, still as this path left it: an `enrichment` row at `probable` is deleted, or handed back to `co_occurrence` / `possible` when articles back it. A withdrawal never lowers what someone else raised: an AI extraction that asserts an `enrichment` row makes it `auto_extracted`, and a row that reviews or MITRE raised to `confirmed` keeps its connection, losing only the claim; an `enrichment` sector row is deleted, or handed back to the rollup when the entity's own articles carry the sector. One source's withdrawal never touches another source's claim.
7. **Merge.** When an entity is merged into another of its type, its claims (made by it, or naming it) move to the survivor with their connections (`rehome_claims`, called from `_repoint_entity_relationships` in `backend/app/api/entity_merge.py`); a claim the survivor already makes is dropped. Reclassified into another type, the claims are withdrawn first, by the rules above, and the source's next answer for the survivor claims afresh.

The claim always runs from the entity the source answered for; the connection runs the way the matrix stores it. The matrix keeps observables target-only, so when an observable's source names the malware family behind it (ThreatFox, URLhaus, MalwareBazaar), the connection is the family's: `malware communicates_with observable` for a C2, `malware uses observable` for delivery and payload material, `tool communicates_with observable` for a C2 framework. These show in the family's Infrastructure (claimed) and the observable's claimed-by list.

An output with `hold=False` drops a name that resolves to nothing instead of holding it. URLhaus uses it for its tags, which mix family names with file types and architectures (`exe`, `32-bit`).

Both ends' cached pivots and graphs are cleared when a connection changes.

### Caching & TTL

A `success` result is reused until `expires_at`. Each adapter picks its TTL per result, for example:

- Wikipedia: 720 hours (30 days). Not-found: 168 hours.
- NVD, Malpedia, MITRE ATT&CK, GreyNoise, Team Cymru, RDAP: 168 hours (7 days). An unannounced IP at Team Cymru: 24 hours.
- EPSS, CISA KEV, VulnCheck, GitHub PoC: 24 hours.
- VirusTotal, and the ThreatFox, URLhaus and MalwareBazaar lookups: 72 hours. ThreatFox's export answers: 48 hours (a daily job); URLhaus's: 24 hours (every six hours).
- Wikidata: 720 hours, not-found titles included. endoflife.date: 48 hours (its job runs daily). CAPEC, CTID and D3FEND: 14 days (their jobs run weekly).
- ETDA: 336 hours (two weekly runs). ransomware.live group profiles: 168 hours, unknown groups included.
- Short-lived misses (a missing VirusTotal or VulnCheck key, a failed Wikipedia fetch): 1 hour. These misses are stored as `success` rows with `found: false`, so they are cached too.

### Source Gateway

`SourceGateway` (`backend/app/enrichment/gateway.py`) is the only way enrichment reaches the network. Every request carries IntelFeed's User-Agent; Wikipedia and Wikidata requests add the `wikimedia_contact_email` setting to it (`user_agent()`), since Wikimedia's User-Agent policy asks for a way to reach the operator. The setting sits on those two sources' Limits tab (a manifest's `settings_keys` are settings that configure the source itself). The pipeline, the key test and the health check build one per source from its row (`adapter_for_source()` in `registry.py`); scheduled jobs and the profile page's Wikipedia fetch get the same one from `gateway_for()` (`backend/app/enrichment/pipeline.py`). Its httpx transport checks every HTTP request, not every `enrich()` call:

1. **Pause.** While enrichment is paused, every request is refused (`paused`).
2. **Circuit breaker.** While it is open, requests are refused (`breaker_open`).
3. **Rate limit and daily budget**, in one Redis script. The rate limit is a token bucket: `requests_per_period` tokens that refill over `period_seconds` (the source's `rate_limit_config`). The budget is `daily_budget` requests per UTC day (NULL = no limit). A request takes a token and is counted against the budget, or does neither, so refused requests cost nothing. The same script counts each sent request in an hourly counter per source type, `enrichment:gw:stats:{source_type}:{YYYYMMDDHH}`, kept 48 hours; the console reads these.
4. **Short wait.** If the next token is at most 2 seconds away the request waits for it; otherwise it is refused (`rate_limited`). Scheduled jobs wait up to 120 seconds (`JOB_TOKEN_WAIT`), so the bucket paces them through their backlog.
5. **User-Agent.** Every request says `IntelFeed/<version> (+<public URL>)`, using `PUBLIC_BASE_URL` (or the project page when it's blank).
6. **The answer.** A throttle status (429 or 503; NVD and GitHub PoC add 403, their `throttle_statuses`) opens the breaker for the `Retry-After` time (seconds or a date), or for a backoff that starts at 60 seconds and doubles up to an hour when there is none, and the request ends as `rate_limited`. Three 5xx answers or connection errors in a row open it for the same backoff. Any other answer closes it.

The bucket, budget and breaker belong to the credential, not the source type: they are keyed by the adapter's `shared_key_group` when it has one, else by `source_type`, plus a short hash of the API key when one is used. A user's own key has its own allowance; sources sharing one key share one. The keys live under `enrichment:gw:` in Redis.

If Redis can't be reached, the gateway refuses the request (`gateway_unavailable`) and sends nothing.

A source whose manifest `requires` an API key gets a gateway that refuses every request while it has none (`needs_key`), before anything else, so no lookup, job or health check sends it a keyless request. A queued lookup that meets it is done, not retried.

Team Cymru answers over DNS and bulk WHOIS, not HTTP, so its adapter takes each query's permit itself. A person's lookup and a new IP go over DNS (two TXT queries); the `cymru-bulk-sync` job sends every active IP that is due down one WHOIS connection to whois.cymru.com:43 under one permit, as Team Cymru asks for batches. For DNS: `gateway.acquire()` before the TXT query and `gateway.record()` after it, so the rate limit, budget, breaker and pause apply the same way. An NXDOMAIN (an unannounced IP) counts as an answer; a timeout or resolver failure counts toward the breaker.

Wikipedia goes through the gateway too: `wikipediaapi` takes the gateway's transport for the httpx client it builds, with its own retries off.

**Jobs.** A job (NVD, EPSS, CISA KEV, MITRE ATT&CK, Malpedia, GitHub PoC, Wikipedia, CVE List, Wikidata, endoflife.date) uses its source row's rate limit, budget and key, so it shares one allowance with the per-entity lookups under the same key. The NVD sweeps fall back to the `nvd_api_key` setting and the GitHub PoC scan to `github_token` when the row has no key; a different key has its own allowance. The catalog sources' jobs (MISP Galaxy, Metasploit, MITRE CWE, Cybergeist, ransomware.live, Tranco, CAPEC, CTID, D3FEND, ETDA) use their rows the same way.

When the gateway refuses (`rate_limited`, `breaker_open`, `budget_exhausted`, `paused`), a job stops, commits what it has done, and records the reason as `stopped` in its stats, which land in the run's details in the Jobs view. The run still counts as a success. Loop jobs also stop with `stopped: "out_of_time"` before their time limit. `gateway_unavailable` fails the run.

NVD allows 50 requests per 30 seconds with a key and 5 without. The NVD row's default rate is the keyless 5 per 30 s; with a key in use the gateway runs it at the keyed 50 per 30 s, unless an admin has changed the row's rate. A rate the row holds above 5 per 30 s runs at 5 per 30 s whenever no key is in use. The bucket refills while it drains, so on its own it could let up to twice its rate through in one window; the NVD sweeps also sleep 0.7 s between lookups with a key and 6.5 s without (`nvd_request_pace()`).

### Daily Budgets

Every source starts with a budget of about twice the requests a busy day sends (the `daily_budget` of its manifest's `quota`): CVE List 12,000, NVD 5,000, Wikipedia 2,000, OSV 2,000, GitHub PoC 1,000, Malpedia 1,000, Team Cymru 4,000 (two queries per IP over DNS, one per bulk connection), RDAP 2,000 (two requests per domain: rdap.org's redirect and the registry), Shodan 1,000, CVEDetails 1,000, VulnCheck 1,000, endoflife.date 1,000, EPSS 500, CISA KEV 500, VirusTotal 500 (its free tier), ThreatFox, URLhaus and MalwareBazaar 500 (one budget for the three: see below), Wikidata 500, ransomware.live 200, MITRE ATT&CK 100, GreyNoise 100, and 50 each for MISP Galaxy, Metasploit, MITRE CWE, Cybergeist, CAPEC, CTID and D3FEND, ETDA; Tranco 20. An admin can change or clear one under Settings → Engine → Enrichment. A source that runs out stops until midnight UTC, jobs included. Every request the gateway sends counts; cached results are free. Sources in one `shared_key_group` using the same key count against one budget: each stops when the group's requests today reach its own `daily_budget`, so ThreatFox, URLhaus and MalwareBazaar together send at most 500 a day. The console's source detail (`used_today`, labelled with the group) and the source list's `daily_budget_used` show today's use under the source's key, the whole group's for a grouped source, and `GET /api/enrichment/sources/{id}/health` shows the tokens left in its bucket.

### Enrichment Console

Settings → Engine → Enrichment is one admin page for every source (`frontend/src/components/engine/EnrichmentConsole.tsx` and `frontend/src/components/engine/enrichment/`). Each control has one home:

- The header has the Running / Paused state and **Pause all sources**.
- A strip of 24-hour numbers: requests (with a sparkline), lookups waiting (and how many are backfill), lookups put off by a rate limit or cap, distinct indicators sent to `shares_ioc` sources, and whether the limiter is healthy.
- **Needs attention** lists each problem in one sentence with the one button that fixes it.
- **Sources**: the list (filtered by entity type; on first, the rest under "Available") and a side panel for the chosen source. The panel says what the source is, what it sends out, its license and which key it uses (a link to Keys), then has four tabs: **Overview** (today against the cap, the queue by lane), **Limits** (rate, cap, auto or manual), **Fields** (fill rates and backfill) and **Jobs** (schedule, run now, last counts, and the settings that tune each job, such as `cve_reenrich_batch_size`).
- **Coverage**: how full each field is, who fills it, and a backfill or "Ask the AI for 10".
- **Keys**: see [API Keys](#api-keys).
- **Activity**: the queue by lane, the lookups that gave up (with retry), and requests by source.

A settings search that lands on the page opens the setting's home: a key in Keys, a job setting on its source's Jobs tab. `?section=enrichment&source=nvd` opens a source on its Jobs tab; `&key_for=virustotal` opens that source's key in Keys (a profile's "Add key" link). Its API (all admin) is built in `backend/app/enrichment/console.py`.

**`GET /api/enrichment/console`** lists the sources and, at the top level, `attention`. Each source has a status word, what it fills (a few words from the manifest's outputs, or the first job's description for a catalog source), its `about` sentence, `egress`, license, credential (`key`, `key_status`), `trigger_mode` (lookup sources only), today's use against its cap, and the settings its jobs read. `?entity_type=` narrows only the source list. The status is, in order:

| Status | When |
|---|---|
| `key_rejected` | It is on and the source turned its key down (the gateway recorded an auth failure) |
| `failing` | It is on and one of its jobs last ended in an error, or its circuit breaker is open |
| `needs_key` | It needs an API key, or an instance setting, and has none |
| `off` | It is switched off |
| `ok` | Otherwise |

A source that is off is never `failing`: its old errors aren't something to act on. Each `attention` item names the problem of a source that is on, with an `action`: a rejected or missing key (`key`, with the credential id), a failing job (`source`, Jobs tab), an open breaker or missing setting (`source`), or lookups that gave up (`retry`). One key problem shared by several sources is one item, labelled with the key. A source whose row was added in the last 14 days, at least a day after the install's first sources, is marked `new`. The summary's 24-hour activity counts requests sent (from the hourly counters), lookups waiting now, lookups put off by a rate limit, cap or pause, and distinct indicators sent to `shares_ioc` sources (`record_ioc_sent`, one HyperLogLog per UTC hour in Redis).

**`GET /api/enrichment/sources/{source_type}/detail`** gives one source's limits (the row's stored `rate`, the `effective_rate` the gateway enforces, with a `rate_note` when they differ: `"with key"` when a keyed rate stands in for the stored one, `"held to the source's limit"` when the stored rate is above the ceiling, the manifest's ceiling, budget and today's use, backfill share, `refresh_days` (how often an answer is looked up again: the row's `config.refresh_days`, else the manifest's `ttl`) and `concurrency`), 24 hourly request counts, its queue by lane and by why rows are waiting (`by_reason`: `rate_limited`, `breaker_open`, `budget_exhausted`, `backfill_share`, `paused`, `auth_failed`, `source_disabled`), the settings the limits form edits, each output with how full its column is (a `relationship` output carries its `linked` and `held` claim counts instead), the gap a backfill would close, and its jobs with their description, settings, schedule (overrides included) and last 30 days of runs from `job_runs`. A fill rate counts the entities the source can look up (for observables, its kinds). The gap is for the source's first column output: `missing` counts every entity without it, `in_scope` the ones the source can look up that aren't already waiting in its queue, and `eta_days` how long those take at the source's rate and backfill share of its budget.

**`GET /api/enrichment/coverage`** gives every column a source fills: how full it is across all entities of its type, the sources that fill it, and an `action`: a `backfill` through an enabled lookup source when the field is that source's first column, else `ai` where the AI gap research covers the field, else none, with the `cadence` of the job that fills it.

**`GET /api/enrichment/activity`** gives the queue by lane (waiting, put off), the lookups that gave up per source with the last error, and each source's requests in the last 24 hours. **`POST /api/enrichment/retry`** (`?source_type=` optional) queues the lookups that gave up again, with their attempts reset.

**`POST /api/enrichment/sources/{source_type}/backfill`** (`{"entity_type", "limit"}`, both optional) queues `backfill`-lane jobs for the in-scope entities missing that column, newest first, 1,000 rows per insert; `limit` defaults to 1,000 and is capped at 50,000. It answers 400 for a catalog source, a type the source doesn't handle, a source with no column output, or a source that is off.

**`POST /api/enrichment/pause`** (`{"paused": true}`) stops every request to outside sources. The switch is the system setting `enrichment_paused`. The gateways read a Redis flag in the same script that takes a request's slot, so a pause applies on every worker's next request. The pause endpoint and the settings API commit the setting, then copy the stored setting onto the flag (`backend/app/enrichment/pause.py`). The dispatcher does the same every tick, every scheduled source job before it runs, and the `enrichment-pause-sync` job every minute on the default worker, so a Redis that lost the flag is corrected within a minute even while the enrichment worker is down. Each copy also writes a marker; until one runs, a gateway that finds no marker reads the setting itself. The copy reads the setting's row, not the settings cache, under a share lock held until the flag is written, so it can't put back a value a change is committing over, and two quick toggles leave the flag at the last one committed. A flag write gives up after 5 seconds, so a hung Redis can't hold the lock longer. While paused, the dispatcher claims nothing, scheduled jobs stop with `stopped: "paused"`, and `POST /api/enrichment/enrich` queues the lookup for later.

### Highlight Popover

The popover shown when you hover or click a highlighted name in an article (`frontend/src/components/EntityPopover.tsx`) adds a few words from enrichment, read from `GET /api/entities/{type}/{id}/glance` (`backend/app/enrichment/glance.py`):

- Up to two **verdict chips** beside the type chip: something you'd act on, red or amber. *Exploited* (CISA's SSVC, on a CVE not already in KEV), *No patch* (a CVE on an end-of-life product or release), *EOL* or *Security fixes only* (a product), *Benign scanner* or *Malicious scanner* (GreyNoise), *New domain* (registered in the last 30 days), *Popular site* (Tranco top 10,000), *Serving malware* (URLhaus), *Archived* (a tool's GitHub repository), *Leak site up* (ransomware.live).
- One **Context** row at the end of the label grid: up to three short neutral facts, for example "AS10439 CariNet · US · VPN" for an IP, "Behind 3,646 CVEs, 108 in KEV" for a CWE, "State-sponsored · Active since 2008" for an actor, "15 D3FEND countermeasures" for a technique, "Targeted by 475 threat actors" for a country.

Every type the reader highlights has rules (`RULES`): CVE, CWE, technique, threat actor, malware, tool, country, vendor, product, mitigation and observable. A rule reads one source's stored answer (a column it writes, or its profile context) or a count its links made possible, and says nothing when nothing is stored. Rules for a source that is off are skipped, and visitors never see a source that sends indicators off the box or bars commercial use. Hovering a chip or fact names its source and date. A failed request leaves the popover as it is.

The **Look up** button (Refresh once a source has answered) runs every lookup source that applies to the entity and can run now (kind-aware: Shodan only for IPs), and the chips and Context row fill in place. A source that waited says why in words under the buttons ("GreyNoise Community is at its daily cap · fills in tomorrow"), one that failed offers Retry, and an admin sees which source needs a key, with a link to Keys.

### Source Jobs

Each source declares its scheduled jobs in its manifest. They are registered in `JOB_REGISTRY` under the Enrichment category with the source named (`source`), and change in the Jobs view of the Engine console like any job; there each carries a chip naming its source ("source · NVD"). A job skips while its source is switched off and returns `{"skipped": "source disabled"}` (`source_job` in `backend/app/workers/db.py`). Every job's run details in `job_runs` start with `fetched` (answers the source gave), `changed` (answers that differed from the stored one) and `written` (entities whose columns or links changed), null when a job has nothing like it.

The bulk catch-up jobs (`cve-nvd-backfill`, `reenrich-cve-nvd`, `cvelist-backfill`, `wikipedia-bulk-sync`) are declared with `source_job(..., lane="backfill")`: their requests run in the gateway's backfill lane, so they stop once the source has used 60% of its daily budget, leaving the rest for new entities and people's requests.

| Job key | Source | Default schedule (UTC) | What it does |
|---|---|---|---|
| `epss-bulk-sync` | `epss` | Daily 06:30 | EPSS scores for every CVE, applied in chunks of 5,000; only changed scores are written |
| `sync-kev-feed` | `cisa_kev` | Every 6 hours at :15 | CISA KEV flags |
| `cve-nvd-backfill` | `nvd` | Daily 01:30 | NVD data for CVEs with no NVD record, whatever else filled them, as many as fit in 13 minutes; the rest wait for the next run. An id NVD keeps missing is tried 3 times, a week apart |
| `cve-nvd-refresh` | `nvd` | Hourly at :00 | Every NVD record changed since the last run (`lastModStartDate`, 2,000 records a request), applied to the CVEs IntelFeed holds. The window starts at the `nvd` row's `last_synced_at` (8 days back on a first run, at most NVD's 120), and moves only after a run that read all of it |
| `reenrich-cve-nvd` | `nvd` | Daily 03:05 | NVD data for bulk-imported CVEs and ones NVD hadn't analysed yet |
| `github-poc-scan` | `github_poc` | Daily 05:00 | Public exploit repos for CVEs, as many as fit in 8 minutes |
| `mitre-attack-sync` | `mitre_attack` | Sunday 03:00 | ATT&CK techniques, groups and mitigations |
| `misp-galaxy-sync` | `misp_galaxy` | Sunday 03:30 | Reference actor aliases from the MISP Galaxy, and the blank country, motive, description and target sectors of tracked actors, through the field map |
| `metasploit-sync` | `metasploit` | Sunday 03:45 | Maps CVEs to Metasploit modules through the field map and raises their exploit status to weaponized |
| `osv-delta-sync` | `osv` | Hourly at :40 | Reads OSV's change list (`modified_id.csv`, newest first) back to the `osv` row's `last_synced_at` (2 days on a first run) and applies the changed records of CVEs IntelFeed tracks, fetched one by one from OSV's bucket, oldest first. A refused run resumes after the last record it applied |
| `refresh-cwe-catalog` | `mitre_cwe` | Monday 03:45 | The MITRE CWE catalog, and NVD weakness references that now match |
| `malpedia-sync` | `malpedia` | Saturday 01:00 | Malware families; on its own day because it writes the actor rows the Sunday syncs also write |
| `wikipedia-bulk-sync` | `wikipedia` | Wednesday 04:00 | Wikipedia content for entities that lack it and have no answer that still stands, as many as fit in 55 minutes. A name with no article (or an off-topic one) gets a "not found" answer for 30 days, so the next runs move on; the time left bounds each entity's whole fetch, not just its first request |
| `sync-cybergeist-feeds` | `cybergeist` | Daily 02:30 | Threat actors and malware from the Cybergeist feeds |
| `cymru-bulk-sync` | `cymru` | Every 6 hours at :25 | Maps up to 10,000 active IPs with no fresh Team Cymru answer to their AS over one bulk WHOIS connection |
| `tranco-sync` | `tranco` | Daily 04:20 | Ranks the ledger's domains against the Tranco top-1M list (`popularity_rank`) and flags top-10k ones for review |
| `sync-ransomware-victims` | `ransomware_live` | Every 30 minutes | Leak-site victim postings |
| `ransomware-group-profiles` | `ransomware_live` | Every 4 hours at :50 | Techniques, tools and leak-site status for up to 10 tracked groups ([below](#ransomwarelive-group-profiles)) |
| `etda-sync` | `etda` | Tuesday 04:15 | Matches ETDA Threat Group Cards to tracked actors ([below](#etda-threat-group-cards)) |
| `threatfox-sync` | `threatfox` | Daily 04:35 | Matches the ledger's active observables against ThreatFox's IOC export ([below](#abusech)) |
| `urlhaus-sync` | `urlhaus` | Every 6 hours at :50 | Matches the ledger's active URLs, domains and IPs against the URLhaus dump ([below](#abusech)) |
| `cvelist-backfill` | `cvelist` | Hourly at :20 | The CVE record for CVEs with no current cvelist result, read from the baseline zip, as many as fit in 13 minutes |
| `cvelist-delta-sync` | `cvelist` | Hourly at :40 | The CVE records changed since its last run, from cvelistV5's delta zips |
| `wikidata-sync` | `wikidata` | Thursday 04:30 | Vendor websites, countries, industries and facts, product vendors, country regions, victim countries ([below](#wikidata)) |
| `github-repo-sync` | `github_repo` | Tuesday 05:15 | Stars, last push, archived state, license and topics of tools' GitHub repositories ([below](#github-repository)) |
| `endoflife-sync` | `endoflife` | Daily 05:15 | Product support lifecycles ([below](#endoflifedate)) |
| `ctid-mappings-sync` | `ctid` | Sunday 04:15 | NIST 800-53 and CIS controls on techniques ([below](#ctid-control-mappings)) |
| `d3fend-sync` | `d3fend` | Sunday 04:30 | D3FEND countermeasures for techniques ([below](#d3fend)) |
| `capec-sync` | `capec` | Monday 04:00 | The CAPEC attack-pattern catalog, and each technique's patterns ([below](#capec)) |

**CVE List.** The source reads the CVE Program's records from the cvelistV5 repository on GitHub: the CNA's container and CISA's ADP container (SSVC, CVSS for CVEs the CNA left unscored, KEV date and CPEs).

- `cvelist-backfill` reads the baseline zip each release carries (every record as of midnight UTC, about 650 MB) for the CVEs in `cves` with no current result. The zip is downloaded once through the source's gateway and kept on local disk (a newer one replaces it), then read front to back, one record in memory at a time. A run stops at its time budget and the next goes on with what is still due. Once a run has read the whole zip, the due CVEs it doesn't hold are stored as not found. With only a few CVEs due (under half a run's worth of requests), it fetches their records one at a time from raw.githubusercontent.com instead. A record's result lasts 90 days (30 for an id with no record), so each CVE is checked again a quarter later.
- `cvelist-delta-sync` lists the repository's releases (one API call) and reads the delta zips released since the source row's `last_synced_at`. Each hourly zip holds every record changed since midnight UTC, and an end-of-day zip holds the whole day, so it reads one zip per day: the end-of-day one once it is out, else the newest hourly one. A zip (about 4 MB for a whole day, refused above 64 MB) streams to a temporary file, and only the records of CVEs in `cves` are read from it. On its first run it reads only the newest zip. If the listing (about four days) no longer reaches back to `last_synced_at`, its stats say `gap: true`; the backfill catches those CVEs when their results expire.

Both jobs, and a lookup ("Enrich now"), store each record as the source's result, write its context and columns, link its CWE ids in `cve_weaknesses` (`source = cvelist`), and write its affected products into `cve_affected`. The stored `raw_response` is only the record's `cveMetadata`. The data is used under the [CVE Program terms of use](https://www.cve.org/Legal/TermsOfUse). The KEV columns stay with the KEV sync.

`resolve-cve-affected` belongs to no source: it matches CPE pairs already stored against new vendors and products, and sends nothing to NVD.

The Malpedia sync passes `alt_names` through `filter_aliases()` (`backend/app/intelligence/autolinker.py`), so junk aliases never enter an entity's `aliases`.

### Wikidata

`wikidata-sync` (`backend/app/enrichment/wikidata.py`) looks up vendors, products and countries that have an English Wikipedia article and no unexpired Wikidata answer: every such vendor (its profile shows Wikidata's facts), products with no vendor, and countries missing a region or ISO code, up to 200 of each per run. It also looks up ransomware victims by website ([below](#ransomware-victims)).

It reads Wikidata through the action API (`wbgetentities`), not the SPARQL query service: one call turns up to 20 article titles straight into their items, and it is the cached read path Wikimedia asks tools to use. The API takes 50 titles, but a country's item can run to megabytes, so calls stay at 20. The item-valued claims the job keeps (country, headquarters, industry, developer) are named by id, so a second call fetches their English labels and article titles, 50 ids at a time.

Each property is read at its best rank: the `preferred` statements when there are any, else the `normal` ones. `deprecated` statements never count, which is what makes Microsoft's logo the current one and not its 1980 logo.

| Entity | Property | Writes |
|---|---|---|
| Vendor | P856 official website | `website` (when blank) |
| Vendor | P17 country | `country_id` (when blank), only to a country IntelFeed tracks |
| Vendor | P452 industry | `operates_in` relations to the sectors the industries map onto; an industry that names no sector ("software development") is dropped |
| Vendor | P571 inception, P159 headquarters, P17 country, P452 industry, P154 logo | Profile context: Founded, Headquarters, Country, Industry (chips), Logo (a Commons link) |
| Product | P178 developer | `vendor_id`, only to a vendor IntelFeed already has (see the `vendor` resolver above) |
| Country | P30 continent | `region`, mapped to the seed data's six regions (Insular Oceania counts as Oceania) |
| Country | P297 ISO 3166-1 alpha-2 | `iso_code` (when blank) |

Every looked-up entity also gets a link to its Wikidata item. A title Wikidata has no item for is stored as not found, so it isn't asked for again for 30 days. Wikidata's data is CC0.

### Ransomware victims

A leak-site victim usually comes with a domain, so three sources look victims up by it (`Match.by_value(column="domain")`). Expect little: most victims are small companies.

- **RDAP** looks up the victim's registrable domain when someone presses Enrich on the victim: registrar, registration date and status as context. The registrant's country is redacted at almost every registry, so it fills no column.
- **Tranco**'s daily job ranks victims' domains from the same list it streams for the ledger, as context only (no column, no review flag).
- **Wikidata**'s weekly job asks the query service (SPARQL) which items give the victim's domain as their official website (P856), 25 domains a call, and takes that item's country (P17) into `country_id`. A domain more than one item claims, or one item in two countries, gets nothing. It looks up victims with a domain and no country, the most-posted first.

### GitHub repository

`github-repo-sync` (`backend/app/enrichment/github_repo.py`) asks GitHub's REST API (`GET /repos/{owner}/{repo}`) about each tool whose `github_url` names a github.com repository and has no answer from the last week, up to 200 a run. It keeps the stars, last push date, archived state (a warning badge), license and topics, and a link, all as profile context; no column is written. A repository GitHub doesn't have is stored as not found; a renamed one is followed. GitHub allows 60 requests an hour without a token and 5,000 with one; the `github_token` setting is used when set. Malware families have no repository column, so only tools are looked up.

### endoflife.date

`endoflife-sync` (`backend/app/enrichment/endoflife.py`) downloads endoflife.date's product list, matches IntelFeed products to it, then fetches each matched product's releases once. A product matches when its name, or its vendor's name followed by its name, equals an endoflife.date product's name, label or alias once case and punctuation are dropped: "Windows Server" is `windows-server`, "Exchange" by Microsoft is "Microsoft Exchange". Nothing fuzzy. A product whose forms point at two endoflife.date products gets nothing, and a product's own aliases are not used, because extracted aliases are too noisy ("XDR", "AWS Lambda"). `OVERRIDES` in the module covers known mismatches (SUSE Linux Enterprise → `sles`, Splunk Enterprise → `splunk`). Products that don't match get nothing.

`support_status` describes the product as a whole, from the releases' flags:

| Value | When |
|---|---|
| `maintained` | A release is maintained and neither its active support nor its security support has ended |
| `security_only` | Releases are maintained, but only for security fixes: active support has ended, or end of life has passed and the release is in extended support |
| `eol` | No release is maintained |
| `unknown` | endoflife.date lists no releases |

`next_eol` is the soonest date after today that a maintained release stops getting security fixes: its end of life, or the end of extended support for one already past end of life. It is empty when no maintained release has one. The profile shows the newest 20 releases (release, released, active until, security until, status) and a link to the product's endoflife.date page. endoflife.date's data is MIT-licensed; the profile credits it.

A CVE's affected rows (`GET /api/intelligence/cves/{id}/affected`) carry `eol_releases`: the end-of-life releases of the row's product that its version range covers (`eol_releases()`, `backend/app/enrichment/endoflife.py`). A release counts when its number, compared at its own length, lies within the range: release `10.2` is inside `10.2.0 – 10.2.9`, release `3.8` inside `< 3.10.2`. Only numbered releases are compared ("23H2" is not), and a range with no bound names none. The CVE's **no patch coming** badge reads them.

### Tranco

The Tranco sync (`_run_tranco_sync` in `backend/app/workers/enrichment_tasks.py`) asks `tranco-list.eu/api/lists/date/latest` for the day's list, then streams its CSV (about 22 MB) line by line, matching 10,000 rows at a time against the ledger's `domain` observables, so only the matches are held in memory. A match is exact: `evil.workers.dev` never takes `workers.dev`'s rank. Each matched domain's rank, and a "not found" answer for each domain that left the list, goes through the field map (`apply_source_result`): `popularity_rank`, its claim and a `rank` context row (48 hours). A domain entering the top 10,000 (`TRANCO_REVIEW_RANK`) gets `needs_review = true` once: a popular site named as an indicator is often a false positive, but nothing is deleted or denied, and a row an analyst has cleared isn't flagged again while it stays there. Denied rows are never flagged.

### CAPEC

`capec-sync` (`backend/app/enrichment/capec.py`) downloads CAPEC's research view, `capec.mitre.org/data/csv/1000.csv.zip` (about 380 KB, every attack pattern), and replaces `capec_patterns` with it: id, name, abstraction, status, description, related weaknesses and ATT&CK taxonomy mappings. Patterns that leave the view are deleted. An empty file fails the run rather than emptying the table.

- **Weaknesses.** A CWE's `capec_ids` come from the CWE catalog. `GET /api/cwes/{cwe_id}` and the `get_cwe` tool return them with their names (`capec_patterns`, `capec_names()`), and the CWE profile's MITRE CWE panel shows the names. An id the catalog lacks keeps a null name. The names are read from the table, not copied onto each weakness, so they are current as soon as the sync has run.
- **Techniques.** A technique's patterns are the ones whose ATT&CK mappings name it exactly (a sub-technique doesn't take its parent's). They show as an "Attack patterns" table (CAPEC, pattern, abstraction) in the technique's Context panel. A technique CAPEC stops mapping loses the table.

CAPEC may be used for research, development and commercial purposes with MITRE's copyright designation ([terms](https://capec.mitre.org/about/termsofuse.html)); the profile credits it.

### CTID Control Mappings

`ctid-mappings-sync` (`backend/app/enrichment/ctid.py`) reads two files from the Center for Threat-Informed Defense's [Mappings Explorer](https://github.com/center-for-threat-informed-defense/mappings-explorer): NIST 800-53 rev5 mapped to ATT&CK 16.1 (about 2 MB) and CIS Controls 8.1.2 mapped to ATT&CK 19.1 (about 870 KB). Each mapping says a control (`capability_id`, such as `AC-06` or `CIS-13.7`) `mitigates` a technique (`attack_object_id`); non-mappable rows are skipped. `MAPPING_URLS` names the files, since a new framework or ATT&CK version is a new path.

Every technique that either file maps, or that holds controls from an earlier run, gets `nist_controls` and `cis_controls` (control ids in control order, newer wins), a claim for each write, and two chip rows on its profile, "NIST 800-53 rev5" and "CIS Controls v8.1", each chip the control id and name. Sub-techniques carry their own mappings. Both files are read before anything is written: if one is refused the run stops without writing, so a missing framework never reads as controls removed.

The mappings link controls to techniques only; they name no ATT&CK mitigation (M-id), so the job writes nothing onto `mitigations` or `ttp_mitigations`. Mappings Explorer is Apache 2.0.

### D3FEND

`d3fend-sync` (`backend/app/enrichment/d3fend.py`) asks `d3fend.mitre.org/api/version.json` for the current release, then streams that release's `d3fend-full-mappings.csv` (about 15 MB) to a temporary file. Each row is one path from a defensive technique, through the digital artifacts both act on, to an offensive technique; the job keeps each ATT&CK technique's defensive techniques with their D3FEND tactic.

The file lists only a technique's own mappings. D3FEND's page for a technique adds the ones inherited through ATT&CK's hierarchy, and so does the job: a sub-technique takes its parent's, a parent its sub-techniques'. That matches what D3FEND's API answers for each technique.

Each technique D3FEND counters gets a "Countermeasures" table (defensive technique, tactic; ordered Model, Harden, Detect, Isolate, Deceive, Evict, Restore) and a link to its D3FEND page. No column is written. A technique D3FEND stops countering loses both. D3FEND may be used for research, development and commercial purposes with MITRE's copyright designation ([terms](https://d3fend.mitre.org/tou/)).

### ETDA Threat Group Cards

`etda-sync` (`backend/app/enrichment/etda.py`) downloads ThaiCERT's Threat Group Cards in one request: the export at `apt.etda.or.th/cgi-bin/getcard.cgi?g=all&o=j`, about 2 MB of JSON for some 500 cards. The per-name card API no longer finds groups by name, so the job never uses it.

A card matches an actor IntelFeed already tracks; no actor is ever created.

- **By MITRE group id first.** A card links to its ATT&CK group (`…/groups/G0016/`); the one actor holding that `mitre_id` is its match.
- **Else by exact name.** The card's names must resolve, in the resolver's normalized form, to exactly one actor. An actor whose `mitre_id` the card contradicts is a different group and is skipped.
- **One to one.** A card that names several actors matches none. When several cards land on one actor, a group-id match beats name matches, and a tie skips the actor.

A matched card writes:

| Card field | Writes |
|---|---|
| `names` | `aliases`: the names the actor doesn't carry yet, through `gate_aliases` (a name another actor owns is dropped) and `filter_aliases` |
| `country` | `country` and `origin_country_id`, when blank and the country exists |
| `motivation` | `motivation`, folded onto the vocabulary, when blank |
| `mitre-attack` | `mitre_id`, when blank |
| `observed-sectors` | Target sectors (see below) |
| `observed-countries` | `targets` country relations |
| `tools` | `uses` relations to a malware family or tool |
| `sponsor`, `first-seen`, `last-card-change` | Profile facts: Sponsor, First seen, Card changed |
| `operations`, `counter-operations` | Profile timelines: the activity's first line, with the first link it cites |

ETDA's sector names map onto the 21 sectors through `normalize_sector`, plus the names in `SECTORS` in the module (High-Tech → technology, Shipping and Logistics → transportation, Industrial → manufacturing, BitCoin exchanges → cryptocurrency, and so on). A name neither maps, such as Construction, Mining or Real estate, is left out rather than held.

An actor that has ETDA claims or context but whose card no longer matches gets a `found: false` answer: its relation claims are withdrawn and its context removed. Columns it filled stay, as any source's fills do. An export with no cards stops the run (`stopped: "empty_export"`) before anything is withdrawn.

The encyclopedia is published under CC BY-NC-SA 4.0 by the Electronic Transactions Development Agency, so `commercial_ok` is false and visitors in public read-only mode never see its context.

### ransomware.live group profiles

`ransomware-group-profiles` (`backend/app/enrichment/ransomware_groups.py`) reads `api.ransomware.live/v2/group/{slug}` for the groups the victim sync already tracks. The disclosures tie each ransomware.live slug to an actor (`group_name_raw`, `group_id`), so the job asks only about groups IntelFeed has and does no matching of its own. An actor several slugs fold into (lockbit2, lockbit3) is looked up by the slug that posted most recently.

ransomware.live allows about one call a minute, and the source's 2-per-minute allowance also serves the victim sync, so a run looks up at most 10 groups: those with no profile first, then the stalest. A run stops starting lookups after 10 minutes. Six runs a day cover about 300 groups a week, and a profile lasts a week. A group ransomware.live doesn't know (404) is stored as not found for a week.

A profile writes:

- `uses` technique relations from `ttps[].techniques[]`, with `technique_details` as each claim's evidence.
- `uses` tool relations from `tools` (category → names).
- Profile context: the description (as plain text), a Tools table by category, a Leak sites table (each site's type and whether it is up), and a link to the group's ransomware.live page.

The sites' onion addresses are never stored: not in the context, not in the result's `parsed_data`, and not in its `raw_response`, which keeps only the slug. ransomware.live's terms ask for written approval for commercial use, so `commercial_ok` is false and visitors never see this context.

---

## Configuration and Extensibility

### abuse.ch

ThreatFox, URLhaus and MalwareBazaar (`backend/app/enrichment/adapters/abusech.py`) need a free abuse.ch Auth-Key (https://auth.abuse.ch/); every API call and every export needs one. Until a key is saved they show as `needs_key` and send nothing.

- **Export jobs** send nothing about the ledger. `threatfox-sync` downloads ThreatFox's full export (every IOC not yet expired; ThreatFox expires IOCs after six months and builds the file hourly). `urlhaus-sync` downloads the URLhaus dump (URLs online now or added in the past 90 days, built every 5 minutes). Each zipped CSV streams to a temporary file and is read a line at a time, matched 5,000 rows at a time against the ledger, so only the matches are held in memory. A match is exact on `(kind, value)`: a ThreatFox `ip:port` matches its IP, a URLhaus URL matches the URL and its host as a domain or IP. Only `active` observables are written. An observable the export answered (`raw_response.export`) and is no longer in the export loses its context and claims; a column it filled stays. A lookup's answer is the lookup's: the exports cover only current data, so they never withdraw one, and a later lookup of an observable the export answered takes it over. An empty export stops the run (`empty_export`) and withdraws nothing. The key is part of the export's URL, so an error names only the HTTP status.
- **Lookups** (ThreatFox `search_ioc`, URLhaus `url` / `host`, MalwareBazaar `get_info`) send the observable to abuse.ch, so the sources are `shares_ioc` and manual: they run when someone presses Enrich, or for a backfill an admin starts. MalwareBazaar is lookup-only; its only small export holds the last 48 hours of samples, and the hashes write-ups name are mostly older.

What they add: the `role` when it is blank; the malware families behind the indicator as [relations](#relations) to families IntelFeed already tracks (ThreatFox's `malware_printable`, URLhaus tags that name a tracked family, MalwareBazaar's `signature`), with the threat type, confidence, first-seen date and reference as evidence; and profile context. ThreatFox shows the threat type, families, confidence, first and last seen, tags, reference and a link; URLhaus a status badge (online is red, offline and unknown are neutral: an offline URL is history), the threat, the malware URL counts for a host, tags, first seen, last online, Spamhaus DBL and SURBL listings (lookups) and a link; MalwareBazaar the signature, file type and name, first and last seen, delivery method, tags, vendor labels and a link.

abuse.ch's terms (https://abuse.ch/terms-of-use/) allow not-for-profit use within volumes "reasonably expected for non-commercial or non-profit purposes"; commercial use may need a Spamhaus subscription. No numeric query limit is published, so the three sources keep to 10 requests a minute and 500 a day between them, on one shared allowance. Their license is marked non-commercial, so visitors never see their context.

### Adding a New Enrichment Adapter

1. Write the class in `backend/app/enrichment/adapters/myapi.py`:

   ```python
   class MyAPIAdapter(EnrichmentAdapter):
       source_type = "myapi"
       display_name = "My API Service"
       applies_to = {"observable": ("ipv4", "domain")}
       requires = (Key(),)
       # Cite the documented limit here.
       quota = Quota(60, 60, daily_budget=1000, ceiling_per_period=60, concurrency=2)
       ttl = timedelta(hours=72)  # used when enrich() doesn't set ttl_hours
       egress = Egress.SHARES_IOC
       license = License("My API terms", attribution="My API", commercial_ok=False)
       outputs = (
           Column("score", "observable.reputation.myapi_score", Policy.NEWER_WINS),
           Context("score", "My API score", Display.FACT),
       )

       async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
           # call the API, then:
           return EnrichmentData(raw_response=data, parsed_data={...})
   ```

2. Export it from `backend/app/enrichment/adapters/__init__.py` and add it to `ADAPTER_REGISTRY` in `backend/app/enrichment/registry.py`. Its seed row and any `jobs` come from the manifest. A source with jobs only (no `enrich()`) extends `Source` in `backend/app/enrichment/catalogs.py` and goes in `CATALOG_REGISTRY`.
3. It then appears under Settings → Engine → Enrichment, off until someone turns it on (on from the start when it has jobs), and marked new for two weeks. Give it an `about` sentence: the console shows it at the top of the source's panel. A key it needs appears under Keys on its own.

### Adding a New AI Task

1. Add it to `SYSTEM_TASKS` in `backend/app/ai/prompts/defaults.py` (name, display name, category, templates, `output_schema`), or create a custom task through the API.
2. Assign it to an instance provider at Settings → AI Configuration. Until then `run_task` returns `None`.
3. If a Celery task calls it, route that Celery task to the `ai` queue ([The `ai` queue](#the-ai-queue)).
4. To let personal keys answer it, add it to `USER_PROVIDER_ELIGIBLE_TASKS` and set `allows_user_provider`.
5. Use it from automation:

   ```json
   { "type": "run_ai_task", "config": { "task_id": "my_analysis" } }
   ```

### Adding a New Automation Action

1. Write the handler in `backend/app/automation/actions.py` and add a `case` to `_execute_action`.
2. Add the type to `PER_ENTRY_ACTIONS` (changes one entry) or `BATCH_ACTIONS` (runs once over many entries).
3. Add it to the rule builder in the frontend.

---

## Testing & Debugging

- **Dry-run a rule**: `POST /api/automation/rules/{id}/test?entry_id=<uuid>`. Nothing is saved or sent.
- **Run a rule now**: `POST /api/automation/rules/{id}/run?hours=24&limit=50`.
- **See AI spend**: `AIResult.cost_estimate` per result, the Cost Dashboard (`GET /api/ai/cost-breakdown`), or the Prometheus counter `AI_COST_TOTAL{provider=...}`.
- **See enrichment budgets**: the source detail (`GET /api/enrichment/sources/{source_type}/detail`), or in code `await source_gateway(source, api_key).used_today()` (`backend/app/enrichment/registry.py`).
- **Enrichment tests**: `backend/tests/test_enrichment_gateway.py` (the window, the cap on requests at once, auth failures, and the scan that fails on a direct HTTP call), `test_enrichment_queue.py`, `test_enrichment_manifests.py`, `test_entity_updater_field_map.py`, `test_enrichment_jobs.py`.
- **Tests**: `backend/tests/test_ai_providers.py`, `test_ai_tasks.py`, `test_ai_prompts.py`, `test_ai_allowance.py`, `test_user_ai_providers.py`, `test_openai_provider.py`, `test_ollama_provider.py`.
