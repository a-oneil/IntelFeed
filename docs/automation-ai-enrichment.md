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
  - [Adapter Registry](#adapter-registry)
  - [Trigger Modes](#trigger-modes)
  - [Pipeline Flow](#pipeline-flow)
  - [API Key Resolution](#api-key-resolution)
  - [Confidence Thresholds](#confidence-thresholds)
  - [Caching & TTL](#caching--ttl)
  - [Rate Limiting](#rate-limiting)
  - [Daily Budgets](#daily-budgets)
  - [Scheduled Enrichment](#scheduled-enrichment)
- [Configuration and Extensibility](#configuration-and-extensibility)
- [Testing & Debugging](#testing--debugging)

## Overview

Three backend subsystems act on intelligence without a person clicking:

1. **Automation engine** (`backend/app/automation/`): rules you write. When an entry matches, the rule runs a list of actions (tag it, notify Slack, run an AI task, and so on).
2. **AI provider system** (`backend/app/ai/`): one interface over several model backends. A *task* (for example "summarize an article") is assigned to a *provider* (for example your Ollama server). A provider does nothing until a task is assigned to it.
3. **Enrichment pipeline** (`backend/app/enrichment/`): pulls extra facts about entities (CVEs, actors, malware, IP addresses) from 13 outside sources and stores the results.

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
| `claude` | `ClaudeProvider` | The Anthropic API (API key) | No |
| `claude_code` | `ClaudeCodeProvider` | The Claude Code CLI under an OAuth sign-in, run in `celery-worker-ai` (see [copilot.md](copilot.md)) | Yes, through the IntelFeed MCP server |
| `ollama` | `OllamaProvider` | An Ollama server (`base_url`, default `http://localhost:11434`) | Yes, a native `/api/chat` tool loop over the backend tool registry |
| `openai_compatible` | `OpenAICompatibleProvider` | Any `/v1/chat/completions` server: OpenAI, LM Studio, vLLM, llama.cpp, LiteLLM, OpenRouter, Groq. `base_url` is required | No |

Some tasks only work with tools. `TOOL_REQUIRED_TASKS` (`copilot`, `entity_enrichment_research`) and `TOOL_CAPABLE_PROVIDER_TYPES` (`claude_code`, `ollama`) in `backend/app/ai/capabilities.py:34` stop you from assigning those tasks to a provider that cannot run tools.

Useful `config` keys by type (provider row, overridable per assignment):

- All: `timeout_seconds`.
- `claude_code`: `cli_path`, `cli_retries`, `allowed_tools`, `max_budget_usd`, `extra_args`, `mcp_server_path`, `agent_api_url`.
- `ollama`: `default_model`, `keep_alive`, `model_overrides`; per assignment, `ollama_tools` and `ollama_tools_read_only` (default `true`).
- `openai_compatible`: `default_model`, `model_overrides`, `model_filter`, `extra_headers`, `embedding_dimensions`, `pricing` (`input_per_mtok`, `output_per_mtok`).

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

1. **Adapters**: one class per source, 13 in all (see [Adapter Registry](#adapter-registry)).
2. **Rate limiting**: a Redis sliding window per source.
3. **Daily budgets**: an optional per-source cap on calls per UTC day.
4. **Caching**: results expire after a per-adapter TTL; a fresh result is reused.
5. **Per-user API keys**: a person can store their own key for a source.

Sources are configured at Settings → Engine → Enrichment (`/api/enrichment/sources`). After an auto enrichment, `apply_enrichment_results_to_entity` (`backend/app/enrichment/entity_updater.py`) copies the useful fields onto the entity itself.

### Data Models

All three tables are in `backend/app/models/enrichment.py`.

**`enrichment_sources`**: one row per source. `source_type` (unique), `display_name`, `is_enabled` (default `false`), `trigger_mode` (`auto` / `scheduled` / `manual`), `api_key_encrypted`, `rate_limit_config` (`requests_per_period`, `period_seconds`), `config`, `min_confidence_threshold` (`low` / `medium` / `high`), `daily_budget` (NULL = unlimited), `daily_budget_used`, `schedule_interval_hours` (default 24), `next_scheduled_at`, `last_synced_at`, `health_status`.

**`user_enrichment_overrides`**: a person's own `api_key_encrypted` for a source, one row per user per source. The pipeline uses it in place of the source's key for that person's enrichments.

**`enrichment_results`**: `entity_type`, `entity_id`, `source_type`, `raw_response`, `parsed_data`, `enriched_at`, `expires_at`, `status`. Only `success` and `error` rows are stored. The other outcomes (`cached`, `skipped_low_confidence`, `budget_exhausted`, `rate_limited`) appear only in the list `enrich_entity()` returns.

### Adapter Registry

`ADAPTER_REGISTRY` (`backend/app/enrichment/registry.py:20`) maps each `source_type` to its adapter class. `DEFAULT_SOURCES` (`registry.py:38`) gives each one its seed settings:

| `source_type` | Display name | Entity types | Default trigger | Key? | Default rate limit | Min confidence |
|---|---|---|---|---|---|---|
| `epss` | FIRST EPSS | cve | scheduled | No | 100 / 60 s | low |
| `nvd` | NVD API 2.0 | cve | auto | No | 50 / 30 s | low |
| `cisa_kev` | CISA KEV | cve | scheduled | No | 100 / 60 s | low |
| `mitre_attack` | MITRE ATT&CK | ttp, threat_actor, malware, tool, mitigation | scheduled | No | 10 / 3600 s | low |
| `vulncheck` | VulnCheck KEV | cve | scheduled | Yes | 1000 / 60 s | medium |
| `osv` | OSV | cve | auto | No | 100 / 60 s | low |
| `malpedia` | Malpedia | malware, tool, threat_actor | scheduled | No | 30 / 60 s | low |
| `github_poc` | GitHub PoC | cve | scheduled | No (optional token) | 10 / 60 s | low |
| `cvedetails` | CVEDetails | cve | auto | Yes | 60 / 60 s | medium |
| `wikipedia` | Wikipedia | threat_actor, malware, tool, country, vendor, product, ttp, mitigation, cve, cwe | auto | No | 10 / 60 s | low |
| `virustotal` | VirusTotal v3 | observable | manual | Yes | 4 / 60 s | medium |
| `greynoise` | GreyNoise Community | observable | manual | Yes | 10 / 3600 s | medium |
| `shodan` | Shodan InternetDB | observable (IPv4 only) | auto | No | 30 / 60 s | medium |

Every adapter extends `EnrichmentAdapter` (`backend/app/enrichment/base.py`). It sets `source_type`, `display_name`, `supported_entity_types`, `requires_api_key`, `default_trigger_mode`, and optionally `shared_key_group`. It implements `enrich(entity_type, value) -> EnrichmentData(raw_response, parsed_data, ttl_hours=24)`, and may override `bulk_sync()` and `check_health()`.

### Trigger Modes

| Mode | When it runs |
|---|---|
| `auto` | When an entity is created or linked: the autolinker, TTP and CVE extraction, the observables ledger and GitHub rule import queue `auto_enrich_entity` |
| `scheduled` | The `scheduled-enrichment-check` job (every 15 minutes) calls `bulk_sync()` on each due source, then sets `next_scheduled_at` to now + `schedule_interval_hours`, even when the sync failed |
| `manual` | A person asks: `POST /api/enrichment/enrich`, or an "Enrich" button. Naming `source_types` runs those sources whatever their mode; the hygiene "Enrich N" buttons use `bulk_enrich_for_gap` the same way |

### Pipeline Flow

`enrich_entity()` (`backend/app/enrichment/pipeline.py:134`) loops over the enabled sources whose `trigger_mode` matches (or the named `source_types`). For each source:

1. Skip it if the adapter does not support the entity type.
2. Resolve the API key ([below](#api-key-resolution)).
3. **Auto mode only**: skip it if the entity's confidence is below the source's minimum (`skipped_low_confidence`).
4. If a fresh `success` result exists, return it (`cached`). No budget is used.
5. If the source has a daily budget and it is used up, skip it (`budget_exhausted`).
6. If the rate limit is reached, skip it (`rate_limited`).
7. Call `adapter.enrich()` and store a `success` row that expires after `ttl_hours`. If the adapter raises, store an `error` row that expires after 1 hour.

If Redis is down, the budget and rate-limit checks let the call through.

### API Key Resolution

`resolve_api_key()` (`backend/app/enrichment/pipeline.py:54`) tries, in order:

1. The calling user's override for this source.
2. The source's own key.
3. A key on a sibling source in the same `shared_key_group` (the user's override first, then the sibling's own key).

No current adapter sets `shared_key_group`, so `SHARED_KEY_GROUPS` (`backend/app/enrichment/registry.py:151`) is empty and step 3 never finds anything. Auto enrichment runs in a worker with no user, so it only uses the source's own key.

### Confidence Thresholds

A source's `min_confidence_threshold` stops cheap or low-value indicators from using up a paid quota (`_passes_confidence_threshold`, `backend/app/enrichment/pipeline.py:22`):

- `low` (or empty) enriches everything.
- An entity with no confidence value at all (most non-observable entities) always passes.
- Otherwise the entity passes if its text level (`high` 3 / `medium` 2 / `low` 1) meets the threshold, or its numeric confidence meets `high` 0.7 / `medium` 0.4.

Only auto enrichment checks this. Manual enrichment skips it.

### Caching & TTL

A `success` result is reused until `expires_at`. Each adapter picks its TTL per result, for example:

- Wikipedia: 720 hours (30 days). Not-found: 168 hours.
- NVD, Malpedia, MITRE ATT&CK, GreyNoise: 168 hours (7 days).
- EPSS, CISA KEV, VulnCheck, GitHub PoC: 24 hours.
- VirusTotal: 72 hours.
- Short-lived misses (a GitHub rate limit, a missing VirusTotal or VulnCheck key, a failed Wikipedia fetch): 1 hour. These misses are stored as `success` rows with `found: false`, so they are cached too.

### Rate Limiting

`RedisRateLimiter` (`backend/app/enrichment/rate_limiter.py`) is a sliding window: each call is added to a Redis sorted set at `enrichment:rate:{source_type}`, calls older than `period_seconds` are dropped, and the call is allowed while fewer than `requests_per_period` remain. Limits come from the source's `rate_limit_config` (seeded from the table above; edit them per source).

### Daily Budgets

When `daily_budget` is set, `RedisBudgetTracker` counts calls in `enrichment:budget:{source_type}:{YYYY-MM-DD}` (UTC; the key expires after 25 hours). A call over the budget is refused and not counted. Only real API calls count; cached results are free. Set a budget on keyed sources such as VirusTotal (free tier: 500 a day) or VulnCheck. `GET /api/enrichment/budget-summary` shows today's use.

### Scheduled Enrichment

Besides the generic `scheduled-enrichment-check`, these beat jobs keep reference data fresh (defaults; change them in the Jobs view of the Engine console):

| Job key | Default schedule (UTC) | What it does |
|---|---|---|
| `epss-bulk-sync` | Daily 06:30 | EPSS scores for every CVE |
| `sync-kev-feed` | Every 6 hours at :15 | CISA KEV flags |
| `cve-nvd-backfill` | Daily 01:30 | NVD data for CVEs that lack it |
| `cve-nvd-refresh` | Daily 12:00 | CVSS changes on existing CVEs |
| `github-poc-scan` | Daily 05:00 | Public exploit repos for CVEs |
| `mitre-attack-sync` | Sunday 03:00 | ATT&CK techniques, groups and mitigations |
| `malpedia-sync` | Sunday 03:30 | Malware families |
| `misp-galaxy-sync` | Sunday 03:30 | Reference actor aliases from the MISP Galaxy |
| `metasploit-sync` | Sunday 03:45 | Maps CVEs to Metasploit modules |
| `wikipedia-bulk-sync` | Wednesday 04:00 | Wikipedia content for entities that lack it |

The Malpedia sync passes `alt_names` through `filter_aliases()` (`backend/app/intelligence/autolinker.py`), so junk aliases never enter an entity's `aliases`.

---

## Configuration and Extensibility

### Adding a New Enrichment Adapter

1. Write the class in `backend/app/enrichment/adapters/myapi.py`:

   ```python
   class MyAPIAdapter(EnrichmentAdapter):
       source_type = "myapi"
       display_name = "My API Service"
       supported_entity_types = ["observable"]
       requires_api_key = True
       default_trigger_mode = "manual"

       async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
           # call the API, then:
           return EnrichmentData(raw_response=data, parsed_data={...}, ttl_hours=72)
   ```

2. Export it from `backend/app/enrichment/adapters/__init__.py`, and add it to `ADAPTER_REGISTRY` and `DEFAULT_SOURCES` in `backend/app/enrichment/registry.py`.
3. It then appears under Settings → Engine → Enrichment, disabled until someone turns it on.

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
- **See enrichment budgets**: `GET /api/enrichment/budget-summary`, or in code `await RedisBudgetTracker("virustotal").get_used()`.
- **Tests**: `backend/tests/test_ai_providers.py`, `test_ai_tasks.py`, `test_ai_prompts.py`, `test_ai_allowance.py`, `test_user_ai_providers.py`, `test_openai_provider.py`, `test_ollama_provider.py`.
