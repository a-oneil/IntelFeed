# AI Copilot — Global Chat, Streaming Tool Traces, and Claude Sign-in

For contributors and operators. After reading this you will know how a copilot chat turn travels from the dock to the model and back, how its tools are kept read-only, how proposed writes are confirmed, and how to keep the Claude sign-in working.

## Overview

The **copilot** is IntelFeed's chat panel, available on every page. It streams its answer, can look up live IntelFeed data with read-only tools while it answers, can *propose* a few writes that you confirm, and saves every conversation on the server. It is separate from the per-entry "Ask Agent" chat (the `entry_qa` task): the copilot knows which page and article you are on, and it can call tools.

| Part | Where | Role |
|---|---|---|
| Stream endpoint | `backend/app/api/copilot.py` | `POST /api/ai/copilot/stream` (SSE), `POST /api/ai/copilot/confirm`, `GET /api/ai/copilot/config` |
| Provider lookup | `backend/app/ai/engine.py` | `resolve_assignment`: the site's copilot assignment, or the person's own key when the admin allows personal keys |
| CLI worker task | `backend/app/workers/copilot_tasks.py` | Runs the Claude Code CLI on the `ai` queue and relays its events over Redis |
| CLI provider | `backend/app/ai/providers/claude_code_provider.py` | `stream_agent()` runs `claude -p --output-format stream-json` and yields typed events |
| Tools | `intelfeed-mcp/intelfeed_mcp.py` | The IntelFeed MCP server the CLI attaches, with a read-only token ([below](#the-tool-layer-read-only-intelfeed-tools)) |
| Sign-in | `backend/app/api/copilot_auth.py`, `backend/app/workers/copilot_auth_tasks.py` | Credential health and the in-app `claude auth login` flow |
| Saved conversations | `backend/app/models/ai_conversation.py`, `backend/app/api/ai_conversations.py` | `ai_conversations` rows and share tokens |
| Public share | `backend/app/api/shared.py` | `GET /api/shared/copilot/{token}`, no sign-in |
| Dock | `frontend/src/components/CopilotDockPanel.tsx` | The right-hand panel: transcript, tool traces, confirm cards, history, share |

The routers mount at `/api/ai/copilot`, `/api/ai/copilot-auth` and `/api/ai/conversations`.

Flow diagram: [diagrams/copilot-stream-flow.md](diagrams/copilot-stream-flow.md).

### API surface

| Endpoint | Who | Purpose |
|---|---|---|
| `POST /api/ai/copilot/stream` | user | One chat turn, streamed as SSE; saved to `ai_conversations` |
| `POST /api/ai/copilot/confirm` | user | Run or cancel a proposed write |
| `GET /api/ai/copilot/config` | user | Who answers *your* copilot: `provider_type`, `provider_name`, `source` (`site` / `user`), `model`, `supports_tools`, `fallback_reason`, `refused` (`{reason, message}` when the turn would be refused), and the Ollama tool list. Reading it spends no allowance |
| `GET`/`POST /api/ai/conversations`, `GET`/`PATCH`/`DELETE /{id}` | owner | List (paginated, filterable by scope), create, read, append, delete |
| `POST /api/ai/conversations/{id}/share`, `DELETE .../share` | owner | Create or revoke a public share link |
| `GET /api/shared/copilot/{token}` | anyone | Read-only view of a shared conversation |
| `GET /api/ai/copilot-auth/status`, `POST /refresh` | admin | Cached sign-in health, or force a re-check |
| `POST /api/ai/copilot-auth/start`, `GET /session/{id}`, `POST /session/{id}/code`, `POST /session/{id}/cancel` | admin | The in-app re-sign-in flow |

Related docs: [automation-ai-enrichment.md](automation-ai-enrichment.md) (providers, tasks, prompts), [cli-reference.md](cli-reference.md) (every tool and read-only mode), [frontend.md](frontend.md) (the dock and `uiStore`), [api-reference.md](api-reference.md), [operations.md](operations.md) (services and the `claude_cli` volume).

---

## The copilot AI task

The copilot is an ordinary AI task named `copilot`, seeded at startup from `backend/app/ai/prompts/defaults.py`. Its defaults:

- **Provider type** `claude_code` (`DEFAULT_PROVIDER_TYPE_ASSIGNMENTS`): the Claude Code CLI under a Claude subscription sign-in, not the API-key provider. It can also be assigned to an **Ollama** provider, which has its own tool loop. The site assignment refuses any other provider type with 400 `provider_incompatible`, because the task needs tools (`TOOL_CAPABLE_PROVIDER_TYPES` in `backend/app/ai/capabilities.py`).
- **Model** `sonnet` (`DEFAULT_MODEL_ASSIGNMENTS`).
- **Assignment config** (`DEFAULT_ASSIGNMENT_CONFIGS`): `allowed_tools: ["IntelFeed"]` and `timeout_seconds: 240`. Older configs that say `["Bash", "Read", "Skill"]` mean the same thing to the provider. If the MCP server is not where the provider looks, the copilot answers without tools, from the prompt and the page context only.
- **Prompt variables**: `question`, `conversation_history`, `ambient_context`. The system prompt tells the model to use its read-only tools for anything that depends on live data, to link to in-app pages instead of quoting raw IDs, that it cannot write, and how to propose a write (see [Proposed writes](#proposed-writes-the-action-fence--confirm-endpoint)).

Both the assignment and the prompt are editable at **Settings → AI Configuration** (the prompt in the Prompts tab). If nothing can answer the task, `/stream` returns 422 `not_configured`.

**Personal keys.** `copilot` is one of the tasks a person's own key may answer (the admin can turn that off per task on the User keys tab). With `allow_user_ai_providers` on, a person who routes copilot (or sets a default key) at Settings → My AI gets their turns on that key. A personal Ollama key runs the same tool loop against *their* Ollama. A Claude API or `openai_compatible` key has no tool loop, so the turn is text only and the dock says "no tools". Those turns do not count against the site allowance; their cost counts toward the person's monthly cap. A per-task "Instance default" route sends copilot back to the site's provider. The full lookup is in [automation-ai-enrichment.md](automation-ai-enrichment.md#personal-keys--the-lookup).

---

## Request flow: `POST /api/ai/copilot/stream`

`copilot_stream` (`backend/app/api/copilot.py:526`) takes `{question, conversation_id?, context?}` and returns an SSE stream. For each turn:

1. **Pick the provider**: `resolve_assignment(db, Caller.user(user.id), "copilot")`. This is where a turn can be refused before anything streams: 403 `user_ai_key_required` (personal keys are required, or the person turned off fallback and their key cannot answer; `details.reason` says why) or 429 `ai_allowance_exceeded` (the person used up today's `site_ai_user_daily_requests`).
2. **Load or create the conversation.** A given `conversation_id` must belong to the caller (404 otherwise). A new conversation is titled from the first 60 characters of the question. Its scope comes from the context (`_scope_from_context`, `backend/app/api/copilot.py:322`): `entry`, `multi_entry`, `entity` (`scope_id = "{entity_type}:{entity_id}"`) or `global`.
3. **Describe where the analyst is** (`_build_ambient_context`, `backend/app/api/copilot.py:267`) from the optional `CopilotContext` (`backend/app/api/copilot.py:71`). Each lookup is best effort; a failure just drops that line.

   | Context field | What the model gets |
   |---|---|
   | `entry_id` | The pinned article: title, date, URL and body (up to 15,000 characters) |
   | `entry_ids` | Several pinned articles: up to 8, each body up to 4,000 characters, plus a note of how many were left out |
   | `entity_type` + `entity_id` | `The analyst is viewing the <type> <name> profile (id …).` |
   | `campaign_id` | `The analyst is viewing the campaign "<name>" (id …).` |
   | `search_query` | `The analyst is searching for "<query>".` |
   | `route` | `They are on the <path> page.` On a `/documentation` page it adds an index of the documentation pages, and `doc_slug` names the page being read |

4. **Render the prompt** from the copilot templates with the question, the context, and the last **20** saved messages (`_MAX_HISTORY_MESSAGES`, `backend/app/api/copilot.py:45`).
5. **Run the turn** (see [Execution topologies](#execution-topologies-worker-dispatch-vs-in-process)) and relay its events as SSE.
6. **Save the turn**: the question and the visible answer are appended to the conversation. Tool events go in the answer's `meta.tool_events`. A failed stream with no visible text is saved as `(error: …)`. If saving fails, the error is logged and the client still gets its answer.

A saved assistant message:

```json
{
  "role": "assistant",
  "content": "LockBit activity in the last week centers on…",
  "created_at": "2026-07-18T14:02:11.512345+00:00",
  "meta": {
    "tool_events": [
      {"type": "tool_call", "id": "toolu_01…", "name": "mcp__intelfeed__search_entries", "args": {"query": "LockBit"}},
      {"type": "tool_result", "id": "toolu_01…", "status": "success", "summary": "…first 200 characters of the result…"}
    ]
  }
}
```

Only the visible text is saved. The proposed-action block is removed first, so a shared conversation never contains raw action JSON. A confirmed action adds a separate `✓ <summary>` message with `meta.action_executed`.

### SSE event schema

Each `data:` frame is one JSON object:

```text
{"type": "chunk", "text": ...}
{"type": "tool_call", "id", "name", "args"}
{"type": "tool_result", "id", "status", "summary"}
{"type": "confirm_request", "action_id", "action_type", "description", "proposed"}
{"type": "error", "message": ...}
{"type": "done", "conversation_id": <uuid>, "answered_by": {...}}
```

`error` is sent only when the stream failed *and* produced no visible text. `done` is always last. Its `answered_by` feeds the reply footer: `provider_name`, `provider_type`, `source`, `model`, `cost_usd` (when usage was reported), `fallback_reason` and `supports_tools`.

### Non-CLI providers: Ollama tool loop and text-only fallback

When the provider is not the Claude Code CLI:

- **Ollama**: a native `/api/chat` tool loop runs **inside the api process**. No CLI or credentials are needed, so `copilot_worker_dispatch` does not apply. Tools run against the backend tool registry (`app.tools.execute_tool`) with the request's database session and user. Only read tools are offered (`ollama_tool_specs(..., read_only=True)`), a non-admin is never offered an admin tool, and `restrict_to_offered` refuses any tool the model names that it was not offered. The default tool list is `DEFAULT_COPILOT_OLLAMA_TOOLS` (`backend/app/tools/__init__.py:109`); change it with the assignment's `ollama_tools` key (Prompt Workspace → Routing panel). Tool traces stream to the dock the same way as with the CLI.
- **Any other provider** (the Anthropic API, `openai_compatible`, and so every personal key of those types): plain text streaming, no tools. The dock's header says "no tools", and the footer says "tools unavailable on this key" when it was the person's own key.

---

## Execution topologies: worker dispatch vs in-process

The Claude Code CLI needs its OAuth credentials (`~/.claude/.credentials.json`). Only the **`celery-worker-ai`** container mounts them, through the `claude_cli` volume. It is the one process that refreshes the tokens; a second container refreshing them at the same time would corrupt the file. The prod api container has no CLI, no credentials and no MCP mount.

`copilot_worker_dispatch` (`backend/app/config.py:444`, default `true`) picks where the CLI runs. It only matters for the `claude_code` provider:

- **Worker dispatch (default)**: the api queues `run_copilot_stream` on the `ai` queue with a new `run_id`, then reads events from a Redis list while the worker runs the CLI.
- **In-process (`false`)**: the api calls `provider.stream_agent()` itself. This only works where the api container has the CLI and credentials. The dev compose mounts `./intelfeed-mcp` into the api for this case.

Either way the endpoint handles events the same way, because the worker relays `stream_agent`'s `{"kind": ...}` events unchanged.

| | Prod (`docker-compose.prod.yml`) | Dev (`docker-compose.dev.yml`) |
|---|---|---|
| Who runs the CLI | `celery-worker-ai` | `celery-worker-ai`, or the api when dispatch is off |
| Credentials | The `claude_cli` volume; the CLI refreshes tokens itself | The `claude_cli` volume, plus `CLAUDE_CODE_OAUTH_TOKEN` from `.env` |
| `CLAUDE_CODE_OAUTH_TOKEN` | Deliberately **not** passed in: it would override the credentials file and stop the silent refresh | Passed in from `.env` |
| MCP server mount (`/opt/intelfeed-mcp`) | `celery-worker-ai` | `celery-worker-ai` and the api |
| Prompt and database work | Always in the api; the worker task only relays events | Same |

### The Redis relay

`run_copilot_stream` (`backend/app/workers/copilot_tasks.py:115`; soft limit 300 s, hard limit 360 s) has no business logic. It runs `ClaudeCodeProvider.stream_agent` and pushes each event onto the list `copilot:stream:{run_id}`, then an `__end__` or `__error__` marker. A list (not pub/sub) means no events are lost if the api subscribes late or falls behind. The list expires after 300 s (`_STREAM_TTL_SECONDS`, `backend/app/workers/copilot_tasks.py:40`) so abandoned runs clean themselves up. Even if the task crashes, it pushes an error marker (`_emergency_terminate`, `backend/app/workers/copilot_tasks.py:152`), so the api never waits forever.

The api reads the list with BLPOP (`_iter_worker_events`, `backend/app/api/copilot.py:430`). If nothing arrives for the CLI timeout plus 60 seconds (180 + 60 when no timeout is set), the turn fails with "Copilot worker produced no output".

### The `ai` queue

All AI-calling Celery tasks are routed to the `ai` queue (`task_routes` in `backend/app/workers/celery_app.py`): copilot turns, the two sign-in tasks, one-pass entry analysis, adjudication, actor refresh, name normalization, AI gap enrichment and thread spines. `celery-worker-ai` reads it with `--concurrency=${CLAUDE_CODE_CONCURRENCY:-1} --prefetch-multiplier=1`, which protects the OAuth session and the subscription's rate limits. The catch: at concurrency 1, a long copilot turn and a background AI job wait for each other.

### The CLI invocation

`stream_agent` (`backend/app/ai/providers/claude_code_provider.py:769`) runs `claude -p --output-format stream-json --verbose --include-partial-messages` (`_build_stream_argv`, `backend/app/ai/providers/claude_code_provider.py:709`), passes the system prompt with `--append-system-prompt`, and adds the confinement flags described in [the tool layer](#the-tool-layer-read-only-intelfeed-tools). `_map_stream_event` (`backend/app/ai/providers/claude_code_provider.py:892`) turns the CLI's output into events: text deltas become `text`, `tool_use` blocks become `tool_call` (sent once the arguments are complete), and `tool_result` blocks become `tool_result` with a 200-character summary. A quota or rate-limit message raises `QuotaExhaustedError` (`backend/app/ai/providers/claude_code_provider.py:40`), with a best guess at the reset time.

---

## The tool layer: read-only IntelFeed tools

With the Claude Code CLI, the copilot's only IntelFeed tools come from the [IntelFeed MCP server](../intelfeed-mcp/README.md) (`intelfeed-mcp/intelfeed_mcp.py`), mounted read-only at `/opt/intelfeed-mcp`. For each turn the provider (see the "tool policy" comment at the top of `claude_code_provider.py`):

1. **Creates an agent token** for the asking user (`create_agent_token` in `backend/app/core/security.py`): type `agent`, read-only, expiring with the run. Ordinary API routes refuse this token type. Only `/api/tools/execute` and `/api/tools/tools` accept it, and `execute` refuses any write tool for it with a 403.
2. **Attaches the MCP server** with `--mcp-config` and `--strict-mcp-config`. The server gets the token and its API address in its own environment (`INTELFEED_TOKEN`, and `INTELFEED_API_URL` from the provider's `agent_api_url` / `INTELFEED_AGENT_API_URL`, default `http://api:8000`). The model never sees either. The server also limits itself to its reviewed read-only tools.
3. **Locks down the CLI.** `--tools` offers no built-in tools except WebSearch when a task asks for it. A deny list covers every built-in shell, file, fetch and agent tool. `--permission-mode dontAsk` refuses anything `--allowedTools` did not name, and `--setting-sources project` with an empty working directory stops settings in `~/.claude` from widening that.
4. **Cleans the environment.** The CLI keeps only `PATH`, `HOME`, locale, proxy and `CLAUDE_*` / `ANTHROPIC_*` variables, so the secrets in `.env` are not visible to it.

Article text in the prompt can still try to instruct the model. The worst it can do is read what the asking user could already read.

With Ollama, the limit is the tool registry itself: only read tools are offered, and `restrict_to_offered` refuses anything else.

---

## Proposed writes: the action fence + confirm endpoint

The copilot cannot write through its tools, but it can **propose** a write that you then confirm. This is handled in the prompt and the endpoint, not in the tools:

- The system prompt tells the model to end its reply with exactly one ` ```intelfeed-action ` fenced JSON block when the user asks it to create or add something.
- The endpoint passes every text delta through `_FenceSplitter` (`backend/app/api/copilot.py:372`). It holds back a short tail (`_HOLDBACK`, the length of the fence marker), so the fence never reaches the browser even when it arrives split across deltas. After the fence starts, the rest of the text is kept for parsing instead of streamed.
- `_parse_action_block` (`backend/app/api/copilot.py:339`) parses it. Only `create_campaign` and `add_note` with a `params` object are accepted (`_SUPPORTED_ACTION_TYPES`, `backend/app/api/copilot.py:62`). If parsing fails there is no proposal; the visible answer is unchanged.
- A valid proposal is stored in Redis at `copilot:action:{action_id}` for **900 seconds** (`_PENDING_TTL_SECONDS`, `backend/app/api/copilot.py:58`) and sent as a `confirm_request` event before `done`.

`POST /api/ai/copilot/confirm` (`copilot_confirm`, `backend/app/api/copilot.py:1076`) then runs or cancels it:

- The stored proposal must belong to the caller (404 otherwise, and 404 once it has expired).
- `edited_params` may replace the proposed parameters.
- A claim key (`copilot:action:{id}:claim`, 60 s) lets only one approval run at a time, so a double click or two tabs cannot create the campaign twice; a second approval gets 409.
- The handler runs through the models layer, never through the tools (`_ACTION_HANDLERS`, `backend/app/api/copilot.py:1069`): `_execute_create_campaign` (TLP:GREEN, status checked) and `_execute_add_note` (an entry note or an entity note).
- On success, a `✓ <summary>` message is appended to the conversation. On a validation error, the proposal is kept so you can retry with edited parameters.

---

## Conversation persistence and public sharing

`AIConversation` (`backend/app/models/ai_conversation.py`) stores a conversation's `messages` as a JSONB list of `{role, content, created_at, meta?}`, with `scope_type` of `entry`, `multi_entry`, `entity` or `global`, and an owner. The API in `backend/app/api/ai_conversations.py` (`/api/ai/conversations`) only ever shows a user their own conversations.

**Sharing.** `POST /{id}/share` creates (or returns) a `share_token` (`uuid4().hex`, unique) and returns `{share_token, path: "/shared/copilot/{token}"}`. `DELETE /{id}/share` clears the token. `GET /api/shared/copilot/{token}` needs no sign-in and returns `{title, scope_type, messages}`. The page `/shared/copilot/:token` (`frontend/src/pages/SharedCopilotPage.tsx`) is one of the few public routes; it calls that endpoint directly and renders the answers as Markdown. A link works until it is revoked; there is no expiry.

Two things to know:

- The shared page shows only each message's text, but the API returns the saved `meta` too. Anyone with the link can therefore see the `tool_events` (tool names, arguments and 200-character result summaries) by calling the endpoint.
- Proposed-action blocks are removed before saving, so shared conversations never contain raw action JSON.

---

## Frontend: the dock

`CopilotDockPanel` (`frontend/src/components/CopilotDockPanel.tsx`) is mounted once in `App.tsx` for signed-in users, outside the router, so it stays open across page changes. It is a resizable right-hand panel that can collapse to a rail.

**State** is in `uiStore` (`frontend/src/stores/uiStore.ts`): `copilotOpen`, `copilotWidth` and `copilotCollapsed` (saved), `copilotActiveConversationId`, and a one-off `copilotSeed` with a nonce.

**Opening it:**

- The header copilot button (`frontend/src/components/AppHeader.tsx`) and `Cmd/Ctrl+Shift+K` (`frontend/src/hooks/useGlobalShortcuts.ts`) toggle the dock. Plain `Cmd/Ctrl+K` opens the command palette, which also has an "Ask Copilot" action.
- **"Ask Copilot" buttons** call `openCopilotWith(seed)`: on entity profile headers, the entry reader, the entry AI panel, AI results, the bulk-selection toolbar (which pins several articles) and the detection workbench. A `CopilotSeed` can carry a starter `prompt` (sent at once), a `context` to pin, a `label`, and `lockContext`. When a seed arrives, the dock stops any running stream, starts a new thread, pins the context for that thread, and sends the prompt.

**Page context.** `useCopilotContext` (`frontend/src/hooks/useCopilotContext.ts`) builds the request `context` from the route and stores: the selected entry, the entity from workbench URLs (`actor` becomes `threat_actor`), the campaign, the search query and the path. The copilot embedded in the documentation pages (`DocsCopilot.tsx`) sends `route: "/documentation"` and the `doc_slug` of the page being read. A pinned (seeded) context replaces it. The `ContextPill` (`frontend/src/components/ContextPill.tsx`) shows what is pinned; dismiss it to ask about the whole instance.

**Streaming.** `streamCopilotChat` (`frontend/src/hooks/useAI.ts`) reads SSE over `fetch`, because `EventSource` cannot send an Authorization header. Each assistant turn shows tool-trace chips (pending, then success or error), the streamed Markdown, and a confirm card when a `confirm_request` arrives. While a confirm card is open, the input is disabled ("Resolve the pending action above to continue…"). Confirming posts to `/ai/copilot/confirm`, adds the result as a message, and refreshes the campaigns list.

**Slash commands.** Typing `/` in an empty input opens a menu (`frontend/src/components/copilotCommands.ts`): `/summarize`, `/pivot`, `/rules`, `/report`, `/campaign`, `/trending`, `/gaps`. Choosing one fills in a prompt; it does not send it.

**History and sharing.** The header lists past `global` conversations to resume or delete. Share creates the public link and copies it. Sharing needs at least one finished turn, because the conversation id only exists after `done`.

Other behavior:

- **Resumed conversations show text only.** Saved tool events are not turned back into chips, and old confirm cards do not reappear.
- **Running streams stop** when the dock closes, a new thread starts, another thread is resumed, or a seed arrives.
- **Empty state** offers four suggested prompts; a turn with nothing to show yet displays "Thinking...".
- **Who answered.** From `GET /api/ai/copilot/config`, the header shows a chip with the provider, "· your key" when your own key answers, and "no tools" when that key has no tool loop. A banner appears when the turn would be refused (with a link to My AI) or ran on the site after your key could not answer. Each reply's footer shows the model, the cost, "your key", and the fallback reason when there is one.

---

## Authentication: the Claude sign-in

The CLI signs in with an OAuth session from a Claude subscription, not a per-token API key. There are two ways to provide it:

- **Prod**: `.credentials.json` in the `claude_cli` volume, mounted only by `celery-worker-ai`. `CLAUDE_CODE_OAUTH_TOKEN` is deliberately not passed to that container (keep it out of the host's `.env` too), because it would override the file and stop the CLI refreshing tokens itself. Never delete the volume: that loses the copilot's sign-in (see [operations.md](operations.md)).
- **Dev**: the dev worker also passes `CLAUDE_CODE_OAUTH_TOKEN` from `.env`, so a long-lived token can stand in for the file.

The session expires now and then (about monthly in practice). When it does, the copilot just fails, so the sign-in is monitored and can be renewed inside the app.

### Health snapshot

`refresh_claude_auth_status` (`backend/app/workers/copilot_auth_tasks.py:369`) runs `claude auth status --json` on the AI worker, reads the expiry from `.credentials.json` when there is one, and saves a snapshot in Redis at `copilot:auth:status`. It runs every 30 minutes (job `refresh-copilot-auth-status`) and on demand. `GET /api/ai/copilot-auth/status` returns the snapshot and starts a refresh if there is none yet.

### In-app re-auth (`claude auth login`)

The flow runs across the api and the AI worker, connected through Redis (`run_claude_auth`, `backend/app/workers/copilot_auth_tasks.py:231`):

1. `POST /api/ai/copilot-auth/start` takes a lock (`copilot:auth:lock`; a second start gets 409) and queues `run_claude_auth` on the `ai` queue.
2. The worker runs `claude auth login --claudeai` in a pseudo-terminal 1000 columns wide, so the long sign-in URL stays on one line. It removes any token variables so a real browser sign-in happens, finds the URL, and sets the session to `awaiting_code`.
3. The browser polls `GET /session/{id}` every 2.5 seconds and opens the URL. The admin signs in, copies the code, and pastes it back; `POST /session/{id}/code` passes it to the worker, which types it into the CLI.
4. Success means a fresh, valid `.credentials.json` appears (checked by its modification time, not the CLI's exit code). The worker updates the snapshot and sets the session to `success`. Each step has a time limit (90 s for the URL, 300 s for the code, 90 s for the exchange), so an abandoned flow cannot block the single AI worker for long. `POST /session/{id}/cancel` frees it at once.

Session states, stored at `copilot:auth:session:{id}` for 15 minutes: `starting → awaiting_code → exchanging → success | error | timeout | cancelled`, plus `expired` on the client when the session key has gone. Failures carry a plain message (`_diagnose_failure`, `backend/app/workers/copilot_auth_tasks.py:207`: rate-limited, bad or expired code, or the CLI's last lines) and a cleaned transcript tail.

### UI surfaces

- **The Claude Code provider card** at Settings → AI Configuration → Providers includes `CopilotAuthCard` (embedded by `frontend/src/components/ClaudeCodeConfigEditor.tsx`): a health badge (Authenticated / expiring within 48 h / Expired / Checking), an expiry countdown, the subscription type, and the start → open URL → paste code flow.
- **The dock's banner**: admins see "Copilot sign-in expired — responses will fail until you re-authenticate" with a button that opens `CopilotReauthModal` (the same flow). It appears only when the copilot's provider is `claude_code`. The status is re-checked after any failed or empty turn, so the banner shows up when it matters.

---

## Cost tracking

**Settings → AI Configuration → Cost Dashboard** shows 30-day totals by task and model from `GET /api/ai/cost-breakdown`, which adds up `AIResult.cost_estimate`.

Each copilot turn writes one `AIResult` row (`target_type="conversation"`, `target_id` = the conversation id), including turns that fail or are abandoned mid-stream. On the CLI the dollar figure is **notional**: the CLI's final `result` event reports token usage and a `total_cost_usd`, which `ClaudeCodeProvider` reads (`_extract_usage`) and passes along in the `done` event. Under a flat-rate subscription that figure is what the usage *would* cost at API prices, not a real charge. The real limit is the subscription's rate limits, which show up as `QuotaExhaustedError` pauses. `tokens_input` includes cache tokens; the raw breakdown is in `parsed_result.usage`.

With other providers the row is priced from the stream's reported usage (`last_stream_usage`), or from the cost table when there are tokens but no dollar figure. Every row records `caller_kind="user"`, the person's `user_id`, and `key_owner_id` when their own key answered. That is what the monthly cap, the site allowance and the By-user table count.

---

## Failure modes

| Symptom | Cause | What to do |
|---|---|---|
| "Copilot worker produced no output" | The AI worker is down, or the `ai` queue is busy past the BLPOP wait | Check `celery-worker-ai` logs. Only the `(error: …)` message is saved |
| Empty or failed answers with no clear error | The Claude sign-in expired | The dock re-checks after a failed turn and shows admins the re-sign-in banner |
| `QuotaExhaustedError` in worker logs | The subscription's usage window is full | Wait for the reset. The single worker means retries do not pile up |
| Confirm returns 404 "expired or does not exist" | The proposal is older than 900 s, or belongs to someone else | Ask the copilot to propose it again |
| Confirm returns 409 | Another approval of the same proposal is running | Wait a moment |
| Leftover `copilot:stream:{run_id}` keys | The client left before the api read the list | They expire after 300 s |
| A turn stops partway after about 4–6 minutes | The 240 s CLI timeout or the 300 s Celery soft limit | Raise `timeout_seconds` in the copilot assignment config, staying under the task limits |
| The status card shows "Checking…" on a fresh install | No snapshot yet | `GET /status` starts a refresh; or press Refresh on the card |

Celery results share Redis with the copilot, so they expire after one hour (`result_expires=3600` in `backend/app/workers/celery_app.py`). Without that limit, old results can fill Redis to `maxmemory` and break copilot streaming with "OOM command not allowed".

---

## Limits and knobs

| Knob | Where | Value and effect |
|---|---|---|
| `copilot_worker_dispatch` | `backend/app/config.py:444` | `true` (default): run the CLI in `celery-worker-ai`. `false`: run it in the api. Ollama always runs in the api |
| `allowed_tools`, `timeout_seconds` | Copilot assignment config (Settings → AI Configuration) | `["IntelFeed"]`, 240 s |
| `ollama_tools` | Copilot assignment config (Prompt Workspace → Routing) | The read-only tools offered to an Ollama copilot; default `DEFAULT_COPILOT_OLLAMA_TOOLS` |
| History | `_MAX_HISTORY_MESSAGES` | Last 20 messages sent as `conversation_history` |
| Pinned articles | `_PINNED_ENTRY_MAX_CHARS`, `_PINNED_MULTI_MAX_ENTRIES`, `_PINNED_MULTI_MAX_CHARS` | 15,000 characters for one article; 8 articles at 4,000 each when several are pinned |
| Pending-action lifetime | `_PENDING_TTL_SECONDS` | 900 s |
| Worker stream lifetime | `_STREAM_TTL_SECONDS` | 300 s for an unread `copilot:stream:{run_id}` list |
| Task time limits | `run_copilot_stream` | Soft 300 s, hard 360 s |
| BLPOP wait | `copilot_stream` | CLI timeout + 60 s |
| Rate limit | `AI_LIMIT`, `backend/app/core/rate_limit.py:32` | 20 requests per minute in the `ai` bucket for `/api/ai/*` (stream, confirm, conversations) and the two public share AI routes, keyed on the client IP behind the proxy. `/api/ai/copilot-auth` is exempt (`AI_EXEMPT_PREFIXES`, `backend/app/core/rate_limit.py:18`) |
| `site_ai_user_daily_requests` | Settings → AI Configuration → User keys | Daily requests one person may make on the instance's providers, copilot turns included. `0` (default) = unlimited. Failed turns count; over the limit is 429 `ai_allowance_exceeded` |
| `allow_user_ai_providers`, `require_user_ai_provider`, `user_ai_provider_types`, `user_ai_daily_request_cap` | Settings → AI Configuration → User keys | Whether a person's own key may (or must) answer their copilot turns, which key types, and the call cap. Off by default. See [automation-ai-enrichment.md](automation-ai-enrichment.md#personal-keys--the-lookup) |
| Worker concurrency | `CLAUDE_CODE_CONCURRENCY` on `celery-worker-ai` | Default 1: copilot turns wait behind other AI jobs |
| Sign-in health job | `refresh-copilot-auth-status` | Every 30 minutes |

---

## Test coverage

- `backend/tests/test_copilot_confirm_claim.py`: a proposed action runs once, however many approvals arrive.
- `backend/tests/test_user_ai_providers.py`: `/config` reporting whose key answers, the Required refusal, and a streamed turn counting toward the person's cap.
- `backend/tests/test_ai_allowance.py`: the site allowance on `/stream`.
- Nearby: `test_ai_providers.py` (providers), `test_ai_tasks.py` and `test_ai_prompts.py` (task and prompt seeding, including `copilot`), `test_rate_limiter.py` (the `ai` bucket), `test_ollama_provider.py`, `test_claude_code_confinement.py` (the CLI's tool confinement and agent token).

The fence splitter and the worker relay have no direct tests yet. `_FenceSplitter` and `_parse_action_block` need no database or Redis, so they are easy to unit-test.
