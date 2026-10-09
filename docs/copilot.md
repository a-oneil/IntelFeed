# AI Copilot — Global Chat, Streaming Tool Traces, and Claude Sign-in

## Overview

The **copilot** is IntelFeed's global, dockable AI chat: a streaming, tool-calling, read-only assistant that answers analyst questions against the live platform data, proposes a small set of confirmable writes, and persists every thread server-side. It is distinct from the per-entry "Ask Agent" chat (`entry_qa` task): the copilot is available on every page, carries ambient context about what the analyst is looking at, and can call IntelFeed's own CLI tools mid-answer.

The moving parts:

| Layer | Where | Role |
|---|---|---|
| Stream endpoint | `backend/app/api/copilot.py` | `POST /api/ai/copilot/stream` (SSE) + `POST /api/ai/copilot/confirm` |
| CLI worker task | `backend/app/workers/copilot_tasks.py` | Runs the Claude Code CLI on the `ai` queue, relays events over Redis |
| Provider | `backend/app/ai/providers/claude_code_provider.py` | `stream_agent()` — spawns `claude -p --output-format stream-json` and yields typed events |
| Auth API + tasks | `backend/app/api/copilot_auth.py`, `backend/app/workers/copilot_auth_tasks.py` | OAuth credential health snapshot + in-app `claude auth login` re-auth flow |
| Persistence | `backend/app/models/ai_conversation.py`, `backend/app/api/ai_conversations.py` | `ai_conversations` threads, share tokens |
| Public share | `backend/app/api/shared.py:1047` | Unauthenticated `GET /api/shared/copilot/{token}` |
| Tool layer | `intelfeed-skill/scripts/intelfeed_cli.py` | Read-only IntelFeed CLI the model calls via Bash/Skill |
| Frontend dock | `frontend/src/components/CopilotDockPanel.tsx` | Right-hand dock: streaming transcript, tool traces, confirm cards, history, share |

Routers are mounted at `backend/app/main.py:780-781` (`/api/ai/copilot`, `/api/ai/copilot-auth`); conversations at `main.py:779` (`/api/ai/conversations`).

Request/streaming flow diagram: [diagrams/copilot-stream-flow.md](diagrams/copilot-stream-flow.md).

### API surface

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/ai/copilot/stream` | user | One chat turn, streamed over SSE; persists to `ai_conversations` |
| `POST /api/ai/copilot/confirm` | user | Execute or cancel a proposed write action |
| `GET/POST /api/ai/conversations`, `GET/PATCH/DELETE /{id}` | user (owner) | Thread CRUD, paginated list filtered by scope |
| `POST /api/ai/conversations/{id}/share`, `DELETE .../share` | user (owner) | Mint / revoke a public share token |
| `GET /api/shared/copilot/{token}` | none | Public read-only view of a shared thread |
| `GET /api/ai/copilot-auth/status`, `POST /refresh` | admin | Cached credential health snapshot / force re-read |
| `POST /api/ai/copilot-auth/start`, `GET /session/{id}`, `POST /session/{id}/code`, `POST /session/{id}/cancel` | admin | Interactive `claude auth login` re-auth flow |

Related docs: [automation-ai-enrichment.md](automation-ai-enrichment.md) (provider system, AI tasks, prompt templates), [cli-reference.md](cli-reference.md) (every skill tool + read-only mode), [frontend.md](frontend.md) (dock component tour, uiStore), [api-reference.md](api-reference.md) (endpoint summaries), [operations.md](operations.md) (service topology, `claude_cli` volume).

---

## The copilot AI task

The copilot is a normal AI task named `copilot`, seeded on startup like every other task (`backend/app/ai/prompts/defaults.py:1532`). What makes it special is its default wiring:

- **Default provider type** is `claude_code` (`DEFAULT_TASK_PROVIDERS`, `defaults.py:87`) — the CLI provider under the Claude Max subscription, not the API-key Anthropic provider. Since the 2026-08 Ollama tool-calling work, the copilot can alternatively be assigned to an **Ollama** provider (`TOOL_CAPABLE_PROVIDER_TYPES` in `backend/app/ai/capabilities.py`); see "Execution topologies" below.
- **Default model** is `sonnet` (`DEFAULT_TASK_MODELS`, `defaults.py:67`).
- **Assignment config** (`defaults.py:118-126`): `allowed_tools: ["Bash", "Read", "Skill"]` and `timeout_seconds: 240`. When the intelfeed skill isn't mounted where the CLI can load it, these tools simply go unused and the copilot degrades to text-only answers from the prompt + injected context.
- **Prompt variables**: `question`, `conversation_history`, `ambient_context`. The system template (`defaults.py:1541`) instructs the model to use the intelfeed skill for anything data-dependent, states that write tools are physically blocked, and defines the ` ```intelfeed-action ` proposal fence (see "Proposed writes" below).

Both the provider assignment and the prompt are editable at **Settings → AI Configuration** like any other task (the prompt in the Prompts tab's master–detail `PromptWorkspace`). If the assignment is missing, `/stream` fails with a 422 `not_configured` error (`backend/app/api/copilot.py:539`).

---

## Request flow: `POST /api/ai/copilot/stream`

`copilot_stream` (`backend/app/api/copilot.py:505`) accepts `{question, conversation_id?, context?}` and returns an `EventSourceResponse`. Per turn:

1. **Resolve the task assignment** — `get_task_assignment(db, user.id, "copilot")`.
2. **Load or create the conversation.** A supplied `conversation_id` must belong to the caller (404 otherwise). New conversations get a title from the first ~60 chars of the question and a scope derived from the context (`_scope_from_context`, `copilot.py:322`): `entry` / `entity` (`scope_id = "{entity_type}:{entity_id}"`) / `global`.
3. **Build ambient context** — `_build_ambient_context` (`copilot.py:267`) renders a short human paragraph from the optional `CopilotContext` (`copilot.py:71`). Every lookup is best-effort; failures degrade to omitting a line rather than erroring the request:

   | Context field | Rendered line |
   |---|---|
   | `entry_id` | `The analyst is reading the article "<title>" (entry id …).` |
   | `entity_type` + `entity_id` | `The analyst is viewing the <threat actor/malware family/vendor/product/tool/CVE> <name> profile (id …).` — resolved via `_entity_display` (`backend/app/api/copilot.py:160`) |
   | `campaign_id` | `The analyst is viewing the campaign "<name>" (id …).` |
   | `search_query` | `The analyst is searching for "<query>".` |
   | `route` | `They are on the <pathname> page.` |
4. **Render the prompt** from the copilot task templates with `question`, `ambient_context`, and the last **20** stored messages (`_MAX_HISTORY_MESSAGES`, `copilot.py:45`) as `conversation_history`.
5. **Run the CLI turn** (two topologies, next section) and relay events as SSE.
6. **Persist the turn** — append the user question and the assembled assistant answer to `conv.messages` with `flag_modified` (`copilot.py:755-773`). Tool events are stored in the assistant message's `meta.tool_events`; a stream error with no visible text persists as `(error: …)`. Persistence failure is logged but never drops the client's answer.

A persisted assistant message looks like:

```json
{
  "role": "assistant",
  "content": "LockBit activity in the last week centers on…",
  "created_at": "2026-07-18T14:02:11.512345+00:00",
  "meta": {
    "tool_events": [
      {"type": "tool_call", "id": "toolu_01…", "name": "Bash", "args": {"command": "python3 …/intelfeed_cli.py search_entries '{…}'"}},
      {"type": "tool_result", "id": "toolu_01…", "status": "success", "summary": "{\"items\": [{\"title\": …"}
    ]
  }
}
```

Only the *visible* prose is persisted — the proposed-action fence (below) is stripped before storage, so shared conversations never leak raw action JSON. Confirmed actions append a separate `✓ summary` message with `meta.action_executed`.

### SSE event schema

Each `data:` frame is a JSON object (the schema is in `copilot_stream`'s docstring, `copilot.py:511-517`):

```
{"type": "chunk", "text": ...}
{"type": "tool_call", "id", "name", "args"}
{"type": "tool_result", "id", "status", "summary"}
{"type": "confirm_request", "action_id", "action_type", "description", "proposed"}
{"type": "error", "message": ...}
{"type": "done", "conversation_id": <uuid>}
```

`error` is only emitted when the stream failed *and* no visible text was produced; `done` is always last.

### Non-CLI providers: Ollama tool loop and text-only fallback

If the assigned provider is not a `ClaudeCodeProvider`, two paths exist (`copilot.py:668-698`, `:700`):

- **Ollama** (`supports_tools` + `stream_agent`) — a native `/api/chat` function-calling loop runs **in-process** in the api (no CLI, no credentials, so `copilot_worker_dispatch` does not apply). Tools are dispatched against the backend tool registry (`app.tools.execute_tool`) via an in-process executor bound to the request's DB session and user; specs come from `ollama_tool_specs(..., read_only=True)`, so only read tools are exposed. The default curated subset is `DEFAULT_COPILOT_OLLAMA_TOOLS` (`backend/app/tools/__init__.py:99`), overridable via the assignment's `ollama_tools` config key (Prompt Workspace → Routing panel). Tool traces stream to the dock exactly as in the CLI path.
- **Any other non-tool provider** (e.g. the Anthropic API provider) falls back to the base `stream_complete` contract — text-only chunks, no tool trace.

---

## Execution topologies: worker dispatch vs in-process

The Claude Code CLI needs OAuth credentials at `~/.claude/.credentials.json`. In production only the **`celery-worker-ai`** container mounts that volume (it is the single writer that rotates tokens — concurrent OAuth refresh from a second mount would corrupt it). The api container has neither the CLI, the credentials, nor the skill mount (`docker-compose.prod.yml:165-170`).

`copilot_worker_dispatch` (`backend/app/config.py:397`, default `true`) selects the topology (it only applies to the `claude_code` provider — the Ollama tool loop always runs in-process):

- **Worker dispatch (prod default)** — the api enqueues `app.workers.copilot_tasks.run_copilot_stream` on the `ai` queue (`copilot.py:630-655`) with a fresh `run_id`, and drains a Redis list while the worker runs the CLI.
- **In-process (dev fallback)** — the api calls `provider.stream_agent()` directly (`copilot.py:656-667`). This only works where the api container itself has the CLI + credentials; the dev compose mounts the skill into the api for this reason (`docker-compose.dev.yml:135`).

Either way, the event-handling loop in the endpoint is identical — `_iter_worker_events` deliberately mirrors `stream_agent`'s `{"kind": ...}` output shape.

| | Prod (`docker-compose.prod.yml`) | Dev (`docker-compose.dev.yml`) |
|---|---|---|
| Who runs the CLI | `celery-worker-ai` only | `celery-worker-ai` (worker dispatch) or the api (in-process) |
| Credentials | `claude_cli` volume → `.credentials.json`; CLI silently refreshes tokens | `CLAUDE_CODE_OAUTH_TOKEN` env forwarded to the CLI worker (`:158`) |
| `CLAUDE_CODE_OAUTH_TOKEN` | Intentionally **not** forwarded (`:230-236`) — it would override the credentials file and disable silent refresh | Forwarded from `.env` |
| Skill mount | CLI worker only (`:222`) | CLI worker (`:151`) **and** api (`:98`) |
| Prompt/DB logic | Always in the api — the worker task is a pure event relay | Same |

### The Redis relay

`run_copilot_stream` (`backend/app/workers/copilot_tasks.py:112`, `soft_time_limit=300`/`time_limit=360`) is a deliberately thin shim: it owns **no** business logic. It runs `ClaudeCodeProvider.stream_agent` and RPUSHes each raw `{"kind": ...}` event, verbatim, onto `copilot:stream:{run_id}` (`copilot_tasks.py:38`), plus terminal sentinels `__error__` / `__end__`. A **list** (not pub/sub) avoids the subscribe-before-publish race and buffers events if the api briefly falls behind; a 300 s TTL (`copilot_tasks.py:39`) cleans up orphaned runs. Even a task crash pushes an emergency terminator (`copilot_tasks.py:152`) so the api consumer never hangs.

The api drains via BLPOP in `_iter_worker_events` (`copilot.py:430`), with a timeout of `cli_timeout + 60 s` (`copilot.py:654`) — if the worker goes silent past that, the stream errors with "Copilot worker produced no output".

### The `ai` queue

All CLI-subprocess tasks are routed to this queue (`backend/app/workers/celery_app.py:58-94`): copilot turns, both auth tasks, link validation, the autonomous entity-maintenance tasks, and the hygiene-review and relationship-adjudication batches. `celery-worker-ai` consumes it with `--concurrency=${CLAUDE_CODE_CONCURRENCY:-1} --prefetch-multiplier=1` (`docker-compose.prod.yml:310`, dev `:212`) to avoid OAuth session-file corruption and respect Max-plan rate limits. Consequence: at the default concurrency of 1, a long copilot turn and a batch maintenance task queue behind each other.

### The CLI invocation

`stream_agent` (`claude_code_provider.py:582`) spawns `claude -p --output-format stream-json --verbose --include-partial-messages` (`_build_stream_argv`, `claude_code_provider.py:519`), passes the system prompt via `--append-system-prompt`, the tool allowlist via `--allowedTools`, and `--dangerously-skip-permissions` (safe: read-only tools, no TTY). It maps CLI stream-json lines to typed events in `_map_stream_event` (`claude_code_provider.py:702`): `text_delta` partials → `text`, `tool_use` blocks on assistant messages → `tool_call` (emitted with fully-assembled args, not at block start), `tool_result` blocks → `tool_result` with a 200-char summary. Quota/rate-limit stderr raises `QuotaExhaustedError` (`claude_code_provider.py:36`) with a best-effort reset-time parse.

---

## The tool layer: read-only intelfeed skill

The copilot's only tool surface is the **intelfeed skill** — the same zero-dependency CLI documented in [cli-reference.md](cli-reference.md), mounted read-only into the CLI worker at `/home/appuser/.claude/skills/intelfeed` (`docker-compose.prod.yml:286`, dev `:193` and, for the in-process path, into the api at dev `:135`). The skill CLI authenticates back into the api with `INTELFEED_API_URL` / `INTELFEED_USERNAME` / `INTELFEED_PASSWORD` env vars set on the worker.

Two enforcement layers keep the copilot read-only:

1. **CLI tool allowlist** — the copilot turn only allows `Bash`, `Read`, `Skill` (assignment config, `defaults.py:124`). No Write/Edit tools exist in the session.
2. **Hard write-tool denylist in the skill CLI** — the endpoint sets `INTELFEED_READ_ONLY=1` in the subprocess env for copilot invocations only (`copilot.py:647`, `copilot.py:666`; threaded through `stream_agent`'s `env` parameter, `claude_code_provider.py:612-628`). When truthy, the skill CLI refuses any batch containing a write tool **before any network call** — it prints a JSON error and exits 2 (`intelfeed-skill/scripts/intelfeed_cli.py:50`, gate at `:3894-3906`). The denylist is a generated `WRITE_TOOLS` frozenset (`intelfeed_cli.py:62`) of 88 tools — every registry tool flagged `mutating` plus the persisting AI tools (`extract_*`, `run_ai_task`) — regenerated by `scripts/dev/sync_skill_clis.py` and guarded by `test_tool_registry_sync.py`; everything not listed is a read tool. This is the physical boundary — it holds even if the system prompt is bypassed. See [diagrams/cli-readonly-gating.md](diagrams/cli-readonly-gating.md). (The Ollama copilot path enforces the same boundary differently: `ollama_tool_specs(..., read_only=True)` simply never exposes mutating registry tools to the model.)

Autonomous maintenance tasks on the same worker never set `INTELFEED_READ_ONLY`, so they retain write access.

---

## Proposed writes: the action fence + confirm endpoint

The copilot cannot write through its tools, but it can **propose** a small set of writes that the user explicitly confirms. The mechanism is prompt-side, not tool-side:

- The system prompt instructs the model to end its reply with exactly one ` ```intelfeed-action ` fenced JSON block (`defaults.py:1360`).
- The endpoint runs every text delta through `_FenceSplitter` (`copilot.py:372`), which withholds a rolling tail (`_HOLDBACK`, sized to the fence marker) so the fence never reaches the client even when split across deltas. Once the fence is seen, all further text accumulates for parsing instead of streaming.
- `_parse_action_block` (`copilot.py:339`) parses the JSON; only types in `_SUPPORTED_ACTION_TYPES = ("create_campaign", "add_note")` (`copilot.py:62`) with a `params` object are accepted. Parse failure degrades to no proposal — the visible answer is unaffected, and the raw block is never persisted to the conversation.
- A valid proposal is staged in Redis at `copilot:action:{action_id}` with a **900 s TTL** (`copilot.py:56-58`) and surfaced to the client as a `confirm_request` SSE event *before* `done`.

`POST /api/ai/copilot/confirm` (`copilot.py:889`) then executes or cancels it: ownership-checked against the staging record, optional `edited_params` override, dispatch through `_ACTION_HANDLERS` (`copilot.py:979`) — `_execute_create_campaign` (`copilot.py:895`, TLP:GREEN, status validated) and `_execute_add_note` (`copilot.py:923`, entry `Note` or `EntityNote`). Handlers go through the models layer directly, **never** the skill CLI. On success a `✓ summary` assistant message is appended to the conversation; on an `AppError` the Redis key is kept so the user can retry with edited params.

---

## Conversation persistence and public sharing

`AIConversation` (`backend/app/models/ai_conversation.py`) stores threads as a JSONB `messages` list of `{role, content, created_at, meta?}` with `scope_type` ∈ `entry | multi_entry | entity | global` and a per-user ownership constraint. The copilot writes `entry`/`entity`/`global` scopes; `multi_entry` is used by the entry-scoped chat features.

CRUD lives in `backend/app/api/ai_conversations.py` (`/api/ai/conversations`): paginated list filtered by scope, create, get, patch (append messages), delete — all scoped to the authenticated user.

**Sharing** (`ai_conversations.py:192-210`): `POST /{id}/share` mints (or returns) a `share_token` — a `uuid4().hex` stored on the row (`ai_conversation.py:32`, unique-indexed) — and returns `{share_token, path: "/shared/copilot/{token}"}`. `DELETE /{id}/share` revokes by nulling the token. The public read side is `GET /api/shared/copilot/{token}` (`backend/app/api/shared.py:1047`) — no auth, returns only `{title, scope_type, messages}`. The frontend route `/shared/copilot/:token` renders `SharedCopilotPage` (`frontend/src/App.tsx:84`, `frontend/src/pages/SharedCopilotPage.tsx`) as one of the few unauthenticated routes; it fetches the endpoint directly (bypassing the axios JWT client) and renders assistant turns as Markdown. There is no expiry — a share link works until revoked.

Two scope notes: the shared page renders only `role`/`content`, but the API response includes the stored message `meta` verbatim — so `tool_events` (tool names, CLI args, 200-char result summaries) are visible to anyone with the link via the raw endpoint. And because proposed-action fences are stripped before persistence, shared threads never contain raw action JSON.

---

## Frontend: the dock

`CopilotDockPanel` (`frontend/src/components/CopilotDockPanel.tsx`) mounts at the App level for authenticated users (`frontend/src/App.tsx:325`), outside the router, so it survives navigation. It is a resizable right-hand dock with a collapsed rail state.

**State** lives in `uiStore` (`frontend/src/stores/uiStore.ts:372-386`): `copilotOpen`, `copilotWidth`/`copilotCollapsed` (persisted), `copilotActiveConversationId`, and a transient `copilotSeed` + nonce.

**Entry points:**

- Header `✦` copilot button (`frontend/src/components/AppHeader.tsx:91`; on desktop it opens then expands/collapses the panel — only the dock's own `×` fully closes it) and `Cmd/Ctrl+Shift+K` (`frontend/src/hooks/useGlobalShortcuts.ts`) — toggle the dock. Plain `Cmd/Ctrl+K` stays with the command palette, which also offers an "Ask Copilot" action (`frontend/src/components/CommandPalette.tsx`).
- **"Ask Copilot" buttons** call `openCopilotWith(seed)` (`uiStore.ts:832`): entity profile headers (`frontend/src/components/entityProfile/ProfileHeader.tsx:175`), the entry reader (`frontend/src/components/EntryReader.tsx:562`), the entry AI panel and AI results display, the entry-list bulk toolbar, and the detection workbench. A `CopilotSeed` (`uiStore.ts:42`) can carry a starter `prompt` (auto-sent as the first message), a `context` to pin, a display `label`, and `lockContext`. The dock consumes seeds nonce-keyed (`CopilotDockPanel.tsx:284-332`): it aborts any in-flight stream, resets the thread, pins the seeded context for the whole thread, and auto-submits the prompt.

**Ambient context** — `useCopilotContext` (`frontend/src/hooks/useCopilotContext.ts:43`) assembles the request `context` from the current route + stores: selected entry id, entity slug parsed from workbench-style URLs (normalizing `actor` → `threat_actor`), campaign id, the active search query, and the pathname. A seeded (locked) context overrides the route-derived one; the `ContextPill` (`frontend/src/components/ContextPill.tsx`) shows what's pinned and can be dismissed to ask instance-wide questions.

**Streaming** — `streamCopilotChat` (`frontend/src/hooks/useAI.ts:601`) uses SSE-over-fetch (EventSource can't set an Authorization header) and dispatches each frame to callbacks. The dock interleaves, per assistant turn: `ToolTraceChip` chips (pending → success/error as `tool_call`/`tool_result` arrive), streamed Markdown text, and a `ConfirmCard` when a `confirm_request` lands. While a confirm is unresolved, the input is gated ("Resolve the pending action above to continue…"). The confirm resolution POSTs `/ai/copilot/confirm` and, on execute, appends the result summary as a linkified assistant message and invalidates the `campaigns` cache (`CopilotDockPanel.tsx:372`).

**Slash commands** — typing `/` in an empty input opens a preset menu (`frontend/src/components/copilotCommands.ts:24`): `/summarize`, `/pivot`, `/rules`, `/report`, `/campaign`, `/trending`, `/gaps`. Selection fills the input with a prompt template — never auto-sends.

**History / share** — the header lists past `global`-scope conversations (resume/delete via the conversations API); Share mints the public link and copies it to the clipboard (`handleShare`, `CopilotDockPanel.tsx:481-495`). Sharing requires at least one completed turn — the conversation id only exists after the backend's `done` event.

Worth knowing about dock behavior:

- **Resumed threads are prose-only.** `resumeConversation` (`CopilotDockPanel.tsx:511`) maps stored messages to `{role, content}` — persisted `meta.tool_events` are not rehydrated into trace chips, and old confirm cards do not reappear.
- **In-flight streams abort** on dock unmount, on starting a new thread, on resuming another thread, and when a seed arrives (`AbortController` via `abortRef`).
- **Input gating**: the textarea and send button are disabled while streaming or while any confirm card is pending/in-flight; the placeholder switches to "Resolve the pending action above to continue…".
- **Empty state** offers four suggested prompts (`CopilotDockPanel.tsx:42`); a streaming assistant turn with no text or traces yet renders a "Thinking…" indicator.

---

## Authentication: the Claude sign-in

The CLI authenticates via an OAuth session from a Claude Max subscription — there is no per-token API billing. Two auth methods exist:

- **Prod:** `.credentials.json` in the `claude_cli` named volume, mounted only by `celery-worker-ai` (`docker-compose.prod.yml:285`). `CLAUDE_CODE_OAUTH_TOKEN` is deliberately **not** forwarded to the prod CLI worker — when present it overrides the credentials file and disables the CLI's silent OAuth refresh (`docker-compose.prod.yml:294-298`). The volume must never be deleted (loses copilot auth; see [operations.md](operations.md)).
- **Dev:** the dev CLI worker forwards `CLAUDE_CODE_OAUTH_TOKEN` from `.env` (`docker-compose.dev.yml:200`), so a long-lived env token can stand in for the credentials file.

The session expires periodically (~monthly in practice), and when it does the copilot fails without an obvious cause — so credential health is monitored and re-auth is possible entirely in-app:

### Health snapshot

`refresh_claude_auth_status` (`backend/app/workers/copilot_auth_tasks.py:368`) runs `claude auth status --json` on the CLI worker (covering both auth methods), reads expiry from `.credentials.json` when applicable, and publishes a snapshot to the Redis key `copilot:auth:status`. It is **beat-scheduled every 30 minutes** (`refresh-copilot-auth-status`, `backend/app/workers/job_registry.py:412`) and runs on demand. `GET /api/ai/copilot-auth/status` (`backend/app/api/copilot_auth.py:39`, admin-only like all copilot-auth endpoints) returns the cached snapshot, kicking a refresh if none exists yet.

### In-app re-auth (`claude auth login`)

The interactive flow spans the api and the CLI worker, bridged over Redis (`backend/app/api/copilot_auth.py` ↔ `copilot_auth_tasks.run_claude_auth`, `copilot_auth_tasks.py:231`):

1. `POST /api/ai/copilot-auth/start` acquires a single-run lock (`copilot:auth:lock`; concurrent starts 409) and dispatches `run_claude_auth` to the `ai` queue.
2. The worker runs `claude auth login --claudeai` under a **pty** — forced to 1000 columns so the OAuth authorize URL isn't line-wrapped/truncated (`copilot_auth_tasks.py:258-263`) — strips any prebaked token env vars so a real browser flow runs, extracts the authorize URL (preferring the OSC-8 hyperlink target), and publishes session state `awaiting_code` + the URL.
3. The client polls `GET /session/{id}` (2.5 s interval, `frontend/src/hooks/useCopilotAuth.ts:103`), opens the URL, and the admin authorizes in the browser and pastes the code back; `POST /session/{id}/code` RPUSHes it to the worker, which feeds it to the CLI on the pty.
4. Success = a fresh, valid `.credentials.json` (polled by mtime, not CLI exit — `copilot_auth_tasks.py:296-320`); the worker updates the status snapshot and flips the session to `success`. Timeouts are bounded (90 s URL / 300 s code / 90 s exchange) so an abandoned flow can't wedge the concurrency-1 worker; `POST /session/{id}/cancel` unblocks it immediately.

Session states, published to `copilot:auth:session:{id}` (15 min TTL) and polled by the client: `starting → awaiting_code → exchanging → success | error | timeout | cancelled`, plus `expired` when the session key has lapsed (`frontend/src/hooks/useCopilotAuth.ts:19-36`). Failure responses carry a human-actionable message (`_diagnose_failure`, `copilot_auth_tasks.py:207` — rate-limited vs invalid/expired code vs raw CLI tail) and a cleaned transcript tail for debugging.

### UI surfaces

- **The Claude Code provider card** at Settings → AI Configuration → Providers embeds `CopilotAuthCard` (`frontend/src/components/ClaudeCodeConfigEditor.tsx:54` renders `<CopilotAuthCard embedded />`, opened from the provider list in `AISettings.tsx:520`): health badge (Authenticated / expiring `<48h` / Expired / Checking), expiry countdown, subscription type, and the start → open-URL → paste-code re-auth flow.
- **The dock's re-auth banner** (`CopilotDockPanel.tsx:119-123`, `:622-632`): admins see "Copilot sign-in expired — responses will fail until you re-authenticate" with a button opening `CopilotReauthModal` (same flow as the card). The banner is gated on the assigned provider actually being `claude_code` — an Ollama-assigned copilot never shows it. The auth status is re-checked after any errored/empty copilot turn so the banner appears right when it's relevant (`CopilotDockPanel.tsx:119`).

---

## Cost tracking

**Settings → AI Configuration → Cost Dashboard** (`frontend/src/components/AISettings.tsx:607`) shows 30-day totals and per-task / per-model breakdowns from `GET /api/ai/cost-breakdown` (`backend/app/api/ai_results.py:228`), which aggregates `AIResult.cost_estimate` — the per-call estimates the AI engine records when it runs tasks (`backend/app/ai/engine.py:574-591`, Prometheus `AI_COST_TOTAL` alongside).

The copilot's relationship to this is important to state precisely: **copilot turns appear in the cost dashboard, but the dollar figures are notional.** The CLI's terminal `result` event carries token usage (`input_tokens`, `output_tokens`, cache creation/read tokens) and a `total_cost_usd`; `ClaudeCodeProvider` parses it (`_extract_usage` in `claude_code_provider.py`) and attaches it to the stream's `done` event — relayed verbatim by the worker topology — and the stream endpoint records one `AIResult` row per turn (`target_type="conversation"`, `target_id=<conversation id>`, `backend/app/api/copilot.py`), with `cost_estimate` set to the CLI-reported `total_cost_usd`. Because the CLI runs under the flat-rate Max-subscription OAuth session, that figure is what the usage *would* cost at API rates, not an actual charge; copilot capacity is still bounded by Max-plan rate limits, surfaced as `QuotaExhaustedError` auto-pauses on the provider health banner. `tokens_input` on the row includes cache creation/read tokens (the full processed context); the raw breakdown is kept in `parsed_result.usage`.

---

## Failure modes

| Symptom | Cause | Behavior / recovery |
|---|---|---|
| Stream errors with "Copilot worker produced no output" | CLI worker down, or `ai` queue backed up past the BLPOP window (`copilot.py:654`) | The turn fails; nothing persisted beyond the `(error: …)` message. Check `celery-worker-ai` logs |
| Empty/failed answers, no obvious error | Expired Claude OAuth session | The dock re-checks auth status after an errored/empty turn and shows the admin re-auth banner (`CopilotDockPanel.tsx:274-276`) |
| `QuotaExhaustedError` in worker logs | Max-plan usage window hit (stderr sentinel match, `claude_code_provider.py:36-51`) | Propagated to the stream as an error; the shared `claude_code` worker also serializes retries, so pressure self-limits |
| Confirm returns 404 "expired or does not exist" | Pending action outlived its 900 s Redis TTL, or another user's `action_id` | Ask the copilot to re-propose |
| Orphaned `copilot:stream:{run_id}` keys in Redis | Client disconnected before the api drained | Self-cleaning via the 300 s list TTL |
| Turn ends mid-answer at ~4–6 min | CLI ceiling (240 s assignment config) or Celery `soft_time_limit=300` | Raise `timeout_seconds` in the copilot assignment config, mindful of the task time limits |
| First status card shows "Checking…" forever on a fresh deploy | No cached snapshot and beat not yet fired | `GET /status` self-heals by kicking a refresh; or press Refresh on the card |

Historical note: Celery task results share the copilot's Redis; before `result_expires` was capped at 1 h (`backend/app/workers/celery_app.py:45-49`), accumulated results could push Redis to `maxmemory` and break all copilot streaming with "OOM command not allowed".

---

## Limits and knobs

| Knob | Where | Value / effect |
|---|---|---|
| `copilot_worker_dispatch` | `backend/app/config.py:397` | `true` (default): dispatch CLI runs to `celery-worker-ai`; `false`: run in-process in the api (claude_code only — Ollama always runs in-process) |
| `allowed_tools` / `timeout_seconds` | copilot task assignment config (`defaults.py:118-126`, editable in Settings → AI Configuration) | `["Bash","Read","Skill"]`, 240 s CLI ceiling |
| `ollama_tools` | copilot assignment config (Prompt Workspace → Routing panel) | Curated read-only tool subset for an Ollama-assigned copilot; defaults to `DEFAULT_COPILOT_OLLAMA_TOOLS` (`backend/app/tools/__init__.py:99`) |
| History replay | `backend/app/api/copilot.py:45` | Last 20 messages injected as `conversation_history` |
| Pending-action TTL | `copilot.py:58` | 900 s before a proposed write expires |
| Worker stream buffer TTL | `copilot_tasks.py:39` | 300 s for an undrained `copilot:stream:{run_id}` list |
| Task time limits | `copilot_tasks.py:109-110` | `soft_time_limit=300`, `time_limit=360` |
| BLPOP silence window | `copilot.py:654` | CLI timeout + 60 s before the api declares the worker dead |
| Rate limit | `backend/app/core/rate_limit.py:29` | 20 req/min "ai" bucket on `/api/ai/*` (covers `/stream`, `/confirm`, conversations); `/api/ai/copilot-auth` is exempt (`rate_limit.py:15`) |
| Worker concurrency | `docker-compose.prod.yml:310` | `ai` queue at `${CLAUDE_CODE_CONCURRENCY:-1}` — at the default of 1, copilot turns serialize with autonomous CLI tasks |
| Re-auth beat job | `job_registry.py:251-256` | `refresh_claude_auth_status` every 30 minutes |

---

## Test coverage

There is no dedicated backend test module for the copilot (`backend/tests/` has no `test_copilot*.py`) — the fence splitter, worker relay, and confirm handlers are exercised only in production. Adjacent coverage exists in `backend/tests/test_ai_providers.py` (provider layer), `test_ai_tasks.py` / `test_ai_prompts.py` (task/prompt seeding, which includes the `copilot` task), and `test_rate_limiter.py` (the `ai` bucket). When adding copilot tests, `_FenceSplitter` (`copilot.py:372`) and `_parse_action_block` (`copilot.py:339`) are self-contained and unit-test without any DB/Redis fixtures.
