# AI Copilot — Global Chat, Streaming Tool Traces, and Claude Sign-in

For contributors and operators. After reading this you will know how a copilot chat turn travels from the dock to the model and back, how every provider gets the same tools under the asking user's permissions, why no write runs until the user clicks Confirm, and how to keep the Claude sign-in working.

## Overview

The **copilot** is IntelFeed's chat panel, available on every page. It streams its answer, looks up live IntelFeed data with tools while it answers, can *propose* any change the asking user is allowed to make (each one waits for their click), and saves every conversation on the server. It is separate from the per-entry "Ask Agent" chat (the `entry_qa` task): the copilot knows which page and article you are on, and it can call tools.

| Part | Where | Role |
|---|---|---|
| Stream endpoint | `backend/app/api/copilot.py` | `POST /api/ai/copilot/stream` (SSE), `POST /api/ai/copilot/confirm`, `GET /api/ai/copilot/config` |
| Provider lookup | `backend/app/ai/engine.py` | `resolve_assignment`: the site's copilot assignment, or the person's own key when the admin allows personal keys |
| CLI worker task | `backend/app/workers/copilot_tasks.py` | Runs the Claude Code CLI on the `ai` queue and relays its events over Redis |
| CLI provider | `backend/app/ai/providers/claude_code_provider.py` | `stream_agent()` runs `claude -p --output-format stream-json` and yields typed events |
| Tool gate | `backend/app/tools/gate.py` | What a model is offered, what it may run, and staging writes for the user's click ([below](#the-tool-layer-one-gate-for-every-provider)) |
| Tool loops | `backend/app/ai/providers/claude_provider.py`, `openai_provider.py`, `ollama_provider.py` | `stream_agent()` for the Anthropic API, OpenAI-compatible servers and Ollama, run in the api process |
| CLI tools | `intelfeed-mcp/intelfeed_mcp.py` | The IntelFeed MCP server the CLI attaches, with an agent token for the asking user |
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
| `POST /api/ai/copilot/confirm` | user | Run or cancel a staged write |
| `GET /api/ai/copilot/config` | user | Who answers *your* copilot: `provider_type`, `provider_name`, `source` (`site` / `user`), `model`, `supports_tools`, `fallback_reason`, `refused` (`{reason, message}` when the turn would be refused), and the tool lists: `default_tools` (shown directly when the assignment sets none) and `enabled_tools` (the assignment's `agent_tools`, or null when the copilot reaches every tool). Reading it spends no allowance |
| `GET`/`POST /api/ai/conversations`, `GET`/`PATCH`/`DELETE /{id}` | owner | List (paginated, filterable by scope), create, read, append, delete |
| `POST /api/ai/conversations/{id}/share`, `DELETE .../share` | owner | Create or revoke a public share link |
| `GET /api/shared/copilot/{token}` | anyone | Read-only view of a shared conversation |
| `GET /api/ai/copilot-auth/status`, `POST /refresh` | admin | Cached sign-in health, or force a re-check |
| `POST /api/ai/copilot-auth/start`, `GET /session/{id}`, `POST /session/{id}/code`, `POST /session/{id}/cancel` | admin | The in-app re-sign-in flow |

Related docs: [automation-ai-enrichment.md](automation-ai-enrichment.md) (providers, tasks, prompts), [cli-reference.md](cli-reference.md) (every tool and read-only mode), [frontend.md](frontend.md) (the dock and `uiStore`), [api-reference.md](api-reference.md), [operations.md](operations.md) (services and the `claude_cli` volume).

---

## The copilot AI task

The copilot is an ordinary AI task named `copilot`, seeded at startup from `backend/app/ai/prompts/defaults.py`. Its defaults:

- **Provider type** `claude_code` (`DEFAULT_PROVIDER_TYPE_ASSIGNMENTS`): the Claude Code CLI under a Claude subscription sign-in. It can be assigned to any provider type with tools (`TOOL_CAPABLE_PROVIDER_TYPES` in `backend/app/ai/capabilities.py`): the Anthropic API (`claude`), `openai_compatible` and `ollama` each run their own tool loop. The one exception is an `openai_compatible` row with **Tool calling** turned off (`config.tools_enabled: false`); the site assignment refuses it with 400 `provider_incompatible`.
- **Model** `sonnet` (`DEFAULT_MODEL_ASSIGNMENTS`).
- **Assignment config** (`DEFAULT_ASSIGNMENT_CONFIGS`): `allowed_tools: ["IntelFeed"]` and `timeout_seconds: 240`. Older configs that say `["Bash", "Read", "Skill"]` mean the same thing to the provider. If the MCP server is not where the provider looks, the copilot answers without tools, from the prompt and the page context only.
- **Prompt variables**: `question`, `conversation_history`, `ambient_context`. The system prompt tells the model to use its tools for anything that depends on live data, to link to in-app pages instead of quoting raw IDs, and that a tool which changes data only proposes the change (see [Confirmed writes](#confirmed-writes-staging-and-the-confirm-endpoint)).

Both the assignment and the prompt are editable at **Settings → AI Configuration** (the prompt in the Prompts tab). If nothing can answer the task, `/stream` returns 422 `not_configured`.

**Personal keys.** `copilot` is one of the tasks a person's own key may answer (the admin can turn that off per task on the User keys tab). With `allow_user_ai_providers` on, a person who routes copilot (or sets a default key) at Settings → My AI gets their turns on that key. Personal Anthropic, `openai_compatible` and Ollama keys all run the same tool loop, through the same gate, under the person's own permissions. A personal `openai_compatible` key with Tool calling turned off answers in text only, and the dock says "no tools". Those turns do not count against the site allowance; their cost counts toward the person's monthly cap. A per-task "Instance default" route sends copilot back to the site's provider. The full lookup is in [automation-ai-enrichment.md](automation-ai-enrichment.md#personal-keys--the-lookup).

---

## Request flow: `POST /api/ai/copilot/stream`

`copilot_stream` (`backend/app/api/copilot.py:564`) takes `{question, conversation_id?, context?}` and returns an SSE stream. For each turn:

1. **Pick the provider**: `resolve_assignment(db, Caller.user(user.id), "copilot")`. This is where a turn can be refused before anything streams: 403 `user_ai_key_required` (personal keys are required, or the person turned off fallback and their key cannot answer; `details.reason` says why) or 429 `ai_allowance_exceeded` (the person used up today's `site_ai_user_daily_requests`).
2. **Load or create the conversation.** A given `conversation_id` must belong to the caller (404 otherwise). A new conversation is titled from the first 60 characters of the question. Its scope comes from the context (`_scope_from_context`, `backend/app/api/copilot.py:361`): `entry`, `multi_entry`, `entity` (`scope_id = "{entity_type}:{entity_id}"`) or `global`.
3. **Describe where the analyst is** (`_build_ambient_context`, `backend/app/api/copilot.py:306`) from the optional `CopilotContext` (`backend/app/api/copilot.py:101`). Each lookup is best effort; a failure just drops that line.

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

Only the visible text is saved. A confirmed write adds a separate `✓ <summary>` message with `meta.action_executed`; for a tool call it includes the start of the tool's result, so the model sees what happened on the next turn.

### SSE event schema

Each `data:` frame is one JSON object:

```text
{"type": "chunk", "text": ...}
{"type": "tool_call", "id", "name", "args"}
{"type": "tool_result", "id", "status", "summary"}
{"type": "confirm_request", "action_id", "action_type", "tool_name", "description", "proposed", "destructive"}
{"type": "error", "message": ...}
{"type": "done", "conversation_id": <uuid>, "answered_by": {...}}
```

`error` is sent only when the stream failed *and* produced no visible text. `done` is always last. Its `answered_by` feeds the reply footer: `provider_name`, `provider_type`, `source`, `model`, `cost_usd` (when usage was reported), `fallback_reason` and `supports_tools`.

### In-process providers: Anthropic API, OpenAI-compatible and Ollama

When the provider is not the Claude Code CLI, its tool loop runs **inside the api process**. No CLI or credentials are needed, so `copilot_worker_dispatch` does not apply.

- **Anthropic API** (`ClaudeProvider.stream_agent`): the Messages API tool-use loop. Text streams as it arrives; the tool list is cached along with the system prompt.
- **OpenAI-compatible** (`OpenAICompatibleProvider.stream_agent`): `/chat/completions` with `tools` and `tool_calls`. A server that rejects the `tools` parameter gets a text-only answer for that turn, which starts with a note saying so.
- **Ollama** (`OllamaProvider.stream_agent`): the native `/api/chat` tool loop.

All three get the same tools and run every call through the same `ToolGate` (see [the tool layer](#the-tool-layer-one-gate-for-every-provider)). `_copilot_tool_plan` (`backend/app/api/copilot.py`) builds them:

- **Shown directly:** the everyday reads and writes, `DEFAULT_COPILOT_TOOLS` plus `DEFAULT_COPILOT_LOCAL_WRITE_TOOLS` (`backend/app/tools/__init__.py`), and two helpers, `find_tools` and `call_tool`.
- **Reachable through the helpers:** every other registry tool the user may run. `find_tools` lists or searches them and returns their arguments; `call_tool` runs one through the same checks as a directly shown tool.

Sending the whole registry instead would cost about 26k tokens a round, swamp a local model, and break OpenAI, which refuses more than 128 tools in one request. The MCP server uses the same idea for the CLI. An assignment's `agent_tools` key (Prompt Workspace → Routing panel) limits the copilot to exactly those tools, with no helpers. Tool traces stream to the dock the same way as with the CLI.

A provider with tool calling turned off streams plain text. The dock's header says "no tools", and the footer says "tools unavailable on this key" when it was the person's own key.

---

## Execution topologies: worker dispatch vs in-process

The Claude Code CLI needs its OAuth credentials (`~/.claude/.credentials.json`). Only the **`celery-worker-ai`** container mounts them, through the `claude_cli` volume. It is the one process that refreshes the tokens; a second container refreshing them at the same time would corrupt the file. The prod api container has no CLI, no credentials and no MCP mount.

`copilot_worker_dispatch` (`backend/app/config.py:477`, default `true`) picks where the CLI runs. It only matters for the `claude_code` provider:

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

The api reads the list with BLPOP (`_iter_worker_events`, `backend/app/api/copilot.py:469`). If nothing arrives for the CLI timeout plus 60 seconds (180 + 60 when no timeout is set), the turn fails with "Copilot worker produced no output".

### The `ai` queue

All AI-calling Celery tasks are routed to the `ai` queue (`task_routes` in `backend/app/workers/celery_app.py`): copilot turns, the two sign-in tasks, one-pass entry analysis, adjudication, actor refresh, name normalization, AI gap enrichment and thread spines. `celery-worker-ai` reads it with `--concurrency=${CLAUDE_CODE_CONCURRENCY:-1} --prefetch-multiplier=1`, which protects the OAuth session and the subscription's rate limits. The catch: at concurrency 1, a long copilot turn and a background AI job wait for each other.

### The CLI invocation

`stream_agent` (`backend/app/ai/providers/claude_code_provider.py:777`) runs `claude -p --output-format stream-json --verbose --include-partial-messages` (`_build_stream_argv`, `backend/app/ai/providers/claude_code_provider.py:717`), passes the system prompt with `--append-system-prompt`, and adds the confinement flags described in [the tool layer](#the-tool-layer-one-gate-for-every-provider). `_map_stream_event` (`backend/app/ai/providers/claude_code_provider.py:905`) turns the CLI's output into events: text deltas become `text`, `tool_use` blocks become `tool_call` (sent once the arguments are complete), and `tool_result` blocks become `tool_result` with a 200-character summary. A quota or rate-limit message raises `QuotaExhaustedError` (`backend/app/ai/providers/claude_code_provider.py:40`), with a best guess at the reset time.

---

## The tool layer: one gate for every provider

Article text reaches the model's context through pinned articles, search results and entity names. So a tool call from the model is not a request from the user: one planted instruction could name any tool. `backend/app/tools/gate.py` makes the same rules hold whichever provider answers:

- **What is offered.** `model_tool_definitions` drops every `ADMIN_TOOLS` entry for a non-admin, removes `confirmation_token` from every schema a model sees, and replaces a delete tool's "call again with the token" instructions with "the user confirms it with a click".
- **What may run.** `check_call` refuses a tool that was not offered, an admin tool for a non-admin (checked again here, not only in the offer), and any call that carries a `confirmation_token`: that token stands for the user's yes, not the model's.
- **Reads** run straight away.
- **Writes are staged, not run.** `needs_confirmation` covers every mutating tool plus the reads that store what they produce (`PERSISTING_READ_TOOLS`: extractions, `run_ai_task`, `generate_detection_rules`). The call is saved for the asking user (`stage_tool_call`) and the model gets `{"status": "awaiting_confirmation", ...}` back. Only the user's click runs it ([below](#confirmed-writes-staging-and-the-confirm-endpoint)).
- **Skipping the click.** An admin can pick low-risk writes that run without it: **Skip Confirm for**, on the copilot's page in the Prompt Workspace (Settings → AI Configuration → Prompts). It stores the `copilot_auto_approve_tools` setting, empty by default. Only `auto_approvable_tools()` may be picked: never an admin tool, and never a two-step delete, whose first call deletes nothing.
- **Read-only surfaces.** The documentation page's copilot (`DocsCopilot.tsx`) shows no confirm cards, so it sends `context.read_only: true` and is offered read tools only (and the CLI gets a `read` token).

The in-process loops call `ToolGate` directly. The Claude CLI reaches the registry over HTTP, so `/api/tools/execute` (`backend/app/api/tools.py`) applies the same checks to its agent token.

### The Claude CLI

With the Claude Code CLI, the copilot's IntelFeed tools come from the [IntelFeed MCP server](../intelfeed-mcp/README.md) (`intelfeed-mcp/intelfeed_mcp.py`), mounted read-only at `/opt/intelfeed-mcp`. For each turn the provider (see the "tool policy" comment at the top of `claude_code_provider.py`):

1. **Creates an agent token** for the asking user (`create_agent_token` in `backend/app/core/security.py`): type `agent`, expiring with the run. On a copilot turn it is a `propose` token bound to the conversation; for every other task it is `read`. Ordinary API routes refuse this token type. Only `/api/tools/execute` and `/api/tools/tools` accept it. `execute` refuses a write for a `read` token with a 403, stages it for a `propose` token, and refuses a `confirmation_token` from either.
2. **Attaches the MCP server** with `--mcp-config` and `--strict-mcp-config`. The server gets the token and its API address in its own environment (`INTELFEED_TOKEN`, and `INTELFEED_API_URL` from the provider's `agent_api_url` / `INTELFEED_AGENT_API_URL`, default `http://api:8000`). The model never sees either. On a copilot turn the provider also sets `INTELFEED_MCP_PROPOSE_WRITES=1`, and the server's `write_action` tool then takes any registry write.
3. **Locks down the CLI.** `--tools` offers no built-in tools except WebSearch when a task asks for it. A deny list covers every built-in shell, file, fetch and agent tool. `--permission-mode dontAsk` refuses anything `--allowedTools` did not name, and `--setting-sources project` with an empty working directory stops settings in `~/.claude` from widening that.
4. **Cleans the environment.** The CLI keeps only `PATH`, `HOME`, locale, proxy and `CLAUDE_*` / `ANTHROPIC_*` variables, so the secrets in `.env` are not visible to it.

Writes the CLI stages are saved against the conversation, so the copilot collects them after the turn the same way as for the in-process providers.

---

## Confirmed writes: staging and the confirm endpoint

A staged write is stored in Redis at `copilot:action:{action_id}` for **900 seconds** (`STAGED_TTL_SECONDS` in `backend/app/tools/gate.py`) with the user, the conversation, the tool and its arguments. The conversation keeps a list of what it staged (`copilot:staged:{conversation_id}`). After the model finishes, `copilot_stream` takes that list (`take_staged`) and sends one `confirm_request` per write, oldest first, before `done`. Each carries `tool_name`, the exact `proposed` arguments, and `destructive` (a delete with a token flow, or an admin tool).

`POST /api/ai/copilot/confirm` (`copilot_confirm`, `backend/app/api/copilot.py`) then runs or cancels it:

- The stored call must belong to the caller (404 otherwise, and 404 once it has expired).
- `edited_params` may replace the arguments, except on a destructive call: that one is confirmed as shown or cancelled.
- A claim key (`copilot:action:{id}:claim`, 60 s) lets only one approval run at a time, so a double click or two tabs cannot run it twice; a second approval gets 409.
- `run_confirmed` runs the tool as the user who clicked, re-checking `ADMIN_TOOLS` against their role at that moment. A tool with a two-step token flow (the seven deletes: `delete_entity`, `delete_feed`, `delete_campaign`, `delete_automation_rule`, `delete_detection_rule`, `delete_intel_report`, `delete_requirement`; `confirmation_token_tools` finds them by their schema) gets its token here, server-side: the click is the confirmation.
- On success, a `✓ Done: <summary>. Result: …` message is appended to the conversation. If the tool returns an error, the staged call is kept so you can retry.

**The older action fence.** A copilot prompt edited before writes became tool calls may still tell the model to end its reply with a ` ```intelfeed-action ` JSON block. The endpoint still honours it: `_FenceSplitter` holds the fence back from the browser, `_parse_action_block` accepts `create_campaign` and `add_note` (`_SUPPORTED_ACTION_TYPES`), and confirming runs `_ACTION_HANDLERS`. The default prompt no longer asks for the fence; reset a customised copilot prompt to pick up the tool-based instructions.

---

## Conversation persistence and public sharing

`AIConversation` (`backend/app/models/ai_conversation.py`) stores a conversation's `messages` as a JSONB list of `{role, content, created_at, meta?}`, with `scope_type` of `entry`, `multi_entry`, `entity` or `global`, and an owner. The API in `backend/app/api/ai_conversations.py` (`/api/ai/conversations`) only ever shows a user their own conversations.

**Sharing.** `POST /{id}/share` creates (or returns) a `share_token` (`uuid4().hex`, unique) and returns `{share_token, path: "/shared/copilot/{token}"}`. `DELETE /{id}/share` clears the token. `GET /api/shared/copilot/{token}` needs no sign-in and returns `{title, scope_type, messages}`. The page `/shared/copilot/:token` (`frontend/src/pages/SharedCopilotPage.tsx`) is one of the few public routes; it calls that endpoint directly and renders the answers as Markdown. A link works until it is revoked; there is no expiry.

Two things to know:

- The shared page shows only each message's text, but the API returns the saved `meta` too. Anyone with the link can therefore see the `tool_events` (tool names, arguments and 200-character result summaries) by calling the endpoint.
- Staged writes are not part of the saved answer; a confirmed one appears as its `✓ Done` message.

---

## Frontend: the dock

`CopilotDockPanel` (`frontend/src/components/CopilotDockPanel.tsx`) is mounted once in `App.tsx` for signed-in users, outside the router, so it stays open across page changes. It is a resizable right-hand panel that can collapse to a rail.

**State** is in `uiStore` (`frontend/src/stores/uiStore.ts`): `copilotOpen`, `copilotWidth` and `copilotCollapsed` (saved), `copilotActiveConversationId`, and a one-off `copilotSeed` with a nonce.

**Opening it:**

- The header copilot button (`frontend/src/components/AppHeader.tsx`) and `Cmd/Ctrl+Shift+K` (`frontend/src/hooks/useGlobalShortcuts.ts`) toggle the dock. Plain `Cmd/Ctrl+K` opens the command palette, which also has an "Ask Copilot" action.
- **"Ask Copilot" buttons** call `openCopilotWith(seed)`: on entity profile headers, the entry reader, the entry AI panel, AI results, the bulk-selection toolbar (which pins several articles) and the detection workbench. A `CopilotSeed` can carry a starter `prompt` (sent at once), a `context` to pin, a `label`, and `lockContext`. When a seed arrives, the dock stops any running stream, starts a new thread, pins the context for that thread, and sends the prompt.

**Page context.** `useCopilotContext` (`frontend/src/hooks/useCopilotContext.ts`) builds the request `context` from the route and stores: the selected entry, the entity from workbench URLs (`actor` becomes `threat_actor`), the campaign, the search query and the path. The copilot embedded in the documentation pages (`DocsCopilot.tsx`) sends `route: "/documentation"`, the `doc_slug` of the page being read, and `read_only: true`. A pinned (seeded) context replaces it. The `ContextPill` (`frontend/src/components/ContextPill.tsx`) shows what is pinned; dismiss it to ask about the whole instance.

**Streaming.** `streamCopilotChat` (`frontend/src/hooks/useAI.ts`) reads SSE over `fetch`, because `EventSource` cannot send an Authorization header. Each assistant turn shows tool-trace chips (pending, then success or error), the streamed Markdown, and one confirm card per `confirm_request` (`frontend/src/components/ConfirmCard.tsx`). A card shows the tool and every argument; a destructive one adds a warning. While any card is open, the input is disabled ("Resolve the pending action above to continue…"). Confirming posts to `/ai/copilot/confirm`, adds the result as a message, and refreshes every cached query, since a write can touch any page.

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
| The copilot says it can't use a tool | The tool is admin-only and the user isn't an admin, or the assignment's `agent_tools` leaves it out | Ask an admin, or widen `agent_tools` |
| An OpenAI-compatible answer starts "This provider didn't accept tools" | The server rejected the `tools` parameter | Turn Tool calling off on that provider, or use a model that supports tools |
| Confirm returns 409 | Another approval of the same proposal is running | Wait a moment |
| Leftover `copilot:stream:{run_id}` keys | The client left before the api read the list | They expire after 300 s |
| A turn stops partway after about 4–6 minutes | The 240 s CLI timeout or the 300 s Celery soft limit | Raise `timeout_seconds` in the copilot assignment config, staying under the task limits |
| The status card shows "Checking…" on a fresh install | No snapshot yet | `GET /status` starts a refresh; or press Refresh on the card |

Celery results share Redis with the copilot, so they expire after one hour (`result_expires=3600` in `backend/app/workers/celery_app.py`). Without that limit, old results can fill Redis to `maxmemory` and break copilot streaming with "OOM command not allowed".

---

## Limits and knobs

| Knob | Where | Value and effect |
|---|---|---|
| `copilot_worker_dispatch` | `backend/app/config.py:477` | `true` (default): run the CLI in `celery-worker-ai`. `false`: run it in the api. The Anthropic API, OpenAI-compatible and Ollama always run in the api |
| `allowed_tools`, `timeout_seconds` | Copilot assignment config (Settings → AI Configuration) | `["IntelFeed"]`, 240 s |
| `agent_tools` | Copilot assignment config (Prompt Workspace → Routing) | Limits the copilot on the Anthropic API, OpenAI-compatible and Ollama to exactly these tools. Unset (default): the everyday tools plus `find_tools` / `call_tool` for the rest. `ollama_tools` is its old name and still works |
| `copilot_auto_approve_tools` | **Skip Confirm for**, the copilot's page in the Prompt Workspace | Writes that run without the click. Empty (default): every write waits for Confirm. Admin tools and deletes always wait |
| Tool calling (`tools_enabled`) | An `openai_compatible` provider's Configure panel | On by default. Off: that provider answers without tools |
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

- `backend/tests/test_copilot_tool_gate.py` (no database): non-admins are never offered or allowed an admin tool, no model sees or may send a `confirmation_token`, a tool that wasn't offered is refused, writes are staged and only run on confirm, the auto-approve list never covers admin tools, and the Anthropic and OpenAI-compatible loops run all of that through the gate.
- `backend/tests/test_copilot_confirmed_writes.py`: the CLI's `propose` token stages writes over `/api/tools/execute`, confirm runs a staged call once and only for its owner, re-checks admin tools, refuses edits to destructive calls, and a whole copilot turn on each in-process provider type stages its write and runs it on confirm.
- `backend/tests/test_copilot_confirm_claim.py`: a proposed action runs once, however many approvals arrive.
- `backend/tests/test_user_ai_providers.py`: `/config` reporting whose key answers, the Required refusal, and a streamed turn counting toward the person's cap.
- `backend/tests/test_ai_allowance.py`: the site allowance on `/stream`.
- Nearby: `test_ai_providers.py` (providers), `test_ai_tasks.py` and `test_ai_prompts.py` (task and prompt seeding, including `copilot`), `test_rate_limiter.py` (the `ai` bucket), `test_ollama_provider.py`, `test_claude_code_confinement.py` (the CLI's tool confinement and agent token).

The legacy fence splitter and the worker relay have no direct tests yet.
