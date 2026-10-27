# Copilot — request and streaming flow (prod worker-dispatch topology)

For developers working on the copilot. It shows one chat turn from the dock to the Claude Code CLI and back: the api picks the provider and conversation, sends the CLI run to the `ai` queue, relays the worker's events from Redis to the browser as SSE, saves the turn, and holds any proposed write until the user confirms it. With `COPILOT_WORKER_DISPATCH=false` the api runs the CLI itself instead of using the worker.

```mermaid
sequenceDiagram
    participant UI as CopilotDockPanel<br/>(streamCopilotChat)
    participant API as api<br/>POST /api/ai/copilot/stream
    participant Q as Redis
    participant W as celery-worker-ai<br/>(ai queue, concurrency 1)
    participant CLI as claude CLI<br/>(stream-json)
    participant SK as IntelFeed MCP server<br/>(intelfeed-mcp, read-only agent token)

    UI->>API: fetch POST {question, conversation_id?, context?}<br/>Authorization: Bearer JWT
    API->>API: resolve_assignment(Caller.user, "copilot")<br/>→ the site's claude_code provider, or the person's own key
    API->>API: load/create AIConversation (scope from context)
    API->>API: render system+user prompt<br/>(ambient context + last 20 messages)
    API->>Q: send_task run_copilot_stream(run_id, ...) → ai queue
    Q->>W: task pickup
    W->>CLI: spawn claude -p --output-format stream-json<br/>--mcp-config (IntelFeed tools only, no shell, file or fetch tools)
    loop agent turn
        CLI->>SK: IntelFeed tool call (search_entries, get_* ...)
        SK-->>CLI: JSON results (read-only token: no writes)
        CLI-->>W: stream-json lines (text_delta, tool_use, tool_result)
        W->>Q: RPUSH copilot:stream:{run_id} {"kind": ...} (TTL 300s)
        Q-->>API: BLPOP drain
        API->>API: _FenceSplitter withholds the intelfeed-action fence tail
        API-->>UI: SSE data: {type: chunk, tool_call or tool_result}
    end
    W->>Q: RPUSH {"kind":"__end__"}
    API->>API: persist user + assistant turn to ai_conversations<br/>(tool_events in message meta)
    opt model proposed a write
        API->>Q: SET copilot:action:{action_id} (TTL 900s)
        API-->>UI: SSE {type:"confirm_request", action_id, proposed}
        UI->>API: POST /api/ai/copilot/confirm {action_id, approved}
        API->>API: execute handler via models layer<br/>(create_campaign | add_note) — never the skill CLI
        API-->>UI: {status:"executed", result}
    end
    API-->>UI: SSE {type:"done", conversation_id}
```
