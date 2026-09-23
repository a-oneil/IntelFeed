# Copilot — request and streaming flow (prod worker-dispatch topology)

How one copilot turn travels from the dock to the Claude Code CLI and back: the api resolves the task assignment and conversation, dispatches the CLI run to the `ai` queue, relays worker events from a Redis list as SSE, withholds a proposed-action fence, persists the turn, and stages any proposed write for the confirm endpoint.

```mermaid
sequenceDiagram
    participant UI as CopilotDockPanel<br/>(streamCopilotChat)
    participant API as api<br/>POST /api/ai/copilot/stream
    participant Q as Redis
    participant W as celery-worker-ai<br/>(ai queue, concurrency 1)
    participant CLI as claude CLI<br/>(stream-json, INTELFEED_READ_ONLY=1)
    participant SK as intelfeed skill CLI<br/>(read-only)

    UI->>API: fetch POST {question, conversation_id?, context?}<br/>Authorization: Bearer JWT
    API->>API: get_task_assignment("copilot") → claude_code provider
    API->>API: load/create AIConversation (scope from context)
    API->>API: render system+user prompt<br/>(ambient context + last 20 messages)
    API->>Q: send_task run_copilot_stream(run_id, ...) → ai queue
    Q->>W: task pickup
    W->>CLI: spawn `claude -p --output-format stream-json`<br/>--allowedTools Bash,Read,Skill
    loop agent turn
        CLI->>SK: Bash: intelfeed_cli.py search_entries / get_* ...
        SK-->>CLI: JSON results (write tools refused, exit 2)
        CLI-->>W: stream-json lines (text_delta, tool_use, tool_result)
        W->>Q: RPUSH copilot:stream:{run_id} {"kind": ...} (TTL 300s)
        Q-->>API: BLPOP drain
        API->>API: _FenceSplitter withholds the intelfeed-action fence tail
        API-->>UI: SSE data: {type: chunk | tool_call | tool_result}
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
