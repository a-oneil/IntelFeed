# IntelFeed MCP server (for local models)

`intelfeed_mcp.py` connects IntelFeed to any MCP client — LM Studio in particular — so a model
running on your own machine can search and pivot through IntelFeed with the same tool
registry the copilot and the skill CLIs use (`POST /api/tools/execute`).

It is built for small context windows. Handing a local model the registry directly costs
~12k tokens of tool schema for the read-only tools (~27k for all 170) before the user has
typed anything, and a single raw result (an entity search, an article) can take another 5–10k.
The server keeps the per-turn cost low instead:

| | Registry as plain tools | This server |
|---|---|---|
| Tool schemas sent every turn | 91 read-only tools, ~12.4k tokens | 9 tools, ~1.3k tokens |
| Everything else | always loaded | `load_skill(name)` adds a short playbook and the signatures of that task's tools (230–620 tokens), `call_tool` runs them |
| Results | raw JSON | shaped to ~2k tokens: HTML stripped, empty and noisy fields dropped, UUIDs → `u12` handles, dates shortened, uniform lists as tables; the rest is paged with `read_more` |
| Writes | whatever the model calls | read-only; opt-in `write_action` for a short allowlist |

The heaviest tools also get per-tool trims (`project()` in the server). A pivot returns ~1.6 MB of
JSON (every related entity's full record and evidence); it becomes one table row per related
entity. Priority-queue, story-thread and leak-site rows lose counters, colours, URLs and blurbs, and
lists the server returns beyond the requested `limit` are cut. On a live instance, eleven typical
calls went from ~11.2k to ~7.4k tokens (disclosures −59%, queue −58%, threads −48%, pivot −39%).

## What the model sees

Nine tools, fixed for the whole session (so the model server can reuse its cached prompt prefix):

- `search_entries`, `search_entities`, `get_entry`, `get_trending_entities` — the registry tools, with smaller default limits.
- `get_profile(entity_type, id)` — one tool for actor, malware, CVE, CWE, TTP, campaign, detection rule, intel report and ransomware victim profiles. `id` can be a handle, a name (`APT29`, resolved through `search_entities`, aliases included), a CVE id or a technique id.
- `pivot_entity` — co-occurrence pivot; also takes a name or a CVE/technique id.
- `load_skill(name)` / `call_tool(tool, args)` — everything else in the registry, one task at a time.
- `read_more(ref, page)` — the untrimmed version of a shortened result.

**Skills** live in `skills/*.md`: front matter (`name`, `description`, `tools`) and a short recipe
for one kind of question. The server appends each listed tool's signature from the live
registry, so a skill never carries a stale schema. Current skills: search-syntax,
actor-research, vulnerability-triage, ransomware, detection-coverage, article-analysis,
daily-briefing, campaigns, iocs, requirements-reports, feeds-sources, platform-admin,
intelfeed-help, and writes (only when writes are enabled). Adding one is adding a file.

**Safety.**
- `call_tool` runs a tool only if it is on the server's hand-reviewed `READ_ONLY_TOOLS` list *and*
  the registry says `mutating: false`; the tools that persist results anyway (`extract_*`,
  `run_ai_task`, `generate_detection_rules`) are excluded. A new or mis-flagged backend tool stays
  blocked until reviewed: `test_intelfeed_mcp.py` fails when the registry gains a read tool the
  list doesn't have.
- With `INTELFEED_MCP_ALLOW_WRITES=1` a separate `write_action` tool appears, limited to notes, tags,
  stars, bookmarks, read state, watches, campaigns and saved searches. `INTELFEED_MCP_WRITE_TOOLS`
  can narrow that list but never extend it. Merges, deletes, feed and automation changes are never
  exposed. Admin-only tools stay gated by `/api/tools/execute` as usual.
- Credentials only travel over `https://` (or `http://` to localhost; `INTELFEED_ALLOW_INSECURE_HTTP=1`
  for a trusted LAN), and redirects are never followed: urllib would otherwise re-send the
  `Authorization` header to whatever host a redirect names.
- The system prompt tells the model to treat article and feed text as data, never as instructions.
  The call log records tool and argument names, not values.

**Registry.** The server reads the live registry from `GET /api/tools/tools` on first use, so
`mutating` flags and schemas always match the deployment. `registry.json` is the fallback,
regenerated with the skill CLIs by `scripts/dev/sync_skill_clis.py`; `test_tool_registry_sync.py`
fails when it drifts.

## Setup (LM Studio)

1. Credentials: copy `.env.example` to `.env` next to the server and fill in
   `INTELFEED_API_URL`, `INTELFEED_USERNAME`, `INTELFEED_PASSWORD` (or set them in the
   environment). Python 3.12+, no packages to install.
2. Add the server to `~/.lmstudio/mcp.json` (LM Studio's Program tab edits this file):
   ```json
   {
     "mcpServers": {
       "intelfeed": {
         "command": "python3",
         "args": ["/path/to/IntelFeed/intelfeed-mcp/intelfeed_mcp.py"]
       }
     }
   }
   ```
   and enable `mcp/intelfeed` in the chat.

   **Bionic** (LM Studio's agent app) doesn't read `mcp.json`: add the server under
   Settings → MCP → Add custom MCP, connection type "On this computer", command `python3`,
   argument `/path/to/IntelFeed/intelfeed-mcp/intelfeed_mcp.py`. Raise the request timeout
   (advanced options, default 60 s) to ~150 s: some searches on a busy instance take a while.
3. Use `system_prompt.md` as the chat's system prompt.
4. Model settings: a tool-calling model (the Qwen 3 family works well), 32k–64k context, and
   a context-overflow policy that drops the middle of the conversation rather than the start.

Any other MCP client that launches stdio servers works the same way (Claude Desktop, Cursor, ...).

## Trying it

```bash
python3 try_local_model.py "What is Qilin up to this month?"
```

`try_local_model.py` plays the MCP host: it starts the server, lets the model behind an
OpenAI-compatible endpoint (`LLM_BASE_URL`, LM Studio by default, Ollama at
`http://localhost:11434/v1`) use it, and prints every tool call with the prompt size the model
server reports.

With `qwen/qwen3.8-27b` in LM Studio (64k context) and canned IntelFeed data, three questions
stayed small end to end:

| Question | Tool calls | Peak prompt |
|---|---|---|
| What do we know about APT29 lately? | 14 (skill loaded, profile, pivot, articles) | 5.0k tokens |
| Quick ransomware picture, last 30 days | 3 (skill → stats → disclosures) | 3.1k tokens |
| How worried should I be about CVE-2025-53770? | 7 (skill → profile → pivot → articles → stack exposure) | 4.0k tokens |

## Configuration

| Variable | Default | |
|---|---|---|
| `INTELFEED_API_URL` | `https://intelfeed.cc` | as for the skill CLIs |
| `INTELFEED_USERNAME` / `INTELFEED_PASSWORD` | — | required |
| `INTELFEED_MCP_ALLOW_WRITES` | off | exposes `write_action` |
| `INTELFEED_MCP_WRITE_TOOLS` | the allowlist above | comma-separated; can only narrow it |
| `INTELFEED_ALLOW_INSECURE_HTTP` | off | allow `http://` to a non-loopback host |
| `INTELFEED_MCP_RESULT_CHARS` | 7000 (≈2k tokens) | per-result budget |
| `INTELFEED_MCP_DEFAULT_LIMIT` | 10 | default `limit` for list/search tools |
| `INTELFEED_MCP_LOG` | — | append a call log to this file (stderr always gets one) |

## Tests

`backend/tests/test_intelfeed_mcp.py` (protocol, shaping, argument checks, the read-only gate
against every mutating registry tool, the reviewed read list, redirect and URL handling, skills
naming real read tools) and the snapshot check in
`backend/tests/test_tool_registry_sync.py` run with the backend suite in CI.
