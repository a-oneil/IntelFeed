# CLI Reference

This is the complete reference for the IntelFeed CLI — a zero-dependency Python tool that exposes 170 tools (organized into two flavors: full and lite) to query and manage a running IntelFeed deployment.

**Table of Contents:**
1. [Overview](#overview)
2. [Installation & Setup](#installation--setup)
3. [Invocation Patterns](#invocation-patterns)
4. [Read-Only Mode](#read-only-mode)
5. [The Lite Skill vs. Full Skill](#the-lite-skill-vs-full-skill)
6. [Search Query Language](#search-query-language)
7. [Tool Reference](#tool-reference)
8. [Common Workflows](#common-workflows)
9. [Error Handling & Troubleshooting](#error-handling--troubleshooting)
10. [Extending the CLI](#extending-the-cli)

---

## Overview

The IntelFeed CLI enables Claude skills (and humans, scripts, and CI systems) to interact with the IntelFeed platform without direct HTTP clients. It provides:

- **Search & discovery** across threat intelligence feeds and entities
- **Intelligence lookups** (threat actors, malware, CVEs, MITRE ATT&CK techniques)
- **Entry analysis** (full content, extracted TTPs, CVEs, campaigns, notes)
- **Detection engineering** (rule generation, validation, coverage analysis)
- **Campaign management** (timeline, correlation, detection gaps)
- **Entity correlation** (pivots, relationship graphs, temporal clustering)
- **Automation & triage** (rules, execution logs, priority scoring)
- **Data curation** (creation, modification, deletion, exports)

The CLI is shipped in two variants:

| Feature | Full CLI | Lite CLI |
|---------|----------|----------|
| **Tools** | 170 | 81 |
| **Write Operations** | Yes (create, update, extract, generate) | No |
| **Read-Only Mode** | Opt-in via `INTELFEED_READ_ONLY=1` (write-tool denylist) | Effectively always (no write tools shipped) |
| **Delete Operations** | Yes | No |
| **AI Tasks** | Yes | No |
| **Automation Execution** | Yes (execute, test, create rules) | No (view only) |
| **Intelligence Extraction** | Yes (TTPs, CVEs, actors, malware) | No |
| **Detection Rule Generation** | Yes | No |
| **Report Generation** | Yes | No |
| **Use Case** | Analyst workflows, automation scripts | Read-only dashboards, query APIs |
| **Context Window** | Standard | Smaller (fewer tool definitions) |

### Why a Custom CLI?

1. **Zero dependencies** — Uses only Python stdlib (`urllib`, `json`, `os`, `sys`). No `requests`, `httpx`, or other external libraries.
2. **Stateless** — Each invocation is independent; no persistent connections or state.
3. **Batching** — Supports multiple tool calls in a single invocation to reduce round-trips.
4. **Token caching** — Handles login once and caches tokens within a single CLI invocation; no persistent cache between invocations.
5. **Skill integration** — Designed to be embedded in Claude skill YAML manifests; keeps skill size small.

### The `--list-tools` Flag

```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py --list-tools
```

Prints all available tools with their descriptions, required parameters, and defaults. Useful for discovering what's available without memorizing the reference.

---

## Installation & Setup

### Requirements

- **Python 3.12+** (no version pinning needed — uses only stdlib)
- **Network access** to the running IntelFeed API
- **Three required environment variables** (plus one optional):

| Variable | Purpose | Example |
|----------|---------|---------|
| `INTELFEED_API_URL` | Base URL of the IntelFeed API | `https://intelfeed.example.com` or `http://localhost:8000` |
| `INTELFEED_USERNAME` | Username for authentication | `analyst@company.com` |
| `INTELFEED_PASSWORD` | Password for authentication | (store securely, e.g., in `.env` or secrets manager) |
| `INTELFEED_READ_ONLY` | Optional. Truthy value (`1`, `true`, `yes`, `on`) refuses all write tools before they reach the API | `1` (see [Read-Only Mode](#read-only-mode)) |

### Setup

1. **Set environment variables** (one-time per shell or permanently in `~/.bashrc`, `~/.zshrc`, Docker secrets, etc.):

```bash
export INTELFEED_API_URL="https://intelfeed.example.com"
export INTELFEED_USERNAME="your-username"
export INTELFEED_PASSWORD="your-password"
```

2. **For Docker deployments** (dev), set them when running the CLI container or in `docker-compose.env`:

```bash
docker run -e INTELFEED_API_URL=http://api:8000 \
           -e INTELFEED_USERNAME=admin \
           -e INTELFEED_PASSWORD=password \
           python:3.12 python intelfeed_cli.py search_entries '{"query": "ransomware"}'
```

### Authentication Under the Hood

1. **Login happens automatically** on first CLI invocation. The client POSTs to `/api/auth/login` with credentials.
2. **Tokens are returned** as `access_token` and `refresh_token` and stored in memory for the duration of the CLI process.
3. **Token refresh** happens automatically if the access token expires (401 response). The CLI uses the refresh token to get a new access token without re-prompting for credentials.
4. **No persistent cache** between invocations. Each CLI invocation logs in fresh. For high-frequency scripts, this is inefficient; consider a persistent client or API gateway (future enhancement).
5. **Redirects are not followed.** urllib would re-send the `Authorization` header to whatever host a redirect names, so a 3xx comes back as an `API returned 30x` error instead. Point `INTELFEED_API_URL` at the final `https://` address (not an `http://` one that redirects).

---

## Invocation Patterns

### Single Tool Call

```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py search_entries '{"query": "ransomware", "limit": 5}'
```

**Output:**
```json
{
  "tool": "search_entries",
  "result": [
    {
      "id": "entry-uuid-1",
      "title": "Ransomware Trends Q1 2026",
      "feed": "Krebs on Security",
      "published": "2026-05-01",
      ...
    }
  ]
}
```

### Multiple Tool Calls (Batched)

```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py \
  search_entries '{"query": "APT29"}' \
  get_feeds '{"limit": 10}' \
  get_dashboard_stats
```

**Output:**
```json
[
  {
    "tool": "search_entries",
    "result": [ ... ]
  },
  {
    "tool": "get_feeds",
    "result": [ ... ]
  },
  {
    "tool": "get_dashboard_stats",
    "result": { ... }
  }
]
```

### Tool with No Arguments

```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_dashboard_stats
```

### Tool-Specific Help

```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py --help-tool search_entries
```

**Output:**
```
search_entries
  Full-text search across RSS entries. Supports query language: ...

  Parameters:
    query (str) — required
    limit (int) — default: 20
    offset (int) — default: 0
    sort (str) — default: relevance, values: ['relevance', 'newest', 'oldest']

  Example:
    python intelfeed_cli.py search_entries '{"query": "<query>"}'
```

### Output Format

All results are **JSON to stdout**, one per line for single tool, or a JSON array for multiple tools.

**Usage and auth errors** (unknown tool, bad JSON, missing env vars, login failure) go to **stderr** as plain text with exit code 1. **API-level errors** are embedded in the stdout result object for the failing tool:

```json
{
  "tool": "get_entry",
  "result": {
    "error": "API returned 404",
    "detail": "{...}"
  }
}
```

**Read-only refusals** print a JSON error to **stdout** and exit with code 2 (see [Read-Only Mode](#read-only-mode)).

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Usage error (unknown tool, bad JSON, missing env vars, auth failure) |
| `2` | Read-only mode refusal — a write tool was requested while `INTELFEED_READ_ONLY` is set |

---

## Read-Only Mode

The full CLI supports a hard read-only mode. When the environment variable `INTELFEED_READ_ONLY` is set to a truthy value (`1`, `true`, `yes`, `on` — case-insensitive), any invocation containing a **write tool** is refused **before any network call is made** — including the login request. This is a physical boundary for read-only agents (e.g., a query-only copilot): even if the agent's system prompt is bypassed, the CLI process itself will not send a mutating request.

```bash
export INTELFEED_READ_ONLY=1
python3 intelfeed-skill/scripts/intelfeed_cli.py create_campaign '{"name": "Test"}'
# stdout: {"error": "read-only mode: create_campaign is a write action and is disabled"}
# exit code: 2
```

**Semantics:**

- The check runs against a `WRITE_TOOLS` denylist (a frozenset in the CLI script) — **84 tools**: every registry tool flagged `mutating` (79), plus the five AI tools that persist new or linked entities as a side effect despite being registry-read-only (`extract_ttps`, `extract_cves`, `extract_threat_actors`, `extract_malware`, `run_ai_task`).
- The denylist is **generated, not hand-maintained**: `scripts/dev/sync_skill_clis.py` rewrites it from the registry's `mutating` flags (plus its `EXTRA_WRITE_TOOLS` set), and `backend/tests/test_tool_registry_sync.py` fails if any mutating tool is missing from the CLI's denylist or a denylist entry no longer exists in the registry. Every tool not in the set (`search_*`, `get_*`, `list_*`, `check_*`, `pivot_*`, `export_attack_layer`, `export_campaign`, `validate_detection_rule`, `generate_detection_rules`, `build_detection_summary`, etc.) runs normally.
- In a **batched invocation**, if *any* requested tool is on the denylist, the **entire batch is refused** — no tool in the batch executes.
- The refusal is a JSON error printed to **stdout** with **exit code 2** (distinct from exit code 1 usage errors).

See the [CLI invocation & read-only gating diagram](diagrams/cli-readonly-gating.md) for the full flow (local validation → read-only gate → login → execute with token refresh).

---

## The Lite Skill vs. Full Skill

### When to Use Each

Use **`intelfeed-lite-skill`** when:
- You only need to **read** data (search, lookup, browse, analyze)
- You want **smaller context windows** (81 tool definitions vs. 170)
- You're building a **read-only dashboard** or **query interface**
- Your Claude skill doesn't need to create entries, extract intelligence, or generate rules

Use **`intelfeed-skill` (full)** when:
- You need to **write** data (create campaigns, extraction, detection rules)
- You're building an **analyst automation** tool or **triage system**
- You want to **generate detection rules** or **intelligence reports**
- You need to **manage automation rules** or **run extraction tasks**

### Feature Comparison

Both CLIs are code-generated from the backend tool registry by `scripts/dev/sync_skill_clis.py`, so the split is rule-based rather than a hand-picked list:

- **Full CLI (170 tools):** every tool in the backend registry (`backend/app/tools/`), read and write.
- **Lite CLI (81 tools):** every tool the registry does **not** flag as `mutating` (79 write tools are excluded), minus the compute-heavy read-only tools in the script's `LITE_EXCLUDE` set (AI invocation and document export: `extract_ttps`, `extract_cves`, `extract_threat_actors`, `extract_malware`, `run_ai_task`, `generate_detection_rules`, `validate_detection_rule`, `build_detection_summary`, `export_attack_layer`, `export_campaign`).

In practice the lite CLI covers all search/lookup/pivot/analytics/landscape reads (including the newer curation-stats, ransomware-tracker, and reader read tools), while creation, updates, merges, deletes, extraction, automation execution, and report generation are full-CLI only. Run `--list-tools` against either script for the authoritative listing.

---

## Search Query Language

All search tools (`search_entries`, `search_entities`, `search_unified`) support a powerful query language for precise filtering.

### Entry Filters

| Filter | Syntax | Example |
|--------|--------|---------|
| Title | `title:"..."` | `title:"zero day"` |
| Content | `content:...` | `content:ransomware` |
| Author | `author:...` | `author:Krebs` |
| Feed | `feed:"..."` | `feed:"Krebs on Security"` |
| Tag | `tag:...` | `tag:critical` |
| Type | `type:` | `type:rss`, `type:atom`, `type:youtube`, `type:podcast` |
| Date | `date:>{DATE}` | `date:>2026-03-01`, `date:2026-01..2026-03` |
| State | `is:...` | `is:starred`, `is:unread`, `is:read`, `is:bookmarked`, `is:noted`, `is:muted`, `is:translated`, `is:image` |
| Media | `media:...` | `media:audio`, `media:video`, `media:image`, `media:document` |
| Language | `lang:...` | `lang:en` |
| Category | `category:...` | `category:Blogs` — the feed's folder |
| Signal | `signal:...` | `signal:under_reported`, `signal:kev_added`, `signal:novel_entity` — the signal engine's reason for ranking an entry |
| Sector | `sector:...` | `sector:healthcare` — sector mentioned in the article |
| URL | `url:...` | `url:github.com` |
| Length | `words:` | `words:>1500`, `words:500..2000` |
| Source grade | `feed.reliability:` | `feed.reliability:B` — Admiralty-code grade (also `feed.timeliness:`, `feed.relevance:`) |
| Sort | `sort:` | `relevance`, `newest`, `oldest`, `radar`, `title_asc`, `title_desc`, `shortest`, `longest` |

`category`, `signal`, `sector`, `url`, `feed.*` and the `is:muted/translated/image`
values are answered from PostgreSQL rather than the search index, so they need no
re-index; the endpoint folds their entry IDs into the same constraint an entity
join uses. `sort:radar` is likewise PostgreSQL-backed — it orders by the signal
engine's `priority_score` (the Priority Queue's ranking), which means it excludes
unscored entries and does not rank free-text terms.

Three things to know before trusting a filter's output:

- **`OR` between two entry-scoped PostgreSQL filters silently means AND.** `signal:kev_added OR
  signal:scoop` intersects rather than unions and returns a plausible wrong number, not an error.
  Affects `signal:`, `sector:`, `url:` and `is:translated`/`is:image`. `is:muted` is worse still —
  it does not participate in OR at all, giving neither the union nor a reliable intersection.
  `feed:`, `category:` and the source grades OR correctly. Run the two queries separately.
- **A negated PostgreSQL filter only subtracts from an entry-ID set.** `NOT signal:feed_echo`
  removes its matches from a set that an *entity* filter or another *entry-scoped PostgreSQL*
  filter established. A bare text term or an index filter (`tag:`, `type:`, `date:` …) builds no
  such set, so the negation is silently dropped — `ransomware NOT signal:kev_added` returns every
  ransomware entry unchanged. On its own it matches everything.
- **Feed grades are exact letters.** `feed.reliability:>B` is not supported, and
  ungraded feeds match no grade filter.

### Intelligence Filters

| Filter | Syntax | Examples |
|--------|--------|----------|
| CVE | `cve:` | `cve:CVE-2025-5777`, `cve.severity:critical`, `cve.cvss:>9.0` |
| CVE exploitation | `cve.kev:` | `cve.kev:true`, `cve.epss:>0.5`, `cve.epss_percentile:>0.9`, `cve.poc:>0`, `cve.exploit:kev` |
| CVE products | `cve.product:` | `cve.product:fortinet` — matches the NVD CPE vendor or product |
| TTP | `ttp:` | `ttp:T1059*`, `ttp.tactic:initial-access` |
| TTP shape | `ttp.platform:` | `ttp.platform:Windows`, `ttp.data_source:process`, `ttp.domain:ics`, `ttp.subtechnique:true` |
| Actor | `threat_actor:` | `threat_actor:APT29`, `threat_actor.country:Russia`, `threat_actor.motivation:espionage`, `threat_actor.sector:healthcare`, `threat_actor.type:ransomware` |
| Malware | `malware:` | `malware:Emotet`, `malware.type:trojan`, `malware.sector:finance` |
| Tool | `tool:` | `tool:Mimikatz`, `tool.type:...`, `tool.platform:Windows` |
| Country | `country:` | `country:"United States"`, `country.region:Europe`, `country.iso:RU` |
| Vendor / product | `vendor:` | `vendor:Cisco`, `product:ASA`, `product.vendor:Cisco` |
| Rule | `rule:` | `rule:"Sigma Detection"`, `rule.type:sigma`, `rule.severity:high` |
| Rule content | `rule.data_source:` | `rule.data_source:sysmon`, `rule.tactic:persistence`, `rule.tag:attack`, `rule.draft:false` |
| Ransomware victim | `ransomware_victim:` | `ransomware_victim.sector:manufacturing`, `ransomware_victim.group:lockbit` |
| PIR | `pir:` | `pir:"Ransomware Activity"`, `pir.priority:critical`, `pir.category:tactical` |
| Notes | `note:` | `note:fortibleed` (title or body), `note.tag:`, `note.type:analysis`, `note.about:cve` / `:entry` / `:standalone`, `note.pinned:true` |
| Report | `intel_report:` | `intel_report:quarterly`, `intel_report.status:draft`, `intel_report.tlp:amber` |
| Catalogue | `<entity>.articles:` | `threat_actor.articles:>100`, `malware.seen:>2026-01-01`, `ttp.first_seen:>2026-06`, `cve.via:ai_extraction`, `threat_actor.review:true` |

The catalogue suffixes (`.articles`, `.seen`, `.first_seen`) work on every
entity type; `.review` and `.via` (extraction provenance) work on
`threat_actor`, `malware`, `cve`, `ttp` and `tool`.

### Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `AND` | Both conditions (implicit between adjacent terms) | `ransomware AND type:rss` |
| `OR` | Either condition | `APT29 OR APT28` |
| `NOT` | Exclude | `NOT type:youtube` |
| `*` | Wildcard | `T1059*` (matches T1059.001, T1059.002, etc.) |
| `"..."` | Exact phrase | `"device code phishing"` |
| `()` | Grouping | `(ransomware OR malware) AND type:rss` |
| `>`, `>=`, `<`, `<=` | Comparison (numeric/date) | `cve.cvss:>9.0`, `date:>=2026-04-01`, `words:>1500` |

### Example Queries

```
# Find recent RSS entries about ransomware
ransomware type:rss sort:newest

# Find starred entries with critical CVEs
cve.severity:critical is:starred

# Find articles about specific TTPs and tactics
threat_actor:APT29 AND ttp.tactic:initial-access

# Find high-CVSS CVEs from the last month
cve.cvss:>9.0 AND date:>2026-04-01

# Known-exploited CVEs that the world is likely already attacking
cve.kev:true cve.epss:>0.5

# What the signal engine thinks is under-covered, ranked by its own score
signal:under_reported sort:radar

# Persistence rules that need Sysmon telemetry
rule.data_source:sysmon rule.tactic:persistence

# Windows techniques detectable from process telemetry
ttp.platform:Windows ttp.data_source:process

# Who has been posting manufacturing victims
ransomware_victim.group:lockbit

# Exclude YouTube, search for phishing
(phishing OR "social engineering") NOT type:youtube

# Complex: entries about specific actors' malware
threat_actor:APT29 AND (malware:APT29_Malware* OR threat_actor.country:Russia)
```

---

## Tool Reference

The registry contains 170 tools. The sections below document 83 core tools in full detail; the remaining 87 are summarized in [Extended Tool Surface](#extended-tool-surface) at the end of this section — use `--help-tool <name>` for their parameters. Each fully documented tool includes:

- **Name & Purpose** — what it does (1-line summary)
- **Arguments** — required and optional parameters with types and defaults
- **Returns** — shape of the JSON response
- **Backed by** — which backend API endpoint(s)
- **Example** — copy-paste-able invocation

### Search & Discovery (4 tools)

#### search_entries

Search across all RSS/Atom/YouTube/podcast entries with the full query language. Returns paginated results.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `query` | `str` | Yes | — | Search query (see Query Language above) |
| `limit` | `int` | No | 20 | Max results to return (per-call max 1000) |
| `offset` | `int` | No | 0 | Skip N results — use with `limit` to paginate through larger result sets |
| `sort` | `str` | No | `relevance` | Sort order: `relevance`, `newest`, `oldest` |

**Returns:** Array of entry objects with `id`, `title`, `content`, `feed`, `published`, `author`, `url`, `tags`, `starred`, `read`, `bookmarked`.

**Backed by:** `POST /api/tools/execute` → backend tool registry → `app.tools.search.search_entries()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py search_entries '{"query": "ransomware", "limit": 5, "sort": "newest"}'
```

---

#### search_entities

Search across all intelligence entities (threat actors, malware, CVEs, TTPs, countries, vendors, products, mitigations, tools). Returns matching entities with type and basic details.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `query` | `str` | Yes | — | Entity name or partial match |
| `limit` | `int` | No | 30 | Max results to return |

**Returns:** Array of entity objects with `type` (threat_actor, malware, cve, ttp, etc.), `id`, `name`, `aliases`, `description` (summary).

**Backed by:** `POST /api/tools/execute` → `app.tools.search.search_entities()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py search_entities '{"query": "APT29", "limit": 10}'
```

---

#### search_unified

Unified search across both entries and entities simultaneously. Returns combined results grouped by type (entries first, then entities).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `query` | `str` | Yes | — | Search query |
| `limit` | `int` | No | 20 | Max results per type |

**Returns:** Object with `entries` (array) and `entities` (array) keys.

**Backed by:** `POST /api/tools/execute` → `app.tools.search.search_unified()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py search_unified '{"query": "Emotet", "limit": 15}'
```

---

#### get_search_facets

Get available search facets: all feeds, categories, tags, and feed types present in the system. Useful for understanding what's available before searching.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| (none) | — | — | — | No parameters |

**Returns:** Object with `feeds` (array), `categories` (array), `tags` (array), `feed_types` (array).

**Backed by:** `POST /api/tools/execute` → `app.tools.search.get_search_facets()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_search_facets
```

---

### Read Operations (17 tools)

#### get_entry

Fetch a single entry by ID with full content and any extracted intelligence (TTPs, CVEs, threat actors, malware, campaigns, detection rules, notes).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | Yes | — | UUID of the entry |

**Returns:** Entry object with `id`, `title`, `content`, `feed`, `published`, `author`, `url`, `media_urls`, `ttps` (array), `cves` (array), `threat_actors` (array), `malware` (array), `campaigns` (array), `detection_rules` (array), `notes` (array), `tags` (array), `starred`, `read`, `bookmarked`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_entry()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_entry '{"entry_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### get_feed_entries

List recent entries from a specific feed, paginated.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `feed_id` | `str` | Yes | — | UUID of the feed |
| `limit` | `int` | No | 20 | Max results to return |

**Returns:** Array of entry objects (same schema as `search_entries` results).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_feed_entries()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_feed_entries '{"feed_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "limit": 10}'
```

---

#### get_threat_actor

Get a threat actor profile including aliases, motivation, country of origin, associated TTPs, campaigns, and linked articles.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `actor_id` | `str` | Yes | — | UUID or actor name (e.g., "APT29") |

**Returns:** Threat actor object with `id`, `name`, `aliases`, `description`, `motivation`, `country`, `ttps` (array), `malware` (array), `campaigns` (array), `entry_count` (int), `recent_entries` (array).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_threat_actor()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_threat_actor '{"actor_id": "APT29"}'
```

---

#### get_malware

Get malware family profile with aliases, malware type, associated threat actors, TTPs, and linked articles.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `malware_id` | `str` | Yes | — | UUID or malware name (e.g., "Emotet") |

**Returns:** Malware object with `id`, `name`, `aliases`, `description`, `type`, `threat_actors` (array), `ttps` (array), `entry_count` (int), `recent_entries` (array).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_malware()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_malware '{"malware_id": "Emotet"}'
```

---

#### get_cve

Get CVE details including CVSS score (v3.1), CVSS vector, EPSS score, severity, affected products, and linked articles.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `cve_id` | `str` | Yes | — | CVE identifier (e.g., "CVE-2025-5777" or UUID) |

**Returns:** CVE object with `id`, `cve_id`, `description`, `cvss_score`, `cvss_vector`, `severity`, `epss_score`, `affected_products` (array), `vendors` (array), `entry_count` (int), `recent_entries` (array), `references` (array).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_cve()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_cve '{"cve_id": "CVE-2025-5777"}'
```

---

#### get_ttp

Get a MITRE ATT&CK technique (TTP) by ID, including tactic, platforms, data sources, detections, and linked articles.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `ttp_id` | `str` | Yes | — | Technique ID (e.g., "T1059.001" or UUID) |

**Returns:** TTP object with `id`, `technique_id`, `name`, `description`, `tactic`, `platforms` (array), `data_sources` (array), `detection_rules` (array), `entry_count` (int), `recent_entries` (array).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_ttp()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_ttp '{"ttp_id": "T1059.001"}'
```

---

#### get_campaign

Get campaign details with timeline (chronological entries), linked entities, linked detection rules, and detection gaps (uncovered TTPs).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `campaign_id` | `str` | Yes | — | UUID of the campaign |

**Returns:** Campaign object with `id`, `name`, `description`, `status`, `tlp_marking`, `created_at`, `entries` (array), `entities` (array), `detection_rules` (array), `detection_gaps` (array), `timeline` (array).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_campaign()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_campaign '{"campaign_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### get_feeds

List all configured RSS/Atom/YouTube/podcast feeds with health status (last fetch time, error count, entry count).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `limit` | `int` | No | 50 | Max feeds to return |

**Returns:** Array of feed objects with `id`, `title`, `url`, `feed_type`, `category`, `enabled`, `last_fetched`, `fetch_error_count`, `entry_count`, `health_status`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_feeds()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_feeds '{"limit": 20}'
```

---

#### get_detection_rules

List detection rules. Optionally filter by rule type (SIGMA, Splunk SPL, CrowdStrike QL, Elastic QL, KQL, YARA, Snort/Suricata).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `rule_type` | `str` | No | `None` (all types) | Filter by type: `sigma`, `splunk_spl`, `crowdstrike_ql`, `elastic_ql`, `kql`, `yara`, `snort_suricata` |
| `limit` | `int` | No | 30 | Max rules to return |

**Returns:** Array of detection rule objects with `id`, `title`, `rule_type`, `rule_content`, `description`, `severity`, `ttp_coverage` (array), `created_at`, `entry_source` (optional).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_detection_rules()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_detection_rules '{"rule_type": "sigma", "limit": 10}'
```

---

#### get_requirements

Get intelligence requirements (Priority Intelligence Requirements / PIRs) with optional status filter.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `status` | `str` | No | `None` (all) | Filter by status: `active`, `fulfilled`, `expired`, `draft` |

**Returns:** Array of requirement objects with `id`, `title`, `keywords`, `description`, `priority`, `category`, `status`, `created_at`, `coverage_count` (int), `recent_matches` (array).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_requirements()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_requirements '{"status": "active"}'
```

---

#### get_correlation_events

Get recent correlation events — new entity sightings, shared infrastructure detections, detection gaps, campaign matches, etc.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `limit` | `int` | No | 30 | Max events to return |
| `unread_only` | `bool` | No | `False` | Filter to unread events only |

**Returns:** Array of correlation event objects with `id`, `type` (sighting, shared_infrastructure, detection_gap, campaign_match, etc.), `entity_type`, `entity_id`, `description`, `linked_entries` (array), `created_at`, `read`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_correlation_events()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_correlation_events '{"limit": 20, "unread_only": true}'
```

---

#### get_analytics

Get platform analytics: trending entities, intelligence velocity, detection coverage gaps, and overview stats.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `metric` | `str` | Yes | — | Metric to retrieve: `overview`, `trending`, `detection_coverage`, `velocity` |
| `entity_type` | `str` | No | `None` | For trending: `threat_actor`, `malware`, `cve`, `ttp` |
| `days` | `int` | No | 30 | Time window in days |

**Returns:** Varies by metric. `overview` returns totals. `trending` returns entity rankings. `detection_coverage` returns gap analysis. `velocity` returns extraction/publication rates.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_analytics()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_analytics '{"metric": "trending", "entity_type": "threat_actor", "days": 30}'
```

---

#### get_dashboard_stats

Get system-wide statistics: total entries, feeds, entities by type, recent activity, unread counts.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| (none) | — | — | — | No parameters |

**Returns:** Object with `total_entries`, `total_feeds`, `total_threat_actors`, `total_malware`, `total_cves`, `total_ttps`, `unread_entries`, `recent_activity` (array), `feed_health_summary`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_dashboard_stats()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_dashboard_stats
```

---

#### get_enrichment_data

Get enrichment results for an entity (EPSS scores, PoC availability, Malpedia details, known exploits, etc.).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entity_type` | `str` | Yes | — | Entity type: `cve` or `malware` |
| `entity_id` | `str` | Yes | — | UUID or identifier of the entity |

**Returns:** Object with `entity_id`, `entity_type`, `epss_score` (if CVE), `poc_available` (bool), `exploit_count` (int), `honeypot_hits` (if malware), `aliases_enriched` (array), `metadata`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_enrichment_data()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_enrichment_data '{"entity_type": "cve", "entity_id": "CVE-2025-5777"}'
```

---

#### get_attack_layer

Get MITRE ATT&CK Navigator layer JSON for the system (all TTPs with coverage stats) or a specific entry (TTPs in that entry only). Useful for visualization.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | No | `None` (system-wide) | UUID of entry to scope to; if None, returns all TTPs |
| `title` | `str` | No | `"IntelFeed ATT&CK Coverage"` | Title for the layer |

**Returns:** JSON object conforming to ATT&CK Navigator v4.3 layer format with techniques, heatmap scores, annotations.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_attack_layer()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_attack_layer '{"entry_id": "550e8400-e29b-41d4-a716-446655440000", "title": "This Article'\''s TTPs"}'
```

---

#### get_telemetry_sources

List configured telemetry/log sources and their coverage (which TTPs can be detected with available data sources).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| (none) | — | — | — | No parameters |

**Returns:** Array of telemetry source objects with `name`, `type` (event logs, network, cloud, etc.), `coverage_ttps` (array), `enabled`, `provider`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_telemetry_sources()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_telemetry_sources
```

---

#### get_requirement_coverage

Get intelligence requirements coverage summary — counts by status, priority, category, and staleness (how long since last match).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| (none) | — | — | — | No parameters |

**Returns:** Object with `total_requirements`, `by_status` (active, fulfilled, expired, draft counts), `by_priority` (critical, high, medium, low counts), `by_category` (strategic, operational, tactical, technical counts), `stale_count` (unfulfilled >30 days).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_requirement_coverage()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_requirement_coverage
```

---

### Campaign Analysis (6 tools)

#### get_campaigns

List campaigns with optional status filter.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `status` | `str` | No | `None` (all) | Filter by status: `active`, `monitoring`, `closed`, `historical` |
| `limit` | `int` | No | 30 | Max campaigns to return |

**Returns:** Array of campaign objects with `id`, `name`, `description`, `status`, `entry_count`, `entity_count`, `detection_rule_count`, `created_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_campaigns()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_campaigns '{"status": "active", "limit": 15}'
```

---

#### get_campaign_timeline

Get chronological entries in a campaign, sorted by publication date (oldest to newest by default).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `campaign_id` | `str` | Yes | — | UUID of the campaign |

**Returns:** Array of entry objects sorted by `published` date.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_campaign_timeline()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_campaign_timeline '{"campaign_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### get_campaign_attack_layer

Get MITRE ATT&CK Navigator layer JSON for all TTPs linked to a campaign.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `campaign_id` | `str` | Yes | — | UUID of the campaign |

**Returns:** ATT&CK Navigator layer JSON with campaign-specific TTPs highlighted.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_campaign_attack_layer()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_campaign_attack_layer '{"campaign_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### get_campaign_detection_gaps

Find TTPs linked to a campaign that have no active detection rules. Identifies coverage gaps.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `campaign_id` | `str` | Yes | — | UUID of the campaign |

**Returns:** Array of TTP objects with `id`, `technique_id`, `name`, `tactic`, `data_sources`, `required_telemetry`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_campaign_detection_gaps()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_campaign_detection_gaps '{"campaign_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### suggest_campaign_entries

Suggest entries that share entities (TTPs, CVEs, actors, malware) with a campaign but aren't yet explicitly linked to it. Useful for finding related articles.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `campaign_id` | `str` | Yes | — | UUID of the campaign |
| `limit` | `int` | No | 10 | Max suggestions to return |

**Returns:** Array of entry objects with `id`, `title`, `published`, `shared_entities` (array showing which entities match the campaign).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.suggest_campaign_entries()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py suggest_campaign_entries '{"campaign_id": "550e8400-e29b-41d4-a716-446655440000", "limit": 10}'
```

---

#### export_campaign

Export a complete campaign intel package including all linked entries, entities, and detection rules. Useful for sharing or archiving.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `campaign_id` | `str` | Yes | — | UUID of the campaign |

**Returns:** JSON object containing `campaign` (profile), `entries` (array), `entities` (array), `detection_rules` (array), `export_timestamp`.

**Backed by:** `POST /api/tools/execute` → `app.tools.export.export_campaign()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py export_campaign '{"campaign_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

### Automation (5 tools)

#### get_automation_rules

List automation rules with optional label filter.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `label` | `str` | No | `None` | Filter by label tag |
| `limit` | `int` | No | 30 | Max rules to return |

**Returns:** Array of automation rule objects with `id`, `name`, `description`, `trigger_type` (new_entry, new_entity, schedule, manual), `conditions` (query), `actions` (array), `enabled`, `execution_count`, `last_executed_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_automation_rules()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_automation_rules '{"label": "ransomware", "limit": 10}'
```

---

#### get_automation_templates

List pre-built automation rule templates with categories and example configurations.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| (none) | — | — | — | No parameters |

**Returns:** Array of template objects with `id`, `name`, `description`, `category`, `trigger_type`, `trigger_config_template` (example), `actions_template` (example).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_automation_templates()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_automation_templates
```

---

#### get_automation_logs

Get recent automation rule execution logs.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `rule_id` | `str` | No | `None` | Filter to specific rule; if None, all rules' logs |
| `limit` | `int` | No | 30 | Max log entries to return |

**Returns:** Array of log objects with `rule_id`, `rule_name`, `entry_id`, `executed_at`, `action_results` (array), `status` (success, partial, error).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_automation_logs()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_automation_logs '{"rule_id": "550e8400-e29b-41d4-a716-446655440000", "limit": 20}'
```

---

#### test_automation_rule

Dry-run an automation rule against an entry to see what would happen without executing actions. Useful for testing before enabling.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `rule_id` | `str` | Yes | — | UUID of the automation rule |
| `entry_id` | `str` | Yes | — | UUID of the entry to test against |

**Returns:** Object with `rule_id`, `entry_id`, `conditions_met` (bool), `matched_conditions` (array), `actions_would_execute` (array showing what would happen), `dry_run` (true).

**Backed by:** `POST /api/tools/execute` → `app.tools.write.test_automation_rule()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py test_automation_rule '{"rule_id": "550e8400-e29b-41d4-a716-446655440000", "entry_id": "660e8400-e29b-41d4-a716-446655440000"}'
```

---

#### run_automation_rule

Execute an automation rule immediately against recent entries (from the last N hours).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `rule_id` | `str` | Yes | — | UUID of the automation rule |
| `hours` | `int` | No | 24 | Look back this many hours for matching entries |

**Returns:** Object with `rule_id`, `entries_matched` (int), `actions_executed` (int), `results` (array of action outcomes), `timestamp`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.run_automation_rule()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py run_automation_rule '{"rule_id": "550e8400-e29b-41d4-a716-446655440000", "hours": 12}'
```

---

### Advanced Analytics (5 tools)

#### get_trending_entities

Get top entities by mention count over a time window.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entity_type` | `str` | Yes | — | Entity type: `threat_actor`, `malware`, `cve`, `ttp` |
| `days` | `int` | No | 30 | Time window in days |
| `limit` | `int` | No | 10 | Max entities to return |

**Returns:** Array of entity objects with `id`, `name`, `mention_count`, `appearance_trend` (sparkline array), `recent_articles` (array).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_trending_entities()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_trending_entities '{"entity_type": "threat_actor", "days": 30, "limit": 10}'
```

---

#### get_feed_value

Get feed value scores — composite 0-100 intelligence contribution metric per feed based on entity extraction, rule generation, and entry quality.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `days` | `int` | No | 30 | Time window in days |

**Returns:** Array of feed objects with `id`, `title`, `feed_type`, `value_score` (0-100), `entry_contribution` (%), `entity_extraction_count`, `rule_generation_count`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_feed_value()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_feed_value '{"days": 30}'
```

---

#### get_source_reliability

Get feeds ranked by intelligence contribution (entity extraction, detection rule generation, unique intelligence).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `limit` | `int` | No | 20 | Max feeds to return |

**Returns:** Array of feed objects ranked by reliability score, with `id`, `title`, `reliability_score`, `entity_count`, `rule_count`, `unique_intelligence_count`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_source_reliability()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_source_reliability '{"limit": 15}'
```

---

#### get_entry_insights

Get actionable intelligence insights for a specific entry's entities — what you should do based on what's in this article.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | Yes | — | UUID of the entry |

**Returns:** Object with `entry_id`, `insights` (array of actionable recommendations), `entities_mentioned` (array), `risk_level` (low, medium, high, critical), `recommended_actions` (array).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_entry_insights()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_entry_insights '{"entry_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### get_triage_queue

Get priority-scored entry queue for analyst review. Entries are scored by recency, entity importance, requirement matches, and detection gaps.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `days` | `int` | No | 7 | Look back this many days |
| `limit` | `int` | No | 20 | Max entries to return |

**Returns:** Array of entry objects with added `priority_score` (0-100), `score_breakdown` (recency, entities, requirements, gaps).

**Backed by:** `POST /api/tools/execute` → `app.tools.read.get_triage_queue()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_triage_queue '{"days": 7, "limit": 20}'
```

---

### Intelligence Extraction (5 tools)

#### extract_ttps

Extract MITRE ATT&CK techniques (TTPs) from an entry. Maps content to technique IDs using pattern matching and optionally AI. Stores results.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | Yes | — | UUID of the entry |
| `use_ai` | `bool` | No | `True` | Use AI-powered extraction (more accurate, slower) vs. pattern matching only |

**Returns:** Object with `entry_id`, `ttps_extracted` (array with technique_id, name, tactic, confidence), `extraction_method` (pattern or ai), `timestamp`.

**Backed by:** `POST /api/tools/execute` → `app.tools.extraction.extract_ttps()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py extract_ttps '{"entry_id": "550e8400-e29b-41d4-a716-446655440000", "use_ai": true}'
```

---

#### extract_cves

Extract CVE references from an entry and optionally enrich with NVD data (CVSS, severity, affected products). Stores results.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | Yes | — | UUID of the entry |

**Returns:** Object with `entry_id`, `cves_extracted` (array with cve_id, description, cvss_score, severity), `enrichment_source`, `timestamp`.

**Backed by:** `POST /api/tools/execute` → `app.tools.extraction.extract_cves()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py extract_cves '{"entry_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### extract_threat_actors

AI-identify threat actors mentioned in an entry. Creates new threat actor entities or links to existing ones. Stores results.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | Yes | — | UUID of the entry |

**Returns:** Object with `entry_id`, `threat_actors_found` (array with actor_id, name, aliases, confidence), `new_actors_created` (int), `existing_actors_linked` (int), `timestamp`.

**Backed by:** `POST /api/tools/execute` → `app.tools.extraction.extract_threat_actors()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py extract_threat_actors '{"entry_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### extract_malware

AI-identify malware families mentioned in an entry. Creates new malware entities or links to existing ones. Stores results.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | Yes | — | UUID of the entry |

**Returns:** Object with `entry_id`, `malware_found` (array with malware_id, name, aliases, type, confidence), `new_malware_created` (int), `existing_malware_linked` (int), `timestamp`.

**Backed by:** `POST /api/tools/execute` → `app.tools.extraction.extract_malware()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py extract_malware '{"entry_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### run_ai_task

Run any registered AI task on an entry (summary, threat_assessment, detection_engineering_summary, etc.). Uses the AI task assignment system.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `task_name` | `str` | Yes | — | Task name: `summary`, `threat_assessment`, `detection_engineering_summary`, or custom registered tasks |
| `entry_id` | `str` | Yes | — | UUID of the entry |

**Returns:** Object with `entry_id`, `task_name`, `result` (task-specific output), `status`, `timestamp`, `model_used`.

**Backed by:** `POST /api/tools/execute` → `app.tools.extraction.run_ai_task()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py run_ai_task '{"task_name": "threat_assessment", "entry_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

### Correlation & Analysis (8 tools)

#### pivot_entity

Find all entities related to a given entity via co-occurrence in entries. One-hop pivot — shows direct relationships only.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entity_type` | `str` | Yes | — | Entity type: `ttp`, `cve`, `threat_actor`, `malware`, `country`, `vendor`, `product`, `mitigation`, `tool` |
| `entity_id` | `str` | Yes | — | UUID or identifier of the entity |

**Returns:** Array of related entity objects, each with `id`, `type`, `name`, `co_occurrence_count` (how many entries mention both entities), `related_entries` (sample).

**Backed by:** `POST /api/tools/execute` → `app.tools.correlation.pivot_entity()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py pivot_entity '{"entity_type": "threat_actor", "entity_id": "APT29"}'
```

---

#### get_entity_graph

Build a correlation graph centered on an entity. Shows nodes (entities) and edges (co-occurrence relationships) up to specified depth.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entity_type` | `str` | Yes | — | Entity type: `ttp`, `cve`, `threat_actor`, `malware`, `country`, `vendor`, `product`, `mitigation`, `tool` |
| `entity_id` | `str` | Yes | — | UUID or identifier of the entity |
| `depth` | `int` | No | 1 | Graph depth (1-3): how many hops to follow |

**Returns:** Graph object with `nodes` (array of entities), `edges` (array of relationships with co-occurrence weights), `center_node` (the queried entity), `layout` (for visualization).

**Backed by:** `POST /api/tools/execute` → `app.tools.correlation.get_entity_graph()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_entity_graph '{"entity_type": "malware", "entity_id": "Emotet", "depth": 2}'
```

---

#### get_entity_timeline

Get chronological timeline of when an entity appeared in articles. Shows emergence and activity patterns.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entity_type` | `str` | Yes | — | Entity type: `ttp`, `cve`, `threat_actor`, `malware`, `country`, `vendor`, `product`, `mitigation`, `tool` |
| `entity_id` | `str` | Yes | — | UUID or identifier of the entity |

**Returns:** Array of timeline events with `date`, `entry_count`, `sample_entries` (articles from that date), `activity_trend` (sparkline).

**Backed by:** `POST /api/tools/execute` → `app.tools.correlation.get_entity_timeline()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_entity_timeline '{"entity_type": "cve", "entity_id": "CVE-2025-5777"}'
```

---

#### check_detection_gaps

Identify TTPs and CVEs that have been observed in entries but lack detection rule coverage. Highlights blind spots.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| (none) | — | — | — | No parameters |

**Returns:** Object with `gap_summary` (total count), `uncovered_ttps` (array), `uncovered_cves` (array), `affected_entries_count`, `remediation_suggestions` (array).

**Backed by:** `POST /api/tools/execute` → `app.tools.correlation.check_detection_gaps()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py check_detection_gaps
```

---

#### check_requirement_match

Check if a specific entry's content matches any active intelligence requirements (PIRs). Returns matched requirements.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | Yes | — | UUID of the entry |

**Returns:** Array of matched requirement objects with `id`, `title`, `keywords_matched` (which PIR keywords matched), `match_strength` (0-100).

**Backed by:** `POST /api/tools/execute` → `app.tools.correlation.check_requirement_match()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py check_requirement_match '{"entry_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### check_telemetry_feasibility

Check if detection rules are feasible given configured telemetry sources. Identifies what log sources are needed vs. available.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `rule_id` | `str` | No | `None` | Check a specific rule; if None, check all rules |

**Returns:** Array of feasibility assessments with `rule_id`, `rule_title`, `required_log_sources` (array), `available_log_sources` (array), `feasible` (bool), `gaps` (array of missing sources).

**Backed by:** `POST /api/tools/execute` → `app.tools.correlation.check_telemetry_feasibility()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py check_telemetry_feasibility '{"rule_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### get_temporal_clusters

Find entries sharing entities within time windows — useful for detecting emerging campaigns or coordinated activity.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `days` | `int` | No | 14 | Look back this many days |
| `window_hours` | `int` | No | 72 | Cluster entries published within this many hours of each other |
| `min_shared` | `int` | No | 3 | Minimum shared entities to form a cluster |
| `limit` | `int` | No | 10 | Max clusters to return |

**Returns:** Array of cluster objects with `cluster_id`, `entries` (array), `shared_entities` (array showing common TTPs, actors, malware, etc.), `temporal_span` (hours), `emergence_score`.

**Backed by:** `POST /api/tools/execute` → `app.tools.correlation.get_temporal_clusters()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_temporal_clusters '{"days": 14, "window_hours": 72, "min_shared": 3, "limit": 10}'
```

---

#### get_entry_graph

Get relationship graph for all entities linked to a single entry. Shows what's in this article and how entities relate to each other.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | Yes | — | UUID of the entry |

**Returns:** Graph object with `entry_id`, `nodes` (entities in the entry), `edges` (relationships between them), `statistics` (entity counts by type).

**Backed by:** `POST /api/tools/execute` → `app.tools.correlation.get_entry_graph()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py get_entry_graph '{"entry_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

### Detection Engineering (3 tools)

#### generate_detection_rules

Generate detection rules from an entry's TTPs. Supports 7 rule formats: SIGMA, Splunk SPL, CrowdStrike QL, Elastic QL, KQL, YARA, Snort/Suricata.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | Yes | — | UUID of the entry |
| `rule_types` | `list[str]` | Yes | — | List of rule formats to generate: `sigma`, `splunk_spl`, `crowdstrike_ql`, `elastic_ql`, `kql`, `yara`, `snort_suricata` |

**Returns:** Object with `entry_id`, `rules_generated` (array with rule_type, rule_content, coverage_ttps), `generation_timestamp`.

**Backed by:** `POST /api/tools/execute` → `app.tools.detection.generate_detection_rules()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py generate_detection_rules '{"entry_id": "550e8400-e29b-41d4-a716-446655440000", "rule_types": ["sigma", "splunk_spl"]}'
```

---

#### validate_detection_rule

Validate detection rule syntax for any supported format. Returns validation errors, warnings, and improvement suggestions.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `rule_type` | `str` | Yes | — | Rule format: `sigma`, `splunk_spl`, `crowdstrike_ql`, `elastic_ql`, `kql`, `yara`, `snort_suricata` |
| `rule_content` | `str` | Yes | — | The rule text to validate |

**Returns:** Object with `valid` (bool), `errors` (array of error messages), `warnings` (array), `suggestions` (array of improvements).

**Backed by:** `POST /api/tools/execute` → `app.tools.detection.validate_detection_rule()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py validate_detection_rule '{"rule_type": "sigma", "rule_content": "title: Test Rule\nlogsource: ...\ndetection: ..."}'
```

---

#### build_detection_summary

Full detection engineering analysis: gathers all intelligence context for entries and produces comprehensive attack chain analysis and detection gaps.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_ids` | `list[str]` | Yes | — | UUIDs of entries to analyze |
| `rule_formats` | `list[str]` | Yes | — | Rule formats to generate: `sigma`, `splunk_spl`, `crowdstrike_ql`, `elastic_ql`, `kql`, `yara`, `snort_suricata` |

**Returns:** Object with `entries_analyzed` (int), `attack_chain` (array showing tactic progression), `all_ttps` (array), `coverage_analysis` (TTPs with/without rules), `generated_rules` (array), `gaps` (array), `recommendations` (array).

**Backed by:** `POST /api/tools/execute` → `app.tools.detection.build_detection_summary()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py build_detection_summary '{"entry_ids": ["550e8400-e29b-41d4-a716-446655440000", "660e8400-e29b-41d4-a716-446655440000"], "rule_formats": ["sigma", "splunk_spl"]}'
```

---

### Write Operations (28 tools)

#### create_threat_actor

Create a new threat actor entity.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `name` | `str` | Yes | — | Primary name of the threat actor (e.g., "APT29", "Cozy Bear") |
| `aliases` | `list[str]` | No | `None` | Alternative names (e.g., ["Cozy Bear", "The Dukes", "NOBELIUM"]) |
| `description` | `str` | No | `None` | Description of the actor, motivations, history |
| `country` | `str` | No | `None` | Country of attribution (e.g., "Russia", "China") |
| `motivation` | `str` | No | `None` | Motivation type: `espionage`, `financial`, `hacktivism`, `unknown` |

**Returns:** Threat actor object with `id`, `name`, `aliases`, `description`, `country`, `motivation`, `created_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.create_threat_actor()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py create_threat_actor '{"name": "APT99", "aliases": ["The New Group"], "country": "North Korea", "motivation": "financial"}'
```

---

#### create_malware

Create a new malware family entity.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `name` | `str` | Yes | — | Malware name (e.g., "Emotet", "Trickbot") |
| `aliases` | `list[str]` | No | `None` | Alternative names |
| `description` | `str` | No | `None` | Description and analysis |
| `malware_type` | `str` | No | `None` | Type: `trojan`, `worm`, `ransomware`, `spyware`, `rootkit`, `botnet`, etc. |

**Returns:** Malware object with `id`, `name`, `aliases`, `description`, `malware_type`, `created_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.create_malware()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py create_malware '{"name": "NewRansom", "malware_type": "ransomware", "description": "Recently discovered ransomware"}'
```

---

#### create_detection_rule

Save a detection rule to the library.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `title` | `str` | Yes | — | Rule title (e.g., "Detect Mimikatz via Command Line") |
| `rule_type` | `str` | Yes | — | Rule format: `sigma`, `splunk_spl`, `crowdstrike_ql`, `elastic_ql`, `kql`, `yara`, `snort_suricata` |
| `rule_content` | `str` | Yes | — | The complete rule text (syntax depends on rule_type) |
| `description` | `str` | No | `None` | Description of what the rule detects |
| `severity` | `str` | No | `None` | Severity: `critical`, `high`, `medium`, `low`, `info` |
| `entry_id` | `str` | No | `None` | Link the rule to an entry (source article) |

**Returns:** Detection rule object with `id`, `title`, `rule_type`, `rule_content`, `description`, `severity`, `created_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.create_detection_rule()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py create_detection_rule '{"title": "Mimikatz Detection", "rule_type": "sigma", "rule_content": "title: Detect Mimikatz\n...", "severity": "high"}'
```

---

#### create_campaign

Create a new campaign to track a threat operation and link entities/entries to it.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `name` | `str` | Yes | — | Campaign name (e.g., "Operation SteadyRain", "Q2 2026 APT29 Activity") |
| `description` | `str` | No | `None` | Campaign description and context |
| `status` | `str` | No | `"active"` | Status: `active`, `monitoring`, `closed`, `historical` |
| `tlp_marking` | `str` | No | `"TLP:GREEN"` | TLP marking: `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED` |

**Returns:** Campaign object with `id`, `name`, `description`, `status`, `tlp_marking`, `created_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.create_campaign()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py create_campaign '{"name": "Operation SteadyRain", "description": "Coordinated ransomware activity", "status": "active", "tlp_marking": "TLP:AMBER"}'
```

---

#### create_feed

Subscribe to a new RSS/Atom/YouTube/podcast feed.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `url` | `str` | Yes | — | Feed URL (e.g., https://krebsonsecurity.com/feed/, https://www.youtube.com/@channel/videos) |
| `title` | `str` | No | `None` | Display title for the feed; auto-detected if not provided |
| `feed_type` | `str` | No | `"rss"` | Feed type: `rss`, `atom`, `youtube`, `podcast` |
| `category` | `str` | No | `None` | Category tag (e.g., "Security News", "Academic") |

**Returns:** Feed object with `id`, `title`, `url`, `feed_type`, `category`, `enabled`, `created_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.create_feed()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py create_feed '{"url": "https://krebsonsecurity.com/feed/", "feed_type": "rss", "category": "News"}'
```

---

#### add_telegram_feed

Subscribe to a Telegram channel feed. Requires server-side Telegram setup and session credentials. Auto-attribution (threat_actor_id / campaign_id) is the killer feature for ransomware leak channels and hacktivist channels that ARE the actor.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `channel` | `str` | Yes | — | Telegram channel username or ID (e.g., "@ransomware_leaks", "@anaraska") |
| `title` | `str` | No | `None` | Display title for the feed |
| `include_media` | `bool` | No | `True` | Download and index media files |
| `extract_forwards` | `bool` | No | `True` | Follow forwarded messages to original source |
| `max_message_age_days` | `int` | No | 30 | Only fetch messages from the last N days |
| `max_messages_per_fetch` | `int` | No | 200 | Limit messages per fetch |
| `fetch_interval_minutes` | `int` | No | 30 | Poll interval in minutes |
| `threat_actor_id` | `str` | No | `None` | Auto-attribute all posts to this threat actor |
| `campaign_id` | `str` | No | `None` | Auto-attribute all posts to this campaign |
| `session_name` | `str` | No | `None` | Telegram session name (if multiple accounts) |
| `category` | `str` | No | `None` | Category tag |

**Returns:** Telegram feed object with `id`, `channel`, `title`, `threat_actor_id`, `campaign_id`, `created_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.add_telegram_feed()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py add_telegram_feed '{"channel": "@ransomware_gang", "threat_actor_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### create_note

Add a note (markdown-enabled) to an entry.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | Yes | — | UUID of the entry |
| `content` | `str` | Yes | — | Note content (supports markdown) |

**Returns:** Note object with `id`, `entry_id`, `content`, `created_at`, `updated_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.create_note()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py create_note '{"entry_id": "550e8400-e29b-41d4-a716-446655440000", "content": "This is a **critical** IOC for Operation X."}'
```

---

#### create_entity_note

Add an analytical note to any intelligence entity (threat actor, malware, CVE, TTP, campaign).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entity_type` | `str` | Yes | — | Entity type: `threat_actor`, `malware`, `cve`, `ttp`, `campaign` |
| `entity_id` | `str` | Yes | — | UUID or identifier of the entity |
| `content` | `str` | Yes | — | Note content (supports markdown) |

**Returns:** Note object with `id`, `entity_type`, `entity_id`, `content`, `created_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.create_entity_note()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py create_entity_note '{"entity_type": "threat_actor", "entity_id": "APT29", "content": "Observed new targeting in financial sector."}'
```

---

#### add_tag

Tag an entry with an existing or new tag.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | Yes | — | UUID of the entry |
| `tag_name` | `str` | Yes | — | Tag name (e.g., "critical", "followup", "verified") |

**Returns:** Tag object with `id`, `name`, and entry's updated `tags` array.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.add_tag()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py add_tag '{"entry_id": "550e8400-e29b-41d4-a716-446655440000", "tag_name": "critical"}'
```

---

#### add_to_campaign

Link an entry or entity to a campaign with an optional role (primary, secondary, related).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `campaign_id` | `str` | Yes | — | UUID of the campaign |
| `entry_id` | `str` | No | `None` | UUID of entry to link (mutually exclusive with entity_type/entity_id) |
| `entity_type` | `str` | No | `None` | Type of entity to link: `ttp`, `cve`, `threat_actor`, `malware` (mutually exclusive with entry_id) |
| `entity_id` | `str` | No | `None` | UUID or identifier of the entity (required if entity_type is set) |
| `role` | `str` | No | `"related"` | Role in campaign: `primary` (central to operation), `secondary` (supporting), `related` (tangentially connected) |

**Returns:** Campaign object with updated linked items.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.add_to_campaign()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py add_to_campaign '{"campaign_id": "550e8400-e29b-41d4-a716-446655440000", "entity_type": "threat_actor", "entity_id": "APT29", "role": "primary"}'
```

---

#### link_entities

Create a relationship between two intelligence entities.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `source_type` | `str` | Yes | — | Type of source entity: `ttp`, `cve`, `threat_actor`, `malware`, `campaign` |
| `source_id` | `str` | Yes | — | UUID or identifier of source entity |
| `target_type` | `str` | Yes | — | Type of target entity: `ttp`, `cve`, `threat_actor`, `malware`, `campaign` |
| `target_id` | `str` | Yes | — | UUID or identifier of target entity |
| `relationship_type` | `str` | Yes | — | Relationship type (e.g., "uses", "exploits", "targets", "related_to") |
| `description` | `str` | No | `None` | Description of the relationship |

**Returns:** Relationship object with `id`, `source_type`, `source_id`, `target_type`, `target_id`, `relationship_type`, `description`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.link_entities()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py link_entities '{"source_type": "threat_actor", "source_id": "APT29", "target_type": "malware", "target_id": "Emotet", "relationship_type": "uses"}'
```

---

#### create_automation_rule

Set up an automation rule with trigger, conditions, and actions.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `name` | `str` | Yes | — | Rule name |
| `trigger_type` | `str` | Yes | — | When to trigger: `new_entry`, `new_entity`, `schedule`, `manual` |
| `actions` | `list[dict]` | Yes | — | List of action objects (e.g., [{"type": "tag", "value": "critical"}]) |
| `description` | `str` | No | `None` | Description |
| `trigger_config` | `dict` | No | `None` | Trigger-specific config (e.g., {"query": "ransomware", "frequency": "daily"} for schedule) |
| `conditions` | `dict` | No | `None` | Conditions (e.g., {"must_match": "all", "rules": [{"field": "entry.tags", "op": "contains", "value": "critical"}]}) |

**Returns:** Automation rule object with `id`, `name`, `trigger_type`, `enabled`, `created_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.create_automation_rule()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py create_automation_rule '{"name": "Tag Ransomware", "trigger_type": "new_entry", "actions": [{"type": "tag", "value": "ransomware"}], "trigger_config": {"query": "ransomware"}}'
```

---

#### create_intel_report

Create an intelligence report from a template with linked entities and entries.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `title` | `str` | Yes | — | Report title |
| `template_type` | `str` | Yes | — | Template: `flash_alert`, `actor_profile`, `campaign_tracker`, `landscape_report`, `custom` |
| `entry_ids` | `list[str]` | No | `None` | UUIDs of source entries |
| `entity_ids` | `dict` | No | `None` | Dictionary mapping entity types to IDs: e.g., {"threat_actor": ["APT29"], "malware": ["Emotet"]} |
| `tlp_marking` | `str` | No | `"TLP:GREEN"` | TLP marking: `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED` |

**Returns:** Report object with `id`, `title`, `template_type`, `tlp_marking`, `status` (draft), `created_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.create_intel_report()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py create_intel_report '{"title": "APT29 Activity Report", "template_type": "actor_profile", "entity_ids": {"threat_actor": ["APT29"]}, "tlp_marking": "TLP:AMBER"}'
```

---

#### update_entity_profile

Update any entity's profile (description, aliases, etc.).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entity_type` | `str` | Yes | — | Entity type: `threat_actor`, `malware`, `cve`, `campaign` |
| `entity_id` | `str` | Yes | — | UUID or identifier of the entity |
| `updates` | `dict` | Yes | — | Dictionary of fields to update (e.g., {"aliases": [...], "description": "..."}) |

**Returns:** Updated entity object.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.update_entity_profile()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py update_entity_profile '{"entity_type": "threat_actor", "entity_id": "APT29", "updates": {"aliases": ["Cozy Bear", "Midnight Blizzard"]}}'
```

---

#### merge_threat_actors

Merge a duplicate threat actor into another. Moves all entries and country links from source → target, unions aliases (source name + aliases are added to the target's aliases), optionally rewrites the description, then deletes the source actor. Use `mode: "shadow"` to log the would-be action without making changes. Always include `reasoning` so the maintenance log can be audited.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `target_id` | `str` | Yes | — | UUID of the surviving actor |
| `source_id` | `str` | Yes | — | UUID of the actor to merge away (deleted at the end) |
| `mode` | `str` | No | `"apply"` | `shadow` (log only, no changes) or `apply` |
| `new_description` | `str` | No | `None` | Replace target description; omit to keep existing |
| `extra_aliases` | `list[str]` | No | `[]` | Additional aliases to add on top of source name + aliases |
| `reasoning` | `str` | No | `None` | Why this merge — recorded in the maintenance log |

**Returns:** Merge result object with `action` (merge), `mode`, `target_id`, `source_id`, `moved_entry_links`, `moved_country_links`, `merged_alias_count`, `log_id`, `applied` (bool).

**Backed by:** `POST /api/tools/execute` → `app.tools.write.merge_threat_actors()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py merge_threat_actors '{"target_id": "550e8400-e29b-41d4-a716-446655440000", "source_id": "660f9511-f3ac-52e5-b827-557766551111", "mode": "shadow", "reasoning": "Same actor: Nobelium is a Microsoft alias for APT29"}'
```

---

#### merge_malware

Merge a duplicate malware family into another. Same semantics as `merge_threat_actors`: moves entry links, unions aliases, optionally rewrites description, deletes the source. Always include `reasoning`.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `target_id` | `str` | Yes | — | UUID of the surviving malware family |
| `source_id` | `str` | Yes | — | UUID of the malware family to merge away |
| `mode` | `str` | No | `"apply"` | `shadow` (log only, no changes) or `apply` |
| `new_description` | `str` | No | `None` | Replace target description; omit to keep existing |
| `extra_aliases` | `list[str]` | No | `[]` | Additional aliases to add |
| `reasoning` | `str` | No | `None` | Why this merge — recorded in the maintenance log |

**Returns:** Merge result object (same shape as `merge_threat_actors`, minus country links).

**Backed by:** `POST /api/tools/execute` → `app.tools.write.merge_malware()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py merge_malware '{"target_id": "550e8400-e29b-41d4-a716-446655440000", "source_id": "660f9511-f3ac-52e5-b827-557766551111", "reasoning": "QakBot and Qbot are the same family"}'
```

---

#### merge_vendors

Merge a duplicate vendor into another. Same semantics as `merge_threat_actors`.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `target_id` | `str` | Yes | — | UUID of the surviving vendor |
| `source_id` | `str` | Yes | — | UUID of the vendor to merge away |
| `mode` | `str` | No | `"apply"` | `shadow` (log only, no changes) or `apply` |
| `new_description` | `str` | No | `None` | Replace target description; omit to keep existing |
| `extra_aliases` | `list[str]` | No | `[]` | Additional aliases to add |
| `reasoning` | `str` | No | `None` | Why this merge — recorded in the maintenance log |

**Returns:** Merge result object (same shape as `merge_malware`).

**Backed by:** `POST /api/tools/execute` → `app.tools.write.merge_vendors()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py merge_vendors '{"target_id": "550e8400-e29b-41d4-a716-446655440000", "source_id": "660f9511-f3ac-52e5-b827-557766551111", "reasoning": "Duplicate: MSFT vs Microsoft"}'
```

---

#### merge_products

Merge a duplicate product into another. Same semantics as `merge_threat_actors`.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `target_id` | `str` | Yes | — | UUID of the surviving product |
| `source_id` | `str` | Yes | — | UUID of the product to merge away |
| `mode` | `str` | No | `"apply"` | `shadow` (log only, no changes) or `apply` |
| `new_description` | `str` | No | `None` | Replace target description; omit to keep existing |
| `extra_aliases` | `list[str]` | No | `[]` | Additional aliases to add |
| `reasoning` | `str` | No | `None` | Why this merge — recorded in the maintenance log |

**Returns:** Merge result object (same shape as `merge_malware`).

**Backed by:** `POST /api/tools/execute` → `app.tools.write.merge_products()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py merge_products '{"target_id": "550e8400-e29b-41d4-a716-446655440000", "source_id": "660f9511-f3ac-52e5-b827-557766551111", "reasoning": "Duplicate: Exchange Server vs Microsoft Exchange"}'
```

---

#### merge_tools

Merge a duplicate tool into another. Same semantics as `merge_vendors`.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `target_id` | `str` | Yes | — | UUID of the surviving tool |
| `source_id` | `str` | Yes | — | UUID of the tool to merge away |
| `mode` | `str` | No | `"apply"` | `shadow` (log only, no changes) or `apply` |
| `new_description` | `str` | No | `None` | Replace target description; omit to keep existing |
| `extra_aliases` | `list[str]` | No | `[]` | Additional aliases to add |
| `reasoning` | `str` | No | `None` | Why this merge — recorded in the maintenance log |

**Returns:** Merge result object (same shape as `merge_malware`).

**Backed by:** `POST /api/tools/execute` → `app.tools.write.merge_tools()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py merge_tools '{"target_id": "550e8400-e29b-41d4-a716-446655440000", "source_id": "660f9511-f3ac-52e5-b827-557766551111", "reasoning": "Cobalt Strike Beacon is a component of Cobalt Strike"}'
```

---

#### reclassify_entity

Move an entity from one type to another (e.g., `malware` → `tool`) when it was filed under the wrong type. If `target_id` is supplied, the source merges into that existing entity; otherwise a new entity is created in `target_type` by copying name/aliases/description. Type-specific fields (motivation, malware_type, tool_type, etc.) are **not** carried across — fix them afterward with `update_entity_profile`. Use `mode: "shadow"` to log without acting; always include `reasoning`.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `source_type` | `str` | Yes | — | Current type: `threat_actor`, `malware`, `vendor`, `product`, `tool` |
| `source_id` | `str` | Yes | — | UUID of the entity being moved |
| `target_type` | `str` | Yes | — | Destination type (same enum as `source_type`) |
| `target_id` | `str` | No | `None` | Existing target entity to merge into; omit to create a new one |
| `mode` | `str` | No | `"apply"` | `shadow` (log only, no changes) or `apply` |
| `new_description` | `str` | No | `None` | Replace description on the target |
| `extra_aliases` | `list[str]` | No | `[]` | Additional aliases to add |
| `reasoning` | `str` | No | `None` | Why this reclassification — recorded in the maintenance log |

**Returns:** Reclassify result object with `action` (reclassify), `mode`, `source_type`, `source_id`, `target_type`, `target_id`, `target_created` (bool — true if a new entity was created), `moved_entry_links`, `merged_alias_count`, `log_id`, `applied` (bool).

**Backed by:** `POST /api/tools/execute` → `app.tools.write.reclassify_entity()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py reclassify_entity '{"source_type": "malware", "source_id": "550e8400-e29b-41d4-a716-446655440000", "target_type": "tool", "reasoning": "Mimikatz is an offensive tool, not malware"}'
```

---

#### create_requirement

Create a new Priority Intelligence Requirement (PIR).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `title` | `str` | Yes | — | PIR title |
| `keywords` | `list[str]` | Yes | — | List of keywords to auto-match against entries |
| `description` | `str` | No | `None` | Description |
| `priority` | `str` | No | `"medium"` | Priority: `critical`, `high`, `medium`, `low` |
| `category` | `str` | No | `None` | Category: `strategic`, `operational`, `tactical`, `technical` |
| `auto_match` | `bool` | No | `True` | Auto-match new entries against keywords |

**Returns:** Requirement object with `id`, `title`, `keywords`, `priority`, `category`, `status` (active), `created_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.create_requirement()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py create_requirement '{"title": "Ransomware Activity", "keywords": ["ransomware", "extortion", "double-extortion"], "priority": "high", "category": "operational"}'
```

---

#### update_requirement

Update an existing intelligence requirement (keywords, status, priority, etc.).

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `requirement_id` | `str` | Yes | — | UUID of the requirement |
| `updates` | `dict` | Yes | — | Dictionary of fields to update (e.g., {"keywords": [...], "status": "fulfilled"}) |

**Returns:** Updated requirement object.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.update_requirement()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py update_requirement '{"requirement_id": "550e8400-e29b-41d4-a716-446655440000", "updates": {"status": "fulfilled"}}'
```

---

#### publish_report

Publish an intelligence report — saves current version and sets status to published.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `report_id` | `str` | Yes | — | UUID of the report |

**Returns:** Report object with `status` set to "published", `published_at` timestamp.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.publish_report()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py publish_report '{"report_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

#### generate_full_report

Generate an AI-powered intelligence report from source entries.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `title` | `str` | Yes | — | Report title |
| `template_type` | `str` | Yes | — | Template: `flash_alert`, `actor_profile`, `campaign_tracker`, `landscape_report`, `custom` |
| `entry_ids` | `list[str]` | Yes | — | UUIDs of source entries to analyze |
| `focus` | `str` | No | `None` | Focus area for the AI (e.g., "detection engineering", "IOC extraction") |
| `tlp_marking` | `str` | No | `"TLP:GREEN"` | TLP marking |

**Returns:** Report object with AI-generated content, `id`, `title`, `content`, `status` (published), `generated_at`.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.generate_full_report()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py generate_full_report '{"title": "Ransomware Threat Report", "template_type": "landscape_report", "entry_ids": ["550e8400-e29b-41d4-a716-446655440000", "660e8400-e29b-41d4-a716-446655440000"], "focus": "detection engineering"}'
```

---

#### generate_campaign_report

Generate an intelligence report from a campaign's linked entries and entities.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `campaign_id` | `str` | Yes | — | UUID of the campaign |
| `template_type` | `str` | No | `"campaign_tracker"` | Template: `flash_alert`, `actor_profile`, `campaign_tracker`, `landscape_report`, `custom` |
| `title` | `str` | No | `None` | Custom title; auto-generated if not provided |
| `tlp_marking` | `str` | No | `"TLP:GREEN"` | TLP marking |

**Returns:** Report object with campaign details, timeline, intelligence, and recommendations.

**Backed by:** `POST /api/tools/execute` → `app.tools.write.generate_campaign_report()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py generate_campaign_report '{"campaign_id": "550e8400-e29b-41d4-a716-446655440000", "template_type": "campaign_tracker", "tlp_marking": "TLP:AMBER"}'
```

---

#### export_report

Export an intelligence report in markdown or HTML format.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `report_id` | `str` | Yes | — | UUID of the report |
| `format` | `str` | Yes | — | Export format: `markdown` or `html` |

**Returns:** String containing the formatted report content.

**Backed by:** `POST /api/tools/execute` → `app.tools.export.export_report()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py export_report '{"report_id": "550e8400-e29b-41d4-a716-446655440000", "format": "markdown"}'
```

---

### Export (1 tool)

#### export_attack_layer

Export MITRE ATT&CK Navigator layer JSON for visualization in the official Navigator tool.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entry_id` | `str` | No | `None` | Scope to a specific entry; if None, exports system-wide coverage |
| `title` | `str` | No | `"IntelFeed ATT&CK Layer"` | Layer title |

**Returns:** ATT&CK Navigator v4.3 layer JSON (can be imported directly into https://mitre-attack.github.io/attack-navigator/).

**Backed by:** `POST /api/tools/execute` → `app.tools.export.export_attack_layer()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py export_attack_layer '{"entry_id": "550e8400-e29b-41d4-a716-446655440000", "title": "This Article'\''s ATT&CK Coverage"}'
```

---

### Delete (1 tool)

#### delete_entity

Delete an entity. Requires user confirmation for safety. First call returns a confirmation prompt — present it to the user. Only call again with the confirmation_token after the user explicitly approves.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `entity_type` | `str` | Yes | — | Entity type to delete: `feed`, `entry`, `note`, `detection_rule`, `campaign`, `automation_rule`, `intelligence_requirement`, `intel_report`, `ttp`, `threat_actor`, `malware`, `tag`, `cve`, `country`, `tool`, `vendor`, `product`, `mitigation`, `observable` |
| `entity_id` | `str` | Yes | — | UUID or identifier of the entity |
| `confirmation_token` | `str` | No | `None` | Confirmation token from first call; required to actually delete |

**Returns (first call):** Object with `confirmation_required` (true), `message` (prompt for user), `confirmation_token` (string to pass back).

**Returns (second call with token):** Object with `deleted` (true), `entity_type`, `entity_id`.

**Backed by:** `POST /api/tools/execute` → `app.tools.delete.delete_entity()`

**Example (first call):**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py delete_entity '{"entity_type": "campaign", "entity_id": "550e8400-e29b-41d4-a716-446655440000"}'
# Returns: {"confirmation_required": true, "message": "Are you sure...", "confirmation_token": "abc123"}
```

**Example (second call, after user confirms):**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py delete_entity '{"entity_type": "campaign", "entity_id": "550e8400-e29b-41d4-a716-446655440000", "confirmation_token": "abc123"}'
# Returns: {"deleted": true, "entity_type": "campaign", "entity_id": "550e8400-e29b-41d4-a716-446655440000"}
```

---

### Telegram (2 tools)

#### list_telegram_feeds

List Telegram channel feeds with their adapter config.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `limit` | `int` | No | 50 | Max feeds to return |

**Returns:** Array of Telegram feed objects with `id`, `channel`, `title`, `threat_actor_id`, `campaign_id`, `enabled`, `last_fetched`, `message_count`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.list_telegram_feeds()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py list_telegram_feeds '{"limit": 20}'
```

---

#### discover_telegram_channels

List every Telegram channel the IntelFeed bootstrap account is joined to. The `is_subscribed` flag shows which ones are already ingested as feeds. Useful for finding channels you joined in Telegram but haven't added to IntelFeed yet.

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `session_name` | `str` | No | `""` | Telegram session name (if multiple accounts configured) |
| `only_unsubscribed` | `bool` | No | `False` | Return only channels not yet subscribed as feeds |

**Returns:** Array of channel objects with `channel_name`, `channel_id`, `is_subscribed` (bool), `member_count`, `description`.

**Backed by:** `POST /api/tools/execute` → `app.tools.read.discover_telegram_channels()`

**Example:**
```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py discover_telegram_channels '{"only_unsubscribed": true}'
```

---

### Extended Tool Surface

The 2026-08 registry expansion added 78 tools in five backend modules; Story Threads, the observables ledger, CWE, the server-side Priority Queue and the in-app docs added nine more over September, bringing the registry to **170**. They follow the same invocation pattern as everything above; run `--help-tool <name>` for parameters and defaults. Grouped by module (`backend/app/tools/`):

**Ledger, queue & catalog reads (`read.py`, 4 tools)** — the September additions to the largest module:
`get_observable` (one IOC ledger row by UUID or value — kind, role, current/base confidence with decay state, sighting count, the judgment door that captured it with its evidence sentence, first/last seen, recent sighting articles; defanged input like `evil[.]com` or `hxxps://` is normalised), `search_observables` (filter the ledger by substring, kind, role, lifecycle status or capture door, sorted by last sighting), `get_cwe` (a MITRE CWE with its abstraction rung, parent and lineage, mapping guidance, catalog mitigations and detection methods, direct and subtree CVE counts, KEV count, linked articles), `get_priority_queue` (the reading queue exactly as the Priority Queue page shows it — radar-clearing unread entries with story threads folded in as single rows; prefer it over `get_triage_queue`, the older heuristic that does not fold stories)

**Documentation (`docs.py`, 3 tools)** — the copilot's route into these very docs:
`list_documentation_pages` (slug, title, section and one-line summary for every page shipped with the deployment), `search_documentation` (full-text with excerpts, to find which page covers a topic), `get_documentation_page` (one page in full as markdown; the slug is the path under `docs/` without `.md`, e.g. `architecture` or `diagrams/entries-lifecycle` — cite it back as a `/documentation/<slug>` link)


**Story Threads (`threads.py`, 2 tools)** — an unfolding story as one object rather than the twenty-three articles that reported it:
`get_story_threads` (open threads with their outlets, counts, key entities and best unread score), `get_story_thread` (one thread's spine, members, yield and nearest neighbours — open it in the UI at `/priority-queue?thread=<slug>`)


**Curation (`curation.py`, 14 tools)** — entry↔entity link (edge) and relationship management, extraction provenance, hygiene:
`list_entity_links`, `get_entity_link_stats`, `unlink_entity_from_entry`, `bulk_unlink_entities`, `report_false_positive`, `list_entity_relationships`, `confirm_relationship`, `reject_relationship`, `delete_relationship`, `get_extraction_stats`, `list_extraction_entities`, `confirm_extraction_entities`, `get_hygiene_stats`, `get_hygiene_feed`

**Feeds & Automation (`feeds_automation.py`, 20 tools)** — feed/category CRUD, automation rule lifecycle, webhook presets, notes, campaign updates:
`update_feed`, `delete_feed`, `refresh_feed`, `list_categories`, `create_category`, `update_automation_rule`, `toggle_automation_rule`, `delete_automation_rule`, `list_webhook_presets`, `create_webhook_preset`, `delete_webhook_preset`, `list_notes`, `update_note`, `delete_note`, `list_entity_notes`, `update_entity_note`, `delete_entity_note`, `update_campaign`, `delete_campaign`, `remove_from_campaign`

**Landscape (`landscape.py`, 12 tools)** — watchlist, ransomware victim tracker, stack exposure, glossary:
`list_watches`, `watch_entity`, `unwatch_entity`, `get_ransomware_disclosures`, `get_ransomware_stats`, `get_ransomware_victim`, `get_ransomware_group_victims`, `get_stack_exposure`, `list_glossary_terms`, `create_glossary_term`, `delete_glossary_term`, `detect_glossary_terms`

**Reader Operations (`reader_ops.py`, 16 tools)** — entry state, similar/story views, translation, daily summary, URL ingest, share links, saved searches:
`mark_entry_read`, `star_entry`, `bookmark_entry`, `bulk_entry_action`, `mark_all_read`, `get_similar_entries` (embedding-backed, keyword fallback), `get_entry_story`, `translate_entry`, `get_daily_summary`, `ingest_url`, `create_share_link`, `get_share_link`, `revoke_share_link`, `list_saved_searches`, `create_saved_search`, `delete_saved_search`

**Workspace (`workspace.py`, 16 tools)** — detection rule lifecycle/versions, intel report management, requirement matches:
`get_detection_rule`, `update_detection_rule`, `delete_detection_rule`, `set_detection_rule_status`, `convert_detection_rule`, `get_detection_rule_versions`, `rollback_detection_rule`, `list_intel_reports`, `get_intel_report`, `update_intel_report`, `delete_intel_report`, `archive_intel_report`, `delete_requirement`, `fulfill_requirement`, `add_requirement_match`, `remove_requirement_match`

---

## Common Workflows

### Workflow 1: "Find recent entries about X and summarize"

```bash
# 1. Search for entries
RESULT=$(python3 intelfeed-skill/scripts/intelfeed_cli.py search_entries \
  '{"query": "ransomware", "limit": 5, "sort": "newest"}')

# 2. For each result, get full entry details and extract intelligence
for ENTRY_ID in $(echo "$RESULT" | jq -r '.result[].id'); do
  python3 intelfeed-skill/scripts/intelfeed_cli.py get_entry "{\"entry_id\": \"$ENTRY_ID\"}"
  python3 intelfeed-skill/scripts/intelfeed_cli.py extract_ttps "{\"entry_id\": \"$ENTRY_ID\", \"use_ai\": true}"
done

# 3. Run an AI task to generate a summary
python3 intelfeed-skill/scripts/intelfeed_cli.py run_ai_task \
  '{"task_name": "summary", "entry_id": "<entry_id>"}'
```

### Workflow 2: "Look up an actor and pivot to malware"

```bash
# 1. Search for the threat actor
ACTOR=$(python3 intelfeed-skill/scripts/intelfeed_cli.py search_entities \
  '{"query": "APT29"}')

# Extract actor ID from results
ACTOR_ID=$(echo "$ACTOR" | jq -r '.result[] | select(.type == "threat_actor") | .id' | head -1)

# 2. Get full actor profile
python3 intelfeed-skill/scripts/intelfeed_cli.py get_threat_actor \
  "{\"actor_id\": \"$ACTOR_ID\"}"

# 3. Pivot to find related malware
python3 intelfeed-skill/scripts/intelfeed_cli.py pivot_entity \
  "{\"entity_type\": \"threat_actor\", \"entity_id\": \"$ACTOR_ID\"}"

# 4. Build a graph of relationships
python3 intelfeed-skill/scripts/intelfeed_cli.py get_entity_graph \
  "{\"entity_type\": \"threat_actor\", \"entity_id\": \"$ACTOR_ID\", \"depth\": 2}"
```

### Workflow 3: "Extract TTPs from an article and generate detection rules"

```bash
# 1. Get the entry
python3 intelfeed-skill/scripts/intelfeed_cli.py get_entry \
  '{"entry_id": "<entry_id>"}'

# 2. Extract TTPs with AI
python3 intelfeed-skill/scripts/intelfeed_cli.py extract_ttps \
  '{"entry_id": "<entry_id>", "use_ai": true}'

# 3. Generate detection rules in multiple formats
python3 intelfeed-skill/scripts/intelfeed_cli.py generate_detection_rules \
  '{"entry_id": "<entry_id>", "rule_types": ["sigma", "splunk_spl", "elastic_ql"]}'

# 4. Validate each rule
python3 intelfeed-skill/scripts/intelfeed_cli.py validate_detection_rule \
  '{"rule_type": "sigma", "rule_content": "<rule_content>"}'

# 5. Save rule to library
python3 intelfeed-skill/scripts/intelfeed_cli.py create_detection_rule \
  '{"title": "Detect X", "rule_type": "sigma", "rule_content": "<rule>", "entry_id": "<entry_id>"}'
```

### Workflow 4: "Audit detection coverage for a campaign"

```bash
# 1. Get the campaign
python3 intelfeed-skill/scripts/intelfeed_cli.py get_campaign \
  '{"campaign_id": "<campaign_id>"}'

# 2. Find detection gaps
python3 intelfeed-skill/scripts/intelfeed_cli.py get_campaign_detection_gaps \
  '{"campaign_id": "<campaign_id>"}'

# 3. For each uncovered TTP, understand the technique
for TTP_ID in $(echo "$GAPS" | jq -r '.uncovered_ttps[].id'); do
  python3 intelfeed-skill/scripts/intelfeed_cli.py get_ttp \
    "{\"ttp_id\": \"$TTP_ID\"}"
done

# 4. Generate rules for the campaign as a whole
python3 intelfeed-skill/scripts/intelfeed_cli.py get_campaign_timeline \
  '{"campaign_id": "<campaign_id>"}' | jq -r '.[] | .id' | xargs -I {} \
  python3 intelfeed-skill/scripts/intelfeed_cli.py generate_detection_rules \
    "{\"entry_id\": \"{}\", \"rule_types\": [\"sigma\", \"splunk_spl\"]}"
```

### Workflow 5: "Set up continuous monitoring for a threat actor"

```bash
# 1. Create a Priority Intelligence Requirement
python3 intelfeed-skill/scripts/intelfeed_cli.py create_requirement \
  '{"title": "APT29 Activity", "keywords": ["APT29", "Cozy Bear", "Midnight Blizzard"], "priority": "critical"}'

# 2. Create an automation rule to tag entries matching the PIR
python3 intelfeed-skill/scripts/intelfeed_cli.py create_automation_rule \
  '{"name": "Tag APT29 Mentions", "trigger_type": "new_entry", "trigger_config": {"query": "APT29"}, "actions": [{"type": "tag", "value": "apt29-monitor"}]}'

# 3. Optionally set up extraction automation
python3 intelfeed-skill/scripts/intelfeed_cli.py create_automation_rule \
  '{"name": "Extract TTPs from APT29 articles", "trigger_type": "new_entry", "trigger_config": {"query": "APT29"}, "actions": [{"type": "extract_ttps", "use_ai": true}]}'

# 4. Monitor coverage gaps
python3 intelfeed-skill/scripts/intelfeed_cli.py check_detection_gaps
```

---

## Error Handling & Troubleshooting

### Auth Failures (401)

**Symptoms:** Error message "API returned 401"

**Causes:**
- Missing or incorrect `INTELFEED_USERNAME` or `INTELFEED_PASSWORD`
- Credentials have been revoked
- Token refresh failed

**Solution:**
1. Verify environment variables are set correctly:
   ```bash
   echo "$INTELFEED_USERNAME"
   echo "$INTELFEED_PASSWORD"
   ```
2. Check with the admin that your account is active
3. Try logging in via the web UI to confirm credentials work

### Connection Errors

**Symptoms:** Error message "Connection refused" or "Name or service not known"

**Causes:**
- `INTELFEED_API_URL` is incorrect or unreachable
- The Docker stack is not running
- Network connectivity issue

**Solution:**
1. Verify `INTELFEED_API_URL` is reachable:
   ```bash
   curl -I "$INTELFEED_API_URL/healthz"
   ```
2. Check Docker stack status:
   ```bash
   docker compose -f docker-compose.dev.yml ps
   ```
3. Start the stack if needed:
   ```bash
   docker compose -f docker-compose.dev.yml up -d
   ```

### Unknown Tool Error

**Symptoms:** "Error: Unknown tool 'tool_name'"

**Causes:**
- Typo in tool name
- Tool doesn't exist in your version of the CLI
- Lite CLI doesn't have write/delete operations

**Solution:**
1. Check tool name spelling:
   ```bash
   python3 intelfeed-skill/scripts/intelfeed_cli.py --list-tools | grep -i partial_name
   ```
2. Use the correct skill/CLI for the operation:
   - Write operations require **full CLI** (`intelfeed-skill`)
   - Read-only? Both **lite and full CLI** work
3. Verify you're using the right script path

### JSON Argument Errors

**Symptoms:** "Invalid JSON for tool"

**Causes:**
- Unescaped quotes in JSON string
- Missing curly braces
- Mismatched brackets/braces

**Solution:**
1. Test JSON syntax:
   ```bash
   echo '{"query": "test"}' | python3 -m json.tool
   ```
2. Use proper escaping in shell:
   ```bash
   # WRONG
   python3 intelfeed_cli.py search_entries '{"query": "hello "world""}'

   # RIGHT
   python3 intelfeed_cli.py search_entries '{"query": "hello \"world\""}'
   ```
3. Use `--help-tool` to see example format:
   ```bash
   python3 intelfeed_cli.py --help-tool search_entries
   ```

### Empty or Sparse Results

**Symptoms:** Search returns no results, or entity has no articles linked

**Causes:**
- Data hasn't been ingested yet (new feed, new feature)
- Entity extraction hasn't run
- Search query is too specific

**Solution:**
1. For search: Try broader queries or alternative names:
   ```bash
   python3 intelfeed-skill/scripts/intelfeed_cli.py search_entities \
     '{"query": "APT29"}' # or "Cozy Bear", "Midnight Blizzard"
   ```
2. For entries: Check if extraction has been run:
   ```bash
   python3 intelfeed-skill/scripts/intelfeed_cli.py get_entry '{"entry_id": "<id>"}'
   # Look for ttps, cves, threat_actors, malware arrays
   ```
3. Run extraction manually:
   ```bash
   python3 intelfeed-skill/scripts/intelfeed_cli.py extract_ttps \
     '{"entry_id": "<id>", "use_ai": true}'
   ```
4. Check dashboard stats:
   ```bash
   python3 intelfeed-skill/scripts/intelfeed_cli.py get_dashboard_stats
   ```

### Timeout Errors

**Symptoms:** "Request timeout" or command hangs

**Causes:**
- Large result set (1000+ entries)
- AI extraction task is slow
- Network latency

**Solution:**
1. Reduce batch size with `limit`:
   ```bash
   python3 intelfeed-skill/scripts/intelfeed_cli.py search_entries \
     '{"query": "ransomware", "limit": 10}'
   ```
2. For AI tasks, be patient (can take 10-30s):
   ```bash
   # This might take a while
   python3 intelfeed-skill/scripts/intelfeed_cli.py extract_threat_actors \
     '{"entry_id": "<id>"}'
   ```
3. Run separately instead of batching:
   ```bash
   # SLOW (if each task is slow)
   python3 intelfeed-skill/scripts/intelfeed_cli.py \
     extract_ttps '{"entry_id": "<id1>"}' \
     extract_ttps '{"entry_id": "<id2>"}' \
     extract_ttps '{"entry_id": "<id3>"}'

   # FASTER (run independently, check status later)
   for id in id1 id2 id3; do
     python3 intelfeed-skill/scripts/intelfeed_cli.py \
       extract_ttps "{\"entry_id\": \"$id\"}" &
   done
   wait
   ```

---

## Extending the CLI

### Adding a New Tool

The CLI tools are **implemented on the backend** in `backend/app/tools/` and executed via `/api/tools/execute`. The CLI script keeps its own local `TOOLS` dict that mirrors the backend registry — and it **validates tool names against this local dict before calling the API**, so a backend-only tool is rejected with "Unknown tool" until it's also added to the CLI script.

To add a new tool:

1. **Implement the tool in the backend** (`backend/app/tools/<category>.py`):

```python
# backend/app/tools/my_category.py
from app.tools import _tool

@_tool(
    name="my_new_tool",
    description="What this tool does",
    input_schema={
        "properties": {
            "param1": {"type": "string"},
            "param2": {"type": "integer", "default": 10},
        },
        "required": ["param1"],
    },
    mutating=True,  # only if the tool creates/updates/deletes state; defaults to
                    # True in write.py/delete.py, False elsewhere
)
async def my_new_tool(db: AsyncSession, user_id: UUID, param1: str, param2: int = 10):
    # Implementation
    return {
        "result": "success",
        "data": [...]
    }
```

2. **Import the module** in `backend/app/tools/__init__.py`:

```python
from app.tools import my_category  # noqa: F401, E402
```

3. **Regenerate the CLI scripts** — run `scripts/dev/sync_skill_clis.py` against a running stack (or `--from-file registry.json`). It rewrites the `TOOLS` dict in both `intelfeed-skill/scripts/intelfeed_cli.py` and `intelfeed-lite-skill/scripts/intelfeed_cli.py` from the backend registry; the lite CLI automatically gets every non-`mutating` tool minus the script's `LITE_EXCLUDE` set. The CLI rejects tool names not present in its local `TOOLS` dict, so this step is required before the tool is callable. `--check` mode reports drift without changing anything.

4. **If the tool mutates state**, mark it `mutating=True` in the decorator (or place it in `write.py`/`delete.py`). The regeneration in step 3 then also rewrites the full CLI's `WRITE_TOOLS` frozenset so [read-only mode](#read-only-mode) blocks it — no hand edit needed. A registry change without a regen fails `test_tool_registry_sync.py`.

5. **Run the drift guards**: `backend/tests/test_tool_registry_sync.py` pins schema enums (entity types, rule formats, TLP, triggers, adapters, relationship verbs) to their canonical sources and checks every tool's handler signature against its schema.

6. **Update documentation**:
   - Add the tool to this reference (cli-reference.md)
   - Update the SKILL.md files in `intelfeed-skill/` and/or `intelfeed-lite-skill/`

### Keeping CLI in Sync with Backend

The CLI scripts mirror the backend's tool registry, and the mirror is **load-bearing**: `parse_tool_calls()` validates every requested tool name against the local `TOOLS` dict and exits with "Unknown tool" for anything missing. If you add a tool to the backend:

- The backend will accept it via `/api/tools/execute`, but the **CLI cannot call it** until its definition is regenerated into the script
- The local definitions also drive `--list-tools` and `--help-tool`
- The full CLI's `WRITE_TOOLS` denylist for read-only mode enforcement is regenerated in the same pass (registry `mutating` flags + the script's `EXTRA_WRITE_TOOLS`)

The mirror is not maintained by hand. `scripts/dev/sync_skill_clis.py` makes the backend registry the single source of truth:

```bash
# Regenerate both CLIs from the live registry (stack running, creds in env)
INTELFEED_API_URL=http://localhost:8000 python3 scripts/dev/sync_skill_clis.py

# Report drift without changing anything (exit 1 if out of sync)
python3 scripts/dev/sync_skill_clis.py --check

# Regenerate from a saved registry dump instead of the API
python3 scripts/dev/sync_skill_clis.py --from-file registry.json
```

The script rewrites the `TOOLS: dict[str, dict] = {...}` block in each CLI and the `WRITE_TOOLS` frozenset in the full CLI, leaving the rest of each file (auth, batching, read-only gating logic) untouched.

---

## Conclusion

The IntelFeed CLI is a powerful, lightweight tool for interacting with the platform. Start with `--list-tools` to explore, use `--help-tool <name>` for specific details, and refer to the Common Workflows section for real-world usage patterns.

For questions, refer to the [main architecture documentation](../docs/architecture.md) or check the backend API routes in `backend/app/api/`.

