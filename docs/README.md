# IntelFeed Documentation

The index of every IntelFeed doc. Use it to find the right page, whether you want to use the app, run it, or change its code.

**If you want to use the app, start with the [user guide](guide/README.md).** Everything after it is reference for operators and developers.

For a project overview and quickstart, see [`../readme.md`](../readme.md). To install on a server, see [`../setup.md`](../setup.md). Short repo conventions are in [`../CLAUDE.md`](../CLAUDE.md).

---

## For users

- **[guide/](guide/README.md)** — The user guide: getting started, reading and triage, search, entities, the Priority Queue, the workbench, detection rules, campaigns and reports, automation and the copilot.
- **[query-language.md](query-language.md)** — The search query syntax used by the search bar, command palette and saved searches.
- **[cli-reference.md](cli-reference.md)** — The `intelfeed_cli.py` tool: 191 tools in the full CLI and 95 in the read-only lite CLI, with arguments, results and examples.
- **[../intelfeed-mcp/README.md](../intelfeed-mcp/README.md)** — The MCP server for local models (LM Studio and other MCP clients). It offers the same tools behind nine fixed tools, loads task guides on demand and keeps results small to fit a small context window.
- **[android-app.md](android-app.md)** — The Android app: where to download it, what it does, and how it is built, signed and released.

## For operators

- **[operations.md](operations.md)** — Running in production: the dev and prod compose stacks, Caddy and TLS, security, logs and metrics, backup and restore, updates, scaling and troubleshooting.
- **[public-read-only-mode.md](public-read-only-mode.md)** — The admin switch that lets anyone browse without an account: what visitors see, what stays private, how the server enforces it, and the request limits.
- **[integrations.md](integrations.md)** — Recipes for connecting IntelFeed to Slack, Discord, Teams, SIEMs (Splunk, Elastic, Sentinel), MISP and GitHub, and for setting up AI providers and enrichment sources.

## For contributors

- **[contributing.md](contributing.md)** — Local setup (full Docker or hybrid), backend and frontend workflow, tests, CI, migrations, code style and debugging.
- **[architecture.md](architecture.md)** — How the system fits together, with a tour of each major part. Read this first when learning the code.

## Subsystem deep dives (developer reference)

| Doc | Covers |
|---|---|
| **[entries.md](entries.md)** | The life of one entry, from feed poll to linked intelligence. |
| **[entity-profiles.md](entity-profiles.md)** | How entity profile pages (actors, malware, CVEs, TTPs, tools, vendors, products, countries and more) are built and where their data comes from. |
| **[adapters.md](adapters.md)** | The feed adapters (RSS, YouTube, podcasts, Reddit, GitHub, NVD, Mastodon, Bluesky, Telegram, ransomware.live, web scraper), the polling loop, dedup, OPML, manual ingest, and how to add an adapter. |
| **[intelligence-engine.md](intelligence-engine.md)** | The autolinker, correlation engine and relationship strength, ATT&CK, CVE and TTP pipelines, and reporting and export. |
| **[detection-engineering.md](detection-engineering.md)** | Detection rules: extraction from articles, validation in 9 languages, the rule library, the workbench, coverage, ATT&CK Navigator export, telemetry sources and mitigations. |
| **[automation-ai-enrichment.md](automation-ai-enrichment.md)** | Automation rules (triggers, conditions, actions), the AI provider system, prompts, AI task assignments and the enrichment pipeline. |
| **[engine.md](engine.md)** | Pipeline stages and plans (feed, then category, then global), signal-engine priority scoring, Radar triage, and the Settings → Engine console. |
| **[engine-settings.md](engine-settings.md)** | Every runtime setting: what it does, its default, where it is edited, which scheduled job it drives, and which settings are env-only. |
| **[copilot.md](copilot.md)** | The AI copilot: streaming with tool traces, the `ai`-queue worker, read-only tools, confirmed writes, saved and shared conversations, Claude sign-in and cost tracking. |
| **[workers-search-dashboards.md](workers-search-dashboards.md)** | The Celery workers and schedule, Meilisearch indexing and queries, and the widgets on the workbench Dashboard. |
| **[frontend.md](frontend.md)** | The React app: routing, layouts, Zustand stores, TanStack Query, the Axios client, theming, components and testing. |
| **[api-reference.md](api-reference.md)** | The REST API: every router and endpoint, auth, errors, pagination, rate limits and middleware. |
| **[observables.md](observables.md)** | The IOC ledger: kinds and validators, which sources can create an observable (and why regex alone never does), shadow and capture modes, corroboration, attribution, publishing and enrichment. |
| **[story-threads.md](story-threads.md)** | Entry embeddings, grouping articles into story threads, the spine, where threads appear, and the tuning settings. |
| **[data-model.md](data-model.md)** | The database: ER diagram, tables and junction tables, enums, indexes, JSONB columns and migration conventions. |

## How to navigate

- **New analyst:** guide/README.md → guide/getting-started.md → query-language.md.
- **New contributor:** architecture.md → contributing.md → frontend.md or api-reference.md → the subsystem doc you need.
- **Connecting another tool:** integrations.md → api-reference.md or cli-reference.md.
- **Adding a feed source:** adapters.md.
- **Adding an enrichment source or AI task:** automation-ai-enrichment.md.
- **Tuning extraction:** intelligence-engine.md.
- **What a setting does:** engine-settings.md.
- **Threads grouping the wrong articles:** story-threads.md.
- **Building a widget:** workers-search-dashboards.md (widgets section) and frontend.md.
- **Writing a migration:** data-model.md (migrations section) and contributing.md.
- **Running in production:** operations.md and [`../setup.md`](../setup.md).

## Conventions

- **Code references** use `path/to/file.py:line` (for example `backend/app/intelligence/autolinker.py:101`). Line numbers move when code changes, so after a refactor run `python3 scripts/dev/check_doc_refs.py` (`--fix` repairs the clear cases) and `python3 scripts/dev/check_doc_links.py` (broken links and anchors). CI runs both.
- **Link, don't repeat.** If the same explanation would appear in two docs, keep it in one and link to it.
- **Dates are absolute** (`2026-05-03`), never "last week".
- **Diagrams** are Mermaid, one per file under [`diagrams/`](diagrams/). Docs link to them instead of embedding them.
