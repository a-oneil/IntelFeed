# IntelFeed Documentation

Documentation for IntelFeed — a self-hosted, security-focused RSS aggregator and threat intelligence platform.

**If you are here to use the app, start with the [user guide](guide/README.md).** Everything below it is developer and operator reference.

For a top-level project overview and quickstart, see [`../readme.md`](../readme.md). For deployment walkthroughs, see [`../setup.md`](../setup.md). Repo-wide conventions live in [`../CLAUDE.md`](../CLAUDE.md).

---

## For users

- **[guide/](guide/README.md)** — **The user guide.** How to actually work in IntelFeed: getting started, reading and triage, search, entity profiles, the Priority Queue, the workbench, detection rules, campaigns and reports, automation and the copilot. Start here if you want to *use* IntelFeed rather than build it.
- **[query-language.md](query-language.md)** — Full reference for the search query syntax used across the unified search bar, command palette, query builder, and saved searches.
- **[cli-reference.md](cli-reference.md)** — Reference for the `intelfeed_cli.py` tool — all 180 tools in the full CLI (81 in the read-only lite variant), with args, returns, and examples.
- **[../intelfeed-mcp/README.md](../intelfeed-mcp/README.md)** — The MCP server for local models (LM Studio and other MCP clients): the same tool registry behind nine fixed tools, on-demand skills and size-capped results, so it fits a small context window.
- **[android-app.md](android-app.md)** — The native Android client: where to download the APK, what the app covers, how it is built, signed and released from CI, and how its source is synced into `android/`.

## For operators

- **[operations.md](operations.md)** — Deployment (dev vs prod Docker Compose, Caddy auto-TLS), security posture, observability, backup/restore, scaling, troubleshooting.
- **[integrations.md](integrations.md)** — Copy-paste recipes for hooking IntelFeed into Slack, Discord, Teams, SIEMs (Splunk/Elastic/Sentinel), MISP, GitHub, and configuring AI providers / enrichment sources.

## For contributors

- **[contributing.md](contributing.md)** — Local dev setup (Docker, hybrid, native), backend & frontend workflows, tests, CI, migrations, code style, debugging.
- **[architecture.md](architecture.md)** — System overview and a tour of every major subsystem. Read this first when learning the codebase.

## Subsystem deep dives (developer reference)

| Doc | Covers |
|---|---|
| **[entries.md](entries.md)** | End-to-end lifecycle of a single entry, from feed poll to correlated intelligence. |
| **[entity-profiles.md](entity-profiles.md)** | How entity profile pages (actors, malware, CVEs, vendors, products, countries) are assembled. |
| **[adapters.md](adapters.md)** | RSS / YouTube / podcast / Reddit / GitHub / NVD / Mastodon / Bluesky / Telegram / web-scraper adapters, the polling loop, dedup, conditional GET, OPML, and how to add a new adapter. |
| **[intelligence-engine.md](intelligence-engine.md)** | Aho-Corasick autolinker, vocab versioning, correlation engine, proximity scoring and relationship strength, MITRE ATT&CK / CVE / TTP pipelines, reporting & export. |
| **[detection-engineering.md](detection-engineering.md)** | Detection rule extraction (Sigma, SPL, CrowdStrike QL, Elastic QL, KQL, YARA), validation, the rule library, the workbench, ATT&CK Navigator export, telemetry sources, mitigations. |
| **[automation-ai-enrichment.md](automation-ai-enrichment.md)** | Automation rule engine (triggers / conditions / actions), pluggable AI provider system, prompt templates, AI task assignments, and the enrichment-source adapter pipeline. |
| **[engine.md](engine.md)** | Pipeline stage registry & plans (feed > category > global), signal-engine priority scoring (IDF weights, feedback loop, shadow/surface flags), Radar triage surfacing, and the Settings → Engine console (single-surface living table: entries/links/relationships/entities/feeds, job runs, pipeline runs, retention). |
| **[engine-settings.md](engine-settings.md)** | Every runtime setting: what it does, its default, and which Engine console surface edits it — plus the setting→scheduled-job map and the env-only list. |
| **[copilot.md](copilot.md)** | The global AI copilot: SSE streaming with tool traces, the `ai`-queue CLI worker topology, read-only skill tooling, confirmable writes, conversation persistence & public sharing, Claude OAuth sign-in / in-app re-auth, and cost-tracking caveats. |
| **[workers-search-dashboards.md](workers-search-dashboards.md)** | Celery worker layer (every task + beat schedule), distributed coordination, Meilisearch indexing & query language, widgets system (the standalone dashboards feature is removed; widgets now live on the workbench Dashboard). |
| **[frontend.md](frontend.md)** | React/TypeScript SPA: routing, layouts, Zustand stores, TanStack Query conventions, Axios JWT refresh, CSS-variable theming, component tour, testing. |
| **[api-reference.md](api-reference.md)** | REST API reference: every router, endpoint, auth flow, error envelope, pagination conventions, rate limiting, middleware stack. |
| **[observables.md](observables.md)** | The IOC ledger: kinds and validators, the judgment doors (AI, article IOC table, feed, analyst) and why regex never creates a row, the indicator-aware analysis window, shadow vs capture and the per-kind list, the extraction fixture and eval, corroboration counts, attribution (claimed vs reported alongside), publishing, tools, automation hooks, enrichment. |
| **[story-threads.md](story-threads.md)** | Entry embeddings (pgvector), story-thread clustering and merging, the spine (heuristic and written), where threads render, and the tuning knobs. |
| **[data-model.md](data-model.md)** | Database schema reference: ER diagram, every table & junction, enums, indexes, JSONB columns, Alembic migration conventions. |

## How to navigate

- **New analyst** → guide/README.md → guide/getting-started.md → query-language.md.
- **Onboarding a new contributor** → architecture.md → contributing.md → frontend.md or api-reference.md depending on focus → relevant subsystem doc.
- **Wiring IntelFeed into another tool** → integrations.md → api-reference.md or cli-reference.md.
- **Adding a new feed source** → adapters.md.
- **Adding a new enrichment source or AI task** → automation-ai-enrichment.md.
- **Tuning intelligence extraction** → intelligence-engine.md.
- **"What does this setting actually do?"** → engine-settings.md.
- **Threads folding the wrong articles together** → story-threads.md.
- **Building a new widget** → workers-search-dashboards.md (widgets section) + frontend.md.
- **Writing or modifying a migration** → data-model.md (migrations section) + contributing.md.
- **Running in production** → operations.md + [`../setup.md`](../setup.md).

## Conventions

- File references use `path/to/file.py:line` format (e.g. `backend/app/intelligence/autolinker.py:101`) so links survive refactors.
- The deep-dive docs deliberately reference, rather than duplicate, content in `architecture.md`. If you find yourself paraphrasing the same content in two places, link instead.
- Dates in docs are absolute (e.g. `2026-05-03`), not relative.
- Mermaid diagrams are used for sequence flows, ER diagrams, and pipeline overviews. Each diagram lives as a standalone file under [`diagrams/`](diagrams/) — one diagram per file — and the doc links to it rather than embedding the chart inline.
