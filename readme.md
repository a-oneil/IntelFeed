<p align="center">
  <img src="assets/intelfeed-logo.svg" alt="IntelFeed" width="300">
</p>

<p align="center">
A self-hosted, security-focused RSS aggregator and threat intelligence platform. Built for security
analysts and detection engineers to consume threat feeds, extract TTPs/CVEs, correlate entities, and
generate detection rules.
</p>

---

## What it is

Most security teams read threat intel in a feed reader and lose it there. An article about a new
loader mentions three malware families, a CVE, and five ATT&CK techniques — and none of that survives
past the browser tab.

IntelFeed is a reader that keeps the intelligence. It ingests the sources you already follow — RSS,
YouTube, Reddit, GitHub, NVD, Mastodon, Bluesky, Telegram, arbitrary web pages — and, as each article
lands, links it to the threat actors, malware, tools, CVEs, ATT&CK techniques, vendors, products, and
countries it actually mentions. Those links accumulate into entity profiles you can pivot through,
a relationship graph you can interrogate, and a corpus you can turn into detection content.

It runs entirely on your own hardware. There is no SaaS backend, no telemetry, and no vendor holding
your collection.

## What it does

**Collection**
- Adapters for RSS/Atom, YouTube, podcasts, Reddit, GitHub releases and repos, the NVD CVE feed,
  Mastodon, Bluesky, Telegram channels, and a generic web scraper
- Conditional GET, content dedup, full-article fetch for truncated feeds, OPML import/export
- Optional article translation (LibreTranslate) and server-side read-aloud (Piper TTS)

**Intelligence extraction**
- Aho–Corasick autolinking of entries against a live vocabulary of actors, malware, tools, CVEs,
  ATT&CK techniques, vendors, products, and countries
- Entity resolution guardrails: junk-alias filtering, cross-type resurrection tombstones, and an
  AI-confirmation tier for ambiguous dictionary-word matches
- Typed entity relationships governed by a semantic matrix and a provenance trust ladder
  (MITRE-sourced → asserted → AI-adjudicated), so the graph stays defensible

**Analysis**
- Correlation and pivots across entity types via shared entries, with paragraph-proximity scoring
- Entity dossiers, campaigns, timelines, and an interactive relationship graph
- A signal engine that scores every entry (IDF-weighted novelty, CVE exploitation events, domain
  convergence) and surfaces a ranked priority queue instead of a reverse-chronological wall
- Ransomware leak-site victim tracking, CVE enrichment (NVD, EPSS, affected CPE products), and
  exposure views

**Detection engineering**
- Rule extraction in six formats — Sigma, Splunk SPL, CrowdStrike QL, Elastic QL, KQL, YARA — with
  per-format syntax validation and source provenance back to the article
- A rule library and workbench, detection-gap analysis, telemetry-source mapping, ATT&CK coverage
  and Navigator layer export
- Research bundles: per-entry markdown, IOC CSV, and an ATT&CK layer in one ZIP

**Automation & AI**
- Automation rules (triggers → conditions → actions) for tagging, filtering, notifications, AI tasks,
  and Priority Intelligence Requirement matching
- Watchlists, scheduled briefings, and Slack / Discord / Teams / webhook delivery
- A model-agnostic AI provider layer (Ollama, Claude, OpenAI, or any custom endpoint) with an
  editable prompt workspace, per-task model routing, and cost tracking
- An in-app copilot with streaming tool traces that can query and act on your own instance

**Working with it**
- Meilisearch-backed full-text search with a purpose-built query language, saved searches, and a
  command palette
- Configurable dashboards and widgets, a three-panel reader, runtime-switchable themes
- Export to CSV and Markdown; outbound observable feeds (EDL blocklists, SIEM lookups, TAXII 2.1); token-gated public RSS re-publishing; shareable read-only links
- REST API covering every feature, plus a zero-dependency CLI (170 tools) for scripting and agents

## Who it's for

- **Threat intel analysts** who want their reading to compound into a searchable, pivotable
  collection rather than a bookmark pile.
- **Detection engineers** who want to get from "this blog post describes a technique" to a validated
  Sigma or SPL rule — with the source article still attached — in one place.
- **Small teams and solo practitioners** who need TIP-shaped workflows without a commercial TIP,
  and who would rather keep their sources and analysis on their own box.

It is deliberately a *self-hosted single-tenant* tool: multi-user, but scoped to one organization.
It serves a minimal read-only TAXII 2.1 collection of its observables, but it is not a replacement for MISP — it happily sits
upstream of one.

## Quick start

Requirements: Docker and Docker Compose.

```bash
git clone <your-repo-url> intelfeed
cd intelfeed
cp .env.example .env
```

Generate the secrets `.env` needs, then fill them in:

```bash
openssl rand -hex 32                                                              # SECRET_KEY
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # ENCRYPTION_KEY
openssl rand -base64 24                                                           # POSTGRES_PASSWORD, MEILI_MASTER_KEY
```

Then bring the stack up:

```bash
docker compose -f docker-compose.dev.yml up
```

Open <http://localhost:3001> and register the first account — it becomes the admin. Migrations run
automatically on API startup, and the first boot seeds AI tasks, enrichment sources, and defaults.
The API is on <http://localhost:8000> (`/docs` for Swagger).

Then seed the reference data the intelligence engine matches against — countries, MITRE ATT&CK,
vendors and products, threat-actor attribution. Without it entries ingest but nothing links to
anything:

```bash
docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_all.py
```

From there, add feeds under **Settings → Feeds** or import an OPML file, and configure an AI provider
under **Settings → AI Configuration** if you want summarization and extraction. Nearly everything
else — thresholds, rate limits, image proxy, backups — is editable at runtime under
**Settings → System**; the database-backed settings table takes precedence over `.env`, so env vars
act as defaults.

For a production deployment (EC2, Caddy auto-TLS, DNS, data migration), see [setup.md](setup.md).

## Documentation

Full documentation lives in [`docs/`](docs/) — [`docs/README.md`](docs/README.md) is the guided index.
It also renders inside the app at **/documentation**.

Start here depending on what you're doing:

| I want to… | Read |
| --- | --- |
| Use IntelFeed day to day | [User guide](docs/guide/README.md), [Query language](docs/query-language.md) |
| Run it in production | [Operations](docs/operations.md), [setup.md](setup.md) |
| Wire it into other tools | [Integrations](docs/integrations.md), [API reference](docs/api-reference.md), [CLI reference](docs/cli-reference.md) |
| Work on the code | [Architecture](docs/architecture.md), [Contributing](docs/contributing.md) |

## Built with Claude

IntelFeed was built end-to-end with [Claude](https://claude.ai). Every line of it — backend,
frontend, migrations, tests, and this documentation — was written by Claude over months of
day-to-day direction, testing, correction, and real operational use by its human maintainer, who ran
the platform against live threat feeds throughout and fed the results back into the next iteration.

Worth knowing if you are evaluating the codebase, contributing to it, or judging how much to trust it
in your own environment.

## Tech stack

Python 3.12 · FastAPI · SQLAlchemy (async) · Alembic · Celery + Redis · PostgreSQL 16 · Meilisearch ·
React 18 · TypeScript · Vite · TanStack Query + Zustand · Docker Compose · Caddy

## License

Copyright (C) 2026 a-oneil

IntelFeed is free software: you can redistribute it and/or modify it under the
terms of the [GNU Affero General Public License](LICENSE) as published by the
Free Software Foundation, either version 3 of the License, or (at your option)
any later version. It is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU AGPL for more details.

In short: you are free to run, study, modify, and share it. If you run a modified
version as a network service, the AGPL requires you to offer those modifications
to its users under the same license.
