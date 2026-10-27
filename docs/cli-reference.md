# CLI Reference

This page is for anyone who wants to drive IntelFeed from a terminal, a script or a Claude skill. After reading it you can set up the CLI, call any tool, search with the query language, and add new tools.

The CLI is one Python file that calls a running IntelFeed server. There are two copies:

- **Full CLI** (`intelfeed-skill/scripts/intelfeed_cli.py`): every tool, read and write.
- **Lite CLI** (`intelfeed-lite-skill/scripts/intelfeed_cli.py`): read tools only.

Both are generated from the backend tool registry (`backend/app/tools/`), so the server and the CLIs always list the same tools. Run `--list-tools` to see what your copy has.

**Contents**

1. [Installation & Setup](#installation--setup)
2. [Invocation Patterns](#invocation-patterns)
3. [Read-Only Mode](#read-only-mode)
4. [The Lite Skill vs. Full Skill](#the-lite-skill-vs-full-skill)
5. [Admin tools and confirmations](#admin-tools-and-confirmations)
6. [Search Query Language](#search-query-language)
7. [Tool Reference](#tool-reference)
8. [Common Workflows](#common-workflows)
9. [Error Handling & Troubleshooting](#error-handling--troubleshooting)
10. [Extending the CLI](#extending-the-cli)

---

## Installation & Setup

You need Python 3 and network access to your IntelFeed server. The CLI uses only the standard library, so there is nothing to install.

Set these environment variables:

| Variable | Required | What it does |
|---|---|---|
| `INTELFEED_API_URL` | Yes | Your server's address, for example `https://intelfeed.example.com` or `http://localhost:8000`. There is no default. |
| `INTELFEED_USERNAME` | Yes | Your IntelFeed username. |
| `INTELFEED_PASSWORD` | Yes | Your IntelFeed password. Keep it in a secrets store or an untracked file. |
| `INTELFEED_READ_ONLY` | No | Full CLI only. Set to `1`, `true`, `yes` or `on` to block every write tool. See [Read-Only Mode](#read-only-mode). |
| `INTELFEED_ALLOW_INSECURE_HTTP` | No | Set to `1` to allow plain `http://` to a host other than localhost, such as a trusted LAN or the Docker Compose network. |

```bash
# On your machine, once per shell (or in your shell profile)
export INTELFEED_API_URL="https://intelfeed.example.com"
export INTELFEED_USERNAME="your-username"
export INTELFEED_PASSWORD="your-password"
```

**The URL must be `https://`, or `http://` to `localhost`, `127.0.0.1` or `::1`.** The CLI sends your password on login, so it refuses plain `http://` to any other host unless you set `INTELFEED_ALLOW_INSECURE_HTTP=1`.

### How login works

- Each run logs in once with `POST /api/auth/login` and keeps the tokens in memory. Nothing is saved between runs.
- If a call gets a 401, the CLI refreshes the token (or logs in again) and retries once.
- Each tool call is a `POST /api/tools/execute`. The request times out after 120 seconds.
- Redirects are not followed, because that could send your token to another host. A redirect shows up as an `API returned 30x` error. Point `INTELFEED_API_URL` at the final `https://` address.

---

## Invocation Patterns

All examples run on your machine from the repo root. Swap in `intelfeed-lite-skill/` to use the lite CLI.

```bash
# One tool, with JSON arguments
python3 intelfeed-skill/scripts/intelfeed_cli.py search_entries '{"query": "ransomware", "limit": 5}'

# A tool with no arguments
python3 intelfeed-skill/scripts/intelfeed_cli.py get_dashboard_stats

# Several tools in one run (one login, calls run in order)
python3 intelfeed-skill/scripts/intelfeed_cli.py \
  search_entries '{"query": "APT29"}' \
  get_feeds '{"limit": 10}' \
  get_dashboard_stats

# Every tool with its description and parameters ([optional] in brackets)
python3 intelfeed-skill/scripts/intelfeed_cli.py --list-tools

# One tool's parameters, types, defaults, allowed values and an example
python3 intelfeed-skill/scripts/intelfeed_cli.py --help-tool search_entries
```

Arguments are one JSON object after the tool name. A tool with no JSON after it runs with no arguments. Keys set to `null` are dropped before sending.

### Output Format

Results print to stdout as indented JSON. One call prints one object; several calls print an array of them, in order.

```json
{
  "tool": "search_entries",
  "result": {
    "total": 412,
    "limit": 5,
    "offset": 0,
    "entries": [
      {"id": "…", "title": "…", "summary": "…", "feed_title": "…", "published_at": "…", "url": "…"}
    ]
  }
}
```

When the server rejects a call (for example a 403 or 404), the CLI still exits 0 and puts the error in that tool's `result`:

```json
{"tool": "get_entry", "result": {"error": "API returned 404", "detail": "…"}}
```

A tool that fails on the server returns `{"error": "<message>"}` as its result in the same way.

### Exit Codes

| Code | Meaning | Where the message goes |
|---|---|---|
| `0` | The run finished. Check each `result` for an `error` key. | stdout |
| `1` | Usage problem: unknown tool, bad JSON, missing username or password, login failed. | stderr |
| `1` | `INTELFEED_API_URL` is missing or not allowed (see the https rule above). | stdout, as `{"error": …}` |
| `2` | Read-only mode refused a write tool. | stdout, as `{"error": …}` |

---

## Read-Only Mode

Set `INTELFEED_READ_ONLY=1` to make the full CLI refuse every write tool. The check happens before login, so a refused run sends nothing to the server. This is a hard stop for agents that should only read, even if their instructions are ignored.

```bash
export INTELFEED_READ_ONLY=1
python3 intelfeed-skill/scripts/intelfeed_cli.py create_campaign '{"name": "Test"}'
# stdout: {"error": "read-only mode: create_campaign is a write action and is disabled"}
# exit code: 2
```

- The blocked list is `WRITE_TOOLS` in the full CLI: every tool the registry marks `mutating`. The tables below show these as **write**. AI tools that save results, such as `extract_ttps`, `run_ai_task` and `generate_detection_rules`, are on it.
- If any tool in a batch is a write tool, the whole batch is refused and nothing runs.
- The list is generated by `scripts/dev/sync_skill_clis.py`; don't edit it by hand.

See the [CLI read-only gating diagram](diagrams/cli-readonly-gating.md) for the full flow.

---

## The Lite Skill vs. Full Skill

| | Full CLI (`intelfeed-skill`) | Lite CLI (`intelfeed-lite-skill`) |
|---|---|---|
| Tools | Every registry tool | Every read tool, minus a few heavy ones |
| Writes, deletes, merges | Yes | No |
| AI calls and exports | Yes | No |
| Read-only switch | `INTELFEED_READ_ONLY=1` | Not needed: it has no write tools |
| Best for | Analyst work, automation, curation | Questions, lookups, dashboards, smaller tool lists for an agent |

The lite CLI drops the tools the registry marks `mutating`, then the read tools in `LITE_EXCLUDE` in `scripts/dev/sync_skill_clis.py`. Today those are `validate_detection_rule`, `export_attack_layer` and `export_campaign` (shown as **read, full only** below). The other names in that set are already write tools.

The lite CLI is not a permission boundary on the server: it logs in as your user. It just has no write tools to call.

---

## Admin tools and confirmations

**Admin tools.** Some tools need an admin account, because the matching web API is admin-only. They are listed in `ADMIN_TOOLS` in `backend/app/tools/__init__.py` and marked **admin** in the tables below. They cover entity merges and reclassification, feed edits and deletes, every automation rule change except creating one, bulk unlinking, sector claims, the IOC deny list, some deletes, and the curation and extraction review reads. A non-admin call comes back as `API returned 403`.

**Confirmations.** Tools that delete for good take a `confirmation_token` and run in two steps:

1. Call without a token. Nothing is deleted. The result has `"status": "confirmation_required"`, a message, and a `confirmation_token`.
2. Show the message to the person. Only if they agree, call again with the same arguments plus the token. The result has `"status": "deleted"`.

The token is tied to your user and that one item, and stops working after 5 to 10 minutes. These tools work this way: `delete_entity`, `delete_feed`, `delete_campaign`, `delete_automation_rule`, `delete_detection_rule`, `delete_intel_report` and `delete_requirement`.

```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py delete_entity \
  '{"entity_type": "campaign", "entity_id": "<uuid>"}'
# result: {"status": "confirmation_required", "confirmation_token": "<token>", ...}

python3 intelfeed-skill/scripts/intelfeed_cli.py delete_entity \
  '{"entity_type": "campaign", "entity_id": "<uuid>", "confirmation_token": "<token>"}'
# result: {"status": "deleted", ...}
```

---

## Search Query Language

`search_entries` and `search_unified` accept the full query language below. It is the same one as the search box in the web app. `search_entities` only matches entity names.

### Entry Filters

These filter articles.

| Filter | Examples | Notes |
|---|---|---|
| `title:` | `title:"zero day"` | |
| `content:` | `content:ransomware` | |
| `author:` | `author:Krebs` | |
| `feed:` | `feed:"Krebs on Security"` | Feed name |
| `category:` | `category:Blogs` | The feed's folder |
| `tag:` | `tag:critical` | |
| `type:` | `type:rss`, `type:youtube`, `type:podcast` | Feed type |
| `date:` | `date:>2026-03-01`, `date:2026-01..2026-03` | |
| `is:` | `is:starred`, `is:unread`, `is:read`, `is:bookmarked`, `is:noted`, `is:muted`, `is:translated`, `is:image` | |
| `media:` | `media:audio`, `media:video`, `media:image`, `media:document` | |
| `lang:` | `lang:en` | |
| `signal:` | `signal:under_reported`, `signal:kev_added`, `signal:novel_entity` | Why the signal engine ranked the article |
| `url:` | `url:github.com` | |
| `words:` | `words:>1500`, `words:500..2000` | Article length |
| `feed.reliability:` | `feed.reliability:B` | Source grade (Admiralty code). Also `feed.timeliness:` and `feed.relevance:` |
| `sort:` | `sort:newest` | `relevance`, `newest`, `oldest`, `radar`, `title_asc`, `title_desc`, `shortest`, `longest` |

`sort:radar` orders by the signal engine's priority score, the same ranking as the Priority Queue. It leaves out unscored articles and ignores text relevance.

Things to know:

- **Some negations are dropped.** A negated `signal:`, `url:`, `is:translated` or `is:image` only removes matches from a set that another filter already built: an entity filter, or another positive `signal:`, `url:`, `is:translated` or `is:image`. With only text or index filters around it, the negation is ignored. For example `ransomware NOT signal:kev_added` returns every ransomware article.
- **Grades are exact letters.** `feed.reliability:>B` does not work, and feeds with no grade match no grade filter.
- **An unknown field becomes free text.** `titel:ransomware` searches for the word `ransomware`.

### Intelligence Filters

These filter articles by the entities linked to them.

| Filter | Examples |
|---|---|
| CVE | `cve:CVE-2025-5777`, `cve.severity:critical`, `cve.cvss:>9.0` |
| CVE exploitation | `cve.kev:true`, `cve.epss:>0.5`, `cve.epss_percentile:>0.9`, `cve.poc:>0`, `cve.exploit:kev` |
| CVE products | `cve.product:fortinet` (NVD vendor or product) |
| CWE | `cwe:CWE-79`, `cwe.abstraction:`, `cwe.parent:` |
| TTP (ATT&CK technique) | `ttp:T1059*`, `ttp.tactic:initial-access` |
| TTP shape | `ttp.platform:Windows`, `ttp.data_source:process`, `ttp.domain:ics`, `ttp.subtechnique:true` |
| Threat actor | `threat_actor:APT29`, `threat_actor.country:Russia`, `threat_actor.motivation:espionage`, `threat_actor.sector:healthcare`, `threat_actor.type:ransomware` |
| Malware | `malware:Emotet`, `malware.type:trojan`, `malware.sector:finance` |
| Sector | `sector:healthcare`, `sector.slug:financial-services` (articles that describe the industry being targeted) |
| Tool | `tool:Mimikatz`, `tool.type:`, `tool.platform:Windows` |
| Country | `country:"United States"`, `country.region:Europe`, `country.iso:RU` |
| Vendor / product | `vendor:Cisco`, `vendor.type:`, `product:ASA`, `product.vendor:Cisco`, `product.type:` |
| Observable (IOC) | `observable.kind:domain`, `observable.role:`, `observable.status:` (`ioc` works as a short form) |
| Campaign | `campaign:`, `campaign.status:active` |
| Mitigation | `mitigation:` |
| Detection rule | `rule:"Sigma Detection"`, `rule.type:sigma`, `rule.severity:high`, `rule.data_source:sysmon`, `rule.tactic:persistence`, `rule.tag:attack`, `rule.draft:false` |
| Ransomware victim | `ransomware_victim.sector:manufacturing`, `ransomware_victim.group:lockbit`, `ransomware_victim.domain:` |
| Requirement (PIR) | `pir:"Ransomware Activity"`, `pir.priority:critical`, `pir.category:tactical` |
| Note | `note:fortibleed` (title or body), `note.tag:`, `note.type:analysis`, `note.about:cve` (or `entry`, `standalone`), `note.pinned:true` |
| Intel report | `intel_report:quarterly`, `intel_report.status:draft`, `intel_report.type:`, `intel_report.tlp:amber` |

Catalogue suffixes:

- `.articles`, `.seen` and `.first_seen` work on `threat_actor`, `malware`, `ttp`, `tool`, `country`, `sector`, `vendor`, `product`, `mitigation`, `cwe` and `observable`. Examples: `threat_actor.articles:>100`, `malware.seen:>2026-01-01`, `ttp.first_seen:>2026-06`.
- `.review` and `.via` (how the entity was created) work on `threat_actor`, `malware`, `cve`, `ttp` and `tool`. Examples: `threat_actor.review:true`, `cve.via:ai_extraction`.

The full list of field names is `ENTRY_FIELDS` and `ENTITY_FIELDS` in `backend/app/search/query_planner.py`.

### Operators

| Operator | Meaning | Example |
|---|---|---|
| `AND` | Both. Also the default between terms. | `ransomware AND type:rss` |
| `OR` | Either | `APT29 OR APT28` |
| `NOT` | Exclude | `NOT type:youtube` |
| `*` | Wildcard | `ttp:T1059*` |
| `"..."` | Exact phrase | `"device code phishing"` |
| `()` | Grouping | `(ransomware OR malware) AND type:rss` |
| `>`, `>=`, `<`, `<=`, `..` | Compare numbers or dates, or give a range | `cve.cvss:>9.0`, `date:>=2026-04-01`, `words:500..2000` |

### Example Queries

```text
# Recent RSS articles about ransomware
ransomware type:rss sort:newest

# Starred articles with critical CVEs
cve.severity:critical is:starred

# APT29 initial-access reporting
threat_actor:APT29 AND ttp.tactic:initial-access

# Known-exploited CVEs that are likely to be attacked
cve.kev:true cve.epss:>0.5

# Under-reported stories, in the signal engine's order
signal:under_reported sort:radar

# Persistence rules that need Sysmon
rule.data_source:sysmon rule.tactic:persistence

# Manufacturing victims on ransomware leak sites
ransomware_victim.sector:manufacturing

# Phishing, without YouTube
(phishing OR "social engineering") NOT type:youtube
```

---

## Tool Reference

The tables below come from the backend registry and are grouped by the file each tool lives in. For the type, default and allowed values of each argument, run `--help-tool <name>`.

- **Arguments**: **bold** ones are required.
- **Kind**:
  - **read**: in both CLIs.
  - **read, full only**: a read tool left out of the lite CLI.
  - **write**: changes data. Full CLI only, and blocked in read-only mode.
  - **admin**: needs an admin account. See [Admin tools and confirmations](#admin-tools-and-confirmations).

### Search

Source: `backend/app/tools/search.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `search_entries` | Search articles with the full query language. Pages with `offset`. | **`query`**, `limit`, `offset`, `sort` | read |
| `search_entities` | Search all entity types and analyst notes by name. | **`query`**, `limit` | read |
| `search_unified` | Search articles and entities in one call. | **`query`**, `limit` | read |
| `get_search_facets` | Feed types, categories and top tags, with counts. | none | read |

### Entries, entities and platform data

Source: `backend/app/tools/read.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `get_entry` | One article with its content and every linked entity. | **`entry_id`** | read |
| `get_feed_entries` | Recent articles from one feed. | **`feed_id`**, `limit` | read |
| `get_threat_actor` | A threat actor profile. | **`actor_id`** | read |
| `get_malware` | A malware family profile. | **`malware_id`** | read |
| `get_cve` | A CVE with scores, KEV status, exploit info, affected products and CWEs. | **`cve_id`** | read |
| `get_observable` | One IOC by UUID or value. Accepts defanged input like `evil[.]com`. | **`observable`**, `kind` | read |
| `search_observables` | Filter the IOC ledger. Sorted by last sighting. | `query`, `kind`, `role`, `status`, `captured_by`, `infra_tag`, `needs_review`, `min_confidence`, `min_reports`, `linked_entity_type`, `linked_entity_id`, `limit` | read |
| `get_cwe` | A CWE weakness with its lineage, mitigations and CVE counts. | **`cwe_id`** | read |
| `get_ttp` | An ATT&CK technique by UUID or ID (for example `T1059.001`). | **`ttp_id`** | read |
| `get_campaign` | A campaign with its timeline, links and detection gaps. | **`campaign_id`** | read |
| `get_feeds` | Configured feeds with their health. | `limit` | read |
| `discover_telegram_channels` | Telegram channels the server account has joined, and which are already feeds. | `session_name`, `only_unsubscribed` | read |
| `list_telegram_feeds` | Telegram feeds with their adapter settings. | `limit` | read |
| `get_detection_rules` | List detection rules, optionally by format. | `rule_type`, `limit` | read |
| `get_requirements` | Intelligence requirements and their coverage. | `status` | read |
| `get_correlation_events` | Recent correlation events (gaps, trends, matches, KEV additions). | `limit`, `unread_only` | read |
| `get_analytics` | Platform analytics: overview, trending, detection coverage or velocity. | **`metric`**, `entity_type`, `days` | read |
| `get_dashboard_stats` | System-wide counts and recent activity. | none | read |
| `get_enrichment_data` | Stored enrichment for a CVE, malware, actor or TTP. | **`entity_type`**, **`entity_id`** | read |
| `get_attack_layer` | ATT&CK Navigator layer for one article, or for all observed techniques. | `entry_id`, `title` | read |
| `get_telemetry_sources` | Configured log sources and what they cover. | none | read |
| `get_campaigns` | List campaigns. | `status`, `limit` | read |
| `get_campaign_timeline` | A campaign's articles, newest first. | **`campaign_id`** | read |
| `get_campaign_attack_layer` | ATT&CK Navigator layer for a campaign. | **`campaign_id`** | read |
| `get_campaign_detection_gaps` | A campaign's techniques split into covered, `library_only` and `gaps`. | **`campaign_id`** | read |
| `suggest_campaign_entries` | Articles that share entities with a campaign but are not linked to it. | **`campaign_id`**, `limit` | read |
| `export_campaign` | A full campaign package: articles, entities and rules. | **`campaign_id`** | read, full only |
| `get_automation_rules` | List automation rules. | `label`, `limit` | read |
| `get_automation_templates` | Built-in automation rule templates. | none | read |
| `get_automation_logs` | Recent automation runs. | `rule_id`, `limit` | read |
| `get_trending_entities` | Most-mentioned entities of one type over a window. | **`entity_type`**, `days`, `limit` | read |
| `get_feed_value` | A 0-100 value score per feed. | `days` | read |
| `get_source_reliability` | Feeds ranked by how much intelligence they produce. | `limit` | read |
| `get_entry_insights` | Insights about the entities in one article. | **`entry_id`** | read |
| `get_triage_queue` | Scored review queue. Older than `get_priority_queue` and does not fold stories. | `days`, `limit` | read |
| `get_priority_queue` | The reading queue as the Priority Queue page shows it, with stories folded into one row. | `limit`, `unread_only`, `with_threads`, `cursor` | read |
| `get_requirement_coverage` | Requirement counts by status, priority, category and staleness. | none | read |

### Pivots, graphs and coverage checks

Source: `backend/app/tools/correlation.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `pivot_entity` | Entities that appear in the same articles as this one, ranked by strength. | **`entity_type`**, **`entity_id`**, `limit_per_type`, `window_days`, `offset`, `sort`, `min_tier` | read |
| `get_entity_graph` | Relationship graph around an entity (typed relationships only). | **`entity_type`**, **`entity_id`**, `depth`, `window_days` | read |
| `get_entity_timeline` | When an entity appeared in articles, in order. | **`entity_type`**, **`entity_id`** | read |
| `check_detection_gaps` | Observed techniques with no published detection rule. | none | read |
| `check_requirement_match` | Which requirements an article matches. Saves nothing. | **`entry_id`** | read |
| `check_telemetry_feasibility` | Whether your log sources can support a rule. | `rule_id` | read |
| `get_temporal_clusters` | Groups of articles sharing entities in a short window (possible campaigns). | `days`, `window_hours`, `min_shared`, `limit` | read |
| `get_entry_graph` | Relationship graph for the entities in one article. | **`entry_id`** | read |

### Workbench boards and intel profiles

Source: `backend/app/tools/boards.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `get_threat_board` | The Threats board: actors, malware and exploited CVEs ranked by how many stories carried them. | `window`, `facet`, `limit`, `min_attention`, `include_handled` | read |
| `list_intel_profiles` | List intel profiles (named scopes such as a customer or portfolio). | `limit`, `offset` | read |
| `get_intel_profile` | One intel profile with its countries and sectors. | **`profile_id`** | read |
| `get_profile_threat_surface` | Actors and malware active against one intel profile, with the reason. | **`profile_id`**, `limit` | read |
| `get_coverage_workspace` | One threat's recent behaviours and the telemetry each one needs. | **`entity_type`**, **`entity_key`**, `window` | read |
| `list_tags` | Every tag with your entry counts. | none | read |
| `get_entity_whats_new` | Recent novelty and severity signals for one entity. | **`entity_type`**, **`entity_id`**, `days`, `scoped` | read |

### Story threads

A story thread groups every article about one unfolding story. Source: `backend/app/tools/threads.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `get_story_threads` | List story threads with outlets, counts and key entities. | `status`, `limit` | read |
| `get_story_thread` | One thread: its timeline of coverage, member articles and what it produced. | **`slug`**, `include_members` | read |

### Sectors

Sectors are the fixed list of victim industries (healthcare, finance and so on). Source: `backend/app/tools/sector.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `list_sectors` | List sectors with article, actor and victim counts. | `search`, `sort_by`, `limit` | read |
| `get_sector` | A sector profile: who targets it, campaigns, victims, recent articles. | **`sector`**, `window_days` | read |
| `who_targets_sector` | Actors and malware ranked by how much they target a sector. | **`sector`**, `limit` | read |
| `set_target_sector` | Add or remove a claim that an actor or malware family targets a sector. | **`entity_type`**, **`entity_id`**, **`sector`**, `action` | write, admin |
| `sector_victims` | Ransomware leak-site victims in a sector. | **`sector`**, `window_days`, `limit` | read |

### Observables (IOCs)

Observables are indicators of compromise (IOCs): IPs, domains, hashes and similar values. Source: `backend/app/tools/observables.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `promote_observable` | Add a value from an article to the IOC ledger. | **`entry_id`**, **`kind`**, **`value`**, `role`, `evidence`, `label` | write |
| `update_observable` | Change an IOC's role, label or description, or pin its confidence. | **`observable_id`**, `role`, `label`, `description`, `confidence_pinned` | write |
| `deny_observable` | Block a value so it is never captured, sighted or exported again. | `observable_id`, `kind`, `value`, `reason` | write, admin |
| `get_entity_infrastructure` | The IOCs tied to an actor, malware family, campaign or tool. | **`entity_type`**, **`entity_id`**, `limit` | read |
| `export_observables` | Export IOCs as EDL lines, CSV or JSON. | `format`, `kind`, `role`, `status`, `min_confidence`, `min_reports`, `include_infra_tagged`, `query`, `limit` | read |

### Watchlist, ransomware, My Stack and glossary

Source: `backend/app/tools/landscape.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `list_watches` | Your watched, muted and "stack" entities. | `mode` | read |
| `watch_entity` | Watch, mute or add an entity to your stack. | **`entity_type`**, **`entity_id`**, **`mode`**, `boost` | write |
| `unwatch_entity` | Remove your watch, mute or stack entry for an entity. | **`entity_type`**, **`entity_id`** | write |
| `get_ransomware_disclosures` | Ransomware leak-site victim posts, newest first. | `group`, `sector`, `country`, `watched_only`, `since`, `q`, `sort`, `limit`, `offset` | read |
| `get_ransomware_stats` | Ransomware totals, trends, top groups, sectors and countries. | `days` | read |
| `get_ransomware_victim` | One ransomware victim organisation and its disclosures. | **`victim_id`** | read |
| `get_ransomware_group_victims` | Victims posted by one ransomware group. | **`actor_id`**, `limit`, `offset` | read |
| `get_stack_exposure` | CVEs that affect the vendors and products in your stack. | none | read |
| `list_glossary_terms` | List glossary terms. | `category`, `search`, `is_system`, `limit` | read |
| `create_glossary_term` | Add a glossary term. | **`name`**, **`category`**, **`description`**, `maturity`, `long_description`, `technologies`, `search_terms` | write |
| `delete_glossary_term` | Delete a glossary term you created. | **`term_id`** | write |
| `detect_glossary_terms` | Glossary terms that appear in one article. | **`entry_id`** | read |

### Reader actions and manual ingest

Source: `backend/app/tools/reader_ops.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `mark_entry_read` | Mark an article read or unread. | **`entry_id`**, `read` | write |
| `star_entry` | Star or unstar an article. | **`entry_id`**, `starred` | write |
| `bookmark_entry` | Bookmark an article or remove the bookmark. | **`entry_id`**, `bookmarked` | write |
| `bulk_entry_action` | Read, unread, star, unstar, bookmark, unbookmark or hide many articles. | **`entry_ids`**, **`action`** | write |
| `mark_all_read` | Mark everything read, or one feed or category. With no scope it marks every article. | `feed_id`, `category_id` | write |
| `get_similar_entries` | Articles similar to this one. | **`entry_id`**, `limit` | read |
| `get_entry_story` | Earlier and later articles that share entities with this one, in date order. | **`entry_id`** | read |
| `translate_entry` | Translate an article and save the translation. | **`entry_id`**, `target` | write |
| `get_daily_summary` | The saved AI daily summary for a day. Never generates one. | `date` | read |
| `ingest_url` | Add a web page as a manual article. | **`url`**, `title` | write |
| `ingest_text` | Add pasted text as a manual article. | **`text`**, `title`, `source_url`, `is_ioc_list` | write |
| `ingest_file` | Add a file (base64) as a manual article. A `.zip` becomes one article per file. | **`filename`**, **`content_base64`**, `title`, `is_ioc_list` | write |
| `ingest_batch` | Add many URLs or texts at once. | `urls`, `texts`, `label`, `is_ioc_list` | write |
| `get_ingest_batch` | Status of an ingest batch. | **`batch_id`** | read |
| `create_share_link` | Make a public share link for an article. | **`entry_id`**, `ttl_days` | write |
| `get_share_link` | Your active share link for an article. | **`entry_id`** | read |
| `revoke_share_link` | Turn off your share link for an article. | **`entry_id`** | write |
| `list_saved_searches` | Your saved searches with counts. | none | read |
| `create_saved_search` | Save a search query. | **`name`**, **`query`**, `display_name` | write |
| `delete_saved_search` | Delete a saved search. | **`search_id`** | write |

### AI extraction

These call the AI provider and save what they find. Source: `backend/app/tools/extraction.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `extract_ttps` | Find ATT&CK techniques in an article. `use_ai` adds an AI pass. | **`entry_id`**, `use_ai` | write |
| `extract_cves` | Find CVEs in an article. | **`entry_id`** | write |
| `extract_threat_actors` | Find threat actors in an article. | **`entry_id`** | write |
| `extract_malware` | Find malware families in an article. | **`entry_id`** | write |
| `run_ai_task` | Run a named AI task on an article. Returns the saved result unless `force` is true. | **`task_name`**, **`entry_id`**, `force` | write |

### Detection rule generation and checks

Source: `backend/app/tools/detection.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `generate_detection_rules` | Write draft detection rules from an article's techniques. | **`entry_id`**, **`rule_types`** | write |
| `validate_detection_rule` | Check a rule's syntax. | **`rule_type`**, **`rule_content`** | read, full only |
| `build_detection_summary` | Full detection analysis across several articles: attack chain and gaps. | **`entry_ids`**, **`rule_formats`**, `focus`, `include_existing` | write |

### Detection rules, reports and requirements

Source: `backend/app/tools/workspace.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `get_detection_rule` | One detection rule with content, source, status and syntax check. | **`rule_id`** | read |
| `update_detection_rule` | Change a detection rule. Content changes save a new version. | **`rule_id`**, **`updates`** | write |
| `delete_detection_rule` | Delete a detection rule. Needs confirmation. | **`rule_id`**, `confirmation_token` | write |
| `set_detection_rule_status` | Set a rule to `draft` or `published`. | **`rule_id`**, **`status`** | write |
| `convert_detection_rule` | Convert a rule to another format with AI. | **`rule_id`**, **`target_format`**, `save` | write |
| `get_detection_rule_versions` | A rule's saved versions. | **`rule_id`** | read |
| `rollback_detection_rule` | Restore a rule from a saved version. | **`rule_id`**, **`version`** | write |
| `list_intel_reports` | List intel reports. | `status`, `template_type`, `limit`, `offset` | read |
| `get_intel_report` | One intel report in full. | **`report_id`** | read |
| `update_intel_report` | Change an intel report. | **`report_id`**, **`updates`** | write |
| `delete_intel_report` | Delete a draft report. Needs confirmation. | **`report_id`**, `confirmation_token` | write, admin |
| `archive_intel_report` | Archive a report. | **`report_id`** | write |
| `delete_requirement` | Delete a requirement and its matches. Needs confirmation. | **`requirement_id`**, `confirmation_token` | write |
| `fulfill_requirement` | Mark a requirement fulfilled. | **`requirement_id`**, `report_id` | write |
| `add_requirement_match` | Match an article to a requirement by hand. | **`requirement_id`**, **`entry_id`**, `relevance` | write |
| `remove_requirement_match` | Remove an article from a requirement. | **`requirement_id`**, **`entry_id`** | write |

### Create, merge and report

Source: `backend/app/tools/write.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `create_threat_actor` | Add a threat actor. Returns the existing one if the name already matches. | **`name`**, `aliases`, `description`, `country`, `motivation` | write |
| `create_malware` | Add a malware family. Returns the existing one if the name already matches. | **`name`**, `aliases`, `description`, `malware_type` | write |
| `create_detection_rule` | Save a detection rule as a draft. | **`title`**, **`rule_type`**, **`rule_content`**, `description`, `severity`, `entry_id`, `tags`, `references`, `source_entry_ids` | write |
| `create_campaign` | Create a campaign. | **`name`**, `description`, `status`, `tlp_marking` | write |
| `create_feed` | Subscribe to a feed. | **`url`**, `title`, `feed_type`, `category`, `adapter_config` | write |
| `add_telegram_feed` | Subscribe to a Telegram channel. Needs Telegram set up on the server. | **`channel`**, `title`, `include_media`, `extract_forwards`, `max_message_age_days`, `max_messages_per_fetch`, `fetch_interval_minutes`, `threat_actor_id`, `campaign_id`, `session_name`, `category` | write |
| `create_note` | Add a note to an article. | **`entry_id`**, **`content`**, `title` | write |
| `create_entity_note` | Add a note to an entity. | **`entity_type`**, **`entity_id`**, **`content`** | write |
| `add_tag` | Tag an article. | **`entry_id`**, **`tag_name`** | write |
| `add_to_campaign` | Link an article or entity to a campaign. | **`campaign_id`**, `entry_id`, `entity_type`, `entity_id`, `role` | write |
| `link_entities` | Record a relationship between two entities (for example actor `uses` malware). | **`source_type`**, **`source_id`**, **`target_type`**, **`target_id`**, **`relationship_type`**, `description`, `confidence`, `evidence_entry_ids` | write |
| `create_automation_rule` | Create an automation rule. It starts enabled. | **`name`**, **`trigger_type`**, **`actions`**, `description`, `trigger_config`, `conditions` | write |
| `create_intel_report` | Create a draft report from a template. | **`title`**, **`template_type`**, `entry_ids`, `entity_ids`, `tlp_marking` | write |
| `merge_threat_actors` | Merge a duplicate actor into another. `mode: shadow` only logs. | **`target_id`**, **`source_id`**, `mode`, `new_description`, `extra_aliases`, `reasoning` | write, admin |
| `reclassify_entity` | Move an entity filed under the wrong type. | **`source_type`**, **`source_id`**, **`target_type`**, `target_id`, `mode`, `new_description`, `extra_aliases`, `reasoning` | write, admin |
| `merge_vendors` | Merge a duplicate vendor into another. | **`target_id`**, **`source_id`**, `mode`, `new_description`, `extra_aliases`, `reasoning` | write, admin |
| `merge_products` | Merge a duplicate product into another. | **`target_id`**, **`source_id`**, `mode`, `new_description`, `extra_aliases`, `reasoning` | write, admin |
| `merge_tools` | Merge a duplicate tool into another. | **`target_id`**, **`source_id`**, `mode`, `new_description`, `extra_aliases`, `reasoning` | write, admin |
| `merge_malware` | Merge a duplicate malware family into another. | **`target_id`**, **`source_id`**, `mode`, `new_description`, `extra_aliases`, `reasoning` | write, admin |
| `update_entity_profile` | Edit an entity's profile fields. | **`entity_type`**, **`entity_id`**, **`updates`** | write |
| `create_requirement` | Create a Priority Intelligence Requirement (PIR). | **`title`**, **`keywords`**, `description`, `priority`, `category`, `auto_match` | write |
| `update_requirement` | Change a requirement. | **`requirement_id`**, **`updates`** | write |
| `test_automation_rule` | Dry-run a rule against one article. Runs no actions. | **`rule_id`**, **`entry_id`** | write, admin |
| `run_automation_rule` | Run a rule now, once per matching recent article. | **`rule_id`**, `hours` | write, admin |
| `publish_report` | Publish a report. | **`report_id`** | write |
| `generate_full_report` | Create a report from articles and queue AI writing. | **`title`**, **`template_type`**, **`entry_ids`**, `focus`, `tlp_marking` | write |
| `generate_campaign_report` | Create a report from a campaign and queue AI writing. | **`campaign_id`**, `template_type`, `title`, `tlp_marking` | write |
| `export_report` | Export a report as Markdown or HTML. | **`report_id`**, **`format`** | write |

### Feeds, automation, notes and campaigns

Source: `backend/app/tools/feeds_automation.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `update_feed` | Change a feed. Only the fields you send change. | **`feed_id`**, `url`, `title`, `category`, `is_muted`, `is_active`, `fetch_interval_minutes`, `exclude_shorts`, `feed_type`, `retention_days`, `reliability_rating`, `timeliness_rating`, `relevance_rating`, `analyst_notes`, `intel_extraction_mode`, `ai_analysis_enabled`, `auto_extract_on_ingest`, `extract_detection_rules`, `extract_tools`, `visible_to_visitors`, `adapter_config` | write, admin |
| `delete_feed` | Delete a feed and all its articles. Needs confirmation. | **`feed_id`**, `confirmation_token` | write, admin |
| `refresh_feed` | Fetch a feed now. | **`feed_id`** | write |
| `list_categories` | Feed categories as a tree, with feed counts. | none | read |
| `create_category` | Create a feed category. | **`name`** | write |
| `update_automation_rule` | Change an automation rule. `actions` replaces the whole list. | **`rule_id`**, `name`, `description`, `trigger_type`, `trigger_config`, `conditions`, `actions`, `labels`, `is_enabled` | write, admin |
| `toggle_automation_rule` | Turn a rule on or off. | **`rule_id`** | write, admin |
| `delete_automation_rule` | Delete a rule. Needs confirmation. | **`rule_id`**, `confirmation_token` | write, admin |
| `list_webhook_presets` | Saved webhook presets. URLs and headers are hidden. | `preset_type`, `limit` | read |
| `create_webhook_preset` | Save a webhook preset for automation actions. | **`name`**, `url`, `payload`, `headers`, `preset_type`, `config` | write |
| `delete_webhook_preset` | Delete a webhook preset. | **`preset_id`** | write, admin |
| `list_notes` | List article and standalone notes. | `entry_id`, `search`, `limit` | read |
| `update_note` | Change a note. | **`note_id`**, **`content`**, `title` | write |
| `delete_note` | Delete a note. | **`note_id`** | write |
| `list_entity_notes` | Notes on one entity. | **`entity_type`**, **`entity_id`**, `limit` | read |
| `update_entity_note` | Change an entity note. | **`note_id`**, **`content`** | write |
| `delete_entity_note` | Delete an entity note. | **`note_id`** | write |
| `update_campaign` | Change a campaign. `tags` replaces the whole list. | **`campaign_id`**, `name`, `description`, `status`, `tlp_marking`, `start_date`, `end_date`, `tags` | write |
| `delete_campaign` | Delete a campaign (not its articles or entities). Needs confirmation. | **`campaign_id`**, `confirmation_token` | write |
| `remove_from_campaign` | Unlink an article or entity from a campaign. | **`campaign_id`**, `entry_id`, `entity_type`, `entity_id` | write |

### Curation: links, relationships, extraction review

Source: `backend/app/tools/curation.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `list_entity_links` | List article-to-entity links, newest first. | `entity_type`, `entity_id`, `entry_id`, `source`, `confidence`, `search`, `days`, `limit`, `offset` | read |
| `get_entity_link_stats` | Link counts by type and source, and the held-match queue. | none | read |
| `unlink_entity_from_entry` | Remove one article-to-entity link. | **`entity_type`**, **`entity_id`**, **`entry_id`** | write |
| `bulk_unlink_entities` | Remove up to 500 article-to-entity links. | **`items`** | write, admin |
| `report_false_positive` | Report a wrong link. `scope` sets how far the fix reaches. | **`entity_type`**, **`entity_id`**, **`entity_value`**, **`scope`**, `source_entry_id`, `reason` | write |
| `list_entity_relationships` | Relationships where an entity is either end. | **`entity_type`**, **`entity_id`**, `relationship_type`, `include_rejected` | read |
| `confirm_relationship` | Mark a relationship confirmed by an analyst. | **`relationship_id`** | write |
| `reject_relationship` | Reject a relationship so it is hidden and not re-created. | **`relationship_id`** | write |
| `delete_relationship` | Delete a relationship. Re-ingest can re-create it; reject cannot. | **`relationship_id`** | write |
| `get_extraction_stats` | Counts of AI-created entities and their review state. | `window` | read, admin |
| `list_extraction_entities` | List AI-created entities with their status. | `types`, `status`, `window`, `q`, `source_entry_id`, `sort_by`, `sort_order`, `limit`, `offset` | read, admin |
| `confirm_extraction_entities` | Sign off AI-created entities so they leave the review queue. | **`entity_type`**, **`ids`** | write, admin |
| `get_hygiene_stats` | Entity clean-up counters and pending proposals. | none | read, admin |
| `get_hygiene_feed` | Log of entity clean-up actions and proposals. | `action`, `source`, `mode`, `origin`, `pending`, `since`, `limit`, `offset` | read, admin |

### Export

Source: `backend/app/tools/export.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `export_attack_layer` | ATT&CK Navigator layer JSON for one article or all observed techniques. | `entry_id`, `title` | read, full only |

### Delete

Source: `backend/app/tools/delete.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `delete_entity` | Delete a record or any entity. Needs confirmation. | **`entity_type`**, **`entity_id`**, `confirmation_token` | write, admin |

### Documentation

These read the pages in `docs/`, as shipped with the deployment. Source: `backend/app/tools/docs.py`.

| Tool | What it does | Arguments | Kind |
|---|---|---|---|
| `list_documentation_pages` | Every documentation page with a one-line summary. | none | read |
| `get_documentation_page` | One page as Markdown. The slug is the path under `docs/` without `.md`. | **`slug`** | read |
| `search_documentation` | Search the documentation. | **`query`**, `limit` | read |

---

## Common Workflows

These run on your machine and use `jq` to pull IDs out of the JSON. Set `CLI=intelfeed-skill/scripts/intelfeed_cli.py` first.

### Find recent articles about a topic and summarise one

```bash
CLI=intelfeed-skill/scripts/intelfeed_cli.py

# 1. Newest five ransomware articles
python3 $CLI search_entries '{"query": "ransomware", "limit": 5, "sort": "newest"}' \
  | jq -r '.result.entries[].id'

# 2. Read one in full, with its linked entities
python3 $CLI get_entry '{"entry_id": "<entry_id>"}'

# 3. AI summary (returns the saved one if it exists; add "force": true to redo it)
python3 $CLI run_ai_task '{"task_name": "article_summary", "entry_id": "<entry_id>"}'
```

### Look up an actor and pivot

```bash
ACTOR_ID=$(python3 $CLI search_entities '{"query": "APT29"}' \
  | jq -r '.result.results[] | select(.type == "threat_actor") | .id' | head -1)

python3 $CLI get_threat_actor "{\"actor_id\": \"$ACTOR_ID\"}"
python3 $CLI pivot_entity "{\"entity_type\": \"threat_actor\", \"entity_id\": \"$ACTOR_ID\"}"
python3 $CLI get_entity_graph "{\"entity_type\": \"threat_actor\", \"entity_id\": \"$ACTOR_ID\", \"depth\": 2}"
```

### Turn an article into detection rules

```bash
# 1. Find the ATT&CK techniques, with an AI pass
python3 $CLI extract_ttps '{"entry_id": "<entry_id>", "use_ai": true}'

# 2. Write draft rules in the formats you use
python3 $CLI generate_detection_rules \
  '{"entry_id": "<entry_id>", "rule_types": ["sigma", "splunk_spl", "elastic_ql"]}'

# 3. Check a rule's syntax, then save your own version as a draft
python3 $CLI validate_detection_rule '{"rule_type": "sigma", "rule_content": "<rule>"}'
python3 $CLI create_detection_rule \
  '{"title": "Detect X", "rule_type": "sigma", "rule_content": "<rule>", "entry_id": "<entry_id>"}'
```

### Check a campaign's detection coverage

```bash
GAPS=$(python3 $CLI get_campaign_detection_gaps '{"campaign_id": "<campaign_id>"}')
echo "$GAPS" | jq '.result.coverage_percentage'

# Read up on each technique with no rule
for T in $(echo "$GAPS" | jq -r '.result.gaps[].technique_id'); do
  python3 $CLI get_ttp "{\"ttp_id\": \"$T\"}"
done
```

### Watch for a threat actor

```bash
# 1. A Priority Intelligence Requirement that matches new articles
python3 $CLI create_requirement \
  '{"title": "APT29 activity", "keywords": ["APT29", "Cozy Bear", "Midnight Blizzard"], "priority": "critical"}'

# 2. An automation rule that tags matching articles and extracts techniques
python3 $CLI create_automation_rule '{
  "name": "Tag APT29 mentions",
  "trigger_type": "on_keyword_match",
  "trigger_config": {"pattern": "APT29|Cozy Bear|Midnight Blizzard", "is_regex": true},
  "actions": [
    {"type": "add_tags", "config": {"tags": ["apt29"]}},
    {"type": "extract_ttps", "config": {}}
  ]
}'

# 3. Dry-run it against one article before it fires for real
python3 $CLI test_automation_rule '{"rule_id": "<rule_id>", "entry_id": "<entry_id>"}'
```

Trigger types start with `on_`. A rule saved with any other spelling never fires. `test_automation_rule` needs an admin account.

---

## Error Handling & Troubleshooting

| What you see | Likely cause | What to do |
|---|---|---|
| `Error: Login failed (401)` on stderr | Wrong username or password | Check `INTELFEED_USERNAME` and `INTELFEED_PASSWORD`. Try logging in to the web app. |
| `Error: INTELFEED_USERNAME and INTELFEED_PASSWORD must be set.` | A variable is missing | Export both. |
| `{"error": "INTELFEED_API_URL is not set. …"}` | No server address | Export `INTELFEED_API_URL`. |
| `{"error": "INTELFEED_API_URL http://… is plain http:// to another host, …"}` | Plain http to a remote host | Use `https://`, or set `INTELFEED_ALLOW_INSECURE_HTTP=1` on a trusted network. |
| `Connection refused` or `Name or service not known` | Wrong URL, or the server is down | `curl "$INTELFEED_API_URL/api/health"`. For a local stack, `docker compose -f docker-compose.dev.yml ps`. |
| `"error": "API returned 30x"` | The URL redirects (often http to https) | Use the final `https://` address. |
| `"error": "API returned 403"` | An admin tool called by a non-admin account | Use an admin account. |
| `Error: Unknown tool '<name>'` | Typo, a write tool in the lite CLI, or a CLI older than the server | `--list-tools \| grep <part>`. Use the full CLI for writes. Pull the latest CLI. |
| `Error: Invalid JSON for tool '<name>'` | Shell quoting broke the JSON | Wrap the JSON in single quotes. Escape inner double quotes: `'{"query": "hello \"world\""}'`. |
| `"error": "Invalid or expired confirmation token. …"` | The token is older than 5 to 10 minutes, or the arguments changed | Call again without a token to get a new one. |
| A timeout or a long wait | Large `limit`, or an AI tool | Lower `limit`. AI tools can take a while; each request times out after 120 seconds. Run slow calls as separate commands rather than one batch. |
| Empty results | The data is not there yet, or the query is too narrow | Try other names (`APT29`, `Cozy Bear`). Check that the article has entities with `get_entry`. Run `get_dashboard_stats` to see what is loaded. |

---

## Extending the CLI

Tools live on the server, in `backend/app/tools/`. The CLI keeps a copy of each tool's name, description and parameters in its `TOOLS` dict, and refuses any name that is not in it. So a new tool needs two steps: register it on the server, then regenerate the CLIs.

### Adding a New Tool

1. **Write the tool** in a module under `backend/app/tools/` with the `@_tool` decorator:

   ```python
   # backend/app/tools/my_module.py
   import uuid

   from sqlalchemy.ext.asyncio import AsyncSession

   from app.tools import _tool


   @_tool(
       name="my_new_tool",
       description="What this tool does, in one or two sentences.",
       input_schema={
           "properties": {
               "param1": {"type": "string", "description": "…"},
               "param2": {"type": "integer", "default": 10},
           },
           "required": ["param1"],
       },
       mutating=True,  # set when the tool changes data
   )
   async def _my_new_tool(db: AsyncSession, user_id: uuid.UUID, param1: str, param2: int = 10) -> dict:
       return {"ok": True}
   ```

   `mutating` defaults to `True` for tools in `write.py` and `delete.py`, and `False` everywhere else. Set it yourself in any other module if the tool changes data, because it decides read-only blocking and lite membership.

2. **Import a new module** in the import block at the bottom of `backend/app/tools/__init__.py`. Existing modules are already imported.

3. **If only admins should run it**, add the name to `ADMIN_TOOLS` in `backend/app/tools/__init__.py`. Do this when the matching web API is admin-only, or the tool changes data for everyone (merges, feed pool changes, automation rules, extraction curation).

4. **Regenerate the CLIs** (see below). Then update `intelfeed-skill/SKILL.md` and, for read tools, `intelfeed-lite-skill/SKILL.md`.

5. **Run the guard tests**: `pytest tests/test_tool_registry_sync.py` from `backend/`. It checks that every mutating tool is in the full CLI's `WRITE_TOOLS`, that the lite CLI has no write tools, that `intelfeed-mcp/registry.json` matches the registry, that schema enums (entity types, rule formats, TLP, triggers, feed types, relationship verbs) match their sources, and that each handler's signature matches its schema.

### Keeping CLI in Sync with Backend

`scripts/dev/sync_skill_clis.py` rewrites three things from the registry: the `TOOLS` dict in both CLIs, the `WRITE_TOOLS` list in the full CLI, and `intelfeed-mcp/registry.json`. The rest of each CLI file is left alone.

```bash
# From the repo root, with the stack running and the CLI login variables set
INTELFEED_API_URL=http://localhost:8000 python3 scripts/dev/sync_skill_clis.py

# Report drift without changing anything (exits 1 if anything is out of date)
python3 scripts/dev/sync_skill_clis.py --check

# Use a saved registry file instead of the live server
python3 scripts/dev/sync_skill_clis.py --from-file intelfeed-mcp/registry.json
```

The sync script reads `/api/tools/tools` from the server. If you leave out `INTELFEED_API_URL`, it uses `http://localhost:8000`.
