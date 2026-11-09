---
name: intelfeed
description: "Interact with the running IntelFeed platform via its CLI tool. Use this skill whenever the user wants to query, search, analyze, or manage data in their IntelFeed instance — searching entries, looking up threat actors or malware, extracting TTPs/CVEs, generating detection rules, pivoting across entities, managing campaigns, feeds and automation rules, curating entity links, or working the priority queue, story threads, observables/IOC ledger, ransomware leak-site victims, My Stack exposure and intel reports. Also trigger on questions IntelFeed could answer — 'what's trending', 'show me recent entries about X', 'who is APT29', 'generate a Sigma rule for this article', 'what should I read today' — or on how IntelFeed itself works. Even if the user doesn't mention IntelFeed explicitly, use this skill when the question is about threat intelligence data, feed entries, detection rules, or security entities that live in the platform."
---

# IntelFeed Skill

You have access to a running IntelFeed instance via a CLI tool. The user is a security engineer who monitors the full threat landscape — not scoped to a single enterprise. They work across threat intelligence and detection engineering — tracking adversaries, analyzing attack techniques, and building detection content. Your output must be technical, detailed, and precise. Never fabricate data points — if IntelFeed returns it, report it accurately. If you're unsure about something, search the web or ask the user rather than guessing.

## How to Use the CLI

The CLI lives at `~/.claude/skills/intelfeed/scripts/intelfeed_cli.py` (the skill is installed under your home directory at `~/.claude/skills/`). Always use the `~/` home-relative path so it resolves regardless of your current working directory — do not use a project-relative `.claude/...` path. Zero external dependencies — just Python 3.12+.

```bash
python3 ~/.claude/skills/intelfeed/scripts/intelfeed_cli.py <tool_name> '<json_args>'
```

It requires three environment variables (already configured):

- `INTELFEED_API_URL` — Base URL of the IntelFeed API
- `INTELFEED_USERNAME` — Username for authentication
- `INTELFEED_PASSWORD` — Password for authentication

### Batching for Efficiency

The CLI supports multiple tool calls in a single invocation. When you need data from independent tools, batch them into one command — this is faster and reduces round-trips.

```bash
# BAD: Two separate invocations
python3 ~/.claude/skills/intelfeed/scripts/intelfeed_cli.py search_entries '{"query": "APT29"}'
python3 ~/.claude/skills/intelfeed/scripts/intelfeed_cli.py search_entities '{"query": "APT29"}'

# GOOD: One invocation, both results returned together
python3 ~/.claude/skills/intelfeed/scripts/intelfeed_cli.py search_entries '{"query": "APT29"}' search_entities '{"query": "APT29"}'
```

Batch when the calls are independent (don't need each other's output). Run sequentially when a later call depends on an earlier result (e.g., you need an entity ID from search before you can pivot).

### Tool with no arguments

```bash
python3 ~/.claude/skills/intelfeed/scripts/intelfeed_cli.py get_dashboard_stats
```

## Search Query Language

`search_entries` and `search_unified` run the **full** query language — every filter below is executed, not just the text terms. 18 article fields and 122 intelligence fields.

`search_entities` is the exception: it is plain text over entity names, aliases, catalogued IDs and prose. A `field:value` string handed to it is matched literally and finds nothing — put filters through `search_unified` (or `search_entries` when you only want the articles).

Prefer a precise filter over free text. `cve.kev:true` is a fact; "known exploited" is a guess about what an article happened to say.

### Entry Filters

- `title:` — Entry title (`title:"zero day"`)
- `content:` — Entry body text
- `author:` — Author name
- `feed:` — Feed name, substring (`feed:"Krebs on Security"`)
- `category:` — The folder a feed lives in (`category:"Vendor Blogs"`)
- `tag:` — Tag name (`tag:critical`)
- `type:` — Feed type: `rss`, `atom`, `youtube`, `podcast`, `reddit`, `github_repo`, `github_releases`, `github_advisories`, `nvd`, `mastodon`, `bluesky`, `telegram`, `web_scraper`
- `date:` — `>`, `<`, `>=`, `<=`, or range (`date:>2026-03-01`, `date:2026-01..2026-03`)
- `is:` — State: `starred`, `unread`, `read`, `bookmarked`, `noted`, `muted`, `translated`, `image`
- `media:` — Media type: `audio`, `video`, `image`, `document`
- `lang:` — Language code (`lang:en`)
- `url:` — Article link contains (`url:github.com`)
- `words:` — Article length (`words:>1500`, `words:500..2000`)
- `sort:` — `relevance`, `newest`, `oldest`, `radar`, `title_asc`, `title_desc`, `shortest`, `longest`

### Signal & Source Filters

- `signal:` — Why the signal engine ranked an entry. All 16 values, by family — coverage: `under_reported`, `source_convergence`, `feed_echo`; severity: `kev_added`, `epss_high`, `epss_jump`, `weaponized_poc`, `critical_cvss`; novelty: `novel_entity`, `entity_resurgence`, `new_pairing`, `scoop`; interest: `pir_match`, `correlation_event`; content: `detection_content`, `research_depth`
- `sector:` — Sector mentioned in the article (`sector:healthcare`)
- `feed.reliability:` / `feed.timeliness:` / `feed.relevance:` — Source Admiralty grade, exact letter (`feed.reliability:B`; ranges are not supported)

**`sort:radar`** orders by the signal engine's priority score — the same ranking as the Priority Queue. It reads from PostgreSQL, so it drops unscored entries and ignores free-text terms. Use it to read a *filtered queue*, not to rank a text search.

### Intelligence Filters

- `cve:` — CVE identifier (`cve:CVE-2025-5777`), plus `cve.severity:`, `cve.cvss:>9.0`, `cve.kev:true`, `cve.epss:>0.5`, `cve.epss_percentile:>0.9`, `cve.poc:>0`, `cve.exploit:kev`, `cve.product:fortios`
- `cwe:` — Weakness by ID or name (`cwe:CWE-416`, `cwe:"use after free"`), plus `cwe.abstraction:Base` (Pillar/Class/Base/Variant), `cwe.kind:weakness|category`, `cwe.usage:Allowed` (Allowed, Allowed-with-Review, Discouraged, Prohibited), `cwe.parent:CWE-664`, `cwe.deprecated:false`
- `observable:` (alias `ioc:`) — IOC ledger value or label (`observable:185.174.100.5`), plus `observable.kind:` (`ipv4`, `ipv6`, `domain`, `url`, `uri_path`, `email`, `ja3`, `ja4`, `cert_fingerprint`, `md5`, `sha1`, `sha256`, `cmdline`, `registry`, `path`, `mutex`, `named_pipe`, `service_name`, `user_agent`, `script`), `observable.role:` (`c2`, `delivery`, `payload`, `phishing`, `exfil`, `exploit`, `scanning`), `observable.status:active|aging|expired`, `observable.infra:`, `observable.reports:>0` / `observable.feeds:>0` (corroboration counts — distinct reporting articles / distinct indicator feeds)
- `ttp:` — MITRE technique (`ttp:T1059*`), plus `ttp.tactic:`, `ttp.platform:Windows`, `ttp.data_source:process`, `ttp.domain:enterprise|mobile|ics`, `ttp.subtechnique:true`, `ttp.deprecated:false`
- `threat_actor:` — Threat actor (`threat_actor:APT29`), plus `threat_actor.country:`, `threat_actor.motivation:espionage`, `threat_actor.sector:`, `threat_actor.type:`, `threat_actor.mitre:G0016`
- `malware:` — Malware family, plus `malware.type:`, `malware.sector:`, `malware.mitre:S0367`
- `tool:` — Tool name, plus `tool.type:`, `tool.platform:`, `tool.mitre:`
- `country:` — Country name, plus `country.region:`, `country.iso:RU`
- `sector:` — Targeted industry sector by name or alias (`sector:healthcare`, `sector:banks`), plus `sector.slug:financial-services`. Articles link to a sector only when the AI judged it *targeted* — a prose mention is not enough.
- `vendor:` / `product:` — plus `vendor.type:`, `product.type:`, `product.vendor:Cisco`
- `mitigation:` — Mitigation name or MITRE ID
- `rule:` — Detection rule title, plus `rule.type:sigma`, `rule.severity:`, `rule.data_source:sysmon`, `rule.tactic:persistence`, `rule.tag:`, `rule.draft:`, `rule.license:`
- `campaign:` — Campaign name, plus `campaign.status:active|monitoring|closed`
- `intel_report:` — Report title, plus `intel_report.status:`, `intel_report.type:`, `intel_report.tlp:amber`
- `ransomware_victim:` — Victim organization, plus `ransomware_victim.sector:`, `ransomware_victim.domain:`, `ransomware_victim.group:lockbit`
- `pir:` — Priority Intelligence Requirement title, plus `pir.priority:`, `pir.category:`

**Catalogue suffixes** work across entity types — useful for curation and triage work:

- `<entity>.articles:>100` — how much has been written about it (`ttp`, `threat_actor`, `malware`, `country`, `sector`, `tool`, `vendor`, `product`, `mitigation`, `cwe`, `observable`/`ioc`)
- `<entity>.seen:>2026-01-01` / `<entity>.first_seen:>2026-06` — recency, same ten types (note: **not** `cve.*` — CVEs carry `.review` and `.via` only)
- `<entity>.review:true` / `<entity>.via:ai_extraction` — extraction provenance (`threat_actor`, `malware`, `cve`, `ttp`, `tool`)

### Operators

- `AND` — Both conditions (implicit between adjacent terms)
- `OR` — Either condition
- `NOT` — Exclude (`NOT type:youtube`)
- `*` — Wildcard (`ttp:T1566*`, `threat_actor:APT*`)
- `"..."` — Exact phrase (`"device code phishing"`). On entity values, quotes force an exact, case-sensitive match and skip alias resolution — use unquoted values unless you mean that.
- `()` — Grouping (`(ransomware OR malware) AND type:rss`)
- `>`, `>=`, `<`, `<=`, `..` — Comparison and inclusive range (`cve.cvss:>9.0`, `date:2026-01..2026-03`)

### Value Types

- **Boolean** (`cve.kev`, `ttp.subtechnique`, `rule.draft`, `<entity>.review`): `true`/`false`. An unparseable value filters nothing.
- **Array** (`rule.data_source`, `rule.tactic`, `rule.tag`, `ttp.platform`, `ttp.data_source`, `threat_actor.sector`, `malware.sector`, `tool.platform`): substring match against the joined elements, so `rule.data_source:process` finds "Process Creation".
- **Date** (`<entity>.seen`, `<entity>.first_seen`): `YYYY-MM-DD` or `YYYY-MM`; a bare value means "on or after".
- **Text**: case-insensitive substring, aliases included.

### Example Queries

```
ransomware type:rss sort:newest
title:"zero day" AND tag:critical
threat_actor:APT29 AND ttp.tactic:initial-access
is:starred NOT type:youtube

# Vulnerabilities that are catalogued as exploited AND likely to be attacked
cve.kev:true cve.epss:>0.5

# The signal engine's own under-covered queue, in its own ranking
signal:under_reported sort:radar

# Detections that run on telemetry the user already collects
rule.data_source:sysmon rule.tactic:persistence

# Windows techniques detectable from process telemetry
ttp.platform:Windows ttp.data_source:process

# Leak-site monitoring
ransomware_victim.group:lockbit ransomware_victim.sector:manufacturing

# Curation backlog: AI-extracted actors with enough coverage to be worth reviewing
threat_actor.via:ai_extraction threat_actor.articles:>10

(phishing OR "social engineering") AND date:>2026-03-01
```

### Gotchas

- **`search_entities` does not parse filters.** It is a text search. `cve.kev:true` sent to it returns nothing at all, not an error — use `search_unified` for anything with a colon in it.
- **Field names are lowercase.** `Actor:APT29` is not a filter — it becomes free text. The actor field is `threat_actor:`, not `actor:`.
- **Multi-word values need quotes.** `threat_actor:Cozy Bear` parses as `threat_actor:Cozy AND Bear`.
- **Free text cannot be negated.** Meilisearch has no term exclusion, so `ransomware NOT phishing` behaves like `ransomware`. `NOT` works on field filters only.
- **`OR` between two entry-scoped PostgreSQL filters silently means AND.** `signal:kev_added OR signal:scoop` returns entries with *both* signals, not either — a plausible small number rather than an error. Affects `signal:`, `sector:`, `url:` and `is:translated`/`is:image`. `is:muted` does not participate in OR at all — neither the union nor a reliable intersection. `feed:`, `category:` and the source grades OR correctly. Issue the two queries separately and merge them yourself.
- **A negated PostgreSQL filter only subtracts from an entry-ID set.** `NOT signal:feed_echo` removes its matches from a set that an *entity* filter or another *entry-scoped PostgreSQL* filter established. A bare text term or an index filter (`tag:`, `type:`, `date:`…) builds no such set, so the negation is silently dropped — `ransomware NOT signal:kev_added` returns all 9,221 ransomware entries unchanged. Alone, it matches everything.
- **An entity AND-group inside an OR returns nothing.** `(threat_actor:APT29 AND threat_actor.country:Russia) OR threat_actor:APT28` yields 0 even though each side matches on its own.
- **Feed grades are exact.** `feed.reliability:B` matches grade B only; `>B` is not supported and ungraded feeds match nothing.
- **No stemming and no regex.** `run` does not match `running`; only `*` wildcards, no character classes. Wildcards work in field *values* only — including entry fields (`tag:apt*`, `type:you*`, `feed:NVD*`, `signal:kev*`) — but not in bare text: a trailing `*` is dropped and one in the middle splits the word.

### Reading Search Results

`search_entities` and `search_unified` tag every entity with **`match_kind`**:

- **`direct`** — the query hit the entity's own identity: its name, an alias, or its catalogued ID (`T1059`, `CVE-2025-5777`, `G0016`). Results from an explicit field filter are always direct.
- **`mention`** — the query hit something the entity merely *says*: a description, tag, tactic, or rule body.

Searching "lockbit" returns the LockBit group as `direct` alongside dozens of actors and YARA rules whose prose cites LockBit as `mention`. **Lead with the direct matches.** Treat mentions as context, and never report a mention as if it were the entity the user asked about.

#### Notes

`search_entities` and `search_unified` also return the user's own writing, as `"type": "note"`. Both note tables come back under that one type, told apart by `note_source`:

- **`note`** — a note on an article (`entry_id` + `entry_title` set) or a standalone one (both null). Also carries `is_pinned`.
- **`entity_note`** — a note on an actor, malware, CVE, TTP, campaign, vendor or product. Carries `entity_type`, `entity_id`, `entity_name` (the resolved subject) and `note_type`. Its title is optional and falls back to `"Note on {subject}"`.

`description` is a ~190-character window **centred on the match**, not the note's opening — so quote from it directly rather than assuming it is a summary.

Notes have their own filters, which reach both tables at once (they are entity filters, so run them through `search_unified` / `search_entries`, not `search_entities`):

```
note:fortibleed          # Title or body
note.tag:followup        # By tag
note.type:analysis       # annotation | analysis | action_taken | false_positive | context
note.about:cve           # Notes on entities of that kind (threat_actor, malware, cve, ttp, campaign, vendor, product)
note.about:entry         # Notes on articles
note.about:standalone    # Notes attached to nothing
note.pinned:true         # Pinned notes
```

`note.type:` and an entity value for `note.about:` only apply to entity notes; `note.pinned:` and `note.about:entry`/`:standalone` only to the other table. Each excludes the other rather than matching all of it, so some combinations are empty by design (`note.pinned:true note.about:cve` can never match). A `note.about:entry` query also returns the articles the notes hang off.

**Treat notes as the user's own prior work, and say so when you use one.** If a note already answers the question, lead with it and attribute it ("your note on CVE-2026-20262 says…") rather than re-deriving the answer from articles. Notes are instance-wide, not per-user, so a note may have been written by a colleague — don't assert the user wrote it unless the result says so.

Article counts come back as `total`. On queries that read from PostgreSQL — `sort:radar`, entity-only queries, or a very large linked-entry set — that number is exact; otherwise it is a Meilisearch estimate. Don't present an estimate as a precise figure.

## Chaining Tool Calls

The real power of IntelFeed is chaining multiple queries together to build a complete picture.

**Example: "What should I read right now?"**

1. `get_priority_queue '{"limit": 20}'` — the Priority Queue itself: unread, signal-ranked, threads folded into one row each
2. `get_story_thread '{"slug": "<slug>", "include_members": true}'` — for any thread row, read the spine before the articles
3. `get_daily_summary` — the day's cached briefing, if one has been generated
4. `get_correlation_events '{"unread_only": true}'` — what the engine noticed while the user was away

Lead with the thread spines, not a flat list of headlines — a thread row stands for a whole story, not one article.

**Example: "What do we know about APT29?"**

1. `search_entities '{"query": "APT29"}'` — find the threat actor entity (plain text; `match_kind: direct` is the actor itself)
2. `get_threat_actor '{"actor_id": "<id>"}'` — full profile
3. `pivot_entity '{"entity_type": "threat_actor", "entity_id": "<id>", "min_tier": "moderate"}'` — co-occurring TTPs, malware, CVEs, ranked by strength
4. `get_entity_graph '{"entity_type": "threat_actor", "entity_id": "<id>"}'` — the asserted relationships, which are claims rather than co-occurrence
5. `search_entries '{"query": "threat_actor:APT29 sort:newest", "limit": 5}'` — recent coverage

Then synthesize everything into a coherent briefing. Say which parts are claims and which are co-occurrence.

**Example: "Analyze this article for threats"**

1. `get_entry '{"entry_id": "<id>"}'` — read it, with everything already extracted at ingest
2. `run_ai_task '{"task_name": "entry_analysis", "entry_id": "<id>"}'` — the consolidated analysis (actors, malware, IOCs, link judgments) when the entry predates it
3. `extract_ttps '{"entry_id": "<id>", "use_ai": true}'` — techniques, regex plus AI mapping
4. `search_observables '{"query": "<domain or hash from the article>"}'` — is this infrastructure already in the ledger
5. `check_detection_gaps` — what of it lacks coverage
6. `generate_detection_rules '{"entry_id": "<id>", "rule_types": ["sigma", "splunk_spl"]}'` — draft rules

**Example: "What are we missing detection coverage for?"**

1. `check_detection_gaps` — uncovered techniques, per tactic
2. `get_analytics '{"metric": "detection_coverage"}'` — coverage stats
3. `get_telemetry_sources` — what the user can actually see
4. `check_telemetry_feasibility '{"rule_id": "<id>"}'` — whether a candidate rule would run on that telemetry
5. For each gap, `get_ttp '{"ttp_id": "<id>"}'` to understand the technique

**Example: "Analyze this campaign's coverage"**

1. `get_campaigns` — list campaigns to find the right one
2. `get_campaign_timeline '{"campaign_id": "<id>"}'` — chronological entries
3. `get_campaign_detection_gaps '{"campaign_id": "<id>"}'` — covered vs library_only (rule exists, telemetry doesn't) vs real gaps
4. `get_campaign_attack_layer '{"campaign_id": "<id>"}'` — Navigator layer
5. `generate_campaign_report '{"campaign_id": "<id>"}'` — draft the report

**Example: "What's my exposure?"**

1. `list_watches '{"mode": "stack"}'` — the vendors and products the user has declared they run
2. `get_stack_exposure` — CVEs hitting that stack, ranked by exposure lift (KEV / EPSS / weaponization)
3. `get_cve '{"cve_id": "CVE-…"}'` — the affected-product detail behind a row
4. `create_intel_report '{"title": "…", "template_type": "exposure_report", "entity_ids": [...]}'` — write it up

**Example: "Did this indicator show up before?"**

1. `get_observable '{"observable": "185.174.100.5"}'` — kind, role, confidence with decay, sighting count, how it got into the ledger
2. `search_entries '{"query": "observable:185.174.100.5 sort:newest"}'` — the articles it was seen in
3. `search_observables '{"kind": "domain", "role": "c2", "status": "active"}'` — neighbouring infrastructure of the same role

Regex never creates a ledger row — everything in there arrived through a judgment door, so absence means "not judged", not "not mentioned".

**Example: "What should I triage first today?"**

1. `get_triage_queue '{"days": 1}'` — priority-scored entries for the window
2. `get_requirement_coverage` — which PIRs are going stale
3. `get_trending_entities '{"entity_type": "threat_actor"}'` — what is moving
4. `check_requirement_match '{"entry_id": "<id>"}'` — why a given entry matters to a PIR

**Example: "Set up monitoring for ransomware campaigns"**

1. `create_requirement '{"title": "Ransomware Campaigns", "keywords": ["ransomware", "extortion", "double extortion"]}'`
2. `get_automation_templates` — start from a template rather than a blank rule
3. `create_automation_rule '{"name": "Tag ransomware articles", "trigger_type": "on_new_entry", "actions": [...]}'` — trigger types carry the `on_` prefix; a rule created with any other spelling never fires
4. `test_automation_rule '{"rule_id": "<id>", "entry_id": "<id>"}'` — dry-run before enabling it

**Example: "This entity is linked to articles it has nothing to do with"**

1. `list_entity_links '{"entity_type": "malware", "entity_id": "<id>", "limit": 50}'` — the actual edges, with provenance
2. `report_false_positive '{"entity_type": "malware", "entity_id": "<id>", "entity_value": "<matched name>", "scope": "alias", "source_entry_id": "<id>"}'` — unlink at the right scope: `entry`, `alias`, `entity` or `word`
3. `get_entity_link_stats` — check the held-match queue afterwards
4. `list_extraction_entities '{"status": "review"}'` / `confirm_extraction_entities` — clear the AI-extraction review backlog while you are in there

**Example: "Here's an advisory / a PDF / a list of URLs — get it into IntelFeed"**

1. `ingest_text '{"text": "<pasted body>", "title": "…"}'` for a paste, `ingest_file '{"filename": "report.pdf", "content_base64": "…"}'` for a file, or `ingest_batch '{"urls": [...]}'` for several links — each returns a `batch_id`. Pass `is_ioc_list: true` when the content is one indicator per line
2. `get_ingest_batch '{"batch_id": "<id>"}'` — poll until `summary.status` is `complete`; it names the entry each item produced and why any item was skipped (duplicate, no_text, unsupported)
3. `get_entry '{"entry_id": "<id>"}'` — the pipeline and one-pass analysis run afterwards like any polled entry, so read back what was extracted
4. `search_observables` / `check_detection_gaps` on what came out, same as any other article

**Example: "How does IntelFeed actually do X?"**

1. `list_documentation_pages` — see what the deployment ships
2. `search_documentation '{"query": "story threads"}'` — find the page
3. `get_documentation_page '{"slug": "story-threads"}'` — read it and cite the page

Answer platform questions from the docs, not from memory.

## Available Tools

196 tools. Names in **bold** are the CLI tool names. `⚠` marks a tool that needs an **admin** account; `🔒` marks one that runs a **confirmation-token flow** — the first call returns a prompt and a token, which you must show the user and only re-send after they explicitly approve.

Everything that creates, changes or deletes data is refused outright when `INTELFEED_READ_ONLY` is set on the environment — that gate is in the CLI itself, not in your instructions.

### Search & Discovery (4 tools)

- **search_entries** — Articles, running the full query language (query, limit, offset, sort). `offset` pages through large result sets; `sort` accepts any `sort:` value including `radar`
- **search_entities** — Plain-text search across all intelligence entity types **and the user's analyst notes** (query, limit). Each result carries `match_kind`; `field:value` filters do not work here
- **search_unified** — Articles and entities in one call, with entity filters constraining the articles (query, limit). Use this for anything with a colon in it
- **get_search_facets** — Feed types, categories, and top tags — what's in the system, before you search it

### The Reading Queue (7 tools)

- **get_priority_queue** — The Priority Queue page as data: unread entries over the radar threshold, signal-ranked, with story threads folded into single rows (limit, unread_only, with_threads, cursor)
- **get_triage_queue** — Priority-scored entries for review over a window (days, limit). Uses the signal engine when `signal_engine_surface` is on, else the legacy composite heuristic
- **get_story_threads** — Unfolding stories assembled from the articles covering them, re-reports folded underneath (status, limit)
- **get_story_thread** — One thread: its spine (a beat per wave of coverage), members with roles (origin/beat/echo), entities and outlets (slug, include_members)
- **get_daily_summary** — The cached AI daily briefing for a day, or null (date). Read-only — never generates one
- **get_entry_story** — Follow-ups and precursors to an entry, chained through shared strong entities in a ±30 day window (entry_id)
- **get_similar_entries** — Nearest neighbours from the embedding index, falling back to shared-entity overlap when the entry isn't embedded (entry_id, limit)

### Workbench Boards (7 tools)

- **get_threat_board** — The Threats board: actors/malware and exploited CVEs ranked by distinct stories over a window, each with lead headline, cached brief, sources, handled state and (CVEs) exposure lift + detection posture (window: 7d/14d/30d, facet: threats/vulns/all, limit, min_attention, include_handled)
- **get_coverage_workspace** — One threat's recent articles and extracted behaviours, each with its quote, the telemetry it needs and whether enabled telemetry sees it; `below_line` = a sourcing gap (entity_type: threat_actor/malware/cve/ttp, entity_key, window)
- **get_entity_whats_new** — An entity's latest developments: novelty and severity signals on its recent articles (entity_type, entity_id, days, scoped)
- **list_intel_profiles** — The instance's intel profiles: named scopes (a customer, a portfolio) of regions, sectors and technology (limit, offset)
- **get_intel_profile** — One intel profile with resolved country names and sector labels (profile_id)
- **get_profile_threat_surface** — Actors and malware active against a profile's regions x sectors, with why each matched (profile_id, limit)
- **list_tags** — Every tag with entry counts; shared list, counts as the caller sees them

### Entries & Reader State (20 tools)

- **get_entry** — Fetch an entry with full content and every extracted entity type (entry_id)
- **get_feed_entries** — List recent entries from a feed (feed_id, limit)
- **mark_entry_read** — Mark an entry read or unread for the current user (entry_id, read)
- **mark_all_read** — Bulk mark-read, optionally scoped to a feed or category (feed_id, category_id). Unscoped, it marks *everything* — confirm first
- **star_entry** — Set/unset the star (entry_id, starred)
- **bookmark_entry** — Set/unset the bookmark (entry_id, bookmarked)
- **bulk_entry_action** — One state action over many entries: read/unread/star/unstar/bookmark/unbookmark/hide (entry_ids, action)
- **add_tag** — Tag an entry with a new or existing tag (entry_id, tag_name)
- **translate_entry** — Translate an entry via the LibreTranslate sidecar and cache it on the row (entry_id, target)
- **ingest_url** — Ingest an arbitrary web page as a manual entry, running the full pipeline (url, title). Errors if the URL was already ingested
- **ingest_text** — Ingest pasted text (a report body, an advisory, a chat log, an indicator dump) as one manual entry under Manual Uploads; set `is_ioc_list` for one-indicator-per-line pastes so they go through the curated indicator-list door (text, title, source_url, is_ioc_list)
- **ingest_file** — Ingest one file (PDF, DOCX, TXT, MD, HTML, CSV, EML, ZIP, …) given as base64; a .zip expands into one entry per member (filename, content_base64, title, is_ioc_list)
- **ingest_batch** — Ingest many URLs and/or text blobs in one batch; a github.com/owner/repo link becomes one entry per file with no feed created (urls, texts, label, is_ioc_list)
- **get_ingest_batch** — Per-item status of a batch (queued / parsing / created / expanded / duplicate / no_text / unsupported / too_large / failed) and the entry id each item produced; poll until `summary.status` is `complete` (batch_id)
- **create_saved_search** — Save a query-language string to the reader sidebar (name, query, display_name)
- **list_saved_searches** — This user's saved searches with unread/total counts
- **delete_saved_search** — Delete one of this user's saved searches (search_id)
- **create_share_link** — Create (or return) this analyst's public share link for an entry (entry_id, ttl_days)
- **get_share_link** — This analyst's active share link for an entry, or null (entry_id)
- **revoke_share_link** — Deactivate this analyst's share link (entry_id)

### Entity Lookups (18 tools)

- **get_threat_actor** — Actor profile: aliases, type, motivation, origin country, targeted sectors, TTPs, article_count (actor_id)
- **get_malware** — Malware family profile with aliases, type, sectors, associated actors (malware_id)
- **list_sectors** — The 21-sector victim-industry vocabulary with article, targeting-actor/malware and 90-day victim counts (search, sort_by, limit)
- **get_sector** — Sector victimology profile: who targets it (reported vs asserted), campaigns, leak-site victims, country cross-tab, intel profiles, recent articles (sector — UUID or slug, window_days)
- **who_targets_sector** — Actors and malware ranked by articles describing them hitting the sector, plus asserted targets-sector claims with source (sector, limit)
- **sector_victims** — Leak-site victims in a sector: totals, 12-month series, top groups, victim countries, recent disclosures (sector, window_days, limit)
- **get_cve** — CVSS/EPSS, KEV status, PoC and Metasploit availability, NVD affected vendor/product links, CWE assignments (cve_id — UUID or CVE-YYYY-NNNNN)
- **get_cwe** — A MITRE CWE weakness: abstraction level, parent and lineage, mapping guidance, catalog mitigations, linked CVEs (cwe_id)
- **get_ttp** — ATT&CK technique with tactic, platforms, data sources, linked articles (ttp_id — UUID or T1059.001)
- **get_observable** — One IOC ledger row by UUID or value: kind, role, confidence with decay state, sightings, provenance (observable, kind)
- **search_observables** — Search the observables ledger by substring, kind, role, lifecycle status, capture door, dual-use tag, review flag, confidence floor and report-count floor (query, kind, role, status, captured_by, infra_tag, needs_review, min_confidence, min_reports, limit)
- **get_entity_infrastructure** — An actor's / family's / campaign's / tool's observables in two tiers: claimed (attribution edges with evidence and trust tier) and reported alongside (co-reported in the same articles, newsletters and list files excluded) (entity_type, entity_id, limit)
- **export_observables** — A filtered ledger slice as EDL lines, CSV rows or JSON, refanged, dual-use infra excluded unless asked (format, kind, role, status, min_confidence, min_reports, include_infra_tagged, query, limit)
- **promote_observable** — The analyst door: turn a staged candidate (or any value the article prints) into a ledger row sighted in that entry, with role and evidence (entry_id, kind, value, role, evidence, label)
- **update_observable** — Correct a ledger row: role, label, description, or pin its confidence so decay stops (observable_id, role, label, description, confidence_pinned)
- **deny_observable** ⚠ — Tombstone a value so it is never captured, sighted or exported again; works on a row by UUID or on any (kind, value) (observable_id, kind, value, reason)
- **get_enrichment_data** — Stored enrichment for a CVE, malware, actor or TTP (entity_type, entity_id)
- **get_entry_insights** — Actionable insights across an entry's entities (entry_id)

### Correlation & Graphs (6 tools)

- **pivot_entity** — One-hop co-occurrence pivot with strength tiers, ranking and a time window (entity_type, entity_id, limit_per_type, window_days, offset, sort, min_tier)
- **get_entity_graph** — Claims-only relationship graph around an entity — typed edges at confirmed/reported confidence, not raw co-occurrence (entity_type, entity_id, depth, window_days)
- **get_entity_timeline** — When an entity appeared in articles, chronologically (entity_type, entity_id)
- **get_entry_graph** — Relationship graph for every entity linked to one entry (entry_id)
- **get_temporal_clusters** — Entries sharing entities inside time windows — emerging campaigns (days, window_hours, min_shared, limit)
- **get_correlation_events** — Recent correlation events: coverage gaps, trending entities, campaign/requirement matches, actor–malware co-occurrence, feed staleness (limit, unread_only)

### Watchlist & My Stack (4 tools)

- **list_watches** — This user's watchlist rows with resolved names (mode: watch / mute / stack)
- **watch_entity** — Upsert a watch: `watch` boosts in priority scoring, `mute` suppresses, `stack` declares "I run this" (entity_type, entity_id, mode, boost)
- **unwatch_entity** — Remove the watch/mute/stack row (entity_type, entity_id)
- **get_stack_exposure** — The My Stack board: CVEs hitting the user's declared vendors/products, ranked by exposure lift

### Ransomware Landscape (4 tools)

- **get_ransomware_stats** — Leak Watch aggregates over a window: totals with WoW change, weekly series, top groups/sectors/countries (days)
- **get_ransomware_disclosures** — Reverse-chronological victim disclosures with filters (group, sector, country, watched_only, since, q, sort, limit, offset)
- **get_ransomware_victim** — One victim org: sector, country, first/last seen, listing groups, every disclosure (victim_id)
- **get_ransomware_group_victims** — Paginated victims disclosed by one group (actor_id, limit, offset)

### Glossary (4 tools)

- **list_glossary_terms** — Security glossary terms, filterable by category, name substring, system vs user (category, search, is_system, limit)
- **detect_glossary_terms** — Which glossary terms appear in an entry, with per-term counts (entry_id)
- **create_glossary_term** — Add a user term (name, category, description, maturity, long_description, technologies, search_terms)
- **delete_glossary_term** — Delete a user-created term; built-in system terms can't be deleted (term_id)

### Campaigns (12 tools)

- **get_campaigns** — List campaigns (status, limit)
- **get_campaign** — Full campaign: timeline, linked entries and entities, detection gaps (campaign_id)
- **get_campaign_timeline** — Linked entries by publication date (campaign_id)
- **get_campaign_attack_layer** — ATT&CK Navigator layer for the campaign's TTPs (campaign_id)
- **get_campaign_detection_gaps** — Telemetry-aware coverage: covered, library_only (rule exists but telemetry is missing), gaps (campaign_id)
- **suggest_campaign_entries** — Entries sharing entities with the campaign but not yet linked (campaign_id, limit)
- **export_campaign** — The complete campaign intel package: entries, every extracted entity type, linked entities, sourced rules (campaign_id)
- **create_campaign** — Create a campaign (name, description, status, tlp_marking)
- **update_campaign** — Partial update; statuses active/monitoring/closed/historical (campaign_id, name, description, status, tlp_marking, start_date, end_date, tags)
- **add_to_campaign** — Link an entry or an entity (campaign_id, entry_id | entity_type + entity_id, role)
- **remove_from_campaign** — Unlink an entry or entity; the object itself survives (campaign_id, entry_id | entity_type + entity_id)
- **delete_campaign** 🔒 — Delete a campaign and its links; entries and entities are untouched (campaign_id, confirmation_token)

### Detection Engineering (17 tools)

Rule formats across the platform: `sigma`, `splunk_spl`, `crowdstrike_ql`, `elastic_ql`, `kql`, `snort_suricata`, `yara`, `nuclei`, `panther`. AI generation covers all but nuclei and panther, which are import/validate-only.

- **get_detection_rules** — List rules, optionally by type (rule_type, limit)
- **get_detection_rule** — One rule with full content, provenance (repo/author/license/references), draft state and telemetry feasibility (rule_id)
- **get_detection_rule_versions** — Saved version snapshots, newest first (rule_id)
- **create_detection_rule** — Save a rule to the library as a **draft** (title, rule_type, rule_content, description, severity, entry_id, tags, references, source_entry_ids)
- **update_detection_rule** — Partial update; a content change snapshots a new version (rule_id, updates)
- **set_detection_rule_status** — Flip draft ⇄ published (rule_id, status)
- **rollback_detection_rule** — Restore content from a saved version number (rule_id, version)
- **convert_detection_rule** — AI-translate a rule into another rule language (rule_id, target_format, save)
- **delete_detection_rule** 🔒 — Delete a rule and its version history (rule_id, confirmation_token)
- **generate_detection_rules** — AI-generate rules from an entry's TTPs and store them as drafts (entry_id, rule_types)
- **validate_detection_rule** — Syntax validation with errors, warnings and suggestions (rule_type, rule_content)
- **build_detection_summary** — Full attack-chain and gap analysis over several entries (entry_ids, rule_formats, focus, include_existing)
- **check_detection_gaps** — Observed TTPs vs non-draft rules, per-tactic, with the uncovered list. TTP-only — CVEs are not part of it
- **check_telemetry_feasibility** — Whether rules are runnable given configured telemetry (rule_id)
- **get_telemetry_sources** — Configured log/telemetry sources and their coverage
- **get_attack_layer** — Navigator layer for one entry's TTPs, or for all observed techniques without entry_id (entry_id, title)
- **export_attack_layer** — Navigator layer JSON for visualization, with per-link confidence and source text (entry_id, title)

### Intelligence Requirements (9 tools)

- **get_requirements** — PIRs and their coverage status (status)
- **get_requirement_coverage** — Coverage summary by status, priority, category and staleness
- **check_requirement_match** — Run an entry through the real matching engine against active PIRs (entry_id)
- **create_requirement** — Create a PIR (title, description, priority, category, keywords, auto_match)
- **update_requirement** — Update a PIR (requirement_id, updates)
- **delete_requirement** 🔒 — Delete a PIR and its matches (requirement_id, confirmation_token)
- **fulfill_requirement** — Mark fulfilled, optionally linking the report that fulfilled it (requirement_id, report_id)
- **add_requirement_match** — Manually match an entry to a PIR (requirement_id, entry_id, relevance)
- **remove_requirement_match** — Unmatch an entry and decrement the count (requirement_id, entry_id)

### Intelligence Reports (10 tools)

Templates: `actor_profile`, `campaign_tracker`, `detection_report`, `exposure_report`, `flash_alert`, `landscape_report`. TLP 2.0 markings; legacy `TLP:WHITE` is accepted and normalized to `TLP:CLEAR`.

- **list_intel_reports** — Reports newest-updated first, section names only (status, template_type, limit, offset)
- **get_intel_report** — One report with every section's content (report_id)
- **create_intel_report** — Draft from a template with linked entries/entities (title, template_type, entry_ids, entity_ids, tlp_marking)
- **update_intel_report** — Update title, TLP, status or full content (report_id, updates)
- **generate_full_report** — AI-generated report from source entries; creates a draft and queues generation (title, template_type, entry_ids, focus, tlp_marking)
- **generate_campaign_report** — Same, sourced from a campaign's entries and entities (campaign_id, template_type, title, tlp_marking)
- **publish_report** — Save the current version and publish (report_id)
- **archive_intel_report** — Archive rather than delete (report_id)
- **delete_intel_report** ⚠🔒 — Delete a **draft** report; published/archived ones must be archived instead (report_id, confirmation_token)
- **export_report** — Export as markdown or HTML (report_id, format)

### Notes (8 tools)

- **list_notes** — Analyst notes (entry-attached and standalone), pinned first (entry_id, search, limit)
- **create_note** — Add a note to an entry; markdown is rendered and stored (entry_id, content, title)
- **update_note** — Update a note's markdown (and title) (note_id, content, title)
- **delete_note** — Delete a note; the entry is untouched (note_id)
- **list_entity_notes** — Notes on one intelligence entity, newest first (entity_type, entity_id, limit)
- **create_entity_note** — Add an analytical note to an entity (entity_type, entity_id, content)
- **update_entity_note** — Update an entity note's content (note_id, content)
- **delete_entity_note** — Delete an entity note (note_id)

### Feeds & Sources (12 tools)

Adapter types: `rss`, `atom`, `youtube`, `podcast`, `reddit`, `github_repo`, `github_releases`, `github_advisories`, `nvd`, `mastodon`, `bluesky`, `telegram`, `web_scraper`.

- **get_feeds** — Configured feeds with health and Admiralty grades (limit)
- **create_feed** — Subscribe to a feed of any adapter type (url, title, feed_type, category, adapter_config)
- **update_feed** ⚠ — Partial update; changing the URL resets fetch state (feed_id, url, title, category, is_muted, is_active, fetch_interval_minutes, reliability_rating, timeliness_rating, relevance_rating, …)
- **delete_feed** ⚠🔒 — Delete a feed **and all of its entries** (feed_id, confirmation_token)
- **refresh_feed** — Queue an immediate background fetch (feed_id)
- **list_categories** — Categories as a tree with direct feed counts
- **create_category** — Create a category, or return the existing one by that name (name)
- **get_feed_value** — Composite 0–100 contribution score per feed (days)
- **get_source_reliability** — Feeds ranked by extractions across every junction type plus rules generated (limit)
- **list_telegram_feeds** — Telegram feeds with adapter config: channel, last_seen_id, session, error state (limit)
- **discover_telegram_channels** — Channels the bootstrap account has joined, flagged by whether IntelFeed ingests them (session_name, only_unsubscribed)
- **add_telegram_feed** — Subscribe to a Telegram channel (channel, title, include_media, extract_forwards, session_name, …). Needs server-side Telegram login first

### Automation (12 tools)

Trigger types: `on_new_entry`, `on_keyword_match`, `on_cve_detected`, `on_correlation_event`, `on_schedule`, `on_manual`.

- **get_automation_rules** — List rules, optionally by label (label, limit)
- **get_automation_templates** — Pre-built rule templates with categories
- **get_automation_logs** — Recent execution logs (rule_id, limit)
- **create_automation_rule** — Trigger + conditions + actions (name, description, trigger_type, trigger_config, conditions, actions)
- **update_automation_rule** ⚠ — Partial update of any rule field (rule_id, …)
- **toggle_automation_rule** ⚠ — Flip enabled state and return the new one (rule_id)
- **test_automation_rule** ⚠ — Dry-run against one entry; actions are not executed (rule_id, entry_id)
- **run_automation_rule** ⚠ — Execute now, once per matching recent entry (rule_id, hours)
- **delete_automation_rule** ⚠🔒 — Delete a rule permanently; to just stop it, toggle it off (rule_id, confirmation_token)
- **list_webhook_presets** — Saved webhook presets; URLs and header values come back redacted (preset_type, limit)
- **create_webhook_preset** — Reusable URL + payload + headers for automation actions (name, url, payload, headers, preset_type, config)
- **delete_webhook_preset** ⚠ — Delete a preset; rules referencing it by id stop resolving (preset_id)

### Intelligence Extraction & AI Tasks (5 tools)

- **extract_ttps** — Regex technique matching, plus the `ttp_mapping` AI task when `use_ai` is set (entry_id, use_ai)
- **extract_cves** — CVE references from an entry, enriched from NVD (entry_id)
- **extract_threat_actors** — Actors via the consolidated `entry_analysis` task; may return the cached ingest-time analysis (entry_id)
- **extract_malware** — Malware families via the same consolidated task (entry_id)
- **run_ai_task** — Run a registered AI task against an entry (task_name, entry_id, force). Tasks include `article_summary`, `threat_assessment`, `detection_rules`, `entry_analysis`

These persist entities as a side effect, so they are gated as writes in read-only mode.

### Curation & Hygiene (17 tools)

Entry→entity autolinks (edges) and entity→entity relationships (claims) are separate layers — these tools work the edges, the claims ledger, and the AI-extraction review queue.

- **get_entity_link_stats** — Autolink health: links by entity type and provenance, held-match queue depth
- **list_entity_links** — Autolink junction rows across all seven tables, newest first (entity_type, entity_id, entry_id, source, confidence, search, days, limit, offset)
- **unlink_entity_from_entry** — Remove one entry→entity link (entity_type, entity_id, entry_id)
- **bulk_unlink_entities** ⚠ — Remove up to 500 links in one call (items)
- **report_false_positive** — Record autolinker noise and unlink at the chosen scope: entry, alias, entity or word (entity_type, entity_id, entity_value, scope, source_entry_id, reason)
- **get_extraction_stats** ⚠ — AI-created entity counts by type: needs-review, orphaned, likely-duplicate (window)
- **list_extraction_entities** ⚠ — AI-created entities with lifecycle status: linked, review, orphan or dupe (types, status, window, q, source_entry_id, sort_by, sort_order, limit, offset)
- **confirm_extraction_entities** ⚠ — Analyst sign-off: clear needs_review on AI-created entities (entity_type, ids)
- **list_entity_relationships** — Every relationship where an entity is source or target, with verb, confidence and provenance (entity_type, entity_id, relationship_type, include_rejected)
- **confirm_relationship** — Trust-ladder confirm: source becomes `analyst_confirmed` (relationship_id)
- **reject_relationship** — Trust-ladder reject: the row is kept so re-ingestion can't resurrect it (relationship_id)
- **delete_relationship** — Hard-delete a relationship. Prefer `reject_relationship` when the claim is wrong (relationship_id)
- **get_hygiene_feed** ⚠ — Chronological merge of link-validator and entity-maintenance logs (action, source, mode, origin, pending, since, limit, offset)
- **get_hygiene_stats** ⚠ — Hygiene counters: operating modes (shadow/apply) and pending advisories
- **list_review_groups** ⚠ — The Engine › Review queue, one row per entity with its proposal counts by kind (q, entity_type, action, domain, origin, limit, offset)
- **get_review_rows** ⚠ — The pending proposals behind a Review group, each with its id, reason and a context snippet from the article (entity_type, entity_id, action, origin, domain, limit, offset)
- **decide_proposals** ⚠ — Apply up to 1000 Review decisions in one call: `{id, decision: apply|dismiss|reclassify:<type>}`; duplicates settle server-side (decisions)

### Entity Writes & Merges (14 tools)

- **create_threat_actor** — Create an actor; the entity resolver folds it into an existing one on a name/alias hit (name, aliases, description, country, motivation)
- **create_malware** — Same for a malware family (name, aliases, description, malware_type)
- **update_entity_profile** — Update an entity's profile fields, per type (entity_type, entity_id, updates)
- **set_target_sector** 🔒 — Assert or withdraw that an actor or malware family targets a sector; an analyst claim on the target-sector junction that the nightly rollup never prunes (entity_type, entity_id, sector, action=add|remove)
- **link_entities** — Assert an analyst-grade relationship, validated against the semantic relationship matrix and auto-flipped into canonical direction (source_type, source_id, target_type, target_id, relationship_type, description, confidence, evidence_entry_ids)
- **merge_threat_actors** ⚠ — Merge a duplicate actor into another; `mode='shadow'` dry-runs it (target_id, source_id, mode, new_description, extra_aliases, reasoning)
- **merge_malware** ⚠ — Same, for malware families
- **merge_tools** ⚠ — Same, for tools
- **merge_vendors** ⚠ — Same, for vendors
- **merge_products** ⚠ — Same, for products
- **merge_entities** ⚠ — Merge duplicates of any one type into a keeper, by name or id; merged names become aliases (entity_type, keeper, merge)
- **remove_entity_aliases** ⚠ — Drop aliases by entity name or id; entries linked only through them are unlinked and the count recounted (entity_type, entity, aliases)
- **reclassify_entity** ⚠ — Move an entity to a different type (a "malware" that is really a tool, a product filed as a vendor), by id or name; with no target it merges into the same-named entity of the target type (source_type, source_id, source_name, target_type, target_id, target_name, mode, …)
- **delete_entity** ⚠🔒 — Delete any record: feed, entry, note, rule, campaign, automation rule, PIR, report, tag or intelligence entity, by id or name (entity_type, entity_id, name, confirmation_token)

Always dry-run a merge with `mode='shadow'` first and always pass `reasoning` — it is written into the audit trail.

### Documentation (3 tools)

- **list_documentation_pages** — Every docs page shipped with this deployment (slug, title, section, summary). Start here for "how does IntelFeed do X"
- **get_documentation_page** — Read one page in full as markdown (slug, e.g. `architecture`, `story-threads`)
- **search_documentation** — Full-text search across the docs with excerpts around each hit (query, limit)

### System & Analytics (3 tools)

- **get_dashboard_stats** — System-wide totals: entries, feeds, rules, counts for every entity type
- **get_analytics** — Platform analytics (metric: overview / trending / detection_coverage / velocity, entity_type, days)
- **get_trending_entities** — Top entities by mention count over a window (entity_type, days, limit)

## Error Recovery

When things go wrong, don't just report the error — try to work around it.

**API connection failures:** The Docker stack may not be running. Tell the user: "The IntelFeed API isn't responding — is the Docker stack running?" Do not retry the same call in a loop.

**Entity not found:** If `search_entities` returns no results, try `search_entries` with the same query — the entity may exist in article text but hasn't been extracted yet. Also try alternative names/aliases (APT29 = Cozy Bear = Midnight Blizzard = The Dukes = NOBELIUM).

**Empty extraction results:** The article may not contain structured indicators — check with `get_entry` whether it's a technical report or an opinion piece. Suggest `use_ai: true` if extraction was run without AI.

**Authentication errors (401):** The CLI handles token refresh automatically. If 401s persist, ask the user to check their `INTELFEED_USERNAME` and `INTELFEED_PASSWORD` environment variables.

**Permission errors (403):** The tool is admin-only (marked ⚠ above) and the account isn't an admin. Report what it would have done and stop — there is no non-admin path to the same change.

**`read-only mode: <tool> is a write action and is disabled`:** `INTELFEED_READ_ONLY` is set on the environment. That is a deliberate boundary, not a misconfiguration — do not work around it. Tell the user which tool was refused.

**A confirmation prompt instead of a result:** Tools marked 🔒 return a prompt and a `confirmation_token` on the first call. Show the user what will be deleted, wait for an explicit yes, then repeat the call with the token. Never re-send it on your own initiative.

## Filling Gaps with Web Search

IntelFeed data is only as complete as what's been ingested and extracted. When you notice gaps — missing context on a threat actor, a CVE with no enrichment, a technique with sparse coverage — supplement with web searches to give the user a complete picture.

- After querying IntelFeed, assess whether the results fully answer the question
- If an entity has sparse data (few articles, missing aliases), search the web for additional context
- For threat actors: look up recent campaigns, known tooling, and targeting patterns not yet in IntelFeed
- For CVEs: check for PoC availability, active exploitation status, and patch guidance
- For TTPs: find real-world examples, detection strategies, and atomic test cases
- Always clearly distinguish what came from IntelFeed data vs. what came from web research
- IntelFeed is the primary source of truth for what the user has tracked — web search fills in what hasn't been ingested yet

## How to Present Results

- **Accuracy is non-negotiable.** Every data point (CVSS scores, technique IDs, dates, attribution) must come directly from IntelFeed results or verified web sources. Never approximate or fabricate. If a field is missing, say so.
- **Focus on TTPs.** Adversaries rotate infrastructure constantly. TTPs are the durable intelligence. Always prioritize ATT&CK techniques, attack patterns, and behavioral detections. Build detections around what adversaries _do_, not ephemeral indicators.
- **Be technical.** Use proper terminology — MITRE ATT&CK IDs (T1059.001, not "PowerShell execution"), full CVE identifiers, CVSS vectors, TLP markings.
- **Structure for scannability.** Tables for entity comparisons. Headers to separate sections. Technique IDs inline with names.
- **Show your sources.** Note whether data came from IntelFeed (which feed/article) or web research. This matters for confidence assessment.
- **Link to IntelFeed.** When referencing entries or entities, include a clickable deep link using the `INTELFEED_API_URL` env var (the app and API share one address). Articles: `{API_URL}/?entry={entry_id}`. Entity profiles: `{API_URL}/workbench/{type}/{id}` — `threat_actor`, `malware`, `cve`, `cwe`, `ttp`, `tool`, `vendor`, `product`, `country`, `sector`, `mitigation`, `observable`, `campaign`. Detection rules: `{API_URL}/workbench/rule/{id}`. Reports: `{API_URL}/workbench/report/{id}`.
- **Flag gaps and suggest next steps.** After answering, proactively note actionable gaps: entities with sparse data, TTPs without detection rules, actors missing aliases that should be merged, unprocessed articles. Offer to fix them.
- **Detection rules must be deployable.** Include full rule content, log source requirements, expected false positive rate, and tuning notes.
- **Study existing rules before writing new ones.** Before generating a detection rule, use `get_detection_rules '{"rule_type": "<type>", "limit": 10}'` to pull existing rules of the same type. Read them to understand the query language conventions, field names, log source patterns, and formatting style already in use.
