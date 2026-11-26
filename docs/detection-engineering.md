# Detection Engineering

This is the technical reference for IntelFeed's detection rule features, for developers and detection engineers. After reading it you will know how rules are pulled out of articles, how they are checked, stored and versioned, how the Rules Library search works, how coverage is measured against your telemetry, and which API endpoints do what. For a how-to written for analysts, see [guide/detection-rules.md](guide/detection-rules.md).

## Table of Contents

1. [Lifecycle Overview](#lifecycle-overview)
2. [Rule Extraction](#rule-extraction)
3. [Rule Validation Engine](#rule-validation-engine)
4. [Data Model](#data-model)
5. [Detection Workbench](#detection-workbench)
6. [Rule Library](#rule-library)
7. [Detection Coverage Analysis](#detection-coverage-analysis)
8. [ATT&CK Catalog and Matrix](#attck-catalog-and-matrix)
9. [Export and Integration](#export-and-integration)
10. [Telemetry Sources and Feasibility](#telemetry-sources-and-feasibility)
11. [Mitigations and ATT&CK Integration](#mitigations-and-attck-integration)

---

## Lifecycle Overview

### End-to-End Flow

The full flowchart is in [diagrams/detection-engineering-rule-pipeline.md](diagrams/detection-engineering-rule-pipeline.md). In short:

```text
Article
  → extract rules (6 formats, no AI)
  → check syntax (invalid rules are dropped)
  → de-duplicate and store as a draft DetectionRule
  → review and edit in the rule editor (/workbench/rule/:id)
  → publish (every content edit saves a version)
  → coverage: covered / library_only / no_rule, against your telemetry
  → export (YAML, ZIP, ATT&CK Navigator layer)
```

### Key Principles

- **Extraction needs no AI.** It uses regex and parsers only.
- **Rules are stored as written.** Each format has its own syntax check.
- **Edits are versioned.** Changing a rule's content saves the old content as a version.
- **Rules point back to their article,** so you can see where a rule came from.
- **Rules inherit the article's TTPs and CVEs** (ATT&CK techniques and vulnerabilities).
- **Coverage depends on your telemetry.** A rule only counts if you collect the logs it needs.

---

## Rule Extraction

### Supported Formats

`backend/app/intelligence/rule_extraction.py` finds rules in six formats. CrowdStrike QL, Nuclei and Panther can be validated and stored but are never extracted from articles.

| Format | What it is | How it is found | Extractor |
|--------|------------|-----------------|-----------|
| **Sigma** (`sigma`) | Vendor-neutral YAML rules for log events | YAML with `title:`, `detection:` and `logsource:` | `_extract_sigma_rules()` |
| **Splunk SPL** (`splunk_spl`) | Splunk's search language | Code blocks that look like SPL; also plain-text lines starting `index=`, `search ` or `\| tstats` | `_extract_query_rules()` |
| **Elastic QL** (`elastic_ql`) | Elastic's EQL and ES\|QL query languages | EQL (`process where …`, `sequence by …`) or ES\|QL (`FROM logs-* \| …`) in code blocks; Elastic TOML rule files | `_extract_query_rules()`, `_extract_elastic_toml_rules()` |
| **KQL** (`kql`) | Kusto Query Language, used by Microsoft Sentinel and Defender XDR | Code blocks with a known Defender/Sentinel table or KQL-only syntax; Elastic TOML rules of type `query`, `threshold` or `new_terms` | `_extract_query_rules()`, `_extract_elastic_toml_rules()` |
| **YARA** (`yara`) | Pattern rules for matching files and memory | `rule <name> { … condition: … }` | `_extract_yara_rules()` |
| **Snort/Suricata** (`snort_suricata`) | Network intrusion-detection rules | One-line rules starting with an action and protocol | `_extract_snort_suricata_rules()` |

### When extraction runs

- At ingest, inside `extract_entry_intel_task`, when the feed has **Extract detection rules** (`extract_detection_rules`) turned on.
- On demand with `POST /entries/{id}/extract-detection-rules`.
- GitHub repository entries go through their own import path instead, which mirrors upstream rules with their repo, author and license.

### Extraction Algorithm

The entry point is `extract_rules_from_content()` (`backend/app/intelligence/rule_extraction.py:32`). It takes `text`, an optional `source_url`, and keyword arguments `html` and `article_title`.

- `text` is the article's plain text. HTML entities (`&gt;`, `&lt;`, `&amp;`) are decoded first, so a saved rule runs as written.
- `html` is the article's sanitized HTML. Code blocks are read from its `<pre>`/`<code>` tags, because the plain text has them flattened into prose.
- Every extractor runs. Each result is then checked with `validate_rule()`. Rules that fail are logged and dropped.
- Duplicates are dropped by `(rule_type, body)`, ignoring whitespace. The same query found in both the HTML and the plain text counts once.

Each rule comes back as a dict with `rule_type`, `title`, `rule_content`, `severity`, `tags`, `mitre_tactics` and `log_sources`.

### Per-Format Details

#### Sigma

- Read from fenced code blocks (any tag, `yaml` or `sigma`), from HTML `<pre>` blocks, or from the whole text if it looks like a Sigma file. Multi-document YAML is supported.
- The document must have `title`, `detection` and `logsource`.
- Severity comes from `level:`. Tactics come from tags like `attack.execution`, stored as the ATT&CK tactic slug (`execution`). Technique tags (`attack.t1059`) stay as tags only.
- The rule is re-saved as clean YAML.
- **The validator also requires `status:`.** A Sigma rule without it is dropped at extraction.

#### Splunk SPL

`_is_spl_query()` decides whether text is SPL. It accepts:

- `index=` plus a pipe, or text starting `search ` plus a pipe, or `| tstats` anywhere.
- A pipe into a common SPL command (`stats`, `where`, `eval`, `table`, `rex`, `dedup`, …) only if `index=`, `sourcetype=` or `source=` also appears. A bare pipe is not enough.

A `spl` or `splunk` code-block tag is a hint, not proof. Plain-text matches shorter than 30 characters are skipped.

#### KQL, EQL and ES|QL

These come **only from code blocks**, so a sentence that says "where" never becomes a rule.

- **KQL:** a table name, a pipe, and a tabular operator. The table must be a known Defender XDR or Sentinel table (`DeviceProcessEvents`, `SecurityEvent`, `SigninLogs`, …), or the query must use syntax SPL lacks (`| summarize`, `| project`, `ago(`, `=~`, `has`, `==`).
- **EQL:** `<category> where …`, `sequence [by …]`, or `join … [`. Stored as `elastic_ql`.
- **ES|QL:** `FROM <index> | WHERE/STATS/EVAL/KEEP/…`. Stored as `elastic_ql`.

#### Query rule titles

SPL, KQL, EQL and ES|QL queries have no name of their own. They are titled `<article title> — KQL query 2` (or `SPL`, `EQL`, `ES|QL`), numbered per language in article order.

#### Elastic TOML

- Used when the text has a `[rule]` or `[metadata]` section. The `rule.query` field is the rule body.
- The rule `type` picks the format: `eql` and `esql` become `elastic_ql`; `query`, `threshold` and `new_terms` become `kql`. Anything else becomes `elastic_ql`.
- `language = "eql"` forces `elastic_ql`; `language = "kusto"` or `"kql"` forces `kql`.
- Tactics and technique IDs come from `[[rule.threat]]`. `rule.index` becomes the log source.

#### YARA

- Matches `rule <name>` and reads to the matching closing brace. The rule must contain `condition:`.
- The title is the `meta:` description (cut to 200 characters) if it is longer than 10 characters, otherwise the rule name. Severity comes from `severity = "…"` in `meta:`.

#### Snort/Suricata

- One rule per line: `action protocol src_addr src_port direction dst_addr dst_port (options)`.
- Actions: `alert`, `log`, `pass`, `drop`, `reject`, `sdrop`. The title is the `msg:` text.

### Storage

`store_extracted_rules()` (`backend/app/intelligence/rule_extraction.py:619`) saves the rules for one entry.

1. It reads the TTPs and CVEs already linked to the entry.
2. It de-duplicates **on the rule body, never the title**:
   - If the same body is already stored by this user, or was auto-extracted by anyone, it is skipped. Processing an article again adds nothing.
   - If the same entry already has an auto-extracted rule with the same title and type but a different body, the rule was edited upstream. Its content is replaced in place.
3. Tags are the extracted tags plus `auto-extracted` and the rule type.
4. `source_ttps` and `source_cves` get the entry's techniques and CVEs.
5. New rules are saved as drafts (`is_draft = true`) and added to the search index.

---

## Rule Validation Engine

`backend/app/intelligence/rule_validation.py` checks syntax only. It does not check whether a rule makes sense. It covers nine rule types: the six extracted formats plus CrowdStrike QL, Nuclei (YAML templates for web scanning) and Panther (Python detections).

### Validation Architecture

`validate_rule()` (`backend/app/intelligence/rule_validation.py:540`) takes a rule type and body, picks the validator for that type, and returns a `ValidationResult`:

```python
@dataclass
class ValidationError:
    line: int | None
    column: int | None
    severity: str      # "error" | "warning"
    message: str

@dataclass
class ValidationResult:
    valid: bool
    errors: list[ValidationError]
    suggestions: list[str]
```

A rule is valid when it has no `error`-level problems. Warnings and suggestions do not fail it. An unknown rule type fails.

### Per-Format Validators

| Type | Fails when | Suggests |
|------|-----------|----------|
| `sigma` | Not valid YAML; not a mapping; missing `title`, `status`, `logsource` or `detection`; `logsource` has none of `category`/`product`/`service`; `detection` has no `condition` or no named selection | `level`, `falsepositives`, ATT&CK `tags` |
| `splunk_spl` | Empty; unbalanced `()`, `[]` or quotes | An `index=` |
| `kql` | Empty; unbalanced brackets or quotes (comments ignored) | Start with a table name, not a pipe |
| `elastic_ql` | Empty; unbalanced brackets or quotes (comments ignored) | Start with an event category, unless it is ES\|QL (`FROM …`) |
| `crowdstrike_ql` | Empty; unbalanced `()`, `[]` or quotes | Filter on `event_simpleName` or `event_platform` |
| `snort_suricata` | A line with fewer than 7 parts, a bad action, a bad direction (`->` or `<>`), no `( … )` options, or no `sid:` | `msg:` (an unknown protocol is a warning) |
| `yara` | Empty; unbalanced `{}` or `()`; no `rule <name>`; no `condition:` | `strings:` and `meta:` sections |
| `nuclei` | Empty; not valid YAML; not a mapping; no `id`; no `info` with `name`, `author` and `severity`; an unknown severity; no request block (`http`, `dns`, `network`, `file`, `headless`, `code`, `workflows` and the like) | `info.tags` |
| `panther` | Empty; no `def rule(event)`; unbalanced brackets | A `def title(event)` |

For KQL and Elastic QL, `//` and `/* */` comments are left out of the bracket and quote check, so "// processes that don't …" is not an unbalanced quote. KQL verbatim strings (`@"C:\Temp\"`) take no backslash escapes.

### Where validation runs

- During extraction, to drop broken rules.
- `POST /detection-rules/validate`, which the rule editor calls as you type (`useValidateRule()` in `frontend/src/hooks/useDetectionRules.ts`).
- `POST /detection-rules/import`, for each imported Sigma file.

---

## Data Model

### DetectionRule

Table `detection_rules` (`backend/app/models/detection_rule.py`):

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID | Primary key |
| `entry_id` | UUID | Source article (indexed; set to null if the entry is deleted) |
| `created_by` | UUID | Owner (indexed) |
| `rule_type` | str(30) | `sigma`, `splunk_spl`, `kql`, … (indexed) |
| `title` | str(500) | |
| `description`, `notes` | Text | |
| `rule_content` | Text | The rule body |
| `severity` | str(20) | `critical`, `high`, `medium`, `low` or null |
| `tags` | text[] | |
| `source_ttps`, `source_cves` | JSONB | Technique IDs and CVE IDs |
| `is_draft` | bool | `true` until published |
| `log_sources` | JSONB | Sigma `logsource` or Elastic index list |
| `mitre_tactics` | text[] | ATT&CK tactic slugs |
| `data_sources` | text[] | Telemetry the rule needs |
| `metadata` | JSONB | Upstream repo, owner, file path, conversion details |
| `source_entries`, `source_actors`, `source_campaigns` | uuid[] | Extra links |
| `license`, `upstream_updated_at`, `references`, `source_products` | | Upstream provenance |
| `derived_from` | UUID | Parent rule, for conversions and extensions (indexed) |
| `created_at`, `updated_at` | timestamp | |

Computed properties: `entry_title`, `entry_url`, `source_repo`, `source_author`, `is_authored_local` (no upstream repo), `linked_entry_count`, `linked_actor_count`.

The `entry` relationship is `lazy="joined"`, so every `select(DetectionRule)` also loads the full source article. Bulk reads that only need rule fields select columns instead, to avoid loading the same article text once per rule.

### DetectionRuleVersion

Table `detection_rule_versions`: `rule_id` (cascade delete), `version_number`, `rule_content`, `rule_type`, `change_description`, `changed_by`, `created_at`.

- A new rule has no versions.
- When `PUT /detection-rules/{id}` changes `rule_content`, the **old** content is saved as version `max + 1`, then the rule is updated.
- Rollback (`POST /detection-rules/{id}/versions/{vid}/rollback`) first saves the current content as a new version ("Snapshot before rollback to vN"), then copies the target version's content and type onto the rule. Old versions are never changed.

### DetectionSummary

Table `detection_summaries`: a saved AI analysis of several entries. Columns: `created_by`, `title`, `entry_ids`, `analysis_focus` (default `campaign`), `summary_content` (the full AI result as JSONB), `created_at`, `updated_at`. The coverage workspace also stores its saved sets here.

### TelemetrySource

Table `telemetry_sources`: one row per log source you collect. Columns: `name`, `category`, `vendor`, `product`, `log_types`, `log_types_canonical`, `ingested_into`, `enabled`, `notes`, `created_by`, `created_at`.

### TelemetrySourceNote

Table `telemetry_source_notes`: notes and saved links about a telemetry source, shared by every user. Columns: `source_name`, `user_id` (the author), `url`, `page_title`, `quote`, `content`, `created_at`, `updated_at`. A row has a `url`, `content`, or both (check constraint). It is keyed by the source's name, not a `telemetry_sources` row, because a catalog source has no row until someone enables it. Renaming a custom inventory source moves its notes to the new name, unless the old name is a catalog name or another inventory row still has it. See [Notes and links per source](#notes-and-links-per-source).

### Mitigation

Table `mitigations`: MITRE ATT&CK mitigations. Columns: `mitre_id` (unique M-ID), `name`, `description`, `mitre_url`, `cis_controls`, `nist_controls`, `article_count`, `first_seen_at`, `last_seen_at`, and Wikipedia fields. See [Mitigations](#mitigations-and-attck-integration) for the link tables.

---

## Detection Workbench

`frontend/src/pages/DetectionWorkbenchPage.tsx` is the AI rule generator. It opens as the **Generate Rules** panel inside the Rules Library. `/detection-workbench` redirects to `/workbench/explore`.

### Workflow

1. **Pick entries.** Search articles by title (debounced 300 ms) and add them as chips.
2. **Pick formats.** Sigma (default), Splunk SPL, CrowdStrike QL, Elastic QL, KQL, Snort/Suricata, YARA.
3. **Pick a focus.** Auto-detect, Campaign, Vulnerability, Malware or Threat Actor.
4. **Generate Analysis.** The page posts to `POST /intelligence/detection-summary`. The AI call runs inside the request and is capped at 150 seconds, below the 180-second gunicorn worker timeout.
5. **Read the results:**
   - Executive summary
   - Attack chain: ATT&CK steps, each with a detection idea, feasibility and log sources
   - Indicators, in Network / Host / Behavioral tabs
   - Generated rules, each with **Copy** and **Save to library**
   - Related intelligence: earlier articles, existing rules, related CVEs
   - Gaps and recommendations
6. **Export:** all rules as text, the summary as Markdown, or an ATT&CK Navigator layer (built in the browser).

`POST /intelligence/detection-summaries` does the same generation and also saves the result as a `DetectionSummary`. `GET` and `DELETE` on `/intelligence/detection-summaries[/{id}]` list, read and remove saved ones.

---

## Rule Library

The Rules Library is the **Rules** section of the Workbench (sidebar group **Detection → Rules Library**, at `/workbench/explore?section=rules`). It is built by `RulesSection` in `frontend/src/pages/WorkbenchPage.tsx`. `?rules_q=<term>` fills the search box, which entity profiles use for their "Search library" links.

### Search and Filters

The list and its facet counts both come from the Meilisearch `rules` index through `GET /detection-rules/search`, in one request. (Meilisearch is the search engine IntelFeed uses; a "facet" is a filter group with a count next to each value.) Because they arrive together, the counts always match the list.

- **Search box.** Relevance-ranked and typo-tolerant. A **Search in** switch picks All, Metadata or Rule body. Metadata covers title, description, tags, tactics, techniques, products, repo, author, and the actors, malware, tools, vendors and products linked to the rule's source article. So typing "APT33" finds rules even though rules have no actor column.
- **Facet rail.** Thirteen groups: Rule format, Severity, Source repo, ATT&CK tactic, Technique, Threat actor, Malware, Tool, Vendor, Product, Telemetry, Tags, License.
  - Values in one group are ORed. Groups are ANDed. Ticking two formats widens the list.
  - Counts are **disjunctive**: each group is counted with every other filter applied but not its own, so picking "sigma" still shows how many rules the other formats have. This costs one extra Meilisearch query per active group, sent together as one multi-search.
- **Telemetry switch** (All telemetry / My telemetry / Gaps). It ticks boxes in the rail's Telemetry group; the boxes do the filtering. The rail group's **select mine** link does the same. Which values you collect comes from `GET /detection-rules/telemetry-vocabulary`, because the match is fuzzy and the browser cannot work it out by comparing strings.
  - Since a group ORs its values, "My telemetry" means "needs at least one source you collect". For "every source the rule needs is collected", call the API with `telemetry=covered` (or `missing`). The Telemetry column's ring shows that strict verdict per rule.
- **Research Views:** All rules, New this week, Recently updated upstream, My drafts.
- **Group rules by:** Flat, Technique, Repo or Product. This regroups the loaded rows in the browser.
- **Sorting.** The Rule and Added headers sort by title and creation date. The API also accepts `rule_type`, `severity`, `is_draft`, `updated_at`, `upstream_updated_at` and `relevance` (used whenever the search box has text).

`GET /detection-rules` is a separate PostgreSQL list for scripts and the API. It filters with `search=` (substring match), `rule_type=`, `is_draft=`, `severity=`, `technique=`, `cve=` and others. The library does not use it.

The global search bar also finds rules, with `rule:`, `rule.type:`, `rule.severity:`, `rule.data_source:`, `rule.tactic:`, `rule.tag:`, `rule.draft:` and `rule.license:`. See [query-language.md](query-language.md).

#### The `rules` index

`entity_indexer.sync_rules()` builds one search document per rule. On top of the rule's own fields it adds:

- **`authored_local`**: true when the rule has no upstream repo. Meilisearch cannot filter on "field is missing", so this is stored.
- **`telemetry_tokens`**: what the rule needs to fire. It is `data_sources` if set, otherwise the Sigma `logsource` product/category/service, otherwise a default per format (YARA: file, memory; Snort: network, ids; Nuclei: http, web, waf). The Telemetry group uses this, because most rules leave `data_sources` empty.
- **Entity links**: actors, malware, tools, vendors and products from the source article.
- **Flattened lists**: `source_products` and `source_cves` can hold plain strings or `{name: …}` objects; both become strings.

Index settings that matter:

- Timestamps are stored as numbers, so date filters and sorts work.
- `maxTotalHits` is 100,000. The default of 1,000 would cap both the total shown and how far you can scroll.
- `maxValuesPerFacet` is 5,000 and facet values are sorted by count, so the most common techniques are never cut off.
- `source_products` is searchable but not a facet: few rules set it and its values are raw CPE strings. The Product group uses the article-linked products instead.

Creating, editing, bulk-editing and deleting rules update the index straight away. The `sync_entity_search_indexes` job (every 4 hours) repairs any drift.

### Display

The list is a table that loads 100 rules at a time as you scroll. Columns:

- Severity stripe and a select checkbox
- **Rule**: title (links to `/workbench/rule/{id}`), format badge, severity, CVE and linked-entry count
- **Source**: "authored here" or the upstream GitHub repo, with author and license
- **ATT&CK**: the first technique chips
- **Telemetry**: a ring showing how much of the needed telemetry you collect
- **Added**: age

Toolbar: **+ New Rule** (`/workbench/rule/new`), **Generate Rules**, **Import**, **Export**. On narrow screens Import, Export and Generate move into a `⋯` menu.

### Bulk Operations

Selecting rows shows a bar with **Publish**, **Unpublish**, **Export** (ZIP), **Delete** (with an undo toast) and **Clear**. These call `POST /detection-rules/bulk-update` (`is_draft`, `tags_add`, `tags_remove`) and `POST /detection-rules/bulk-delete`. Tag changes are available in the API only.

### Rule detail page

`frontend/src/pages/RuleDetailPage.tsx` (`/workbench/rule/:id`) is the editor. Three columns: the **Structure** rail (outline, attribution, provenance: techniques, CVE, created and updated, latest upstream commit, references), the editor, and the **Context** rail (source article, fresh intel, fields vs inventory with the data-source picker, near-duplicates). The headline row above the editor holds the format, a severity select and the title. The title is an input on a rule authored in the app and read-only with a lock on a rule mirrored from a git repo, because the upstream sync finds the rule by its title; `PUT /detection-rules/{id}` refuses such a rename with `rename_locked`. The pane components live in `frontend/src/components/ruleBench/`.

Under the Save bar a tab strip holds everything else, at the editor's full width:

- **Details**: description, tags, analyst notes, MITRE tactics, and **Auto-fill from rule body** when the metadata extractor found fields in the rule text.
- **Convert**: every language from Settings › Reading › Preferred query language (the preferred one marked) plus the rule-only formats (Snort/Suricata, YARA, Nuclei), an optional note added to the prompt, and the existing conversions with their model, tokens, cost and time.
- **AI Assist**: the four quick actions (Reduce noise, Evasion check, Explain, Cover a new observable) above the streaming chat; answers arrive as code blocks with **Apply to editor**.
- **History**: one timeline of local versions (View, Diff, Rollback) and, for a mirrored rule, the upstream commits (message, author, file path, link) and the import baseline. Comparing a near-duplicate from the Context rail opens inside this tab.

Below 1200px the Context rail becomes a tab here too, and below 900px so does Structure.

---

## Detection Coverage Analysis

### Telemetry-Aware Coverage Classification

`backend/app/services/detection_coverage.py` sorts each ATT&CK technique (or CVE) into one of three states:

| Status | Meaning |
|--------|---------|
| `covered` | At least one published rule references it, and you collect everything that rule needs. Rules with no `data_sources` count as satisfiable. |
| `library_only` | Rules exist, but each one needs telemetry you do not collect. `missing_data_sources` lists the gaps of the rule that is closest to working. |
| `no_rule` | No published rule references it. |

Drafts never count.

Main functions:

- `classify_techniques(db, technique_ids)`: matches rules on `source_ttps`, and also on technique IDs found in `mitre_tactics`, where some rules carry them. Returns status, rule counts, missing sources and up to 5 example rules per technique.
- `classify_cves(db, cve_ids)`: the same, for CVEs. A rule references a CVE if `source_cves` contains it or the title mentions it.
- `summarize(classification)`: totals and a `coverage_percentage`.
- `entry_opportunity_tiers(...)`: per entry, `actionable_gap` (a technique has no rule at all), `telemetry_gap` (rules exist but are blocked by telemetry) or `None`.

**How a data source matches your telemetry.** Rules and your inventory name things differently (Elastic index patterns, Sentinel connector IDs, product names, ATT&CK log channels). So matching runs in three tiers, strongest first: a ticked product name, a shared canonical log type, or a category that has at least one ticked source. The rule-detail feasibility badge, the telemetry gaps list and the ATT&CK matrix all use this same match.

`POST /intelligence/detection-coverage` takes up to 500 technique IDs and returns `{summary, techniques}`. Entity profiles and the ATT&CK matrix use it.

### Coverage workspace

An entity profile's **Detection** tab is backed by `/api/coverage-workspace` (`backend/app/services/coverage_workspace.py`). For one actor, malware, CVE or technique over a window (7d, 14d, 30d, 90d or all), it shows the articles, the techniques they describe (with the quoted sentence), prior rules for each technique, and a set of rules you are assembling. Sets are saved as `DetectionSummary` rows and export as Markdown or a ZIP. It makes no AI calls. A technique whose log channels match nothing you collect is shown as a sourcing problem, not a detection gap.

### Dashboard widgets

These endpoints live in `backend/app/api/widgets_detection.py` unless noted. Each takes `date_from`, `date_to` (default: the last 30 days) and `limit` (default 15).

- **`GET /widgets/attack-coverage-gap`**: techniques mentioned in articles that have no rule extracted from them, ranked by how many such articles mention each. Use it to choose what to write next.
- **`GET /widgets/detection-format-breakdown`**: rule counts by format, for rules created in the window.
- **`GET /widgets/kev-matches`**: CVEs mentioned in the window that are marked as actively exploited, ranked by mentions and then CVSS score, with EPSS, KEV status and KEV due date.
- **`GET /widgets/detection-coverage`** (`widgets.py`): technique coverage for the Detection Coverage widget.

---

## ATT&CK Catalog and Matrix

### Catalog Hydration

`backend/app/intelligence/attack_catalog.py` downloads the official MITRE ATT&CK data for the `enterprise`, `mobile` and `ics` domains and writes every technique to the `ttps` table. Catalog fields on `TTP`: `matrix_domain`, `tactics` (all tactics; `tactic` is the main one), `is_subtechnique`, `parent_technique_id`, `is_deprecated`.

It runs in the weekly `run_mitre_attack_sync` job (Sunday 03:00 UTC). To run it by hand, inside the API container:

```bash
docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_mitre_attack.py
```

### Matrix Endpoint

`GET /attack/matrix?domain=enterprise|mobile|ics&days=<n>&include_deprecated=<bool>` (`backend/app/api/attack.py`):

- Tactics come back in kill-chain order (`TACTIC_ORDER` in `backend/app/intelligence/tactics.py`). Empty tactics are left out.
- Each technique has `article_count` (in the `days` window, or all time), `rule_count`, `has_rule`, `coverage` (from `classify_techniques()`), `deployable` (same as `coverage == "covered"`), `missing_data_sources`, its `subtechniques`, and `rollup_article_count` (parent plus subs).
- The response also has `coverage_summary` and `max_article_count` (for scaling the heat colors).
- Results are cached in Redis for 180 seconds per domain, window and deprecated flag. Anonymous visitors get their own cache entry.

### Matrix UI

`frontend/src/components/AttackMatrixSection.tsx`, at Workbench **Detection → ATT&CK Matrix**:

- Domain: Enterprise, Mobile, ICS. Window: 7d, 30d (default), 90d, All.
- Layer mode: **Feed heat** (color by article count), **Coverage** (green covered, amber "Missing telemetry", red "No rule"), or **Both** (heat fill, coverage border). Visitors see Feed heat only.
- Sub-technique rows expand. Hovering shows coverage and missing sources. Clicking opens the technique profile.
- **Export Navigator JSON** downloads an ATT&CK Navigator layer built in the browser by `buildNavigatorLayer()` (`frontend/src/utils/attackMatrix.ts`). ATT&CK Navigator is MITRE's web tool for coloring the technique matrix.

---

## Export and Integration

### Export Formats

`GET /detection-rules/export?format=yaml|zip&rule_ids=<comma-separated ids>`. Leave out `rule_ids` to export every rule.

| Format | What you get |
|--------|--------------|
| `yaml` (default) | One `detection-rules.yml` with every rule body joined by `---` |
| `zip` | `detection-rules.zip` with one file per rule, named from the title, with an extension per format: `.yml` (Sigma), `.spl`, `.kql`, `.eql`, `.cql`, `.rules` (Snort/Suricata), `.yar`, or `.txt` |

The library's Export buttons always ask for ZIP. ATT&CK Navigator layers come from the matrix page or `GET /attack/layer` (below).

### Rule Import

`POST /detection-rules/import` takes one file up to 20 MB:

- A `.yml`/`.yaml` file, or a `.zip` of them. Other files in a ZIP are counted as skipped.
- **Sigma only.** Each file is checked with `validate_rule("sigma", …)`; failures are listed in `errors`.
- Imported rules are drafts, with title, description, severity, tags and tactics taken from the Sigma fields.
- There is no duplicate check. Importing the same file twice makes two copies.
- Returns `{imported, skipped, errors}`.

### ATT&CK Navigator

`GET /attack/layer` (`backend/app/api/attack.py`) returns a Navigator layer of techniques seen in articles between `date_from` and `date_to` (default: the last 30 days). Each technique gets a score from 0 to 100, relative to the most-mentioned one, and a white-to-red color. The comment says how many articles mention it. The layer is for the `enterprise-attack` domain.

Import the file at <https://mitre-attack.github.io/attack-navigator/> to view it.

---

## Telemetry Sources and Feasibility

### Inventory Management

You list the log sources you collect at Workbench **Detection → Telemetry Sources**. Endpoints under `/telemetry-sources`:

| Endpoint | Purpose |
|----------|---------|
| `GET`, `POST /telemetry-sources` | List and add sources |
| `PUT`, `DELETE /telemetry-sources/{id}` | Edit and remove a source |
| `GET /telemetry-sources/catalog` | The built-in catalog of common sources, for the checkbox picker |
| `POST /telemetry-sources/sync` | Admin only. Match the inventory to a list of ticked catalog names (creates, enables or disables rows) |
| `GET /telemetry-sources/taxonomy` | A flat list of data-source names by category |
| `POST /telemetry-sources/check-feasibility` | Which of a list of data sources you collect |
| `GET /telemetry-sources/telemetry-gaps` | Rules blocked by missing telemetry |
| `GET`, `POST /telemetry-sources/notes` | A source's notes and saved links (`?source=`), and adding one |
| `PUT`, `DELETE /telemetry-sources/notes/{id}` | Edit or delete a note (its author or an admin) |
| `GET /telemetry-sources/notes/counts` | Notes per source name, for the catalog |
| `GET /telemetry-sources/notes/suggest` | Which sources a page (`?url=&title=`) is probably about, for the browser extension |

### What a source collects from

The inventory is instance-wide, and a log type alone overstates what it covers: CrowdStrike Falcon gives process creation only where its sensor runs, never on an ESXi host or a vCenter appliance. `app/telemetry_platforms.py` works out which platforms each source collects from, in the vocabulary hunt hypotheses use for their target: Windows, macOS, Linux, ESXi (ESXi hosts and vCenter appliances), Network Devices, Containers, IaaS, SaaS, Identity Provider, Office Suite, or Any for sources that watch from the network or don't depend on the host (firewalls, NDR, DNS, proxies, NetFlow). Nobody assigns it: it follows from the source's category (an EDR: Windows, macOS, Linux; virtualization: ESXi; firewalls: Any), with name hints for the exceptions (Hyper-V is Windows, macOS logs are macOS). Nothing is stored.

A hunt's runs / needs badge uses it: a log type counts as collected for a hunt only when an enabled source that gives it collects from the hunt's platform, and the source the hunt names must collect from it too.

### Notes and links per source

Each catalog item on the Telemetry Sources page has a **Notes** button that opens a side panel: the source's log types, then the links and notes analysts have saved about it, newest first. Notes are markdown, written and shown with the same editor and card as entry and entity notes, and they are listed on the sidebar's **Notes** page with the others (filter: **Telemetry Source Notes Only**; search covers the note, quote, page title, link and source name). Anyone can add one; the author or an admin edits or deletes it. Notes can be added to any catalog or inventory source, enabled or not, so you can write notes about a source before you start collecting its logs. The [browser extension](browser-extension.md) saves the page being read to a source's notes, with any selected text as a quote.

Where the notes are used:

- **Rule detail rail.** `GET /detection-rules/{id}` returns `telemetry.sources`: up to eight enabled sources that provide the rule's collected data sources, each with `provides` and `note_count`, sources with notes first. The rail lists them under **Log sources for this rule**; clicking one opens its notes. `sources_answering()` in `app/services/detection_coverage.py` lists specific sources, so it is stricter than the coverage check. A source is listed when its name or product contains every main word of the rule's most specific data source (`logs-aws.cloudtrail-*` lists AWS CloudTrail). If no source matches by name, it lists the sources that supply the most of that data source's log types (`process_creation` lists the EDRs). Generic data sources (`audit.generic`, `threat.detection`) and matches on category alone list nothing, because every product in the category would qualify. Source names are compared without regard to case.
- **AI prompts.** `get_telemetry_notes_for_prompt()` (`app/intelligence/telemetry_context.py`) collects the text notes on enabled sources, matching source names without regard to case (a saved link with no note is left out; a link's quote is included with its note), newest first, up to 600 characters per source and 3,000 in all. `run_task` adds them as the `telemetry_notes` variable to any prompt whose template names it. The `hunt_pack`, `detection_rules` and `threat_assessment` default templates do. A prompt customized under Settings → AI Configuration keeps its own text and does not show the notes until `telemetry_notes` is added to it.
- **Suggestions.** `GET /telemetry-sources/notes/suggest` ranks sources someone already saved a link to from the same part of the site (host plus the first two path segments) first, then catalog products named in the page's address or title. A product shorter than four letters never matches on its own.
- **Tools.** `get_telemetry_source_notes` and `add_telemetry_source_note` in the tool registry.

The catalog covers virtualization (VMware vCenter Server, ESXi, NSX, Hyper-V, Nutanix Prism, Proxmox VE), web servers (Apache HTTP Server, Nginx, IIS, Tomcat, HAProxy, Envoy), network infrastructure (Cisco IOS/IOS-XE and NX-OS, Junos, Arista EOS, Aruba, F5 BIG-IP, Citrix NetScaler ADC, NetFlow/IPFIX, Infoblox NIOS), backup and storage (Veeam, Rubrik, Cohesity, Commvault, NetApp ONTAP, Dell PowerScale), managed file transfer (MOVEit Transfer, GoAnywhere MFT, Cleo, Kiteworks), RMM tools (ScreenConnect, TeamViewer, AnyDesk), Exchange Server and SQL Server audit, alongside the EDR, Windows, Linux, network, identity, cloud and SaaS sources.

### Feasibility Checking

```json
// POST /telemetry-sources/check-feasibility
{ "data_sources": ["Windows Security Log", "Network IDS", "Endpoint EDR"] }

// response
{ "feasible": ["Windows Security Log", "Endpoint EDR"], "missing": ["Network IDS"], "coverage_pct": 0.67 }
```

It uses the same three-tier match as coverage (`get_available_telemetry()` and `split_data_sources()`). The rule detail page re-checks whenever the rule's data sources change and colors its badge by `coverage_pct`: 0.8 or more is green, 0.5 or more is amber, below that is red.

### Telemetry Gaps

`GET /telemetry-sources/telemetry-gaps` checks every rule that declares `data_sources`. It returns `rules_with_gaps` (lowest coverage first), `total_rules_checked`, `rules_with_gaps_count`, and `most_needed_sources`: the 20 missing sources that would unblock the most rules.

---

## Mitigations and ATT&CK Integration

### Mitigation Model

Two link tables in `backend/app/models/mitigation.py`:

- **`TTPMitigation`**: `ttp_id`, `mitigation_id`, `created_at`. Which mitigations address which techniques (from ATT&CK).
- **`EntryMitigation`**: `entry_id`, `mitigation_id`, `confidence`, `source` (`regex`, `ai`, `manual`, or `auto_link` for an M-ID backlink), `extracted_at`, `paragraph_indices`, `detail` (the article's own wording). Which articles recommend which ATT&CK catalog mitigations. A recommendation that fits no catalog mitigation creates nothing.

### MITRE ATT&CK Integration

`GET /attack/techniques` returns the most-mentioned techniques between `date_from` and `date_to` (default: the last 30 days), with `limit` 50 by default and up to 500:

```json
[
  {
    "technique_id": "T1059.001",
    "name": "Command and Scripting Interpreter: PowerShell",
    "tactic": "execution",
    "count": 42,
    "latest": "2024-01-15"
  }
]
```

---

## Detection Workbench Advanced Features

### Rule Conversion (AI-powered)

`POST /detection-rules/{id}/convert` with `{"target_type": "splunk_spl"}` asks the AI provider assigned to the `detection_rules` task to rewrite the rule in another format. It fails with `no_ai_assignment` if no provider is assigned. Two optional fields: `dialect`, a query-language id from `backend/app/ai/query_language.py` whose `rule_type` is the target (ES|QL and EQL are both stored as `elastic_ql`, so `{"target_type": "elastic_ql", "dialect": "esql"}` says which one), which also puts the language's full name in the prompt; and `notes`, free text appended to the prompt. A dialect that does not belong to the target format fails with `bad_dialect`.

Every language in Settings › Reading › Preferred query language is a target: `yaral`, `aql`, `sumo` and `sql` are rule types the library stores without a syntax check (`POST /detection-rules/validate` reports them valid with a suggestion saying so).

The prompt is built in `convert_detection_rule` in `backend/app/api/intelligence.py`, not in the AI task registry, so it is not editable under Settings › AI Configuration. It carries the source rule, its title, description, severity, tactics and data sources, the notes, and six instructions (valid syntax, field-name mapping, log-source translation, preserved logic and ATT&CK mappings, a comment for anything untranslatable, target-format headers).

The result is saved as its own rule, linked to the original by `derived_from`. There is one converted rule per original, target format and dialect; converting again overwrites it and saves the old body as a version. The new rule copies the original's techniques, CVEs, actors and entries, but not its data sources or log sources, which are worked out again from the new body.

The response has `converted_content`, `source_type`, `target_type`, `dialect`, `model`, `tokens_input`, `tokens_output`, `tokens_used`, `cost`, and the new rule's `rule_id` and `title`. `GET /detection-rules/{id}/conversions` lists a rule's conversions.

### Extending a rule

`POST /detection-rules/{id}/extend` makes a draft copy titled "<title> (extended)", linked by `derived_from`, so you can change an upstream rule and keep a record of where it came from. Each call makes a new copy.

### Rule Chat (Streaming)

`POST /detection-rules/chat` streams an AI conversation about a rule as server-sent events (`data: {text, error}` frames). The request carries `message`, `rule_content`, `rule_type`, `title`, `severity`, `mitre_tactics`, `data_sources` and `history`. The frontend helper is `streamRuleChat()` in `frontend/src/hooks/useDetectionRules.ts`.

### Version Management

See [DetectionRuleVersion](#detectionruleversion) for how versions are made and how rollback works. The History pane lists versions with date, author and description. `GET /detection-rules/{id}/diff` compares two versions, or a version with the current content.

### Provenance Tracking

`GET /detection-rules/{id}/provenance` returns where a rule came from: the rule's upstream fields (repo, author, license, references, upstream date), its linked entries (`entry_id` plus `source_entries`), the TTPs and malware on those entries, and threat actors from those entries plus `source_actors`.

Related endpoints on the rule page:

- `GET /detection-rules/{id}/fresh-intel`: articles about the rule's CVEs or techniques that arrived **after** the rule was last edited. This suggests the rule may be out of date.
- `GET /detection-rules/{id}/related`: rules that share a CVE or technique, other formats of the same rule, and near-duplicates.
- `GET /detection-rules/{id}/commits`: the upstream GitHub commit history, for mirrored rules. The sync (`backend/app/services/github_rule_import.py`) appends each new commit here and, when the body changes, saves the body it replaces as a version (`Upstream <sha>: <message>`), so the History tab can diff one upstream state against the next.

### How a mirrored rule follows its file

A `github_repo` feed lists one entry per file; the entry's GUID is the file path, and its metadata carries `owner`, `repo`, `file_path` and the newest commit. When a poll lists a file again at a different commit, the fetcher (`_refresh_github_entry` in `backend/app/workers/feed_tasks.py`) updates that entry in place and runs the importer again. A full sync of the feed does the same for every known file whose git blob id no longer matches the text stored on its entry: the tree walk lists those files as `modified`, stamped with the last commit that touched them, and the worker refreshes them; files with unchanged blobs are skipped without a request. The importer finds the rule by owner, repo and file path, whoever imported it, appends the commit to `metadata.commit_history`, snapshots the old body as a version and writes the new one. A rule is "authored here" (`is_authored_local`) only when its metadata has no `repo`.

Those provenance keys (`repo`, `owner`, `file_path`, `commit_*`, `commit_history`) survive every save: the metadata re-extraction that runs on a body change keeps them (`PRESERVED_METADATA_KEYS` in `backend/app/intelligence/rule_metadata.py`), and a `metadata` blob sent by a client is merged over them rather than replacing them. The editor only sends back the metadata it was given plus the chat history.
---

## Appendix: Frontend Components Reference

| Component | File | Purpose |
|-----------|------|---------|
| `RulesSection` | `pages/WorkbenchPage.tsx` | The Rules Library: search, facets, bulk actions, import/export |
| `DetectionWorkbenchPage` | `pages/DetectionWorkbenchPage.tsx` | AI generator, shown inside the Rules Library |
| `RuleDetailPage` | `pages/RuleDetailPage.tsx` | Rule editor (`/workbench/rule/:id`) |
| `ruleBench/*` | `components/ruleBench/` | Editor tabs and rails: details, chat, convert, history (with compare), structure, context |
| `RuleBuilderShell` | `components/RuleBuilderShell.tsx` | Editor frame around CodeMirror |
| `CodeMirrorEditor` | `components/CodeMirrorEditor.tsx` | Code editor with syntax highlighting |
| `RuleEntryCard` | `components/RuleEntryCard.tsx` | Compact rule card |
| `AttackMatrixSection` | `components/AttackMatrixSection.tsx` | ATT&CK matrix with heat and coverage |
| `CoverageWorkspace` | `components/coverageWorkspace/` | Entity profile Detection tab |
| `DetectionCoverageWidget` | `components/widgets/DetectionCoverageWidget.tsx` | Coverage widget |
| `DetectionFormatBreakdownWidget` | `components/widgets/DetectionFormatBreakdownWidget.tsx` | Rules by format |
| `AttackCoverageGapWidget` | `components/widgets/AttackCoverageGapWidget.tsx` | Techniques with no rule |
| `KEVMatchesWidget` | `components/widgets/KEVMatchesWidget.tsx` | Actively exploited CVEs |

## Appendix: Backend API Endpoints Reference

All paths are under `/api`.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/detection-rules` | POST | Create a rule |
| `/detection-rules` | GET | PostgreSQL list with filters (scripts and API) |
| `/detection-rules/search` | GET | Library list and facet counts (Meilisearch `rules` index) |
| `/detection-rules/facets` | GET | Facet value counts |
| `/detection-rules/telemetry-vocabulary` | GET | Telemetry values split into collected and missing |
| `/detection-rules/coverage-board` | GET | Trending entities and how many library rules cover each (not used by the UI) |
| `/detection-rules/needing-review` | GET | Published rules with new intel for their techniques |
| `/detection-rules/{id}` | GET | One rule, with its telemetry feasibility |
| `/detection-rules/{id}` | PUT | Update (a content change saves a version) |
| `/detection-rules/{id}` | DELETE | Delete |
| `/detection-rules/{id}/status` | PATCH | Publish or unpublish |
| `/detection-rules/{id}/versions` | GET | List versions, newest first |
| `/detection-rules/{id}/versions/{vid}` | GET | One version |
| `/detection-rules/{id}/versions/{vid}/rollback` | POST | Restore a version (saves the current content first) |
| `/detection-rules/{id}/diff` | GET | Compare versions |
| `/detection-rules/validate` | POST | Syntax check |
| `/detection-rules/extract-metadata` | POST | Read fields out of a rule body |
| `/detection-rules/bulk-update` | POST | Publish, unpublish, add or remove tags |
| `/detection-rules/bulk-delete` | POST | Delete many |
| `/detection-rules/import` | POST | Import Sigma YAML or ZIP |
| `/detection-rules/export` | GET | Export YAML or ZIP |
| `/detection-rules/{id}/convert` | POST | AI conversion to another format (saved as a rule) |
| `/detection-rules/{id}/conversions` | GET | A rule's conversions |
| `/detection-rules/{id}/extend` | POST | Draft copy for editing an upstream rule |
| `/detection-rules/chat` | POST | Streaming AI chat about a rule |
| `/detection-rules/{id}/provenance` | GET | Source entries, entities and upstream details |
| `/detection-rules/{id}/fresh-intel` | GET | New intel since the last edit |
| `/detection-rules/{id}/related` | GET | Related rules |
| `/detection-rules/{id}/commits` | GET | Upstream GitHub commits |
| `/entries/{id}/extract-detection-rules` | POST | Run regex extraction on one entry |
| `/entries/{id}/generate-rules` | POST | AI rule generation from one entry |
| `/intelligence/detection-summary` | POST | Generate a multi-entry analysis (not saved) |
| `/intelligence/detection-summaries` | POST | Generate and save an analysis |
| `/intelligence/detection-summaries` | GET | List saved analyses |
| `/intelligence/detection-summaries/{id}` | GET, DELETE | Read or remove a saved analysis |
| `/intelligence/detection-coverage` | POST | Classify techniques as covered / library_only / no_rule |
| `/coverage-workspace/{entity_type}/{entity_key}` | GET | Coverage workspace for one entity (plus `/sets` and export routes) |
| `/attack/matrix` | GET | ATT&CK matrix with heat and coverage |
| `/attack/layer` | GET | ATT&CK Navigator layer |
| `/attack/techniques` | GET | Most-mentioned techniques |
| `/widgets/detection-format-breakdown` | GET | Rules by format |
| `/widgets/attack-coverage-gap` | GET | Techniques with no rule |
| `/widgets/kev-matches` | GET | Actively exploited CVEs |
| `/widgets/detection-coverage` | GET | Technique coverage widget |
| `/telemetry-sources/...` | | See [Inventory Management](#inventory-management) |

---

## See Also

- [guide/detection-rules.md](guide/detection-rules.md): using the rule features as an analyst
- [architecture.md](architecture.md#8-detection-engineering): where detection fits in the system
- [workers-search-dashboards.md](workers-search-dashboards.md): the jobs that maintain rules (`rebuild_rule_coverage`, `backfill_rule_attack_mappings`, `backfill_rule_data_sources`) and the search indexes
- `frontend/src/hooks/useDetectionRules.ts`: the frontend hooks for rules
