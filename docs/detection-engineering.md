# Detection Engineering

## Overview

IntelFeed's Detection Engineering subsystem provides analysts with end-to-end detection rule lifecycle management: extracting rules from intelligence articles, authoring new rules in a rich code editor, validating syntax across 9 detection languages, versioning all changes, and exporting to SIEM/EDR platforms. It also classifies detection coverage against the analyst's telemetry inventory and renders a full ATT&CK matrix (Enterprise/Mobile/ICS) heat-mapped by feed frequency and coverage. The subsystem bridges intelligence ingestion and detection implementation, enabling security teams to operationalize threat research into runnable detection logic.

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

See [diagrams/detection-engineering-rule-pipeline.md](diagrams/detection-engineering-rule-pipeline.md) for the full extraction → validation → coverage flowchart. In short:

```
Threat Intelligence Article
  ↓
Rule Extraction (6 output formats)
  ↓
Syntax Validation (per-format validator; invalid rules dropped)
  ↓
Auto-Tag & Deduplicate
  ↓
Storage as DetectionRule (is_draft = true)
  ↓
Manual Review/Editing in RuleBuilderShell
  ↓
Publish to Rule Library (immutable version trail)
  ↓
Telemetry-Aware Coverage Classification (covered / library_only / no_rule)
  ↓
Export to SIEM/EDR (YAML, ZIP, ATT&CK Navigator layer)
```

### Key Principles

- **No AI required for extraction** — Pattern matching + regex + parsers only (lines 1-5, `rule_extraction.py`)
- **Format-agnostic storage** — Rule content stored as-is; validation per-format
- **Immutable versioning** — Every edit creates a new `DetectionRuleVersion`; no soft deletes
- **Entry linkage** — Rules traced back to source article for provenance and context
- **TTP/CVE mapping** — Rules inherit and link to TTPs/CVEs extracted from their source entry
- **Telemetry-aware** — Feasibility assessments based on user's configured data sources

---

## Rule Extraction

### Supported Formats

Extraction pipeline (`rule_extraction.py`) scans article content for 6 detection languages:

| Format | Detection Heuristic | Extractor | Confidence |
|--------|-------------------|-----------|-----------|
| **SIGMA** | YAML with `title:`, `detection:`, `logsource:` | `_extract_sigma_rules()` | High |
| **Splunk SPL** | `index=` or `\|` pipes + SPL commands | `_extract_splunk_spl_rules()` | Medium-High |
| **Elastic QL** | TOML `[rule]` section with `query` field | `_extract_elastic_toml_rules()` | High |
| **KQL** | Elastic TOML with `language: kusto/kql` or `type: query/threshold/new_terms` | `_extract_elastic_toml_rules()` with type mapping | Medium |
| **CrowdStrike QL** | Reserved words like `event_simpleName` | Reserved in validator only; no dedicated extractor | Low |
| **YARA** | `rule {name}` with `strings:` and `condition:` | `_extract_yara_rules()` | High |
| **Snort/Suricata** | `alert/log/pass/drop/reject` + protocol + options | `_extract_snort_suricata_rules()` | High |

### Extraction Algorithm

**Entry point:** `extract_rules_from_content(text: str, source_url: str | None = None) -> list[dict]` (lines 24-56)

For each format, the extractor:

1. **Scans for code blocks** — Fenced markdown (`\`\`\`sigma`, `\`\`\`yaml`, `\`\`\`spl`)
2. **Matches pattern** — Language-specific regex or parser
3. **Extracts metadata** — Title (from content or fallback), severity, tags, MITRE tactics, log sources
4. **Returns structured dict** with keys:
   - `rule_type` — Format identifier
   - `title` — Human-readable name (max 200 chars)
   - `rule_content` — Full rule text
   - `severity` — low | medium | high | critical (nullable)
   - `tags` — String array (auto-extracted, ATT&CK IDs)
   - `mitre_tactics` — Extracted from tags or metadata
   - `log_sources` — Dict with category/product/service keys

**Deduplication:** After extraction, rules are validated. Invalid rules (lines 42-56) are logged but filtered out before storage.

### Per-Format Details

#### SIGMA (lines 215-279)

- **Parser:** `yaml.safe_load_all()` handles multi-document YAML
- **Required fields:** `title`, `detection`, `logsource`
- **Metadata extraction:**
  - Title from `title:` field
  - Severity from `level:` (e.g., `level: high`)
  - MITRE tactics from tags like `attack.execution` → prefix check + title-casing (lines 254-260); `attack.t…` technique tags are excluded from tactics but kept as tags
- **Log sources:** Entire `logsource:` dict (category, product, service, etc.)
- **Normalization:** Re-serialized to canonical YAML for storage (line 265)

#### Splunk SPL (lines 315-399)

- **Heuristic detection:** `_is_spl_query()` (lines 315-351) checks for:
  - `index=` + pipe operators (strong)
  - `search ` + pipe operators
  - `| tstats` anywhere in text
  - Pipe into known SPL commands (stats, where, eval, table, rex, dedup, etc.)
- **False positive avoidance:** Requires multiple SPL indicators; won't match raw pipes alone
- **Code block parsing:** Looks for \`\`\`spl, \`\`\`splunk, or any fenced block + content analysis
- **Inline extraction:** Multi-line blocks starting with `index=`, `search `, or `| tstats`; fragments under 30 chars skipped (lines 387-397)
- **Dedup by content:** Tracks seen rules to avoid duplicates (line 357)

#### Elastic/KQL (lines 125-212)

- **Format detection:** TOML files with `[rule]` or `[metadata]` sections
- **Type mapping:** Query language in TOML determines rule_type:
  - `type: eql | esql` → `elastic_ql`
  - `type: query | threshold | new_terms` → `kql`
  - `language: eql` → `elastic_ql`; `language: kusto | kql` → `kql` (overrides type)
  - Unknown types default to `elastic_ql`
- **MITRE mapping:** `[[rule.threat]]` arrays with `tactic.name` and `technique.id` (lines 182-196)
- **Log sources:** Pulled from `rule.index[]` field
- **Query extraction:** `rule.query` field contains the actual query

#### YARA (lines 59-122)

- **Pattern:** Regex matches `rule {name}` with balanced braces (lines 63-81)
- **Validation:** Must contain `condition:` section
- **Metadata:** Extracted from `meta:` section:
  - Description → title (or rule name if missing)
  - Severity from `severity = "..."` key-value pair
- **Fallback title:** Rule name if description missing or < 10 chars

#### Snort/Suricata (lines 282-312)

- **Pattern:** Single-line rules starting with action (alert/log/pass/drop/reject/sdrop)
- **Structure:** `action protocol src_addr src_port direction dst_addr dst_port (options)`
- **Title extraction:** From `msg: "..."` field in options
- **No severity/log_sources:** Protocol and direction are implicit in rule syntax

### Storage (lines 402-490)

**Function:** `store_extracted_rules(db, entry_id, user_id, rules) -> list[DetectionRule]`

1. **Fetch context:**
   - All TTPs linked to the entry (via EntryTTP junction)
   - All CVEs linked to the entry (via EntryCVE junction)

2. **Deduplication strategy (scoped to the same `created_by` user):**
   - Check for exact content match (lines 428-436): Skip if identical rule exists
   - Check for title+type match from auto-extraction (lines 438-448): Update if found
   - **Update scenario:** If upstream source changed the rule, merge new content and re-point `entry_id` at the new entry

3. **Tag construction (line 450):**
   - Always include `"auto-extracted"` and `rule_type`
   - Merge in extracted tags (severity, technique IDs, etc.)
   - Deduplicate via set

4. **TTP linkage (lines 452-453):**
   - Merge entry-level TTPs with any TTPs parsed from rule metadata
   - Store as array in `source_ttps` JSONB

5. **CVE linkage (lines 455-456):**
   - Merge entry-level CVEs with any CVEs mentioned in rule
   - Store as array in `source_cves` JSONB

6. **Create or update (lines 458-485):**
   - Existing rule: Update `rule_content`, `entry_id`, metadata fields
   - New rule: Create record with `is_draft = true` (line 478)

---

## Rule Validation Engine

**Module:** `backend/app/intelligence/rule_validation.py` (433 lines)

Syntax-only validation (no semantic checks) for 9 rule types (7 formats plus `nuclei` and `panther`). Returns `ValidationResult` with optional errors and suggestions.

### Validation Architecture

**Function:** `validate_rule(rule_type: str, rule_content: str) -> ValidationResult` (lines 405-433)

Routes to format-specific validator via dispatch table:

```python
validators = {
    "sigma": validate_sigma,
    "splunk_spl": validate_splunk_spl,
    "kql": validate_kql,
    "elastic_ql": validate_elastic_ql,
    "crowdstrike_ql": validate_crowdstrike_ql,
    "snort_suricata": validate_snort_suricata,
    "yara": validate_yara,
    "nuclei": validate_sigma,  # YAML-based
    "panther": _validate_panther,
}
```

Each validator returns `ValidationResult(valid: bool, errors: list, suggestions: list)`.

### Per-Format Validators

#### SIGMA Validation (lines 75-149)

**Required fields:** `title`, `status`, `logsource`, `detection`

**Checks:**
- YAML syntax (try `yaml.safe_load()`)
- Root must be dict
- `logsource` must have at least one of: `category`, `product`, `service`
- `detection.condition` required (lines 124-129)
- At least one named selection (not just condition/timeframe) (lines 130-139)

**Suggestions:**
- Missing `level` → suggest severity levels
- Missing `falsepositives` → suggest documenting FP scenarios
- Missing `tags` → suggest ATT&CK mapping

#### Splunk SPL Validation (lines 152-172)

**Checks:**
- Non-empty content
- Balanced parens, brackets, quotes (helper `_check_balanced()`, `_check_balanced_quotes()`)

**Suggestions:**
- Missing `index=` specification

#### KQL/Elastic QL/CrowdStrike QL (lines 175-245)

**Checks:**
- Non-empty content
- Balanced parens, brackets, quotes

**Suggestions (per-format):**
- KQL: Suggests starting with table name before pipes
- EQL: Suggests event categories (process, file, network, registry, sequence, join)
- CrowdStrike: Suggests filtering by event_simpleName or event_platform

#### Snort/Suricata (lines 248-332)

**Structure:** `action protocol src_addr src_port direction dst_addr dst_port (options)`

**Checks per line (lines 265-329):**
- Minimum 7 parts (action, protocol, addresses, ports, direction)
- Valid action from {alert, log, pass, drop, reject, sdrop}
- Known protocol (tcp, udp, icmp, ip, http, ftp, tls, smb, dns, pkthdr)
- Valid direction ({->, <>})
- Options block with parentheses
- Required `sid:` in options
- Suggested `msg:` field

#### YARA Validation (lines 335-372)

**Checks:**
- Non-empty content
- Balanced braces and parens
- Regex match for `rule <name>` declaration (line 350)
- Required `condition:` section (lines 357-362)

**Suggestions:**
- Missing `strings:` section
- Missing `meta:` section (author, description, date)

#### Panther Validation (lines 375-402)

Python-based Panther detections: requires a `def rule(event)` function, checks balanced parens/brackets/braces, and suggests a `def title(event)` function. `nuclei` rules reuse the SIGMA YAML validator.

### Error Data Model

```python
@dataclass
class ValidationError:
    line: int | None          # Line number if available
    column: int | None        # Column (rarely populated)
    severity: str             # "error" | "warning"
    message: str              # Human-readable error text

@dataclass
class ValidationResult:
    valid: bool               # Pass/fail
    errors: list[ValidationError] = []
    suggestions: list[str] = []  # Improvement ideas
```

### Integration Points

- **Backend:** Validation called during extraction (`extract_rules_from_content()`, `rule_extraction.py` lines 42-56), the `POST /detection-rules/validate` endpoint, and the SIGMA import endpoint
- **Frontend:** `useValidateRule()` hook (`useDetectionRules.ts` lines 97-113) triggers real-time validation in CodeMirror editor

---

## Data Model

### DetectionRule (lines 11-85, `detection_rule.py`)

```python
class DetectionRule(Base):
    __tablename__ = "detection_rules"
    
    id                  UUID          PK
    entry_id            UUID          FK (entries)
    created_by          UUID          FK (users)
    rule_type           str(30)       Index (sigma, splunk_spl, kql, etc.)
    title               str(500)
    description         Text
    rule_content        Text          Full rule body
    severity            str(20)       Optional (critical, high, medium, low)
    tags                ARRAY(Text)   Searchable tags
    source_ttps         JSONB         TTPs from entry or rule metadata
    source_cves         JSONB         CVEs from entry or rule metadata
    is_draft            bool          true = unpublished, false = published
    log_sources         JSONB         Category/product/service dict
    mitre_tactics       ARRAY(Text)   Extracted MITRE tactics
    data_sources        ARRAY(Text)   Telemetry sources required
    notes               Text          Analyst notes
    metadata_           JSONB         Extensible metadata
    source_entries      ARRAY(UUID)   Entry IDs rule was extracted from
    source_actors       ARRAY(UUID)   ThreatActor IDs mentioned in rule
    source_campaigns    ARRAY(UUID)   Campaign IDs for context
    license             str(60)       Upstream repo license (MIT/DRL/CC0/...)
    upstream_updated_at DateTime      Source commit date for mirrored rules
    references          ARRAY(Text)   Advisory/blog URLs the rule cites
    source_products     JSONB         Product names the rule detects against
    created_at          DateTime
    updated_at          DateTime
    
    # Relationships
    entry               Entry         Back-reference
    creator             User
    versions            [DetectionRuleVersion]  Immutable edit history
```

The `license`/`upstream_updated_at`/`references`/`source_products` columns carry rule provenance.

**Composite query fields:**
- `entry_title` (property) — Convenience accessor
- `entry_url` (property) — Rule provenance
- `source_repo` / `source_author` (properties) — Upstream repo name and original author, derived from `metadata_` for mirrored rules
- `is_authored_local` (property) — True when the rule originated in-app rather than mirrored from a repo
- `linked_entry_count` / `linked_actor_count` (properties) — Sizes of the `source_entries` / `source_actors` arrays

**Indexes:**
- `rule_type` — Fast filtering in Rule Library
- `created_by` — Per-user rules
- `entry_id` — Reverse lookups from entry

**Eager-load caveat:** The `entry` relationship is `lazy="joined"`, so any `select(DetectionRule)` pulls the full source article with each rule. Bulk read paths that only need rule metadata (e.g., the correlation pivot's related-rules block) deliberately select individual columns instead — the entity form of the query once duplicated each entry's article content per rule and OOM'd the worker on heavily-linked entities.

### DetectionRuleVersion (lines 11-28, `detection_rule_version.py`)

```python
class DetectionRuleVersion(Base):
    __tablename__ = "detection_rule_versions"
    
    id                  UUID          PK
    rule_id             UUID          FK (detection_rules) CASCADE
    version_number      int           1, 2, 3, ...
    rule_content        Text          Immutable snapshot
    rule_type           str(30)       May change across versions
    change_description  Text          Changelog entry
    changed_by          UUID          FK (users)
    created_at          DateTime      When edit was made
    
    # Relationships
    rule                DetectionRule  Back-reference
```

**Semantics:**
- Newly created/auto-extracted rules have no version rows; a version is auto-created whenever `rule_content` changes via `PUT /detection-rules/{id}` (numbered `max + 1`, starting at 1)
- **Immutable:** Old versions never modified; new version created for each edit
- **Rollback:** Rollback endpoint (RuleDetailPage) snapshots the current content as a new version, then restores the target version's content (and type) onto the rule

### DetectionSummary (lines 11-29, `detection_summary.py`)

Captures AI-generated detection content from multi-entry analysis:

```python
class DetectionSummary(Base):
    __tablename__ = "detection_summaries"
    
    id                  UUID          PK
    created_by          UUID          FK (users)
    title               str(500)      User-provided title
    entry_ids           ARRAY(UUID)   Entries analyzed
    analysis_focus      str(30)       campaign | vulnerability | malware | actor
    summary_content     JSONB         Full AI response:
                                      - executive_summary
                                      - attack_chain (list)
                                      - indicators (host/network/behavioral)
                                      - generated_rules (list)
                                      - gaps_and_recommendations
                                      - related_intelligence
    created_at          DateTime
    updated_at          DateTime
    
    # Relationships
    creator             User
```

**Used by:** Detection Workbench page (saves AI analysis for later retrieval).

### TelemetrySource (lines 11-31, `telemetry_source.py`)

Analysts define available data sources to inform feasibility checks:

```python
class TelemetrySource(Base):
    __tablename__ = "telemetry_sources"
    
    id                  UUID          PK
    created_by          UUID          FK (users)
    name                str(255)      e.g., "Windows Event Logs"
    category            str(30)       endpoint | network | email | identity | 
                                      cloud | saas | virtualization | container | 
                                      database | application
    vendor              str(100)      e.g., "Microsoft"
    product             str(100)      e.g., "Windows Server"
    log_types           ARRAY(Text)   e.g., ["Security", "Sysmon", "PowerShell"]
    ingested_into       str(50)       splunk | elastic | sentinel | crowdstrike | etc.
    enabled             bool
    notes               Text          Availability/quality notes
    created_at          DateTime
    
    # Relationships
    creator             User
```

### Mitigation (lines 11-31, `mitigation.py`)

Tracks MITRE ATT&CK mitigations and cross-references:

```python
class Mitigation(Base):
    __tablename__ = "mitigations"
    
    id                  UUID          PK
    mitre_id            str(20)       Unique (M-ID)
    name                str(255)      e.g., "Data Backup"
    description         Text          MITRE description
    mitre_url           Text          MITRE link
    cis_controls        ARRAY(Text)   CIS v8 mappings
    nist_controls       ARRAY(Text)   NIST 800-53 mappings
    article_count       int           Denormalized mention count
    first_seen_at       DateTime
    last_seen_at        DateTime
    wikipedia_url       Text          External reference
    wikipedia_content   Text
    wikipedia_image_url Text
    
    # Relationships
    entry_mitigations   [EntryMitigation]   Links to entries
    ttp_mitigations     [TTPMitigation]     Links to TTPs (M-ID mappings)
```

---

## Detection Workbench

**Component:** `DetectionWorkbenchPage.tsx` (783 lines)

AI-powered interface for analyzing multi-entry threat intelligence and generating detection content.

**Where it lives:** It renders as the collapsible "Generate Rules" generator panel inside the Rule Library section of the Workbench (`WorkbenchPage.tsx` `RulesSection`). `/detection-workbench` redirects to `/workbench/explore`.

### Workflow

1. **Entry Selection**
   - Search bar debounced at 300ms (line 82-84)
   - Multi-select via autocomplete dropdown (lines 298-318)
   - Selected entries shown as removable chips (lines 319-334)

2. **Configuration**
   - **Rule Formats:** Checkbox toggles for SIGMA, Splunk SPL, CrowdStrike QL, Elastic QL, KQL, Snort/Suricata, YARA (lines 340-357)
   - **Analysis Focus:** Dropdown selector for campaign | vulnerability | malware | actor | auto-detect (lines 359-373)

3. **Generation**
   - API call to `/intelligence/detection-summaries` via `useDetectionSummary()` hook (line 89-90)
   - Request payload: `DetectionSummaryRequest` with entry_ids, rule_formats, focus, include_existing_intelligence flag
   - Single long-running POST with loading spinner (lines 408-415). The backend runs the AI task synchronously inside the request, bounded to 150s so a slow provider call can't outlast the 180s gunicorn worker timeout (`detection_summary.py`, lines 166-178)

4. **Results Display** (sections 425-471)

   a. **Executive Summary** (ExecutiveSummarySection)
      - High-level threat overview
      
   b. **Attack Chain** (AttackChainSection)
      - MITRE-mapped steps: tactic → technique
      - Each step includes:
        - Phase (e.g., "Initial Access")
        - Technique ID and name
        - Description
        - Detection opportunity
        - Feasibility badge (High/Medium/Low)
        - Log source tags
      
   c. **Indicators** (IndicatorsSection, lines 544-601)
      - Tabbed view: Network | Host | Behavioral
      - Each indicator card shows type, value, context, detection note
      
   d. **Generated Rules** (GeneratedRulesSection, lines 624-690)
      - Multi-language rule output
      - Copy to clipboard (lines 130-134)
      - Save to library (lines 136-150)
      - Rules display in a preformatted block (line 682)
      
   e. **Related Intelligence** (lines 692-760)
      - Previous articles mentioning same entities
      - Existing detection rules for same TTPs
      - Related CVEs
      
   f. **Gaps & Recommendations** (lines 762-783)
      - Detection gaps (TTPs with no rules)
      - Feasibility constraints
      - Data source recommendations

5. **Export Options** (lines 451-470)
   - **Export Rules:** All generated rules as newline-separated blocks
   - **Export Summary:** Markdown with all sections
   - **Export Navigator:** ATT&CK Navigator JSON layer (line 243-261)

### State Management

```typescript
[entrySearch, setEntrySearch]           // Live input
[debouncedSearch, setDebouncedSearch]   // Debounced for API
[selectedEntries, setSelectedEntries]   // Multi-select state
[ruleFormats, setRuleFormats]           // Checkbox selections
[focus, setFocus]                       // Analysis focus dropdown
[activeIndicatorTab, setActiveIndicatorTab]  // Indicator section tab
[copiedRuleIndex, setCopiedRuleIndex]   // Feedback for copy action
[savedRuleIndices, setSavedRuleIndices] // Track saved rules
```

### Key Hooks

- `useEntitySearch(query)` — Search entries by title (from correlation engine)
- `useDetectionSummary()` — Mutation for AI analysis request (TanStack Query)
- `useCreateDetectionRule()` — Save individual rule to library
- `useNavigate()` — Route to chat agent with entry context

### API Integration

**Frontend → Backend flow:**
1. User clicks "Generate Analysis"
2. `handleGenerate()` assembles `DetectionSummaryRequest` (lines 108-120)
3. `detectionSummary.mutate(request)` POSTs to `/intelligence/detection-summaries`
4. Backend runs AI task with variables (entry data, TTPs, telemetry sources)
5. Frontend receives `DetectionSummaryResponse` with all sections
6. UI renders results with copy/save/export actions

---

## Rule Library

**Component:** `RulesSection` in `WorkbenchPage.tsx`

The rule library is a section of the unified Workbench: sidebar group **DETECTION → Rules Library** at `/workbench/explore`. Deep links: `/workbench/explore?section=rules` activates the section, and `?rules_q=<term>` seeds the search box (used by entity profile "Search library" CTAs).

The library is a research/authoring surface: a faceted rail, provenance columns, and an "Intel → Rules" coverage board.

### Search and Filters

The library reads its rows **and** its facet counts from a dedicated Meilisearch `rules` index via `GET /detection-rules/search` (no client-side query parser). Rows and counts arrive in the same round trip, so the rail narrows with the list instead of showing library-wide totals.

- **Search box** — debounced, relevance-ranked with typo tolerance (`q=` param). Searchable fields: title, description, tags, tactics, techniques, source products, repo, author, and the actors/malware/tools/vendors/products borrowed from the rule's source entry — so typing "APT33" or "Fortinet" filters the list even though rules carry no such columns of their own.
- **Facet rail** — fourteen groups: **Rule format** (`rule_type=`), **Severity** (`severity=`), **ATT&CK tactic** (`tactic=`), **Technique** (`technique=`), **Telemetry** (`telemetry_token=`), **Source repo** (`source_repo=`), **Author** (`source_author=`), **License** (`license=`), **Tags** (`tag=`), and the entry-borrowed **Actors** / **Malware** / **Tools** / **Vendors** / **Products** (`actor=`, `malware=`, `tool=`, `vendor=`, `product=`).
  - Values within one group OR together; groups AND with each other. Ticking two formats widens the list.
  - Counts are **disjunctive** — each facet is counted with every other filter applied but not its own, so picking "sigma" still shows the other formats. This costs one extra Meilisearch query per active facet, batched into a single multi-search request.
- **Telemetry switch** — All telemetry / My telemetry / Gaps, beside the search box. It is a **bulk-select over the rail's Telemetry group**, not a filter of its own: clicking it ticks the matching boxes and the boxes do the filtering, so the list can never disagree with what the rail shows and every tick stays adjustable afterwards. The same action sits on the group itself as `select mine`. Which values count as collected comes from `GET /detection-rules/telemetry-vocabulary` — the match is tiered and fuzzy (a ticked product name, a canonical behaviour id, or a category with a ticked source), so the client cannot derive it by comparing strings. Hand-editing the ticks leaves no segment lit rather than one claiming a preset that no longer holds.
  - Because a group ORs internally, "My telemetry" means *touches at least one source we collect* — partially covered rules included. For the strict "every required source is collected" read, the API takes `telemetry=covered|missing`; the Telemetry column's per-row ring shows the same verdict.
- **Research Views** — All rules / New this week (`created_after=`) / Recently updated upstream (sorts by `upstream_updated_at`) / My drafts (`authored_local=true` + `is_draft=true`). These have no facet group of their own, so they narrow every count including their own.
- **Lens toggle** — client-side regrouping of loaded rows: Flat / Technique / Repo / Product
- **Library / Intel → Rules toggle** — the board mode renders `RuleCoverageBoard` (backed by `GET /detection-rules/coverage-board`): entities trending in recent entries with how many library rules cover each
- **Sortable column headers** — Rule (title) and Added (created_at) in the UI; `sort_by` also accepts rule_type, severity, is_draft, updated_at, upstream_updated_at, and `relevance` (used automatically whenever the search box has text)

`GET /detection-rules` (PostgreSQL, `ILIKE` substring matching) remains for scripted/API use and for the `search=` + `status=` shape; the UI no longer calls it for the list.

**Deep links:** `?rules_q=<term>` seeds the search box (used by entity profile "Search library" CTAs).

The app's global search bar covers rules too, as one entity type among many: `rule:`, `rule.type:`, `rule.severity:`, `rule.data_source:`, `rule.tactic:`, `rule.tag:`, `rule.draft:`, `rule.license:` (see [`query-language.md`](query-language.md)). Use that to find rules *alongside* other intelligence; use the library when rules are the subject.

#### The `rules` index

`entity_indexer.sync_rules()` builds one document per rule. Beyond the rule's own columns it precomputes four things Meilisearch cannot express:

- **`authored_local`** — "no repo in metadata"; Meilisearch has no "attribute is absent" filter.
- **`telemetry_tokens`** — what the rule needs to fire, across every format: `data_sources` where declared, else the Sigma `log_source` triple or the per-format defaults (`detection_coverage.telemetry_tokens_from_rule`). This is what the rail's **Telemetry** group faces: 8,479 of the corpus leave `data_sources` empty and would otherwise be untickable. The raw column stays filterable for the `data_source=` param, but is no longer a facet.
- **Entity links** — actors/malware/tools/vendors/products resolved from the source entry's autolink junctions, one query per junction per batch.
- **Flattened JSONB** — `source_products` and `source_cves` have historically held both bare strings and `{name: ...}` objects; both are flattened to strings so a facet has one value per product rather than a mix of shapes.

Timestamps are epoch integers, not ISO strings, so range filters and sorts compare numerically. `maxTotalHits` is raised to 100,000 (the default 1,000 caps both the reported total *and* paging depth), and facet values are sorted by count so the default 100-value truncation keeps the meaningful ones — sorted alphabetically, the Technique facet stopped at T1068 and dropped T1078, its most common technique.

Writes keep the index current: create, update, bulk-update and both delete paths re-index or remove the affected documents. Drift is healed by `sync_entity_search_indexes` (every 4 hours), which now includes rules.

`source_products` stays searchable but is deliberately **not** a facet: only a handful of rules declare it and the values are raw CPE strings (`6bk1602-0aa12-0tp0_firmware`). The Products facet uses the entry-derived `products` instead — the same vocabulary as the rest of the app.

### Display

Plain table with infinite scroll (100 rules per page, IntersectionObserver sentinel — not virtualized):
- Severity stripe (color-coded critical/high/medium/low) + checkbox column for multi-select
- Rule cell — title (clickable through to `/workbench/rule/{id}`) with format badge, severity, CVE chip, and linked-entry count
- Source — "authored here" vs. upstream GitHub repo, original author, and license (provenance columns)
- ATT&CK — technique chips (first 3)
- Telemetry — per-rule feasibility ring against the enabled telemetry inventory
- Added — relative age

Toolbar actions: **+ New Rule** (`/workbench/rule/new`), **Generate Rules** (toggles the embedded AI Detection Workbench generator panel), **Import**, **Export**.

### Bulk Operations

Selecting rows reveals a bulk bar: Publish / Unpublish / Export (ZIP) / Delete (with undo toast) / Clear.

`useBulkUpdateRules()` hook (lines 133-152 in `useDetectionRules.ts`) → `POST /detection-rules/bulk-update`:
- `is_draft` — bulk publish/unpublish
- `tags_add` / `tags_remove` — bulk tag management (API-level; the UI bulk bar currently only exposes publish state)

---

## Detection Coverage Analysis

### Telemetry-Aware Coverage Classification

**Service:** `backend/app/services/detection_coverage.py`

Coverage is deliberately not a rule-lifecycle concept. Each ATT&CK technique (or CVE) is classified three ways:

| Status | Meaning |
|--------|---------|
| `covered` | At least one **non-draft** rule references it AND that rule's `data_sources` are all satisfiable by the enabled telemetry inventory (rules with no data sources count as satisfiable). |
| `library_only` | Rules exist, but every one requires data sources missing from enabled telemetry. `missing_data_sources` reports the best (fewest-missing) rule's gaps — the cheapest telemetry unlock. |
| `no_rule` | No non-draft rule references the technique at all. |

Key functions:
- `classify_techniques(db, technique_ids)` — matches rules via `source_ttps` JSONB (with a legacy fallback on `mitre_tactics`), returns `{technique_id: {status, rule_count, satisfiable_rule_count, missing_data_sources, rules[]}}` (max 5 rules per technique)
- `classify_cves(db, cve_ids)` — same statuses; a rule references a CVE when `source_cves` contains it or the title mentions it
- `summarize(classification)` — aggregate counts + `coverage_percentage`
- `entry_opportunity_tiers(...)` — per-entry tier: `actionable_gap` (some technique has no rule at all), `telemetry_gap` (rules exist but are telemetry-blocked), or `None`

Data-source ↔ telemetry matching (normalized exact or bidirectional substring match) is shared with the rule-detail feasibility check, so both surfaces agree on "satisfiable."

**API endpoint:** `POST /intelligence/detection-coverage` with a list of technique IDs (max 500) → `{summary, techniques}`. Used by entity profiles to roll up genuine detection coverage; also feeds the ATT&CK matrix (below).

### Coverage Gap Detection

**Widget endpoint:** `GET /widgets/attack-coverage-gap` (`widgets_detection.py` lines 49-96)

Identifies TTPs mentioned in recent articles that lack detection rules:

```python
# Query entries with TTPs but NO detection rules
covered_entries = select(DetectionRule.entry_id)  # Rules link to entries

# Find TTPs in UNCOVERED entries
select(
    TTP.technique_id,
    TTP.technique_name,
    TTP.tactic,
    count(distinct EntryTTP.entry_id)  # Frequency
)
.join(TTP, TTP.id == EntryTTP.ttp_id)
.where(
    EntryTTP.extracted_at >= start,
    EntryTTP.extracted_at <= end,
    ~EntryTTP.entry_id.in_(covered_entries)  # NOT in covered_entries
)
.group_by(TTP.id, ...)
.order_by(count DESC)
.limit(15)
```

**Output:** Ranked list of gap techniques with:
- technique_id, technique_name, tactic
- mention_count (how many articles reference this TTP without rules)

**Use case:** Priority queue for which TTPs to author rules for next.

### Format Breakdown Widget

**Endpoint:** `GET /widgets/detection-format-breakdown`

Counts rules by type in a date window:

```python
select(DetectionRule.rule_type, count())
.where(DetectionRule.created_at >= start, <= end)
.group_by(rule_type)
```

**Output:** `[{rule_type, count}, ...]` — Visualized as bar chart showing SIGMA vs. Splunk vs. YARA distribution.

### KEV Coverage

**Endpoint:** `GET /widgets/kev-matches`

Identifies known exploited CVEs (from CISA KEV catalog) mentioned in detection gaps:

```python
window_cves = CVEs mentioned in [date_from, date_to]
kev_cves = window_cves WHERE exploit_status="active_exploitation"
          OR exploit_availability="active_exploitation"

select(CVE, mention_count, ...)
.where(CVE.id.in_(kev_cves))
.order_by(mention_count DESC, cvss_score DESC)
```

**Output:** CVE list with CVSS/EPSS scores and mention count — prioritizes which CVEs to create rules for.

---

## ATT&CK Catalog and Matrix

The full MITRE ATT&CK catalog is hydrated locally and rendered as a Navigator-style matrix with feed-frequency heat and telemetry-aware coverage.

### Catalog Hydration

**Module:** `backend/app/intelligence/attack_catalog.py`

- Fetches official ATT&CK STIX bundles for the `enterprise`, `mobile`, and `ics` domains and upserts every technique into the `ttps` table
- Catalog fields on `TTP`: `matrix_domain`, `tactics` (all tactics; `tactic` remains the primary), `is_subtechnique`, `parent_technique_id`, `is_deprecated`
- Refreshed via `scripts/seed/seed_mitre_attack.py` (run inside the API container) or the enrichment worker task that calls `hydrate_attack_catalog()` (`workers/enrichment_tasks.py`)

### Matrix Endpoint

**Endpoint:** `GET /attack/matrix?domain=enterprise|mobile|ics&days=<n>&include_deprecated=<bool>` (`attack.py` lines 95-223)

- Tactics returned in canonical kill-chain order (`TACTIC_ORDER`, lines 29-78) with legacy/v18 slug handling; empty tactics dropped
- Per-technique cell: `article_count` (windowed via `days`, or the all-time rollup), `rule_count`, `has_rule`, `coverage` (covered / library_only / no_rule via `classify_techniques()`), `deployable` (legacy boolean alias for `coverage == "covered"`), `missing_data_sources`, nested `subtechniques`, and `rollup_article_count` (parent + subs)
- Top-level payload includes `coverage_summary` and `max_article_count` for heat scaling
- Heavy aggregate — cached in Redis for 180s per `(domain, days, include_deprecated)` combination

### Matrix UI

**Component:** `AttackMatrixSection.tsx` — Workbench sidebar **DETECTION → ATT&CK Matrix**

- Domain toggle (Enterprise / Mobile / ICS) and time windows (7d / 30d / 90d / All)
- Three layer modes: **Feed heat** (color by article frequency), **Coverage** (color by covered/library_only/no_rule), **Both** (heat fill + coverage edge)
- Coverage legend: covered = green, "Missing telemetry" (library_only) = amber, "No rule" = red
- Expandable sub-technique rows; hover tooltip shows coverage status and missing data sources; cells click through to TTP profiles
- Client-side ATT&CK Navigator layer export via `buildNavigatorLayer()` (`utils/attackMatrix.ts`)

---

## Export and Integration

### Export Formats

**API endpoint:** `GET /detection-rules/export?format=yaml|zip&rule_ids=<csv>`

Supported formats:

| Format | Content | Use |
|--------|---------|-----|
| **YAML** | YAML-based rules (SIGMA, Nuclei) | Import to detection as code repos |
| **ZIP** | All selected rules + metadata | Backup, sharing |
| **ATT&CK Navigator Layer** | Technique coverage heatmap | Strategic visualizations |

**Frontend integration:** `useExportRules()` hook (lines 191-219, `useDetectionRules.ts`) — triggers a blob download of `detection-rules.zip` / `.yml`

### Rule Import

**Endpoint:** `POST /detection-rules/import`

- Accepts a single `.yml`/`.yaml` file or a `.zip` archive (non-YAML zip entries counted as skipped)
- **SIGMA only** — each YAML document is validated with `validate_rule("sigma", ...)`; failures land in `errors`
- Imported rules are created as drafts with title/description/severity/tags/tactics lifted from the SIGMA fields; no content-hash dedup — re-importing creates duplicates
- Returns: `{imported: N, skipped: M, errors: [...]}`

**Frontend:** `useImportRules()` hook

### ATT&CK Navigator

**Endpoint:** `GET /attack/layer` (`attack.py` lines 226-308)

Generates navigator-compatible JSON layer:

```python
techniques = []
for ttp in covered_ttps:
    score = (mention_count / max_mention) * 100
    intensity = 255 - (score / 100) * 155
    color = f"#ff{intensity:02x}{intensity:02x}"  # Red gradient
    
    techniques.append({
        "techniqueID": row.technique_id,
        "tactic": row.tactic,
        "color": color,           # Gradient by frequency
        "score": score,           # 0-100
        "comment": f"Found in {row.count} articles",
        "metadata": [
            {"name": "articles", "value": str(row.count)},
            {"name": "latest", "value": str(row.latest.date())},
        ]
    })

return {
    "name": "IntelFeed - Detected TTPs (Month Year)",
    "domain": "enterprise-attack",
    "versions": {"attack": "15", "navigator": "4.9.5", "layer": "4.5"},
    "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
    "techniques": techniques
}
```

**Frontend:** DetectionWorkbenchPage exports navigator layer on demand (line 243-261).

**Use:** Import into MITRE ATT&CK Navigator at https://mitre-attack.github.io/attack-navigator/ for heatmap visualization.

---

## Telemetry Sources and Feasibility

### Inventory Management

Analysts maintain their telemetry inventory in the Workbench (**DETECTION → Telemetry Sources**). CRUD endpoints: `GET/POST /telemetry-sources`, `PUT/DELETE /telemetry-sources/{id}`.

Two catalog endpoints back the picker UI:

- `GET /telemetry-sources/taxonomy` — legacy flat taxonomy: `{category: [data_source_name, ...]}` (e.g., `endpoint: ["process_creation", "file_creation", ...]`)
- `GET /telemetry-sources/catalog` — prepopulated catalog entries (`name`, `category`, `vendor`, `product`, `log_types`) for checkbox selection
- `POST /telemetry-sources/sync` — reconciles `TelemetrySource` records against a list of selected catalog names (creates / enables / disables; returns per-item actions and counts)

### Feasibility Checking

**Endpoint:** `POST /telemetry-sources/check-feasibility`

Request:
```json
{
  "data_sources": ["Windows Security Log", "Network IDS", "Endpoint EDR"]
}
```

Response:
```json
{
  "feasible": ["Windows Security Log", "Endpoint EDR"],
  "missing": ["Network IDS"],
  "coverage_pct": 0.67
}
```

Matching delegates to `services/detection_coverage.py` (`get_available_telemetry()` + `split_data_sources()`), so the rule-detail feasibility badge, telemetry gaps, and the ATT&CK matrix coverage statuses all agree on what "satisfiable" means.

**Frontend hook:** `useCheckFeasibility()` (lines 221-231, `useDetectionRules.ts`)

**Integration:** Rule detail page re-checks feasibility whenever the rule's data sources change and shows a badge colored by `coverage_pct` (≥0.8 green, ≥0.5 amber, else red).

### Telemetry Gaps

**Endpoint:** `GET /telemetry-sources/telemetry-gaps`

Scans every rule that declares `data_sources` and returns `{rules_with_gaps[], total_rules_checked, rules_with_gaps_count, most_needed_sources[]}` — rules sorted by lowest coverage, plus the top 20 most-needed missing sources across the library (a telemetry shopping list).

---

## Mitigations and ATT&CK Integration

### Mitigation Model

TTP-to-mitigation mappings (`TTPMitigation` junction table in `mitigation.py`):

```python
class TTPMitigation(Base):
    ttp_id: UUID        FK (ttps)
    mitigation_id: UUID FK (mitigations)
    created_at: DateTime
```

Also entry-level mitigations (`EntryMitigation`):
```python
class EntryMitigation(Base):
    entry_id: UUID
    mitigation_id: UUID
    confidence: str             # high | medium | low
    source: str                 # regex | ai
    extracted_at: DateTime
    paragraph_indices: int[]    # Where in entry text
```

### MITRE ATT&CK Integration

**Technique listing:** `GET /attack/techniques`

Returns top techniques by frequency (default limit 50, max 500; default window last 30 days):

```json
[
  {
    "technique_id": "T1059.001",
    "name": "Command and Scripting Interpreter: PowerShell",
    "tactic": "execution",
    "count": 42,
    "latest": "2024-01-15"
  },
  ...
]
```

**Frontend:** Displayed in campaigns, entity profiles, workbench results.

### Detection Rule → Mitigation Flow

1. Rule extracts `mitre_tactics` from YAML tags (e.g., `attack.execution`)
2. TTPs in entry are fetched; mitigation mappings retrieved
3. Suggested mitigations displayed in rule detail page
4. Analyst can manually link mitigations via UI

---

## Detection Workbench Advanced Features

### Rule Conversion (AI-powered)

**Endpoint:** `POST /detection-rules/{ruleId}/convert`

Request:
```json
{
  "target_type": "splunk_spl"
}
```

Response (via `useConvertRule()` hook):
```typescript
{
  converted_content: string,      // Target format rule
  source_type: string,
  target_type: string,
  model: string,                  // e.g., "claude-opus"
  tokens_input: number,
  tokens_output: number,
  tokens_used: number,
  cost: number
}
```

**Use case:** Convert SIGMA rule to Splunk SPL for local deployment.

### Rule Chat (Streaming)

**Function:** `streamRuleChat(options, signal?)` (lines 547-627, `useDetectionRules.ts`)

Streaming endpoint for asking AI about a rule:

```typescript
POST /detection-rules/chat with:
{
  message: string,
  rule_content: string,
  rule_type: string,
  title: string,
  severity: string,
  mitre_tactics: string[],
  data_sources: string[],
  history: ChatMessage[]
}
```

**Response:** Server-sent events (SSE) with `data: {text, error}` frames.

**Frontend:** Real-time streaming text display in rule detail chat panel.

### Version Management

**Rollback:** `POST /detection-rules/{ruleId}/versions/{versionId}/rollback`

Snapshots the current content as a new version, then restores the target version's content onto the rule:

```python
snapshot = DetectionRuleVersion(
    rule_id=rule_id,
    version_number=max_ver + 1,
    rule_content=rule.rule_content,  # Pre-rollback content preserved
    change_description=f"Snapshot before rollback to v{target_version.version_number}",
    changed_by=user.id,
)
rule.rule_content = target_version.rule_content  # Restored
```

**Timeline:** RuleDetailPage shows version history with dates, authors, change descriptions.

### Provenance Tracking

**Endpoint:** `GET /detection-rules/{ruleId}/provenance`

Returns the full intelligence provenance chain:
```typescript
{
  rule: {                 // id, title, rule_type, created_at, plus upstream
    source_repo,          // provenance: repo, author, license, references,
    source_author,        // upstream_updated_at
    license, references, upstream_updated_at, ...
  },
  entries: Entry[],       // Linked entries (source_entries + entry_id)
  ttps: TTP[],            // TTPs from linked entries
  threat_actors: Actor[], // From linked entries + source_actors
  malware: Malware[]      // From linked entries
}
```

Two sibling research endpoints round out the provenance panel on RuleDetailPage:
- `GET /detection-rules/{ruleId}/fresh-intel` — entries on the rule's CVEs/techniques that arrived **after** the rule was last edited (the decay signal)
- `GET /detection-rules/{ruleId}/related` — rules related by shared CVE, shared technique, alternate format, or near-duplicate content

---

## Appendix: Frontend Components Reference

| Component | File | Purpose |
|-----------|------|---------|
| `RulesSection` | `pages/WorkbenchPage.tsx` | Rule library section of the Workbench (search, filters, bulk ops, import/export) |
| `DetectionWorkbenchPage` | `pages/DetectionWorkbenchPage.tsx` | Multi-entry AI analysis interface (embedded generator panel in `RulesSection`) |
| `RuleDetailPage` | `pages/RuleDetailPage.tsx` | Single rule view with edit/version/chat (`/workbench/rule/:id`) |
| `AttackMatrixSection` | `components/AttackMatrixSection.tsx` | ATT&CK matrix with feed heat + coverage layers |
| `RuleBuilderShell` | `components/RuleBuilderShell.tsx` | CodeMirror editor wrapper |
| `SaveRuleModal` | `components/SaveRuleModal.tsx` | Modal for creating new rules |
| `RuleEntryCard` | `components/RuleEntryCard.tsx` | Compact rule display card |
| `RuleCoverageBoard` | `components/RuleCoverageBoard.tsx` | Intel → Rules coverage board (trending entities vs. rule counts) |
| `CodeMirrorEditor` | `components/CodeMirrorEditor.tsx` | Syntax-highlighting editor with validation |
| `DetectionCoverageWidget` | `components/widgets/DetectionCoverageWidget.tsx` | Dashboard widget for coverage metrics |
| `DetectionFormatBreakdownWidget` | `components/widgets/DetectionFormatBreakdownWidget.tsx` | Chart of rules by type |
| `AttackCoverageGapWidget` | `components/widgets/AttackCoverageGapWidget.tsx` | Uncovered-technique ranking widget |
| `KEVMatchesWidget` | `components/widgets/KEVMatchesWidget.tsx` | Known-exploited CVE widget |

## Appendix: Backend API Endpoints Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/detection-rules` | POST | Create new rule |
| `/detection-rules` | GET | List rules (PostgreSQL; paginated, `search=`/`status=` filters) |
| `/detection-rules/search` | GET | Library list + disjunctive facet counts (Meilisearch `rules` index) |
| `/detection-rules/{id}` | GET | Fetch single rule (with telemetry feasibility annotation) |
| `/detection-rules/{id}` | PUT | Update rule (content change creates a new version) |
| `/detection-rules/{id}` | DELETE | Delete rule |
| `/detection-rules/{id}/status` | PATCH | Publish/unpublish |
| `/detection-rules/facets` | GET | Facet distribution counts (type, repo, tactic, product) |
| `/detection-rules/coverage-board` | GET | Trending entities vs. library rule counts (Intel → Rules board) |
| `/detection-rules/{id}/versions` | GET | List all versions |
| `/detection-rules/{id}/versions/{vid}` | GET | Fetch single version |
| `/detection-rules/{id}/versions/{vid}/rollback` | POST | Revert to previous version (snapshots current first) |
| `/detection-rules/validate` | POST | Syntax validation |
| `/detection-rules/extract-metadata` | POST | Parse rule, extract fields |
| `/detection-rules/bulk-update` | POST | Batch tag/publish/unpublish |
| `/detection-rules/bulk-delete` | POST | Batch delete |
| `/detection-rules/import` | POST | Import YAML/ZIP |
| `/detection-rules/export` | GET | Export selected rules |
| `/detection-rules/{id}/convert` | POST | AI rule format conversion |
| `/detection-rules/{id}/provenance` | GET | Source entries, entities, and upstream lineage |
| `/detection-rules/{id}/fresh-intel` | GET | New intel since the rule's last edit |
| `/detection-rules/{id}/related` | GET | Related rules (shared CVE/technique, alt format, near-dup) |
| `/detection-rules/{id}/commits` | GET | Upstream GitHub commit timeline (mirrored rules) |
| `/detection-rules/needing-review` | GET | Published rules with new intel for their techniques |
| `/detection-rules/{id}/diff` | GET | Version comparison |
| `/detection-rules/chat` | POST | Streaming AI chat about rule |
| `/intelligence/detection-summaries` | POST | Generate multi-entry analysis |
| `/intelligence/detection-summaries` | GET | List saved summaries |
| `/intelligence/detection-summaries/{id}` | GET | Fetch saved summary |
| `/intelligence/detection-summaries/{id}` | DELETE | Remove summary |
| `/intelligence/detection-coverage` | POST | Classify techniques covered / library_only / no_rule |
| `/entries/{id}/extract-detection-rules` | POST | Re-run regex extraction on one entry |
| `/entries/{id}/generate-rules` | POST | AI rule generation from one entry |
| `/attack/matrix` | GET | Full ATT&CK matrix with heat + coverage |
| `/attack/layer` | GET | ATT&CK Navigator JSON |
| `/attack/techniques` | GET | Ranked technique list |
| `/widgets/detection-format-breakdown` | GET | Rule type distribution |
| `/widgets/attack-coverage-gap` | GET | Uncovered techniques |
| `/widgets/kev-matches` | GET | Known exploited CVEs |
| `/telemetry-sources/taxonomy` | GET | Legacy flat data-source taxonomy |
| `/telemetry-sources/catalog` | GET | Prepopulated telemetry catalog |
| `/telemetry-sources/sync` | POST | Sync inventory to catalog selections |
| `/telemetry-sources/check-feasibility` | POST | Assess rule implementability |
| `/telemetry-sources/telemetry-gaps` | GET | Missing data sources |

---

## See Also

- **Section 9 of architecture.md** — Overview of rule formats, lifecycle, and gap analysis
- **backend/app/intelligence/** — All extraction, validation, and generation logic
- **backend/app/api/** — REST endpoint definitions
- **frontend/src/pages/** — Page-level UI components
- **frontend/src/hooks/useDetectionRules.ts** — All detection-related TanStack Query hooks

