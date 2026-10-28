# Entity Profiles

For developers: how the profile page for an actor, malware, CVE or any other entity is put together, and where to change it.

See diagram: [Entity profile assembly](diagrams/entity-profiles-assembly.md)

## One page, many entity types

Every profile — actors, malware, CVEs, CWEs, TTPs, countries, sectors, tools, observables, mitigations, vendors, products, campaigns — renders through `frontend/src/pages/EntityProfilePage.tsx`. A per-type entry in `frontend/src/components/entityProfile/entityProfileConfig.tsx` sets the tabs, header badges and identity fields, extra Overview panels, external lookup links, and whether the name is editable (`nameEditable`). Header, tabs and panels sit beside it in `components/entityProfile/`.

## Page anatomy

- **Header.** Breadcrumb, type badge and name (click to rename where `nameEditable`). **SignalBadges** are click-to-edit chips (motivation, malware type, tactic, severity, CVSS, EPSS, KEV, region); the country badge links to its profile. Also:
  - **Ask Copilot**, a **Watch** toggle, enrichment status
  - an actions menu: markdown export, merge into, add to campaign, convert to another type. Merge and convert are admin-only; convert writes a tombstone so the old name isn't recreated.
- **Strip under the header.** Mentions timeline and pulse line. CVEs add a lifecycle strip; observables add `ObservableLifecycleStrip`.
- **Overview tab:**
  - description via `EntityLinkedMarkdown` (names become links)
  - assessment block with recent developments (`GET /api/engine/entities/{type}/{id}/whats-new`)
  - known associates and identity fields
  - entity-scoped AI analysis (`AIAnalysisModule`, for prompts with `show_in_entity_actions`)
  - essential reading, Wikipedia summary, analyst notes (`EntityNotesSection`), activity feed
  - sources card and next-actions rail
  - per-type config panels (CVE affected products, TTP MITRE details and mitigations, CWE family and catalog, infrastructure on actors, malware, tools and campaigns)
- **Relationships tab** (all types). A typed graph that draws claims only, plus a list in two parts:
  - **Claims** — typed verbs graded by trust (confidence from analyst action or AI adjudication).
  - **Co-mentions** — entities in the same articles, marked not claims.

  Rows show verb, evidence count, sparkline, confirm / reject; filterable and sortable.
- **Detection tab** (actor, malware, campaign, CVE, CWE, TTP). Linked rules and coverage; **Detection Gaps** (uncovered techniques) opens from the rail's "Review gaps". Public read-only visitors see neither.
- **Vulnerabilities tab** (CWE, vendor, product). CVEs with this weakness, or affecting this vendor/product via `cve_affected` (NVD CPE links, separate from `entity_relationships`).
- **Weaknesses tab** (CVE). The CVE's CWEs.
- **Geography tab** (country). Role breakdown; actors from or targeting the country.
- **Victimology tab** (sector). Who targets the industry (reporting vs claims), plus leak-site victims.

## Where the data comes from

| Source | How | What it fills |
|---|---|---|
| Autolinker | Dictionary scan at ingest (`backend/app/intelligence/autolinker.py`), with junk-alias and LOLBin filtering | Entry links for actors, malware, countries, vendors, products, tools, mitigations |
| Regex and AI extraction | `CVE-YYYY-NNNN` and `TNNNN(.NNN)` regex; one-pass AI analysis | CVE and TTP links, new entities, sectors, indicators |
| NVD / EPSS / KEV / GitHub PoC | Scheduled syncs ([entries.md](entries.md#beat-scheduled-enrichment)) | CVE scores, exploit status, affected products |
| MITRE ATT&CK / Malpedia / Wikipedia | Weekly syncs | TTP details and mitigations; actor and malware descriptions and aliases |
| Wikidata / endoflife.date | Weekly and daily syncs ([rules](automation-ai-enrichment.md#wikidata)) | Vendor websites and facts, product vendors, country regions; product support status and releases |
| Co-occurrence and the Telegram forward graph | Post-ingest pipeline step; job every 4 hours | `entity_relationships` links |
| Analyst | Badge edits, descriptions, merges, notes, relationship confirm/reject | Any of the above, marked analyst-sourced |

### Relationships and trust

Rows in `entity_relationships` (`backend/app/models/entity_relationship.py`) have:
- a **verb**: `uses`, `exploits`, `targets`, `attributed_to`, `variant_of`, `communicates_with`, `delivers`, `drops`, `controls`, `related_to`, `successor_of`, `subgroup_of`, `overlaps_with`
- a **confidence**: `confirmed`, `probable` or `possible`
- a **source**: `co_occurrence`, `auto_extracted`, `analyst_confirmed`, `analyst_created`, `analyst_rejected` or `external_feed` (the MITRE ATT&CK import writes `external_feed` with `confirmed`)
- **`evidence_entry_ids`**: the supporting articles

Writes check (source type, verb, target type) against the allowlist in `backend/app/intelligence/relationship_matrix.py`; a disallowed combination is flipped to its allowed direction or dropped.

The adjudicate stage reviews machine links (`auto_extracted`, `co_occurrence`) against the evidence article:
- **Demote** sets `adjudication_verdict = coincidental` and confidence `possible`; the link is never promoted again.
- **Keep** adds the article to `reviewer_kept_entry_ids`. Once `relationship_evidence_promote_count` different articles keep it, it becomes `confirmed` / `corroborated`.

A link with a verdict leaves the review list, so later co-mentions can't undo it. Analyst and `external_feed` links are never reviewed.

Two tombstones stop rejected data returning:
- `source = analyst_rejected` rows stay, so co-occurrence never recreates a rejected pair.
- Converting an entity's type writes an `entity_reclassify_tombstones` row, so importers don't recreate the old name.

## Observables and infrastructure

The observable profile is the simplest: the heading is the value in monospace, nothing is editable inline, and badges are lifecycle facts (kind, role, confidence, status, capture method). It has two tabs (`overview`, `relationships`) and two Overview panels:

- **`observable_provenance`** — capture method, shared-infrastructure tag, role, evidence sentence; base and current confidence, decay and projected expiry; the **Sources** row (`N reports · M feeds`, plus raw sighting count), with a "Reporting" row flagging feed-only values. Buttons: copy (plain or defanged), export sightings CSV, pin confidence, tombstone (admins).
- **`observable_backlinks`** — **Attribution**: who claims the value (verb and trust level), and which actors, malware, campaigns and tools the reporting articles name ("reported with").

`ObservableLifecycleStrip`, mounted by the page rather than the config, draws first seen → latest report → projected expiry. For feed-only values the middle point reads "Listed on N indicator feed(s)".

Actor, malware, campaign and tool profiles carry the **`infrastructure`** panel, from `useEntityInfrastructure` (`GET /api/entities/{type}/{id}/infrastructure`), in two groups:
- **Claimed** — observables linked by an evidenced claim.
- **Reported alongside** — observables in articles that also name the entity, computed on load and never stored; indicator files and newsletters are excluded.

Rows link to observable profiles; buttons are "Copy all defanged" and "Export CSV". The Relationships tab shows only claim-backed observables. See [observables.md](observables.md#attribution-claimed-vs-reported-alongside).

## Field provenance

Single fields (an actor's motivation, origin country, targeted sectors, assessment text) have their own provenance, separate from relationship trust, in `entity_field_claims` (`backend/app/models/entity_field_claim.py`), one row per (field, value, source). Every path that sets a field writes a claim:

| Source kind | Written by |
|---|---|
| `analyst` | Per-type `PUT /api/entities/...` endpoints via `_apply_fields` (only on a real change), and the sector tool |
| `ai_extraction` | `intelligence/enrichment.py` while reading an article (records the `entry_id`) |
| `ai_assessment` | The AI gap-fill in `workers/entity_maintenance_tasks.py` and the assessment writer in `services/entity_summary.py` (the model's reason is the quote) |
| `enrichment` | `enrichment/entity_updater.py` (Wikipedia, MITRE ATT&CK, Malpedia, Wikidata, endoflife.date and the other sources' declared columns) and the sector rollup in `workers/maintenance.py`, which writes `threat_actor_target_sectors` / `malware_target_sectors` rows from the entity's articles and rebuilds the `targeted_sectors` cache (`services/sector_links.py`). |
| `external_feed` | The CyberGeist attribute fill (`workers/enrichment_tasks.py`) and the ransomware.live sync (`intelligence/ransomware_sync.py`) |
| `seed` | Reserved for seeded reference data; nothing writes it. |

Rules:
- **Recording never blocks the edit.** `record_claim` (`services/claim_provenance.py`) returns a bool and catches its own errors.
- **Agreement is computed, never stored.** `get_entity_claims` compares claims with the current value on read; losing claims stay as history.

Fields with a value but no claim return in `unsourced_fields`, marked unsourced.

Claims merge on `claim_key` (entity + field + value + source + article): a nightly sync repeating a value only updates its timestamp, while different sources or articles stay separate rows — that is the agreement count shown. `scripts/maintenance/backfill_field_claims.py` fills the table from existing provenance (`actor_description_history`, `enrichment_results`, `created_via` / `created_from_entry_id`); anything untraceable stays unsourced on purpose.

## Backend endpoints

All paths are under `/api`.

| Endpoint | Returns |
|---|---|
| `GET /entities/{type}/{id}/provenance` | each tracked field's claims with article, feed and feed reliability grade, plus `unsourced_fields` |
| `GET /entities/{type}/{id}/infrastructure` | claimed and reported-alongside observables |
| `GET /engine/entities/{type}/{id}/whats-new` | recent developments for the assessment block |
| `GET /intelligence/pivot/{type}/{id}` | the entity, related entities and entries |
| `GET /intelligence/graph/{type}/{id}` | graph nodes and typed edges |
| `GET /intelligence/timeline/{type}/{id}` | correlation events |
| `/entity-relationships` | list, create, update, confirm, reject |
| `/entity-notes` | notes CRUD |
| `GET /export/entities/{type}/{id}`, `POST /export/entities/bulk` | markdown export (bulk returns a ZIP) |

Each type also has CRUD, merge, duplicates and merge-suggestion endpoints.

Pivot and graph responses are cached in Redis under `intelfeed:corr:pivot3:*` and `intelfeed:corr:graph3:*` for `correlation_cache_ttl_seconds`. After changing either response shape, flush `intelfeed:corr:*`.
