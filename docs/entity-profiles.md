# Entity Profiles

How entity profile pages are assembled: which pipelines and syncs produce the data, where it is stored, and how the single config-driven profile page renders it.

See diagram: [Entity profile assembly](diagrams/entity-profiles-assembly.md)

## One page, many entity types

All entity profiles (threat actor, malware family, CVE, TTP, country, tool, mitigation, vendor, product) render through a single shell, `frontend/src/pages/EntityProfilePage.tsx`, driven by per-type declarations in `frontend/src/components/entityProfile/entityProfileConfig.tsx` (tab components, header, badges, and panels live alongside it in `components/entityProfile/`). The config declares, per type: available tabs, header signal badges, identity fields, overview panels, and external pivot links. Campaigns are the one exception — they keep their own page (overview / timeline / entities / ATT&CK / detection gaps / suggestions).

## Page anatomy

- **Header** — breadcrumb, type badge, name (click-to-edit rename on name-keyed types via the config's `nameEditable` flag), and **SignalBadges**: click-to-edit chips for per-type identity fields (motivation, malware type, tactic, severity/CVSS/EPSS/KEV, region; the country badge links to the country's own profile). Also: Ask Copilot, a Watch toggle, enrichment status, and an actions menu (markdown export, merge into, watch/mute, add to campaign, convert type — any type to any of the resolvable types, writing reclassify tombstones). Meta row shows article count and first/last seen.
- **Overview tab** — description rendered via `EntityLinkedMarkdown` (entity names in prose become profile links, including tools and mitigations), an assessment block with recent developments (fed by `/api/engine/entities/{type}/{id}/whats-new`), identity fields, mentions timeline, activity feed, per-type panels (CVE threat/exploitation/affected-products, TTP MITRE metadata + mitigations, vendor products container, Wikipedia summary), external pivot links.
- **Relationships tab** — typed entity graph (custom SVG; edges labeled with relationship verbs; claims-only) plus a relationship browser split into **claims** (typed verbs, graded by trust: confidence from analyst action or AI adjudication) and **co-mentions** (co-occurrence context, presented separately as "not claims"): verb, evidence count, sparkline, confirm/reject actions, filtering and sorting.
- **Detection tab** (actor/malware/cve/ttp) — linked detection rules and coverage.
- **ATT&CK and Detection Gaps tabs** (actor/malware) — technique matrix and uncovered-technique views.
- **Vulnerabilities tab** (vendor/product) — CVEs affecting the vendor's/product's software via the `cve_affected` table (NVD CPE affects-links, deliberately separate from `EntityRelationship`).
- **Geography tab** (country only) — role breakdown, origin/targeting actors.
- **AI tab** (all types) — run entity-scoped AI analysis tasks (prompts opted in via `show_in_entity_actions`).
- **Notes tab** — titled entity notes with a split editor/viewer, note types, tags.

## Where the data comes from

| Source | Mechanism | Feeds |
|---|---|---|
| Autolinker | Aho-Corasick scan on ingest (`backend/app/intelligence/autolinker.py`) with junk-alias/LOLBin false-positive filtering | Entry junctions for actors, malware, countries, vendors, products, tools, mitigations |
| Regex + AI extraction | `CVE-YYYY-NNNN` / `TNNNN(.NNN)` regex; one-pass `analyze_entry()` | CVE/TTP links, new entities |
| NVD / EPSS / KEV / GitHub PoC | Beat-scheduled syncs (schedule table in [entries.md](entries.md)) | CVE scoring, exploit status, CPEs |
| MITRE ATT&CK / Malpedia / Wikipedia | Weekly syncs | TTP metadata + mitigations, actor/malware descriptions and aliases |
| Co-occurrence engine + Telegram forward graph | Post-ingest chord + 4-hourly beat task | `EntityRelationship` edges |
| Analyst | Chip edits, descriptions, merges, notes, relationship confirm/reject | Everything above, with `analyst_*` provenance |

Relationships use the strength model (`backend/app/models/entity_relationship.py`): typed verb (uses, exploits, targets, attributed_to, variant_of, communicates_with, delivers, drops, related_to, successor_of, subgroup_of, overlaps_with), confidence (confirmed / probable / possible), source (co_occurrence, auto_extracted, analyst_confirmed/created/rejected, external_feed — the MITRE ATT&CK import writes external_feed + confirmed), and `evidence_entry_ids`. Every write path validates `(source_type, verb, target_type)` against the semantic allowlist in `backend/app/intelligence/relationship_matrix.py` (disallowed triples are flipped to their allowed orientation or dropped). The adjudicate pipeline stage judges each edge against the entry that supplied its evidence: a demote verdict stamps `adjudication_verdict=coincidental` (confidence possible, never re-promoted); keeps accumulate in `reviewer_kept_entry_ids`, and at `relationship_evidence_promote_count` distinct entries the edge becomes confirmed / `corroborated`. Rows with `source=analyst_rejected` are kept as tombstones so a rejected pair is not resurrected by the co-occurrence engine; cross-type reclassifies write `EntityReclassifyTombstone` rows so folded names are not recreated by importers.

## Observables and infrastructure

The observable profile is the lightest in the app: its hero is the mono value,
every badge is a lifecycle fact (kind, role, confidence, status, capture door)
and nothing is editable inline. `entityProfileConfig.tsx` gives it two tabs
(`overview`, `relationships`) and two Overview panels:

- `observable_provenance` — captured by, dual-use tag, role, the evidence
  sentence, base and current confidence, decay and projected expiry, the
  **Sources** row (`N reports · M feeds`, with the raw sighting count), and an
  honest "Reporting: none" row when a value is only on an indicator feed. The
  buttons copy the value (plain or defanged), export sightings as CSV, pin the
  confidence, and (admin) tombstone the value.
- `observable_backlinks` — **Attribution**: who claims the value (edges with
  their verb and trust tier) and which actors, families, campaigns and tools
  its reporting articles name ("reported with").

`ObservableLifecycleStrip` (mounted by `EntityProfilePage`, not the config)
draws first seen → latest report → projected expiry; its middle node reads
"Listed on 1 indicator feed" for feed-only rows.

Threat actor, malware, campaign and tool profiles carry the mirror panel,
`infrastructure` (`useEntityInfrastructure` → `GET /api/entities/{type}/{id}/infrastructure`):
**Claimed** rows (attribution edges with evidence) and **Reported alongside**
rows (observables sighted by a reporting door in articles that link the
entity — co-occurrence computed at read time, never persisted, with indicator
files and newsletters excluded), each linking to the observable's profile,
plus "Copy all defanged" and "Export CSV". The Relationships tab shows
claim-backed observables and keeps co-mention observables suppressed. See
[observables.md](observables.md#attribution-claimed-vs-reported-alongside).

## Field provenance

The trust ladder above covers relationships. Scalar profile fields — an actor's
motivation, origin country, targeted sectors, the assessment prose — carry their
own provenance in `entity_field_claims`
(`backend/app/models/entity_field_claim.py`). One row per (field, value,
asserter), written alongside the column by every path that fills one:

| Source kind | Written by |
|---|---|
| `analyst` | the per-type `PUT /entities/...` endpoints, via `_apply_fields` — only when a value actually changes, so a no-op save doesn't restamp the field |
| `ai_extraction` | `intelligence/enrichment.py` while reading an article (carries `entry_id`) |
| `ai_assessment` | the AI gap-fill in `workers/entity_maintenance_tasks.py` (carries the model's reason as the quote) |
| `enrichment` | `enrichment/entity_updater.py` (wikipedia / mitre_attack / malpedia) and the sector rollup in `workers/maintenance.py`, which writes `threat_actor_target_sectors` / `malware_target_sectors` rows from the entity's own articles and rebuilds the `targeted_sectors` cache (`services/sector_links.py`) |
| `external_feed` | the Cybergeist attribute fill and the ransomware.live sync |

Two invariants. Recording never fails the write — `record_claim` returns a bool
and swallows its own errors, because an audit trail must not roll back an edit.
And agreement is computed, never stored: `get_entity_claims` compares each
claim against the live column at read time, so a claim that lost stays on the
record as history rather than drifting out of step with a stored "current" flag.
Fields holding a value with no claim at all come back in `unsourced_fields`, and
the profile marks them — an unattributable fact is flagged, not presented as
established.

Claims collapse on `claim_key` (entity + field + value + source + article), so a
nightly adapter re-asserting the same value bumps recency instead of growing the
table, while two different sources or two different articles stay distinct — that
is the corroboration the popover counts.
`scripts/maintenance/backfill_field_claims.py` seeds the table from provenance
already on record (`actor_description_history`, `enrichment_results`, and
`created_via`/`created_from_entry_id`); anything it can't recover stays unsourced
on purpose.

## Backend endpoints

- `GET /entities/{type}/{id}/provenance` — every tracked field's claims, with the article, feed and feed reliability grade behind each one, plus `unsourced_fields`
- `GET /intelligence/pivot/{type}/{id}` — entity + related entities + entries (Redis-cached, `intelfeed:corr:pivot2:*`)
- `GET /intelligence/graph/{type}/{id}` — nodes + typed edges (Redis-cached, `intelfeed:corr:graph2:*`; TTL via `correlation_cache_ttl_seconds` — flush `intelfeed:corr:*` after payload-shape changes)
- `GET /intelligence/timeline/{type}/{id}` — correlation events
- `/entity-relationships` — list/create/update + confirm/reject
- Per-type entity CRUD, plus merge, duplicates, and merge-suggestions endpoints
- `/entity-notes` — notes CRUD
- `GET /export/entities/{type}/{id}` and `POST /export/entities/bulk` — markdown export (bulk returns a ZIP)
