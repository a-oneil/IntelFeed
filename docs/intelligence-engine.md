# Intelligence Engine

For contributors and operators. It explains how a feed article becomes linked intelligence, and why something did or did not link. After reading it you can trace an entry through each stage, find the code for it, and know which setting changes its behaviour.

**Contents**

- [Overview](#overview)
- [Entry-to-Intelligence Pipeline](#entry-to-intelligence-pipeline)
  - [Phase 1: Entry Arrival & Text Normalization](#phase-1-entry-arrival--text-normalization)
  - [Phase 2: Autolinker Scan (Layer 0)](#phase-2-autolinker-scan-layer-0)
  - [Phase 3: Junction Record Storage](#phase-3-junction-record-storage)
  - [Phase 4 (Optional): Secondary Extraction Layers](#phase-4-optional-secondary-extraction-layers)
- [Autolinker Deep Dive](#autolinker-deep-dive)
  - [False Positive Filtering](#false-positive-filtering)
  - [Pending Tier: Dictionary-Word Matches](#pending-tier-dictionary-word-matches)
  - [Junk Alias Filtering at Import](#junk-alias-filtering-at-import)
  - [Cross-Type Resurrection Guard](#cross-type-resurrection-guard)
  - [False Positive Feedback Loop](#false-positive-feedback-loop)
- [Entity Hygiene Console](#entity-hygiene-console)
- [Observables — the IOC ledger](#observables--the-ioc-ledger)
- [Entity Types & Resolution](#entity-types--resolution)
- [Correlation Engine](#correlation-engine)
- [Detection Rule Extraction](#detection-rule-extraction)
- [TTP & MITRE ATT&CK Integration](#ttp--mitre-attck-integration)
- [CVE Pipeline](#cve-pipeline)
- [Glossary & Inline Highlighting](#glossary--inline-highlighting)
- [Reporting & Export](#reporting--export)
- [Configuration](#configuration)
- [Troubleshooting & Debugging](#troubleshooting--debugging)
- [Per-feed pipeline switches](#per-feed-pipeline-switches)
- [Signal Engine (engine phase 2)](#signal-engine-engine-phase-2)

## Overview

Terms used throughout:

| Term | Meaning |
|---|---|
| Entry | One article, post or file pulled from a feed |
| Entity | A tracked thing: threat actor, malware family, CVE, technique, vendor, product, tool, mitigation, country, CWE, sector, observable |
| TTP | An ATT&CK technique ID such as `T1059.001` (tactics, techniques and procedures) |
| CVE / CWE | A vulnerability ID (`CVE-2024-3400`) / a weakness class ID (`CWE-79`) |
| IOC / observable | Indicator of compromise: an IP, domain, hash, command line and so on. IntelFeed keeps these in the observables ledger |
| Autolink | Matching an entry's text against the names of entities already in the database |
| Junction row | The link between one entry and one entity (`entry_threat_actors`, `entry_cves`, …) |
| Correlation event | A notice that something interesting co-occurred, such as a new technique seen with a known actor |

Each new entry goes through these stages (registered in `backend/app/pipeline/registry.py`):

```text
Entry ingested (sanitize, dedup, relevance score, search index, translate)
    │
    ├─ autolink     dictionary scan for known entities + CVE / CWE / TTP IDs   (no AI)
    ├─ observables  stage IOC candidates, sight known ledger values              (no AI)
    ├─ extract      regex CVE/TTP/mitigation pass, NVD lookups, rule extraction  (no AI)
    │
    ├─ cooccurrence → correlation events → requirement matching
    └─ score        signal engine sets priority_score
    │
    └─ one-pass AI analysis (batch queue) → adjudicate (AI review of what it wrote)
```

The non-AI layer ("Layer 0") runs on every entry the feed allows. The AI layer runs only when it is switched on; see [Per-feed pipeline switches](#per-feed-pipeline-switches).

---

## Entry-to-Intelligence Pipeline

### Phase 1: Entry Arrival & Text Normalization

`split_into_paragraphs()` (`backend/app/intelligence/autolinker.py:303`) cuts the entry into numbered paragraphs: the title, then the summary, then each block of the body separated by a blank line. Empty parts are skipped, so the numbering stays dense.

Paragraph numbers matter because they are stored on every link. Correlation uses them to tell "named in the same paragraph" (strong) from "both somewhere in a long roundup" (weak).

When an entry has a translation, the autolinker and the extract stage scan the original and translated text together (`entry_text_with_translation`, called from `_autolink_entry` in `backend/app/workers/intel_feed_tasks.py:218`).

### Phase 2: Autolinker Scan (Layer 0)

The autolinker matches text against a dictionary of every known entity name and alias, using an Aho-Corasick automaton (one pass over the text finds every dictionary word in it).

**The vocabulary.** `EntityVocabulary` (`backend/app/intelligence/autolinker.py:350`) loads the name and aliases of every threat actor, malware family, country, vendor, product and tool, plus mitigation names (mitigations have no aliases). Names shorter than `autolinker_min_name_length` (default 3) are skipped, as are names the false-positive lists rule out.

**Keeping workers in sync.** Each worker process holds its own copy. The vocabulary's version is a hash of its contents, published to Redis under `intelfeed:autolinker:vocab_version`. Before a scan, `_ensure_vocabulary()` compares its local version with Redis and rebuilds on a mismatch. The `refresh-autolinker-vocabulary` job rebuilds every 30 minutes, and denying a name or curating extractions rebuilds at once. A brand-new entity therefore starts matching new articles within 30 minutes.

**The scan** (`scan_text()`, `backend/app/intelligence/autolinker.py:929`), per paragraph:

1. Match the lowercased text against every name and alias.
2. Drop matches that sit inside a longer word ("APT" inside "RAPT", "RTM" inside "RTMP" or `RTM_NEWLINK`) or inside a longer matched name ("Korea" inside "North Korea").
3. Short single words (alphabetic, up to `autolinker_ambiguous_name_max_length`, default 10) must be written the way the name is: an acronym in capitals, a mixed-case name exactly ("SynAck", not "Synack"), any other word with a capital first letter. A name written in lower case on purpose, such as the npm package "axios", matches lower-case text; capitalised mid-sentence ("reported by Axios") it is something else. For actor, malware, country and mitigation names, a short word is also dropped if it appears more than `autolinker_ambiguous_max_occurrences` (default 3) times in the entry.
4. A name of several words must have its first real word cased as in the name: "push security" is not Push Security, and "the COM object" is not The Com.
5. Each match is then judged in its sentence (`_occurrence_verdict()`, `backend/app/intelligence/autolinker.py:868`). It is dropped when it is:
   - inside a "Related:" / "Read more:" headline, at the start of a line or run into the body (Dark Reading), since that headline is another article's. IDs in it are skipped too;
   - part of a code or file token: a dotted package id (`com.apple.…`), a hyphenated compound with a capital or digit after the hyphen ("X-Agent-Secret", "Proton-J"; "-linked" and "-based" only describe the name), or a capitalised name written in lower case inside a file name or path (`push security-audit.yml`, `id-ed25519`);
   - a number used as a number, for a name made only of digits ("PID: 764", "port 764", "1,764", "764 seconds");
   - a release stage after a version ("Windows 10 RTM", "the RTM build");
   - a country alias in demonym form used as a language ("staff who speak Persian", "Spanish-speaking", "Portuguese text").
6. Some matches are held for the AI instead (see [Pending Tier](#pending-tier-dictionary-word-matches)):
   - a one-word name inside a longer capitalised name: "NVIDIA Inception", "Quasar Framework", "WWHF DEADWOOD", "Adi Moldovan". A word that says what the name is ("Quasar RAT", "Lazarus Group") or a demonym before it ("Russian Sandworm") doesn't count. In a Title Case headline only an acronym next to the name counts. For vendors and products, which have no AI check, only a dictionary-word alias is affected, and it is dropped ("SOC Teams" is not Microsoft Teams);
   - a name made only of digits (the group "764");
   - an actor name with initials ("J.P. Morgan"), and an actor or malware name that a vendor or product also uses.
   With the pending tier off these matches are dropped, not linked.
7. A canonical-name match is `high` confidence; an alias match is `medium`.
8. Regex picks up structured IDs in the same pass: `CVE-YYYY-NNNN…` (through `extract_cve_ids()`, which strips a CVSS score glued onto an id, so "CVE-2026-10384910.0" is CVE-2026-103849, and skips ids that can't be real), `CWE-N`, and ATT&CK technique IDs (`T1234` or `T1234.001`; the invalid `.000` falls back to the parent).

### Phase 3: Junction Record Storage

`store_autolink_matches()` (`backend/app/intelligence/autolinker.py:1172`) writes one junction row per entity, with:

- `confidence` — the match's confidence scaled by the feed's reliability rating (see [Confidence weighting](#confidence-weighting-and-reliability-rating))
- `source = "auto_link"` (TTP links store `source_text = "auto_link:T1234"` instead)
- `matched_names` — the names and aliases that matched
- `paragraph_indices` — where they appear

Inserts use `ON CONFLICT DO NOTHING`, so re-running is safe. Each new link adds one to the entity's `article_count` and sets `last_seen_at`. Rows are written in a fixed (type, id) order so concurrent workers cannot deadlock.

How each ID type is handled:

| Type | Behaviour |
|---|---|
| CVE | The one type the autolinker creates. An unknown ID becomes a stub row (`created_via = "auto_link"`) and is queued for NVD enrichment, unless the ID is on the do-not-recreate list or can't be a real id (`is_plausible_cve_id()`). |
| TTP | Checked against the ATT&CK catalog first (`resolve_technique_ids()`, `backend/app/intelligence/attack_catalog.py:615`): unknown IDs are dropped, revoked IDs map to their replacement, and ICS techniques (`T0xxx`) need ICS/OT words in the entry. |
| CWE | Linked only if the ID is in the seeded CWE catalog. Never created. |
| Dictionary words | Held for AI confirmation instead of linked; see [Pending Tier](#pending-tier-dictionary-word-matches). |

### Phase 4 (Optional): Secondary Extraction Layers

Other stages add more intelligence after (or beside) the autolinker:

- **Observables stage** — stages IOC candidates and records sightings of known ledger values. See [observables.md](observables.md).
- **Extract stage** (`_extract_entry_intel`, `backend/app/workers/intel_feed_tasks.py:483`) — a standalone regex pass for CVEs (new ones are queued for NVD lookups), TTPs and mitigation IDs, plus detection-rule extraction and GitHub rule import.
- **One-pass AI analysis** (`entry_analysis` task) — reads the article once and returns entities, relationships, IOCs and a summary. It confirms or rejects held autolinks.
- **Adjudicate stage** — a second AI call that reviews what the analysis wrote. See [Entity Hygiene Console](#entity-hygiene-console).

---

## Autolinker Deep Dive

### False Positive Filtering

Five rules stop common words from becoming links:

1. **False-positive name list** (`autolinker_false_positive_names`). A curated list of common words, brand names, Windows built-in tools and junk aliases ("storm", "windows", "certutil", "page", …). It applies to actor, malware and country names. Vendor, product, tool and mitigation names skip it, because many of them really are those words (Microsoft, Norton).
2. **Analyst blocks** (`autolinker_blocked_surface_forms`). Words an analyst marked "never match this" from the reader. These apply to every entity type.
3. **Case rules** for short single words and multi-word names (steps 3 and 4 of the scan above). "fox" in "Firefox" or lowercase prose does not match the "Fox" entity.
4. **Repeat limit** for those short words (also step 3).
5. **Context rules** (steps 5 and 6): Related headlines, file names and paths, hyphenated compounds, numbers, languages, and one-word names inside longer names.

Both lists are checked when the vocabulary is built, so a blocked word never enters the automaton.

### Pending Tier: Dictionary-Word Matches

The capital-letter rule cannot tell "Royal" the ransomware from "Royal Navy", or "INC" the group from "N2K Networks, Inc." So matches on ordinary English words wait for the AI to confirm them.

- **Which words.** `is_provisional_form()` (`backend/app/intelligence/autolinker.py:194`) marks a single alphabetic word that appears in the bundled list of about 31,000 common English words (`backend/app/intelligence/data/common_english_words.txt`). Examples: "royal", "inc", "hive", "medusa". Coined names such as "Emotet" or "LockBit" link at once. This applies to actors, malware, tools and countries. Countries use a short list of their own instead (`AMBIGUOUS_COUNTRY_WORDS`: Chad, China, Georgia, Guinea, Jersey, Jordan, Niger, Panama, Turkey, Chile, Cuba). Vendors and products always link at once.
- **Other held matches.** The context rules hold a few more kinds of match the same way (step 6 of the scan): one-word names inside a longer capitalised name, names made only of digits, actor names with initials, and actor or malware names a vendor or product also uses.
- **Holding.** If every occurrence of an entity in the article is held, the match goes to `pending_autolink_matches` instead of a junction table. Held matches are invisible to correlation, scoring, counts and the UI. One non-dictionary name (the alias "Royal Ransomware", say) turns the whole match into a normal link.
- **Confirming.** When the one-pass AI analysis lands, `reconcile_pending_autolinks()` (`backend/app/intelligence/autolink_reconcile.py:59`) promotes held entities whose name or alias the AI also extracted. Promotion goes through the normal store path. The rest are rejected with a `FalsePositiveRecord` (`extraction_source = "ai_reconcile"`).
- **Feeds without AI.** `entry_will_get_ai_analysis()` (`backend/app/services/ai_eligibility.py:41`) checks the instance switch `ai_one_pass_enabled`, the feed's `ai_analysis_enabled`, and that the feed's mode is not `none`. If the entry will never be analysed, nothing could confirm a held match, so these matches are dropped. They are counted in daily Redis keys (`autolink:pending_dropped_ai_off:<YYYYMMDD>`), and the Engine's Autolinking view shows the 30-day total.
- **Expiry.** Some entries never get an AI pass (junk-gated, out of budget). `prune_engine_tables` deletes unresolved held rows after 14 days and resolved ones after `engine_run_retention_days` (default 30).
- **Review by hand.** Engine → Review → Held links (`GET /api/entity-links/pending`, `POST /api/entity-links/pending/resolve`).

The tier is on by default (`autolink_pending_tier_enabled`). It switches itself off while `ai_one_pass_enabled` is off, because nothing could confirm the matches. Retroactive linking of a new entity (`link_entity_to_existing_entries`) does not use the tier.

### Junk Alias Filtering at Import

The same word lists keep junk out of `aliases` arrays in the first place (`backend/app/intelligence/autolinker.py:77-130`):

- `is_junk_alias(alias, canonical_name)` rejects aliases shorter than the minimum length, copies of the entity's own name, and anything on the false-positive or blocked lists.
- `filter_aliases(aliases, canonical_name)` drops junk aliases and removes case-insensitive duplicates, keeping order.

AI extraction and the Cybergeist sync pass new aliases through `gate_aliases()` (`backend/app/intelligence/entity_resolution.py:1966`), which applies `is_junk_alias()` plus further quality checks. The Malpedia sync (`_run_malpedia_sync`, `backend/app/workers/enrichment_tasks.py:873`) runs Malpedia's `alt_names` through `filter_aliases()`.

### Cross-Type Resurrection Guard

A same-type merge survives re-import because the loser's name becomes an alias of the survivor (`backend/app/intelligence/entity_dedup.py`). A cross-type fold (the "Akira" malware folded into the "Akira" actor) needs more, because each importer only searches its own table and would recreate the loser within hours.

All automated creation goes through `resolve_entity_creation()` (`backend/app/intelligence/entity_resolution.py:1543`). Manual creation in the UI goes through it too, and may override a refusal with `force=true`. In order, it:

1. **Matches an existing entity** by exact name or alias, then a normalized match through `entity_alias_index`, then known actor synonyms.
2. **Checks reclassify tombstones.** A cross-type reclassify (`perform_reclassify()` in `backend/app/api/entity_merge.py`) writes one `EntityReclassifyTombstone` row per folded name: `(source_type, normalized_name) → (target_type, target_id)`. On a hit, nothing is created and the entry links to the survivor through `link_entry_to_entity()`. Set `active = False` on a tombstone row in the database to allow a split again; there is no UI for this.
3. **Applies always-on blocks.** For automated sources creating an actor or malware family, `is_fp_entity_name()` (`backend/app/intelligence/autolinker.py:101`) rejects the false-positive list and bare file names such as `svchost.exe`, `*.dll` or `*.sys`. The do-not-recreate list (`entity_name_denylist`) also applies here.
4. **Applies the switchable gates** (`entity_creation_gates`: `off`, `shadow` or `on`, default `on`). `shadow` logs what it would block and still creates. Besides generic phrases, regions and countries, the gates refuse names that are not things at all (`non_entity_reason()`): protocols (WebRTC, MQTT), cipher names (RSA, Ed25519), install commands (`npm install`, `git clone`), code tokens (`trust_remote_code=True`, `CAP_NET_ADMIN`, AutoConfig), OS APIs and kernel features (BitBlt, ptrace, inotify), product categories (SIEM, ZTNA, "OpenAI models"), technique names (BYOVD, HVNC, DNS tunneling) and hex literals. These apply to actors, malware, tools and products; protocols may still be products, and vendors are not checked. For actors, descriptions ("China-nexus", "North Korea-linked group", "Russian submarine operation") and number-only names ("888") are refused too. The same checks drop matching aliases.
5. **Holds weak candidates.** A name that only loosely matches an existing entity is held for review and never auto-merged.

Every decision is written to `EntityMaintenanceLog` (`resolution_*` actions), so it shows in the hygiene feed.

Tools have two extra guards that apply whatever `entity_creation_gates` says:

- Concept words in `TOOL_CONCEPT_NAMES` (hash algorithms, bug classes such as SQL injection, protocols such as WebSocket, generic words such as payload) are blocked as `generic_name:concept_term`.
- A name already on file as a product or vendor is held as `product_or_vendor_name`, and the entry links to that product or vendor instead. Dual-use tools in `DUAL_USE_TOOL_NAMES` (AnyDesk, rclone, ngrok, …) are exempt.

A feed with `extract_tools` off calls the resolver with `link_only=True`: known tools still link, and a name that would create a row is blocked as `creation_disabled`.

See diagram: [Entity creation guards](diagrams/intelligence-engine-entity-creation-guards.md)

### False Positive Feedback Loop

`FalsePositiveRecord` (`backend/app/models/false_positive_record.py`) stores each "this link is wrong" verdict: the entity, the wrong value, the entry, the reason, who marked it and which layer produced it (`extraction_source`, such as `auto_link` or `ai_reconcile`). The reader's "Wrong?" menu writes these and can also add the word to the analyst block list. The same menu, narrowest fix first, also converts the entity to another type, merges it into a duplicate, unlinks it from every article (admins), and deletes it outright, after a confirm and a 5-second undo (`frontend/src/components/EntityPopover.tsx`). For an observable it removes this article's sighting, tombstones the value (admins) or deletes the row.

---

## Entity Hygiene Console

Day-to-day cleanup of links and entities is run from one admin screen, Workbench → **Engine** (`frontend/src/components/engine/EngineMatrix.tsx`). Its **Proposals** view (`ProposalsQueue.tsx`) lists pending proposals from the adjudicate stage and the scanners, with Apply, Dismiss, bulk actions and a History view with Restore. The **Maintenance** drawer (`MaintenancePanel.tsx`) holds orphan pruning, full re-extract, proximity backfill and resets. See [engine.md](engine.md) for the console itself.

The API is `backend/app/api/hygiene.py`, under `/api/admin/hygiene/*` and admin-only, except the cascade preview:

| Endpoint | Does |
|---|---|
| `GET /feed` | One timeline of `entity_link_validation_log` and `entity_maintenance_log` rows. `origin=adjudicator\|legacy` splits AI proposals from scanner ones; `orphaned=true` lists proposals whose entry or entity is gone |
| `DELETE /feed/{source}/{row_id}`, `POST /dismiss-proposals` | Dismiss one row, or every pending proposal of one origin |
| `GET /stats` | Counters (applied 24h/7d, pending, orphans) plus `adjudication_mode`, `adjudication_pending`, `adjudication_breaker_until` |
| `POST /adjudication/{log_id}/apply`, `/restore`, `/adjudication/apply-all` | Act on, or undo, adjudicator proposals |
| `POST /link-log/{log_id}/restore`, `/apply-removal` | Undo or apply one link-log row. A restore re-creates the link and counts as an analyst restore |
| `POST /apply-reclassify-advisories` | Turn `needs_reclassification` advisories into reclassifies through `perform_reclassify()` |
| `GET /review-groups`, `POST /review-groups/dismiss` | The Review tab's one queue: every pending proposal folded per entity |
| `GET /reclassify-groups`, `/unlink-groups` (+ `/apply`, `/dismiss`, `/keep`) | Per-entity apply paths the queue's row buttons use |
| `POST /scan-duplicates` | Run the duplicate review (`review-duplicate-entities`) now |
| `GET /orphans`, `POST /orphans/prune` | Entities with `article_count = 0` |
| `/enrichment-gaps/enrich`, `/run-name-normalization, `/scan-alias-hygiene`, `/scan-vendor-autolink`, `/scan-id-hygiene` | On-demand scanners with shadow/apply flows |
| `GET /api/entities/{type}/{id}/cascade-preview` | What deleting an entity would remove. Any signed-in user |

**The adjudicate stage** (`backend/app/services/entry_adjudication.py`). After an entry's one-pass analysis lands, `adjudicate_entry_task` (on the `ai` queue) sends the article plus a list of everything the analysis wrote: links, entities it created (with their nearest existing names), relationship claims and IOCs. The reviewer answers only for items it would change: remove, reclassify, veto, merge, demote or drop. Anything it leaves out is kept.

- Each item line says where the item sits in the article. An IOC gets its table row or list line and the heading above it, found in its defanged form too, so a value from the article's own IoC table is judged there and not by an earlier passing mention. A `script` IOC carries its code, since its value is a hash of that code. An AI-linked TTP gets its row in the report's ATT&CK table when it has one.
- Verdicts are checked before they count. A remove, demote or reclassify whose reason does not name its item (the entity, a form it matched as, a TTP's id, either end of an edge) is dropped, as is any destructive verdict whose reason argues the record is right ("validating the edge"), and one reason pasted onto three or more items. A dropped edge verdict is not counted as a keep.
- `adjudication_mode` (default `apply`): `shadow` files every verdict as a proposal; `apply` acts on high-confidence verdicts and files the rest. Every applied change writes an audit row that doubles as its undo.
- `reclassify` is a catalogue-wide change, so in apply mode it needs agreement: each article's verdict is a vote (filed as a proposal), and the review that brings the count to `adjudication_reclassify_consensus` (default 2) converts the entity and clears the other proposals about it. A name that was folded out of a type (a reclassify tombstone) is never proposed back into it, so types do not ping-pong.
- Circuit breakers turn a destructive run into proposals. The rolling breaker also pauses dispatch for an hour (`adjudication_breaker_until`).
- Never touched: relationship edges an analyst confirmed, created or rejected, and external-feed edges (only `auto_extracted` and `co_occurrence` edges are reviewed). A link an analyst restored in the last 90 days is shown to the reviewer flagged, and never changed.
- `merge` can only target a name the reviewer was shown. `veto` deletes an entity only when this entry created it and nothing else uses it. Two entities that both already exist are never compared here; that is the daily duplicate review (`backend/app/services/entity_merge_review.py`, job `review-duplicate-entities`), which scores same-type pairs by name similarity and a shared alias (shared articles only break ties), asks the `entity_merge_review` task, and files each `same` verdict as a Merge proposal on the Review tab.
- `backfill_entry_adjudications` walks older entries through the same review, using at most half of each hour's budget. Run it by hand:

```bash
# in the api or celery-worker container
celery -A app.workers.celery_app call app.workers.adjudication_tasks.backfill_entry_adjudications \
  --kwargs '{"limit": 500, "since_days": 30}'
```

Settings: [engine-settings.md](engine-settings.md#adjudicate-stage-post-analysis-ai-review).

**Merge suggestions** (`backend/app/intelligence/merge_suggestions.py`, `GET /api/entities/{entity_type}/merge-suggestions`) rank likely duplicate pairs by name similarity, alias overlap, shared relationships and co-mentions. Dismissed pairs are kept in `entity_merge_suggestion_dismissals` and never suggested again. A tool and a malware family with the same name are flagged but never offered for merge; they need a reclassify.

---

## Observables — the IOC ledger

The ledger stores indicators (IPs, domains, hashes, command lines, registry keys and more) with `(kind, value)` as their identity. The rule that shapes it: **regex never creates a row.** Pattern scanning only nominates *candidates* that stay on the entry. A ledger row exists only when something with judgment created it:

| Door (`created_via`) | Base confidence | Source |
|---|---|---|
| `manual` | 1.0 | An analyst promotes a candidate or creates a row |
| `publisher_ioc` | 0.9 | The indicator file an article links to, from allow-listed repositories |
| `ioc_list` | 0.85 | A curated indicator-list feed |
| `ttp_observable` | 0.85 | A host artifact attached to a technique claim |
| `ai_extraction` | 0.8 | The one-pass analysis's `iocs` array |

Author-defanged values (`evil[.]com`) get +0.1. Once a row exists, later entries that contain the exact value add a sighting. Network values lose confidence over time; hashes and host artifacts do not.

The full story (kinds, validators, what the AI sees, attribution, publishing and jobs) is in [observables.md](observables.md). Columns: [data-model.md](data-model.md#observable--the-ioc-ledger). Settings: [engine-settings.md](engine-settings.md#observables-stage).

---

## Entity Types & Resolution

The type names come from `backend/app/entity_types.py`; import its constants rather than typing the strings.

| Entity | Identity | Notes |
|---|---|---|
| Threat actor | `name` | Aliases; created by AI extraction, feeds or analysts |
| Malware family | `name` | Aliases; Malpedia enrichment |
| CVE | `cve_id` | Created as a stub when first seen, then enriched from NVD |
| TTP | `technique_id` | Loaded from the MITRE ATT&CK catalog |
| Mitigation | `name` / MITRE ID | Loaded from ATT&CK; no aliases |
| Tool | `name` | Attack and dual-use tooling (Mimikatz, AnyDesk) |
| Vendor, product | `name` | A product belongs to a vendor |
| Country | `name` | Seeded; aliases |
| CWE | `cwe_id` | Seeded from the MITRE catalog; `parent_cwe_id` links to the broader weakness |
| Sector | slug | Canonical sector vocabulary |
| Observable | `(kind, value)` | Created only by a judgment door |

**Enrichment** fills in profiles from outside sources: MITRE ATT&CK (techniques, groups, mitigations), Malpedia (malware), Wikipedia, NVD (CVSS, description, affected products, references), FIRST EPSS (exploit probability), CISA KEV (known exploited), GitHub PoC search and Metasploit modules. See [automation-ai-enrichment.md](automation-ai-enrichment.md) for the enrichment pipeline.

---

## Correlation Engine

Correlation runs after extraction. It finds second-order facts from which entities appear together.

### Correlation events

`correlate_new_entities()` (`backend/app/intelligence/correlation_events.py:117`) checks each new entry. "Known" means the entity was in more than one article (`article_count > 1`); "new" means this is its first.

| Event | Fires when | Severity |
|---|---|---|
| `new_ttp_for_known_actor` | A new technique appears with a known actor | medium |
| `new_ttp_for_known_malware` | A new technique appears with known malware | medium |
| `new_malware_for_known_actor` | New malware appears with a known actor | medium |
| `actor_malware_cooccurrence` | A known actor and known malware appear together | low |
| `coverage_gap` | A technique in the entry has no detection rule (draft or published) | high |
| `new_intel_for_rule` | A technique in the entry has a published detection rule | low |

Other code raises the remaining event types: `campaign_match`, `requirement_match` (medium), `trending_entity` (medium), `feed_stale` (low), `feed_error` (medium), `exploit_status_change`, `cve_score_change`, `new_exploit_discovered` and `kev_addition` (high). The full map is `EVENT_SEVERITY` (`backend/app/intelligence/correlation_events.py:18`).

- **Dedup.** An event with the same type and source entity inside 24 hours is not stored again; the existing row's `occurrence_count` goes up instead (`_deduplicate_event`, `backend/app/intelligence/correlation_events.py:88`).
- **Delivery.** Stored events go to `correlation_events` and are pushed to open browsers over SSE (`publish_event("broadcast", "correlation_event", …)`). Automation rules with the `on_correlation_event` trigger can notify, call a webhook or take other actions.
- **Retention.** The `archive-correlation-events` job (04:45 daily) deletes events that are read and older than 90 days (`archive_old_events`, `backend/app/intelligence/correlation_events.py:553`). The 24-hour window and 90 days are code defaults, not settings.

### Pivot queries and relationship strength

`GET /api/intelligence/pivot/{entity_type}/{entity_id}` returns every entity that shares entries with the given one, grouped by type (`pivot_from_entity()` in `backend/app/intelligence/correlation.py`). Options: `limit_per_type`, `offset`, `min_tier` (`weak` / `moderate` / `strong`), `window_days`, and `sort` (`strength`, `recent` or `articles`).

Each related entity carries a **strength** score from 0 to 1, made of three parts:

| Part | How | Weight setting (default) |
|---|---|---|
| Corroboration | Distinct evidence articles, log-scaled, full at `relationship_corroboration_saturation` (8) | `relationship_weight_corroboration` (0.45) |
| Closeness | Mean of the top 3 per-article proximity scores | `relationship_weight_closeness` (0.40) |
| Recency | Decays with `relationship_recency_half_life_days` (90) since the newest evidence | `relationship_weight_recency` (0.15) |

**Proximity** for one article (`_compute_proximity_score`, `backend/app/intelligence/correlation.py:176`) is `1 / (1 + proximity_decay_rate × d)`, where `d` is the smallest paragraph distance between the two entities. Same paragraph = 1.0, one apart = 0.5, five apart ≈ 0.17. With no paragraph data it is `proximity_default_score` (0.3).

Adjustments:

- **Feed reliability.** Evidence from A/B-rated feeds counts ×1.15 and from D/E feeds ×0.85 (`relationship_reliability_high_multiplier` / `_low_multiplier`).
- **Specificity.** An entity mentioned across most of the corpus (Linux, a big security vendor) says little. The score is damped by an IDF-style specificity term, blended in by `relationship_specificity_weight` (0.5). Vendors and products with specificity below `relationship_reporting_source_specificity` (0.45) are marked `reporting_source`, and the UI folds them into a collapsed group.
- **Tier.** `strong` at or above `proximity_strong_threshold` (0.7), `moderate` at or above `proximity_moderate_threshold` (0.3), else `weak`.

### Timeline Construction

`GET /api/intelligence/timeline/{entity_type}/{entity_id}` (`entity_timeline()`, `backend/app/intelligence/correlation.py:2336`) merges, by date: linked articles (one per duplicate story), correlation events, enrichment runs, detection rules created, typed relationships and campaign membership.

### Typed relationships

Co-occurrence also writes `entity_relationships` rows (actor *uses* malware, and so on) with a trust level, but only for a pair named in the same paragraph, where that paragraph is not boilerplate and names fewer than five entities (see [architecture.md](architecture.md#7-correlation-engine)). The weekly `relationship-confidence-decay` job moves stale co-occurrence rows from `probable` back to `possible`; rows an analyst touched are never demoted. Entry-to-entity link confidence does not decay. See [entity-profiles.md](entity-profiles.md) for how relationships appear on profiles.

---

## Detection Rule Extraction

`extract_rules_from_content()` (`backend/app/intelligence/rule_extraction.py:32`) finds ready-made detection rules in article text. It stores six rule types:

| Found | Stored as | How it is found |
|---|---|---|
| YARA | `yara` | `rule name { … }` with balanced braces |
| Sigma | `sigma` | YAML with `title`, `detection` and `logsource`, in a fence, a `<pre>` block, or the whole text |
| Elastic rule files (TOML) | `kql` or `elastic_ql` | A `[rule]` section with a `query`; the rule's `language` decides the type |
| Snort / Suricata | `snort_suricata` | One-line rules: `alert\|log\|pass\|drop\|reject\|sdrop` + protocol + `( … )` options; the `msg` becomes the title |
| Splunk SPL | `splunk_spl` | Code blocks, plus inline lines starting `index=`, `search ` or `\| tstats` (30+ characters) |
| KQL, EQL, ES\|QL | `kql`, `elastic_ql` | Code blocks only (EQL and ES\|QL are both stored as `elastic_ql`) |

Callers pass the entry's sanitized HTML, because the plain text flattens `<pre>` blocks into prose. HTML entities (`&gt;`, `&amp;`) are decoded so saved queries run as written.

**Query languages come only from code blocks**, never from prose, so a sentence containing "where" never becomes a rule. A fence tag or `language-*` class (`kql`, `kusto`, `eql`, `esql`, `spl`, `splunk`) is a hint, but the block must still look like the language:

- **SPL** — `index=` plus a pipe; `search ` plus a pipe; `| tstats`; or a pipe into a Splunk command (`| stats`, `| where`, `| eval`, …) plus `index=`, `sourcetype=` or `source=`.
- **KQL** — a table followed by a pipe and a tabular operator (`DeviceProcessEvents | where …`). The table must be a known Defender XDR / Sentinel table, or the query must use syntax SPL never has (`| summarize`, `| project`, `ago(`, `=~`, `has`, `==`). `index=` or `sourcetype=` rules it out.
- **EQL** — `<category> where …` (`process`, `file`, `network`, `registry`, `any`, …), or `sequence` / `join` with `[` brackets.
- **ES|QL** — `FROM <index>` followed by `| WHERE`, `| STATS`, `| EVAL`, `| KEEP`, ….

Leading `//` comment lines are dropped from KQL, EQL and ES|QL. Queries have no name of their own, so they are titled from the article: `"<article title> — KQL query 2"`, numbered per language in article order.

Every rule must pass the syntax validator (`backend/app/intelligence/rule_validation.py`) or it is dropped. The validator also covers CrowdStrike QL, Nuclei and Panther for rules written or imported in the rule library; no extractor finds those formats in articles.

**Storage** (`store_extracted_rules()`, `backend/app/intelligence/rule_extraction.py:619`):

- A rule whose body is already stored (by this user, or auto-extracted by anyone) is skipped. Dedup is on the body, never the title.
- A rule with the same entry, title and type but a new body replaces the old body (the source was edited and re-processed).
- New rules are saved as drafts (`is_draft = True`), tagged `auto-extracted` and their type, with `source_ttps` and `source_cves` set from the entry's links plus any IDs inside the rule.

Re-processing the same article stores nothing new. See [detection-engineering.md](detection-engineering.md) for the rule library.

---

## TTP & MITRE ATT&CK Integration

### TTP Extraction Layers

1. **Autolinker** — picks up technique IDs during the scan (no AI).
2. **Regex pass** (`extract_ttp_ids_regex()`, `backend/app/intelligence/ttp.py:67`) — the same ID pattern, used by the extract stage. Results have `medium` confidence.
3. **AI** — the one-pass analysis returns techniques with names and evidence. The standalone `ttp_mapping` task (`extract_ttps()`, `backend/app/intelligence/ttp.py:83`) does the same on demand; AI results replace regex results for the same ID.

### TTP Storage & Enrichment

`store_ttps()` (`backend/app/intelligence/ttp.py:146`) validates every ID against the hydrated ATT&CK catalog (unknown dropped, revoked remapped, ICS techniques need ICS/OT context). If the extractor's technique name contradicts the catalog's name for that ID, the link is kept but its confidence drops to `low`. ICS context words are a setting (`attack_ics_context_keywords`).

### MITRE ATT&CK Sync

`backend/app/intelligence/attack_catalog.py` downloads the official ATT&CK STIX bundles (Enterprise, Mobile and ICS) and loads techniques, mitigations and their links. It runs from `scripts/seed/seed_mitre_attack.py` on a fresh install and from the weekly `mitre-attack-sync` job (Sunday 03:00). Until the catalog is loaded, technique IDs pass through unchecked.

---

## CVE Pipeline

### CVE Extraction & NVD Enrichment

CVE IDs come from the autolinker (stubs), the extract stage (`extract_and_store_cves()` in `backend/app/intelligence/cve.py`) and the KEV sync. None of them calls NVD: each new CVE is queued in the [enrichment job queue](automation-ai-enrichment.md#enrichment-job-queue), and NVD looks it up from there while the source is switched on. `enrich_from_nvd()` (`backend/app/intelligence/cve.py:144`) calls the NVD API 2.0 and fills in the CVSS score and severity (v3.1, then v3.0, then v2), the English description, affected products (CPE) and references.

- Every lookup goes through the `nvd` source's [gateway](automation-ai-enrichment.md#source-gateway). An NVD API key (`nvd_api_key`, set under Settings → Engine → Enrichment → Keys) raises the rate limit from 5 to 50 requests per rolling 30 seconds. The gateway paces every caller inside that window, one request at a time.
- A 429, or a 403 that isn't a rejected key, opens the gateway's breaker for the whole source. A sweep then stops and picks up on its next run. A rejected key stops NVD until the key changes and shows as "key rejected" in the Enrichment console.
- Every answer goes through the NVD source's field map, so NVD's score replaces a CNA's or CISA's but never an analyst's, and every source's score stays visible as a claim.
- An ID NVD has no record of is retried at most 3 times, 7 days apart, so junk IDs stop costing quota.
- `extract_cve_ids()` skips IDs that can't be real. A sequence longer than seven digits, or of five or more digits with a leading zero, is dropped. An ID followed by `.<digit>` has a CVSS score glued on (`CVE-2026-10384910.0`); the score's integer part is cut off and the real ID kept. A seven-digit ID (outside the real `1000xxx` block) is dropped when its six-digit prefix is named in the same text, and `extract_and_store_cves()` won't create one whose prefix is already a stored CVE.

### EPSS & Exploit Tracking

| Data | Columns on `cves` | Job |
|---|---|---|
| EPSS (chance of exploitation in 30 days) | `epss_score`, `epss_percentile`, `epss_previous_score` | `epss-bulk-sync`, daily 06:30 |
| CISA KEV (known exploited) | `is_kev`, `kev_date_added`, `kev_due_date` | `sync-kev-feed`, every 6 h |
| Public PoC code on GitHub | `github_poc_count`, `github_poc_urls` | `github-poc-scan`, daily 05:00 |
| Metasploit module | `metasploit_module` | `metasploit-sync`, weekly |
| NVD refresh | CVSS, description, products | `cve-nvd-backfill` (01:30), `reenrich-cve-nvd` (03:05), `cve-nvd-refresh` (12:00) |

`exploit_availability` is one of `none`, `poc`, `weaponized`, `active_exploitation`. An analyst-set value (`exploit_status_source = 'manual'`) is never overwritten by enrichment.

### CVE Scoring & Priority

The UI shows a **risk tier** from `compute_risk_tier()` (`backend/app/intelligence/cve.py:557`), weighted toward evidence of exploitation:

| Tier | Rule |
|---|---|
| critical | In CISA KEV |
| high | EPSS ≥ `cve_epss_high_risk_threshold` (0.1), or a Metasploit module exists |
| medium | A public GitHub PoC, or CVSS critical/high |
| low | Everything else |

CVSS alone never goes above medium. API responses also carry a simpler `priority` field (`calculate_cve_priority()`, `backend/app/intelligence/cve.py:518`): CRITICAL if in KEV; HIGH if EPSS > 0.5 or CVSS ≥ 9.0; MEDIUM if EPSS > 0.1 or CVSS ≥ 7.0; else LOW.

---

## Glossary & Inline Highlighting

Glossary terms (`backend/app/models/glossary_term.py`) are short definitions of security terms. Each has a `name`, `category`, optional `maturity`, a `description`, an optional `long_description`, related `technologies` and `search_terms` (other spellings to match). `is_system` marks shipped terms; users can add their own.

The reader highlights glossary terms in an article in the browser (`frontend/src/components/GlossaryTooltip.tsx`, `GlossaryPanel.tsx`). Hovering shows the short definition. This is display only and creates no links.

---

## Reporting & Export

### Report Templates

`REPORT_TEMPLATES` (`backend/app/intelligence/reporting.py:20`) defines six report types:

| Template (key) | For | Sections |
|---|---|---|
| Flash Alert (`flash_alert`) | Fast notice of an emerging threat | summary, key_findings, iocs, recommended_actions, references |
| Threat Actor Profile (`actor_profile`) | One actor in depth | overview, aliases_attribution, ttps, target_sectors, infrastructure, iocs, timeline, references |
| Campaign Tracker (`campaign_tracker`) | An active campaign | executive_summary, campaign_overview, attack_chain, iocs, ttps, affected_systems, timeline, recommendations |
| Threat Landscape Report (`landscape_report`) | A periodic overview | executive_summary, key_trends, notable_threats, vulnerability_highlights, sector_impact, outlook, appendix |
| Threat Exposure Report (`exposure_report`) | Exposure for a saved scope | executive_summary, scope, threat_surface, ttps, iocs, outlook, references |
| Detection Engineering Report (`detection_report`) | Detection work | executive_summary, attack_chain, ttps, detection_opportunities, coverage_gaps, iocs, log_source_requirements, recommended_actions, references |

The `iocs` section is filled from the observables ledger: judged rows sighted in the report's source entries, defanged, with their attribution.

Each template has its own AI prompt for writing sections (`REPORT_SECTION_TASKS`, `backend/app/intelligence/reporting.py:110`): `report_section_flash_alert`, `report_section_actor_profile`, `report_section_campaign_tracker`, `report_section_landscape`, `report_section_exposure`, `report_section_detection`. They are seeded from `backend/app/ai/prompts/defaults.py` and editable at Settings → AI Configuration → Prompts.

### Intel profiles and exposure reports

An **intel profile** (`intel_profiles`, `backend/app/api/intel_profiles.py`) is a saved report scope: regions (countries) × verticals (sectors) × a lookback window. Keep one per scope you report on, such as a customer, a portfolio or a watch area.

`build_threat_surface()` (`backend/app/intelligence/threat_surface.py:199`) finds the actors and malware active against a scope, each with the reason it matched:

| Evidence | Meaning |
|---|---|
| Co-occurrence | Entries in the window link the entity and a scope country or sector |
| Claims | Recorded targeting: `threat_actor_target_countries`, `threat_actor_target_sectors`, `malware_target_sectors` |
| Victims | Ransomware leak-site victims of that group in the scope, inside the window |

An entity that matches on only one dimension still appears, ranked lower and with the gap stated. The module only reads. The analyst's keep/drop choices are saved in `intel_profiles.curation`, so a rebuild does not ask again.

Endpoints: `GET/POST /api/intel-profiles`, `GET/PUT/DELETE /api/intel-profiles/{id}`, `GET /api/intel-profiles/{id}/surface`, `POST /api/intel-profiles/surface-preview` (unsaved scope), `GET /api/intel-profiles/sector-vocabulary`, and `POST /api/intel-reports/generate-exposure`. Frontend: `ExposureBuilderPage.tsx`, `ReportBuilderPage.tsx`, and `SendToReportModal.tsx` (send entries or entities to a report).

### Report Generation

A report's sources are a single entry, a list of entries, a search or a saved search (`resolve_report_sources()`). The entities linked to those entries are collected automatically. `generate_report_content()` (`backend/app/intelligence/reporting.py:311`) builds the data sections; the AI writes the narrative ones. Reports render to Markdown (`render_markdown()`) or HTML (`render_html()`).

### Export Formats

| Export | Where |
|---|---|
| Markdown of an entry, note, entity profile, or a bulk selection | `/api/export/entries/{id}`, `/notes/{id}`, `/entities/{type}/{id}`, `/bulk`, `/entities/bulk` |
| Research bundle (ZIP: per-entry Markdown, `entities.md`, `iocs.csv`, an ATT&CK Navigator `attack_layer.json`) | `POST /api/export/research-bundle`, `GET /api/export/campaigns/{id}/bundle` |
| Indicator feeds: firewall blocklists (EDL), SIEM lookup CSVs, TAXII 2.1 (STIX) | `/api/publish/edl/…`, `/api/publish/lookup/…`, `/api/taxii2/` |

The indicator feeds and their gates are described in [engine-settings.md](engine-settings.md#publishing-engine--publishing-browse-screen).

---

## Configuration

Every setting below is read through `settings.get()`, which checks the `system_settings` table before the default in `backend/app/config.py`. All are editable in Settings → Engine.

| Setting | Default | Effect |
|---|---|---|
| `autolinker_min_name_length` | 3 | Shorter names and aliases are never matched |
| `autolinker_false_positive_names` | curated list | Words never matched as actor, malware or country names |
| `autolinker_blocked_surface_forms` | empty | Analyst blocks, for every entity type |
| `autolinker_ambiguous_name_max_length` | 10 | Single words up to this length must be written the way the name is (see the scan, step 3) |
| `autolinker_ambiguous_max_occurrences` | 3 | More repeats than this and a short word is ignored |
| `autolink_pending_tier_enabled` | true | Hold dictionary-word matches for AI confirmation |
| `entity_creation_gates` | `on` | `off` / `shadow` / `on` for the creation gates |
| `adjudication_mode` | `apply` | `off` / `shadow` / `apply` for the adjudicate stage |
| `proximity_default_score` | 0.3 | Proximity when paragraph data is missing |
| `proximity_decay_rate` | 1.0 | How fast proximity falls with distance |
| `proximity_strong_threshold` / `proximity_moderate_threshold` | 0.7 / 0.3 | Strength tier cut-offs |
| `ai_analysis_relevance_threshold` | 0.15 | Relevance score below which `selective` feeds skip autolinking and the AI skips the entry |
| `cve_epss_high_risk_threshold` | 0.1 | EPSS score that makes a CVE high risk |
| `nvd_api_key` | empty | NVD API key |

The complete list, including the relationship-strength knobs, is in [engine-settings.md](engine-settings.md).

---

## Troubleshooting & Debugging

**A known entity does not link.**

- The name is shorter than `autolinker_min_name_length`.
- The name is on the false-positive list (actor, malware, country) or the analyst block list.
- It is a short single word written in lowercase, or repeated more than the limit.
- It is a dictionary word and the entry is waiting for AI confirmation (Engine → Review → Held links), or the feed has no AI, so the match was dropped.
- The feed's mode is `manual` or `none`, or `selective` and the entry scored below the relevance threshold.
- The entity is less than 30 minutes old; the vocabulary has not rebuilt yet. A manually created entity is linked to existing entries straight away by `link_entity_to_existing_entries()`.

To rebuild the vocabulary by hand, run the `refresh-autolinker-vocabulary` job from Engine → Jobs.

**No correlation events.**

- The same event type for the same entity already fired in the last 24 hours (its `occurrence_count` went up instead).
- The "known" side has `article_count` of 1, so it does not count as known yet.
- For `coverage_gap`: a rule already lists the technique.

**CVE details missing.**

- NVD is rate-limiting you (set `nvd_api_key`), or NVD has no record yet. After 3 misses a week apart the ID is no longer retried.
- The feed has regex enrichment off (`auto_extract_on_ingest`), so the stub waits for the nightly `cve-nvd-backfill` job.

---

## Per-feed pipeline switches

Each feed has switches that decide what the pipeline does with its articles. Edit them in the Edit Feed modal's **Pipeline** pane, or for a whole category in the Edit Category modal (`frontend/src/components/feedModal/pipelineStages.ts`).

| Switch | Field | Controls |
|---|---|---|
| Process this feed | `intel_extraction_mode` = `none` or not | Everything below. `none` turns all extraction off |
| Autolink known entities | `manual` (off) vs `selective` / `full` (on) | The dictionary scan |
| ↳ Only security-relevant articles | `selective` (on) vs `full` (off) | Whether autolinking first applies the relevance filter |
| AI analysis (one pass) | `ai_analysis_enabled` | The one-pass `entry_analysis` call. Off also drops dictionary-word autolinks (see [Pending Tier](#pending-tier-dictionary-word-matches)) |
| Regex enrichment | `auto_extract_on_ingest` | The standalone CVE/NVD, TTP and mitigation pass |
| Detection rule extraction | `extract_detection_rules` | Rule parsing from article bodies |
| ↳ Create tool entities | `extract_tools` | Whether the AI may create new tools. Off, known tools still link. Advisory-type articles never create tools. No effect when AI is off |

The observables stage has no switch of its own, but `_scan_entry_observables` skips feeds set to `none`. Its tuning is in the global `observables_*` settings.

**The AI pass has its own gates.** `enqueue_entry_analysis()` (`backend/app/services/entry_analysis.py:343`) queues an entry only when `ai_one_pass_enabled` is on, the feed's mode is not `none`, and `ai_analysis_enabled` is true. Use `ai_analysis_enabled = false` to keep matching a noisy source against your catalog without letting the AI create entities from it. Apart from `none`, the mode has no effect on the AI.

### The two pipelines

**Pipeline A — the autolinker.** Entry point `_autolink_entry` (`backend/app/workers/intel_feed_tasks.py:218`). Runs for `full` and `selective` (if the entry passes the relevance filter). It links actors, malware, countries, vendors, products, tools and mitigations, plus CVE, CWE and technique IDs. See [Phase 2](#phase-2-autolinker-scan-layer-0).

**Pipeline B — the extract stage.** Entry point `_extract_entry_intel` (`backend/app/workers/intel_feed_tasks.py:483`):

- CVE extraction with NVD enrichment
- Technique-ID regex pass
- Mitigation IDs (MITRE `M####`)
- Detection-rule extraction from article bodies (when `extract_detection_rules` is on)
- GitHub rule import: entries from a `github_repo` feed with a `content_type` go to `process_github_entry` (`backend/app/services/github_rule_import.py`) instead

It is dispatched when `auto_extract_on_ingest` or `extract_detection_rules` is on and the mode is not `none` (`feed_runs_extraction()`, `backend/app/pipeline/plans.py:39`). Each half then checks its own flag. The task re-checks mode `none` itself, so no pipeline plan, forced run or Engine re-run gets past it.

### `full` — autolink every article

Every entry is autolinked with no relevance check, plus whatever regex enrichment and rule extraction are on. Most recall, most cost: new CVEs become stubs filled from NVD, and busy feeds add many junction rows. NVD allows 5 requests per 30 seconds without a key and 50 with one.

Use for high-signal sources where nearly every entry is intel: NVD, vendor security advisories, CISA, major research blogs, curated incident trackers. Avoid for general news, social feeds and noisy video transcripts.

### `selective` — autolink security-relevant articles (default)

The relevance filter (`backend/app/intelligence/relevance_filter.py`) scores title, summary, body and any translation. Below `ai_analysis_relevance_threshold` (default 0.15) the autolinker skips the entry; the entry is still stored and readable. Only autolinking reads this gate here: regex enrichment, rule extraction and the observables stage run anyway. The same score also decides whether the AI reads an entry, on every mode.

The filter is a cheap keyword scorer (no AI, no database). Keywords match at the start of a word ("exploited" counts for "exploit"; "laptop" does not count for "APT"). Keywords of four letters or fewer must be the whole word, allowing a plural *s* or trailing digits ("APT29", "IOCs").

| Category | Weight | Examples |
|---|---|---|
| Vulnerability | 0.30 | vulnerability, CVE-, RCE, zero-day, CVSS, PoC, advisory |
| Malware | 0.30 | malicious, ransomware, trojan, Cobalt Strike, C2 server, stealer |
| Incident | 0.25 | breach, hacked, compromise, phishing, lateral movement, supply chain |
| Threat actor | 0.35 | APT, nation-state, espionage, hacktivist, financially motivated |
| Detection | 0.20 | Sigma, YARA, IOC, MITRE ATT&CK, Splunk, SIEM, threat hunting |

One hit in a category earns 80% of its weight; two or more earn all of it. Bonuses: a CVE ID +0.4, a technique ID +0.3, an IOC-like value (IPv4, hash, defanged URL) +0.2, a security keyword in the title +0.15. The score is capped at 1.0. At the default threshold one keyword is enough, so only articles with no security words at all are dropped.

Use for general security news, mixed social sources and vendor blogs: the safe default. The keywords are English, so for foreign-language feeds turn on `auto_translate` or use `full`.

### `full` with `auto_extract_on_ingest=false` — catalog matching without NVD cost

The autolinker runs on everything, but the standalone CVE/NVD, TTP and mitigation pass does not. Rule extraction still runs if enabled. The autolinker still creates CVE stubs and links known techniques; the stubs are filled later by the nightly `cve-nvd-backfill` and `reenrich-cve-nvd` jobs.

You lose immediate NVD details and mitigation links. You keep full matching against your catalog and later backlinking of new entities.

Use for high-volume sources where you want catalog matching without NVD cost (Telegram channels, Bluesky, Reddit), or sources you don't trust enough to enrich from.

### `manual` — no autolinking

The autolinker is skipped. Regex enrichment and rule extraction still follow their own switches. The AI still reads each article if `ai_analysis_enabled` is on, and the observables stage still runs. You can autolink a single entry on demand from the intelligence workspace. Retroactive backlinking of new entities skips `manual` and `none` feeds.

Use for feeds you read for awareness but don't want in the entity graph.

### `none` — process nothing

No autolinking, AI analysis, observables scan, regex enrichment, rule extraction or GitHub import, whatever the other switches say. `_extract_entry_intel`, `_autolink_entry` and `_scan_entry_observables` each check this themselves, so no pipeline plan can turn them back on, and bulk rescans skip these feeds.

Entries are still stored, sanitized, indexed and translated. They still get a priority score, are embedded and grouped into story threads, are matched against intelligence requirements and run through automation rules.

Use for personal or non-security feeds, test feeds, or to quiet a feed while you fix the entity catalog.

### Confidence weighting and reliability rating

`_weighted_confidence()` (`backend/app/intelligence/autolinker.py:1100`) scales each autolink's confidence by the feed's reliability rating. A canonical-name match starts at 0.9 and an alias at 0.5. The result is multiplied by the feed weight (`reliability_to_weight()`, `backend/app/intelligence/autolinker.py:235`):

| Rating | A | B | C | D | E | F | unrated |
|---|---|---|---|---|---|---|---|
| Weight | 1.0 | 0.85 | 0.7 | 0.5 | 0.3 | 0.15 | 0.5 |

Then it is bucketed: ≥ 0.7 high, ≥ 0.4 medium, else low. So "APT29" on an A-rated feed stays high, and the alias "Cozy Bear" on an F-rated feed becomes low.

### Choosing a mode — quick decision guide

| Source | Suggested |
|---|---|
| NVD, CISA, vendor security advisories, top research feeds | `full` |
| General security news | `selective` (default) |
| Reddit / Mastodon / Bluesky | `selective`, or `full` with regex enrichment off |
| Foreign-language threat actor channel | `full` with regex enrichment off, or `selective` with `auto_translate` on |
| High-volume source you want matched but not read by the AI | any mode, `ai_analysis_enabled = false` |
| Industry news, untrusted sources read for awareness | `manual` |
| Personal or non-security feeds | `none` |
| A feed with persistent false positives | `manual` while you fix the catalog |

### Operational notes

- Changing a feed's mode only affects new entries. To re-process old ones, use the rescan endpoints or `autolink_batch()` (`backend/app/intelligence/autolinker.py:1573`), which commits every 100 entries.
- Creating an entity by hand runs `link_entity_to_existing_entries()` (`backend/app/intelligence/autolinker.py:1839`), which links it to existing entries using the same rules as ingest: `manual` and `none` feeds skipped, both word lists applied, the case and context rules applied, and confidence scaled by feed reliability. The pending tier does not apply, so a match ingest would hold is not linked.

### None of this uses AI

The autolinker, the relevance filter, the regex passes, NVD lookups, rule extraction and confidence weighting are all plain code: string matching, regex and arithmetic. They are cheap, fast, and need no AI provider.

AI is a separate layer (`backend/app/ai/`): the one-pass analysis, the adjudicate stage, summaries, briefings and rule drafts. AI-created links carry a source other than `auto_link`, so re-running the autolinker leaves them alone. Providers are set up in Settings → AI Configuration.

---

## Signal Engine (engine phase 2)

After post-processing, `score_entry_task` (`backend/app/workers/signal_tasks.py`) computes explainable signals (`backend/app/intelligence/signals.py`), stores them in `entry_signals` (one row per entry and signal type) and sets `entries.priority_score` (0–10).

| Family | Signals |
|---|---|
| novelty | `novel_entity`, `entity_resurgence`, `new_pairing`, `scoop` |
| coverage | `source_convergence`, `under_reported`, `feed_echo` (negative) |
| severity | `kev_added`, `epss_jump`, `epss_high`, `weaponized_poc`, `critical_cvss` |
| interest | `pir_match`, `correlation_event` |
| content | `detection_content`, `research_depth` |

Rare signals weigh more. The daily `signal-rate-recompute` job (04:20) stores each signal's 30-day firing rate in Redis (`intelfeed:signal_engine:rates`). A signal's weight is `ln(1/rate) / ln(1/0.05)`, so a signal that fires on 5% of entries weighs 1.0, clamped to 0.1–3.0. Family multipliers live at `intelfeed:signal_engine:multipliers`. `signal-rescore-recent` (every 6 hours) re-scores recent entries so late KEV and EPSS changes count.

Flags (Settings → Engine → score stage): `signal_engine_shadow` computes and stores scores (check them with `GET /api/entries/triage?mode=signals`); `signal_engine_surface` shows them in the UI. Both default to on.

Scheduled-job runs are recorded in `job_runs` by `backend/app/workers/task_tracking.py` and pruned after 30 days by `prune-engine-tables`.

### Surfacing (engine phase 3)

With `signal_engine_surface` on:

- Entry lists carry `priority_score`, `top_signals` (the top two explanations, when the score clears the radar threshold) and `is_echo`. The list shows score chips, dims echoes and offers a "Radar" sort.
- The radar threshold is automatic (the 95th percentile of the last 7 days' scores) unless overridden in the score-stage panel (`ScoreStageConfig.tsx`, API under `/api/engine/signals/*`).
- Per-user watch and mute (`/api/intelligence/watchlist`) boost or hide entities at read time.
- Entity profiles show recent developments from `GET /api/engine/entities/{type}/{id}/whats-new`.

The Priority Queue (`/priority-queue`) mixes open **story threads** with single ranked entries, built server-side by `GET /api/entries/priority-queue` (`build_priority_queue`, `backend/app/api/entries.py:1431`). A thread ranks by the score of its best unread, non-echo article, and its articles do not also appear on their own. See [story-threads.md](story-threads.md). Signal details: [engine.md](engine.md#signal-catalog).
