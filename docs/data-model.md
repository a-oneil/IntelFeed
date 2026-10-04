# Database Schema Reference

Complete reference to the IntelFeed PostgreSQL 16 schema, including tables, relationships, indexes, and migration patterns.

**Setup Context:** This document assumes you've completed [setup.md](../setup.md). See [architecture.md](./architecture.md) for conceptual overview.

---

## Table of Contents

1. [ER Diagram](#er-diagram)
2. [Entity Clusters](#entity-clusters)
3. [Junction Tables](#junction-tables)
4. [Enums & Constants](#enums--constants)
5. [Unique Constraints & Deduplication](#unique-constraints--deduplication)
6. [Indexing Strategy](#indexing-strategy)
7. [JSONB Columns](#jsonb-columns)
8. [Migration System](#migration-system)
9. [Test Database Pattern](#test-database-pattern)

---

## ER Diagram

See diagram: [ER diagram](diagrams/data-model-er-diagram.md)

---

## Entity Clusters

### 1. Users & Auth

Tables: `users`, `user_entry_states`, `playback_progress`

**Purpose:** User accounts, roles, and per-user application state (read/unread entries, podcast playback position).

**Key Relationships:**
- `User.id` (UUID PK, unique `username`)
- Users have many `UserEntryState` records (cascade delete on user removal)
- Users can own `Categories`, `Tags`, `SavedSearches`, etc. (soft delete via `created_by` not CASCADE)

**Notes:**
- Password stored as bcrypt hash (`password_hash` field)
- `role` field: "admin", "user", or "system" — the single `system` row is a non-loginable service account that background workers attribute auto-created data to (hidden from the users admin UI)
- `settings` JSONB: per-user preferences (theme, API settings, notification config)
- `last_login` tracks user activity (set on successful auth)
- `theme_id` FK omitted from model to avoid circular dependency with `Theme.created_by`; constraint exists in migration

---

### 2. Feeds & Entries

**Tables:** `feeds`, `entries`, `entry_media`, `user_entry_states`, `user_feed_subscriptions`, `podcasts`, `playback_progress`, `tags`, `entry_tags`

**Purpose:** RSS/Atom feed subscriptions, ingest of feed articles, and metadata tracking.

#### Feeds

**Columns:**
- `id` (UUID PK)
- `url` (Text, unique) — canonical feed URL
- `title`, `custom_title` — feed title and user-customized title
- `feed_type` ("rss", "atom", "json", "email", etc.) — indexed
- `last_fetched_at`, `error_count`, `last_error` — fetch health
- `etag`, `last_modified` — HTTP caching headers
- `is_active` (Boolean, indexed) — subscription status
- `reliability_rating`, `timeliness_rating`, `relevance_rating` — analyst ratings (A-F or similar)
- `intel_extraction_mode` ("full", "selective", "manual", "none") — TTP/CVE/Actor extraction strategy
- `ai_analysis_enabled`, `auto_extract_on_ingest`, `extract_detection_rules` — per-feed pipeline switches. `ai_analysis_enabled` gates the one-pass AI analysis independently of `intel_extraction_mode`, so a noisy source can stay matched against the catalog without the AI reading it
- `category_id` (FK, nullable, SET NULL on category delete)
- `retention_days` — auto-delete entries older than N days
- `adapter_config` (JSONB) — feed-type-specific config

**Relationships:**
- Has many `Entry` records (CASCADE delete)
- Has one `Podcast` (CASCADE delete, if feed is audio)
- Belongs to `Category` (optional, SET NULL)

**Deduplication:** `Entry(feed_id, guid)` unique constraint ensures no duplicate entries per feed.

#### User Feed Subscriptions

**Columns:**
- `user_id` (FK, CASCADE), `feed_id` (FK, CASCADE) — unique together
- `is_muted` (Boolean) — personal mute over the shared feed pool

Each analyst's visibility and personal mute over the shared feed pool; only consulted when the `per_user_subscriptions_enabled` system setting is on (default off). Backfilled so every existing user subscribes to every feed.

#### Entries

**Columns:**
- `id` (UUID PK)
- `feed_id` (FK, CASCADE) — which feed this came from
- `guid` (String 2000, nullable) — feed-provided ID (nullable for some feed types)
- `url`, `title`, `author` — article metadata
- `content_html`, `content_text` — article body
- `summary` — feed summary
- `published_at` (DateTime, indexed) — article publication time
- `fetched_at` (DateTime, server default) — when IntelFeed ingested it
- `word_count`, `language` — content metrics
- `content_hash` (String 64, indexed) — SHA256 of content for dedup
- `image_url` — featured/hero image
- `extracted_urls` (JSONB array) — URLs found in content
- `metadata_` (JSONB) — feed-specific metadata (e.g., feed author's categories, tags)
- `translated_html`, `translated_title`, `translation_source_language`, `translation_target_language`, `translated_at` — machine translation cache
- `last_link_validation_at` (DateTime, indexed) — last AI entity-link validation pass
- `priority_score` (Float, indexed), `scored_at` — signal engine composite score (see Signal Engine cluster)

**Relationships:**
- Belongs to `Feed` (CASCADE delete)
- Has many `UserEntryState` (CASCADE delete)
- Has many `EntryMedia` (CASCADE delete)
- Has many `EntryTag` (CASCADE delete)
- Has many `EntryTTP`, `EntryCVE`, `EntryThreatActor`, `EntryMalware`, `EntryCountry`, `EntryMitigation`, `EntryVendor`, `EntryProduct`, `EntryTool`, `EntrySector` (all CASCADE delete)
- Has many `EntrySignal`, `EntryPipelineRun`, `EntitySignalFeedback` rows and one `AIAnalysisRequest` (all CASCADE delete; signal engine)
- Has many `Note` records (NO cascade; keep notes on entry deletion)
- Has many `DetectionRule` references (NO cascade; rule may apply to many entries)
- Has many `AIResult` (NO cascade; analysis results are reference data)

**Deduplication Strategy:**
- Unique constraint on `(feed_id, guid)` prevents re-ingesting same article
- `content_hash` indexed for detecting near-duplicates across feeds

---

### 3. Intelligence Entities

**Tables:** `ttps`, `cves`, `cve_affected`, `cve_weaknesses`, `cwes`, `observables`, `threat_actors`, `malware_families`, `countries`, `sectors`, `vendors`, `products`, `mitigations`, `tools`, `ransomware_victims`, `victim_disclosures`

**Maintenance & audit tables:** `entity_maintenance_log`, `actor_description_history`, `entity_link_validation_log`, `entity_merge_suggestion_dismissals`, `entity_reclassify_tombstones`

**Resolution infrastructure:** `entity_alias_index`, `known_alias_map`, `entity_name_denylist`, `pending_autolink_matches`

**Canonical type vocabulary:** every `entity_type`-style column stores a slug from `app/entity_types.py` (`threat_actor`, `malware`, `cve`, `ttp`, `cwe`, `observable`, `country`, `tool`, `vendor`, `product`, `mitigation`, `ransomware_victim`). Note that the slug and the storage name diverge in one place: the `malware` slug is backed by the `malware_families` table and the `MalwareFamily` class.

**Name-resolved entity tables** (`threat_actors`, `malware_families`, `tools`, `vendors`, `products`, `ransomware_victims`) carry a DB-computed `normalized_name` column (`entity_norm(name)`, persisted, indexed) — the hardened normal form used for dedup and alias lookups.

**AI-extraction provenance** (migration `f1a3c5e7g9i1`): `threat_actors`, `malware_families`, `tools`, `cves`, and `ttps` carry `created_via` ("ai_extraction", "manual", "seed", or NULL when unattributed), `created_from_entry_id` (FK, SET NULL), `created_confidence`, and `needs_review` (Boolean) — powering the Engine → Extraction management tab.

**Purpose:** Catalog of threat intelligence entities extracted from entries and enriched from external sources.

#### TTP (Tactic/Technique/Procedure)

**Columns:**
- `id` (UUID PK)
- `technique_id` (String 20, unique, indexed) — MITRE ATT&CK ID (e.g., "T1234.001")
- `technique_name` — human-readable name
- `tactic` (String 100, indexed) — MITRE tactic (e.g., "Initial Access")
- `description`, `platforms`, `data_sources` (JSONB) — MITRE metadata; `data_sources` and `detection` are resolved from ATT&CK detection strategies (v17+ no longer puts them on the technique object)
- `mitre_url` — link to MITRE page
- `detection` — detection guidance
- `is_subtechnique` — true if sub-technique (T1234.001 vs T1234)
- `tactics` (JSONB) — full multi-tactic list (a technique can span tactics)
- `parent_technique_id` (String 20, indexed) — parent technique for sub-techniques
- `is_deprecated`, `superseded_by` — ATT&CK deprecation/revocation tracking
- `matrix_domain` (String 20, indexed) — "enterprise", "mobile", or "ics"
- `first_seen_at`, `last_seen_at` — temporal tracking
- `article_count` — how many entries mention this TTP
- `wikipedia_url`, `wikipedia_content`, `wikipedia_image_url` — enrichment from Wikipedia

**Deduplication:** `technique_id` unique constraint (one TTP per MITRE ID).

#### CVE

**Columns:**
- `id` (UUID PK)
- `cve_id` (String 20, unique) — CVE ID (e.g., "CVE-2021-44228")
- `cvss_score`, `severity` (indexed) — CVSS v3 score & severity
- `affected_products` (JSONB array) — affected software/products
- `exploit_status`, `exploit_sources` — exploitation tracking
- `references_` (JSONB array) — links to advisories
- `nvd_data` (JSONB) — NVD metadata
- `timeline` (JSONB) — timeline of events (disclosure, exploitation, patch)
- `epss_score`, `epss_percentile`, `epss_updated_at` — EPSS (Exploit Prediction Scoring System)
- `epss_previous_score`, `epss_changed_at` — prior score + when it last actually changed (read by the `epss_jump` signal)
- `exploit_availability` ("none", "poc", "weaponized", "active_exploitation")
- `exploit_status_source` (String 20) — provenance: "manual" when analyst-set (enrichment never clobbers it), NULL/"auto" otherwise
- `is_kev` (Boolean, indexed), `kev_date_added`, `kev_due_date` — first-class CISA KEV tracking
- `github_poc_count`, `github_poc_urls` — public exploits
- `metasploit_module` — Metasploit module if available
- `wikipedia_url`, `wikipedia_content`, `wikipedia_image_url` — enrichment

**Deduplication:** `cve_id` unique constraint.

#### CVEAffected

Authoritative CVE → vendor/product affects-links parsed from NVD CPE data (table `cve_affected`; not `EntityRelationship` rows). Raw CPE strings are always kept; `vendor_id`/`product_id` fill in only when the strings resolve to canonical entities, so unmatched pairs persist and can resolve retroactively.

**Columns:**
- `id` (UUID PK)
- `cve_id` (FK, CASCADE, indexed)
- `cpe_vendor`, `cpe_product` (Text) — raw lowercase CPE 2.3 segments
- `vendor_id`, `product_id` (FK, nullable, SET NULL, indexed) — resolved canonical entities
- `version_start`, `version_end` (Text)
- `source` (String 20, default "nvd")
- `created_at`, `resolved_at`

**Unique Constraint:** `(cve_id, cpe_vendor, cpe_product)`.

#### ThreatActor

**Columns:**
- `id` (UUID PK)
- `name` (String 255, unique, indexed) — canonical name (e.g., "APT29")
- `aliases` (ARRAY(Text)) — alternate names
- `normalized_name` (String 255, computed `entity_norm(name)`, indexed)
- `description`, `mitre_id` — metadata
- `actor_type` (String 30, indexed) — "ransomware", "nation-state", "hacktivist", "ecrime", …
- `country` (String 100) — attributed country (denormalized)
- `origin_country_id` (FK, nullable, SET NULL) — link to `Country` record
- `motivation` (String 100) — e.g., "financial", "espionage", "activism"
- `targeted_sectors` (ARRAY(Text)) — read cache of the sector *labels* on `threat_actor_target_sectors`, rebuilt by `services/sector_links.refresh_targeted_sectors_cache` and written by nothing else
- `associated_ttps` (JSONB) — list of TTPs used by this actor
- `first_seen_at`, `last_seen_at`, `article_count` — temporal & frequency
- `wikipedia_url`, `wikipedia_content`, `wikipedia_image_url` — enrichment
- `metadata_` (JSONB) — additional fields

**Deduplication:** `name` unique constraint.

#### MalwareFamily

**Columns:**
- `id` (UUID PK)
- `name` (String 255, unique, indexed) — canonical name (e.g., "Emotet")
- `aliases` (ARRAY(Text)) — alternate names
- `normalized_name` (String 255, computed `entity_norm(name)`, indexed)
- `description`, `malpedia_url` — metadata
- `malware_type` (String 50, indexed) — e.g., "trojan", "ransomware", "worm"
- `associated_actors` (JSONB) — list of actors known to use this malware
- `targeted_sectors` (ARRAY(Text)) — read cache of `malware_target_sectors`, same rule as the actor column
- `first_seen_at`, `last_seen_at`, `article_count` — temporal & frequency
- `wikipedia_url`, `wikipedia_content`, `wikipedia_image_url` — enrichment
- `metadata_` (JSONB)

**Deduplication:** `name` unique constraint.

#### Country

**Columns:**
- `id` (UUID PK)
- `name` (String 100, unique, indexed) — country name
- `iso_code` (String 2, unique) — ISO 3166-1 alpha-2 code
- `region` (String 50, indexed) — geographic region

#### Sector

The victim-industry vocabulary as an entity: 21 rows seeded from `app/intelligence/sectors.py` (one per canonical slug), ids minted as `uuid5(SECTOR_NAMESPACE, slug)` so every install agrees on them. Closed — no create, merge, convert or delete — and never autolinked, because sector names are everyday words.

**Columns:**
- `id` (UUID PK) — deterministic from the slug
- `slug` (String 50, unique, indexed) — canonical slug, e.g. `financial-services`
- `name` (String 100, unique) — display label, e.g. `Financial Services`
- `aliases` (ARRAY(Text)) — the vocabulary's alias map (`banks`, `hospitals`), so `sector:banks` resolves; never fed to the autolinker
- `description` (Text) — analyst-editable
- `article_count`, `first_seen_at`, `last_seen_at`, `metadata_` (JSONB)

Linked to entries through `entry_sectors` (written only by the one-pass AI analysis) and to actors / malware / campaigns through `threat_actor_target_sectors`, `malware_target_sectors` and `campaign_sectors` (see Junction Tables). The `targeted_sectors` arrays on actors and malware are a read cache of those junctions' labels.

#### Vendor & Product

**Columns (Vendor):**
- `id` (UUID PK)
- `name` (String 255, unique, indexed) — vendor name
- `aliases` (ARRAY(Text))
- `vendor_type` (String 50, indexed) — "software", "hardware", "cloud", etc.
- `website` (Text)
- `article_count`, `first_seen_at`, `last_seen_at`
- `wikipedia_url`, `wikipedia_content`, `wikipedia_image_url`
- `metadata_` (JSONB)

**Columns (Product):**
- `id` (UUID PK)
- `vendor_id` (FK, nullable, SET NULL)
- `name` (String 255, unique, indexed)
- `aliases` (ARRAY(Text))
- `product_type` (String 50, indexed) — "os", "application", "security_tool", etc.
- `website` (Text)
- `article_count`, `first_seen_at`, `last_seen_at`
- `wikipedia_url`, `wikipedia_content`, `wikipedia_image_url`
- `metadata_` (JSONB)

**Deduplication:** Vendor.name and Product.name unique constraints.

#### Mitigation

**Columns:**
- `id` (UUID PK)
- `mitigation_id` (String 20, unique) — MITRE mitigation ID
- `name` — mitigation name
- `description` — mitigation guidance
- `mitre_url`

**Relationships:** Many-to-many with TTP via `TTPMitigation` junction table.

#### Tool

Table `tools` — any software tool: offensive, defensive, general software, services, LLMs.

**Columns:**
- `id` (UUID PK)
- `name` (String 255, unique, indexed)
- `aliases` (ARRAY(Text))
- `normalized_name` (String 255, computed `entity_norm(name)`, indexed)
- `description` (Text)
- `tool_type` (String 50, indexed) — controlled vocabulary (`TOOL_TYPES` in `models/tool.py`): "c2_framework", "credential_access", "exploitation", "lolbas", "phishing_kit", "remote_access", "ai_model", "defensive", "dev_tool", "service", "software", etc. Free text is coerced on write; the raw string lands in `metadata_["raw_tool_type"]`
- `platforms` (ARRAY(Text)) — windows, linux, macos, cross-platform
- `malpedia_url`, `github_url`
- `detection_artifacts` (JSONB) — named pipes, process names, PE metadata, etc.
- `article_count`, `first_seen_at`, `last_seen_at`
- `wikipedia_url`, `wikipedia_content`, `wikipedia_image_url`
- `metadata_` (JSONB)

**Relationships:** Many-to-many with entries via `entry_tools` junction (confidence, matched_names, paragraph_indices).

**Deduplication:** `name` unique constraint.

#### RansomwareVictim & VictimDisclosure

Leak-site victim tracker (migration `c3d5e7f9a1b3`, behind `ransomware_tracker_enabled`). A victim is the *organization*; a disclosure is one *posting event* (org × group × timestamp × leak site) — re-extortion or a second group re-listing the same victim yields one org with multiple disclosures.

**Columns (`ransomware_victims`):**
- `id` (UUID PK)
- `name` (String 255, indexed, NOT unique — dedup goes through `normalized_name`/`domain`)
- `aliases` (ARRAY(Text)), `normalized_name` (computed `entity_norm(name)`, indexed)
- `domain` (String 255, indexed) — strongest dedup signal when present
- `country_id` (FK, SET NULL), `sector` (String 50, canonical sector slug)
- `description`, `first_seen_at`, `last_seen_at`
- `disclosure_count` (Integer) — denormalized, resolver-maintained
- `metadata_` (JSONB), `created_at`, `updated_at`

**Columns (`victim_disclosures`):**
- `id` (UUID PK)
- `victim_id` (FK, CASCADE, indexed)
- `group_id` (FK to threat_actors, nullable, SET NULL) — ransomware group; `group_name_raw` keeps the as-posted name
- `leak_site_url`, `posted_at` (indexed), `published_at` (countdown deadline)
- `country_id` (FK, SET NULL), `sector`, `claimed_data` (Text)
- `source` (String 30, e.g. "ransomware.live"), `guid` (String 64) — dedup id
- `metadata_` (JSONB), `created_at`

**Unique Constraint:** `victim_disclosures(source, guid)`.

#### Entity Resolution Infrastructure

**`entity_alias_index`** — trigger-maintained (entity, surface form, normalized form) index over the six name+aliases entity tables (actors, malware, tools, vendors, products, ransomware victims). One row per name/alias with its `entity_norm()` form; powers O(1) normalized lookups and cross-type collision checks. Unique on `(entity_type, entity_id, normalized)`.

**`known_alias_map`** — read-only industry alias knowledge from MISP Galaxy and MITRE ATT&CK intrusion sets (full replace per `source` on the enrichment beat). Lets the resolver map "Secret Blizzard" → Turla without an AI call. Unique on `(source, normalized_canonical, normalized_alias)`.

**`entity_name_denylist`** — names banned from entity creation per type (seeded from the 2026-08 prod cleanup). Unique on `(entity_type, normalized_name)`.

**`pending_autolink_matches`** — dictionary-word autolinker matches ("Royal", "Hive", "Turkey") held for one-pass AI confirmation instead of creating junction rows; promoted or rejected via `resolution`, expired by `prune_engine_tables`. Unique on `(entry_id, entity_type, entity_id)`.

#### EntityMaintenanceLog & ActorDescriptionHistory

Audit trail for autonomous entity maintenance (merge/alias/description actions by AI tasks).

**Columns (`entity_maintenance_log`):**
- `id` (UUID PK)
- `entity_type` (String 30, indexed) — canonical slugs from `app/entity_types.py`, e.g. "threat_actor", "malware"
- `entity_id` (UUID, nullable, indexed) — surviving/updated entity; NULL for cluster no-ops
- `action` (String 40, indexed) — "merge", "update_description", "update_aliases", "no_op"
- `mode` (String 10) — "shadow" or "apply"
- `before`, `after` (JSONB) — snapshots
- `reasoning` (Text), `ai_result_id` (FK, SET NULL), `applied` (Boolean)

**Columns (`actor_description_history`):**
- `id` (UUID PK)
- `actor_id` (FK, CASCADE)
- `previous_text`, `new_text`, `change_reason` (Text)
- `source` (String 30) — "ai_refresh", "manual", "initial_extraction"
- `ai_result_id` (FK, SET NULL), `applied` (Boolean)

#### EntityLinkValidationLog

One row per AI decision on an entity↔entry link (the `entity_link_validation` task). Snapshots the junction row so removals can be restored.

**Columns:**
- `id` (UUID PK)
- `entry_id` (FK, CASCADE), `entity_type` (String 20), `entity_id` (UUID, no FK — keeps audit history after entity deletion)
- `entity_name_snapshot` (String 255)
- `action` (String 40) — "shadow_remove", "removed", "restored", "needs_reclassification"
- `reason` (Text), `suggested_entity_type` (String 20)
- `original_source`, `original_confidence`, `original_matched_names`, `original_paragraph_indices`, `original_extracted_at` — junction row snapshot for restore
- `ai_result_id` (FK, SET NULL)

#### EntityMergeSuggestionDismissal

Dismissed merge-suggestion pairs from the Find Duplicates workbench — the suggestion engine never re-surfaces them. Pairs stored canonically ordered by `(entity_type, entity_id::text)`.

**Columns:**
- `id` (UUID PK)
- `entity_type_a`, `entity_id_a`, `entity_type_b`, `entity_id_b`
- `dismissed_by` (FK, SET NULL)

**Unique Constraint:** `(entity_type_a, entity_id_a, entity_type_b, entity_id_b)`.

#### EntityReclassifyTombstone

Suppresses resurrection of an entity deliberately folded cross-type (e.g., a malware family folded into a same-named threat actor). Automated creation paths (AI extraction, external feed sync) check `(source_type, normalized_name)` before creating an entity and link into the survivor at `(target_type, target_id)` instead.

**Columns:**
- `id` (UUID PK)
- `normalized_name` (String 255) — lowercased folded name/alias
- `source_type` (String 30) — entity type the name was folded OUT of
- `target_type` (String 30), `target_id` (UUID, indexed) — surviving canonical entity
- `active` (Boolean, default true) — set false to intentionally re-allow a split

**Unique Constraint:** `(source_type, normalized_name)`.

#### Observable — the IOC ledger

The indicator ledger, first-class as of 2026-09 (successor to the v1 IOC tables
dropped in `060_remove_ioc_tables`). Identity is `(kind, value)`. See
[intelligence-engine.md](intelligence-engine.md) for the capture doors.

**The rule the schema is built around: regex never creates a row.** Pattern
scanning stages entry-local candidates on `entries.observable_candidates`; rows
come only from judgment doors, and known values are then *sighted* by exact
match.

**Columns:**
- `id` (UUID PK)
- `kind` (String 20, indexed) — one of `ALL_KINDS` (`backend/app/models/observable.py:43`), in four families:
  - **network** — `ipv4`, `ipv6`, `domain`, `url`, `uri_path`, `ja3`, `ja4`, `cert_fingerprint`, `email` (stored refanged/canonical; the defanged surface form lives on the sighting)
  - **hash** — `md5`, `sha1`, `sha256`
  - **host** — `cmdline`, `registry`, `path`, `mutex`, `named_pipe`, `service_name`, `scheduled_task`, `user_agent`, `http_header` (judged by the one-pass AI's `iocs` array, or mapped from `EntryTTP.observable_type`'s vocabulary)
  - **script** — `script`, for a body-carrying fragment rather than an atom
- `value` (Text, indexed) — the canonical refanged form; `evil[.]com` and `hxxps://` normalise on the way in
- `label`, `content`, `language` — for body-carrying kinds (a rule/script fragment rather than an atom)
- `role` (String 20, indexed) — how it was used: `c2`, `delivery`, `payload`, `phishing`, `exfil`, `exploit`, `scanning` (`ROLES`)
- `description`, `evidence` (Text) — the sentence the capture door quoted
- `base_confidence`, `current_confidence` (Float, default 0.8) — base is what capture asserted, current is after decay
- `confidence_pinned` (Boolean) — exempt this row from decay
- `status` (String 12, indexed, default `active`) — derived from current confidence: `active` ≥ 0.5, `aging` < 0.5, `expired` < 0.15; `is_denied` (Boolean) — analyst denial is separate from lifecycle status
- `infra_tag` (String 20, indexed) — dual-use infrastructure kept but marked (shared hosting, CDN, URL shortener) so publishing can exclude it without deleting the intel
- `created_via` (String 20, indexed) — **which judgment door created the row**: `ai_extraction` (the one-pass `entry_analysis` `iocs` array, base confidence 0.8), `ttp_observable` (`EntryTTP.observable_value` upsert, 0.85), `ioc_list` / `publisher_ioc` (curated indicator-list feed body, 0.85), or `manual` (analyst promote/create, 1.0). There is intentionally **no value meaning "regex"**. Author-defanged input earns a +0.1 bonus — someone who defangs a string is telling you it is an indicator
- `created_from_entry_id` (FK, SET NULL), `created_confidence`, `needs_review`
- `article_count`, `sighting_count` (Integer) — raw junction counts, maintained as O(1) counters, reconciled nightly by `reconcile-observable-counters`
- `report_count`, `feed_source_count` (Integer) — the corroboration pair the UI shows as *Sources*: distinct reporting entries (articles, advisories, rule files) and distinct indicator feeds carrying the value. A feed that republishes one list as eighteen CSV variants is `feed_source_count = 1`, `report_count = 0`. `record_sighting` increments `report_count` for every door but the feed door; the nightly reconcile recomputes both from `entry_observables` (migration `s8j0l2n4p6r8`)
- `first_seen_at`, `last_seen_at`

**Unique Constraint:** `uq_observable_kind_value` on `(kind, value)` — the same
string is a different observable as a domain than as a URL path component.

**Confidence decay** (`decay-observable-confidence`, daily 02:20 UTC, gated by
`observables_decay_enabled`) is per kind (`DECAY_HALF_LIFE_DAYS`,
`observable.py:47`): `ipv4`/`ipv6` 30-day half-life, `url` 60, `domain`/`email`
90, `uri_path` 120. Hashes, host artifacts, scripts, JA3/JA4 and certificate
fingerprints never decay — behaviour and math persist, infrastructure rotates.
A new sighting resets the clock, and `confidence_pinned` opts a row out.

#### EntryObservable

Junction, PK `(entry_id, observable_id)`.

**Columns:** `confidence`, `source` (String 20), `extracted_at`,
`paragraph_indices` (Integer[]), `surface_form` (Text — the literal string as it
appeared, which may be defanged), `was_defanged` (Boolean), `ttp_id`
(FK → ttps, SET NULL — set when the sighting came from a TTP's observable
upsert, so the artifact keeps its technique).

**Index:** `observable_id`.

#### CWE

The MITRE CWE catalog as an entity type (deployed 2026-09-12). Seeded from the
official catalog by `refresh-cwe-catalog` (Mondays 03:45 UTC).

**Columns:**
- `id` (UUID PK), `cwe_id` (String 20, **unique index**) — e.g. `CWE-79`
- `name` (String 500), `kind` (String 20, indexed, default `weakness`) — the catalog also carries categories and views
- `abstraction` (String 20, indexed) — `Pillar` | `Class` | `Base` | `Variant`, the rung on the ladder
- `status`, `mapping_usage` (String 24, indexed) — MITRE's own guidance on whether the ID is appropriate for mapping
- `description`, `extended_description`
- `parent_cwe_id` (String 20, indexed) — the lineage is walked in SQL, not materialised
- `likelihood_of_exploit`
- `alternate_terms`, `capec_ids` (String[]), `consequences`, `mitigations`, `detection_methods` (JSONB arrays)
- `cwe_url`, `is_deprecated`, `superseded_by`
- `article_count`, `first_seen_at`, `last_seen_at`
- `wikipedia_url` / `wikipedia_content` / `wikipedia_image_url` — enrichment, same shape as the other entity tables
- AI-extraction provenance: `created_via` (indexed), `created_from_entry_id`, `created_confidence`, `needs_review`

#### EntryCWE

Junction, PK `(entry_id, cwe_id)`, with `confidence`, `source`, `extracted_at`,
`paragraph_indices` — the standard entry-junction shape.

#### CVEWeakness

The CVE → CWE affects-link, kept separate from `entry_cwes` because it is a
property of the vulnerability, not of an article.

**Columns:** `id`, `cve_id` (FK, CASCADE), `cwe_ref` (String 40 — the raw
reference as NVD gave it, including non-CWE placeholders like `NVD-CWE-noinfo`),
`cwe_id` (FK → cwes, SET NULL — null until the ref resolves to a catalog row),
`is_primary` (Boolean), `assigner` (String 120), `source` (String 20, default
`nvd`), `created_at`, `resolved_at`.

**Unique Constraint:** `uq_cve_weakness_pair` on `(cve_id, cwe_ref)`.
Storing the unresolved ref is deliberate: a CVE can cite a CWE the catalog
doesn't carry, and dropping it would lose the assignment.

---

### 4. Detection & Correlation

**Tables:** `detection_rules`, `detection_rule_versions`, `detection_summaries`, `correlation_event_records`, `rule_coverage`, `threat_board_state`, `log_type_alias`

**Purpose:** Detection engineering content, version control, and correlation event tracking.

#### DetectionRule

**Columns:**
- `id` (UUID PK)
- `entry_id` (FK, nullable, SET NULL) — source entry (if rule extracted from article)
- `created_by` (FK, nullable, SET NULL) — rule author
- `rule_type` (String 30, indexed) — "sigma", "splunk_spl", "crowdstrike_ql", "elastic_ql", "kql", "snort_suricata", "yara"
- `title`, `description` — rule metadata
- `rule_content` (Text) — actual rule code
- `severity` — rule severity
- `tags` (ARRAY(Text)) — rule tags
- `source_ttps`, `source_cves` (JSONB) — TTP/CVE IDs this rule detects
- `source_entries`, `source_actors`, `source_campaigns` (ARRAY(UUID)) — cross-references
- `is_draft` — draft vs published
- `log_sources` (JSONB) — for Sigma rules, log source filter
- `mitre_tactics`, `data_sources` (ARRAY(Text)) — MITRE mapping
- `notes`, `metadata_` (JSONB)
- `license` (String 60), `upstream_updated_at` (DateTime), `references` (ARRAY(Text)), `source_products` (JSONB) — provenance/reuse columns (migration `b3d5f7h9j1k3`); repo/author provenance is derived from `metadata_` (`repo`, `commit_author`, `owner`)
- `created_at`, `updated_at`

**Relationships:**
- Belongs to `Entry` (optional, SET NULL)
- Belongs to `User` (creator, SET NULL)
- Has many `DetectionRuleVersion` (CASCADE delete)

#### DetectionRuleVersion

**Columns:**
- `id` (UUID PK)
- `rule_id` (FK, CASCADE)
- `version_number` (Integer) — incrementing version
- `rule_content` (Text) — snapshot of content
- `created_by` (FK, SET NULL)
- `created_at` — version timestamp
- `notes` — change summary

#### DetectionSummary

AI-generated multi-entry detection analysis (executive summary + attack chain + rules).

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `title` (String 500)
- `entry_ids` (ARRAY(UUID)) — entries analyzed
- `analysis_focus` (String 30, default "campaign")
- `summary_content` (JSONB) — full AI response: executive_summary, attack_chain, indicators, generated_rules, gaps, related_intelligence
- `created_at`, `updated_at`

#### CorrelationEventRecord

Persisted correlation events for user notification (table `correlation_event_records`).

**Columns:**
- `id` (UUID PK)
- `event_type` (String 50, indexed)
- `entry_id` (FK, nullable, CASCADE)
- `source_entity_type`, `source_entity_id`, `source_entity_label` — pivot origin
- `related_entity_type`, `related_entity_id`, `related_entity_label` — correlated entity
- `context` (Text) — human-readable explanation
- `severity` (String 10, default "medium", indexed)
- `occurrence_count` (Integer, default 1)
- `is_read` (Boolean, indexed; composite index `(is_read, created_at)`)
- `created_at`

#### RuleCoverage

The materialised "which rules cover this entity" index behind the Threats board
and the coverage workspace. Rebuilt by `rebuild-rule-coverage` (daily 03:50 UTC)
rather than computed per request, because the join is over rule ATT&CK mappings,
CVE references and entity names at once.

It exists because the tag columns on `detection_rules` (`source_cves` /
`source_ttps` / `source_actors`) are only written by in-app authoring and by the
two importers whose upstream format carries the field — they resolve 3,996 of
11,517 rules and zero actors. This table is the resolver's answer instead of a
hope at import time.

**Composite PK:** `(rule_id, entity_type, entity_key)` — `entity_key` is a
stable string (`CVE-2026-1731`, `T1059.001`, or an entity UUID as text), not
always a UUID, so a rule can cover a behaviour with no row of its own yet.

**Columns:** `via` (String 10 — `tag` | `meta` | `text`, **which writer produced
the row**, so the UI can show why a rule matched instead of laundering a
body-text hit into a green check), `confidence` (`high` | `medium` | `low`),
`matched_on` (Text — the literal that matched, keeping every text-derived row
auditable), `updated_at`.

#### ThreatBoardState

One analyst decision per board row on the Threats board. Deliberately **not**
a lifecycle: IntelFeed does not deploy rules and cannot see whether one is
running, so there is no stage, owner or review date — only whether you have
dealt with this threat.

**Composite PK:** `(entity_type, entity_key)`.

**Columns:** `state` (String 10, default `open` — `open` | `handled` | `muted`),
`new_count_at_decision` (Integer), `decided_by` (FK → users, SET NULL),
`decided_at`, `note` (Text).

`new_count_at_decision` is what makes a snooze date unnecessary: a handled
threat returns on its own once its live count of first-seen techniques exceeds
the count at dismissal. New tradecraft reopens the row; a quiet fortnight does
not.

#### LogTypeAlias

A tiny lookup that folds the many spellings of a log source ("Microsoft-Windows-
Sysmon/Operational", "sysmon", "Sysmon EventLog") onto one canonical name, so
telemetry-feasibility checks across Sigma `logsource` blocks compare like with
like.

**PK:** `raw` (String 120). **Columns:** `canonical` (String 60, indexed),
`note` (Text).

---

### 5. Automation & Execution

**Tables:** `automation_rules`, `automation_logs`, `ai_tasks`, `ai_task_assignments`, `ai_results`, `ai_conversations`, `ai_analysis_requests`, `ai_batch_jobs`

**Purpose:** Automation rule definitions, execution logs, and AI task orchestration.

#### AutomationRule

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL) — rule creator
- `name` (String 255) — rule name
- `description` (Text)
- `is_enabled` (Boolean, default true)
- `trigger_type` (String 50) — "on_entry_ingest", "on_cve_mention", "on_schedule", "webhook", etc.
- `trigger_config` (JSONB) — trigger-specific config (e.g., schedule cron, webhook path)
- `conditions` (JSONB) — match conditions (e.g., feed_id filter, keyword filter)
- `actions` (JSONB array) — list of actions to execute (e.g., tag entries, create detection rules, post to Slack)
- `labels` (JSONB) — custom labels/tags
- `last_triggered_at`, `run_count`
- `created_at`, `updated_at`

**Relationships:** Has many `AutomationLog` (CASCADE delete).

#### AutomationLog

**Columns:**
- `id` (UUID PK)
- `rule_id` (FK, CASCADE)
- `entry_id` (FK, nullable, SET NULL)
- `trigger_source` — what triggered the rule
- `status` — "success", "error", "skipped"
- `error_message` (Text)
- `actions_taken` (JSONB) — result of each action
- `executed_at`

#### AITask

**Columns:**
- `id` (UUID PK)
- `name` (String 100) — task name (e.g., "extract_iocs", "summarize_entry")
- `display_name` (String 255)
- `description` (Text)
- `category` (String 50) — "extraction", "analysis", "summarization"
- `default_prompt_template` (Text) — default system prompt
- `output_schema` (JSONB) — expected output structure (JSON schema)
- `variables` (JSONB array) — placeholder variables in prompt
- `default_system_template` (Text) — default system prompt
- `is_system` (Boolean) — true for built-in tasks
- `is_deprecated` (Boolean) — superseded task seeds (kept for `ai_results` history, hidden from run pickers)
- `created_at`

**Relationships:** Has many `AITaskAssignment` (CASCADE delete).

#### AITaskAssignment

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `task_id` (FK, CASCADE) — which AI task
- `provider_id` (FK, CASCADE) — which AI provider
- `model_name` (String 100) — model to use (e.g., "claude-opus-4", "gpt-4")
- `is_enabled` (Boolean, default true)
- `execution_mode` (String 10) — "api" or "agent"
- `config` (JSONB) — provider-specific config (temperature, max_tokens, etc.)

**Unique Constraint:** One assignment per task (`uq_ai_task_assignments_task_id`).

**Relationships:** Belongs to `AITask`, `AIProvider`, and `User` (creator).

#### AIResult

**Columns:**
- `id` (UUID PK)
- `entry_id` (FK, nullable, SET NULL)
- `task_id` (FK, nullable, SET NULL)
- `provider_id` (FK, nullable, SET NULL)
- `model_used` (String 100)
- `input_text` (Text) — what was sent to AI
- `output_text` (Text) — raw AI response
- `parsed_output` (JSONB) — structured output (if schema defined)
- `tokens_input`, `tokens_output` (Integer)
- `cost_usd` (Numeric)
- `status` — "success", "error", "rate_limited"
- `error_message` (Text)
- `created_at`

#### AIConversation

Server-side persistence for AI copilot chat threads (global dock panel + entry/entity scoped chats).

**Columns:**
- `id` (UUID PK)
- `user_id` (FK, CASCADE, indexed)
- `title` (String 200)
- `scope_type` (String 20, indexed) — "entry", "multi_entry", "entity", "global"
- `scope_id` (String 200) — entry id, "{entity_type}:{entity_id}", or NULL for global
- `entry_ids` (JSONB) — entry list for multi_entry scope
- `messages` (JSONB array) — `{role, content, created_at, meta?}` objects
- `share_token` (String 64, unique, indexed) — non-null when a read-only public share link is published
- `created_at`, `updated_at`

#### AIAnalysisRequest & AIBatchJob

Bookkeeping for the one-pass `entry_analysis` batch extraction pipeline. Rows pruned after 30 days by `prune_engine_tables`.

**Columns (`ai_analysis_requests`):**
- `id` (UUID PK)
- `entry_id` (FK, CASCADE, unique) — one request per entry
- `status` (String 20) — "pending", "submitted", "completed", "failed", "skipped_junk", "reused_echo"
- `batch_id` (String 80, indexed), `custom_id` (String 64)
- `attempts` (Integer), `reused_from_entry_id` (UUID), `error` (Text)
- `created_at`, `submitted_at`, `completed_at`

**Columns (`ai_batch_jobs`):**
- `id` (UUID PK)
- `provider_batch_id` (String 80, unique), `provider_id` (FK, SET NULL)
- `status` (String 20) — "in_progress", "ingesting", "ended", "canceled", "failed"
- `request_count`, `succeeded`, `errored`, `expired` (Integer)
- `cost_estimate` (Numeric 12,6)
- `created_at`, `ended_at`

---

### 6. Enrichment & External Data

**Tables:** `enrichment_sources`, `user_enrichment_overrides`, `enrichment_results`, `entity_notes`, `entity_relationships`

**Purpose:** Enrichment source management, per-user overrides, and enrichment result caching.

#### EnrichmentSource

**Columns:**
- `id` (UUID PK)
- `source_type` (String 30, unique) — "nvd", "epss", "cisa_kev", "mitre_attack", "vulncheck", "osv", "malpedia", "github_poc", "cvedetails", "wikipedia"
- `display_name` (String 100)
- `is_enabled` (Boolean, default false)
- `trigger_mode` (String 20) — "auto", "scheduled", "manual"
- `api_key_encrypted` (Text) — encrypted API key
- `rate_limit_config` (JSONB) — {"requests_per_period": 50, "period_seconds": 604800}
- `last_synced_at` (DateTime, nullable)
- `health_status` (String 20) — "healthy", "degraded", "down", "unknown"
- `config` (JSONB) — source-specific config
- `min_confidence_threshold` (String 10) — "high", "medium", "low"
- `daily_budget` (Integer, nullable) — max enrichment requests per day
- `daily_budget_used` (Integer) — counter synced from Redis
- `schedule_interval_hours` (Integer) — for scheduled trigger mode
- `next_scheduled_at` (DateTime, nullable)
- `created_at`, `updated_at`

#### UserEnrichmentOverride

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `source_id` (FK, CASCADE)
- `api_key_encrypted` (Text) — per-user API key override
- `trigger_mode_override` (String 20) — per-user trigger mode override

**Unique Constraint:** One override per source per user.

#### EnrichmentResult

**Columns:**
- `id` (UUID PK)
- `entity_type` (String 20) — "ioc", "cve", "threat_actor", "malware", "ttp"
- `entity_id` (UUID) — ID of entity being enriched
- `source_type` (String 30) — which source provided this
- `raw_response` (JSONB) — original API response
- `parsed_data` (JSONB) — normalized/parsed data
- `enriched_at` (DateTime)
- `expires_at` (DateTime) — cache TTL
- `status` — "success", "error", "rate_limited", "not_found", "budget_exhausted", "skipped_low_confidence"
- `error_message` (Text)

#### EntityNote

**Columns:**
- `id` (UUID PK)
- `user_id` (FK, CASCADE)
- `entity_type` (String 20, indexed) — "ttp", "cve", "threat_actor", "malware", "campaign"
- `entity_id` (UUID, indexed)
- `title` (String 500, nullable) — unified note-card rendering with entry notes
- `content` (Text) — analyst note
- `note_type` (String 20, default "annotation") — "annotation", "analysis", "action_taken", "false_positive", "context"
- `tags` (ARRAY(Text))
- `created_at`, `updated_at`

#### EntityFieldClaim

Provenance for scalar profile fields — the field-level counterpart to `EntityRelationship`'s trust ladder. One row per (field, value, asserter), written alongside the column by every path that fills one. Agreement with the live column is computed at read time, never stored. See [entity-profiles.md](entity-profiles.md).

**Columns:**
- `id` (UUID PK)
- `entity_type` (String 30), `entity_id` (UUID) — `app.entity_types` slug
- `field` (String 40) — the entity column, e.g. "motivation", "targeted_sectors"
- `value_text` (Text) — the asserted value, rendered as the profile shows it
- `source_kind` (String 20) — analyst, ai_extraction, ai_assessment, enrichment, external_feed, seed
- `source_ref` (String 100, nullable) — adapter/feed within that kind ("wikipedia", "cybergeist")
- `entry_id` (FK, SET NULL, indexed), `quote` (Text, nullable) — the article and sentence behind the claim
- `confidence` (String 10, nullable), `created_by` (FK, SET NULL), `ai_result_id` (FK, SET NULL)
- `claim_key` (String 64, unique) — digest of entity + field + value + source + article
- `first_asserted_at`, `last_asserted_at`

**Indexes:** `(entity_type, entity_id, field)`, `(entity_type, last_asserted_at)`, `entry_id`. Repeat assertions collapse on `claim_key` and bump `last_asserted_at`; different sources or articles stay distinct rows so corroboration is countable.

#### EntityRelationship

**Columns:**
- `id` (UUID PK)
- `source_type` (String 20, indexed) — "threat_actor", "malware", "ttp", etc.
- `source_id` (UUID, indexed)
- `target_type` (String 20, indexed)
- `target_id` (UUID, indexed)
- `relationship_type` (String 30, indexed) — "uses", "exploits", "targets", "attributed_to", "variant_of", "communicates_with", "delivers", "drops", "hosts", "related_to". Valid (source_type, verb, target_type) triples are gated by the semantic allowlist in `app/intelligence/relationship_matrix.py` (`ALLOWED_RELATIONSHIPS`), enforced on every write path
- `confidence` (String 20) — "confirmed", "probable", "possible"
- `source` (String 20) — "co_occurrence", "auto_extracted", "analyst_confirmed", "analyst_created", "analyst_rejected" (hidden + never resurrected by co-occurrence), "external_feed"
- `description` (Text)
- `adjudication_verdict` (String 20, nullable), `adjudicated_at` — AI adjudicator outcome: "corroborated" (promoted to confirmed) or "coincidental" (demoted to possible, never re-promoted by co-occurrence)
- `evidence_entry_ids` (ARRAY(UUID)) — entries supporting this relationship
- `created_by` (FK, nullable, CASCADE)
- `created_at`, `updated_at`

**Unique Constraint:** One relationship per (source_type, source_id, target_type, target_id, relationship_type) tuple.

---

### 7. Dashboards & Reporting

**Tables:** `dashboards`, `dashboard_widgets`, `saved_searches`, `intel_profiles`, `intel_reports`, `intel_report_versions`, `report_templates`, `campaigns`, `campaign_entries`, `campaign_entities`, `campaign_saved_searches`, `campaign_countries`, `campaign_sectors`, `campaign_sources`

**Purpose:** User dashboards, intelligence reports, campaigns, and saved searches.

#### Dashboard

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `name` (String 255)
- `layout` (JSONB) — react-grid-layout definition
- `is_default` (Boolean) — the default dashboard
- `sort_order` (Integer)
- `created_at`

**Relationships:** Has many `DashboardWidget` (CASCADE delete).

#### DashboardWidget

**Columns:**
- `id` (UUID PK)
- `dashboard_id` (FK, CASCADE)
- `widget_type` (String 50) — "feed-activity", "cve-severity", "triage-queue-stats", …
- `title`, `config` (JSONB) — widget-specific config
- `position_x`, `position_y`, `width`, `height` — grid layout position

#### SavedSearch

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `name` (String 255)
- `display_name` (String 255) — UI-facing name (may differ from name)
- `query` (Text) — search query/filter
- `filters` (JSONB) — parsed filter object
- `created_at`

**Relationships:** Has many `CampaignSavedSearch` (CASCADE delete on search deletion).

#### Campaign

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `name` (String 255)
- `description` (Text)
- `status` (String 20) — "active", "monitoring", "closed", "historical"
- `tlp_marking` (String 20) — TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED
- `start_date`, `end_date` (Date, nullable)
- `tags` (ARRAY(Text))
- `metadata_` (JSONB)
- `created_at`, `updated_at`

**Relationships:**
- Has many `CampaignEntry` (CASCADE delete)
- Has many `CampaignEntity` (CASCADE delete)
- Has many `CampaignSavedSearch` (CASCADE delete)
- Has many `CampaignCountry` (CASCADE delete)

#### CampaignEntry

**Columns:**
- `campaign_id` (FK, CASCADE) — PK
- `entry_id` (FK, CASCADE) — PK
- `added_by` (FK, nullable)
- `notes` (Text)
- `added_at` (DateTime)

#### CampaignEntity

**Columns:**
- `id` (UUID PK)
- `campaign_id` (FK, CASCADE)
- `entity_type` (String 20) — "ttp", "cve", "threat_actor", "malware"
- `entity_id` (UUID) — ID of entity
- `role` (String 20) — "primary", "secondary", "related"
- `added_by` (FK, nullable)
- `added_at` (DateTime)

#### CampaignSavedSearch

**Columns:**
- `id` (UUID PK)
- `campaign_id` (FK, CASCADE)
- `saved_search_id` (FK, CASCADE)
- `auto_sync` (Boolean, default true) — auto-add matching entries
- `last_synced_at` (DateTime, nullable)
- `entries_added` (Integer)
- `added_by` (FK, nullable)
- `created_at` (DateTime)

#### CampaignSource

Standing intake the **campaign** owns. The alternative, a linked saved search,
belongs to whoever saved it: teammates cannot see it in their own list, it can
only be linked if it already exists, and it drifts — the campaign's subject
changes and the query doesn't.

**Columns:**
- `id` (UUID PK)
- `campaign_id` (FK, CASCADE, indexed)
- `kind` (String 20) — one of:
  - `entity` — the actor, malware, CVE or other entity named as the subject. Every article carrying it joins, which is what makes curating the primary role worth doing.
  - `story` — a thread the campaign has already accepted part of; later waves of a story you are tracking are the clearest "obviously yes".
  - `query` — a query-language string typed into the campaign. Same reach as a saved search; campaign-owned, so every analyst on it can read, pause and rewrite the query.
- `entity_type` (String 32, nullable), `ref_id` (UUID, nullable) — the target. Both null for a `query` source.
- `query` (Text, nullable) — the query-language string; set **only** when `kind = 'query'`
- `label` (Text) — **frozen at link time**, so a source still reads after its target is renamed or merged away. For a `query` source it is the query text, truncated to 120 characters.
- `auto_sync` (Boolean, default true), `last_synced_at`, `entries_added` (Integer)
- `added_by` (FK → users, SET NULL), `created_at`

**Constraints:**
- `uq_campaign_sources_target` on `(campaign_id, kind, entity_type, ref_id)` — identity for an entity/story source.
- `uq_campaign_sources_query`, a partial unique index on `(campaign_id, query) WHERE kind = 'query'` — Postgres treats NULL `ref_id`s as distinct, so query rows need their own uniqueness on the text.
- `ck_campaign_sources_shape` — `query` rows carry a query and no `ref_id`; every other kind carries a `ref_id` and no query.

**Followable types.** An entity source is refused for a type with no entry
junction (`entry_scope_junction` answers `None`): it would be created and then
never add anything. `GET /api/campaigns/source-options` is the server's own list
— the pickers read it rather than keeping a copy.

**Sync semantics.** Every kind recomputes its *full* claimed set each run and
inserts only what the campaign does not already hold, so an article that joins a
story, gains an entity link or starts matching the query later still arrives.
(The older `campaign_saved_searches` sweep diffs instead, which is why an
article that gains a link later never reaches a campaign through one.)

#### CampaignCountry

**Columns:**
- `campaign_id` (FK, CASCADE) — PK
- `country_id` (FK, CASCADE) — PK
- `role` (String 20) — "origin", "target"
- `added_at` (DateTime)

#### IntelProfile

A named, reusable **report scope**: a saved regions × verticals combination (a
customer, a client portfolio, a watch area). The platform is
enterprise-agnostic — nothing here is "the org". Analysts keep one profile per
scope they report against, and exposure reports, standing briefs and
threat-surface previews all take a profile as input.

**Columns:**
- `id` (UUID PK)
- `name` (String 255, **unique**), `description` (Text)
- `country_ids` (UUID[]) — regions, as country entity ids
- `sectors` (Text[]) — canonical slugs from the `app.intelligence.sectors` vocabulary
- `window_days` (Integer, default 90) — the lookback a surface build uses
- `curation` (JSONB) — keep/drop decisions from the last exposure build, remembered per profile: `{"kept": {"actors": [...], "malware": [...]}, "dropped": {...}}`, so a rebuild doesn't re-ask what the analyst already rejected
- `created_by` (FK → users, SET NULL, indexed), `created_at`, `updated_at`

#### IntelReport

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, CASCADE)
- `title` (String 500)
- `description` (Text)
- `template_id` (FK, nullable, SET NULL)
- `status` (String 20) — "draft", "published", "archived"
- `tlp_marking` (String 20)
- `created_at`, `updated_at`

**Relationships:** Has many `IntelReportVersion` (CASCADE delete).

#### IntelReportVersion

**Columns:**
- `id` (UUID PK)
- `report_id` (FK, CASCADE)
- `version_number` (Integer)
- `content_html` (Text)
- `entities` (JSONB) — referenced entities
- `created_at`

#### ReportTemplate

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, cascade)
- `name` (String 255)
- `description` (Text)
- `content_template` (Text) — Jinja2 template
- `variables` (JSONB array) — template variables
- `created_at`, `updated_at`

---

### 8. Tags & Comments

**Tables:** `tags`, `entry_tags`, `comments`, `comment_mentions`, `notes`

**Purpose:** User-defined tags, comments with @mentions, and free-form notes on entries.

#### Tag

Tags are global (shared across users), managed via the Tag Manager UI.

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `name` (String 100, unique, indexed)
- `color` (String 7, default "#6B7280")
- `created_at`

#### EntryTag

**Columns:**
- `entry_id` (FK, CASCADE) — PK
- `tag_id` (FK, CASCADE) — PK
- `tagged_at` (DateTime)

#### Comment

Polymorphic — comments attach to any commentable object, with threading.

**Columns:**
- `id` (UUID PK)
- `user_id` (FK, CASCADE) — comment author
- `commentable_type` (String 30, indexed), `commentable_id` (UUID, indexed) — polymorphic target
- `parent_id` (FK to comments, CASCADE) — threaded replies
- `content` (Text)
- `created_at`, `updated_at`

**Relationships:** Has many `CommentMention` (CASCADE delete).

#### CommentMention

**Columns (composite PK):**
- `comment_id` (FK, CASCADE) — PK
- `mentioned_user_id` (FK, CASCADE) — PK; who was mentioned

#### Note

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `entry_id` (FK, nullable, SET NULL) — notes survive entry deletion
- `title` (String 500)
- `content_markdown` (Text), `content_html` (Text)
- `tags` (ARRAY(Text))
- `is_pinned` (Boolean)
- `created_at`, `updated_at`

---

### 9. System & Configuration

**Tables:** `system_settings`, `themes`, `categories`, `intelligence_requirements`, `requirement_matches`, `telemetry_sources`, `glossary_terms`, `ai_providers`, `ai_prompt_templates`, `webhook_presets`, `shared_entries`, `telegram_channel_mentions`, `telegram_link_mentions`, `false_positive_records`, `tts_audio`

**Purpose:** System-wide configuration, user themes, feed categories, and external system integrations.

#### SystemSettings (Singleton)

**Columns:**
- `id` (Integer PK = 1) — enforced by CHECK constraint
- `settings` (JSONB) — public settings (alert thresholds, feed update frequency, etc.)
- `secrets` (JSONB) — encrypted secrets (API keys, webhooks)
- `updated_at` (DateTime)

**Notes:** Only one row allowed (CHECK constraint id = 1).

#### Theme

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `name` (String 100)
- `css_variables` (JSONB) — CSS variables (--primary-color, etc.)
- `is_system` (Boolean) — built-in themes
- `created_at`

#### Category

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `name` (String 255)
- `parent_id` (FK, nullable, SET NULL) — self-referential for hierarchy
- `position` (Integer) — sort order
- `created_at`

**Relationships:** Has many `Feed` records.

#### IntelligenceRequirement

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `title` (String 500)
- `description` (Text)
- `priority` (String 20) — "critical", "high", "medium", "low"
- `status` (String 20, indexed) — "active", "fulfilled", "expired", "draft"
- `category` (String 20, default "operational") — "strategic", "operational", "tactical", "technical"
- `keywords` (ARRAY(Text)) — search keywords
- `linked_feed_ids` (ARRAY(UUID)) — feed scoping
- `linked_entities` (JSONB) — entity refs the PIR tracks: `{"threat_actors": [{"id", "name"}], "malware": [...], "cves": [...], "ttps": [...]}`
- `min_relevance` (String 10, nullable) — per-PIR floor for auto-match relevance (NULL keeps all)
- `auto_match` (Boolean, default true)
- `match_count` (Integer), `last_matched_at`
- `expires_at` (DateTime, nullable)
- `fulfilled_by_report_id` (FK to intel_reports, SET NULL) — report that fulfilled this requirement
- `created_at`, `updated_at`

**Relationships:** Has many `RequirementMatch` (CASCADE delete).

#### RequirementMatch

**Columns (composite PK):**
- `requirement_id` (FK, CASCADE) — PK
- `entry_id` (FK, CASCADE) — PK
- `match_type` (String 20) — "keyword", "entity", "manual"
- `matched_on` (String 500) — what matched
- `relevance` (String 10) — "high", "medium", "low"
- `matched_at` (DateTime)

#### TelemetrySource

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, CASCADE)
- `name` (String 255)
- `source_type` (String 50) — "log", "event", "alert", "telemetry"
- `description` (Text)
- `config` (JSONB)
- `is_enabled` (Boolean)
- `created_at`, `updated_at`

#### GlossaryTerm

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `is_system` (Boolean) — seeded terms
- `name` (String 200, unique, indexed)
- `category` (String 50), `maturity` (String 20)
- `description` (Text), `long_description` (Text)
- `technologies`, `search_terms` (JSONB arrays)
- `created_at`, `updated_at`

#### AIProvider

**Columns:**
- `id` (UUID PK)
- `name` (String 100)
- `provider_type` (String 30) — "openai", "anthropic", "groq", etc.
- `base_url` (Text, nullable)
- `api_key_encrypted` (Text)
- `models` (JSONB array) — list of available models
- `is_active` (Boolean)
- `config` (JSONB) — provider-specific config
- `created_at`, `updated_at`

**Relationships:** Has many `AITaskAssignment` (CASCADE delete).

#### AIPromptTemplate

**Columns:**
- `id` (UUID PK)
- `task_id` (FK, CASCADE)
- `name` (String 255)
- `content` (Text) — Jinja2 template
- `variables` (JSONB array)
- `is_default` (Boolean)
- `created_at`

#### WebhookPreset

Reusable webhook/notification targets for automation actions.

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, nullable, SET NULL)
- `name` (String 255)
- `preset_type` (String 30, default "webhook")
- `url` (Text), `payload` (Text) — payload template
- `headers`, `config` (JSONB)
- `created_at`, `updated_at`

#### SharedEntry

Token-based public share links for entries.

**Columns:**
- `id` (UUID PK)
- `entry_id` (FK, CASCADE)
- `token` (String 64, unique) — random share token
- `created_by` (FK, nullable, SET NULL)
- `is_active` (Boolean, default true)
- `expires_at` (DateTime, nullable) — link expiration
- `created_at`

#### TelegramChannelMention

Aggregated discovery of Telegram channels mentioned across feeds (candidate sources).

**Columns:**
- `id` (UUID PK)
- `handle` (String 255, unique, indexed) — normalized channel handle
- `display_handle` (String 255), `canonical_url` (Text)
- `primary_link_type` (String 20, default "channel")
- `mention_count`, `distinct_feed_count` (Integer)
- `feed_id` (FK, nullable) — set once subscribed as a feed
- `dismissed_at`, `dismissed_by` — analyst dismissal
- `notes` (Text)
- `first_seen_at`, `last_seen_at`

#### TelegramLinkMention

Individual t.me link sightings backing the channel aggregate.

**Columns:**
- `id` (UUID PK)
- `channel_id` (FK to telegram_channel_mentions, CASCADE)
- `entry_id` (FK, CASCADE), `feed_id` (FK, nullable)
- `url` (Text), `link_type` (String 20)
- `message_id` (BigInteger), `invite_hash` (String 255)
- `discovered_at` (DateTime)

#### TTSAudio

Bookkeeping for server-side (Piper) read-aloud audio. One row per cached MP3 on the `tts_media` volume; the bytes live on disk keyed by `cache_key`.

**Columns:**
- `cache_key` (String 64 PK) — sha256 of (source + ref_id + content-hash + voice); also the mp3 filename stem
- `source` (String 20) — "entry" or "summary"
- `ref_id` (String 200) — entry_id / day_key, for debugging
- `voice` (String 80)
- `status` (String 20) — "pending", "ready", "error"
- `duration_seconds` (Float), `byte_size` (BigInteger), `error` (String 500)
- `created_at`, `last_accessed_at` — LRU eviction key
- `ttl_days` (Float, nullable) — per-row eviction TTL override in days since last access (migration `a1b2c3d4e5f6`); NULL → global `tts_cache_ttl_days`; share pre-generation sets 1.0 (~24h)

#### FalsePositiveRecord

Tracks entity FP markings for the AI prompt feedback loop.

**Columns:**
- `id` (UUID PK)
- `entity_type` (String 20, indexed), `entity_id` (UUID, indexed), `entity_value` (String 500)
- `source_entry_id` (FK, nullable, SET NULL)
- `reason` (Text) — why this is a false positive
- `marked_by` (FK, not null)
- `extraction_source` (String 20)
- `created_at`

---

### 10. Signal Engine & Pipeline Observability

**Tables:** `entry_signals`, `entry_signal_feedback`, `user_entity_watches`, `job_runs`, `entry_pipeline_runs`, `pipeline_plans`

**Purpose:** Signal engine scoring (Radar/Priority Queue), per-user entity curation, and observability for scheduled jobs and per-entry pipeline stages. Bookkeeping rows (`job_runs`, `entry_pipeline_runs`, `ai_analysis_requests`) are pruned after 30 days by `prune_engine_tables`.

#### EntrySignal

One scored, explainable signal per (entry, signal_type) — upserted, never appended.

**Columns:**
- `id` (UUID PK)
- `entry_id` (FK, CASCADE, indexed)
- `signal_type` (String 40) — novelty: `novel_entity`, `entity_resurgence`, `new_pairing`, `scoop`; coverage: `source_convergence`, `under_reported`, `feed_echo` (negative); severity: `kev_added`, `epss_jump`, `weaponized_poc`, `critical_cvss`; interest: `pir_match`, `correlation_event` (`watchlist` is read-time only, not stored); content: `detection_content`, `research_depth`
- `score` (Float) — raw strength 0..1
- `explanation` (Text), `payload` (JSONB)
- `created_at`

**Unique Constraint:** `(entry_id, signal_type)`. The composite score lands on `entries.priority_score` / `entries.scored_at`.

#### EntrySignalFeedback

Per-user thumbs verdict on an entry's Radar placement.

**Columns:**
- `id` (UUID PK)
- `entry_id` (FK, CASCADE), `created_by` (FK, CASCADE)
- `verdict` (SmallInteger)
- `created_at`

**Unique Constraint:** `(entry_id, created_by)`.

#### UserSignalWeight

Per-analyst learned signal-family weight, fitted nightly from that user's own Radar thumbs by `fit_user_signal_weights`. Applied as a read-time lift on their Radar ordering; the stored `entries.priority_score` stays global, so personalisation is reversible with one toggle. See [engine.md](engine.md).

**Columns:**
- `id` (UUID PK)
- `user_id` (FK, CASCADE, indexed)
- `family` (String 20) — novelty, coverage, severity, interest, content
- `weight` (Float) — clamped to 0.65–1.35
- `up_votes`, `down_votes`, `sample_count` (Integer) — the attributed votes behind the fit
- `updated_at`

**Unique Constraint:** `(user_id, family)`.

#### UserEntityWatch

Per-user entity watch/mute — watch boosts read-time priority, mute suppresses entries from Radar/chips.

**Columns:**
- `id` (UUID PK)
- `created_by` (FK, CASCADE)
- `entity_type` (String 20) — threat_actor, malware, cve, tool, vendor, product, country
- `entity_id` (UUID)
- `mode` (String 10) — "watch" or "mute"
- `boost` (Float, default 1.0)

**Unique Constraint:** `(created_by, entity_type, entity_id)`.

#### JobRun

Execution record for scheduled (JOB_REGISTRY) Celery tasks, written by celery signal handlers.

**Columns:**
- `id` (UUID PK)
- `task_name` (String 200), `job_key` (String 60), `celery_task_id` (String 64)
- `status` (String 12) — "success", "error", "retry"
- `started_at`, `finished_at`, `duration_ms`
- `error` (Text)
- `detail` (JSONB) — clipped `{args, kwargs, result}` context

#### EntryPipelineRun

Per-entry pipeline stage run records (which stages ran, how long, what failed).

**Columns:**
- `id` (UUID PK)
- `entry_id` (FK, CASCADE, indexed)
- `stage` (String 30), `status` (String 12)
- `duration_ms` (Integer), `error` (Text), `detail` (JSONB)
- `created_at`

#### PipelinePlan

Data-defined pipeline stage composition per scope. A seeded "Global default" row always exists; unspecified stages fall through category → global → legacy Feed booleans.

**Columns:**
- `id` (UUID PK)
- `name` (String 100)
- `scope_type` (String 10) — "global", "category", "feed"
- `scope_id` (UUID, nullable)
- `stages` (JSONB) — `{stage_name: {"enabled": bool, "config": {...}}}`
- `is_active` (Boolean)
- `created_at`, `updated_at`

**Unique Constraint:** `(scope_type, scope_id)`.

---

## Junction Tables

**Key junction tables (many-to-many):**

- **`entry_ttps`** — links entries to TTPs (with confidence, source_text, paragraph_indices)
- **`entry_cves`** — links entries to CVEs (with paragraph_indices)
- **`entry_cwes`** — links entries to CWE weaknesses (with confidence, source, paragraph_indices)
- **`entry_observables`** — links entries to IOC ledger rows (with surface_form, was_defanged, and an optional `ttp_id` when the sighting came from a TTP's observable upsert)
- **`entry_threat_actors`** — links entries to threat actors (with confidence, matched_names)
- **`entry_malware`** — links entries to malware families (with confidence, matched_names)
- **`entry_countries`** — links entries to countries (with confidence)
- **`entry_mitigations`** — links entries to mitigations
- **`entry_vendors`** — links entries to vendors (with confidence, matched_names)
- **`entry_products`** — links entries to products (with confidence, matched_names)
- **`entry_tools`** — links entries to tools (with confidence, matched_names, paragraph_indices)
- **`entry_sectors`** — links entries to the victim sectors the article describes as *targeted* (`sector_id` FK to `sectors` plus the canonical slug as a natural key; confidence, source, role, paragraph_indices). Written only by the one-pass AI analysis (`store_sectors`) — sectors are never autolinked, so a row is a judgment, not a word match
- **`entry_tags`** — links entries to user-defined tags
- **`threat_actor_target_countries`** — links threat actors to targeted countries
- **`threat_actor_target_sectors`** / **`malware_target_sectors`** — "X targets sector S" claims, each with a `source` (`rollup` from the entity's own articles, `enrichment`, `seed`, `analyst`) and an `article_count` of evidence; the nightly rollup owns only its own rows
- **`campaign_sectors`** — the victim verticals a campaign is scoped to
- **`campaign_countries`** — links campaigns to countries (origin/target role)
- **`ttp_mitigations`** — links TTPs to mitigations

**Pattern:** All junction tables use composite primary keys on FK columns, with the right-hand entity's ID as PK2 indexed separately for fast lookups in reverse direction.

### 11. Story Threads

**Tables:** `entry_embeddings`, `story_threads`, `story_thread_entries`, `story_thread_beats`, `user_thread_states`

**Purpose:** One unfolding story as a persistent object, so a story reported
twenty-three times is one row rather than twenty-three. Written only by
`app.intelligence.story_threads` (clustering) and `app.services.thread_narrative`
(the spine). See [story-threads.md](story-threads.md).

**Requires the `vector` extension** — the db image is built from `db/Dockerfile`
(`postgres:16-alpine` + pgvector 0.8.1, so the existing data directory needs no
migration).

#### EntryEmbedding

One dense vector per entry. Its own table rather than a column on `entries`,
which is the hottest table in the schema and would carry 1.5KB per row through
every sequential scan that never touches it.

**Columns:**
- `entry_id` (UUID PK, FK → entries, CASCADE)
- `embedding` (`halfvec(768)`) — 2 bytes per dimension; `vector` would cost ~200MB more resident index at 134k rows
- `model` (String 80), `content_hash` (String 64) — hash of the exact text that was embedded, so an unchanged entry is never re-embedded
- `threaded_checked_at` (timestamptz, null) — when the thread sweeper last considered this entry
- `verified_at` (timestamptz, null) — when `content_hash` was last confirmed against the entry's current text. Null sorts first in the re-hash pass, which is what makes a re-sanitized article (or a changed `build_text` recipe) find its own way back through the sweeper
- `created_at`

**Indexes:** HNSW on `embedding halfvec_cosine_ops` (created empty, before the
backfill — building it afterwards over 134k rows needs a `maintenance_work_mem`
the production host cannot spare), btree on `model`, `threaded_checked_at` and
`verified_at`.

#### StoryThread

**Columns:** `id`, `slug` (unique), `title`, `summary`, `status`
(`open` | `dormant` | `closed`), `centroid` (`halfvec(768)`, the mean of its
members), `entry_count`, `source_count` (distinct outlets, not feed rows),
`echo_count`, `first_seen`, `last_seen`, `peak_at`, `key_entities` (JSONB,
`[{entity_type, entity_id, label, count}]`), `narrative_hash` (member-set hash
the current spine was written from), `narrated_at`, `created_at`, `updated_at`.

**Index:** `(status, last_seen)`.

#### StoryThreadEntry

**Columns:** `id`, `thread_id` (FK, CASCADE), `entry_id` (FK, CASCADE, **unique**),
`role` (`origin` | `beat` | `echo`), `similarity`, `duplicate_of_entry_id` (FK,
SET NULL — for echoes, the article this one re-reports), `source_key` (host, not
feed id), `added_at`.

`entry_id` is unique on purpose: an article belongs to at most one story.

#### StoryThreadBeat

One wave of coverage. Regenerated wholesale whenever the spine is rewritten.

**Columns:** `id`, `thread_id` (FK, CASCADE), `position`, `occurred_at`, `kind`
(`first_disclosure` | `new_tradecraft` | `peak` | `update`), `headline`, `body`,
`lead_entry_id` (FK, SET NULL), `entry_ids` (JSONB), `collapsed_count`, `is_ai`
(false = the day-grouping fallback).

#### UserThreadState

**Columns:** `id`, `user_id` (FK, CASCADE), `thread_id` (FK, CASCADE),
`last_opened_at` (what "N new" is measured from).

**Unique Constraint:** `(user_id, thread_id)`.

---

### 12. Narrative Themes

**Tables:** `narrative_briefings`, `narrative_theme_members`

**Purpose:** Keep the daily briefing's own grouping of the day's articles. The
briefing already does something the engine pays an AI nowhere else to do — it
reads a whole day of reporting, sorts it into `### Theme` sections, and links
every article it cites back by entry id. That structure was rendered, shown to a
reader, and thrown away. Parsing it back costs nothing: it reads markdown that
was already generated and cached. See
`backend/app/intelligence/narrative_themes.py`; gated by
`narrative_themes_enabled` and `narrative_theme_gating`
([engine-settings.md](engine-settings.md#relationship-adjudication-and-narrative-themes)).

#### NarrativeBriefing

One parsed daily briefing — its existence is what lets "no rows for this entry"
be told apart from "this day was never parsed".

**Columns:** `id`, `day_key` (String 10, **unique index**), `theme_count`,
`cited_entry_count`, `parsed_at`.

#### NarrativeThemeMember

Which articles the briefing placed under which heading.

**Columns:** `id`, `day_key` (String 10, indexed), `entry_id` (FK, CASCADE,
indexed), `theme` (String 200), `section` (String 20, default `theme`),
`created_at`.

**Unique Constraint:** `uq_narrative_theme_member` on `(day_key, entry_id, theme)`.
**Index:** `(day_key, theme)`.

`section` is one of `theme` | `notable` | `closer` | `tldr`. Only `theme` rows
carry a heading; the rest are the briefing's own leftover buckets — which is
itself worth knowing, because an article the briefing could not place under any
theme is not corroborating anything.

---

## Enums & Constants

Enums are defined as string columns with CHECK constraints or documented in Python constant lists. No native PostgreSQL enums are used (for migration flexibility).

### Key Enums

**Feed Types:** `rss`, `atom`, `json`, `email`, `telegram`, `api`

**Intelligence Extraction Modes:** `full`, `selective`, `manual`, `none`

**Rule Types:** `sigma`, `splunk_spl`, `crowdstrike_ql`, `elastic_ql`, `kql`, `snort_suricata`, `yara`

**Campaign Status:** `active`, `monitoring`, `closed`, `historical`

**Intelligence Requirement Status:** `active`, `fulfilled`, `expired`, `draft`

**Exploit Availability (CVE):** `none`, `poc`, `weaponized`, `active_exploitation`

**Threat Level:** `critical`, `high`, `medium`, `low`, `informational`

**Confidence Levels:** `confirmed`, `probable`, `possible`

**Vendor Types:** `software`, `hardware`, `cloud`, `security`, `networking`, `semiconductor`, `telecommunications`, `other`

**Product Types:** `os`, `application`, `security_tool`, `network_device`, `cloud_service`, `database`, `firmware`, `library`, `other`

**TLP Markings:** `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, `TLP:RED`

**Enrichment Trigger Modes:** `auto`, `scheduled`, `manual`

**Enrichment Source Health:** `healthy`, `degraded`, `down`, `unknown`

---

## Unique Constraints & Deduplication

**Critical Deduplication Constraints:**

- **`entries(feed_id, guid)`** — no duplicate entries per feed
- **`feeds(url)`** — one feed per unique URL
- **`users(username)`** — unique usernames
- **`threat_actors(name)`** — one threat actor per canonical name
- **`cves(cve_id)`** — one CVE per CVE ID
- **`ttps(technique_id)`** — one TTP per MITRE technique ID
- **`malware_families(name)`** — one malware per canonical name
- **`tools(name)`** — one tool per canonical name
- **`vendors(name)`** — one vendor per canonical name
- **`products(name)`** — one product per canonical name
- **`cve_affected(cve_id, cpe_vendor, cpe_product)`** — one affects-link per CPE pair
- **`victim_disclosures(source, guid)`** — one leak-site posting per source dedup id
- **`pending_autolink_matches(entry_id, entity_type, entity_id)`** — one pending match per entry/entity
- **`entity_alias_index(entity_type, entity_id, normalized)`** — one row per entity surface form
- **`enrichment_sources(source_type)`** — one source per type
- **`ai_task_assignments(task_id)`** — one assignment per task
- **`user_enrichment_overrides(source_id)`** — one override per source per user
- **`countries(iso_code)`** — one country per ISO code
- **`entity_relationships(source_type, source_id, target_type, target_id, relationship_type)`** — one relationship per directed pair and type
- **`glossary_terms(name)`** — unique glossary entries
- **`tags(name)`** — tags are global; unique by name
- **`ai_tasks(name)`** — one task per name
- **`campaign_saved_searches(campaign_id, saved_search_id)`** — one link per pair
- **`entry_signals(entry_id, signal_type)`** — one signal per type per entry (upsert)
- **`entry_signal_feedback(entry_id, created_by)`** — one verdict per user per entry
- **`user_entity_watches(created_by, entity_type, entity_id)`** — one watch/mute per user per entity
- **`ai_analysis_requests(entry_id)`** — one analysis request per entry
- **`ai_batch_jobs(provider_batch_id)`** — one row per provider batch
- **`ai_conversations(share_token)`** — unique public share tokens
- **`pipeline_plans(scope_type, scope_id)`** — one plan per scope
- **`entity_reclassify_tombstones(source_type, normalized_name)`** — one tombstone per folded name per source type
- **`entity_merge_suggestion_dismissals(entity_type_a, entity_id_a, entity_type_b, entity_id_b)`** — one dismissal per canonical pair
- **`shared_entries(token)`** — unique share links
- **`telegram_channel_mentions(handle)`** — one row per discovered channel

---

## Indexing Strategy

### Clustered Indexes (Primary Keys)

All tables have UUID PKs with btree indexes (default).

### Non-Clustered Indexes

**Performance-critical indexes:**
- `feeds.is_active` — for active feed selection
- `feeds.feed_type` — for feed type filtering
- `entries.feed_id` — for feed → entries joins
- `entries.published_at` — for timeline queries
- `entries.content_hash` — for dedup detection
- `entries.priority_score` + composite `(published_at, priority_score)` — Priority Queue / Radar ordering
- `cves.is_kev`, `cves.epss_score` — exploited-first CVE sorting
- `ttps.parent_technique_id`, `ttps.matrix_domain` — ATT&CK catalog navigation
- `ttps.technique_id`, `threat_actors.name`, `cves.cve_id`, `malware_families.name` — entity lookups
- `threat_actors.origin_country_id` — actor by country
- `products.vendor_id` — product by vendor
- `cves.severity` — by CVSS severity
- `detection_rules.rule_type` — by rule type
- `automation_rules.is_enabled` — active rules
- `campaigns.status` — campaign lifecycle
- `enrichment_sources.source_type` — source lookup
- `entity_relationships(source_type, source_id, target_type, target_id)` — relationship traversal
- `entity_relationships.evidence_entry_ids` — GIN index (new_pairing signal probe)
- `entry_ttps(ttp_id)`, `entry_cves(cve_id)`, `entry_threat_actors(threat_actor_id)` — reverse junction lookups
- `entry_signals(signal_type, created_at)` — signal-type timelines
- `job_runs(task_name, started_at)` — job history
- `user_entry_states(user_id, entry_id)` — per-user entry state
- `playback_progress(user_id, podcast_id)` — podcast resume

### Full-Text Search Indexes

**Meilisearch indexes (separate from PostgreSQL):**
- `entries.title`, `entries.content_text`, `entries.author` — article search
- `threat_actors.name`, `threat_actors.aliases` — actor search
- `cves.cve_id`, `cves.description` — CVE search
- `campaigns.name`, `campaigns.description` — campaign search
- `detection_rules.title`, `detection_rules.rule_content` — rule search

### Partial Indexes

- `feeds(id) WHERE is_active = true` — speed up active feed queries
- `automation_rules(id) WHERE is_enabled = true` — active rules only

---

## JSONB Columns

**JSONB is used for semi-structured, extensible data:**

- **`users.settings`** — per-user preferences (theme color, notification level, API tokens)
- **`feeds.adapter_config`** — feed-type-specific config (auth headers, pagination, custom selectors)
- **`entries.metadata_`** — feed-provided metadata (original feed categories, tags, custom fields)
- **`entries.extracted_urls`** — array of URLs found in content
- **`ttps.platforms`, `ttps.data_sources`, `ttps.tactics`** — MITRE ATT&CK metadata
- **`cves.affected_products`, `cves.references_`, `cves.timeline`, `cves.nvd_data`** — NVD enrichment
- **`threat_actors.associated_ttps`, `threat_actors.metadata_`** — actor-TTP relationships & custom data
- **`malware_families.associated_actors`, `malware_families.metadata_`** — malware-actor relationships
- **`detection_rules.source_ttps`, `detection_rules.source_cves`** — detection coverage mapping
- **`detection_rules.log_sources`, `detection_rules.metadata_`** — Sigma-specific & custom data
- **`automation_rules.trigger_config`, `automation_rules.conditions`, `automation_rules.actions`, `automation_rules.labels`** — rule definition
- **`campaign.metadata_`** — campaign-specific data
- **`enrichment_sources.rate_limit_config`, `enrichment_sources.config`** — source-specific settings
- **`enrichment_results.raw_response`, `enrichment_results.parsed_data`** — caching enrichment results
- **`entity_relationships.evidence_entry_ids`** — supporting evidence
- **`dashboard.layout_config`** — grid layout
- **`dashboard_widget.config`** — widget-specific settings
- **`system_settings.settings`, `system_settings.secrets`** — global config & secrets
- **`themes.css_variables`** — CSS custom properties
- **`ai_provider.models`, `ai_provider.config`** — supported models & settings
- **`ai_prompt_template.variables`** — template placeholders
- **`ai_task.variables`** — task variable definitions
- **`ai_task_assignment.config`** — model-specific execution config
- **`intel_report.entities`** — referenced entities in report
- **`report_template.variables`** — template placeholders
- **`intelligence_requirements.linked_entities`** — PIR entity matching criteria
- **`ai_conversations.messages`, `ai_conversations.entry_ids`** — copilot chat threads
- **`entry_signals.payload`** — per-signal evidence for explanations
- **`pipeline_plans.stages`** — data-defined stage composition
- **`job_runs.detail`, `entry_pipeline_runs.detail`** — clipped execution context
- **`detection_summaries.summary_content`** — full AI detection analysis
- **`entity_maintenance_log.before` / `.after`** — entity snapshots for AI maintenance audit

**Indexing JSONB:** Use `GIN` (Generalized Inverted Index) for JSON containment queries. Example:

```sql
CREATE INDEX idx_feeds_adapter_config_gin ON feeds USING gin(adapter_config);
```

---

## Migration System

### Alembic Setup

**Location:** `backend/alembic/` — Alembic migration scripts directory.

**Configuration:** `backend/alembic.ini` — Alembic configuration file.

**Versions:** `backend/alembic/versions/` — migration files.

### Migration Naming

Migration file naming convention (by convention, not enforced by Alembic):

```
NNNN_descriptive_name.py         (legacy numeric style, e.g., 001_initial_schema.py)
<uuid>_descriptive_name.py       (UUID style, e.g., 10cba6685383_merge_heads.py)
```

Common migration prefixes:
- `add_` — add new column, table, or constraint
- `remove_` — drop column or table
- `rename_` — rename column or table
- `create_` — explicitly create a new table
- `merge_` — merge migration heads (after parallel development)
- `sync_` — sync model changes (indexes, constraints)

### Migration History

**Current head migration** (as of 2026-09-13, single head):
- `v7x9y1z3b5c7_embedding_verified_at.py` — `entry_embeddings.verified_at`

**Recent notable migrations (September 2026):**
- `s4t6u8w0x2y4` — `entry_embeddings` + the `vector` extension (pgvector)
- `u6w8x0y2z4a6` — `entry_embeddings.threaded_checked_at` (thread scan marker)
- `t5u7w9x1y3z5` — `story_threads`, `story_thread_entries`, `story_thread_beats`, `user_thread_states`
- `q2r4s6t8u0w2` — per-analyst learned Radar weights
- `r3s5t7u9w1x3` — `entity_field_claims` (profile-field provenance)

**Recent notable migrations (August 2026):**
- `h3c5e7g9i1k3` — canonical entity-type slugs (`malware_family` → `malware` across all `entity_type` columns)
- `x2m4n6p8r0s1` — `tts_audio` cache table; `a1b2c3d4e5f6` added `ttl_days`
- `y4p6q8r0s2t3` — `pending_autolink_matches` (dictionary-word matches held for AI confirmation)
- `b2d4f6h8j0l2` — CVE EPSS jump tracking (`epss_previous_score`, `epss_changed_at`)
- `c3e5g7i9k1m3` — `cve_affected` (NVD CPE affects-links)
- `d4f6h8j0l2n4`–`f6h8j0l2n4p6` — entity resolution guardrails: `entity_norm()` + `normalized_name` computed columns, `entity_alias_index`, `entity_name_denylist`, `known_alias_map`
- `g7i9k1m3o5q7` — `offensive_tools` → `tools` rename
- `c3d5e7f9a1b3` — ransomware victim tracker (`ransomware_victims`, `victim_disclosures`)
- `b3d5f7h9j1k3` — detection rule provenance (license, upstream_updated_at, references, source_products)
- `f1a3c5e7g9i1` — AI-extraction provenance columns on the five extractable entity tables
- `g2b4d6f8h0j2` — relationship adjudication columns (`adjudication_verdict`, `adjudicated_at`)

**Notable migrations (July 2026):**
- `d2a2b3c4d5g0` — CVE KEV flags + exploit-status provenance
- `e2a2b3c4d5g1` — TTP ATT&CK catalog fields (multi-tactic, sub-technique linkage, matrix domain)
- `f2a2b3c4d5g2` — dropped `boards`/`board_entries`
- `g2a2b3c4d5g3`–`i2a2b3c4d5g5` — merge suggestion dismissals, PIR entity matching, entry sectors
- `j2a2b3c4d5g6`, `l2a2b3c4d5g8` — AI copilot conversations + share tokens
- `m2a2b3c4d5g9` — pruned ~1.9M duplicate bulk-sync enrichment_results rows
- `n2b3c4d5e6f7`–`t6h8i9j0k1l2` — signal engine + pipeline observability (entry_signals, job_runs, user_entity_watches, ai_analysis queue, entry_pipeline_runs, pipeline_plans, signal feedback)
- `u7i9j0k1l2m3` — cross-type reclassify tombstones

**Notable migrations (September–October 2026):**
- `q6h8j0l2n4p6` — sector as an entity: `sectors` table seeded from the vocabulary, `entry_sectors.sector_id` FK, the three target-sector junctions, enum CHECKs widened to `sector`
- `r7i9k1m3o5q7` — `my_sectors` setting folded into per-user `sector` watches and removed

**Previous major migrations:**
- Phase 1: Core schema (users, feeds, entries, TTPs, CVEs, threat actors)
- Phase 2: Intelligence requirements & campaigns
- Phase 3: Enrichment sources & results
- Phase 4: Entity relationships & notes
- Phase 5: Detection rules & versions
- Phase 6: Automation rules & logs
- Phase 7: AI tasks & results
- Phase 8: Dashboards & themes
- Phase 9: Telegram mentions & shared entries
- Phase 10: Vendor/Product entities
- Phase 11: Index & constraint sync migrations
- Phase 12: Feature flag columns, metadata JSONB migrations

### Writing a New Migration

**Step 1: Run Alembic create**

```bash
cd backend
alembic revision --autogenerate -m "descriptive_name"
```

Alembic will auto-detect model changes and create a draft migration file.

**Step 2: Review the generated migration**

Open `backend/alembic/versions/<rev>_descriptive_name.py` and verify:
- `upgrade()` and `downgrade()` functions
- Column definitions, constraints, indexes
- Foreign key relationships (ONDELETE behavior)

**Step 3: Manual edits (if needed)**

For non-ORM changes (raw SQL, data migrations), edit the migration manually:

```python
def upgrade() -> None:
    op.add_column('entries', sa.Column('new_field', sa.String(255)))
    op.create_index('idx_entries_new_field', 'entries', ['new_field'])

def downgrade() -> None:
    op.drop_index('idx_entries_new_field', 'entries')
    op.drop_column('entries', 'new_field')
```

**Step 4: Test locally**

```bash
# Run migration up
alembic upgrade head

# Verify schema changes
psql -U intelfeed -d intelfeed_test -c "\d entries"

# Test rollback
alembic downgrade -1

# Test re-apply
alembic upgrade head
```

**Step 5: Commit and deploy**

```bash
git add backend/alembic/versions/<rev>_descriptive_name.py
git commit -m "add: new feature schema"
```

Migrations run automatically on app startup (see `backend/entrypoint.sh` and `RUN_MIGRATIONS=true`).

### Multiple Heads & Merging

If two branches introduce migrations independently, you may have multiple heads:

```bash
alembic heads
# outputs:
# <hash1>_feature_a.py
# <hash2>_feature_b.py
```

To merge:

```bash
alembic merge --message "merge feature_a and feature_b"
```

This creates a new migration file with `down_revision` pointing to both parents.

### Migration Status

**Check migration status:**

```bash
alembic current          # current DB version
alembic history          # all migrations
alembic heads            # current branch tips
```

---

## Test Database Pattern

### Setup

Tests use a separate PostgreSQL database with suffix `_test`:

```bash
POSTGRES_DB=intelfeed_test
```

### Fresh Schema Per Test (Recommended)

Each test should start with a fresh schema:

```python
# conftest.py
@pytest.fixture(scope="function")
async def db():
    """Fresh schema per test."""
    async with async_engine.connect() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        await conn.commit()
    
    async with async_session() as session:
        yield session
        await session.rollback()
```

### Alternative: Alembic for Tests

If you need to test migrations:

```bash
alembic -x db_name=intelfeed_test upgrade head
```

### Test Cleanup

Truncate key tables between test runs:

```sql
TRUNCATE TABLE entries, feeds, users, ttps, cves, threat_actors CASCADE;
```

---

## Summary: Key Schema Patterns

1. **UUIDs everywhere** — UUID primary keys across all tables (idempotent, distributed-friendly)
2. **Soft deletes via relationships** — `created_by` FKs do NOT cascade; delete users without losing their work
3. **Cascade deletes for user data** — `UserEntryState`, `PlaybackProgress` cascade on user delete (personal data)
4. **JSONB for extensibility** — Configuration, metadata, enrichment results stored in JSONB (easy schema evolution)
5. **Temporal tracking** — `created_at`, `updated_at`, `first_seen_at`, `last_seen_at` on entity tables for trending
6. **Dedup constraints** — Unique constraints on entity names, feed URLs, and entry GUIDs prevent duplicates
7. **Junction tables with metadata** — EntryTTP, EntryCVE, etc. include `confidence`, `source`, `paragraph_indices` for extraction provenance
8. **Relationship cardinality** — Most entity relationships are many-to-many (via junctions); campaigns are many-to-many with entries
9. **Enrichment result caching** — `EnrichmentResult` table caches API responses with `expires_at` TTL
10. **Audit trail** — Detection rules, automation logs, and comments track `created_by` and timestamps

---

## File References

- Models: `backend/app/models/`
- Migrations: `backend/alembic/versions/`
- Config: `backend/alembic.ini`
- Tests: `backend/tests/`
