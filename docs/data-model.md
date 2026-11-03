# Database Schema Reference

For developers who read or change the IntelFeed database. After reading it you can find any table, see what its columns mean and how tables connect, and add a migration safely.

The database is PostgreSQL 16 with two extensions: `pg_trgm` (fuzzy name matching) and `vector` (pgvector, for article embeddings). The models in `backend/app/models/` are the source of truth; this page explains them. See [architecture.md](./architecture.md) for the bigger picture and [setup.md](../setup.md) to get a database running.

---

## Table of Contents

1. [ER Diagram](#er-diagram)
2. [Conventions](#conventions)
3. [Entity Clusters](#entity-clusters)
4. [Junction Tables](#junction-tables)
5. [Enums & Constants](#enums--constants)
6. [Unique Constraints & Deduplication](#unique-constraints--deduplication)
7. [Indexing Strategy](#indexing-strategy)
8. [JSONB Columns](#jsonb-columns)
9. [Migration System](#migration-system)
10. [Test Database Pattern](#test-database-pattern)

---

## ER Diagram

See diagram: [ER diagram](diagrams/data-model-er-diagram.md)

---

## Conventions

These hold for every table unless its section says otherwise, so the column lists below skip them.

- **Primary keys** are UUIDs named `id`. The exceptions are junction tables (composite keys), `system_settings` (integer `1`), `tts_audio` (`cache_key`), `log_type_alias` (`raw`), `rule_coverage` and `threat_board_state` (composite keys), `entry_embeddings` and `user_ai_preferences` (keyed by the row they belong to).
- **Timestamps** are timezone-aware. `created_at` and `updated_at` default to `now()`.
- **`created_by`** points at `users` with `ON DELETE SET NULL`, so deleting a user keeps their work. Per-user state (read marks, watches, personal AI keys, subscriptions) uses `CASCADE` instead.
- **`metadata_`** is the Python attribute name. On `entries`, `campaigns`, `detection_rules`, `entry_media` and `podcasts` the database column is called `metadata`; on the entity tables it is `metadata_`.
- **Entity-type columns** (`entity_type`, `source_type`, `target_type`, …) store a slug from `backend/app/entity_types.py`: `threat_actor`, `malware`, `cve`, `ttp`, `cwe`, `observable`, `country`, `sector`, `tool`, `vendor`, `product`, `mitigation`, `ransomware_victim`. Import the constants rather than typing the strings. The `malware` slug is stored in the `malware_families` table (class `MalwareFamily`).
- **Fixed value sets** are plain string columns, not native PostgreSQL enums. Many carry a CHECK constraint named `ck_<table>_<column>`, added by migrations. Those constraints exist only in a migrated database, not in the test schema built by `create_all`.

---

## Entity Clusters

### 1. Users & Auth

**Tables:** `users`, `user_entry_states`, `playback_progress`

#### User (`users`)
- `username` (String 30, unique)
- `password_hash` — bcrypt
- `role` — `admin`, `user` or `system`. The single `system` row is a service account that cannot log in. Background workers attribute auto-created data to it, and the users admin page hides it.
- `is_active`, `last_login` (set on successful login)
- `settings` (JSONB) — per-user preferences
- `theme_id` (UUID, no foreign key), `custom_css`

A user's personal AI keys (`ai_providers.user_id`), AI routes and AI preferences are deleted with them. Their `ai_results` rows stay, with `user_id` / `key_owner_id` set to NULL.

#### UserEntryState (`user_entry_states`)
One row per user per entry they have touched. Unique on `(user_id, entry_id)`.
- `is_read`, `is_starred`, `is_bookmarked`, `is_hidden`, `read_at`

#### PlaybackProgress (`playback_progress`)
Where a user stopped in a podcast or video. Unique on `(user_id, entry_media_id)`.
- `entry_media_id` (FK → `entry_media`, CASCADE), `position_seconds`, `is_completed`

---

### 2. Feeds & Entries

**Tables:** `feeds`, `user_feed_subscriptions`, `podcasts`, `entries`, `entry_media`, `ingest_batches`, `ingest_batch_items`, `ingest_files`

#### Feed (`feeds`)
- `url` (Text, unique), `title`, `custom_title`, `site_url`, `icon_url`, `description`, `language`
- `feed_type` (default `rss`, indexed) — see [Enums & Constants](#enums--constants)
- `adapter_config` (JSONB) — settings for the feed's adapter (for example `auto_translate`, `exclude_shorts`)
- `category_id` (FK → `categories`, SET NULL)
- Fetching: `fetch_interval_minutes` (default 30), `last_fetched_at`, `etag`, `last_modified`
- Health: `error_count`, `last_error`, `error_since`, `auto_paused_at`. While errors continue, the poller waits longer between fetches.
- Switches: `is_active` (indexed), `is_muted`, `visible_to_visitors` (shown in public read-only mode; default off)
- Analyst ratings: `reliability_rating` (one letter, A–F), `timeliness_rating` (excellent / good / fair / poor), `relevance_rating` (high / medium / low), `analyst_notes`, `last_reviewed_at`
- Pipeline switches:
  - `intel_extraction_mode` (default `selective`) — `full`, `selective`, `manual` or `none`. `none` turns off autolinking and extraction for the feed.
  - `ai_analysis_enabled` — lets the one-pass AI read this feed. It works separately from the extraction mode, so a noisy feed can still be matched against known entities without the AI reading it.
  - `auto_extract_on_ingest` (regex CVE/TTP pass), `extract_detection_rules`, `extract_tools`
  - `exclude_title_patterns` — entries whose title contains one of these phrases are skipped
- `retention_days` — entries older than this are deleted

A feed has many entries and at most one `podcasts` row (both CASCADE).

#### UserFeedSubscription (`user_feed_subscriptions`)
Each analyst's view of the shared feed pool. Unique on `(user_id, feed_id)`.
- `is_muted` — articles still arrive but leave this user's unread counts
- `is_paused` — this user stops receiving new articles. The feed keeps fetching while at least one subscriber has it unpaused.

Read only while the `per_user_subscriptions_enabled` setting is on (the default). With it off, `feeds.is_active` and `feeds.is_muted` are the shared switches.

#### Podcast (`podcasts`)
Extra details for an audio feed. Unique on `feed_id`.
- `author`, `categories` (Text[]), `is_explicit`, `podcast_type` (default `episodic`), `artwork_url`, `metadata`

#### Entry (`entries`)
One article, post, video or uploaded file.
- `feed_id` (FK, CASCADE, indexed)
- `guid` (String 2000, nullable) — the feed's own id for the item
- `url`, `title` (String 2000), `author`, `summary`
- `content_html` (sanitized), `content_text`
- `published_at` (indexed), `fetched_at`, `created_at`
- `word_count`, `language`
- `content_hash` (String 64) — SHA-256 of the normalized title plus the first 500 characters of text. Used to spot the same article arriving from another feed.
- `image_url` — lead image
- `extracted_urls` (JSONB) — links found in the content
- `observable_candidates` (JSONB) — indicator-like strings found by pattern scanning. They stay here until a judgment step creates a ledger row (see [Observable — the IOC ledger](#observable--the-ioc-ledger)).
- `metadata` (JSONB) — adapter-specific data (for example the GitHub `content_type`, Telegram `forwarded_from`, or an upload's `batch_id`)
- Translation cache: `translated_html`, `translated_title`, `translation_source_language`, `translation_target_language`, `translated_at`
- Signal engine: `priority_raw` (unbounded weighted sum, the sort key, indexed), `priority_score` (the same placed on a 0–10 scale, indexed), `scored_at`

Unique on `(feed_id, guid)`.

What happens to related rows when an entry is deleted:
- **Deleted with it (CASCADE), among others:** read state, media, tags, every entity junction, `entry_signals`, `entry_signal_feedback`, `entry_pipeline_runs`, `ai_analysis_requests`, `ai_results`, `entry_embeddings`, story-thread membership, share links.
- **Kept, link cleared (SET NULL):** `notes`, `detection_rules`, `entity_field_claims`, upload items and files, and the `created_from_entry_id` on entities.

#### EntryMedia (`entry_media`)
Audio, video or images attached to an entry.
- `entry_id` (FK, CASCADE), `media_type`, `url`, `mime_type`, `file_size`, `duration_seconds`, `thumbnail_url`
- `transcript_text` — YouTube or podcast transcript
- `metadata`

#### Bulk ingest (`ingest_batches`, `ingest_batch_items`, `ingest_files`)
Files, pasted text and URLs an analyst uploads. Each item that parses becomes an ordinary entry on the built-in Manual Uploads feed and goes through the normal pipeline. The only trace on the entry is `metadata.batch_id` plus some file bookkeeping keys.

- **`ingest_batches`** — one upload. `user_id` (SET NULL), `label`, `source` (default `ui`), `options` (JSONB).
- **`ingest_batch_items`** — one thing in the batch.
  - `batch_id` (CASCADE), `parent_item_id` (a .zip or repo expands into child items), `position`
  - `kind` — `url`, `file`, `text`, `github_repo`, `github_file`
  - `status` — `queued`, `parsing`, `created`, `expanded`, `duplicate`, `no_text`, `unsupported`, `too_large`, `failed`, `cancelled`. Every outcome is a status here, not a failed request.
  - `filename`, `content_type`, `size_bytes`, `sha256`, `title`, `source_url`, `is_ioc_list`
  - `entry_id` (SET NULL) — the entry it became, or the existing twin for a duplicate
  - `error`, `attempts`, `extra` (JSONB), `started_at`, `finished_at`
- **`ingest_files`** — the original bytes on disk (under `ingest_files_dir`). Unique on `item_id`. `path`, `sha256` (indexed), `filename`, `content_type`, `size_bytes`, `entry_id`. A nightly sweep deletes old files and sets `evicted_at` but keeps the row, so the reader can say "original not kept".

---

### 3. Intelligence Entities

**Tables:** `ttps`, `cves`, `cve_affected`, `cve_weaknesses`, `cwes`, `capec_patterns`, `observables`, `threat_actors`, `malware_families`, `countries`, `sectors`, `vendors`, `products`, `mitigations`, `tools`, `ransomware_victims`, `victim_disclosures`

**Maintenance and audit tables:** `entity_maintenance_log`, `actor_description_history`, `entity_link_validation_log`, `entity_merge_suggestion_dismissals`, `entity_reclassify_tombstones`, `proposal_dismissals`

**Name-resolution tables:** `entity_alias_index`, `known_alias_map`, `entity_name_denylist`, `pending_autolink_matches`

These hold the threat-intel "things" that articles mention, plus the tables that keep them clean.

Columns shared across entity tables:
- **Activity:** `article_count`, `first_seen_at`, `last_seen_at`.
- **Wikipedia:** `wikipedia_url`, `wikipedia_content`, `wikipedia_image_url` (on actors, malware, tools, vendors, products, CVEs, TTPs, CWEs, countries and mitigations).
- **Normalized name:** `threat_actors`, `malware_families`, `tools`, `vendors`, `products` and `ransomware_victims` have a `normalized_name` column. The database computes it as `entity_norm(name)` and stores and indexes it. Dedup and alias lookups use it.
- **Creation provenance:** `threat_actors`, `malware_families`, `tools`, `cves`, `ttps`, `cwes` and `observables` record how a row was created:
  - `created_via` — for example `ai_extraction`, `manual` or `seed`; NULL when unknown
  - `created_from_entry_id` (FK → `entries`, SET NULL), `created_confidence`
  - `needs_review` (Boolean)

  The Engine → Extraction page reads these columns.

#### TTP (Tactic/Technique/Procedure)
Table `ttps`: one MITRE ATT&CK technique or sub-technique.
- `technique_id` (String 20, unique) — for example `T1059.001`
- `technique_name`
- `tactic` (indexed) — the primary tactic; `tactics` (JSONB) — every tactic the technique belongs to
- `description`, `platforms` (JSONB), `data_sources` (JSONB), `detection`, `mitre_url`. `data_sources` and `detection` come from ATT&CK detection strategies.
- `is_subtechnique`, `parent_technique_id` (indexed)
- `is_deprecated`, `superseded_by`
- `matrix_domain` (indexed) — `enterprise`, `mobile` or `ics`
- `nist_controls`, `cis_controls` (Text[]) — the NIST 800-53 and CIS controls that mitigate the technique (`AC-06`, `CIS-13.7`), from CTID's Mappings Explorer ([rules](automation-ai-enrichment.md#ctid-control-mappings))

#### CVE
Table `cves`: one published vulnerability.
- `cve_id` (String 20, unique) — for example `CVE-2021-44228`
- `aliases` (Text[]) — other ids for the same vulnerability (`GHSA-…`, a distro's advisory id), added by the OSV source
- `description`, `cvss_score` (Numeric 3,1), `severity` (indexed)
- `affected_products`, `references_`, `nvd_data`, `timeline` (all JSONB)
- EPSS (the Exploit Prediction Scoring System, a daily probability that a CVE will be exploited): `epss_score` (indexed), `epss_percentile`, `epss_updated_at`, `epss_previous_score`, `epss_changed_at`. The `epss_jump` signal reads the last two.
- Exploitation:
  - `exploit_status`, `exploit_sources` (JSONB)
  - `exploit_availability` — `none`, `poc`, `weaponized` or `active_exploitation`
  - `exploit_status_source` — `manual` when an analyst set it; enrichment never overwrites a manual value
- KEV (CISA's Known Exploited Vulnerabilities list): `is_kev` (indexed), `kev_date_added`, `kev_due_date`
- SSVC (CISA's Stakeholder-Specific Vulnerability Categorization, from the CISA-ADP container of the CVE record): `ssvc_exploitation` (`none`, `poc`, `active`), `ssvc_automatable` (`yes`, `no`), `ssvc_technical_impact` (`partial`, `total`). The cvelist enrichment source writes them.
- Public exploits: `github_poc_count`, `github_poc_urls` (Text[]), `metasploit_module`

#### CVEAffected
Table `cve_affected`: which vendors and products a CVE affects, read from NVD CPE data, the CNA's `affected` list in the CVE record and CISA-ADP's CPEs (CPE is NVD's naming scheme for software). These links live here, not in `entity_relationships`. The raw CPE strings are always kept. `vendor_id` and `product_id` are filled in when the strings match a known entity, so an unmatched pair can still match later.
- `cve_id` (FK, CASCADE)
- `cpe_vendor`, `cpe_product` — raw lowercase CPE 2.3 parts
- `vendor_id`, `product_id` (FK, SET NULL)
- `version_start`, `version_end`, `resolved_at`
- `source` (default `nvd`) — `nvd`, `cna` (the CVE record's `affected` list) or `cisa_adp` (CISA's CPEs, which carry no version range)

Unique on `(cve_id, cpe_vendor, cpe_product)`.

#### ThreatActor
Table `threat_actors`.
- `name` (String 255, unique), `aliases` (Text[]), `normalized_name`
- `description`, `mitre_id`
- `actor_type` (indexed) — for example `ransomware`, `nation-state`, `hacktivist`, `ecrime`
- `country` (String 100, free text), `origin_country_id` (FK → `countries`, SET NULL)
- `motivation` — for example `financial`, `espionage`
- `targeted_sectors` (Text[]) — a cache of the sector labels in `threat_actor_target_sectors`. Only `services/sector_links.refresh_targeted_sectors_cache` writes it.
- `associated_ttps` (JSONB), `metadata_` (JSONB)

#### MalwareFamily
Table `malware_families`.
- `name` (String 255, unique), `aliases`, `normalized_name`
- `description`, `mitre_id`, `malpedia_url`
- `malware_type` (indexed) — for example `trojan`, `ransomware`, `worm`
- `associated_actors` (JSONB)
- `targeted_sectors` (Text[]) — a cache of `malware_target_sectors`, kept the same way as the actor column
- `metadata_`

#### Country
Table `countries`.
- `name` (String 255, unique), `iso_code` (String 3), `aliases`, `region` (String 100), `description`, `metadata_`

#### Sector
Table `sectors`: the industries that attacks target. There are 21 rows, one per slug in `app/intelligence/sectors.py`. Each id is `uuid5(SECTOR_NAMESPACE, slug)`, so every install has the same ids. The list is closed: no create, merge, convert or delete. Sectors are never autolinked, because their names are everyday words.
- `slug` (String 50, unique) — for example `financial-services`
- `name` (String 100, unique) — for example `Financial Services`
- `aliases` — alternative names (`banks`, `hospitals`) so a search like `sector:banks` works. They are never fed to the autolinker.
- `description` (analyst-editable), `metadata_`

Entries link to sectors through `entry_sectors`, which only the one-pass AI analysis writes. Actors, malware and campaigns link through `threat_actor_target_sectors`, `malware_target_sectors` and `campaign_sectors` (see [Junction Tables](#junction-tables)).

#### Vendor & Product
Tables `vendors` and `products`.
- Both: `name` (String 255, unique), `aliases`, `normalized_name`, `description`, `website`, `metadata_`
- `vendors.vendor_type` (indexed) — see [Enums & Constants](#enums--constants)
- `vendors.country_id` (FK → `countries`, SET NULL, indexed) — the company's country, from Wikidata (P17), when IntelFeed tracks that country
- `products.vendor_id` (FK → `vendors`, SET NULL), `products.product_type` (indexed)
- `products.support_status` (String 20) — `maintained`, `security_only`, `eol` or `unknown`; `products.next_eol` (Date) — the soonest end of security support among maintained releases. Both come from endoflife.date and stay empty for products it doesn't list ([rules](automation-ai-enrichment.md#endoflifedate))

#### Mitigation
Table `mitigations`: MITRE ATT&CK mitigations.
- `mitre_id` (String 20, unique) — for example `M1036`
- `name`, `description`, `mitre_url`
- `cis_controls`, `nist_controls` (Text[])

Linked to TTPs through `ttp_mitigations`.

#### Tool
Table `tools`: any named software. That includes attack tools, defensive tools, ordinary software, online services and AI models. The AI only creates new rows for software an attacker uses; the other kinds come from imports and analysts, and the AI links to them once they exist.
- `name` (String 255, unique), `aliases`, `normalized_name`, `description`, `mitre_id`
- `tool_type` (indexed) — one of `TOOL_TYPES` in `models/tool.py`. Free text is mapped onto the list when written, and the original string is kept in `metadata_["raw_tool_type"]`.
- `platforms` (Text[]), `malpedia_url`, `github_url`
- `detection_artifacts` (JSONB) — named pipes, process names, file metadata and similar
- `metadata_`

#### RansomwareVictim & VictimDisclosure
The leak-site victim tracker, filled by the `sync_ransomware_victims` job from ransomware.live. A victim is the organization. A disclosure is one posting: one organization, one group, one time, one leak site. If a group re-lists a victim, or a second group claims it, there is still one victim with several disclosures.

**`ransomware_victims`:**
- `name` (indexed, **not** unique — dedup uses `normalized_name` and `domain`), `aliases`, `normalized_name`
- `domain` (indexed) — the strongest dedup signal when present
- `country_id` (FK, SET NULL), `sector` (a sector slug)
- `description`, `disclosure_count` (kept up to date by the resolver), `metadata_`

**`victim_disclosures`:**
- `victim_id` (FK, CASCADE)
- `group_id` (FK → `threat_actors`, SET NULL); `group_name_raw` keeps the name as posted
- `leak_site_url`, `posted_at` (indexed), `published_at` (the countdown deadline)
- `country_id`, `sector`, `claimed_data`
- `source` (for example `ransomware.live`), `guid` — together the dedup key, unique on `(source, guid)`

#### Entity Resolution Infrastructure

These tables stop duplicate and junk entities from being created.

- **`entity_alias_index`** — one row per name or alias of every actor, malware family, tool, vendor, product and ransomware victim, kept up to date by database triggers. Columns: `entity_type`, `entity_id`, `surface` (as written), `normalized`, `is_name`. It gives fast normalized lookups and catches the same name used by two entity types. Unique on `(entity_type, entity_id, normalized)`.
- **`known_alias_map`** — alias lists from MISP Galaxy and MITRE ATT&CK intrusion sets, refreshed weekly by `misp-galaxy-sync` and `mitre-attack-sync` (each sync replaces its own source's rows). It lets the resolver map "Secret Blizzard" to Turla without asking the AI. Unique on `(source, normalized_canonical, normalized_alias)`.
- **`entity_name_denylist`** — names that may not be created as a given entity type. Columns: `display_name`, `reason`, `source`, `active`. Unique on `(entity_type, normalized_name)`.
- **`proposal_dismissals`** — analyst decisions that stop a cleanup proposal from coming back. `kind='reclassify'` stops reclassify proposals for `(entity_type, entity_id)`. `kind='not_duplicate'` drops the pair `(entity_id, other_key)` from the likely-duplicate check. Unique on `(kind, entity_type, entity_id, other_key)`.
- **`pending_autolink_matches`** — autolinker matches on dictionary words ("Royal", "Hive", "Turkey") that wait for the one-pass AI to confirm them, instead of becoming links straight away. `resolution` records the outcome: `promoted`, `rejected`, or `dropped_ai_off`. `prune_engine_tables` deletes old rows. Unique on `(entry_id, entity_type, entity_id)`.

#### EntityMaintenanceLog & ActorDescriptionHistory

Audit trail for automatic entity maintenance: merges, alias and description changes, and adjudication verdicts.

**`entity_maintenance_log`:**
- `entity_type`, `entity_id` (NULL for a no-op)
- `action` — for example `merge`, `update_description`, `update_aliases`, `no_op`, the cleanup scanners' proposal codes, and the adjudicate stage's `adjudication_*` verdicts. An `adjudication_restored` row records an analyst undoing a verdict. It is always `applied`, holds the undone code in `before.undid`, and is never offered as a proposal.
- `mode` — `shadow` (recorded only) or `apply`
- `before`, `after` (JSONB snapshots), `reasoning`, `ai_result_id` (SET NULL), `applied`

**`actor_description_history`:**
- `actor_id` (FK, CASCADE), `previous_text`, `new_text`, `change_reason`
- `source` — for example `ai_refresh`, `manual`, `initial_extraction`
- `ai_result_id` (SET NULL), `applied`

#### EntityLinkValidationLog
Table `entity_link_validation_log`: one row per decision about a link between an entry and an actor, malware family, vendor, product or country.
- The adjudicate stage writes `shadow_remove` and `needs_reclassification` in shadow mode, and `removed` in apply mode.
- An analyst restore writes `restored` (via `POST /api/admin/hygiene/link-log/{id}/restore` or the adjudication undo).

Each row keeps a copy of the junction row so a removal can be undone. A `restored` row from the last 90 days stops the adjudicator from changing that link again. This guard reads this table, so it only protects those five link types.

- `entry_id` (FK, CASCADE), `entity_type`, `entity_id` (no FK, so history survives entity deletion), `entity_name_snapshot`
- `action`, `reason`, `suggested_entity_type`
- `original_source`, `original_confidence`, `original_matched_names`, `original_paragraph_indices`, `original_extracted_at` — the junction row copy
- `ai_result_id` (SET NULL)

#### EntityMergeSuggestionDismissal
Table `entity_merge_suggestion_dismissals`: pairs an analyst dismissed in Find Duplicates, so the suggestion never comes back. Pairs are stored in a fixed order by `(entity_type, entity_id::text)`.
- `entity_type_a`, `entity_id_a`, `entity_type_b`, `entity_id_b`, `dismissed_by` (SET NULL)

Unique on all four pair columns.

#### EntityReclassifyTombstone
Table `entity_reclassify_tombstones`: stops an entity that was folded into another type from being created again. For example, a malware family merged into a threat actor of the same name. Automatic creation paths (AI extraction, external feed syncs) check `(source_type, normalized_name)` first and link to the surviving entity instead.
- `normalized_name`, `source_type` (the type the name was folded out of)
- `target_type`, `target_id` — the surviving entity
- `active` (default true) — set false to allow the split again

Unique on `(source_type, normalized_name)`.

#### Observable — the IOC ledger

Table `observables`: the indicator ledger. An IOC (indicator of compromise) is a value such as an IP address, domain, file hash or command line that points to attacker activity. Identity is `(kind, value)`. See [intelligence-engine.md](intelligence-engine.md) and [observables.md](observables.md) for how rows get here.

**The rule the schema is built around: regex never creates a row.** Pattern scanning only stages candidates on `entries.observable_candidates`. Rows come from judgment steps ("capture doors"), and once a value is known, later articles containing it are recorded as sightings by exact match.

- `kind` (indexed) — one of `ALL_KINDS` (`backend/app/models/observable.py:67`), in four families:
  - **network** — `ipv4`, `ipv6`, `domain`, `url`, `uri_path`, `ja3`, `ja4`, `cert_fingerprint`, `email`
  - **hash** — `md5`, `sha1`, `sha256`
  - **host** — `cmdline`, `registry`, `path`, `mutex`, `named_pipe`, `service_name`, `scheduled_task`, `user_agent`, `http_header`
  - **script** — `script`, a block of code rather than a single value
- `value` (indexed) — the canonical form with defanging removed (`evil[.]com` and `hxxps://` are normalized on the way in). The defanged form as written is kept on the sighting.
- `label`, `content`, `language` — for script-like kinds
- `role` (indexed) — what the indicator was doing:
  - network roles: `c2`, `delivery`, `payload`, `phishing`, `exfil`, `exploit`, `scanning`
  - host roles: `persistence`, `execution`, `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`, `collection`
- `description`, `evidence` — the sentence the capture step quoted
- `base_confidence`, `current_confidence` (Float, default 0.8) — base is what capture asserted; current is after decay
- `confidence_pinned` — exempt from decay
- `status` (indexed, default `active`) — set from current confidence: `active` at 0.5 or above, `aging` below 0.5, `expired` below 0.15
- `is_denied` — analyst denial, separate from status
- `infra_tag` (indexed) — marks shared infrastructure (shared hosting, CDN, URL shortener) so publishing can leave it out without deleting it
- `reputation` (JSONB) — the reputation summary enrichment writes (Shodan ports, hostnames, tags and vulns; VirusTotal `vt_*`; GreyNoise `gn_noise`, `gn_riot`, `gn_name`; `enriched_at`)
- `asn` (BigInteger, since 32-bit AS numbers run to 4,294,967,295), `asn_org`, `geo_country` (2 letters) — the IP's origin AS, its name and the allocation's country (Team Cymru)
- `registered_at` — when the registrable domain was registered (RDAP)
- `popularity_rank` (indexed) — the domain's rank in the daily Tranco top-1M list; null when it isn't in it
- `noise_class` — GreyNoise: `malicious`, `benign` or `unknown` when seen mass-scanning; empty when GreyNoise hasn't seen the IP scanning or hasn't been asked
- `created_via` (indexed) — which judgment step created the row, with its base confidence:

  | `created_via` | Source | Base confidence |
  |---|---|---|
  | `ai_extraction` | the one-pass `entry_analysis` `iocs` array | 0.8 |
  | `ttp_observable` | an `EntryTTP.observable_value` | 0.85 |
  | `ioc_list` | a curated indicator-list feed | 0.85 |
  | `publisher_ioc` | the indicator file a write-up links to | 0.9 |
  | `manual` | analyst promote or create | 1.0 |

  There is deliberately no value meaning "regex". A value the author defanged gets +0.1, because defanging tells you the author meant it as an indicator.
- `created_from_entry_id`, `created_confidence`, `needs_review`
- `article_count`, `sighting_count` — raw counts, updated as sightings arrive and corrected nightly by `reconcile-observable-counters`
- `report_count` (indexed), `feed_source_count` — the pair the UI shows as *Sources*: how many distinct reporting entries (articles, advisories, rule files) and how many distinct indicator feeds carry the value. A feed that publishes one list as eighteen CSV files counts as `feed_source_count = 1`, `report_count = 0`.

Unique on `(kind, value)` (`uq_observable_kind_value`), because the same string is a different observable as a domain than as a URL path.

**Confidence decay.** `decay-observable-confidence` runs daily at 02:20 UTC when `observables_decay_enabled` is on. Half-lives are per kind (`DECAY_HALF_LIFE_DAYS`, `backend/app/models/observable.py:71`):

| Kind | Half-life |
|---|---|
| `ipv4`, `ipv6` | 30 days |
| `url` | 60 days |
| `domain`, `email` | 90 days |
| `uri_path` | 120 days |
| hashes, host kinds, `script`, `ja3`, `ja4`, `cert_fingerprint` | never decay |

Attacker infrastructure changes often; file hashes and host artifacts do not. A new sighting resets the clock, and `confidence_pinned` opts a row out.

#### EntryObservable
Table `entry_observables`: one sighting. Primary key `(entry_id, observable_id)`; `observable_id` is indexed.
- `confidence`, `source`, `extracted_at`, `paragraph_indices`
- `surface_form` — the string as it appeared, possibly defanged; `was_defanged`
- `ttp_id` (FK → `ttps`, SET NULL) — set when the sighting came from a TTP's observable, so the artifact keeps its technique

#### CWE
Table `cwes`: the MITRE CWE catalog (Common Weakness Enumeration, the list of software weakness types). Loaded by `refresh-cwe-catalog` (Mondays 03:45 UTC).
- `cwe_id` (String 20, unique) — for example `CWE-79`
- `name`, `kind` (indexed, default `weakness`; the catalog also has categories and views)
- `abstraction` (indexed) — `Pillar`, `Class`, `Base` or `Variant`
- `status`, `mapping_usage` (indexed) — MITRE's advice on whether the id should be used for mapping
- `description`, `extended_description`, `likelihood_of_exploit`
- `parent_cwe_id` (indexed) — the parent chain is walked in SQL
- `alternate_terms`, `capec_ids` (Text[]); `consequences`, `mitigations`, `detection_methods` (JSONB). `capec_ids` resolve to names against `capec_patterns`
- `cwe_url`, `is_deprecated`, `superseded_by`

#### CAPECPattern
Table `capec_patterns`: MITRE's CAPEC catalog of attack patterns, replaced weekly by `capec-sync` ([rules](automation-ai-enrichment.md#capec)). A lookup table: nothing references it by key.
- `capec_id` (String 20, primary key) — for example `CAPEC-248`, the form `cwes.capec_ids` holds
- `name`, `abstraction` (`Meta`, `Standard` or `Detailed`), `status`, `description`
- `cwe_ids` (Text[]) — related weaknesses (`CWE-77`); `technique_ids` (Text[]) — ATT&CK taxonomy mappings (`T1574.010`)
- `updated_at`

#### EntryCWE
Table `entry_cwes`: primary key `(entry_id, cwe_id)`, with `confidence`, `source`, `extracted_at`, `paragraph_indices`.

#### CVEWeakness
Table `cve_weaknesses`: which CWE a CVE is classed under. It is separate from `entry_cwes` because it describes the vulnerability, not an article.
- `cve_id` (FK, CASCADE)
- `cwe_ref` (String 40) — the reference exactly as NVD or the CNA gave it, including placeholders like `NVD-CWE-noinfo`
- `cwe_id` (FK → `cwes`, SET NULL) — NULL until the reference matches a catalog row
- `is_primary`, `assigner`, `resolved_at`
- `source` — `nvd` (default) or `cvelist` (the CNA's CWE ids in its CVE record); a pair keeps the source that recorded it first

Unique on `(cve_id, cwe_ref)`. Keeping unmatched references is deliberate: a CVE can cite a CWE the catalog lacks, and dropping it would lose the assignment.

---

### 4. Detection & Correlation

**Tables:** `detection_rules`, `detection_rule_versions`, `detection_summaries`, `correlation_event_records`, `rule_coverage`, `threat_board_state`, `log_type_alias`, `telemetry_sources`

#### DetectionRule
Table `detection_rules`.
- `rule_type` (indexed) — see [Enums & Constants](#enums--constants)
- `title`, `description`, `rule_content`, `severity`, `tags` (Text[]), `notes`
- `is_draft` (default true)
- `entry_id` (FK, SET NULL) — the article it came from
- `created_by` (SET NULL)
- `derived_from` (FK → `detection_rules`, SET NULL) — the rule this one was copied or converted from
- What it detects: `source_ttps`, `source_cves` (JSONB); `source_entries`, `source_actors`, `source_campaigns` (UUID[]); `source_products` (JSONB)
- `mitre_tactics`, `data_sources` (Text[]); `log_sources` (JSONB) — the Sigma `logsource` block
- Origin: `license`, `upstream_updated_at`, `references` (Text[]). The repo and author come from `metadata` (`repo`, `commit_author`, `owner`).
- `metadata` (JSONB)

Has many `detection_rule_versions` (CASCADE).

#### DetectionRuleVersion
Table `detection_rule_versions`: a saved copy of a rule's content.
- `rule_id` (FK, CASCADE), `version_number`, `rule_content`, `rule_type`
- `change_description`, `changed_by` (FK → `users`, CASCADE)

#### DetectionSummary
Table `detection_summaries`: an AI detection analysis across several entries (summary, attack chain, rules).
- `title`, `entry_ids` (UUID[]), `analysis_focus` (default `campaign`)
- `summary_content` (JSONB) — the full AI response

#### CorrelationEventRecord
Table `correlation_event_records`: stored correlation events, shown as notifications.
- `event_type` (indexed) — one of 15 types; see [entries.md](entries.md)
- `entry_id` (FK, CASCADE)
- `source_entity_type`, `source_entity_id`, `source_entity_label`; `related_entity_type`, `related_entity_id`, `related_entity_label`
- `context` — a readable explanation
- `severity` (default `medium`), `occurrence_count` (default 1)
- `is_read` (indexed, plus a composite index on `(is_read, created_at)`)

#### RuleCoverage
Table `rule_coverage`: which rules cover which entity. The Threats board and the coverage pages read it. `rebuild-rule-coverage` rebuilds it daily at 03:50 UTC, because the matching joins rule ATT&CK mappings, CVE references and entity names all at once. Most rules arrive without CVE or actor tags, so this table works the coverage out from the rule itself.

- Primary key `(rule_id, entity_type, entity_key)`. `entity_key` is a stable string (`CVE-2026-1731`, `T1059.001`, or an entity UUID as text), so a rule can cover something that has no row yet.
- `via` — `tag`, `meta` or `text`: which matcher produced the row, so the UI can say why a rule matched
- `confidence` — `high`, `medium` or `low`
- `matched_on` — the exact text that matched

#### ThreatBoardState
Table `threat_board_state`: one analyst decision per row on the Threats board. It is not a workflow: IntelFeed does not deploy rules, so there is no stage or owner, only whether you have dealt with the threat.
- Primary key `(entity_type, entity_key)`
- `state` (default `open`) — `open`, `handled` or `muted`
- `new_count_at_decision`, `decided_by` (SET NULL), `decided_at`, `note`

A handled threat comes back by itself once its count of newly seen techniques goes above `new_count_at_decision`. New attacker behavior reopens it; a quiet fortnight does not.

#### LogTypeAlias
Table `log_type_alias`: maps the many spellings of a log source ("Microsoft-Windows-Sysmon/Operational", "sysmon") to one name, so telemetry checks compare like with like.
- Primary key `raw` (String 120); `canonical` (indexed); `note`

#### TelemetrySource
Table `telemetry_sources`: log sources the analyst says they collect. Coverage checks compare rules against these.
- `name`, `category` (a fixed list, for example `endpoint_edr`), `vendor`, `product`
- `log_types`, `log_types_canonical` (Text[])
- `ingested_into`, `enabled`, `notes`, `created_by` (SET NULL)

---

### 5. Automation & Execution

**Tables:** `automation_rules`, `automation_logs`, `ai_tasks`, `ai_prompt_templates`, `ai_task_assignments`, `user_ai_routes`, `user_ai_preferences`, `ai_results`, `ai_conversations`, `ai_analysis_requests`, `ai_batch_jobs`

Automation rules, their run logs, and AI task routing: which provider answers a task for the whole instance, which answers it for one person, and who each result belongs to. The lookup across these tables is explained in [automation-ai-enrichment.md](automation-ai-enrichment.md#personal-keys--the-lookup).

#### AutomationRule
Table `automation_rules`.
- `name`, `description`, `is_enabled` (default true), `created_by`
- `trigger_type` — for example `on_new_entry`, `on_schedule`; see [entries.md](entries.md) for the full list
- `trigger_config`, `conditions` (JSONB objects); `actions`, `labels` (JSONB arrays)
- `last_triggered_at`, `run_count`

Has many `automation_logs` (CASCADE).

#### AutomationLog
Table `automation_logs`: one rule run.
- `rule_id` (FK, CASCADE), `entry_id` (FK, SET NULL)
- `trigger_type`, `status`, `actions_executed` (JSONB), `error_message`, `executed_at`

#### AITask
Table `ai_tasks`: one kind of AI job, for example `entry_analysis`, `entry_adjudication`, `daily_summary` or `copilot`.
- `name` (String 100, unique), `display_name`, `description`
- `category` — `analysis`, `extraction`, `generation` or `maintenance` for the built-in tasks
- `default_prompt_template`, `default_system_template`
- `output_schema`, `output_schema_override` (JSONB) — the expected JSON shape
- `variables` (JSONB) — hints for the prompt editor only. The backend never checks them when rendering.
- `is_system` (built-in), `is_deprecated` (kept for old `ai_results`, hidden from pickers)
- `show_in_entry_actions`, `entry_action_order`, `show_in_entity_actions` — where the task appears as a one-click action
- `allows_user_provider` (default false) — a person's own key may answer this task. It starts true for the tasks in `USER_PROVIDER_ELIGIBLE_TASKS` (`backend/app/ai/capabilities.py:73`). The admin can turn it off, or on for a custom task, but not on for a pipeline task outside that set.

Has many prompt templates, assignments and user routes (all CASCADE).

#### AIPromptTemplate
Table `ai_prompt_templates`: an edited prompt that replaces the task's default.
- `task_id` (FK, CASCADE), `created_by`, `name`
- `template_text`, `system_text`, `variables` (JSONB)
- `is_active`, `version`

#### AITaskAssignment
Table `ai_task_assignments`: which instance provider and model run a task. Unique on `task_id` (one assignment per task).
- `task_id`, `provider_id` (both FK, CASCADE). The provider is always an instance provider (`ai_providers.user_id` NULL), never a personal key.
- `model_name`, `is_enabled`
- `execution_mode` (default `api`) — `api` or `agent`
- `config` (JSONB) — provider options such as temperature or max tokens

A provider row on its own runs nothing; work only happens for tasks that have an assignment.

#### UserAIRoute
Table `user_ai_routes`: which of a person's own keys runs a task. It is the personal version of `ai_task_assignments` (`backend/app/models/user_ai_route.py:21`). It is used only for `user` callers, only while `allow_user_ai_providers` is on, and only for tasks with `allows_user_provider`.
- `user_id` (FK, CASCADE)
- `task_id` (FK, CASCADE, nullable) — NULL is the person's default key, which covers every allowed task that has no row of its own
- `provider_id` (FK, CASCADE, nullable) — one of the person's keys. NULL on a per-task row is an opt-out: that task uses the instance's provider even though a default key exists.
- `model_name` — NULL only when `provider_id` is NULL
- `config` (JSONB) — merged over the provider's config at call time

Two partial unique indexes: one route per task per person (`uq_user_ai_routes_task`, where `task_id IS NOT NULL`) and one default per person (`uq_user_ai_routes_default`, where `task_id IS NULL`).

#### UserAIPreferences
Table `user_ai_preferences`: one row per person, created on first save (`backend/app/models/user_ai_route.py:58`). Primary key `user_id` (FK, CASCADE).
- `fallback_to_site` (default true) — when the person's key can't answer, the instance's provider takes the call. Turned off, the call is refused instead, but only once the person has a key.
- `monthly_cap_usd` (Numeric 10,4) — the person's own spending cap on their keys; NULL is no cap

#### AIResult
Table `ai_results`: one row per AI call. It is either the answer from `run_task`, or a cost-only row for paths that stream or call a provider directly (copilot, rule chat, the shared Ask Agent, rule conversion). It is the only spending record: the cost dashboard, the per-person allowance and the personal-key caps are all sums over it.
- `entry_id` (FK, CASCADE) — an entry's results are deleted with it
- `target_type`, `target_id` — what the result is about (`entry`, `conversation`, an entity type, …)
- `is_current` (default true) — re-runs mark the previous row not current. Cost-only rows are never current.
- `task_id` (FK, no ON DELETE) — a task that has results can't be deleted; the delete route answers 409 `task_has_results`
- `provider_id` (FK, SET NULL), `provider_name` (kept after the provider is deleted), `model_name`
- `prompt_used`, `raw_response`
- `parsed_result` (JSONB) — the parsed output plus meta keys:
  - `_extraction_status`, `_error`
  - `_fallback_reason` — the person's key could not answer, so the instance's provider did
  - `_prompt_version` — an edited prompt ran
- `tokens_input`, `tokens_output`, `cost_estimate` (Numeric 10,6), `processing_time_ms`
- `caller_kind` — `user`, `system`, `automation` or `share` (`backend/app/ai/caller.py:41`). NULL where nothing recorded it; the dashboard shows these as `unattributed`.
- `user_id` (SET NULL) — who the call counts against: the person, the rule's author or the sharer
- `key_owner_id` (SET NULL) — set when a personal key paid; NULL means the instance's provider did

Index `ix_ai_results_target_task_current` on `(target_type, target_id, task_id, is_current)`, plus `(user_id, created_at)` and `(key_owner_id, created_at)` for spending sums.

#### AIConversation
Table `ai_conversations`: saved copilot chat threads.
- `user_id` (FK, CASCADE), `title`
- `scope_type` (indexed) — `entry`, `multi_entry`, `entity` or `global`
- `scope_id` — the entry id, `{entity_type}:{entity_id}`, or NULL for global
- `entry_ids` (JSONB) — for `multi_entry`
- `messages` (JSONB array) — `{role, content, created_at, meta?}` objects
- `share_token` (String 64, unique) — set when a read-only share link exists

#### AIAnalysisRequest & AIBatchJob
Bookkeeping for the one-pass `entry_analysis` (one AI call that reads an article and returns all its entities and indicators) and the adjudicate stage after it. `prune_engine_tables` deletes rows older than 30 days (`engine_run_retention_days`).

**`ai_analysis_requests`** — one row per entry (unique `entry_id`, CASCADE):
- `status` — `pending`, `submitted`, `completed`, `failed`, `skipped_junk`, `reused_echo`, `skipped_feed_ai` (the feed's AI switch is off) or `skipped_feed_none` (the feed's extraction mode is `none`). The last two are looked at again by the missed-entry sweep once the feed allows AI.
- `batch_id` (indexed), `custom_id`, `attempts`, `reused_from_entry_id`, `error`
- `adjudication_status` (indexed) — the adjudicate stage's state:
  - `pending`, `completed` or `failed`
  - or why it was skipped: `skipped_off`, `skipped_plan`, `skipped_echo`, `skipped_nothing_new`, `skipped_score`, `skipped_budget`, `skipped_paused`

  An hourly resweep queues budget and paused rows again.
- `adjudication_queued_at` — when the row went pending. A pending row older than 6 hours with no run is treated as lost and queued again.
- `adjudicated_at`, `submitted_at`, `completed_at`

**`ai_batch_jobs`** — one provider batch:
- `provider_batch_id` (unique), `provider_id` (SET NULL)
- `status` — for example `in_progress`, `ingesting`, `ended`, `canceled`, `failed`
- `request_count`, `succeeded`, `errored`, `expired`, `cost_estimate` (Numeric 12,6), `ended_at`

---

### 6. Enrichment & External Data

**Tables:** `enrichment_sources`, `user_enrichment_overrides`, `enrichment_results`, `entity_context`, `entity_relation_claims`, `entity_notes`, `entity_field_claims`, `entity_relationships`

#### EnrichmentSource
Table `enrichment_sources`: one external data source.
- `source_type` (unique) — `nvd`, `epss`, `cisa_kev`, `mitre_attack`, `vulncheck`, `osv`, `malpedia`, `github_poc`, `cvedetails`, `cvelist`, `wikipedia`, `virustotal`, `greynoise`, `shodan`, `cymru`, `rdap`, `threatfox`, `urlhaus`, `malwarebazaar` (the 19 lookup sources in `ADAPTER_REGISTRY`), and the 13 catalog sources `misp_galaxy`, `metasploit`, `mitre_cwe`, `ransomware_live`, `cybergeist`, `wikidata`, `endoflife`, `tranco`, `capec`, `ctid`, `d3fend`, `etda`, `github_repo`
- `display_name`, `is_enabled` (seeded on for a source with scheduled jobs; a disabled source's jobs skip and its queued lookups wait)
- `trigger_mode` (default `manual`) — `auto` or `manual`. A source that sends an observable to a third party (`shares_ioc`) is seeded `manual`
- `api_key_encrypted`, `config` (JSONB)
- `rate_limit_config` (JSONB) — for example `{"requests_per_period": 50, "period_seconds": 604800}`
- `health_status` (default `unknown`) — `healthy`, `degraded`, `down` or `unknown`
- `min_confidence_threshold` (default `low`)
- `daily_budget` (requests per UTC day; the gateway counts usage in Redis), `last_synced_at`

#### UserEnrichmentOverride
Table `user_enrichment_overrides`: a person's own API key for a source. Unique on (`created_by`, `source_id`): each user has at most one override per source.
- `source_id` (FK, CASCADE), `created_by`, `api_key_encrypted`

#### EnrichmentResult
Table `enrichment_results`: a cached answer from a source.
- `entity_type`, `entity_id`, `source_type`
- `raw_response`, `parsed_data` (JSONB)
- `status` (default `success`) — for example `success`, `error`, `rate_limited`, `not_found`, `budget_exhausted`, `skipped_low_confidence`
- `enriched_at`, `expires_at` (when the cache entry runs out)
- A lookup adds a row only when `parsed_data` changed; otherwise it re-dates the latest one

#### EntityContext
Table `entity_context`: what one enrichment source says about one entity, for the profile's Context panel. One row per declared `Context` output. See [automation-ai-enrichment.md](automation-ai-enrichment.md#source-context).
- Primary key (`entity_type`, `entity_id`, `source_type`, `key`)
- `value` (JSONB, shaped for its display), `observed_at`, `expires_at` (indexed; rows expired over 30 days are pruned nightly)

#### EntityRelationClaim
Table `entity_relation_claims`: one enrichment source's claim that an entity is connected to another, one row per target name a declared `Relation` output lists. See [automation-ai-enrichment.md](automation-ai-enrichment.md#relations).
- Primary key (`entity_type`, `entity_id`, `source_type`, `output`, `target_key`); `target_key` is the name folded for case and spacing
- `relation`, `target_name`, `evidence`, `first_seen_at`, `last_seen_at`
- `target_type`, `target_id` — the existing entity the name resolved to; both null while the claim is held, with `held_reason` `unknown` or `ambiguous`
- Indexed on (`target_type`, `target_id`) and (`source_type`, `output`); claims whose entity is gone are pruned nightly

#### EntityNote
Table `entity_notes`: an analyst's note on an entity.
- `user_id` (FK, CASCADE), `entity_type`, `entity_id` (both indexed)
- `title`, `content`, `tags` (Text[])
- `note_type` (default `annotation`) — `annotation`, `analysis`, `action_taken`, `false_positive` or `context`

#### EntityFieldClaim
Table `entity_field_claims`: where each profile field value came from. It does for single fields (motivation, origin country, …) what the trust levels on `entity_relationships` do for links. Each path that sets a field writes one row per (field, value, source). Whether a claim agrees with the current value is worked out when read, never stored. See [entity-profiles.md](entity-profiles.md#field-provenance).
- `entity_type`, `entity_id`
- `field` — the column, for example `motivation` or `targeted_sectors`
- `value_text` — the value as the profile shows it
- `source_kind` — `analyst`, `ai_extraction`, `ai_assessment`, `enrichment`, `external_feed` or `seed`
- `source_ref` — the adapter or feed within that kind (for example `wikipedia`, `cybergeist`), or one part of a source's answer (`cvelist:cna`, `cvelist:adp` for the CVE record's CNA and CISA-ADP scores)
- `entry_id` (FK, SET NULL), `quote` — the article and sentence behind the claim
- `confidence`, `created_by` (SET NULL), `ai_result_id` (SET NULL)
- `claim_key` (String 64, unique) — a digest of entity + field + value + source + article
- `first_asserted_at`, `last_asserted_at`

Indexes on `(entity_type, entity_id, field)`, `(entity_type, last_asserted_at)` and `entry_id`. A repeated claim updates `last_asserted_at`. Different sources or articles stay separate rows, so agreement between sources can be counted.

#### EntityRelationship
Table `entity_relationships`: a typed link between two entities, for example "APT29 uses Cobalt Strike".
- `source_type`, `source_id`, `target_type`, `target_id` (all indexed)
- `relationship_type` (indexed) — the verb: `uses`, `exploits`, `targets`, `attributed_to`, `variant_of`, `communicates_with`, `delivers`, `drops`, `controls`, `related_to`, `successor_of`, `subgroup_of`, `overlaps_with`, `exposes` (observable → CVE), `operates_in` (vendor → sector). Which (source type, verb, target type) combinations are allowed is set by `ALLOWED_RELATIONSHIPS` in `app/intelligence/relationship_matrix.py`, checked on every write.
- `confidence` (default `possible`) — `confirmed`, `probable` or `possible`
- `source` (default `analyst_created`) — `co_occurrence`, `auto_extracted`, `analyst_confirmed`, `analyst_created`, `analyst_rejected` (hidden and never recreated by co-occurrence), `external_feed` or `enrichment` (held by claims in `entity_relation_claims`)
- `description`
- `evidence_entry_ids` (UUID[]) — articles that support the link (GIN-indexed)
- `adjudication_verdict`, `adjudicated_at` — the adjudicate stage's outcome:
  - `corroborated` — promoted to confirmed
  - `coincidental` — demoted to possible, and never promoted again by co-occurrence
- `reviewer_kept_entry_ids` (UUID[]) — articles whose adjudicate review explicitly kept this link in apply mode, at or above the apply confidence floor. At `relationship_evidence_promote_count` distinct articles the link becomes confirmed and corroborated.
- `created_by` (FK, CASCADE)

Unique on `(source_type, source_id, target_type, target_id, relationship_type)`.

---

### 7. Dashboards & Reporting

**Tables:** `dashboards`, `dashboard_widgets`, `saved_searches`, `campaigns`, `campaign_entries`, `campaign_entities`, `campaign_saved_searches`, `campaign_sources`, `campaign_countries`, `campaign_sectors`, `intel_profiles`, `intel_reports`, `intel_report_versions`, `report_templates`

#### Dashboard
Table `dashboards`.
- `name`, `layout` (JSONB, react-grid-layout), `is_default`, `sort_order`, `created_by`

Has many `dashboard_widgets` (CASCADE).

#### DashboardWidget
Table `dashboard_widgets`.
- `dashboard_id` (FK, CASCADE)
- `widget_type` — for example `feed-activity`, `cve-severity`, `triage-queue-stats`
- `title`, `config` (JSONB)
- `position_x`, `position_y`, `width` (default 4), `height` (default 3)

#### SavedSearch
Table `saved_searches`.
- `name`, `display_name`, `query`, `filters` (JSONB), `created_by`

#### Campaign
Table `campaigns`: an analyst's case file for an operation or threat.
- `name`, `description`, `created_by`
- `status` (indexed, default `active`) — `active`, `monitoring`, `closed` or `historical`
- `tlp_marking` (default `TLP:GREEN`) — see [Enums & Constants](#enums--constants)
- `start_date`, `end_date` (Date), `tags` (Text[]), `metadata` (JSONB)

Its entries, entities, saved searches, sources, countries and sectors are deleted with it.

#### CampaignEntry
Table `campaign_entries`: primary key `(campaign_id, entry_id)`, both CASCADE.
- `added_by`, `notes`, `added_at`

#### CampaignEntity
Table `campaign_entities`.
- `campaign_id` (FK, CASCADE), `entity_type`, `entity_id`
- `role` (default `related`) — for example `primary`, `secondary`, `related`
- `added_by`, `added_at`

#### CampaignSavedSearch
Table `campaign_saved_searches`: a saved search linked to a campaign.
- `campaign_id`, `saved_search_id` (both FK, CASCADE)
- `auto_sync` (default true), `last_synced_at`, `entries_added`, `added_by`

#### CampaignSource
Table `campaign_sources`: a standing source of new articles that the campaign itself owns. A linked saved search belongs to whoever saved it: teammates can't see it, and it drifts when the campaign's subject changes. A campaign source avoids both problems.
- `campaign_id` (FK, CASCADE)
- `kind`:
  - `entity` — an actor, malware family, CVE or other entity. Every article that mentions it joins the campaign.
  - `story` — a story thread the campaign already holds part of, so later waves of the story join too.
  - `query` — a search-language query typed into the campaign. Everyone on the campaign can read, pause and edit it.
- `entity_type`, `ref_id` — the target; both NULL for a `query` source
- `query` — set only when `kind = 'query'`
- `label` — fixed when the source is added, so it still reads correctly after the target is renamed or merged. For a query it is the query text, cut to 120 characters.
- `auto_sync` (default true), `last_synced_at`, `entries_added`, `added_by` (SET NULL)

Constraints:
- `uq_campaign_sources_target` on `(campaign_id, kind, entity_type, ref_id)`
- `uq_campaign_sources_query` — a partial unique index on `(campaign_id, query) WHERE kind = 'query'`. PostgreSQL treats NULL `ref_id`s as distinct, so query rows need their own uniqueness.
- `ck_campaign_sources_shape` — a `query` row has a query and no `ref_id`; every other kind has a `ref_id` and no query

An entity source is refused for a type that has no entry junction, because it would never add anything. `GET /api/campaigns/source-options` returns the allowed types, and the pickers read it.

Every sync works out the full set of matching articles and adds only the ones the campaign doesn't have yet. So an article that later joins a story, gains an entity link or starts matching the query still arrives. The `campaign_saved_searches` sync only looks at new matches instead, so an article that gains a link later never arrives that way.

#### CampaignCountry
Table `campaign_countries`: primary key `(campaign_id, country_id)`, both CASCADE.
- `role` (default `target`) — `origin` or `target`; `added_at`

#### IntelProfile
Table `intel_profiles`: a named, reusable report scope. It saves a set of regions and industries, for example one customer, a client portfolio or a watch area. Analysts keep one profile per scope they report on. Exposure reports, standing briefs and threat-surface previews take a profile as input.
- `name` (unique), `description`
- `country_ids` (UUID[]) — regions, as country ids
- `sectors` (Text[]) — sector slugs
- `window_days` (default 90) — how far back a build looks
- `curation` (JSONB) — keep and drop decisions from the last exposure build, for example `{"kept": {"actors": [...], "malware": [...]}, "dropped": {...}}`, so a rebuild doesn't ask again
- `created_by` (SET NULL)

#### IntelReport
Table `intel_reports`.
- `title`, `summary`, `created_by` (SET NULL)
- `template_type` — `actor_profile`, `campaign_tracker`, `detection_report`, `exposure_report`, `flash_alert` or `landscape_report`
- `status` (indexed, default `draft`) — `draft`, `published` or `archived`
- `tlp_marking` (default `TLP:GREEN`)
- `content` (JSONB) — the report sections
- `version` (default 1), `entry_ids` (UUID[]), `entity_ids` (JSONB), `tags` (Text[]), `published_at`

Has many `intel_report_versions` (CASCADE).

#### IntelReportVersion
Table `intel_report_versions`.
- `report_id` (FK, CASCADE), `version`, `content` (JSONB), `change_description`
- `created_by` (FK → `users`, CASCADE)

#### ReportTemplate
Table `report_templates`.
- `name`, `description`
- `template_slug` (String 50, unique)
- `sections` (JSONB) — the section list
- `is_builtin`, `is_shared`, `created_by` (SET NULL)

---

### 8. Tags, Comments & Notes

**Tables:** `tags`, `entry_tags`, `comments`, `comment_mentions`, `notes`

#### Tag
Table `tags`. The tag list is shared: one row per name, with a color, a chip flag and a tooltip, managed in Tag Manager. Who sees a tag on an entry is per user (see EntryTag), unless the tag is global. A tag shown as a chip (`display_as_chip`) appears in the entry's badge row instead of the quiet meta line, with `description` as its tooltip.
- `name` (String 100, unique), `color` (default `#6B7280`)
- `display_as_chip` (default false), `description` (String 255)
- `is_global` (default false):
  - Global — one shared tag row per entry that everyone sees.
  - Personal — each user's tags are their own.

  Anyone can switch a tag in Tag Manager. Switching to global merges everyone's rows into one shared row per entry. Switching to personal gives the shared row to every human account. Both reindex the affected entries.
- `created_by` (audit only)

#### EntryTag
Table `entry_tags`: one tag on one entry.
- `entry_id`, `tag_id` (FK, CASCADE)
- `user_id` (FK, CASCADE, nullable) — who applied a personal tag, by hand, in bulk, through the copilot or through their automation rule. Only they see it. A global tag has one row per entry with `user_id` NULL.

Unique on `(entry_id, tag_id, user_id)` with NULLs not distinct.

Read tags through `app.services.entry_tags.visible_to` and write them through `ensure_assignment`, which picks the owner from the tag's scope. In Meilisearch, global tag names are in `tags`. Personal tags are in the filter-only field `user_tags` as `"<user_id>:<name>"`; the server strips that field from results and folds it into the viewer's own `tags` facet.

#### Comment
Table `comments`: a comment on any object, with replies.
- `user_id` (FK, CASCADE) — the author
- `commentable_type`, `commentable_id` (both indexed) — what it is attached to, for example a `detection_rule`
- `parent_id` (FK → `comments`, CASCADE) — the comment it replies to
- `content`

#### CommentMention
Table `comment_mentions`: primary key `(comment_id, mentioned_user_id)`, both CASCADE.

#### Note
Table `notes`: a free-form note, optionally on an entry.
- `created_by` (SET NULL), `entry_id` (FK, SET NULL — the note survives the entry)
- `title`, `content_markdown`, `content_html`, `tags` (Text[]), `is_pinned`

---

### 9. System & Configuration

**Tables:** `system_settings`, `themes`, `categories`, `intelligence_requirements`, `requirement_matches`, `glossary_terms`, `ai_providers`, `webhook_presets`, `shared_entries`, `telegram_channel_mentions`, `telegram_link_mentions`, `false_positive_records`, `tts_audio`

#### SystemSettings (Singleton)
Table `system_settings`: one row only (`id = 1`, enforced by the `singleton_row` CHECK constraint).
- `settings` (JSONB) — settings changed in the UI. `config.py` reads this before falling back to `.env`.
- `secrets` (JSONB) — encrypted secrets such as API keys

#### Theme
Table `themes`.
- `name`, `css_variables` (JSONB), `is_system` (built-in), `created_by` (SET NULL)

#### Category
Table `categories`: feed folders.
- `name`, `parent_id` (FK → `categories`, SET NULL), `position`
- `feed_defaults` (JSONB) — default settings for feeds in this category
- `created_by`

#### IntelligenceRequirement
Table `intelligence_requirements`: a PIR (priority intelligence requirement), a question the team needs answered. Matching entries are recorded in `requirement_matches`.
- `title`, `description`, `created_by`
- `priority` — for example `critical`, `high`, `medium`, `low`
- `status` (indexed, default `active`), `category` (default `operational`)
- `keywords` (Text[]), `linked_feed_ids` (UUID[])
- `linked_entities` (JSONB) — the entities it tracks: `{"threat_actors": [{"id", "name"}], "malware": [...], "cves": [...], "ttps": [...]}`
- `min_relevance` — the lowest relevance an automatic match may have; NULL keeps all
- `auto_match` (default true), `match_count`, `last_matched_at`, `expires_at`
- `fulfilled_by_report_id` (FK → `intel_reports`, SET NULL)

#### RequirementMatch
Table `requirement_matches`: primary key `(requirement_id, entry_id)`, both CASCADE.
- `match_type` — for example `keyword`, `entity`, `manual`
- `matched_on` — what matched
- `relevance` — `high`, `medium` or `low`; `matched_at`

#### GlossaryTerm
Table `glossary_terms`.
- `name` (String 200, unique), `category`, `maturity`
- `description`, `long_description`, `technologies`, `search_terms` (JSONB)
- `is_system` (seeded), `created_by`

#### AIProvider
Table `ai_providers`: one AI endpoint and its credentials.
- `name`
- `provider_type` — `claude`, `claude_code`, `ollama` or `openai_compatible`
- `base_url`, `models` (JSONB), `config` (JSONB), `is_active`
- `api_key_encrypted` — encrypted with the instance's `ENCRYPTION_KEY`, personal keys included
- `user_id` (FK, CASCADE, nullable):
  - NULL — an instance provider, used by site assignments and background work.
  - Set — a personal key. Only its owner's `user_ai_routes` point at it, it is never a site assignment, and only the owner and admins can see it (`backend/app/api/ai_providers.py:59`).
- `paused_until`, `paused_reason` — set automatically after a quota or rate-limit answer; a paused key is treated as unable to answer
- `last_tested_at`, `last_test_error` — the last connection test; a NULL error means it passed

Assignments and user routes are deleted with the provider. `ai_results` rows keep their `provider_name` and have `provider_id` set to NULL.

#### WebhookPreset
Table `webhook_presets`: saved webhook targets for automation actions.
- `name`, `preset_type` (default `webhook`), `url`, `payload` (a template), `headers`, `config` (JSONB), `created_by`

#### SharedEntry
Table `shared_entries`: a public share link for one entry.
- `entry_id` (FK, CASCADE), `token` (String 64, unique, random)
- `is_active` (default true), `expires_at`, `created_by` (SET NULL)

#### TelegramChannelMention
Table `telegram_channel_mentions`: Telegram channels mentioned across feeds, as possible new sources.
- `handle` (unique) — the normalized channel name; `display_handle`, `canonical_url`
- `primary_link_type` (default `channel`)
- `mention_count`, `distinct_feed_count`
- `feed_id` (FK, SET NULL) — set once the channel is added as a feed
- `dismissed_at`, `dismissed_by` (SET NULL), `notes`

#### TelegramLinkMention
Table `telegram_link_mentions`: each t.me link found, behind the channel totals. Unique on `(entry_id, url)`.
- `channel_id` (FK, CASCADE), `entry_id` (FK, CASCADE), `feed_id` (FK, SET NULL)
- `url`, `link_type`, `message_id`, `invite_hash`, `discovered_at`

#### TTSAudio
Table `tts_audio`: bookkeeping for read-aloud audio made by the Piper text-to-speech service. Each row is one cached MP3 on the `tts_media` volume.
- `cache_key` (String 64, primary key) — SHA-256 of source + ref id + text hash + voice; also the MP3 file name
- `source` — `entry` or `summary`; `ref_id` — the entry id or day key; `voice`
- `status` (default `pending`) — `pending`, `ready` or `error`
- `duration_seconds`, `byte_size`, `error`
- `last_accessed_at` — the eviction sweep removes the least recently used files
- `ttl_days` (nullable) — keep the file this many days after last access. NULL uses the `tts_cache_ttl_days` setting; share links pre-generate audio with 1.0 (about a day).

#### FalsePositiveRecord
Table `false_positive_records`: entities an analyst marked as wrong matches, fed back into AI prompts.
- `entity_type`, `entity_id` (both indexed), `entity_value`
- `source_entry_id` (FK, SET NULL), `reason`, `extraction_source`
- `marked_by` (FK → `users`, no ON DELETE)

---

### 10. Signal Engine & Pipeline Observability

**Tables:** `entry_signals`, `entry_signal_feedback`, `user_signal_weights`, `user_entity_watches`, `job_runs`, `entry_pipeline_runs`, `pipeline_plans`

The signal engine scores each entry so the Radar and Priority Queue can rank them. These tables also record what scheduled jobs and per-entry pipeline stages did. `prune_engine_tables` deletes `job_runs` and `entry_pipeline_runs` rows older than 30 days.

#### EntrySignal
Table `entry_signals`: one scored, explained signal per (entry, signal type). Rows are upserted, never appended. Unique on `(entry_id, signal_type)`.
- `entry_id` (FK, CASCADE)
- `signal_type` — grouped into five families (`SIGNAL_FAMILIES` in `app/intelligence/signals.py`):

  | Family | Signal types |
  |---|---|
  | novelty | `novel_entity`, `entity_resurgence`, `new_pairing`, `scoop` |
  | coverage | `source_convergence`, `under_reported`, `feed_echo` |
  | severity | `kev_added`, `epss_jump`, `epss_high`, `weaponized_poc`, `critical_cvss` |
  | interest | `pir_match`, `correlation_event` |
  | content | `detection_content`, `research_depth` |

- `score` (Float, 0–1), `explanation`, `payload` (JSONB)

The weighted sum goes to `entries.priority_raw`, its 0–10 placement to `entries.priority_score`, and the time to `entries.scored_at`.

#### EntrySignalFeedback
Table `entry_signal_feedback`: a user's thumbs up or down on an entry's Radar placement. Unique on `(entry_id, created_by)`.
- `entry_id`, `created_by` (both FK, CASCADE), `verdict` (SmallInteger)

#### UserSignalWeight
Table `user_signal_weights`: a per-analyst weight for each signal family, fitted nightly from that user's own thumbs by `fit_user_signal_weights` (04:35 UTC). It is applied when that user's Radar is read; the stored `priority_raw` and `priority_score` stay the same for everyone, so the personal weighting can be switched off at any time. See [engine.md](engine.md). Unique on `(user_id, family)`.
- `user_id` (FK, CASCADE), `family` — `novelty`, `coverage`, `severity`, `interest` or `content`
- `weight` (default 1.0, kept between 0.65 and 1.35)
- `up_votes`, `down_votes`, `sample_count` — the votes behind the fit

#### UserEntityWatch
Table `user_entity_watches`: a user's watch or mute on an entity. Watching raises an entry's priority when that user reads it; muting hides entries from their Radar and chips. Unique on `(created_by, entity_type, entity_id)`.
- `created_by` (FK, CASCADE)
- `entity_type` — `threat_actor`, `malware`, `cve`, `cwe`, `tool`, `vendor`, `product`, `country`, `sector`, `ransomware_victim` or `observable`
- `entity_id`, `mode` (`watch` or `mute`), `boost` (default 1.0)

#### JobRun
Table `job_runs`: one run of a scheduled Celery task (a `JOB_REGISTRY` job), written by Celery signal handlers. Indexed on `(task_name, started_at)`.
- `task_name`, `job_key`, `celery_task_id`
- `status` — `success`, `error` or `retry`
- `started_at`, `finished_at`, `duration_ms`, `error`
- `detail` (JSONB) — shortened `{args, kwargs, result}`

#### EntryPipelineRun
Table `entry_pipeline_runs`: one pipeline stage run for one entry. Indexed on `(entry_id, created_at)`.
- `entry_id` (FK, CASCADE), `stage`, `status`, `duration_ms`, `error`, `detail` (JSONB)

#### PipelinePlan
Table `pipeline_plans`: which pipeline stages run for a scope. A "Global default" row is seeded. For each stage the setting is taken from the feed's plan, then its category's plan, then the global plan, then the feed's own switches (`intel_extraction_mode`, `auto_extract_on_ingest`, `extract_detection_rules`).
- `name`, `scope_type` — `global`, `category` or `feed`; `scope_id` (NULL for global)
- `stages` (JSONB) — `{stage_name: {"enabled": bool, "config": {...}}}`
- `is_active`

Unique on `(scope_type, scope_id)` with NULLs not distinct, so there is only one global plan.

---

### 11. Story Threads

**Tables:** `entry_embeddings`, `story_threads`, `story_thread_entries`, `story_thread_beats`, `user_thread_states`

A story thread groups every article about one unfolding story, so a story reported twenty-three times is one row rather than twenty-three. Only `app.intelligence.story_threads` (grouping) and `app.services.thread_narrative` (the written summary, called the spine) write these tables. See [story-threads.md](story-threads.md).

These tables need the `vector` extension. The db image is built from `db/Dockerfile` (`postgres:16-alpine` plus pgvector 0.8.1).

#### EntryEmbedding
Table `entry_embeddings`: one vector per entry, in its own table so the busy `entries` table doesn't carry 1.5 KB per row.
- `entry_id` (primary key, FK → `entries`, CASCADE)
- `embedding` (`halfvec(768)`, 2 bytes per dimension)
- `model` (indexed), `content_hash` — hash of the exact text that was embedded, so an unchanged entry is never embedded again
- `threaded_checked_at` — when the thread sweeper last looked at this entry
- `verified_at` — when `content_hash` was last checked against the entry's current text. NULL sorts first in the re-check pass, so a re-sanitized article finds its way back through the sweeper.

An HNSW index (`halfvec_cosine_ops`) on `embedding` serves similarity search.

#### StoryThread
Table `story_threads`.
- `slug` (unique), `title`, `summary`
- `status` (default `open`) — `open`, `dormant` or `closed`
- `centroid` (`halfvec(768)`) — the average of its members
- `entry_count`, `source_count` (distinct outlets, not feed rows), `echo_count`
- `first_seen`, `last_seen`, `peak_at`
- `key_entities` (JSONB) — `[{entity_type, entity_id, label, count}]`
- `narrative_hash` (the member set the current spine was written from), `narrated_at`

Indexed on `(status, last_seen)`.

#### StoryThreadEntry
Table `story_thread_entries`: one article in a thread.
- `thread_id` (FK, CASCADE), `entry_id` (FK, CASCADE, **unique** — an article belongs to at most one story)
- `role` (default `beat`) — `origin`, `beat` or `echo`
- `similarity`, `duplicate_of_entry_id` (FK, SET NULL — for an echo, the article it repeats)
- `source_key` (the outlet's host, not the feed id), `added_at`

#### StoryThreadBeat
Table `story_thread_beats`: one wave of coverage. All beats are rewritten whenever the spine is rewritten.
- `thread_id` (FK, CASCADE), `position`, `occurred_at`
- `kind` (default `update`) — `first_disclosure`, `new_tradecraft`, `peak` or `update`
- `headline`, `body`, `lead_entry_id` (FK, SET NULL), `entry_ids` (JSONB), `collapsed_count`
- `is_ai` — false means the simple group-by-day fallback wrote it

#### UserThreadState
Table `user_thread_states`: unique on `(user_id, thread_id)`, both CASCADE.
- `last_opened_at` — what "N new" counts from

---

### 12. Narrative Themes

**Tables:** `narrative_briefings`, `narrative_theme_members`

The daily briefing sorts a day's articles into `### Theme` sections and links each article it cites. These tables save that grouping by parsing the briefing's markdown, which costs no extra AI call. See `backend/app/intelligence/narrative_themes.py`. Controlled by `narrative_themes_enabled` and `narrative_theme_gating` ([engine-settings.md](engine-settings.md#narrative-themes-and-actor-refresh-mode)).

#### NarrativeBriefing
Table `narrative_briefings`: one parsed daily briefing. Its existence tells "this entry has no theme" apart from "this day was never parsed".
- `day_key` (String 10, unique), `theme_count`, `cited_entry_count`, `parsed_at`

#### NarrativeThemeMember
Table `narrative_theme_members`: which articles the briefing put under which heading. Unique on `(day_key, entry_id, theme)`; also indexed on `(day_key, theme)`.
- `day_key`, `entry_id` (FK, CASCADE), `theme` (String 200)
- `section` (default `theme`) — `theme`, `notable`, `closer` or `tldr`. Only `theme` rows have a heading. An article the briefing couldn't place under a theme backs up nothing.

---

## Junction Tables

Junction tables link entries to entities (many to many). Each has a composite primary key on its two foreign keys (both CASCADE), with the entity-side column indexed for reverse lookups.

| Table | Links entries to | Extra columns |
|---|---|---|
| `entry_ttps` | TTPs | `confidence`, `source_text`, `paragraph_indices`, `observable_type`, `observable_value`, `telemetry` |
| `entry_cves` | CVEs | `paragraph_indices` |
| `entry_cwes` | CWEs | `confidence`, `source`, `paragraph_indices` |
| `entry_observables` | observables | see [EntryObservable](#entryobservable) |
| `entry_threat_actors` | threat actors | `confidence`, `source`, `matched_names`, `paragraph_indices` |
| `entry_malware` | malware families | `confidence`, `source`, `matched_names`, `paragraph_indices` |
| `entry_tools` | tools | `confidence`, `source`, `matched_names`, `paragraph_indices` |
| `entry_vendors` | vendors | `confidence`, `source`, `matched_names`, `paragraph_indices` |
| `entry_products` | products | `confidence`, `source`, `matched_names`, `paragraph_indices` |
| `entry_countries` | countries | `confidence`, `source`, `role`, `matched_names`, `paragraph_indices` |
| `entry_mitigations` | mitigations | `confidence`, `source`, `paragraph_indices` |
| `entry_sectors` | sectors | `confidence`, `source`, `role`, `paragraph_indices` |

All of them also carry `extracted_at`.

`entry_sectors` is the exception to the key pattern. Its primary key is `(entry_id, sector)`, where `sector` is the slug, and it also has a `sector_id` foreign key that is unique per entry. Only the one-pass AI analysis writes it (`store_sectors`). Sectors are never autolinked, so every row is a judgment, not a word match.

`entry_tags` has its own `id` key; see [EntryTag](#entrytag).

Other many-to-many tables:
- **`threat_actor_target_countries`** — countries an actor targets
- **`threat_actor_target_sectors`**, **`malware_target_sectors`** — "X targets sector S" claims. Each has a `source` (`rollup` from the entity's own articles, `enrichment`, `seed` or `analyst`, the default) and an `article_count` of evidence. The nightly `rollup-targeted-sectors` job changes only its own `rollup` rows.
- **`campaign_sectors`** — industries a campaign is scoped to
- **`campaign_countries`** — see [CampaignCountry](#campaigncountry)
- **`ttp_mitigations`** — mitigations for a TTP

---

## Enums & Constants

Fixed value sets are plain strings. The lists below come from code; where a migration also adds a CHECK constraint, it is noted.

| Column | Values | Defined in |
|---|---|---|
| `feeds.feed_type` | `rss`, `atom`, `youtube`, `podcast` (HTTP adapters); `reddit`, `github_releases`, `github_advisories`, `github_repo`, `nvd`, `mastodon`, `web_scraper`, `bluesky`, `telegram` (extended adapters) | `app/adapters/` |
| `feeds.intel_extraction_mode` | `full`, `selective`, `manual`, `none` | `schemas/feed.py` |
| `detection_rules.rule_type` | `sigma`, `splunk_spl`, `crowdstrike_ql`, `elastic_ql`, `kql`, `snort_suricata`, `yara`, `nuclei`, `panther` | `RULE_TYPE_PATTERN` in `schemas/intelligence.py`. The `ck_detection_rules_rule_type` CHECK lists only the first seven. |
| `campaigns.status` | `active`, `monitoring`, `closed`, `historical` | CHECK `ck_campaigns_status` |
| `cves.exploit_availability` | `none`, `poc`, `weaponized`, `active_exploitation` | CHECK `ck_cves_exploit_availability` |
| `entity_relationships.confidence` | `confirmed`, `probable`, `possible` | CHECK `ck_entity_relationships_confidence` |
| `vendors.vendor_type` | `software`, `hardware`, `cloud`, `security`, `networking`, `semiconductor`, `telecommunications`, `other` | `VENDOR_TYPES` in `models/vendor.py` |
| `products.product_type` | `os`, `application`, `security_tool`, `network_device`, `cloud_service`, `database`, `firmware`, `library`, `other` | `PRODUCT_TYPES` in `models/product.py` |
| `tools.tool_type` | `c2_framework`, `credential_access`, `lateral_movement`, `reconnaissance`, `exploitation`, `persistence`, `defense_evasion`, `lolbas`, `framework`, `phishing_kit`, `tunneling`, `remote_access`, `ai_model`, `defensive`, `observability`, `cloud`, `identity`, `dev_tool`, `service`, `software`, `other` | `TOOL_TYPES` in `models/tool.py` |
| TLP markings (`campaigns`, `intel_reports`) | `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, `TLP:RED`. `TLP:WHITE` is accepted on input and stored as `TLP:CLEAR`. | `app/schemas/tlp.py` |
| `users.role` | `admin`, `user`, `system` | CHECK `ck_users_role` |
| `enrichment_sources.trigger_mode` | `auto`, `manual` | `EnrichmentSourceUpdate` in `schemas/enrichment.py` |
| `enrichment_sources.health_status` | `healthy`, `degraded`, `down`, `unknown` | |

TLP (Traffic Light Protocol) marks how widely a report may be shared.

---

## Unique Constraints & Deduplication

Each table's section lists its unique keys. These are the ones that prevent duplicate data:

- **`entries(feed_id, guid)`** — the same item is never stored twice for one feed. Duplicates across feeds are caught by `entries.content_hash` before insert (no constraint).
- **`feeds(url)`** — one feed per URL
- **Entity names** — `threat_actors(name)`, `malware_families(name)`, `tools(name)`, `vendors(name)`, `products(name)`, `countries(name)`, `sectors(slug)`, `sectors(name)`
- **Catalog ids** — `cves(cve_id)`, `ttps(technique_id)`, `cwes(cwe_id)`, `mitigations(mitre_id)`
- **`observables(kind, value)`** — one ledger row per indicator
- **`victim_disclosures(source, guid)`** — one leak-site posting per source id
- **`cve_affected(cve_id, cpe_vendor, cpe_product)`**, **`cve_weaknesses(cve_id, cwe_ref)`**
- **`entity_relationships(source_type, source_id, target_type, target_id, relationship_type)`** — one link per direction and verb
- **`entity_field_claims(claim_key)`** — repeated claims update one row
- **`entry_signals(entry_id, signal_type)`** — signals are upserted
- **`ai_analysis_requests(entry_id)`** — one analysis request per entry
- **`story_thread_entries(entry_id)`** — an article is in at most one story
- **`entity_reclassify_tombstones(source_type, normalized_name)`**, **`entity_name_denylist(entity_type, normalized_name)`**, **`pending_autolink_matches(entry_id, entity_type, entity_id)`**, **`entity_alias_index(entity_type, entity_id, normalized)`**

Ransomware victims are the one name-keyed entity without a unique name; the resolver matches on `normalized_name` and `domain` instead.

---

## Indexing Strategy

Every foreign key and most filter columns have a plain btree index, declared in the models with `index=True` or `__table_args__`. These indexes are worth knowing about:

| Index | Why it exists |
|---|---|
| `entries.priority_raw` | Radar and Priority Queue ordering |
| `entries.priority_score`, `ix_entries_published_priority (published_at, priority_score)` | score threshold filters |
| `entries (content_hash, created_at)` | cross-feed duplicate check |
| `user_entry_states (user_id, is_read)`, `(user_id, is_starred)`, `(user_id, is_bookmarked)` | unread, starred and bookmarked lists |
| `cves.is_kev`, `cves.epss_score` | exploited-first CVE sorting |
| `ttps.parent_technique_id`, `ttps.matrix_domain` | ATT&CK catalog navigation |
| `entity_relationships.evidence_entry_ids` (GIN) | the `new_pairing` signal's lookup |
| `normalized_name` (GIN, `gin_trgm_ops`) on the six name tables, and `entity_alias_index.normalized` | fuzzy name matching |
| `entry_embeddings.embedding` (HNSW, `halfvec_cosine_ops`) | similar-article search |
| `entry_signals (signal_type, created_at)` | signal timelines |
| `job_runs (task_name, started_at)` | job history |
| `ai_results (target_type, target_id, task_id, is_current)` | latest result per target |

Partial unique indexes: `uq_user_ai_routes_task`, `uq_user_ai_routes_default` and `uq_campaign_sources_query` (see their sections).

The GIN, HNSW and `ix_entries_published_priority` indexes are created by migrations only. The models don't declare them, so the test schema doesn't have them.

### Full-Text Search Indexes

Text search runs in Meilisearch, not PostgreSQL (`app/services/meilisearch_client.py`):
- **`entries`** — searches `title`, `content_text`, `summary`, `author`, `feed_title`, `tags`
- **`rules`** — detection rules: rule metadata plus `rule_content`
- **`entities_<type>`** — one index each for `cve`, `ttp`, `threat_actor`, `malware`, `country`, `sector`, `cwe`, `mitigation`, `observable` and `tool`

---

## JSONB Columns

JSONB holds data whose shape changes often or differs by type: adapter settings, raw API responses, AI output, per-type metadata and layouts. The column lists above mark each JSONB column.

None of them has a GIN index. If you need to query inside one with containment (`@>`), add the index in a migration:

```sql
CREATE INDEX ix_feeds_adapter_config_gin ON feeds USING gin (adapter_config);
```

---

## Migration System

### Alembic Setup

- **Migrations:** `backend/alembic/versions/`
- **Config:** `backend/alembic.ini`; `backend/alembic/env.py` reads the database URL from app settings
- **Startup:** the api container runs `alembic upgrade head` from `backend/entrypoint.sh` when `RUN_MIGRATIONS=true`

The history has a single head. CI fails if there is more than one, and it also tests a fresh `upgrade head` and a `downgrade -1` followed by re-applying it. Find the current head with `alembic heads`.

### Migration Naming

File names are `<revision>_<description>.py`. Older files use a short number (`016_glossary_terms.py`); newer ones use a 12-character revision id (`h5c6d7e8f9a0_feed_visible_to_visitors.py`). The docstring at the top of each file explains the change. Read it before changing anything nearby.

### Writing a New Migration

Run these from `backend/`, against a database you can throw away.

**1. Generate a draft.**

```bash
# from backend/
alembic revision --autogenerate -m "short_description"
```

Autogenerate compares the models with the database and writes a draft file.

**2. Review it.** Open the new file in `backend/alembic/versions/` and check:
- `upgrade()` and `downgrade()` both exist and undo each other
- column types, constraints, indexes and `ondelete` behavior match the model
- nothing unrelated was picked up. Autogenerate does not know about the migration-only indexes listed above and may try to drop them.

**3. Edit by hand when needed.** Data changes and raw SQL go in by hand:

```python
def upgrade() -> None:
    op.add_column("entries", sa.Column("new_field", sa.String(255)))
    op.create_index("ix_entries_new_field", "entries", ["new_field"])


def downgrade() -> None:
    op.drop_index("ix_entries_new_field", table_name="entries")
    op.drop_column("entries", "new_field")
```

**4. Test it** the way CI does:

```bash
# from backend/, against a scratch database
alembic upgrade head
alembic downgrade -1
alembic upgrade head
```

Don't run these against a dev database you care about. A downgrade drops data.

### Multiple Heads & Merging

If two branches each add a migration, there will be two heads:

```bash
# from backend/
alembic heads
alembic merge -m "merge_feature_a_and_feature_b" <head_a> <head_b>
```

The merge file has a `down_revision` pointing at both parents.

### Migration Status

```bash
# from backend/
alembic current   # the revision the database is at
alembic history   # every migration
alembic heads     # branch tips
```

---

## Test Database Pattern

The backend tests use their own database: the main database name plus `_test` (for example `intelfeed_test`). The name can have two more suffixes:
- `PYTEST_DB_SUFFIX` — set it so two test sessions in one checkout don't share a database
- the xdist worker name — added by `pytest -n auto`, so each worker gets its own

`backend/tests/conftest.py` sets the database up like this:
1. Once per session it creates the database if needed, then drops and recreates the `public` schema.
2. It installs the `vector` extension and builds every table with `Base.metadata.create_all`. Migrations do not run, so migration-only indexes and CHECK constraints are missing from the test schema.
3. It seeds the 21 sector rows.
4. Each test runs inside a transaction that is rolled back afterwards. A `commit()` in the code under test becomes a savepoint release.
5. Tests marked `@pytest.mark.committed_db` commit for real (to act like Celery workers with their own connections). After them, every table is truncated and the sectors are seeded again.

To check a migration, use `alembic upgrade head` against a scratch database, as above.

---

## File References

- Models: `backend/app/models/`
- Entity-type slugs: `backend/app/entity_types.py`
- Migrations: `backend/alembic/versions/`
- Alembic config: `backend/alembic.ini`, `backend/alembic/env.py`
- Test fixtures: `backend/tests/conftest.py`
