# Scripts

Everything operational lives here, in one tree, grouped by what it does.

Most scripts use the application's own models and database session, so they run
**inside the api container**. `./scripts` is bind-mounted to `/app/scripts`
(see `docker-compose.dev.yml` / `docker-compose.prod.yml`), the same way `./docs`
is — the image itself only carries `./backend`.

```bash
docker compose -f docker-compose.dev.yml exec api python scripts/<folder>/<script>.py
```

`ops/`, `dev/` and `build_apk.sh` are the exception: they drive Docker, SSH,
the API or the Android SDK from outside, so run those from the repo root on
your own machine.

Every script's docstring carries its exact invocation and flags. Anything that
writes takes `--dry-run` (or `--apply`), so you can see the damage first.

---

## `seed/` — reference data for a fresh install

A new install isn't quite empty — migrations load the countries and a baseline of
ATT&CK techniques — but it has no CWE catalog, vendors, products, CPE curation or
actor attribution, so most of what the autolinker matches against is missing and
entries ingest without linking to it. These populate the reference entities it
matches against. Run them in this order; each is idempotent, so re-running later just
fills gaps.

| Order | Script | Seeds |
| --- | --- | --- |
| 1 | `seed_countries.py` | Every UN-recognized country, with ISO codes and regions. |
| 2 | `seed_country_aliases.py` | Demonyms and adjective forms ("Iranian" → Iran) so prose actually matches. |
| 3 | `seed_sectors.py` | The 21 victim-sector entities (closed vocabulary, deterministic ids). Also refreshes aliases/descriptions on re-run. |
| 4 | `seed_mitre_attack.py` | The full MITRE ATT&CK catalog (Enterprise + Mobile + ICS) from the official STIX bundles: techniques, tactics, platforms, mitigations. |
| 5 | `seed_cwe_catalog.py` | The full MITRE CWE catalog (969 weaknesses + 422 categories) from `cwec_latest.xml`: abstraction ladder, ChildOf parents, mapping guidance, consequences, mitigations. Must run before `backfill_cve_weaknesses.py` so NVD refs resolve. |
| 6 | `seed_vendors_products.py` | 107 vendors and 862 products, with Wikipedia-sourced descriptions. |
| 7 | `seed_vendor_descriptions.py` | Re-fetch and reformat those descriptions as markdown; fills in any the first pass missed. |
| 8 | `seed_cpe_names.py` | CPE curation lists so NVD's CPE pairs resolve onto your vendors and products. |
| 9 | `seed_actor_countries.py` | Origin-country attribution for ~530 threat actors with high-confidence public attribution. |
| 10 | `seed_entity_attributes.py` | Motivation on threat actors, controlled-vocabulary type on malware families. |
| — | **`seed_all.py`** | **Runs all ten above, in this order.** |
| — | `seed_feeds.py` | Curated starter feeds, from the OPML packs in `backend/app/feed_packs/` — the same ones the onboarding wizard offers. Defaults to the 37-feed `core` pack; `--list` / `--packs` / `--all` / `--dry-run`. Deliberately **not** in `seed_all.py`: that is reference data, identical on every install, while which sources an instance polls is editorial. |
| — | `seed_log_type_aliases.py` | Flattens the free-text `log_types` on telemetry sources onto the canonical behaviour axis in `app/services/detection_coverage.py`, writing `log_type_alias` and `telemetry_sources.log_types_canonical` so detection-coverage matching compares like with like. A deterministic table plus keyword rules, not a model call, so it is re-runnable: edit the table, run again. Not in `seed_all.py`. `--dry-run`. |

`seed_all.py` runs all ten in order — that is the whole first-boot step:

```bash
D="docker compose -f docker-compose.dev.yml exec api python"
$D scripts/seed/seed_all.py --dry-run    # preview every step, write nothing
$D scripts/seed/seed_all.py              # seed everything
```

All ten seeders support `--dry-run`, so the preview is real rather than just a
plan, and takes about 15 seconds: the Wikipedia steps skip their network lookups
when dry, while the ATT&CK and CWE steps still download their catalogs because
that is the only way to know what would change.

It runs each seeder as a subprocess, so one failure can't poison another's
database session, and everything completed before the failure stays committed.
On a failure it stops, marks the rest skipped, and prints the resume command:

```bash
$D scripts/seed/seed_all.py --only attribution,attributes   # retry just those
$D scripts/seed/seed_all.py --offline                       # skip the downloads
$D scripts/seed/seed_all.py --list                          # step names
```

| Flag | Effect |
| --- | --- |
| `--dry-run` | Run every step in its own dry-run mode. Nothing is written — verified by comparing database state before and after. |
| `--offline` | Skip `attack`, `cwe`, `vendors`, `descriptions` — the four that download. |
| `--only` / `--skip` | Comma-separated step names, for resuming or re-running a part. |
| `--overwrite` | Let `attribution` and `attributes` replace existing values instead of only filling blanks. |
| `--continue-on-error` | Keep going after a failure instead of stopping. |

Or run any step on its own: `$D scripts/seed/seed_countries.py`.

Steps 9 and 10 only enrich actors and malware that already exist, so they are
worth re-running once the feeds have been ingesting for a while.
`seed_mitre_attack.py`, `seed_cwe_catalog.py` and the vendor scripts reach out to the network (MITRE's
STIX bundles, Wikipedia) and take a few minutes each.

## `maintenance/` — repeatable repair

Reconciliation passes for when data drifts. All idempotent and safe to re-run.
None are scheduled — the Celery beat schedule covers routine upkeep, and these
are for fixing something by hand.

| Script | Fixes |
| --- | --- |
| `backfill_cve_weaknesses.py` | Parses the NVD `weaknesses` block on every stored CVE into `cve_weaknesses` rows. Run after `seed_cwe_catalog.py`. |
| `backfill_entry_cwes.py` | Scans existing entries for `CWE-n` ids and links them, so weaknesses have article counts without waiting for re-ingest. |
| `backfill_field_claims.py` | Seeds `entity_field_claims` from provenance already on record — description history, enrichment results, and the article AI-extracted entities were minted from. Fields whose origin isn't recoverable stay unsourced on purpose. `--dry-run` / `--only`. |
| `backfill_narrative_themes.py` | Parses every cached daily briefing into the `### Theme` groupings it already made, so the co-occurrence promotion gate can tell repeat coverage from one reporting wave. Reads stored markdown only — no AI call. The nightly job covers 14 days; this covers the whole history. `--dry-run` / `--force` / `--days`. |
| `enrich_cves.py` | Backfills EPSS scores, CISA KEV flags, and NVD metadata on CVEs. Batched and resumable, with `--phase epss` / `--phase nvd`. |
| `normalize_vocabularies.py` | Folds `mitre_tactics`, `motivation`, `platforms` and `country` onto one spelling each, so a search facet stops listing `Persistence` and `persistence` as separate values. One-shot catch-up for rows written before the model validators landed; unrecognized values are kept and reported, not dropped, except the `platforms` entries that name an architecture or a language runtime, which are pruned and listed. `--dry-run`. |
| `backfill_targeted_sectors.py` | One-shot: folds the legacy free-text `targeted_sectors` arrays on actors and malware into the target-sector junctions (`source=seed`), optionally rehomes values that name a country onto `threat_actor_target_countries` (`--rehome-countries`), rebuilds the array cache, and writes a CSV of every distinct value and its decision (`--report`). Run in prod after reading the `--dry-run` report. |
| `audit_feed_packs.py` | Re-probes every source in the shipped starter feed packs: newest item date for RSS-ish feeds, `pushed_at` and archived for GitHub repos, liveness for the rest. Run it before a release and prune what it calls DEAD; WARN means bot protection or rate limiting, so look before cutting. Reads no database and writes nothing, so it runs on a laptop — set `GITHUB_TOKEN` to lift GitHub's 60/hour cap. Exits non-zero only on a confirmed dead source. |
| `prune_setting_overrides.py` | Drops `system_settings` overrides that no longer do anything: values equal to the shipped default (which would otherwise pin the install to a stale copy when the default moves), keys no setting reads any more, and `_job_schedule_overrides` entries for jobs that were removed or that repeat the job's default. Never touches secrets, the public-RSS token, the default theme, or any override that differs. `--dry-run` to list, `--json` for machines. Run it after a release that moved defaults. |
| `merge_same_url_entries.py` | Collapses copies of one article that a feed stored under churning guids (CrowdStrike's random `?p=` guids). Per feed, groups rows by normalised link + title + enclosure, keeps the earliest, moves every reference (tags, notes, story-thread membership, read/starred state, entity links, AI results, report and relationship evidence ids — read from the catalog's foreign keys to `entries.id`) onto it, deletes the copies and drops them from Meilisearch. Podcast episodes merge only when title and audio match. Dry run by default; `--apply`, `--feed <id or title>` (repeatable; default the five feeds the 2026-10 feed audit found), `--all-feeds`, `--ignore-title`. |
| `reconcile_search_index.py` | Deletes Meilisearch documents whose feed no longer exists, after a cascade cleanup missed them. |
| `reindex_entry_tags.py` | Re-pushes entries' `tags` / `user_tags` fields to the Meilisearch entries index. Run once with `--all` after deploying migration `y6q8s0u2w4y6` (per-user tag assignments), once the rebuilt api container is healthy: until then the index still lists pre-migration shared tags to everyone. `--dry-run` counts; without `--all` only entries that currently carry a tag row are touched. Safe to re-run. |
| `revalidate_wikipedia.py` | Clears Wikipedia enrichment on entities whose stored article title doesn't match the entity, so they re-enrich against the right article. |
| `refetch_truncated_entries.py` | Re-fetches full text for entries that stored a "continue reading" stub. |
| `refix_entry_image_urls.py` | Re-derives lead images for entries whose image is a tracking pixel or a relative URL. |
| `resanitize_entries.py` | Re-runs HTML sanitization to repair broken image-proxy URLs. |
| `rescan_observable_candidates.py` | Rebuilds the candidate tier under today's scanner rules. Default purge drops regex-origin host-kind candidates; `--purge-all-scan` drops every scan-origin candidate (AI stagings stay); `--purge-invalid` drops candidates of any origin that today's validators reject (stale rows that could never be promoted); `--rescan-days N` / `--rescan-all` re-run the observables scan. `--dry-run`. Dev 2026-10-01: 7,115 distinct candidates → purge all + rescan all after the queue review. |
| `replay_ai_observables.py` | Backfills the ledger from stored `entry_analysis` results through the same `apply_ai_observables` door ingest uses (identical validators and per-kind capture list) and re-asserts the AI's relationship claims — the step after flipping `observables_ai_capture_mode` to `capture`, so earlier judgments land with role, evidence and attribution instead of being promoted blind. `--since`, `--mode`, `--kinds`, `--dry-run`. Never fires automation rules. |
| `reanalyze_truncated_entries.py` | Queues a fresh one-pass analysis (`run_entry_analysis_task`, the `ai` queue) for research articles whose body exceeds the old prompt cap *and* carries an indicator section — the analyses that never saw their IOC tables before the indicator-aware window. `--days`, `--min-chars` (default 15000, the old cap), `--limit`, `--feed-like`, `--dry-run`. |
| `backfill_feed_observable_roles.py` | One-time: gives existing indicator-feed rows (`ioc_list`, `role = NULL`) the role their feed file implies — C2 lists → `c2`, scanner lists → `scanning`, phish-sim → `phishing`; dual-use VPN/RMM/KVM files none. Fill-only. `--dry-run`. |
| `backfill_publisher_iocs.py` | Runs the publisher IOC-file door over corpus articles that link an allow-listed indicator repo (Cisco Talos, Bitdefender, Datadog): fetches, parses, writes rows with roles, sighted on the article. `--limit`, `--dry-run`. |
| `audit_ai_observables.py` | Dumps every indicator the one-pass analysis AI judged (`iocs` / `scripts` arrays of current `entry_analysis` results, plus AI-origin staged candidates) to a CSV with role, evidence and a `verdict` column to label by hand — the precision record that gates `observables_ai_capture_mode`. `--since` / `--sample N` writes a stratified sample too. |
| `rematch_requirements.py` | Re-matches every entry against intelligence requirements using whole-word matching. |
| `purge_invalid_relationships.py` | Deletes or reorients entity relationships that violate the semantic relationship matrix. Dry-run by default. |
| `backfill_rule_conversions.py` | Promotes `metadata.rule_conversions` blobs into real sibling detection rules on `derived_from`, then indexes them. `--dry-run` to preview; `--prune` to strip the blob afterwards. |
| `fold_cross_type_twins.py` | Folds same-name entities living under two types ("Qilin" the actor vs "Qilin" the malware) into one survivor via reclassify, writing tombstones so extraction can't resurrect them. Dry-run writes a review CSV to `scripts/out/`; `--apply --plan <csv>` executes the reviewed decisions; `--replay-holds` recovers entry links that enforced cross-type holds dropped before the resolver learned to link them. Run `reconcile_search_index.py` afterwards. |
| `strip_cross_type_aliases.py` | Removes aliases that duplicate another entity type's canonical name (malware DEADWOOD carrying the actor name "Agrius"), and purges the entry links that alias alone created. Analyst-sourced links are never touched. Dry-run writes a review CSV; `--report-ambiguous` lists alias-vs-alias collisions it refuses to guess at. |
| `purge_cve_named_entities.py` | Removes CVE identifiers from the actor/malware/tool/vendor/product catalogs — both entities *named* after a CVE (a malware family called "CVE-2026-55193") and legitimate entities carrying one as an *alias* (Spring4Shell aliased CVE-2022-22965). Either way the id sits in the autolinker vocabulary twice, so every mention links to the CVE and to the impostor. Name rows re-link their entries to the real CVE entity before deletion (rows with no CVE row default to `skip`); alias rows purge only the links that alias alone produced. Dry-run writes a review CSV; `--apply --plan <csv>` executes it. Run `reconcile_search_index.py` afterwards. |
| `backfill_observables.py` | Fills the observables ledger from the two pre-curated sources only — `EntryTTP.observable_value` rows and `ioc_list` feed bodies. There is deliberately no regex sweep over article prose. Idempotent on `(kind, value)`. `--dry-run` / `--only ttp\|ioc_list`. |
| `purge_junk_tools.py` | Cleans the tool catalog in three stages — reclassify tool rows already claimed by a product or vendor, purge rows with no evidence anyone wielded them (denylisted so extraction can't re-mint them), delete unlinked orphans. Two-step: `--dry-run --out FILE` writes a review CSV, `--apply --plan FILE` executes it. Run the creation-side extraction fixes first or the catalog refills. |
| `rebuild_search_indexes.py` | Rebuilds every Meilisearch index from the database — the `entries` index from scratch, plus the entity and rule indexes. Run it after restoring a dump from another environment (`ops/sync_prod_to_dev.sh` does). Runs inline, so the exit code says whether search works. `--user` (whose read/star state to bake in), `--entries-only`, `--entities-only`. |
| `sync_denylist.py` | Moves the do-not-recreate list between environments: the `entity_name_denylist` rows plus the names in the `autolinker_false_positive_names` setting. `--export FILE` from the instance you curated in, `--import FILE` into the other. Import is additive and never deletes. `--dry-run`. |

## `telegram/` — channel ingestion setup

Telegram is the one adapter needing out-of-band setup. Both scripts are
interactive, so they need `exec -it`, not plain `exec`.

| Script | What it does |
| --- | --- |
| `telegram_login.py` | Bootstraps a Telegram session file. Run once per instance; prompts for phone number, SMS code, and 2FA password. `--session NAME` for multiple identities. |
| `telegram_join.py` | Joins a private channel from an invite link, so the adapter can then reference it by id or handle. |

```bash
docker compose -f docker-compose.dev.yml exec -it api python scripts/telegram/telegram_login.py
```

Also needs `TELEGRAM_API_ID` and `TELEGRAM_API_HASH` in `.env`.

## `ops/` — running a deployment  *(host-side)*

| Script | What it does |
| --- | --- |
| `backup.sh` | `pg_dump` + gzip into `./backups/` with 7-day retention, plus a Meilisearch snapshot. Optional GPG encryption via `BACKUP_ENCRYPT_KEY`. Suitable for cron. |
| `restore.sh` | Restore a database from a compressed (or encrypted) backup produced by `backup.sh`. |
| `deploy.sh` | Push `main`, run `update.sh` on the production host over SSH, then verify the containers came back healthy. |
| `sync_prod_to_dev.sh` | Dump the production database over SSH and restore it into the local dev stack, so you develop against real data. **Destroys the local dev database.** |
| `cf-origin-lockdown.sh` | Restrict inbound 80/443 on the production host to Cloudflare's published edge ranges, closing the origin-bypass hole. Idempotent; never touches port 22. |
| `version.sh` | **Sourced, not run.** Exports `APP_VERSION` / `GIT_SHA` / `BUILD_TIME` from the checkout so `docker compose build` can stamp the api and frontend images. `update.sh` sources it on every deploy; do the same for a hand-rolled build you want stamped. |
| `pace_reanalyze.sh` | Runs on the prod host (`nohup scripts/ops/pace_reanalyze.sh &`): every 15 min, if the `ai` queue holds fewer than 10 messages, queues 8 forced `entry_analysis` re-runs for long research articles (>15k chars with an indicator section, last 90 days) that have no result newer than the 2026-10-02 prompt fixes; exits when none remain. Logs to `logs/reanalyze-pace.log`. Keeps a backfill from starving live analysis behind it on the concurrency-1 AI worker. |

`deploy.sh` and `sync_prod_to_dev.sh` need your production host:

```bash
export INTELFEED_PROD_HOST=user@prod.example.com   # required
export INTELFEED_PROD_DIR=intelfeed                # optional, checkout path on that host

./scripts/ops/backup.sh
./scripts/ops/restore.sh backups/intelfeed_20260828_020000.sql.gz
./scripts/ops/deploy.sh
```

## `build_apk.sh` — Android app build  *(host-side)*

Bumps `android/version.properties` (build number +1, `1.x` → `1.x+1`, or
`2.0` with `--major`), runs the unit tests, builds the debug APK
(`android/app/build/outputs/apk/debug/app-debug.apk`) and installs it on every
connected device with data kept; with no device it tells you to plug a phone
in and rerun with `--install`. A failed build restores the old version.
Merging the bump to `main` makes CI publish the release `android-v<version>`;
see [docs/android-app.md](../docs/android-app.md). Needs JDK 17, the Android
SDK and `adb`.

```bash
scripts/build_apk.sh            # new minor version
scripts/build_apk.sh --major    # new major version
scripts/build_apk.sh --install  # phone plugged in after the build
```

## `dev/` — developer tooling  *(host-side)*

| Script | What it does |
| --- | --- |
| `sync_skill_clis.py` | Regenerate both skill CLIs' `TOOLS` and `WRITE_TOOLS` blocks from the live backend tool registry, which is the single source of truth. `--check` reports drift without writing (exit 1 if out of sync). |
| `check_doc_refs.py` | Checks the `path/to/file.py:line` references in the docs against the code and reports the ones whose line number no longer lands on the symbol beside them. `--fix` repairs the unambiguous ones; the rest are left for a human. Exits 1 on drift, so it can gate a pre-release check. |
| `check_doc_links.py` | Checks the relative links, `#anchors` and images between the Markdown docs: the target file exists, the heading the fragment names exists (GitHub's slug rules, which the in-app docs reader also uses), the image path resolves. External URLs and in-app routes such as `/documentation` are skipped. Exits 1 if anything is broken. |
| `webhook_proxy.py` | TCP proxy so containers on Docker Desktop for Mac can reach LAN hosts via `host.docker.internal`, for testing webhook deliveries. |
| `build_observable_fixture.py` | *(runs in the api container)* Seeds one `backend/tests/fixtures/observables/cases/<slug>.json` case from a corpus article: `expected` from the article's own IOC section (with the publisher's role text as `note`), prose candidates to `optional`, reference-domain links to `must_not`. Hand-review before committing. |
| `eval_observable_extraction.py` | *(runs in the api container)* Scores the one-pass analysis's observables judgment against the fixture — per-kind precision/recall, `must_not` hits, attribution-edge recall — rendering the prompt exactly as ingest does. `--offline` scores the stored current results instead of calling the model; nothing is persisted unless `--store`. Writes a markdown report. |

```bash
INTELFEED_API_URL=http://localhost:8000 python3 scripts/dev/sync_skill_clis.py --check
python3 scripts/dev/webhook_proxy.py 10138 192.0.2.10 80
python3 scripts/dev/check_doc_refs.py          # add --fix to repair what it can
python3 scripts/dev/check_doc_links.py         # broken doc links and anchors
```

## `archive/` — completed one-shots

Backfills and data fixes already run to completion against a production
database. They are kept because they document what changed and how, and because
a database restored from an old dump may still need them. Nothing here is part
of a normal install — read the docstring for what it assumes before running any
of it.

| Script | What it did |
| --- | --- |
| `fix_mistyped_entities_2026_09.py` | Undid the three cross-type folds that merged unrelated things (Medusa the Kali brute-forcer vs the ransomware, Sigma the rule format vs the malware, a Storm-1175 tombstone pointing at malware), and gave the NetSupport entities their real names — the legitimate product had been filed as malware and its abuse as a tool. Run against prod 2026-09-14. |
| `backfill_og_images.py` | Fetched `og:image` for entries that had no `image_url`. |
| `backfill_ransomware_victims.py` | Backfilled years of `victim_disclosures` from ransomware.live's per-year history so the Landscape dashboard had trend data on day one. Same resolver and dedup path as the live sync; idempotent on `(source, guid)`. `--start-year`. |
| `backfill_rule_metadata.py` | Re-extracted metadata from each rule's content into `mitre_tactics` and `source_ttps`, normalizing tactic names to snake_case. |
| `backfill_rule_provenance.py` | Filled `license`, `upstream_updated_at`, `references` and `source_products` on rules imported before those provenance fields existed. Idempotent. |
| `backfill_type_vocab.py` | Coerced free-text `tool_type` / `malware_type` onto the controlled vocabulary — 1,544 of 1,705 prod tool rows had free text across 1,040 distinct values — keeping the originals in `metadata_`, and re-indexed the changed rows. The entity-creation guardrails coerce new writes; this fixed the stock. |
| `fix_ttp_000_subtechniques.py` | Merged invalid `.000` TTP sub-techniques into their parent technique. TTP extraction rejects them at the source, so it only matters for a database that predates that check. Idempotent; `--dry-run`. |
| `guardrails_prod_chores_2026_08.py` | One-shot prod data chores from the entity-guardrails follow-up (2026-08-16): merged a leetspeak duplicate malware (`n0_esc4pe` → `NoEscape`) and stripped a generic AV-detection alias that cross-linked unrelated entities. Read the docstring for the rest. |
| `import_profiles.py` | Imported ~3,390 legacy markdown intelligence profiles (YAML frontmatter, Obsidian wikilinks) into actor, malware, tool and country entities as descriptions. Alias-aware matching; nothing is written without `--apply`. |
