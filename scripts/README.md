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
| `enrich_cves.py` | Backfills EPSS scores, CISA KEV flags, and NVD metadata on CVEs. Batched and resumable, with `--phase epss` / `--phase nvd`. |
| `audit_feed_packs.py` | Re-probes every source in the shipped starter feed packs: newest item date for RSS-ish feeds, `pushed_at` and archived for GitHub repos, liveness for the rest. Run it before a release and prune what it calls DEAD; WARN means bot protection or rate limiting, so look before cutting. Reads no database and writes nothing, so it runs on a laptop — set `GITHUB_TOKEN` to lift GitHub's 60/hour cap. Exits non-zero only on a confirmed dead source. |
| `prune_setting_overrides.py` | Drops `system_settings` overrides that no longer do anything: values equal to the shipped default (which would otherwise pin the install to a stale copy when the default moves), keys no setting reads any more, and `_job_schedule_overrides` entries for jobs that were removed or that repeat the job's default. Never touches secrets, the public-RSS token, the default theme, or any override that differs. `--dry-run` to list, `--json` for machines. Run it after a release that moved defaults. |
| `reconcile_search_index.py` | Deletes Meilisearch documents whose feed no longer exists, after a cascade cleanup missed them. |
| `refetch_truncated_entries.py` | Re-fetches full text for entries that stored a "continue reading" stub. |
| `resanitize_entries.py` | Re-runs HTML sanitization to repair broken image-proxy URLs. |
| `rescan_observable_candidates.py` | Rebuilds the candidate tier under today's scanner rules. Default purge drops regex-origin host-kind candidates; `--purge-all-scan` drops every scan-origin candidate (AI stagings stay); `--purge-invalid` drops candidates of any origin that today's validators reject (stale rows that could never be promoted); `--rescan-days N` / `--rescan-all` re-run the observables scan. `--dry-run`. |
| `replay_ai_observables.py` | Backfills the ledger from stored `entry_analysis` results through the same `apply_ai_observables` door ingest uses (identical validators and per-kind capture list) and re-asserts the AI's relationship claims — the step after flipping `observables_ai_capture_mode` to `capture`, so earlier judgments land with role, evidence and attribution instead of being promoted blind. `--since`, `--mode`, `--kinds`, `--dry-run`. Never fires automation rules. |
| `audit_ai_observables.py` | Dumps every indicator the one-pass analysis AI judged (`iocs` / `scripts` arrays of current `entry_analysis` results, plus AI-origin staged candidates) to a CSV with role, evidence and a `verdict` column to label by hand — the precision record that gates `observables_ai_capture_mode`. `--since` / `--sample N` writes a stratified sample too. |
| `rematch_requirements.py` | Re-matches every entry against intelligence requirements using whole-word matching. |
| `purge_invalid_relationships.py` | Deletes or reorients entity relationships that violate the semantic relationship matrix. Dry-run by default. |
| `purge_generic_entities.py` | Applies today's creation gate to what is already in the actor/malware/tool/vendor/product catalogs: rows whose name is denylisted, generic ("the threat actor", "North America", AV strings, filenames, protocols, install commands, OS APIs, categories …) or a country name/demonym. These are the rows every article links to and the review queues keep proposing against. A dry run is the default and writes a review CSV sorted by link count; `--only protocol,shell_command` limits it to the given reasons, and a heavily linked row flagged by a non-entity rule defaults to `review` (not deleted until you change it); `--apply --plan <csv>` deletes through the review queues' own path (links, relationships and pending proposals go with the row, names are denylisted). Run `reconcile_search_index.py` afterwards. |
| `backfill_ransomware_victims.py` | Backfills `victim_disclosures` from ransomware.live's per-year history, so the Landscape dashboard has trend data from day one instead of only what the live sync has seen. Same resolver and dedup path as the live sync; idempotent on `(source, guid)`. `--start-year`. |
| `rebuild_search_indexes.py` | Rebuilds every Meilisearch index from the database — the `entries` index from scratch, plus the entity and rule indexes. Run it after restoring a dump from another environment (`ops/sync_prod_to_dev.sh` does). Runs inline, so the exit code says whether search works. `--user` (whose read/star state to bake in), `--entries-only`, `--entities-only`. |
| `sync_denylist.py` | Moves the do-not-recreate list between environments: the `entity_name_denylist` rows plus the names in the `autolinker_false_positive_names` setting. `--export FILE` from the instance you curated in, `--import FILE` into the other. Import is additive and never deletes. `--dry-run`. |
| `recount_article_counts.py` | Recounts every entity's stored `article_count` from its entry links and fixes the ones that drifted (a junk alias, a bulk unlink or a merge leaves the old number). Re-indexes the changed entities and clears the cached graphs. Observables are left to the nightly counter job. `--type`, `--entity` (UUID or name), `--apply`. |
| `sweep_cooccurrence_edges.py` | Re-checks every `co_occurrence` edge against today's builder rule (both names in one body paragraph, not boilerplate, fewer than five entities, a recorded position). Drops evidence articles that fail; rejects edges left with none, like the Reject button; a trimmed `probable` edge that no longer passes the promotion rule goes back to `possible`. Reviewer-kept articles stay; other edge sources are never touched. Writes a CSV that is also the undo (`--undo <csv>`). `--apply`. |
| `audit_auto_removals.py` | Lists link removals and IoC drops the adjudicate stage applied on its own since `--since` that match known-bad patterns: sector links, legitimate/defensive tools, TTPs from a rule's ATT&CK tags or an ATT&CK table, hashes from an indicator table, "legitimate/victim/publisher" reasons. Writes a review CSV with `restore=y` prefilled on strong matches; `--restore <csv> --apply` puts those rows back through the Review queue's own Restore. `--all` lists every auto-applied removal. |
| `rederive_content_text.py` | Rewrites stored `content_text` from `content_html` with today's `html_to_text`, which separates text at block and table-cell boundaries (older text glued IPs, CVE ids and CVSS scores together). Keeps the appended Transcript / Image OCR tail, writes only rows whose text changes by whitespace alone (others are reported as `differs`; `--include-differing` writes them too), updates `word_count` and the search documents, and leaves `content_hash` alone so dedup stays stable. `--since`, `--feed`, `--entry`, `--rerun` (queue autolink/observables/extract + co-occurrence for changed entries), `--apply`. |

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
