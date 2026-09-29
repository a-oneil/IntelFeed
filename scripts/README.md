# Scripts

Everything operational lives here, in one tree, grouped by what it does.

Most scripts use the application's own models and database session, so they run
**inside the api container**. `./scripts` is bind-mounted to `/app/scripts`
(see `docker-compose.dev.yml` / `docker-compose.prod.yml`), the same way `./docs`
is — the image itself only carries `./backend`.

```bash
docker compose -f docker-compose.dev.yml exec api python scripts/<folder>/<script>.py
```

`ops/` and `dev/` are the exception: they drive Docker, SSH, or the API from
outside, so run those from the repo root on your own machine.

Every script's docstring carries its exact invocation and flags. Anything that
writes takes `--dry-run` (or `--apply`), so you can see the damage first.

---

## `seed/` — reference data for a fresh install

A new install starts empty: the autolinker has no vocabulary, so entries ingest
and nothing links to anything. These populate the reference entities it matches
against. Run them in this order; each is idempotent, so re-running later just
fills gaps.

| Order | Script | Seeds |
| --- | --- | --- |
| 1 | `seed_countries.py` | Every UN-recognized country, with ISO codes and regions. |
| 2 | `seed_country_aliases.py` | Demonyms and adjective forms ("Iranian" → Iran) so prose actually matches. |
| 3 | `seed_mitre_attack.py` | The full MITRE ATT&CK catalog (Enterprise + Mobile + ICS) from the official STIX bundles: techniques, tactics, platforms, mitigations. |
| 4 | `seed_cwe_catalog.py` | The full MITRE CWE catalog (969 weaknesses + 422 categories) from `cwec_latest.xml`: abstraction ladder, ChildOf parents, mapping guidance, consequences, mitigations. Must run before `backfill_cve_weaknesses.py` so NVD refs resolve. |
| 5 | `seed_vendors_products.py` | 107 vendors and 862 products, with Wikipedia-sourced descriptions. |
| 6 | `seed_vendor_descriptions.py` | Re-fetch and reformat those descriptions as markdown; fills in any the first pass missed. |
| 7 | `seed_cpe_names.py` | CPE curation lists so NVD's CPE pairs resolve onto your vendors and products. |
| 8 | `seed_actor_countries.py` | Origin-country attribution for ~530 threat actors with high-confidence public attribution. |
| 9 | `seed_entity_attributes.py` | Motivation on threat actors, controlled-vocabulary type on malware families. |
| — | **`seed_all.py`** | **Runs all nine above, in this order.** |

`seed_all.py` runs all nine in order — that is the whole first-boot step:

```bash
D="docker compose -f docker-compose.dev.yml exec api python"
$D scripts/seed/seed_all.py --dry-run    # preview every step, write nothing
$D scripts/seed/seed_all.py              # seed everything
```

All nine seeders support `--dry-run`, so the preview is real rather than just a
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
| `--offline` | Skip `attack`, `vendors`, `descriptions` — the three that download. |
| `--only` / `--skip` | Comma-separated step names, for resuming or re-running a part. |
| `--overwrite` | Let `attribution` and `attributes` replace existing values instead of only filling blanks. |
| `--continue-on-error` | Keep going after a failure instead of stopping. |

Or run any step on its own: `$D scripts/seed/seed_countries.py`.

Steps 7 and 8 only enrich actors and malware that already exist, so they are
worth re-running once the feeds have been ingesting for a while.
`seed_mitre_attack.py` and the vendor scripts reach out to the network (MITRE's
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
| `normalize_vocabularies.py` | Folds `mitre_tactics`, `motivation`, `targeted_sectors`, `platforms` and `country` onto one spelling each, so a search facet stops listing `Persistence` and `persistence` as separate values. One-shot catch-up for rows written before the model validators landed; unrecognized values are kept and reported, not dropped, except the `platforms` entries that name an architecture or a language runtime, which are pruned and listed. `--dry-run`. |
| `reconcile_search_index.py` | Deletes Meilisearch documents whose feed no longer exists, after a cascade cleanup missed them. |
| `revalidate_wikipedia.py` | Clears Wikipedia enrichment on entities whose stored article title doesn't match the entity, so they re-enrich against the right article. |
| `refetch_truncated_entries.py` | Re-fetches full text for entries that stored a "continue reading" stub. |
| `refix_entry_image_urls.py` | Re-derives lead images for entries whose image is a tracking pixel or a relative URL. |
| `resanitize_entries.py` | Re-runs HTML sanitization to repair broken image-proxy URLs. |
| `rematch_requirements.py` | Re-matches every entry against intelligence requirements using whole-word matching. |
| `purge_invalid_relationships.py` | Deletes or reorients entity relationships that violate the semantic relationship matrix. Dry-run by default. |
| `backfill_rule_conversions.py` | Promotes `metadata.rule_conversions` blobs into real sibling detection rules on `derived_from`, then indexes them. `--dry-run` to preview; `--prune` to strip the blob afterwards. |
| `fold_cross_type_twins.py` | Folds same-name entities living under two types ("Qilin" the actor vs "Qilin" the malware) into one survivor via reclassify, writing tombstones so extraction can't resurrect them. Dry-run writes a review CSV to `scripts/out/`; `--apply --plan <csv>` executes the reviewed decisions; `--replay-holds` recovers entry links that enforced cross-type holds dropped before the resolver learned to link them. Run `reconcile_search_index.py` afterwards. |
| `strip_cross_type_aliases.py` | Removes aliases that duplicate another entity type's canonical name (malware DEADWOOD carrying the actor name "Agrius"), and purges the entry links that alias alone created. Analyst-sourced links are never touched. Dry-run writes a review CSV; `--report-ambiguous` lists alias-vs-alias collisions it refuses to guess at. |

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

## `dev/` — developer tooling  *(host-side)*

| Script | What it does |
| --- | --- |
| `sync_skill_clis.py` | Regenerate both skill CLIs' `TOOLS` and `WRITE_TOOLS` blocks from the live backend tool registry, which is the single source of truth. `--check` reports drift without writing (exit 1 if out of sync). |
| `local_link_validator.py` | Bulk-run the entity-link validator against a production database over an SSH tunnel using your local `claude` CLI, for when the scheduled batches can't keep up with the backlog. Resumable. |
| `webhook_proxy.py` | TCP proxy so containers on Docker Desktop for Mac can reach LAN hosts via `host.docker.internal`, for testing webhook deliveries. |

```bash
INTELFEED_API_URL=http://localhost:8000 python3 scripts/dev/sync_skill_clis.py --check
python3 scripts/dev/webhook_proxy.py 10138 192.0.2.10 80
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
