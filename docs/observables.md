# Observables — the IOC ledger, end to end

An **observable** (IOC) is a value you can match exactly in logs: an IP, hash, C2 domain, or a host artifact quoted in research (command line, file path, registry value, task or service name, mutex, user-agent, custom HTTP header). This page covers how a value becomes a ledger row, the checks it passes, how its confidence changes, and where it is published.

Related: summary in [intelligence-engine.md](intelligence-engine.md#observables--the-ioc-ledger), columns in [data-model.md](data-model.md#observable--the-ioc-ledger), settings in [engine-settings.md](engine-settings.md#observables-stage).

| File | Holds |
|---|---|
| `backend/app/intelligence/observables.py` | Scanning, validation, doors, sightings, decay |
| `backend/app/services/analysis_window.py` | What the AI sees of an article |
| `backend/app/intelligence/infrastructure.py` | "What infrastructure does this actor use?" |
| `backend/app/models/observable.py` | Kinds, roles, decay rates, the table |

## The contract

**Regex never creates a row.** Scanning only nominates *candidates* on the entry (`entries.observable_candidates`, at most `observables_candidate_max`, default 200) and shown in the reader to promote. Only a judgment "door" creates a row, setting `created_via` and a starting confidence:

| Door | `created_via` | Base confidence | What it is |
|---|---|---|---|
| Analyst | `manual` | 1.0 | Promote from reader, candidates queue or `promote_observable` tool |
| Article IOC table | `publisher_ioc` | 0.9 | The IOC file an article links to (Talos `.txt` and STIX `.json`, Bitdefender CSV, Datadog CSV). Allow-listed repos only; roles from publisher labels; sighting recorded on the article. Switch: `observables_publisher_ioc_enabled` |
| Curated indicator feed | `ioc_list` | 0.85 | A whole file from a curated list repo (C2IntelFeeds, C2-Tracker). Path sets role and infrastructure tag. `whitelist`, `allowlist`, `benign` and `unverified` files, and C2-Tracker's combined `all.txt`, are refused |
| TTP observable | `ttp_observable` | 0.85 | A host artifact on a technique claim (`EntryTTP.observable_value`). Sighting carries the technique |
| One-pass AI analysis | `ai_extraction` | 0.8 | `entry_analysis`'s `iocs` array: any kind, with role, evidence sentence and optional ATT&CK `technique_id` |

Defanged values (`evil[.]com`, `hxxps://`) get +0.1. No `created_via` value means "regex".

Door input must pass `validate_kind_value()` (`backend/app/intelligence/observables.py:1240`). New entries are then **sighted**: `sight_known_values()` (`backend/app/intelligence/observables.py:1001`) records exact matches of ledger values.

## What becomes a candidate

Rules in `scan_candidates()` (`backend/app/intelligence/observables.py:434`):

| Family | Becomes a candidate when |
|---|---|
| Hashes, public IPs | Always; IPs must be public, outside reserved or benign ranges (`_valid_public_ip`, `backend/app/intelligence/observables.py:250`) |
| Domains, URLs, emails | Only when defanged (`microsoft.com` in prose nominates nothing) |
| Host artifacts | Never from prose. A `<pre>`/`<code>` block may nominate one (`scan_code_block_candidates`) only if the block is mostly commands and the line starts with a shell prompt or known executable |

`refang()` (`backend/app/intelligence/observables.py:66`) undoes `hxxp`, `[.]`, `(dot)`, `[:]`, `[@]` and similar. The defanged form is kept on the sighting (`entry_observables.surface_form`, `was_defanged`).

### Candidate precision rules

The scanner also refuses:

- **Advisory sources.** Entries with a GitHub `content_type` (Sigma, Nuclei, LOLDrivers repositories), feeds in a category in `observables_codeblock_skip_categories` (default "Security Advisories, Government / CERT"), and NVD feeds nominate **only defanged values** (bare hex there is a checksum, a dotted quad a version); their code blocks nominate nothing.
- **Version numbers.** "9.4.0.0 through 9.4.0.25", "20.15.6.1 and earlier", "from X to Y", or a dotted quad after version/release/affected wording with no address wording nearby.
- **Commit hashes.** Hex in commit / fixed-in / version context with no sample, hash or file word nearby.
- **Glued table cells.** The scan reads renderer text (`cell | cell`); a TLD shaped like `com` + letters (`pobelstudio.comdomain`) is rejected.
- **Placeholders and reference sites.** `attacker.com`, `contoso.com`; sandbox, catalog, vendor and social sites (VirusTotal, urlscan, GitHub, MITRE, Microsoft Learn, Telegram API, IP-echo services); the bare apex of shared hosting (`amazonaws.com`, `github.io`). Their subdomains can still be candidates.
- **Hashes inside longer tokens.** 32/40/64 hex inside a hostname, path segment or identifier (`pub-9ee1bf…a.r2.dev`). Cloud dev platforms (`r2.dev`, `pages.dev`, `trycloudflare.com`, `ngrok`, `vercel.app`, …) are in `SHARED_INFRA_SUFFIXES`: their apex never nominates, and rows under them are never published.
- **Bare paths.** One top-level segment (`/PSEMHUB/`) or a well-known location (`/dev/shm`, `/var/tmp`, `/etc/hosts`, `C:\ProgramData`).

The queue re-applies current validators on read, hiding stale candidates. To rebuild:

```bash
# in the api container
python scripts/maintenance/rescan_observable_candidates.py --purge-all-scan --purge-invalid --rescan-all
```

## Kinds and their validators

| Group | Kinds | Confidence half-life | Validator highlights |
|---|---|---|---|
| network (infrastructure rotates, so these decay) | `ipv4`, `ipv6` | 30 days | Public, non-reserved addresses |
| | `domain`, `email` | 90 days | Real TLDs, not file extensions; no placeholders |
| | `url` | 60 days | A full `http(s)://` URL |
| | `uri_path` | 120 days | Starts with `/`; benign paths (`/favicon.ico`, `/login`) rejected |
| | `ja3`, `ja4`, `cert_fingerprint` | never decays | Correct fingerprint shape |
| hash | `md5`, `sha1`, `sha256` | never decays | Length sets the kind; the AI door rejects 64-hex its evidence calls a key, token or secret |
| host | `cmdline`, `path`, `registry`, `scheduled_task`, `service_name`, `mutex`, `named_pipe`, `user_agent`, `http_header` | never decays | See below |
| script | `script` | never decays | SHA-256 of the normalised snippet (kept in `content`) |

Host rules (`_plausible_cmdline`, `_plausible_path_atom`, and the branches of `validate_kind_value`):

- **`cmdline`**: two+ tokens; not a generic admin command (`whoami /priv`, `systeminfo`, `net group "Domain Admins" /domain`, `nltest`, `tasklist`, …); not detection logic (`process.`, `index=`, `OR`/`AND` chains); and has something attacker-chosen: path, host, URL, IP, quoted string, encoded blob, dropped file name, or state-changing flag (`/add`, `/create`, `-enc`, `-ExecutionPolicy`).
- **`path`**: absolute (env-var prefixes allowed); not a known OS binary under `System32` / `SysWOW64` (a planted `phoneinfo.dll` there *is* kept); not a bare well-known directory or lab path (`C:\Users\Lab\…`); no `REDACTED`, `<…>` or `{…}`.
- **`registry`**: a hive-rooted key **with** the value name (`HKCU\…\Run\AppResolver`); a bare well-known key is not an artifact.
- **`scheduled_task`, `service_name`, `mutex`, `named_pipe`**: 3–128 characters, at most 5 words, not an OS default (`Schedule`, `Spooler`, `wuauserv`, …).
- **`http_header`**: a custom header name, optionally `Name: value`; standard headers rejected (`User-Agent` has its own kind).
- **`user_agent`**: product/version syntax (`Mozilla/5.0 …`, `curl/8.1.2`).

**Roles.** Network: `c2`, `delivery`, `payload`, `phishing`, `exfil`, `exploit`, `scanning`. Host (a tactic): `persistence`, `execution`, `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`, `collection`. Feed rows take it from the file path (`domainC2s` → `c2`, scanners → `scanning`, phishing-simulation → `phishing`); VPN, RMM and KVM lists get an infrastructure tag.

**Shared infrastructure.** `is_shared_infra()` (`backend/app/intelligence/observables.py:652`) tags shared hosting, CDNs and URL shorteners in `infra_tag`; publishing skips them, profiles show them.

## What the AI sees: the analysis window

`build_analysis_variables()` (`backend/app/services/entry_analysis.py:61`) renders the article for the prompt via `analysis_window.py`:

- HTML is flattened with structure kept: table rows become `cell | cell` (a hash stays by its "loader" description), headings get their own line (an empty `<h2 id="indicators-of-compromise">` renders its id), `<pre>` keeps line breaks.
- If the body exceeds `ai_analysis_content_max_chars`, the **indicator appendix** (an IOC heading past the first 20% of the body, an indicator table header, or else the trailing region with three or more hash, IP or defanged candidates) is appended after the article start behind a marker line. It gets up to `observables_analysis_tail_reserve` (default 0.4) of the budget. Indicator-only lines are capped per kind (10 per hash kind, 15 per network kind); the publisher door handles full IOC files.
- Candidate hints are ranked (earlier AI stagings, defanged values, hashes, IPs); scanned host candidates are never hints.

(Talos, Unit 42, Huntress, Datadog and Bitdefender put IOCs at the end of 20,000–80,000-character articles.)

The seeded `entry_analysis` assignment has a 10,000-token output budget (`backend/app/ai/prompts/defaults.py`). `parse_ai_json()` (`backend/app/ai/engine.py:161`) repairs bad backslash escapes small models write in Windows paths.

## Shadow, capture, and the per-kind list

`observables_ai_capture_mode` controls the AI door:

- **`capture`** (default) writes rows only for kinds in `observables_ai_capture_kinds` (default: network kinds, hash kinds and `script`).
- **`shadow`** stages every AI value as a candidate **carrying its role, evidence, confidence and technique**.

Kinds outside the list are staged as in shadow. The TTP door obeys both switches. Host kinds stay off the list until the fixture (below) shows they are precise. Promoting a staged value (UI, API or tool) carries its judgment to the new row.

After changing either, `scripts/maintenance/replay_ai_observables.py` replays stored analysis results through the door and re-creates actor/malware → observable relationships.

## Measuring the judge: the extraction fixture

`backend/tests/fixtures/observables/cases/*.json` has one hand-reviewed case per real article (from `scripts/dev/build_observable_fixture.py`):

- `expected` — correct values with roles
- `optional` — real artifacts that may or may not belong
- `must_not` — garbage: publisher links, reference URLs, keys quoted as hashes

`scripts/dev/eval_observable_extraction.py` runs the ingest prompt (`--offline` scores stored results) and reports per-kind precision/recall, `must_not` hits and attribution-edge recall. Gate: network precision ≥ 0.95, recall ≥ 0.80; host precision ≥ 0.90; zero garbage. `backend/tests/test_observable_fixture.py` checks the fixture agrees with the validators.

## Sources: reports vs feeds

The UI shows **Sources** instead of the raw `sighting_count`:

- `report_count` — distinct reporting entries (articles, advisories, rule files)
- `feed_source_count` — distinct indicator feeds (a feed's eighteen CSV variants count once)

`record_sighting()` adds to `report_count` for every door but the indicator feed; the nightly `reconcile-observable-counters` job recomputes the counters. A feed-only row reads "listed on 1 indicator feed, no reporting".

## Attribution: claimed vs reported alongside

`backend/app/intelligence/infrastructure.py` answers "what infrastructure does X use?":

- **Claimed** — `entity_relationships` edges onto the ledger (`threat_actor|malware|tool|campaign → uses|communicates_with|controls → observable`), from the one-pass AI's evidence, an analyst or a tool, with a trust level. The graph's only observable edges.
- **Reported alongside** — observables sighted by a reporting door in articles linking the entity, computed at read time. Excludes indicator-list files and newsletter-style articles (over 2 actors or over 3 malware families).

Surfaces: `GET /api/entities/{type}/{id}/infrastructure` (`?format=csv` for a file), `GET /api/observables/{id}/backlinks`, the **Infrastructure** panel on actor, malware, campaign and tool profiles, the **Attribution** panel on the observable profile, claim-backed Relationships-tab rows (co-mention observables hidden), `get_entity_infrastructure`.

## Tools, automation, enrichment

**Registry tools:** `get_observable`; `search_observables` ( `kind`, `role`, `status`, `captured_by`, `infra_tag`, `needs_review`, `min_confidence`, `min_reports`, and `linked_entity_type` + `linked_entity_id` for one entity's infrastructure); `promote_observable`; `update_observable`; `deny_observable` (admin); `get_entity_infrastructure`; `export_observables` (EDL, CSV or JSON). Regenerate the skill CLIs with `scripts/dev/sync_skill_clis.py` after changes.

**Automation:**

- `on_observable_captured` fires once per rule per entry when the AI, article IOC table or an analyst promote writes rows — never for the indicator-feed door or replay script.
- Its `trigger_config` matches the `has_observable` condition (kinds, roles, `min_confidence`, exclude dual-use, sighting sources), which also works on any entry-triggered rule.
- `{observables_count}` and `{observables}` (defanged, one per line) feed notifications and webhooks.
- `add_to_campaign` with `link_observables` attaches captured rows to the campaign.
- Shipped templates: "Notify on New C2 Infrastructure" and "Add an Actor's New Infrastructure to Its Campaign".

**Search and browse:** "Open in observables browser" on a profile is `GET /api/observables?linked_entity=<type>:<id>` (claimed plus reported alongside). The search language has `ioc.reports:>0` and `ioc.feeds:>0` (also `observable.reports` / `observable.feeds`); see [query-language.md](query-language.md).

**Enrichment:** new IPv4, IPv6, domain and hash rows from the AI, analyst and article-IOC-table doors queue lookups in the [enrichment job queue](automation-ai-enrichment.md#enrichment-job-queue) at each auto source that takes the kind (max 25 per entry); bulk feed rows never do. Shodan InternetDB, GreyNoise Community, Team Cymru and RDAP need no key; VirusTotal needs one, and ThreatFox, URLhaus and MalwareBazaar share one abuse.ch key (Settings → Engine → Enrichment). Reputation goes to `Observable.reputation`; network context has its own columns:

| Column | Source | What it holds |
|---|---|---|
| `asn`, `asn_org`, `geo_country` | Team Cymru (DNS), VirusTotal | The IP's origin AS, its name and the allocation's country; newest answer wins |
| `registered_at` | RDAP | When the registrable domain (`login.evil.co.uk` → `evil.co.uk`) was registered; the profile shows its age |
| `popularity_rank` | Tranco (daily job) | The domain's exact rank in the top-1M list, null when unlisted |
| `noise_class` | GreyNoise | `malicious` / `benign` / `unknown` when seen mass-scanning, `not_seen` otherwise |

Team Cymru and RDAP look up only `active` rows on their own; aged and expired rows are never queued or backfilled, though an analyst's Enrich button still runs. RDAP caches each registrable domain for 7 days, so a second subdomain costs no request. A domain that enters the Tranco top 10,000 gets `needs_review` once (a popular site named as an indicator is often a false positive); it stays in the ledger, and shows in the browser's Review column and `search_observables(needs_review=true)`. The prefix, registry and allocation date, the registrar, expiry, status and nameservers, and the rank show in the profile's Context panel. A dual-use host (Shodan `vpn` / `proxy` / `tor`, GreyNoise RIOT → `benign_service`) gets an `infra_tag`, keeping it out of published feeds. The provenance panel shows Network, Registered (with the domain's age) and Popularity rows, and the browser has a hidden-by-default Reputation column. `scripts/maintenance/backfill_feed_observable_roles.py` fills missing feed-row roles from the file path.

**abuse.ch:** once a key is saved, the `threatfox-sync` (daily) and `urlhaus-sync` (every six hours) jobs download ThreatFox's IOC export and the URLhaus dump and match them exactly against the ledger, sending nothing about it; only `active` rows are written. A match fills a blank `role` (ThreatFox `botnet_cc` → `c2`, `payload_delivery` → `delivery`, `payload` → `payload`; a URLhaus URL → `delivery`), claims the malware families IntelFeed already tracks (the connection is the family's: `malware communicates_with` a C2, `malware uses` delivery and payload material; an unknown family name is held, never created), and shows the threat type, confidence, first and last seen, tags and a link in the Context panel, with a URLhaus online / offline badge (offline is neutral). A row the export answered loses that context and those claims when it leaves the export; an analyst's lookup is never withdrawn by an export. Looking one indicator up at ThreatFox, URLhaus or MalwareBazaar sends it to abuse.ch, so those lookups only run when an analyst presses Enrich. See [automation-ai-enrichment.md](automation-ai-enrichment.md#abusech).

## Publishing

`backend/app/api/publish.py` serves firewall blocklists (EDL: `ipv4.txt`, `domains.txt`, `urls.txt`, …), SIEM lookup CSVs and a TAXII 2.1 collection. Filters: confidence, age, status, shared-infrastructure and never-publish suffixes, infrastructure tag. Host kinds never go in blocklists; `host_artifacts.csv` carries them. Gates and switches: [engine-settings.md](engine-settings.md#publishing-engine--publishing-browse-screen).

## Lifecycle and jobs

Confidence = `base × 0.5^(days since last sighting / half-life)`. `status_for()` (`backend/app/intelligence/observables.py:753`) derives status: `active`, `aging` below 0.5, `expired` below 0.15. `retro_sight_observable()` (`backend/app/intelligence/observables.py:1945`) searches recent entries when a row is created, so promoted candidates keep their history.

| Job | When (UTC) | Does |
|---|---|---|
| `decay-observable-confidence` | 02:20 daily | Per-kind decay and status changes (switch: `observables_decay_enabled`) |
| `reconcile-observable-counters` | 02:50 daily | Recounts sighting, report and feed counters from `entry_observables` |
| `retro-sight-observables` | every 6 hours at :40 | Exact-match search of the corpus for recently confirmed rows |
