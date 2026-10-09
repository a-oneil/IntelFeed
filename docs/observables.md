# Observables — the IOC ledger, end to end

The observables ledger is where IntelFeed keeps *atoms*: values that exact-match
in telemetry. An IP, a hash, a C2 domain — and, since the issue #1 work, the
behavioural artifacts research write-ups quote: full command lines, dropped
file paths, registry values, scheduled-task and service names, mutexes,
user-agents and custom HTTP headers. This page is the deep-dive; the summary
lives in [intelligence-engine.md](intelligence-engine.md#observables--the-ioc-ledger),
the columns in [data-model.md](data-model.md#observable--the-ioc-ledger), the
knobs in [engine-settings.md](engine-settings.md#observables-stage).

Code: `backend/app/intelligence/observables.py` (engine),
`backend/app/services/analysis_window.py` (what the AI sees),
`backend/app/intelligence/infrastructure.py` (attribution surface),
`backend/app/models/observable.py` (vocabulary + schema).

## The contract

**Regex never creates a row.** Pattern scanning only nominates *candidates*
that stay on the entry (`entries.observable_candidates`). A ledger row exists
only when something with judgment created it:

| Door | `created_via` | Base confidence | What it is |
|---|---|---|---|
| One-pass analysis AI | `ai_extraction` | 0.8 (+0.1 if the author defanged) | The `iocs` array of `entry_analysis`: every kind, with a role, an evidence sentence and an optional ATT&CK `technique_id` |
| TTP observable | `ttp_observable` | 0.85 | `EntryTTP.observable_value` upserts (host artifacts attached to a technique claim) — backfill path; at ingest the AI door covers these |
| Article IOC table | `publisher_ioc` | 0.9 | The indicator file the article links to (Talos `.txt`/STIX `.json`, Bitdefender CSV, Datadog CSV) — allow-listed repositories only, roles from the publisher's labels, sighted on the article |
| Curated indicator feed | `ioc_list` | 0.85 | A whole file from a curated list repo (C2IntelFeeds, C2-Tracker), path-gated and infra-tagged; role from the file path |
| Analyst | `manual` | 1.0 | Promote from the reader, the candidates queue, or the `promote_observable` tool |

Every door's input passes `validate_kind_value()`. Then the pipeline may
*sight* a known value in new entries (`sight_known_values`, exact match only).

## Kinds and their validators

| Group | Kinds | Decay | Validator highlights |
|---|---|---|---|
| network | `ipv4`, `ipv6`, `domain`, `url`, `uri_path`, `email`, `ja3`, `ja4`, `cert_fingerprint` | 30d / 30d / 90d / 60d / 120d / 90d / none | public, non-reserved IPs; real TLDs (file-suffix lookalikes out); benign URI paths (`/favicon.ico`, `/login`) out; placeholders out |
| hash | `md5`, `sha1`, `sha256` | none | length-classified; the AI door also rejects a 64-hex whose evidence calls it a key/token/secret |
| host | `cmdline`, `path`, `registry`, `scheduled_task`, `service_name`, `mutex`, `named_pipe`, `user_agent`, `http_header` | none | see below |
| script | `script` | none | sha256 of the normalised snippet; body in `content` |

Host-kind rules (`_plausible_cmdline`, `_plausible_path_atom`, the registry /
header / name branches of `validate_kind_value`):

- `cmdline` needs ≥2 tokens, is not a generic discovery/admin command
  (`whoami /priv`, `systeminfo`, `net group "Domain Admins" /domain`,
  `nltest`, `tasklist`, …), is not detection logic (`process.`, `index=`,
  `OR`/`AND` chains), and carries something the attacker chose: a two-segment
  path, a host/URL/IP, a quoted string, an encoded blob, a dropped file name,
  or a state-changing flag (`/add`, `/create`, `-enc`, `-ExecutionPolicy`).
- `path` is an absolute path (env-var prefixes allowed) that is not a known OS
  binary under `System32`/`SysWOW64` (a planted `phoneinfo.dll` there *is*
  kept), not a bare well-known directory, not a lab path
  (`C:\Users\Lab\…`), and carries no `REDACTED` / `<…>` / `{…}` placeholder.
- `registry` is a hive-rooted key **with** the value name
  (`HKCU\…\Run\AppResolver`); the bare well-known key is the technique's
  location, not the artifact.
- `scheduled_task` / `service_name` / `mutex` / `named_pipe` are 3–128 chars,
  ≤5 words, not an OS default (`Schedule`, `Spooler`, `wuauserv`, …).
- `http_header` is a custom header name (optionally `Name: value`); standard
  headers are rejected (`User-Agent` is its own kind).

Roles: network values carry what the infrastructure did (`c2`, `delivery`,
`payload`, `phishing`, `exfil`, `exploit`, `scanning`); host artifacts carry
the tactic (`persistence`, `execution`, `defense_evasion`,
`credential_access`, `discovery`, `lateral_movement`, `collection`). Feed rows
get their role from the file path (`domainC2s` → `c2`, scanner → `scanning`,
phish-sim → `phishing`; VPN/RMM/KVM rows carry a tag instead of a role).

## What the AI sees: the analysis window

`build_analysis_variables` renders the article for the one-pass prompt with
`analysis_window.py`:

- HTML is flattened with structure kept — table rows become `cell | cell`
  (a hash stays next to its "loader" description), headings sit on their own
  line (an empty `<h2 id="indicators-of-compromise">` renders its id),
  `<pre>` keeps its line breaks.
- When the body exceeds `ai_analysis_content_max_chars`, the **indicator
  appendix** is found (an IOC heading past 20% of the body, or an indicator
  table header row, or the trailing region with ≥3 hash/IP/defanged
  candidates) and appended after the head behind a marker line, within
  `observables_analysis_tail_reserve` of the budget. Lines that are only an
  indicator are quota'd (12 hashes, 20 of each network kind) so the model's
  output stays bounded; the article's full IOC table is the table door's concern.
- Candidate hints are ranked (AI stagings, then defanged tokens, hashes, IPs)
  and scan-origin host kinds never enter the hint block.

Why: Talos, Unit 42, Huntress, Datadog and Bitdefender put the IOC section at
the end of 20k–80k-character articles; a head slice never showed the model any
of it. The engine also gives `entry_analysis` a 16k-token output budget so a
long article's payload is not cut mid-field (`parse_ai_json` repairs the
illegal backslash escapes small models write into Windows paths).

## Shadow, capture, and the per-kind list

`observables_ai_capture_mode` = `shadow` (default) stages every AI-judged
value on the entry as a promotable candidate **carrying its role, evidence,
confidence and technique**; `capture` writes rows — but only for kinds in
`observables_ai_capture_kinds` (default: network + hash + `script`). Host kinds
stay shadowed until the extraction fixture says they are precise. Promote
(UI, API, tool) carries the staged judgment onto the row.

Backfill after flipping: `scripts/maintenance/replay_ai_observables.py`
re-applies stored `ai_results` payloads through the same door and re-asserts
the actor/malware → observable relationships that were dropped while no row
existed.

### Candidate-tier precision rules (queue review, 2026-10-01)

The queue is only as useful as its precision, so the prose scanner carries
these vetoes on top of "hashes and public IPs always, domains/URLs/emails
only when defanged":

- **Advisory policy.** Entries with a GitHub `content_type` (rule and
  catalog repositories — Sigma, Nuclei, LOLDrivers YAML), feeds in
  `observables_codeblock_skip_categories`, and NVD feeds nominate **only
  defanged tokens**: a bare hex string there is a package checksum or a
  commit id, a dotted quad is a version.
- **Version quads.** "9.4.0.0 through 9.4.0.25", "20.15.6.1 and earlier",
  "from X to Y", and any quad with version/release/affected talk earlier in
  the sentence and nothing nearby calling it an address, never nominate.
- **Commit hashes.** A hex id in commit/fixed-in/up-to/version context with
  no sample/hash/file word nearby is not an indicator.
- **Glued table cells.** The stage scans the analysis renderer's text
  (`cell | cell`), not nh3's flat strip, and a TLD shaped like
  `com`+letters (`pobelstudio.comdomain`, `nuf.co.jpsender`) is rejected
  for domains and emails alike.
- **Placeholders and references.** `third-party.com`, `attacker.com`,
  `contoso.com` and friends; sandbox/catalog/vendor/social hosts
  (VirusTotal, urlscan, GitHub, MITRE, Microsoft Learn, Telegram API,
  IP-echo services); and the apex of a shared-infrastructure suffix
  (`amazonaws.com`, `github.io`) are never candidates. Subdomains on shared
  infrastructure still are.
- **Hashes inside tokens.** A 32/40/64-hex run that is part of a larger
  token (`pub-9ee1bf…a.r2.dev`, a path segment, an identifier) is not a
  hash. Cloud developer platforms (`r2.dev`, `pages.dev`, `trycloudflare.com`,
  `ngrok`, `vercel.app`, …) sit in `SHARED_INFRA_SUFFIXES`: their apex never
  nominates and rows under them never publish.
- **Paths.** A single top-level segment (`/PSEMHUB/`) and bare well-known
  locations (`/dev/shm`, `/var/tmp`, `/etc/hosts`, `C:\ProgramData`) are
  rejected by the validator, which the code-block scanner and the queue
  both apply.
- **The queue applies today's validators on read**, so nominations staged
  under older rules never show; `rescan_observable_candidates.py
  --purge-all-scan --purge-invalid --rescan-all` rebuilds the tier.

## Measuring the judge: the extraction fixture

`backend/tests/fixtures/observables/cases/*.json` — one case per real article
(seeded by `scripts/dev/build_observable_fixture.py`, hand-reviewed):
`expected` (canonical values with roles), `optional` (real artifacts whose
ledger-worthiness is a call), `must_not` (that article's garbage: publisher
links, reference URLs, keys quoted as hashes). `scripts/dev/eval_observable_extraction.py`
renders the prompt exactly as ingest does, runs the model (or `--offline`
scores stored results), and reports per-kind precision/recall, `must_not`
hits and attribution-edge recall against the gate (network P ≥ 0.95 / R ≥ 0.80,
host P ≥ 0.90, zero garbage). `tests/test_observable_fixture.py` keeps the
fixture consistent with the validators offline.

## Sources: reports vs feeds

`sighting_count` is the raw junction count. The UI shows **Sources** instead:
`report_count` (distinct reporting entries — articles, advisories, rule files)
and `feed_source_count` (distinct indicator feeds; a feed's eighteen CSV
variants count once). `record_sighting` increments `report_count` for every
door but the feed door; the nightly `reconcile-observable-counters` recomputes
all four from `entry_observables`. A feed-only row's profile says "listed on 1
indicator feed, no reporting" rather than rendering blank under a big number.

## Attribution: claimed vs reported alongside

`intelligence/infrastructure.py` answers "what infrastructure does X use?":

- **Claimed** — `entity_relationships` edges onto the ledger
  (`threat_actor|malware|tool|campaign → uses|communicates_with|controls →
  observable`), born from an evidence sentence (the one-pass AI), an analyst
  or a tool, carrying the trust ladder. These are the only observable edges in
  the graph.
- **Reported alongside** — observables a reporting door sighted in articles
  that link the entity. Read-time co-occurrence, never persisted, with
  indicator-list files and newsletters (>2 actors or >3 families in one
  article) excluded.

Surfaces: `GET /api/entities/{type}/{id}/infrastructure` (`?format=csv`),
`GET /api/observables/{id}/backlinks`, the **Infrastructure** panel on actor /
malware / campaign / tool profiles, the **Attribution** panel on the
observable profile, claim-backed rows in the Relationships tab (co-mention
observables stay suppressed), and the `get_entity_infrastructure` tool.

## Tools, automation, enrichment

Registry tools: `get_observable`, `search_observables` (filters: kind, role,
status, captured_by, infra_tag, needs_review, min_confidence, min_reports,
linked_entity_type + linked_entity_id for one entity's infrastructure),
`promote_observable`, `update_observable`, `deny_observable` (admin),
`get_entity_infrastructure`, `export_observables` (edl/csv/json). Regenerate
the skill CLIs after changing them (`scripts/dev/sync_skill_clis.py`).

Automation: the `on_observable_captured` trigger fires once per rule per
entry when a judgment door writes rows for it (AI, article IOC table, analyst
promote — never the indicator-feed door, never the replay backfill); its
`trigger_config` has the same shape as the `has_observable` condition (kinds,
roles, min_confidence, exclude dual-use, sighting sources), which also works
on any entry-triggered rule. `{observables_count}` / `{observables}` template
variables (defanged, one per line) feed notifications and webhooks, and
`add_to_campaign` with `link_observables` attaches the captured rows to the
campaign as entities. Templates: "Notify on New C2 Infrastructure", "Add an
Actor's New Infrastructure to Its Campaign". The profile's "Open in
observables browser" pivot is `GET /api/observables?linked_entity=<type>:<id>`
(claimed + reported-alongside), and the search language has
`ioc.reports:>0` / `ioc.feeds:>0` for the corroboration counts.

Enrichment: Shodan InternetDB (keyless) runs automatically for freshly judged
IPs from the AI, analyst and article-IOC-table doors — never for bulk feed rows;
VirusTotal and GreyNoise join once their keys are set (Settings → Engine →
Enrichment). Results fold into `Observable.reputation` and fill `infra_tag`
when the host is dual-use (Shodan `vpn`/`proxy`/`tor`, GreyNoise RIOT →
`benign_service`), which keeps it out of every published feed. The summary
rides `ObservableResponse.reputation`: a "Reputation" row on the profile's
provenance panel and a hidden-by-default "Reputation" column in the browser.
The one-time `backfill_feed_observable_roles.py` gives pre-existing feed rows
the role their file path implies.

## Publishing

Unchanged by this work: EDL blocklists, SIEM lookup CSVs and TAXII 2.1 under
`api/publish.py`, gated on confidence, age, status, shared-infra and
never-publish suffixes, and the infra tag. Host kinds never publish to
blocklists; `host_artifacts.csv` carries them.

## Jobs

| Job | When | Does |
|---|---|---|
| `decay-observable-confidence` | 02:20 | per-kind half-life decay |
| `reconcile-observable-counters` | 02:50 | recompute sighting / report / feed counters |
| `retro-sight-observables` | every 6h | exact-match new rows across the corpus |
