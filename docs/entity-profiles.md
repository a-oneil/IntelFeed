# Entity Profiles

For developers: how the profile page for an actor, malware, CVE or any other entity is put together, and where to change it.

See diagram: [Entity profile assembly](diagrams/entity-profiles-assembly.md)

## One page, many entity types

Every profile (actors, malware, CVEs, CWEs, TTPs, countries, sectors, tools, observables, mitigations, vendors, products, campaigns) renders through `frontend/src/pages/EntityProfilePage.tsx`. A per-type entry in `frontend/src/components/entityProfile/entityProfileConfig.tsx` sets the tabs, header badges and identity fields, extra Overview panels, external lookup links, and whether the name is editable (`nameEditable`). The header, tabs and panels are in `components/entityProfile/`.

## Page anatomy

- **Header.** Breadcrumb, type badge and name (click to rename where `nameEditable`). **SignalBadges** are click-to-edit chips (motivation, malware type, tactic, severity, CVSS, EPSS, KEV, region); the country badge links to its profile (a vendor's country comes from Wikidata). Badges from enrichment sources appear next to them: a product's support status (`EOL` in red; amber for "security fixes only" or an end of life under 90 days away), and **no patch coming** on a CVE that affects a product past end of life, or a release past end of life of a product that is still maintained (the affected rows' `eol_releases`). Also:
  - **Ask Copilot**, a **Watch** toggle, enrichment status
  - an actions menu: markdown export, merge into, add to campaign, convert to another type. Merge and convert are admin-only; convert writes a tombstone so the old name isn't recreated.
- **Activity sparkline.** `PulseLine` sits at the bottom right of the header, on the first-seen / last-seen row: article counts as bars over the chosen window (24 hours to all time), with the window picker and **Expand**. It shows no numbers; the Overview's **Reporting** fact says what the curve means. **Expand** opens the full `MentionsTimeline` under the header, which CVEs follow with a lifecycle strip and observables with `ObservableLifecycleStrip`.
- **Overview tab.** One column, from the brief down to the workspace. The **brief** reads top to bottom. First comes the assessment (`AssessmentBlock`: description via `EntityLinkedMarkdown`, so names become links; text longer than 480 characters is collapsed to its opening lines). Then **key facts**, a table with one row per fact: the fact, its value, and who says so on the right. The rows are an activity verdict; on a CVE, the affected products and how the flaw is reached (from the CVSS vector); the type's numbers from `SnapshotCard` (a CVE's CVSS, EPSS, risk tier and weaknesses; an actor's leak-site victims from ransomware.live); and the best-evidenced claims from `KnownAssociates`, one row per verb (Targets, Uses, Used by) naming the other entities; hovering a name says who confirmed it (MITRE ATT&CK, an analyst, AI review) or that it was reported in several separate stories. The verdict (`activityVerdict.ts`) compares the last 21 days of the 90-day mentions series with the days before it, per day: Rising, Steady, Cooling, Quiet or New, with the busiest day. Then **what changed** (`LatestDevelopments`: items from `GET /api/engine/entities/{type}/{id}/whats-new`, plus an actor's latest leak-site victim). Last is **next steps** (`NextActions`). On actors and malware it opens with detection coverage from `GET /api/entities/{type}/{id}/detection-gaps`: a bar and counts of techniques with a rule, with a rule whose log source isn't collected, and with no rule. No percentage is shown, because technique tag matching reads about 90% for every actor. On a KEV CVE it opens with the patch deadline and how many detection rules are linked. Under that is one line per remaining job (claims to corroborate, a missing assessment, a campaign's suggestions and standing searches), and the **Review gaps** and **Download hunt package** buttons. On the hunt types (actor, malware, CVE, technique, campaign) the button runs `useHuntPackageDownload`: with no hunts yet it queues a draft (`POST /api/hunt-packs/{type}/{id}`, scope `all`), shows a "Drafting hunts" line with the elapsed time while `GET` polls, then downloads `GET /api/hunt-packs/{type}/{id}/package.zip`. A draft that can't run (engine stopped, no provider, nothing to hunt from) says why and downloads the zip without hunts. Once hunts exist the line reads "N hunts drafted" with how many run on the collected telemetry. Other types keep the research bundle (`POST /api/export/research-bundle`, the 100 most recent articles).
- **Overview rows.** Everything else is a **section row** (`OverviewSection`): one line with a caret, the section name, a count and a one-line summary (count, top items, how recent), which opens in place. Each type lists its rows under `overviewSections` in the config. Every row starts closed; the rows you open are remembered per entity type. A row with nothing to show is left out. The order is the same on every type (`OVERVIEW_SECTION_ORDER`): Context first, then the rows that are the entity's own record, then Stories & reading, Activity and Workspace. The rows, in that order, are:
  - **Hunts** (the hunt types; visitors never see it): the profile's hunt pack from all reporting, one line per hunt (`components/hunt/HuntPackPanel.tsx`): number, title, tactic, any telemetry it needs that isn't collected, and **Copy** and **ATHF file** on the line. A line opens in place to the hypothesis, its techniques (links to their profiles, names read live from the catalog), the log it reads ("Reads vCenter VCSA syslog…", flagged when no enabled telemetry source holds it, which also puts "needs …" on the hunt's line), the query one stage per line, and **Why, adapt, false positives**. The row's line carries **Draft more** (keeps the hunts and adds new ones numbered on, H6, H7…, up to 20) and **Draft again** (replaces them). Before the first draft the row reads "none yet" and opens to **Draft hunts**. It sits just above Stories & reading.
  - **Context** (`ContextPanel`): what each enrichment source says about the entity, one collapsible row per source (the first open) with when it last answered and whether that answer is still fresh or stale. Refresh re-runs every source; ↻ re-runs one. A source without its key shows "needs key" and, for admins, links to that source in the Enrichment console. A CVE also gets **CVSS by source**: each source's score (NVD, the CVE record's CNA and CISA-ADP scores) with its vector, and which one the profile shows. Visitors see the section without its buttons. The `SourcesCard` of outbound links (external pivots, Malpedia, GitHub, Wikipedia, a CVE's NVD references) sits in the same row; attaching a Wikipedia article starts from it. See [Source Context](automation-ai-enrichment.md#source-context).
  - **Recent victims** (ransomware actors): leak-site victims from the tracker.
  - **Catalog**: a TTP's MITRE details, related techniques and mitigations; a CWE's family, catalog data, mitigations and affected vendors.
  - **Provenance & confidence** (observable): how the indicator was captured and how its confidence decays.
  - **Exploit & PoC** (CVE): proof-of-concept repositories and Metasploit modules, when any exist.
  - **Affected** (CVE), **Weakness profile** (vendor, product), **Infrastructure** (actor, malware, tool, campaign), **Attribution** (observable): the per-type panels.
  - **Stories & reading**: active story threads, essential reading, and the Wikipedia summary when an article is attached.
  - **Activity**: the activity feed; a campaign's intake panel (searches and suggestions) sits above it.
  - **Workspace**: entity-scoped AI analysis (`AIAnalysisModule`, for prompts with `show_in_entity_actions`) and analyst notes (`EntityNotesSection`); `?tab=notes` opens this row. Visitors do not get it.

  Which rows are open is remembered per entity type (`profileOpenSections` in `uiStore`). The **Brief / Everything** switch at the right of the tab bar opens every row at once; closing one row switches back to Brief.
- **Relationships tab** (all types). The typed graph (hidden until **Show graph**), then a list of the entity's relationships beside an evidence panel (`RelationshipsTab.tsx`, `components/entityProfile/relationships/`). The tab's count is the number of relationships.
  - **Relationships**: grouped as sentences by verb and type ("Qilin uses · TTPs", "Threat Actors that use Qilin"), sorted by article count. Each row names its source in plain words (`utils/relationshipSource.ts`): **MITRE ATT&CK**, an enrichment feed by name (ransomware.live, Malpedia), **AI-reviewed articles** (the adjudicator kept or corroborated it), **Articles, not reviewed**, or **Analyst**. A **Source** filter narrows the list to one of them. On a country profile the targeting, origin and infrastructure rows from article tagging are listed here too.
  - **Evidence panel** for the selected row: who says so and how sure it is; the reviewer's reason or the feed's note; the articles that state it, each with its sentence, and the reviews (`GET /api/entity-relationships/{id}/evidence`, signed-in users only); articles over time; its stories; and, kept apart, the articles that only mention both. Signed-in users can confirm it, remove it (reject), or change its verb to another the pair allows. On a phone the panel opens under the tapped row.
  - **From reference data** (CVE, CWE): a CVE's weaknesses with who assigned each (NVD, the vendor, CISA ADP) and its affected products (NVD CPE); a weakness's parent and children in the CWE catalog, its CAPEC attack patterns, and its CVEs with the KEV ones listed.
  - **Not matched yet** (signed-in users): names an enrichment source gave that match no entity, or more than one (`GET /api/entity-relationships/claims/{type}/{id}`).
  - **Mentioned in the same articles**: entities named in the same articles with no relationship stated, as a card per type with the shared-article count. Closed by default; open when the entity has no relationships. Two entities of one type with the same name are marked as a duplicate name.
- **Detection tab** (actor, malware, campaign, CVE, CWE, TTP). Linked rules and coverage; **Detection Gaps** (uncovered techniques) opens from the "Review gaps" next-action chip. Public read-only visitors see neither.
- **Vulnerabilities tab** (CWE, vendor, product). CVEs with this weakness, or affecting this vendor/product via `cve_affected` (NVD CPE data and the CVE record's affected list, separate from `entity_relationships`).
- **Weaknesses tab** (CVE). The CVE's CWEs.
- **Geography tab** (country). Role breakdown; actors from or targeting the country.
- **Victimology tab** (sector). Who targets the industry (reporting vs claims), plus leak-site victims.

## Where the data comes from

| Source | How | What it fills |
|---|---|---|
| Autolinker | Dictionary scan at ingest (`backend/app/intelligence/autolinker.py`), with junk-alias and LOLBin filtering | Entry links for actors, malware, countries, vendors, products, tools |
| Regex and AI extraction | `CVE-YYYY-NNNN` and `TNNNN(.NNN)` regex; one-pass AI analysis | CVE and TTP links, new entities, sectors, indicators |
| NVD / EPSS / KEV / GitHub PoC | Scheduled syncs ([entries.md](entries.md#beat-scheduled-enrichment)) | CVE scores, exploit status, affected products |
| MITRE ATT&CK / Malpedia / Wikipedia | Weekly syncs | TTP details and mitigations; actor and malware descriptions and aliases |
| Wikidata / endoflife.date | Weekly and daily syncs ([rules](automation-ai-enrichment.md#wikidata)) | Vendor websites, countries, industries and facts, product vendors, country regions, victim countries; product support status and releases |
| CAPEC / CTID / D3FEND | Weekly syncs ([rules](automation-ai-enrichment.md#capec)) | CAPEC names for a CWE's attack patterns; a technique's CAPEC patterns, NIST 800-53 and CIS controls (`nist_controls`, `cis_controls`) and D3FEND countermeasures |
| ETDA Threat Group Cards / ransomware.live group profiles | Weekly sync; a few groups every 4 hours ([rules](automation-ai-enrichment.md#relations)) | Actor aliases, origin, MITRE id; targeted sectors and countries, tools and techniques as `enrichment` claims; operations and leak-site status on the Context panel |
| Co-occurrence and the Telegram forward graph | Post-ingest pipeline step; job every 4 hours | `entity_relationships` links |
| Analyst | Badge edits, descriptions, merges, notes, relationship confirm/reject | Any of the above, marked analyst-sourced |

### Relationships and trust

Rows in `entity_relationships` (`backend/app/models/entity_relationship.py`) have:
- a **verb**: `uses`, `exploits`, `targets`, `attributed_to`, `variant_of`, `communicates_with`, `delivers`, `drops`, `controls`, `related_to`, `successor_of`, `subgroup_of`, `overlaps_with`, `exposes`, `operates_in`
- a **confidence**: `confirmed`, `probable` or `possible`
- a **source**: `co_occurrence`, `auto_extracted`, `analyst_confirmed`, `analyst_created`, `analyst_rejected`, `external_feed` (the MITRE ATT&CK import writes `external_feed` with `confirmed`) or `enrichment` (an enrichment source's relation claim, `probable`, so it reads as reported)
- **`evidence_entry_ids`**: the supporting articles

An `enrichment` row exists while some source's claim in `entity_relation_claims` holds it; the claim keeps the source, the name it gave and its evidence, and the row is deleted when the last claim is withdrawn. See [Relations](automation-ai-enrichment.md#relations).

Writes check (source type, verb, target type) against the allowlist in `backend/app/intelligence/relationship_matrix.py`; a disallowed combination is reversed to its allowed direction or dropped.

Machine links (`auto_extracted`, `co_occurrence`) are judged by two reviewers, and each judgment is a row in `relationship_reviews`; `backend/app/services/edge_settlement.py` derives the link's verdict from them:
- The adjudicate stage judges a link against one article at a time, by the sentence that would state it. **Keep** is that article's vote for it; **demote** its vote against; **reverb** says the article states the pair with another verb or the other way round, which demotes the claim for that article and credits the corrected link. Only high-confidence answers count.
- Keeps from articles in two or more feeds (reposts excluded), at `relationship_evidence_promote_count` articles, make it `confirmed` / `corroborated`. A demote with no counted keep makes it `coincidental`: confidence `possible`, hidden from profiles, pivots and graphs. A keep and a demote from different articles make it `disputed`, which stays in Review.
- The edge sweep takes the links still open after a day and judges each against passages from up to four of its articles. In apply mode a stated claim becomes `kept`; see [the edge sweep](intelligence-engine.md#the-edge-sweep).
- Restore on a demote settles the link as `kept`.

A settled link (`kept`, `corroborated`, `coincidental`) leaves the review list, so later co-mentions can't undo it. Analyst, `external_feed` and `enrichment` links are never reviewed.

Two tombstones stop rejected data returning:
- `source = analyst_rejected` rows stay, so co-occurrence never recreates a rejected pair.
- Converting an entity's type writes an `entity_reclassify_tombstones` row, so importers don't recreate the old name.

## Observables and infrastructure

The observable profile is the simplest: the heading is the value in monospace, nothing is editable inline, and badges are lifecycle facts (kind, role, confidence, status, capture method). It has two tabs (`overview`, `relationships`) and two Overview panels:

- **`observable_provenance`** — capture method, shared-infrastructure tag, role, evidence sentence; base and current confidence, decay and projected expiry; the **Sources** row (`N reports · M feeds`, plus raw sighting count), with a "Reporting" row that marks feed-only values. Buttons: copy (plain or defanged), export sightings CSV, pin confidence, tombstone (admins).
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
| `enrichment` | `enrichment/entity_updater.py` (Wikipedia, MITRE ATT&CK, Malpedia, Wikidata, endoflife.date and the other sources' declared columns), the NVD and KEV syncs (`intelligence/cve.py`, `intelligence/external_feeds.py`), the GitHub PoC and Metasploit jobs (`workers/enrichment_tasks.py`) and the sector rollup in `workers/maintenance.py`, which writes `threat_actor_target_sectors` / `malware_target_sectors` rows from the entity's articles and rebuilds the `targeted_sectors` cache (`services/sector_links.py`). |
| `external_feed` | The ransomware.live sync (`intelligence/ransomware_sync.py`) |
| `seed` | Reserved for seeded reference data; nothing writes it. |

Rules:
- **Recording never blocks the edit.** `record_claim` (`services/claim_provenance.py`) returns a bool and catches its own errors.
- **Agreement is computed, never stored.** `get_entity_claims` compares claims with the current value on read; losing claims stay as history.

Fields with a value but no claim return in `unsourced_fields`, marked unsourced.

Claims merge on `claim_key` (entity + field + value + source + article). A nightly sync that repeats a value only updates its timestamp. Different sources or articles stay separate rows, and their count is the agreement count the profile shows.

## Backend endpoints

All paths are under `/api`.

| Endpoint | Returns |
|---|---|
| `GET /entities/{type}/{id}/provenance` | each tracked field's claims with article, feed and feed reliability grade, plus `unsourced_fields` |
| `GET /entities/{type}/{id}/infrastructure` | claimed and reported-alongside observables |
| `GET /entities/{type}/{id}/context` | the Context section's source blocks and the header's context badges |
| `GET /entity-relationships/claims/{type}/{id}` | which enrichment sources claim each connection, and the names they gave that resolved to nothing |
| `GET /engine/entities/{type}/{id}/whats-new` | recent developments for the assessment block |
| `GET /intelligence/pivot/{type}/{id}` | the entity, related entities and entries |
| `GET /intelligence/graph/{type}/{id}` | graph nodes and typed edges |
| `GET /intelligence/timeline/{type}/{id}` | correlation events |
| `/entity-relationships` | list, create, update, confirm, reject |
| `/entity-notes` | notes CRUD |
| `GET /export/entities/{type}/{id}`, `POST /export/entities/bulk` | markdown export (bulk returns a ZIP) |

Each type also has CRUD, merge, duplicates and merge-suggestion endpoints.

Pivot and graph responses are cached in Redis under `intelfeed:corr:pivot3:*` and `intelfeed:corr:graph3:*` for `correlation_cache_ttl_seconds`. After changing either response shape, flush `intelfeed:corr:*`.
