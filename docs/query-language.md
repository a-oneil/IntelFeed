# Query Language Reference

A comprehensive guide to IntelFeed's unified query syntax, used across the search bar, command palette, and saved searches. Learn to compose queries that seamlessly search free text and structured intelligence entities.

---

## Table of Contents

1. [Quick Reference](#quick-reference)
2. [Syntax Fundamentals](#syntax-fundamentals)
3. [Field Filters](#field-filters)
4. [Boolean Operators](#boolean-operators)
5. [Ranges and Comparators](#ranges-and-comparators)
6. [Wildcards](#value-wildcards)
7. [How Queries Route](#how-queries-route)
8. [The Search Surface](#the-search-surface)
9. [Worked Examples](#worked-examples)
10. [Saved Searches](#saved-searches)
11. [Entity Pivot Links](#entity-pivot-links)
12. [Tips & Limitations](#tips--limitations)

---

## Quick Reference

### Operators & Syntax

| Operator | Usage | Example |
|----------|-------|---------|
| `AND` | Both terms must match (any case) | `ransomware AND APT29` |
| `OR` | Either term can match (any case) | `APT28 OR APT29` |
| `NOT` | Exclude matching results (any case; field filters only — negated free text is ignored) | `NOT tag:noise` |
| `()` | Grouping for precedence | `(APT28 OR APT29) AND CVE` |
| `""` | Exact phrase match | `"zero day exploit"` |
| `:` | Field filter separator | `threat_actor:APT29` |
| `*` | Wildcard in a **value** (not in free text) | `cve:CVE-2024-*` |
| `>`, `>=`, `<`, `<=` | Range comparators | `cve.cvss:>9.0` |
| `..` | Inclusive range | `date:2025-01..2025-06` |

### Core Fields

18 entry fields, 99 entity fields, and `sort:` — every one of them appears below.
The grouping follows `frontend/src/components/search/queryFields.ts`, the same file
that drives the in-app autocomplete and the syntax reference card. The authority for
what actually parses is `ENTRY_FIELDS` / `ENTITY_FIELDS` in
`backend/app/search/query_planner.py`; an unrecognised field is not an error — its
value is searched as free text, and the name comes back in `unknown_fields` so the
search page can flag it.

| Field | Type | Example |
|-------|------|---------|
| **Entry Fields** | | |
| `title` | text | `title:ransomware` |
| `content` | text | `content:"exploit kit"` |
| `author` | text | `author:Shodan` |
| `feed` | text (feed name) | `feed:"Dark Reading"` |
| `category` | text (feed folder) | `category:"Vendor Blogs"` |
| `tag` | exact | `tag:critical` |
| `type` | exact | `type:rss`, `type:youtube`, `type:telegram` |
| `media` | exact | `media:video` |
| `lang` | exact | `lang:en`, `lang:es` |
| `url` | substring | `url:github.com` |
| `words` | numeric | `words:>1500`, `words:500..2000` |
| `date` | timestamp | `date:>=2025-01-01` |
| `is` | status flag | `is:starred`, `is:unread`, `is:muted`, … ([8 values](#status-flags)) |
| `sort` | meta | `sort:newest`, `sort:radar`, … ([8 values](#sorting)) |
| **Signal & Source Fields** | | |
| `signal` | exact | `signal:under_reported`, `signal:kev_added` |
| `sector` | substring | `sector:healthcare` |
| `feed.reliability` | grade | `feed.reliability:B` |
| `feed.timeliness` | grade | `feed.timeliness:A` |
| `feed.relevance` | grade | `feed.relevance:C` |
| **Entity Fields — CVE** | | |
| `cve` | entity | `cve:CVE-2024-1234` |
| `cve.severity` | property | `cve.severity:critical` |
| `cve.cvss` | numeric | `cve.cvss:>=9.0` |
| `cve.kev` | boolean | `cve.kev:true` |
| `cve.epss` | numeric | `cve.epss:>0.5` |
| `cve.epss_percentile` | numeric | `cve.epss_percentile:>0.9` |
| `cve.poc` | numeric | `cve.poc:>0` |
| `cve.exploit` | exact | `cve.exploit:kev` |
| `cve.product` | join | `cve.product:fortios` |
| **Entity Fields — CWE (weaknesses)** | | |
| `cwe` | entity | `cwe:CWE-79` |
| `cwe.abstraction` | property | `cwe.abstraction:Base` |
| `cwe.usage` | property | `cwe.usage:Allowed` |
| `cwe.parent` | property | `cwe.parent:CWE-707` |
| `cwe.kind` | property | `cwe.kind:weakness` |
| `cwe.deprecated` | boolean | `cwe.deprecated:false` |
| **Entity Fields — Observables (IOCs)** | | |
| `observable` / `ioc` | entity | `observable:evil.com` |
| `observable.kind` | property | `observable.kind:sha256` |
| `observable.role` | property | `observable.role:c2` |
| `observable.status` | property | `observable.status:active` |
| **Entity Fields — ATT&CK** | | |
| `ttp` | entity | `ttp:T1059` |
| `ttp.tactic` | property | `ttp.tactic:execution` |
| `ttp.platform` | array | `ttp.platform:Windows` |
| `ttp.data_source` | array | `ttp.data_source:process` |
| `ttp.domain` | exact | `ttp.domain:ics` |
| `ttp.subtechnique` | boolean | `ttp.subtechnique:true` |
| `ttp.deprecated` | boolean | `ttp.deprecated:false` |
| `mitigation` | entity | `mitigation:M1234` |
| **Entity Fields — Actors, Malware, Tools** | | |
| `threat_actor` | entity | `threat_actor:APT29` |
| `threat_actor.country` | property | `threat_actor.country:Russia` |
| `threat_actor.motivation` | property | `threat_actor.motivation:espionage` |
| `threat_actor.sector` | array | `threat_actor.sector:healthcare` |
| `threat_actor.type` | property | `threat_actor.type:ransomware` |
| `threat_actor.mitre` | property | `threat_actor.mitre:G0016` |
| `malware` | entity | `malware:Emotet` |
| `malware.type` | property | `malware.type:trojan` |
| `malware.sector` | array | `malware.sector:finance` |
| `malware.mitre` | property | `malware.mitre:S0367` |
| `tool` | entity | `tool:Mimikatz` |
| `tool.type` | property | `tool.type:framework` |
| `tool.platform` | array | `tool.platform:Windows` |
| `tool.mitre` | property | `tool.mitre:S0002` |
| **Entity Fields — Geography, Supply Chain** | | |
| `country` | entity | `country:"North Korea"` |
| `country.region` | property | `country.region:Asia` |
| `country.iso` | property | `country.iso:RU` |
| `vendor` | entity | `vendor:Microsoft` |
| `vendor.type` | property | `vendor.type:software` |
| `product` | entity | `product:Exchange` |
| `product.type` | property | `product.type:firewall` |
| `product.vendor` | join | `product.vendor:Cisco` |
| **Entity Fields — Detection & Reporting** | | |
| `rule` | entity | `rule:backdoor` |
| `rule.type` | property | `rule.type:sigma` |
| `rule.severity` | property | `rule.severity:high` |
| `rule.data_source` | array | `rule.data_source:sysmon` |
| `rule.tactic` | array | `rule.tactic:persistence` |
| `rule.tag` | array | `rule.tag:attack.t1059` |
| `rule.draft` | boolean | `rule.draft:false` |
| `rule.license` | property | `rule.license:DRL` |
| `campaign` | entity | `campaign:"Volt Typhoon"` |
| `campaign.status` | property | `campaign.status:active` |
| `intel_report` | entity | `intel_report:quarterly` |
| `intel_report.status` | property | `intel_report.status:draft` |
| `intel_report.type` | property | `intel_report.type:threat_brief` |
| `intel_report.tlp` | property | `intel_report.tlp:amber` |
| `pir` | entity | `pir:"APT capability"` |
| `pir.priority` | property | `pir.priority:high` |
| `pir.category` | property | `pir.category:Strategic` |
| **Entity Fields — Notes** | | |
| `note` | entity | `note:fortibleed` |
| `note.tag` | array | `note.tag:followup` |
| `note.type` | property | `note.type:analysis` |
| `note.about` | property | `note.about:cve`, `note.about:entry` |
| `note.pinned` | boolean | `note.pinned:true` |
| **Entity Fields — Ransomware** | | |
| `ransomware_victim` | entity | `ransomware_victim:Finastra` |
| `ransomware_victim.sector` | property | `ransomware_victim.sector:healthcare` |
| `ransomware_victim.domain` | property | `ransomware_victim.domain:acme.com` |
| `ransomware_victim.group` | join | `ransomware_victim.group:lockbit` |
| **Catalogue Suffixes** ([not on every type](#catalogue-suffixes)) | | |
| `<entity>.articles` | numeric | `threat_actor.articles:>100` |
| `<entity>.seen` | date | `malware.seen:>2026-01-01` |
| `<entity>.first_seen` | date | `ttp.first_seen:>2026-06` |
| `<entity>.review` | boolean | `threat_actor.review:true` |
| `<entity>.via` | exact | `cve.via:ai_extraction` |

---

## Syntax Fundamentals

### Free-Text Search

The default behavior for bare words: Meilisearch searches `title`, `content_text`, `summary`, `author`, `feed_title`, and `tags` for all matches. No Boolean logic required.

```
ransomware
zero day exploit
```

Results ranked by relevance, with typo tolerance enabled (1 typo for words ≥4 chars, up to 2 typos for words ≥8 chars).

### Quoted Phrases

Force exact phrase matching:

```
"cobalt strike beacon"
title:"initial access broker"
```

Quoted phrases are not tokenized—the system looks for the exact substring.

### Tokenization & Stemming

- Free-text terms are split on whitespace and punctuation.
- **No stemming:** `run` will not match `running`. Meilisearch relies on typo tolerance and proximity matching.
- **Highlighting:** Matching segments in results are wrapped in `<mark>` tags.

### Implicit AND

Adjacent terms automatically AND:

```
ransomware attack APT29
```

Equivalent to:

```
ransomware AND attack AND APT29
```

---

## Field Filters

Entry and entity fields use the `field:value` syntax. Field names must be lowercase (`Actor:APT29` is not recognized as a filter). Values match case-insensitively — except quoted entity values, which require an exact, case-sensitive match (see [Limitations](#limitations)).

**A value stops at the first space.** `feed:Dark Reading` is parsed as `feed:Dark` plus the free-text term `Reading`, which quietly returns the wrong thing rather than failing. Always quote a multi-word value: `feed:"Dark Reading"`, `country:"North Korea"`, `note:"initial access broker"`.

### Entry Fields

#### Text Search Fields

**`title:`, `content:`, `author:`**

Search within specific document fields:

```
title:exploit
content:"buffer overflow"
author:Shodan
```

These integrate with Meilisearch's full-text matching. Use quotes for exact phrases.

#### Feed Selection

**`feed:`**

Filter by feed name (substring match, case-insensitive internally):

```
feed:"Dark Reading"
feed:RSS
```

The system resolves feed names to `feed_id` automatically. A single `feed:` filter that matches several feeds ORs their IDs together; separate `feed:` filters AND together like any other filters.

**`category:`**

Filter by the *folder* a feed lives in, rather than the feed itself (substring, case-insensitive):

```
category:"Vendor Blogs"
category:news
```

Resolved to the set of feeds in matching categories, then to `feed_id` clauses — same mechanism as `feed:`.

**`feed.reliability:`, `feed.timeliness:`, `feed.relevance:`**

Filter by the source's Admiralty-code letter grade, set per feed in the feed editor. These are exact grade matches, not numeric comparisons — `feed.reliability:>B` does not work:

```
feed.reliability:A
feed.timeliness:B
feed.relevance:C
```

Ungraded feeds match no grade filter.

#### Categorical Filters

**`tag:`, `type:`, `media:`, `lang:`**

Exact match, or a wildcard pattern against the values actually indexed:

```
tag:critical
tag:critical*           # every tag starting "critical"
type:rss
type:youtube
type:telegram
media:image
lang:en
```

A wildcard here is resolved against the attribute's real values before the search
runs, so `tag:apt*` becomes "any of the tags that start with apt" rather than a
filter for a tag literally named `apt*`.

Valid values:
- `type`: feed adapter type — `rss`, `atom`, `youtube`, `podcast`, `reddit`, `github_releases`, `github_advisories`, `github_repo`, `nvd`, `mastodon`, `bluesky`, `telegram`, `web_scraper`
- `media`: `image`, `video`, `audio`, `document`
- `lang`: ISO 639-1 codes (`en`, `es`, `fr`, `zh`, `ja`, etc.)
- `tag`: any tag name (managed in the tag manager; tag names also autocomplete after `tag:`)

**`url:`, `words:`**

```
url:github.com          # Article link contains this substring (case-insensitive)
url:https://github*     # Wildcard: the pattern is anchored, not a substring
words:>1500             # Long reads
words:<300              # Stubs and link-only posts
words:500..2000         # Inclusive range
```

`url:` is a substring match against the article link, resolved in PostgreSQL. A
value containing `*` switches to anchored pattern matching — so `url:github*`
means "the link starts with github" (nothing does; links start with `https://`),
while plain `url:github` still matches anywhere in the URL. `words:` filters the indexed `word_count` attribute and accepts the same comparators as `date:`.

#### Signal and Sector

**`signal:`**

Filter by the signal engine's *reason* for scoring an entry — the same reasons rendered on the "Why" card in the Priority Queue:

```
signal:under_reported     # Few sources carried it relative to its importance
signal:kev_added          # A CVE in the entry joined CISA KEV
signal:novel_entity       # Introduced an entity not seen before
signal:correlation_event  # Fired a correlation between tracked entities
signal:pir_match          # Matched an intelligence requirement
signal:critical_cvss      # Carries a critical-severity CVE
signal:source_convergence # Independent sources converged on it
signal:feed_echo          # Repeat of something already covered
signal:new_pairing        # First time two entities appeared together
signal:epss_high          # High EPSS exploitation probability
signal:detection_content  # Contains deployable detection content
signal:scoop              # First source to report it
```

Pair with `sort:radar` to read the queue the engine would build:

```
signal:under_reported sort:radar
```

**`sector:`**

Filter by a sector *mentioned in the article* (substring, case-insensitive) — distinct from `threat_actor.sector:` / `malware.sector:`, which describe who an entity targets:

```
sector:healthcare
sector:"critical infrastructure"
```

#### Status Flags

**`is:`**

Filter by user state (persisted per-user in the database):

```
is:starred       # Entries you've starred
is:read          # Entries you've marked as read
is:unread        # Entries you haven't read
is:bookmarked    # Entries you've bookmarked
is:noted         # Entries with notes attached
```

Three further values describe the entry rather than your relationship to it, and are answered from PostgreSQL:

```
is:muted         # From a muted feed (hidden from the triage queue)
is:translated    # Machine-translated by LibreTranslate
is:image         # Carries a hero image
```

Negate to exclude:

```
NOT is:read       # Unread entries
is:unread         # Equivalent shorthand
```

`NOT` on the three PostgreSQL-backed values only subtracts from a set another filter has already established — `NOT is:translated` on its own matches everything (see [Limitations](#limitations)).

#### Date Filtering

**`date:`**

Every date literal names a **span**, not an instant — `2025` is a year, `2025-01` is a month, `2025-01-15` is a day — and each comparison resolves against the right end of that span:

```
date:>=2025-01-01              # On or after Jan 1
date:>2025-01-01               # Strictly after Jan 1 (excludes Jan 1 itself)
date:<=2025-12-31              # On or before Dec 31 (includes all of Dec 31)
date:<2025-12-31               # Before Dec 31 (excludes Dec 31)
date:2025-01-01                # That one day
date:2025-01                   # All of January
date:2025                      # All of 2025
date:2025-01..2025-06          # Jan 1 through the last day of June, inclusive
date:2025-01-15..2025-03-20    # Inclusive of both endpoints
```

Dates are parsed as `YYYY`, `YYYY-MM` or `YYYY-MM-DD` and converted to Unix timestamps in UTC. A range includes every entry published on its final day, and a bare month or year covers the whole of it. An unparseable date is ignored rather than matching nothing. `date:` filters cannot be negated with `NOT`.

#### Sorting

**`sort:` (meta field)**

Controls result ordering (does not filter, only sorts):

```
sort:newest      # Order by published_at descending
sort:oldest      # Order by published_at ascending
sort:relevance   # By Meilisearch relevance score (default)
sort:title_asc   # Order by title A-Z
sort:title_desc  # Order by title Z-A
sort:shortest    # Order by word count ascending
sort:longest     # Order by word count descending
sort:radar       # Order by the signal engine's priority_score, highest first
```

Any other `sort:` value is ignored and results stay relevance-ordered. The first seven work in both execution paths (Meilisearch and the PostgreSQL fallback); in the PG path `relevance` degrades to newest-first since no relevance scores are available there.

**`sort:radar`** is the exception: `priority_score` is a PostgreSQL column the search index does not carry, so a query that sorts by it *always* takes the PostgreSQL path, whatever else it contains. Two consequences follow:

- Unscored entries are excluded outright — an entry with no `priority_score` has no place in a ranked list.
- Free-text terms are not applied on this path; `sort:radar` is for reading a filtered queue (`signal:kev_added sort:radar`), not for ranking a text search.

Ties break on `published_at` descending. This is the same ordering the Priority Queue renders.

### Entity Fields

Entity fields query structured intelligence databases (PostgreSQL). A single query can combine entry and entity filters.

#### Core Entity Types

**`cve:`, `cwe:`, `observable:` (alias `ioc:`), `threat_actor:`, `ttp:`, `malware:`, `country:`, `tool:`, `vendor:`, `product:`, `mitigation:`, `campaign:`, `ransomware_victim:`, `rule:`, `intel_report:`, `pir:`, `note:`**

```
cve:CVE-2024-1234                # CVE ID
threat_actor:APT29                      # Threat actor name
ttp:T1059                        # MITRE ATT&CK technique
malware:Emotet                   # Malware family name
country:Russia                   # Country name
rule:my_detection_rule           # Detection rule title
pir:"APT Capability Assessment"  # Intelligence requirement title (quote multi-word values)
```

`note:` is the odd one out — it matches a note's title *or* its body, since that is how you look for something you wrote. See [Entity Properties](#entity-properties) for the note grammar and [Notes as Results](#notes-as-results) for the result shape.

Unquoted values match as case-insensitive substrings, and also search aliases (`threat_actor`, `malware`, `country`, `tool`, `vendor`, `product`, `ransomware_victim`) and technique names (`ttp`). Quoted values require an exact, case-sensitive match against the primary name and skip alias resolution.

**Wildcard matching:**

```
cve:CVE-2024-*          # All CVEs published in 2024
ttp:T1566*              # All initial access techniques (T1566, T1566.001, etc.)
malware:Emotet*         # Emotet and variants
threat_actor:APT*              # Any threat actor name starting with APT
```

#### Entity Properties

Most entity types carry a set of `<type>.<property>` filters (`mitigation` is the exception — it has only the catalogue suffixes below). They narrow the entities themselves; the entries returned are then the entries linked to whatever survived.

**CVE — severity, and whether anyone is actually exploiting it**

```
cve.severity:critical        # critical | high | medium | low
cve.cvss:>=9.0               # CVSS base score
cve.kev:true                 # In the CISA Known Exploited Vulnerabilities catalog
cve.epss:>0.5                # EPSS exploitation probability (0.0-1.0)
cve.epss_percentile:>0.9     # EPSS percentile among all CVEs
cve.poc:>0                   # Count of public GitHub proof-of-concept repos
cve.exploit:kev              # Exploitation status
cve.product:fortios          # Affected product OR vendor, from NVD CPE data
```

`cve.severity` and `cve.cvss` say how bad a flaw could be; the rest say whether it is being used. `cve.product:` resolves through the `cve_affected` table and matches either the CPE vendor or the CPE product, since someone typing "fortinet" means either.

**CWE — the weakness behind the vulnerability**

```
cwe:CWE-79                   # By ID, name, or alternate term
cwe.abstraction:Base         # Pillar | Class | Base | Variant — the rung on the ladder
cwe.usage:Allowed            # MITRE's own mapping guidance for this ID
cwe.parent:CWE-707           # Direct parent in the catalogue lineage
cwe.kind:weakness            # weakness | category
cwe.deprecated:false         # Exclude IDs MITRE has retired
```

`cwe.abstraction:` is the one worth knowing. A Pillar is a whole family and a
Variant is one concrete mistake; `cwe.abstraction:Base` is usually the level a
detection or a secure-coding rule is actually written at. `cwe.usage:` carries
MITRE's guidance on whether an ID is even appropriate to map to — several
heavily-used IDs are marked Discouraged.

**Observables — the IOC ledger**

`observable:` and `ioc:` are the same field, and so are their properties —
`ioc.kind:`, `ioc.role:` and `ioc.status:` behave identically to the
`observable.*` forms below. Use whichever you type faster.

```
observable:evil.com          # By value — defanged input (evil[.]com) is normalised
observable.kind:sha256       # ipv4 | ipv6 | domain | url | uri_path | email | md5 |
                             # sha1 | sha256 | ja3 | ja4 | cert_fingerprint | cmdline |
                             # registry | path | mutex | named_pipe | service_name |
                             # user_agent | script
observable.role:c2           # c2 | delivery | payload | phishing | exfil | exploit | scanning
observable.status:active     # active | aging | expired — derived from decayed confidence
```

`observable.status:` is a lifecycle read, not a judgement: `aging` and `expired`
mean the confidence has decayed past a threshold since the last sighting, which
for a rotating IP is expected. Hashes and host artifacts never decay, so they
stay `active` indefinitely.

**ATT&CK — narrowing a technique to the telemetry you have**

```
ttp.tactic:execution         # ATT&CK tactic
ttp.platform:Windows         # Windows | Linux | macOS | Containers | ...
ttp.data_source:process      # Required telemetry, substring-matched
ttp.domain:enterprise        # enterprise | mobile | ics
ttp.subtechnique:true        # Sub-techniques only (T1059.001, not T1059)
ttp.deprecated:false         # Exclude techniques MITRE has retired
```

**Actors, malware and tools**

```
threat_actor.country:China          # Origin country
threat_actor.motivation:espionage   # espionage | financial | hacktivism | disruption
threat_actor.sector:healthcare      # Sector the actor targets
threat_actor.type:ransomware        # Actor classification
threat_actor.mitre:G0016            # MITRE ATT&CK group ID
malware.type:ransomware             # Malware classification
malware.sector:finance              # Sector the family targets
malware.mitre:S0367                 # MITRE ATT&CK software ID
tool.type:framework                 # Tool classification
tool.platform:Windows               # Platforms the tool runs on
tool.mitre:S0002                    # MITRE ATT&CK software ID
```

**Geography and supply chain**

```
country.region:Europe        # Geographic region
country.iso:RU               # ISO 3166 alpha-2 code
vendor.type:software         # Vendor classification
product.type:firewall        # Product classification
product.vendor:Cisco         # Products made by a given vendor
```

**Detection rules**

```
rule.type:sigma              # sigma | yara | elastic_ql | splunk_spl | panther | nuclei | kql | crowdstrike_ql | snort_suricata
rule.severity:high           # critical | high | medium | low | info
rule.data_source:sysmon      # Log source the rule requires
rule.tactic:persistence      # ATT&CK tactic the rule covers
rule.tag:attack.t1059        # Rule tag
rule.draft:true              # Drafts only
rule.license:DRL             # Upstream license
```

`rule.data_source:` is the same field the telemetry-coverage view reads, so a query can now ask what the coverage board shows.

**Reports, campaigns and requirements**

```
campaign.status:active               # active | monitoring | closed
intel_report.status:draft            # Report status
intel_report.type:threat_brief       # Report template type
intel_report.tlp:amber               # clear | green | amber | red
pir.priority:critical                # critical | high | medium | low
pir.category:Strategic               # strategic | operational | tactical
```

**Notes**

```
note:fortibleed              # Title or body of any note
note.tag:followup            # Note tag
note.type:analysis           # annotation | analysis | action_taken | false_positive | context
note.about:threat_actor      # Notes on entities of this type
note.about:entry             # Notes attached to an article
note.about:standalone        # Notes attached to nothing
note.pinned:true             # Pinned notes
```

`note:` spans both note tables at once, so one field reaches everything you have written. It matches a note's title *or* its body, since that is how you look for something you wrote.

`note.about:` takes an entity kind — `threat_actor`, `malware`, `cve`, `ttp`, `campaign`, `vendor`, `product` — or one of two words for the other table: `entry` (a note on an article) and `standalone` (a note on nothing at all).

Two fields only make sense on one table, and say so rather than matching everything: `note.type:` and an entity value for `note.about:` apply to entity notes; `note.pinned:` and `note.about:entry` / `:standalone` apply to the other. Negation still reads correctly — `NOT note.type:analysis` keeps the notes that are not analysis notes, untyped ones included. The flip side is that some combinations are empty by construction: `note.pinned:true note.about:cve` can never match, and `note:baselining note.about:standalone` is empty if that note is attached to an article.

Because a note on an article carries that article, `note.about:entry` narrows the article stream too: the query returns the notes *and* the entries they hang off.

**Ransomware victims**

```
ransomware_victim.sector:manufacturing   # Victim sector
ransomware_victim.domain:acme.com        # Victim domain
ransomware_victim.group:lockbit          # Group that posted the victim on its leak site
```

`ransomware_victim.group:` matches the group name *as the leak site wrote it*, which is how someone searching a leak site types it.

#### Catalogue Suffixes

Five suffixes work across entity types rather than belonging to one:

```
threat_actor.articles:>100      # How much has been written about it
malware.seen:>2026-01-01        # Last seen in an article
ttp.first_seen:>2026-06         # First catalogued
threat_actor.review:true        # Flagged for curation
cve.via:ai_extraction           # How the record was created
```

- `.articles`, `.seen`, `.first_seen` — available on `ttp`, `threat_actor`, `malware`, `country`, `tool`, `vendor`, `product`, `mitigation`, `cwe`, `observable` and `ioc`. **Not** on `cve`, `campaign`, `rule`, `pir`, `intel_report`, `ransomware_victim` or `note`.
- `.review`, `.via` (extraction provenance) — available on `threat_actor`, `malware`, `cve`, `ttp`, `tool`.

The two lists differ, so `cve.via:ai_extraction` is valid while `cve.first_seen:` is not. An unrecognised field is not an error — its value is searched as free text — but it is no longer silent: the response lists the name in `unknown_fields` and the search page says so above the results, so a typo reads as a typo rather than as a plausible wrong answer.

Date suffixes take `YYYY-MM-DD` or `YYYY-MM`. A bare value means "on or after", since `seen:2026-01` is asking for recency; use `<` for "before".

#### Value Types

How a property's value is interpreted depends on its underlying column:

| Kind | Behaviour | Fields |
|------|-----------|--------|
| Boolean | `true`/`yes`/`1`/`y` and `false`/`no`/`0`/`n`. An unparseable value filters nothing rather than matching everything. | `cve.kev`, `ttp.subtechnique`, `ttp.deprecated`, `rule.draft`, `note.pinned`, `<entity>.review` |
| Array | Substring match against the joined elements, so `rule.data_source:process` finds "Process Creation". | `rule.data_source`, `rule.tactic`, `rule.tag`, `note.tag`, `threat_actor.sector`, `malware.sector`, `tool.platform`, `ttp.platform`, `ttp.data_source` |
| Date | `YYYY-MM-DD` or `YYYY-MM`; bare means "on or after". | `<entity>.seen`, `<entity>.first_seen` |
| Numeric | `>`, `>=`, `<`, `<=`, or bare equality. | `cve.cvss`, `cve.epss`, `cve.epss_percentile`, `cve.poc`, `<entity>.articles` |
| Join | Resolved through a second table, then folded back as an `IN (subquery)` so AND/OR/NOT still work. | `cve.product`, `ransomware_victim.group`, `product.vendor` |
| Exact | Whole-value equality, case-insensitive. A partial value matches nothing. | `note.type`, `note.about` |
| Two-column | Substring against either of two columns. | `note` (title or body) |
| Text | Case-insensitive substring; `*` wildcards supported. | Everything else |

---

---

## Boolean Operators

Explicit operators provide precise control over matching logic.

### AND (Conjunction)

All operands must match:

```
ransomware AND APT29
threat_actor:APT28 AND cve.cvss:>8.0
```

AND has higher precedence than OR, so `a OR b AND c` parses as `a OR (b AND c)`.

### OR (Disjunction)

At least one operand must match:

```
APT28 OR APT29
```

OR works between:
- bare text terms/phrases (`APT28 OR APT29` — run as separate searches and merged),
- text combined with grouping (`(APT28 OR APT29) AND ransomware` — expanded to `APT28 ransomware` and `APT29 ransomware`, then merged, so the `AND` is genuinely applied to both sides),
- filters of the *same* entity type (`threat_actor:APT28 OR threat_actor:APT29` — the conditions are OR'd in one SQL query and results unioned),
- filters of *different* entity types (`cve:* OR threat_actor:*` — linked entries are unioned),
- filterable entry fields (`tag:a OR tag:b`, `is:noted OR is:bookmarked` — combined into a single OR filter clause), including parenthesized AND groups (`(tag:a type:rss) OR tag:b`),
- an entry predicate and an entity predicate (switches the join to OR mode),
- the entry-scoped PostgreSQL fields (`signal:`, `sector:`, `url:`, `is:translated`/`is:image`) — these resolve to a *set of entry IDs* rather than a filter clause, so the disjunction is taken on the sets: `signal:under_reported OR signal:kev_added` returns 2,174 where the sides alone return 1,637 and 565 (28 entries carry both). Cross-field works too — `signal:kev_added OR sector:healthcare` unions. Negation inside such an OR goes through the complement: `NOT signal:a OR signal:b` excludes exactly the entries matching `a` but not `b`, since `¬(¬A ∪ B) = A \ B`.
- `feed:` and the other feed-scoped PostgreSQL filters (`category:`, `feed.*:`, `is:muted`) — `feed:"Reddit Digest" OR feed:"Red Canary"` returns the union of both feeds, and mixing them with a text term (`ransomware OR feed:"Red Canary"`) unions too. Repeating one without an operator still ANDs — `feed:A feed:B` matches nothing, since no entry belongs to two feeds. `is:muted` is in this family too, so `is:muted OR tag:morning-brief` really is the union of both.

Remaining OR limitations:
- An AND sub-expression of *entity* fields inside an OR **returns nothing**. `(threat_actor:APT29 AND threat_actor.country:Russia) OR threat_actor:APT28` yields 0 even though each side alone matches (261 and 360): conditions on one entity type collect into a single AND group whatever operator separates them, so the query becomes "APT29 AND Russia AND APT28", which nothing satisfies. The same shape built from entry filter fields works correctly.
- Mixing a bare text term with an *index* filter under one OR (`ransomware OR tag:a`) runs as two searches and unions them, so grouping is preserved — but the union's result count is an upper bound (see [Result Limits](#result-limits--pagination)).
- Mixing a text term with an *entry-scoped* PostgreSQL filter (`ransomware OR signal:kev_added`) still intersects. Those fields narrow by entry ID after the index search rather than inside it, so there is no branch for the union to happen between. `feed:`, `category:`, `is:` and the index filters have no such restriction.

### NOT (Negation)

Exclude matching results:

```
NOT tag:noise
malware AND NOT malware:Emotet
```

**NOT only works on field filters** — entity fields (`threat_actor:`, `cve:`, …) and filterable entry fields (`tag:`, `type:`, `media:`, `lang:`, `is:`, `feed:`). Negating bare text terms or the text-search fields (`title:`, `content:`, `author:`) is not supported by the search backend: the negated term is dropped from the query entirely (it neither excludes nor matches — `ransomware NOT phishing` behaves like `ransomware`). `date:` filters also cannot be negated (the `NOT` is ignored and the date filter still applies).

NOT applies to the following atom. Use parentheses for complex negations:

```
NOT (threat_actor:APT28 AND cve.cvss:>9.0)  # Neither APT28 nor high CVSS
```

Note: negation distributes to each condition inside the parentheses (`NOT (a AND b)` behaves as `(NOT a) AND (NOT b)`), matching the "neither" reading above. `NOT (a OR b)` follows De Morgan's law and behaves as `(NOT a) AND (NOT b)` as well — excluding entries that match either condition.

### Operator Precedence

1. **Parentheses** (highest)
2. **NOT**
3. **AND** (implicit or explicit)
4. **OR** (lowest)

Examples:

```
a OR b AND c              → a OR (b AND c)
(a OR b) AND c            → (a OR b) AND c
NOT a AND b               → (NOT a) AND b
a OR NOT b OR c           → a OR (NOT b) OR c
```

---

## Ranges and Comparators

### Numeric Ranges

Numeric entity fields (currently only `cve.cvss`) support comparison operators and inclusive ranges:

```
cve.cvss:>9.0               # Greater than
cve.cvss:>=8.5              # Greater than or equal
cve.cvss:<7.0               # Less than
cve.cvss:8.5..9.5           # Inclusive range
```

Comparators only work with numeric values. Text-valued fields like `rule.severity` and `pir.priority` are exact-match only (`rule.severity:high`) — `rule.severity:<=medium` will not work.

### Date Ranges

Two syntaxes:

```
date:>=2025-01-01           # Comparison syntax
date:2025-01..2025-06       # Inclusive range
date:2025-01-15..2025-03-20 # Full-date range
```

Both parse dates as UTC and create `published_at` filters in Meilisearch.

### Value Wildcards

`*` in a field **value** makes it a pattern:

```
cve:CVE-2024-*              # Any CVE from 2024
ttp:T1566*                  # T1566, T1566.001, etc.
threat_actor:APT*           # Any actor starting with APT
threat_actor:Laz*rus        # Wildcards work in the middle too
tag:critical*               # Any tag starting "critical"
feed:Krebs*                 # Any feed whose title starts "Krebs"
```

Every field that takes a value accepts one, but they resolve in three different
places, which changes what "partial" means:

| Fields | How the pattern resolves |
|--------|--------------------------|
| Entity fields (`threat_actor:`, `cve:`, `malware:`, …) | SQL `ILIKE` against the name, aliases and secondary columns |
| `feed:`, `category:`, `sector:`, `url:`, `signal:` | SQL `ILIKE` in PostgreSQL — **anchored**, unlike the plain substring these do without a `*` |
| `tag:`, `type:`, `media:`, `lang:` | Matched against the attribute's indexed values, then expanded to an OR of the ones that hit |

**Not in free text.** The search index has no wildcard operator, so `*` in a bare
term or in `title:`/`content:`/`author:` is not a pattern. A *trailing* `*` is
simply dropped (`ransom*` searches `ransom`, which already prefix-matches, so it
finds "ransomware"). A `*` anywhere else is treated as a word separator, which is
rarely what you want — `ran*ware` searches for "ran" AND "ware", not "ransomware".
Search the prefix on its own instead.

---

## How Queries Route

IntelFeed uses a **hybrid backend**: Meilisearch for full-text (entry) queries, PostgreSQL for entity (structured) queries. See the [query routing diagram](diagrams/query-language-routing.md) for the full flow.

### Query Classification

The **query planner** walks your AST and classifies each field into one of three lanes:

- **Indexed entry fields** (`title`, `content`, `author`, `feed`, `tag`, `type`, `media`, `lang`, `words`, `date`, most `is:` values) → Meilisearch filter clauses.
- **PostgreSQL entry fields** (`category`, `signal`, `sector`, `url`, `feed.reliability`, `feed.timeliness`, `feed.relevance`, and `is:muted` / `is:translated` / `is:image`) → resolved against PostgreSQL. None of these live in the search index, and resolving them in the database avoids re-indexing ~95k documents to add them.
- **Entity fields** (`cve`, `threat_actor`, `ttp`, `malware`, `country`, `tool`, `vendor`, `product`, `mitigation`, `campaign`, `ransomware_victim`, `rule`, `intel_report`, `pir`, `note` + all sub-fields) → PostgreSQL entity tables. `note` is the one type backed by two tables — the conditions are compiled once for each and the results merged.
- **Text terms** (bare words, phrases) → Meilisearch **and**, when the query carries no explicit entity filter, a cross-entity name sweep in PostgreSQL (`search_all_entities`) that also covers analyst notes.

### Execution

1. **Feed resolution:** `feed:` and the feed-scoped PostgreSQL filters (`category:`, `feed.*:`, `is:muted`) resolve to a set of feed IDs. There are only a few hundred feeds, so these become ordinary Meilisearch `feed_id` clauses.
2. **Entry-scoped PostgreSQL filters:** `signal:`, `sector:`, `url:`, `is:translated`, `is:image` resolve to a set of *entry* IDs. Multiple such filters intersect.
3. **Entity Query:** PostgreSQL queries entity tables and junction tables to find linked entry IDs.
4. **Intersection:** The PostgreSQL entry-ID set and the entity-linked entry-ID set intersect — a `signal:` filter narrows exactly the way an entity join does.
5. **Entry Query:** Meilisearch searches free text and applies the indexed filters, constrained to the surviving IDs.
6. **Join mode:**
   - **AND** (default): Only entries in *both* result sets.
   - **OR** (only if you use `OR` between entry and entity predicates): Union of both result sets.

### When the query bypasses Meilisearch

The search endpoint reads entries straight from PostgreSQL, skipping the index entirely, in three cases:

- **`sort:radar`** — the ordering column lives in PostgreSQL (see [Sorting](#sorting)).
- **Nothing to search** — there is an entry-ID constraint but no text term and no indexed filter, e.g. an entity-only query or a bare `signal:under_reported`.
- **Large ID sets** — more than 800 constraining entry IDs. Passing tens of thousands of IDs as a Meilisearch filter string is what used to happen, and it silently returned zero.

On this path counts are exact rather than estimated, `sort:relevance` degrades to newest-first, and the response carries no `facetDistribution` — facets come from Meilisearch, so the rail's entry facets go quiet on a purely PostgreSQL-backed query.

### Performance Implications

- **Fast:** Free-text only (Meilisearch is optimized for this).
- **Medium:** Single entity type with a few entry filters; a PostgreSQL entry filter costs one indexed `IN` list.
- **Slower:** Complex entity queries with range operators or large result sets.

Example slow query:

```
threat_actor:* AND date:>=2025-01-01 AND cve.cvss:>8.0
```

(Multiple entity groups plus entry filters; the join runs before the index query.)

### Result Limits & Pagination

- Entry results: default 20 per page, up to 500 per request.
- Entity results: `entity_limit` defaults to **200**, max 500 — how many matched entities the payload carries. Entities are returned most-covered-first (by article count) with a stable tiebreaker, and the linked *entries* are derived from every match rather than from this page, so the cap changes what the intelligence panel shows without changing which articles come back.
- Per-type rendering: `entity_group_limit` defaults to **25**, max 500 — how many rows of each entity type the payload carries.
- `entities.counts` is computed **before** the per-type trim, so the facet rail can say "Threat Actors 57" while the payload holds the first 25. (Trimming first is what once answered a plain-text query with ten actors and nothing else: a global slice after a cross-type relevance sort keeps whichever type ranks first and drops the others entirely.)
- Total hit counts are estimates from Meilisearch (`estimatedTotalHits`); on the PostgreSQL path they are exact.
- A query whose text half contains an `OR` runs one search per alternative and unions the pages here rather than in the index. The total is then the **sum** of the branches' estimates, so entries matching more than one branch are counted twice — an upper bound, deliberately stable across pages rather than drifting as you page. Each branch is fetched to at most 1000 rows, which bounds how deep such a query can page.
- Mixed entry+entity queries pass at most **500** linked-entry IDs into the Meilisearch filter, while the switch to PostgreSQL only trips above **800**. Between those two numbers the ID list is silently truncated to the first 500, so a query whose entity half matches 501–800 entries can under-report. Narrowing the entity half (or pushing it past 800, e.g. by dropping the text term) avoids the window.

### Direct Matches vs Mentions

Entity results carry a `match_kind`:

- **`direct`** — the query hit the entity's own identity: its name, an alias, or the identifier it is catalogued under (`technique`, `cve_id`, `mitre_id`).
- **`mention`** — the query hit something the entity merely *says*: a description, tags, a tactic, a rule body.

Titles are judged separately. A detection rule or report title is a sentence describing what the thing does — "Detects a backdoor DLL used by LockBit 3.0 affiliates" contains "lockbit", but the rule is not LockBit. A title counts as identity only when the query is what the title opens with.

Results from an explicit field filter are `direct` by construction: `cve.kev:true` returns the KEV CVEs, which *are* the answer, not entities that happen to mention the query. The search page groups direct matches above per-type mention groups, and the facet rail can filter on the distinction.

Notes are the one exception — they carry `match_field` but no `match_kind` when they come from a `note:` filter, so those rows land under Mentions. See [Limitations](#limitations).

### Notes as Results

Your own writing is searchable alongside the intelligence, from two directions: free text finds it in the cross-entity sweep, and the [`note:` grammar](#entity-properties) filters it directly.

Both note tables come back as one **`note`** result type, discriminated by `note_source`:

| `note_source` | Where it lives | Carries |
|---------------|----------------|---------|
| `note` | On an article, or standalone | `entry_id`, `entry_title`, `is_pinned` |
| `entity_note` | On an actor, malware, CVE, TTP, campaign, vendor or product | `entity_type`, `entity_id`, `entity_name`, `note_type` |

Every note result also carries `title`, `tags` and `match_field`.

Three details worth knowing:

- **The description is a snippet, not a preamble.** Every other entity leads with a description whose first line says what it is, so a head truncation reads fine. A note is prose — the sentence that matched is usually nowhere near the top — so the description is a ~190-character window *centred on the match*, with markdown and pasted HTML flattened to readable text. A query made only of property filters (`note.pinned:true`) has no term to centre on, so it falls back to the opening.
- **An entity note's title is optional.** Without one, the row is named for its subject: "Note on CVE-2026-20262".
- **On free-text queries, a title hit is `direct` and a body or tag hit is `mention`** — the same distinction every other entity draws.

Notes sort last among entity types, so they never crowd out the actor or CVE you were probably looking for.

**Notes are instance-wide, not per-user.** Search returns any note on the instance, exactly as the notes browser lists them — the read model has always been shared, and search follows it. (Editing and deleting a note is author-or-admin, but reading is not.) Don't write anything into a note you wouldn't want a colleague to find.

---

## The Search Surface

One input, one results route. `HeaderSearch` is the only search field in the app on every route and every breakpoint; typing routes to `/search`, which is the only place results are drawn.

### Scope (`in:`)

The input carries a scope chip — Tab cycles it:

| Scope | Renders |
|-------|---------|
| `everything` | Entities and articles |
| `workbench` | Entities only |
| `feeds` | Articles only |

The chip is a **content** contract, not a routing one: it decides what the results page renders, nothing else. It defaults to `everything` and only ever changes when you change it — cycling the chip, ticking the rail's Scope facet, or opening a saved search that carries one. The route you came from does not narrow it. The field's placeholder follows the chip, so it always names the half you are actually searching.

### The Facet Rail

The results page's left rail is a second sidebar inside the content area. It offers:

- **Scope** and **entity type** (with server-side counts from `entities.counts`) — including **Notes**, which appear as their own group whenever a note matched
- **Matched on** — identity vs mention (see [Direct Matches vs Mentions](#direct-matches-vs-mentions))
- **Entry facets** — published window, read state, feed, content type, tags, media, language

Entry facets are written back into the query string as `field:value`. Ticking "Last 7 days" and "Unread" produces `date:>=… is:unread` in the input — visible, hand-editable, and saveable as a saved search. Facet counts come from Meilisearch's distribution over `feed_type`, `feed_title`, `tags`, `media_type` and `language`.

On mobile the rail becomes a slide-over sheet behind a **Filters** button, and the reader a full-screen overlay. Same page, same query.

### Opening a Note Result

A note row opens whichever surface holds it, since there is no per-note route:

| Note | Opens |
|------|-------|
| On an entity | That entity's profile, **Notes** tab |
| On an article | The reader for that article, **Notes** panel |
| Standalone | The notes browser, with its title seeded into the filter so the row you clicked is on top |

### Did You Mean

A value ends at the first space, so `country:North Korea` filters on `country:North` and full-text searches `Korea` — returning Northern Cyprus and Sudan alongside 1,611 articles instead of North Korea's 1,461. It looks like it worked.

The parser cannot fix this by consuming greedily: `threat_actor:APT29 ransomware` is a legitimate filter-plus-search-term, and quoting *that* would be wrong in the other direction. So the response carries a `did_you_mean` string instead, and the results page offers it as a one-click correction above the counts.

It only appears when the extended value is a real value for that field — the same lookup the autocomplete uses. `country:North Korea` gets a suggestion because "North Korea" is a country; `threat_actor:APT29 ransomware` gets none, because no actor is called that. Longer extensions win, so `country:North Korea attacks` suggests `country:"North Korea" attacks` rather than giving up.

Picking a value from the autocomplete inserts the quotes for you, so this only comes up on hand-typed queries.

### Autocomplete

Field names and values complete as you type, from one of two dictionaries depending on scope: `GET /api/search/autocomplete` (`FIELD_SUGGESTIONS` in `backend/app/api/search.py`) and the client-side `frontend/src/components/search/queryFields.ts`, which also renders the in-app syntax reference card.

The two are maintained separately and agree on 78 fields today, but nothing enforces that — nor that either matches what the planner accepts. A field can be offered and not parse (`cve.first_seen:` is currently completable and invalid), or parse and not be offered. When they disagree, `ENTRY_FIELDS` / `ENTITY_FIELDS` in `backend/app/search/query_planner.py` is the one that decides.

### The Rule Library's own search

The Rule Library (Workbench → Detection → Rules Library) does **not** use this query language. It is a faceted list backed by a dedicated Meilisearch index and `GET /api/detection-rules/search`, with typo tolerance and disjunctive facet counts. Use `rule:`, `rule.type:`, `rule.data_source:` etc. in the main search bar to find rules *alongside* other intelligence; use the library when rules are the subject.

---

## Worked Examples

### Example 1: Recent Critical CVEs

**Goal:** All CVEs with CVSS ≥ 9.0 published in the last 30 days.

```
cve.cvss:>=9.0 date:>=2025-04-03
```

**Breakdown:**
- `cve.cvss:>=9.0`: Entity filter (PostgreSQL) finds CVEs with CVSS ≥ 9.0.
- `date:>=2025-04-03`: Entry filter (Meilisearch) restricts to recent articles.
- **Join:** AND (entries must be linked to matching CVEs *and* published recently).

### Example 2: Articles Linking APT29 or Cozy Bear

**Goal:** Threat intelligence on APT29 (aliases: Cozy Bear) mentioning the actor.

```
threat_actor:APT29
```

**Note:** The actor search resolves aliases automatically. If Cozy Bear is in APT29's alias list, articles linked to APT29 appear.

`threat_actor:APT29 OR threat_actor:"Cozy Bear"` also works (same-type entity OR returns the union), but alias resolution on a single `threat_actor:` filter usually makes it unnecessary.

### Example 3: Unread Ransomware Articles from RSS Feeds

**Goal:** New ransomware articles you haven't read yet.

```
ransomware is:unread type:rss
```

**Breakdown:**
- `ransomware`: Free-text search (title, content, author, feed).
- `is:unread`: Entry filter (boolean; entries you haven't read).
- `type:rss`: Categorical filter (RSS feeds only).

### Example 4: High-Severity Detection Rules for T1059

**Goal:** Detection rules targeting command-line execution, high severity only.

```
ttp:T1059 rule:* rule.severity:high
```

**Breakdown:**
- `ttp:T1059`: Entity filter; find articles linked to T1059.
- `rule:*`: Entity filter; articles must mention a detection rule.
- `rule.severity:high`: Rules must be high severity.

To include critical rules too, use OR: `ttp:T1059 rule:* (rule.severity:critical OR rule.severity:high)`. Note that `NOT telemetry` can't be added — free-text negation is not supported (the term would just be dropped); see [Limitations](#limitations).

### Example 5: TTP Coverage Outside a Tactic

**Goal:** Articles linked to ATT&CK techniques, excluding a tactic you've already covered.

```
ttp:* NOT ttp.tactic:impact
```

**Note:** IOC search is not exposed as a query field (`ioc:` is not valid), and free-text negation is not supported — so "TTPs but no IOCs" cannot currently be expressed in one query.

### Example 6: Spanish-Language Threat Analysis

**Goal:** Intelligence in Spanish about threat actors.

```
threat_actor:* lang:es
```

**Breakdown:**
- `threat_actor:*`: All articles mentioning any threat actor.
- `lang:es`: Language filter (Spanish).

### Example 7: YouTube Videos from Last 7 Days

**Goal:** Malware demonstrations on YouTube this week.

```
type:youtube date:>=2025-03-27
```

(Assumes today is 2025-04-03; adjust date as needed.)

### Example 8: Bookmarked Entries (Curation)

**Goal:** Your curated collection (entries you've marked for follow-up).

```
is:bookmarked
```

To combine states, use OR: `is:noted OR is:bookmarked` matches entries that are noted, bookmarked, or both.

### Example 9: Complex: KEV + High CVSS + Recent

**Goal:** CISA Known Exploited Vulnerabilities with CVSS ≥ 8.5 from the last 2 weeks.

```
cve.kev:true cve.cvss:>=8.5 date:>=2025-03-20
```

**Breakdown:**
- `cve.kev:true` and `cve.cvss:>=8.5`: Both are CVE-typed filters, so they AND *within* one CVE query — a single CVE must satisfy both.
- `date:>=2025-03-20`: An entry filter, applied to the articles those CVEs are linked to.

KEV membership is a boolean on the CVE record, not something the article has to mention — this is strictly better than free-text searching "CISA" or "KEV", which only finds articles that happened to use the words.

### Example 10: Multiple Threat Actors, Excluding Noise

**Goal:** Articles mentioning APT28 or APT29, excluding entries you've tagged as digests.

```
("APT28" OR "APT29") NOT tag:digest
```

Text-term OR runs both searches and merges the results, with the tag exclusion applied to each. For linked-entity matching instead of free text, `(threat_actor:APT28 OR threat_actor:APT29) NOT tag:digest` also works — same-type entity OR returns the union. Free-text negation like `NOT summary` is still not supported (the term is dropped); negate a field filter instead.

### Example 11: Starred Articles with a Tag

**Goal:** Your starred articles tagged as critical.

```
is:starred tag:critical
```

Adjacent `tag:` filters AND (`tag:critical tag:urgent` requires both tags); use OR for either: `is:starred (tag:critical OR tag:urgent)`.

### Example 12: Exploitation-Ranked CVE Triage

**Goal:** Vulnerabilities that are both catalogued as exploited and statistically likely to be attacked.

```
cve.kev:true cve.epss:>0.5
```

**Breakdown:**
- `cve.kev:true`: In the CISA Known Exploited Vulnerabilities catalog.
- `cve.epss:>0.5`: EPSS puts exploitation probability above 50%.
- Both are entity filters on the same type, so they AND within one CVE query — a CVE must satisfy both.

### Example 13: Rules You Can Actually Deploy

**Goal:** Persistence detections that run on telemetry you already collect.

```
rule.data_source:sysmon rule.tactic:persistence
```

`rule.data_source:` is the same field the telemetry-coverage board reads, so the results are the rules whose log-source requirements you meet.

### Example 14: The Engine's Own Queue

**Goal:** Read what the signal engine thinks is under-covered, in its own order.

```
signal:under_reported sort:radar
```

Both halves are PostgreSQL-backed, so this bypasses the index entirely: exact counts, `priority_score` ordering, unscored entries excluded.

### Example 15: Leak-Site Monitoring

**Goal:** Manufacturing victims posted by a specific ransomware group.

```
ransomware_victim.group:lockbit ransomware_victim.sector:manufacturing
```

`ransomware_victim.group:` matches the group name as the leak site wrote it.

### Example 16: Curation Backlog

**Goal:** AI-extracted threat actors with enough coverage to be worth reviewing.

```
threat_actor.via:ai_extraction threat_actor.articles:>10
```

Catalogue suffixes turn the entity tables into a work queue.

### Example 17: Feed Subset with Date Range

**Goal:** Articles from your Shodan feeds published in Q1 2025.

```
feed:Shodan date:2025-01..2025-03
```

A single `feed:` filter ORs all feeds whose names contain the value — so `feed:Shodan` covers "Shodan Alerts" and "Shodan Blog" at once. `(feed:Shodan OR feed:Censys)` does *not* work: separate `feed:` filters AND together.

---

## Saved Searches

A saved search is a persistent stored query.

### Creating a Saved Search

1. Compose a query in the unified search bar.
2. Click the "Save" button and give it a name.

The query string is stored as-is (name + query; older saved searches may also carry a legacy structured-filters JSON that is converted back to query syntax on load). When a saved search runs, the backend:

1. Parses the query string using `parse_query()`.
2. Builds an execution plan using `build_execution_plan()`.
3. Resolves the deferred PostgreSQL filters with `resolve_deferred_filters()`.
4. Runs the index-facing half with `execute_entry_search()`.

### Match Counts

The `refresh_saved_search_counts` Celery task recomputes match counts for all saved searches every 5 minutes (counting up to 5,000 matching entries per search) and caches them in Redis for 10 minutes. Counts are not stored on the saved search record itself.

> **The pinned count is not the search.** Opening a saved search runs the full query
> through `POST /api/search/unified` and returns exactly what the search bar would.
> The *number beside it in the sidebar* comes from this narrower counting path, which
> never calls `execute_entity_queries()` — so when the query has an entity half, the
> count is wrong while the results are fine:
>
> | Query | Sidebar count | Opening it returns |
> |-------|---------------|--------------------|
> | `country:"United States"` | 0 | 5,896 |
> | `threat_actor:APT29` | 0 | 261 |
> | `cve.kev:true` | 0 | 4,751 |
> | `ransomware threat_actor:APT29` | 5,000 | 48 |
> | `"device code phishing"` | 186 | 186 ✓ |
>
> A pure entity query counts **zero**, because dropping the entity half leaves the
> index nothing to search. Mixed with text it counts the *text term alone*, which
> over-counts instead.
>
> Entry-scoped PostgreSQL filters (`signal:`, `sector:`, `url:`) do apply, but their
> entry-ID list is capped at 500 before the index query, so anything matching more
> under-counts: `signal:scoop` counts 21 against 162, `sector:healthcare` 12 against
> 276.
>
> Counts are right for searches built from **text, `tag:`, `type:`, `feed:`,
> `category:`, `date:` and the `is:` states**. Treat the number on an entity-filtered
> saved search as decorative until the counting path grows an entity join.

### Campaign Auto-Sync

A saved search can be attached to a campaign with auto-sync enabled: the `sync_campaign_saved_searches` task (also every 5 minutes) reruns the query for active/monitoring campaigns and adds any new matching entries to the campaign.

Unlike the sidebar count, this one *writes*: it runs through the same entity-blind path, so a campaign auto-syncing on `threat_actor:APT29` collects nothing, and one on `ransomware threat_actor:APT29` collects every ransomware article into the campaign. Prefer entry-field queries for auto-sync, or add entries explicitly.

### Query Validation

- Genuinely malformed syntax (e.g. an unbalanced parenthesis) raises a parse error: the backend falls back to an empty query and returns no results, while the filter-chip parser in the UI treats the input as plain text.
- A field with a missing value like `threat_actor:` still parses — it becomes an empty-value filter that matches broadly.

---

## Entity Pivot Links

Clicking an entity name (threat actor, CVE, TTP, etc.) in an article opens its entity popover; from there you can jump to the entity's profile page or pivot into search.

### Pivot Query Pattern

The popover's **Search** action pivots the global search bar to the entity as a quoted phrase (e.g. `"Cozy Bear"`). For structured pivots, type the field filter yourself:

```
threat_actor:APT29
cve:CVE-2024-1234
ttp:T1566.001
```

The system also generates **external pivot links** to analyst platforms. See `frontend/src/utils/pivotLinks.ts`:

### External Pivot Platforms

For **threat_actor**, links include:
- MITRE ATT&CK Groups
- Google
- Mandiant
- CISA
- Recorded Future

For **malware**:
- VirusTotal
- MalwareBazaar
- Hybrid Analysis
- MITRE ATT&CK Software
- Google

For **ttp**:
- MITRE ATT&CK Techniques
- Sigma Rule Repository
- Google

For **cve**:
- CVE.org
- NVD (NIST)
- CVEDetails
- MITRE CVE Records
- ExploitDB

For **country**:
- Wikipedia
- Google
- CISA

### Manual Pivot Construction

To pivot manually, construct a query string and pass it to the workbench:

```javascript
const pivotQuery = `threat_actor:"${entityValue}"`;
// Navigate to /workbench?q=threat_actor:"APT29"
```

The `?q=` parameter pre-fills the unified search bar on load.

---

## Tips & Limitations

### Best Practices

1. **Use quotes for multi-word values:**
   ```
   threat_actor:"Cozy Bear"        # Correct (exact, case-sensitive name match)
   threat_actor:Cozy Bear          # Parsed as: threat_actor:Cozy AND Bear (wrong)
   ```

2. **Combine entity and entry filters:**
   ```
   threat_actor:APT29 is:unread date:>=2025-01-01
   ```
   Finds unread articles about APT29 from this year—most powerful pattern.

3. **Leverage wildcards for discovery:**
   ```
   cve:CVE-2024-*           # Discover 2024 CVEs
   ttp:T1*                  # All MITRE techniques
   tag:critical*            # Every tag starting "critical"
   ```
   Wildcards work in field values only. In free text, search the prefix on its own
   — `ransom` already prefix-matches "ransomware".

4. **Use OR for alternatives:**
   ```
   threat_actor:APT28 OR threat_actor:APT29        # Union of both actors
   tag:critical OR tag:urgent        # Either tag
   ```
   Same-type entity OR and entry-filter OR both return the union. Watch the edge cases: `feed:` filters and entity AND-groups inside an OR still AND (see [Boolean Operators](#boolean-operators)).

5. **Exact match with quotes when needed:**
   ```
   title:"zero day"         # Exact phrase
   title:zero day           # Free-text search for "zero" and "day"
   ```

6. **Prefer a fact over a phrase:**
   ```
   cve.kev:true                    # CVEs CISA lists as exploited
   "known exploited vulnerability" # Articles that happened to use the words
   ```
   Structured filters query the record. Free text queries what someone wrote about it.

7. **Let the facet rail write your filters:**
   Tick facets on the results page and read the search box — it fills in with the
   equivalent `field:value` syntax. It's the fastest way to learn the grammar, and
   the result is a query you can save.

### Limitations

1. **No free-text negation:** Meilisearch cannot exclude query terms, so a negated bare term (or negated `title:`/`content:`/`author:` value) is dropped from the query — `ransomware NOT phishing` behaves like `ransomware`, and a query that is *only* negated text (`NOT phishing`) matches everything, since nothing is left to constrain it. `NOT` only works on field filters — entity fields, `tag:`/`type:`/`media:`/`lang:`/`is:`/`feed:`, and the PostgreSQL-backed entry fields (with the caveat in #8). `date:` is the one field filter that ignores negation entirely.

2. **No regex:** Only `*` wildcards are supported, and only in field *values* — any position, including the middle (`ttp:T1*5*` works). No character classes, lookahead, or alternation, and no wildcards in free text (see [Value Wildcards](#value-wildcards)).

3. **No stemming:** `run` ≠ `running`. Meilisearch's typo tolerance helps, but not a full stemmer.

4. **Case-sensitive field names:** `Actor:APT29` is invalid. Use lowercase: `threat_actor:APT29`. The boolean operators are *not* case-sensitive — `not tag:noise` and `NOT tag:noise` are the same query — so quote the word to search for it literally (`"not"`).

5. **Quoted values are strict:** unquoted values match case-insensitively (`threat_actor:apt29` matches `APT29`), but quoted values require an exact, case-sensitive match against the primary name and skip alias resolution.

6. **Feed name resolution:** `feed:` does substring matching, not exact. `feed:Dark` matches "Dark Reading" and "Dark Web Monitoring". If ambiguous, use the full name or add quotes: `feed:"Dark Reading"`. A `*` switches it to an anchored pattern: `feed:Krebs*` matches titles that *start* with "Krebs".

7. **Result limits:**
   - Entry pagination: 20 results per page by default, up to 500 per request.
   - Entity queries return at most 200 entities per request (max 500), trimmed to 25 per type in the payload — even for wildcards like `threat_actor:*`. The per-type `counts` are not trimmed, and the linked articles are drawn from every match rather than from the returned page.
   - Mixed entry+entity queries pass at most 500 linked-entry IDs into the Meilisearch filter; above 800 IDs, and for entity-only queries, results paginate directly from PostgreSQL.

8. **A negated PostgreSQL filter only subtracts from an entry-ID set.** `NOT signal:feed_echo`, `NOT is:translated` and the other entry-scoped PostgreSQL filters remove their matches from a set of entry IDs — and only an *entity* filter or another *entry-scoped PostgreSQL* filter builds one. A bare text term and the index filters (`tag:`, `type:`, `media:`, `lang:`, `date:`, `is:starred`…) do not, so the negation is silently dropped:

    ```
    signal:scoop NOT signal:kev_added        162 → 160   ✓ subtracts
    threat_actor:APT29 NOT signal:kev_added  261 → 253   ✓ subtracts
    ransomware NOT signal:kev_added        9,221 → 9,221 ✗ dropped
    tag:morning-brief NOT signal:kev_added 6,499 → 6,499 ✗ dropped (185 of them do carry it)
    ```

    Negating one on its own matches everything: the complement is every other entry, and enumerating it is unbounded.

9. **Feed grades are exact, not ranges:** `feed.reliability:B` matches grade B only. `feed.reliability:>B` is not supported, and ungraded feeds match no grade filter.

10. **`sort:radar` drops unscored entries and ignores text terms:** it is a queue-reading sort, not a search ranking. See [Sorting](#sorting).

11. **`note:` is one field over two tables.** `note.type:` and an entity value for `note.about:` only apply to entity notes; `note.pinned:` and `note.about:entry` / `:standalone` only apply to the other table. A field that cannot apply excludes that table rather than matching all of it. A query made entirely of *other* entities' filters still returns no notes.

12. **`OR` between a text term and an entry-scoped PostgreSQL filter means AND.** `ransomware OR signal:kev_added` intersects rather than unions: `signal:`, `sector:`, `url:` and `is:translated`/`is:image` narrow by entry ID *after* the index search, so they cannot be a branch of it. These fields OR correctly against each other and against `feed:`/`category:`/`is:`/the index filters. See [OR (Disjunction)](#or-disjunction).

13. **`note:` results are not tagged as direct matches.** Every other field filter marks its results `match_kind: "direct"`; note results carry `match_field` but no `match_kind`, so the search page files them under Mentions. Rows and counts are correct — only the grouping is off.

14. **`ioc:` still does not exist:** indicator search surfaces via entity suggestions and profile pages, not a `field:value` filter.

15. **Search history is local:** your last 10 queries are kept in this browser's localStorage and shown when the search bar is empty. Use saved searches to persist queries server-side.

16. **User state is per-user, notes are not:** `is:starred` is relative to your account — sharing a query with a colleague doesn't share your starred status. Notes go the other way: search returns every note on the instance regardless of who wrote it, matching how the notes browser has always listed them.

### Debugging Queries

If results seem wrong:

1. **Check the parsed filters:** `POST /api/search/unified` echoes a `parsed_filters` array; the search page renders it as removable chips. Verify the parser extracted what you intended. An unrecognised field is *not* a filter — its value is searched as free text, and the response lists the name in `unknown_fields` so the search page can say so above the results. A typo like `titel:ransomware` therefore behaves as a search for `ransomware`, not as a filter and not as an error.

2. **Simplify incrementally:** Remove one filter at a time to find the culprit.
   ```
   threat_actor:APT29 date:>=2025-01-01 is:unread type:rss
   → threat_actor:APT29  # Start here
   → threat_actor:APT29 date:>=2025-01-01  # Add date
   → ... # Continue adding filters
   ```

3. **Check entity records:** If `threat_actor:APT29` returns no results, verify that the actor exists in the database with that exact name (or aliases). Use the admin panel or API to inspect.

4. **Use free-text fallback:** If a complex query times out, fall back to free-text + one entity filter:
   ```
   ransomware threat_actor:APT29  # Better than 10-filter query
   ```

---

## Cross-References

- **User Guide:** `/docs/guide/searching.md` — How to use the search bar, the filter rail, and saved searches in the UI.
- **Workers & Search:** `/docs/workers-search-dashboards.md` — Backend architecture, Meilisearch indexing, and Celery task scheduling.
- **API:** `/backend/app/api/search.py` — REST endpoints for unified search and saved searches.
- **Query Parser:** `/backend/app/search/query_parser.py` — Grammar and implementation details.
- **Query Planner:** `/backend/app/search/query_planner.py` — Field classification, branch expansion, and `resolve_deferred_filters()` (call that rather than the two resolvers it wraps — running one without the other leaves placeholders unresolved).
- **Entity Builder:** `/backend/app/search/entity_builder.py` — `FIELD_MAP`, value-type handling, entity serialization.
- **Field Catalogue (UI):** `/frontend/src/components/search/queryFields.ts` — The field list as data; drives autocomplete and the in-app syntax reference.
- **Saved Searches:** `/backend/app/api/saved_searches.py` — Saved search creation, alerting, and scheduling.

---

**Last Updated:** 2026-09-01  
**Version:** 1.5

