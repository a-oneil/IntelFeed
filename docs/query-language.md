# Query Language Reference

This is the reference for the search box at the top of IntelFeed. Read it to learn how to search articles and intelligence (actors, CVEs, techniques and so on) in one query, filter by field, and combine filters with `AND`, `OR` and `NOT`.

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

| Operator | Meaning | Example |
|----------|---------|---------|
| `AND` | Both must match. Also the default between words | `ransomware AND lockbit` |
| `OR` | Either can match | `APT28 OR APT29` |
| `NOT` | Exclude. Works on field filters only, not on plain words | `NOT tag:noise` |
| `()` | Group | `(APT28 OR APT29) AND ransomware` |
| `""` | Exact phrase, or a value with spaces | `"zero day"`, `feed:"Dark Reading"` |
| `:` | Field filter | `threat_actor:APT29` |
| `*` | Wildcard, in a field value only | `cve:CVE-2024-*` |
| `>`, `>=`, `<`, `<=` | Compare | `cve.cvss:>=9.0` |
| `..` | Inclusive range | `date:2025-01..2025-06` |

`AND`, `OR` and `NOT` work in any case (`not tag:noise` is the same as `NOT tag:noise`). To search for the word itself, quote it: `"not"`.

### Core Fields

The list of fields the search understands is `ENTRY_FIELDS` and `ENTITY_FIELDS` in `backend/app/search/query_planner.py`. A field name that is not on that list is not an error: its value is searched as plain text, and the results page tells you the field was not recognised.

| Field | Kind | Example |
|-------|------|---------|
| **Article fields** | | |
| `title`, `content`, `author` | text | `title:ransomware` |
| `feed` | feed name, substring | `feed:"Dark Reading"` |
| `category` | feed folder, substring | `category:"Vendor Blogs"` |
| `tag` | exact | `tag:critical` |
| `type` | exact | `type:rss`, `type:youtube` |
| `media` | exact | `media:video` |
| `lang` | exact | `lang:en` |
| `url` | substring | `url:github.com` |
| `words` | number | `words:>1500`, `words:500..2000` |
| `date` | date | `date:>=2025-01-01` |
| `is` | status | `is:starred`, `is:unread` ([all values](#status-flags)) |
| `sort` | ordering | `sort:newest`, `sort:radar` ([all values](#sorting)) |
| `signal` | exact | `signal:kev_added` |
| `info` | number 1–6 | `info:1`, `info:<=2`, `info:1..3` |
| `grade` | letter + number | `grade:B2` |
| `feed.reliability`, `feed.timeliness`, `feed.relevance` | letter grade | `feed.reliability:B` |
| **CVE** | | |
| `cve` | entity | `cve:CVE-2024-1234` |
| `cve.severity` | exact | `cve.severity:critical` |
| `cve.cvss` | number | `cve.cvss:>=9.0` |
| `cve.kev` | true/false | `cve.kev:true` |
| `cve.epss` | number | `cve.epss:>0.5` |
| `cve.epss_percentile` | number | `cve.epss_percentile:>0.9` |
| `cve.poc` | number | `cve.poc:>0` |
| `cve.exploit` | exact | `cve.exploit:kev` |
| `cve.product` | linked table | `cve.product:fortios` |
| **CWE (weaknesses)** | | |
| `cwe` | entity | `cwe:CWE-79` |
| `cwe.abstraction` | exact | `cwe.abstraction:Base` |
| `cwe.usage` | exact | `cwe.usage:Allowed` |
| `cwe.parent` | exact | `cwe.parent:CWE-707` |
| `cwe.kind` | exact | `cwe.kind:weakness` |
| `cwe.deprecated` | true/false | `cwe.deprecated:false` |
| **Observables (IOCs)**: `ioc` works anywhere `observable` does | | |
| `observable` / `ioc` | entity | `ioc:evil.com` |
| `observable.kind` | exact | `ioc.kind:sha256` |
| `observable.role` | exact | `ioc.role:c2` |
| `observable.status` | exact | `ioc.status:active` |
| `observable.infra` | exact | `ioc.infra:<tag>` |
| `observable.reports` | number | `ioc.reports:>0` |
| `observable.feeds` | number | `ioc.feeds:>=2` |
| **ATT&CK** | | |
| `ttp` | entity | `ttp:T1059` |
| `ttp.tactic` | exact | `ttp.tactic:execution` |
| `ttp.platform` | list | `ttp.platform:Windows` |
| `ttp.data_source` | list | `ttp.data_source:process` |
| `ttp.domain` | exact | `ttp.domain:ics` |
| `ttp.subtechnique` | true/false | `ttp.subtechnique:true` |
| `ttp.deprecated` | true/false | `ttp.deprecated:false` |
| `mitigation` | entity | `mitigation:M1036` |
| **Actors, malware, tools** | | |
| `threat_actor` | entity | `threat_actor:APT29` |
| `threat_actor.country` | exact | `threat_actor.country:Russia` |
| `threat_actor.motivation` | exact | `threat_actor.motivation:espionage` |
| `threat_actor.sector` | linked table | `threat_actor.sector:healthcare` |
| `threat_actor.type` | exact | `threat_actor.type:ransomware` |
| `threat_actor.mitre` | exact | `threat_actor.mitre:G0016` |
| `malware` | entity | `malware:Emotet` |
| `malware.type` | exact | `malware.type:trojan` |
| `malware.sector` | linked table | `malware.sector:finance` |
| `malware.mitre` | exact | `malware.mitre:S0367` |
| `tool` | entity | `tool:Mimikatz` |
| `tool.type` | exact | `tool.type:framework` |
| `tool.platform` | list | `tool.platform:Windows` |
| `tool.mitre` | exact | `tool.mitre:S0002` |
| **Sectors** | | |
| `sector` | entity | `sector:healthcare`, `sector:banks` |
| `sector.slug` | exact | `sector.slug:financial-services` |
| **Geography and supply chain** | | |
| `country` | entity | `country:"North Korea"` |
| `country.region` | exact | `country.region:Asia` |
| `country.iso` | exact | `country.iso:RU` |
| `vendor` | entity | `vendor:Microsoft` |
| `vendor.type` | exact | `vendor.type:software` |
| `product` | entity | `product:Exchange` |
| `product.type` | exact | `product.type:firewall` |
| `product.vendor` | linked table | `product.vendor:Cisco` |
| **Detection and reporting** | | |
| `rule` | entity (title) | `rule:backdoor` |
| `rule.type` | exact | `rule.type:sigma` |
| `rule.severity` | exact | `rule.severity:high` |
| `rule.data_source` | list | `rule.data_source:sysmon` |
| `rule.tactic` | list | `rule.tactic:persistence` |
| `rule.tag` | list | `rule.tag:attack.t1059` |
| `rule.draft` | true/false | `rule.draft:false` |
| `rule.license` | exact | `rule.license:DRL` |
| `campaign` | entity | `campaign:"Volt Typhoon"` |
| `campaign.status` | exact | `campaign.status:active` |
| `intel_report` | entity (title) | `intel_report:quarterly` |
| `intel_report.status` | exact | `intel_report.status:draft` |
| `intel_report.type` | exact | `intel_report.type:threat_brief` |
| `intel_report.tlp` | exact | `intel_report.tlp:TLP:AMBER` |
| `pir` | entity (title) | `pir:"APT capability"` |
| `pir.priority` | exact | `pir.priority:high` |
| `pir.category` | exact | `pir.category:strategic` |
| **Notes** | | |
| `note` | title or body | `note:fortibleed` |
| `note.tag` | list | `note.tag:followup` |
| `note.type` | exact | `note.type:analysis` |
| `note.about` | exact | `note.about:cve`, `note.about:entry` |
| `note.pinned` | true/false | `note.pinned:true` |
| **Ransomware victims** | | |
| `ransomware_victim` | entity | `ransomware_victim:Finastra` |
| `ransomware_victim.sector` | exact | `ransomware_victim.sector:healthcare` |
| `ransomware_victim.domain` | exact | `ransomware_victim.domain:acme.com` |
| `ransomware_victim.group` | linked table | `ransomware_victim.group:lockbit` |
| **Shared suffixes** ([not on every type](#catalogue-suffixes)) | | |
| `<type>.articles` | number | `threat_actor.articles:>100` |
| `<type>.seen` | date | `malware.seen:>2026-01-01` |
| `<type>.first_seen` | date | `ttp.first_seen:>2026-06` |
| `<type>.review` | true/false | `threat_actor.review:true` |
| `<type>.via` | exact | `cve.via:ai_extraction` |

The kinds are explained in [Value Types](#value-types).

---

## Syntax Fundamentals

### Free-Text Search

Plain words search the article index (Meilisearch). It looks in the title, body, summary, author, feed name and tags.

```text
ransomware
zero day exploit
```

- Every word must match. `ransomware attack APT29` is the same as `ransomware AND attack AND APT29`.
- Results are ranked by relevance.
- Small typos are forgiven: one typo in words of 4 or more letters, two in words of 8 or more.
- The last word also matches as a prefix, so `ransom` finds "ransomware".
- There is no stemming: `run` does not match `running`.
- Matches are highlighted in the results.

### Quoted Phrases

Quotes search for the words together, in order:

```text
"cobalt strike beacon"
```

### `title:`, `content:` and `author:`

These do not limit the search to one part of the article. `title:exploit` searches for `exploit` everywhere, the same as typing `exploit`. Use them for readability, not for precision.

---

## Field Filters

A filter is `field:value`. Field names are lowercase: `Threat_actor:APT29` is not a filter, so `APT29` is searched as plain text.

**A value ends at the first space.** `feed:Dark Reading` means `feed:Dark` plus the word `Reading`. This returns the wrong results without any error. Quote values that have spaces: `feed:"Dark Reading"`, `country:"North Korea"`.

### Article Fields

#### Feed and Folder

`feed:` matches feeds whose name contains the value (ignoring case). If several feeds match, any of them counts.

```text
feed:"Dark Reading"
feed:Krebs*            # name starts with "Krebs"
```

`category:` works the same way on the feed's folder:

```text
category:"Vendor Blogs"
```

`feed.reliability:`, `feed.timeliness:` and `feed.relevance:` match the letter grade (A, B, C and so on) set on each feed in the feed editor. They match one grade exactly; `feed.reliability:>B` does not work. Feeds without a grade never match.

```text
feed.reliability:A
```

`info:` matches the article's own credibility number, 1 (confirmed by another outlet) to 6 (cannot be judged); it takes `<`, `>` and `..` ranges. `grade:` matches the feed's letter and the article's number together. Articles with no number never match. See [Admiralty grade](entries.md#admiralty-grade).

```text
info:<=2               # confirmed or probably true
grade:B1               # usually reliable source, confirmed story
```

#### Tags, Type, Media, Language

`tag:`, `type:`, `media:` and `lang:` match a value exactly. A `*` matches any indexed value that fits the pattern.

```text
tag:critical
tag:critical*          # any tag starting with "critical"
type:youtube
media:video
lang:es
```

Values:

- `type`: the feed type: `rss`, `atom`, `youtube`, `podcast`, `reddit`, `github_releases`, `github_advisories`, `github_repo`, `nvd`, `mastodon`, `bluesky`, `telegram`, `web_scraper`, `manual` (uploaded files and URLs).
- `media`: `image`, `video`, `audio`, `document`.
- `lang`: two-letter language codes (`en`, `es`, `fr`, `zh`, `ja` and so on).
- `tag`: any tag name. It matches global tags and the tags you put on articles yourself. Other people's personal tags never match.

#### URL and Length

```text
url:github.com         # the article link contains this text
url:https://github*    # with *, the link must start this way
words:>1500            # long articles
words:<300             # short posts
words:500..2000        # between, inclusive
```

Without `*`, `url:` matches anywhere in the link. With `*`, the pattern must match the whole link: `url:github*` matches nothing, because links start with `https://`. Use `url:*github.com*`.

#### Signal and Sector

`signal:` filters by the reasons the signal engine gave an article its score. These are the same reasons shown on the "Why" card in the Priority Queue.

| Signal | Meaning |
|--------|---------|
| `novel_entity` | Mentions an entity not seen before |
| `entity_resurgence` | An entity that had gone quiet is back |
| `new_pairing` | Two entities appear together for the first time |
| `scoop` | First source to report it |
| `source_convergence` | Independent sources are reporting the same thing |
| `under_reported` | Few sources carried it, given how important it is |
| `feed_echo` | Repeats something already covered |
| `kev_added` | A CVE in the article joined CISA KEV |
| `epss_jump` | A CVE's EPSS score rose sharply |
| `epss_high` | A CVE has a high EPSS score |
| `weaponized_poc` | A public exploit exists for a CVE in the article |
| `critical_cvss` | Carries a critical-severity CVE |
| `pir_match` | Matches an intelligence requirement |
| `correlation_event` | Fired a correlation between tracked entities |
| `detection_content` | Contains detection content you can deploy |
| `research_depth` | In-depth research rather than a news item |

Use it with `sort:radar` to read the queue in the engine's order:

```text
signal:under_reported sort:radar
```

`sector:` returns articles where the AI analysis judged that industry to be a *target*, not articles that just use the word. It matches the sector's name, slug or aliases (`banks`, `hospitals`).

`threat_actor.sector:` and `malware.sector:` are different: they match the sectors an actor or malware family is recorded as targeting.

```text
sector:healthcare
sector.slug:critical-infrastructure
threat_actor.sector:healthcare
```

#### Status Flags

`is:` takes eight values:

```text
is:starred       # starred
is:read          # marked read
is:unread        # not marked read
is:bookmarked    # bookmarked
is:noted         # has notes
is:muted         # from a muted feed
is:translated    # machine-translated
is:image         # has a hero image
```

`NOT is:read` is the same as `is:unread`.

The first five are stored in the search index as one flag per article. On an instance with several users, that flag shows the last change anyone made, not only yours. The **Hide read** toggle on the results page does use your own read state.

`NOT is:translated` and `NOT is:image` only work next to an entity filter or another database filter (see [Limitations](#limitations), item 8).

#### Date Filtering

A date can be a year (`2025`), a month (`2025-01`) or a day (`2025-01-15`). Each one covers the whole span, and dates are in UTC.

```text
date:>=2025-01-01              # on or after Jan 1
date:>2025-01-01               # after Jan 1 (Jan 1 not included)
date:<=2025-12-31              # up to and including Dec 31
date:<2025-12-31               # before Dec 31
date:2025-01-01                # that day
date:2025-01                   # all of January
date:2025                      # all of 2025
date:2025-01..2025-06          # January 1 to June 30, inclusive
```

A date that cannot be read is ignored. `NOT` has no effect on `date:`.

#### Sorting

`sort:` changes the order; it does not filter.

```text
sort:relevance   # best match first (default)
sort:newest      # newest first
sort:oldest      # oldest first
sort:title_asc   # title A to Z
sort:title_desc  # title Z to A
sort:shortest    # fewest words first
sort:longest     # most words first
sort:radar       # signal engine score, highest first
```

Any other value is ignored.

`sort:radar` uses the same score and order as the Priority Queue. That score lives in the database, not the search index, so a `sort:radar` query is answered from the database:

- Articles with no score are left out.
- Plain words and index filters (`tag:`, `type:`, `feed:`, `date:`, `is:starred` and the like) are ignored. Only entity filters, `signal:`, `url:`, `is:translated` and `is:image` apply.
- Ties go to the newer article.

### Entity Fields

Entity fields search IntelFeed's intelligence records (in PostgreSQL) and return two things: the matching records, and the articles linked to them.

#### Core Entity Types

`cve`, `cwe`, `observable` (or `ioc`), `threat_actor`, `ttp`, `malware`, `country`, `sector`, `tool`, `vendor`, `product`, `mitigation`, `campaign`, `ransomware_victim`, `rule`, `intel_report`, `pir`, `note`.

```text
cve:CVE-2024-1234
threat_actor:APT29
ttp:T1059
malware:Emotet
rule:backdoor                    # rule title contains "backdoor"
pir:"APT Capability Assessment"  # requirement title
```

How the value matches:

- **Unquoted**: contains the value, ignoring case. For actors, malware, countries, sectors, tools, vendors, products and ransomware victims, aliases are checked too (as whole words). For `ttp`, the technique name is checked; `ttp:phishing` finds T1566. `cwe` also checks the weakness name, `mitigation` the MITRE ID, and `observable` the label.
- **Quoted**: must equal the main name exactly, including case. Aliases are not checked.
- **With `*`**: a pattern. `*` stands for any text, and the rest must match the whole name: `APT*` matches names that start with APT.

```text
cve:CVE-2024-*          # CVE IDs from 2024
ttp:T1566*              # T1566 and its sub-techniques
threat_actor:APT*       # names starting with APT
```

Three types have no article links, so they return only the records: `ransomware_victim`, `intel_report`, and `rule` (a rule returns the one article it was extracted from, if any). `pir:` only matches active requirements.

#### Entity Properties

`<type>.<property>` filters narrow the records. The articles returned are the ones linked to the records that are left. `mitigation` has only the [shared suffixes](#catalogue-suffixes).

**CVE**

```text
cve.severity:critical        # critical | high | medium | low
cve.cvss:>=9.0               # CVSS base score
cve.kev:true                 # in the CISA Known Exploited Vulnerabilities catalog
cve.epss:>0.5                # EPSS exploitation probability, 0.0 to 1.0
cve.epss_percentile:>0.9     # EPSS percentile
cve.poc:>0                   # number of public GitHub proof-of-concept repos
cve.exploit:kev              # exploitation status
cve.product:fortios          # affected product or vendor, from NVD CPE data
```

`cve.product:` matches either the CPE vendor or the CPE product, so `fortinet` and `fortios` both work.

**CWE**

```text
cwe:CWE-79                   # by ID, name, or part of the name
cwe.abstraction:Base         # Pillar | Class | Base | Variant
cwe.usage:Allowed            # MITRE's guidance on using this ID for mapping
cwe.parent:CWE-707           # direct parent
cwe.kind:weakness            # weakness | category
cwe.deprecated:false         # leave out deprecated IDs
```

A Pillar is a broad family and a Variant is one specific mistake. Base is usually the level that detections and coding rules are written for. `cwe.usage:` tells you whether MITRE says the ID should be used at all; some common IDs are marked Discouraged.

**Observables (IOCs)**

`ioc` and `observable` are the same field, with the same properties.

```text
ioc:evil.com                 # by value or label; type the plain value (evil.com, not evil[.]com)
ioc.kind:sha256              # ipv4 | ipv6 | domain | url | uri_path | email | md5 |
                             # sha1 | sha256 | ja3 | ja4 | cert_fingerprint | cmdline |
                             # registry | path | mutex | named_pipe | service_name |
                             # scheduled_task | http_header | user_agent | script
ioc.role:c2                  # c2 | delivery | payload | phishing | exfil | exploit | scanning |
                             # persistence | execution | defense_evasion | credential_access |
                             # discovery | lateral_movement | collection
ioc.status:active            # active | aging | expired
ioc.reports:>0               # number of articles reporting it (indicator lists don't count)
ioc.feeds:>=2                # number of indicator feeds listing it
```

`status` comes from confidence that fades over time since the last sighting. `aging` or `expired` is normal for an IP address that changes hands. Hashes and host artifacts never fade, so they stay `active`.

**ATT&CK**

```text
ttp.tactic:execution         # primary tactic, as MITRE spells it (defense-evasion, not defense_evasion)
ttp.platform:Windows         # Windows | Linux | macOS | Containers | ...
ttp.data_source:process      # telemetry needed; part of the name is enough
ttp.domain:enterprise        # enterprise | mobile | ics
ttp.subtechnique:true        # sub-techniques only (T1059.001, not T1059)
ttp.deprecated:false         # leave out techniques MITRE has deprecated
```

**Actors, malware and tools**

```text
threat_actor.country:China          # country of origin
threat_actor.motivation:espionage   # espionage | financial | hacktivism | disruption
threat_actor.sector:healthcare      # sectors the actor targets
threat_actor.type:ransomware        # actor type
threat_actor.mitre:G0016            # MITRE group ID
malware.type:ransomware             # malware type
malware.sector:finance              # sectors the family targets
malware.mitre:S0367                 # MITRE software ID
tool.type:framework                 # tool type
tool.platform:Windows               # platforms it runs on
tool.mitre:S0002                    # MITRE software ID
```

**Geography and supply chain**

```text
country.region:Europe        # region
country.iso:RU               # ISO 3166 two-letter code
vendor.type:software         # vendor type
product.type:firewall        # product type
product.vendor:Cisco         # products from this vendor
```

**Detection rules**

```text
rule.type:sigma              # sigma | yara | elastic_ql | splunk_spl | panther | nuclei | kql | crowdstrike_ql | snort_suricata
rule.severity:high           # critical | high | medium | low | info
rule.data_source:sysmon      # log source the rule needs
rule.tactic:persistence      # ATT&CK tactic the rule covers
rule.tag:attack.t1059        # rule tag
rule.draft:true              # drafts only
rule.license:DRL             # upstream license
```

`rule.data_source:` is the same field the telemetry coverage view uses.

**Reports, campaigns and requirements**

```text
campaign.status:active               # active | monitoring | closed | historical
intel_report.status:draft            # report status
intel_report.type:threat_brief       # report template
intel_report.tlp:TLP:AMBER           # TLP:CLEAR | TLP:GREEN | TLP:AMBER | TLP:AMBER+STRICT | TLP:RED
pir.priority:critical                # critical | high | medium | low
pir.category:strategic               # strategic | operational | tactical | technical
```

**Notes**

```text
note:fortibleed              # title or body of any note
note.tag:followup            # note tag
note.type:analysis           # annotation | analysis | action_taken | false_positive | context
note.about:threat_actor      # notes on this kind of entity
note.about:entry             # notes on an article
note.about:standalone        # notes attached to nothing
note.pinned:true             # pinned notes
```

Notes are kept in two places: notes on entities, and notes on articles or on nothing. `note:` searches both. `note.about:` takes an entity kind (`threat_actor`, `malware`, `cve`, `ttp`, `campaign`, `vendor`, `product`) or `entry` or `standalone`.

Some properties only exist on one kind of note. `note.type:` and `note.about:<entity kind>` apply to entity notes only. `note.pinned:` and `note.about:entry` / `standalone` apply to the others only. So `note.pinned:true note.about:cve` can never match anything.

**Ransomware victims**

```text
ransomware_victim.sector:manufacturing   # victim sector
ransomware_victim.domain:acme.com        # victim domain
ransomware_victim.group:lockbit          # group that posted the victim, as the leak site spelled it
```

#### Catalogue Suffixes

These suffixes work on several entity types:

```text
threat_actor.articles:>100      # how many articles mention it
malware.seen:>2026-01-01        # last seen in an article
ttp.first_seen:>2026-06         # first seen
threat_actor.review:true        # flagged for review
cve.via:ai_extraction           # how the record was created
```

- `.articles`, `.seen`, `.first_seen`: on `ttp`, `threat_actor`, `malware`, `country`, `sector`, `tool`, `vendor`, `product`, `mitigation`, `cwe`, `observable` and `ioc`.
- `.review`, `.via`: on `threat_actor`, `malware`, `cve`, `ttp` and `tool`.

So `cve.via:ai_extraction` works but `cve.first_seen:` does not.

Date suffixes take `YYYY-MM-DD` or `YYYY-MM`. A date with no operator, or with `>`, means "on or after". `<` means "on or before".

#### Value Types

| Kind | How it matches | Fields |
|------|----------------|--------|
| entity | Contains the value, ignoring case, plus aliases. Quoted means exact | `threat_actor`, `cve`, `malware`, and the other type names |
| exact | Equals the value, ignoring case. Part of a value matches nothing; add `*` for a pattern | Most `<type>.<property>` fields |
| true/false | `true`, `yes`, `1`, `y` or `false`, `no`, `0`, `n`. Anything else is ignored | `cve.kev`, `cwe.deprecated`, `ttp.subtechnique`, `ttp.deprecated`, `rule.draft`, `note.pinned`, `<type>.review` |
| list | Contains the value anywhere in the list, ignoring case: `rule.data_source:process` finds "Process Creation" | `rule.data_source`, `rule.tactic`, `rule.tag`, `note.tag`, `tool.platform`, `ttp.platform`, `ttp.data_source` |
| number | Use `>`, `>=`, `<`, `<=` or a range `a..b` | `cve.cvss`, `cve.epss`, `cve.epss_percentile`, `cve.poc`, `observable.reports`, `observable.feeds`, `<type>.articles` |
| date | `YYYY-MM-DD` or `YYYY-MM` | `<type>.seen`, `<type>.first_seen` |
| linked table | Contains the value, looked up in a related table | `cve.product`, `threat_actor.sector`, `malware.sector`, `product.vendor`, `ransomware_victim.group` |

---

## Boolean Operators

### AND

Both sides must match. Words next to each other are joined with AND.

```text
ransomware AND APT29
threat_actor:APT28 cve.cvss:>8.0
```

AND binds tighter than OR: `a OR b AND c` means `a OR (b AND c)`.

Filters on **different entity types** are the exception: they are combined with OR, not AND. `threat_actor:APT28 cve.cvss:>8.0` returns articles linked to APT28 *or* to a CVE above 8.0. See [Limitations](#limitations), item 5.

### OR (Disjunction)

Either side can match.

These work:

- Plain words: `APT28 OR APT29`.
- Groups of words: `(APT28 OR APT29) AND ransomware` runs as two searches, `APT28 ransomware` and `APT29 ransomware`, and merges them.
- Filters on the same entity type: `threat_actor:APT28 OR threat_actor:APT29`.
- Filters on different entity types: `cve:* OR threat_actor:*`.
- Index filters: `tag:a OR tag:b`, `is:noted OR is:bookmarked`, `(tag:a type:rss) OR tag:b`.
- Feed filters: `feed:"Red Canary" OR feed:"Reddit Digest"`, `category:`, `feed.*:` and `is:muted`, with each other and with index filters.
- Database filters with each other: `signal:under_reported OR signal:kev_added`, `signal:kev_added OR url:github.com`.
- Words with index or feed filters: `ransomware OR tag:a` runs two searches and merges them. The total count is then an upper bound (see [Result Limits](#result-limits--pagination)).

These do not work:

- **Words or article filters OR'd with an entity filter.** `ransomware OR threat_actor:APT29` returns the entity matches, but the article list comes back unfiltered.
- **Words OR'd with `signal:`, `url:`, `is:translated` or `is:image`.** `ransomware OR signal:kev_added` drops `ransomware` and returns only the signal matches.
- **`date:` or `words:` inside an OR.** `tag:x OR date:2025` keeps only the date filter.
- **An AND group of entity filters inside an OR.** `(threat_actor:APT29 AND threat_actor.country:Russia) OR threat_actor:APT28` returns nothing. All three conditions are joined with AND, and no actor is both APT29 and APT28. The same shape with article filters works.
- **Repeating `feed:` without OR.** `feed:A feed:B` matches nothing, because no article is in two feeds.

### NOT (Negation)

```text
NOT tag:noise
ransomware NOT tag:digest
```

NOT only works on field filters. On plain words, and on `title:`, `content:` and `author:`, it is dropped: `ransomware NOT phishing` is the same as `ransomware`. On `date:` it has no effect.

NOT applies to the next item. Use brackets to negate a group:

```text
NOT (tag:a AND tag:b)     # not both tags
NOT (tag:a OR tag:b)      # neither tag
```

For article filters this follows normal logic. For entity filters, each condition inside the brackets is negated on its own and the results are joined with AND.

Negating an entity filter selects the *other* records of that type. `NOT threat_actor:APT28` returns articles linked to some other actor. An article that names APT28 and another actor is still included, and an article with no actor is not.

### Operator Precedence

1. Brackets (first)
2. NOT
3. AND (typed or implied)
4. OR (last)

```text
a OR b AND c              → a OR (b AND c)
(a OR b) AND c            → (a OR b) AND c
NOT a AND b               → (NOT a) AND b
a OR NOT b OR c           → a OR (NOT b) OR c
```

---

## Ranges and Comparators

### Numeric Ranges

Number fields (`cve.cvss`, `cve.epss`, `cve.epss_percentile`, `cve.poc`, `observable.reports`, `observable.feeds`, `<type>.articles`, `words`) take comparators and ranges:

```text
cve.cvss:>9.0               # greater than
cve.cvss:>=8.5              # greater than or equal
cve.cvss:<7.0               # less than
cve.cvss:8.5..9.5           # between, inclusive
cve.cvss:9.8                # exactly
cve.cvss:9*                 # 9.0 to 9.9
```

Comparators only work on numbers. `rule.severity:<=medium` does not work; list the values instead: `(rule.severity:medium OR rule.severity:low)`.

### Date Ranges

```text
date:>=2025-01-01
date:2025-01..2025-06
date:2025-01-15..2025-03-20
```

See [Date Filtering](#date-filtering).

### Value Wildcards

`*` in a field value makes it a pattern. It works at the end or in the middle.

```text
cve:CVE-2024-*              # CVE IDs from 2024
ttp:T1566*                  # T1566, T1566.001, ...
threat_actor:Laz*rus        # middle of the value
tag:critical*               # tags starting "critical"
feed:Krebs*                 # feed names starting "Krebs"
```

A pattern must match the whole value, so put `*` wherever any text may appear. Without `*`, `feed:`, `category:`, `url:` and entity names match anywhere in the value.

**No wildcards in plain text.** The search index has no wildcard operator. A trailing `*` is removed (`ransom*` searches `ransom`, which already matches "ransomware"). A `*` in the middle splits the word: `ran*ware` searches for "ran" and "ware".

---

## How Queries Route

Search uses two back ends: Meilisearch for article text, PostgreSQL for intelligence records and a few article fields. The [query routing diagram](diagrams/query-language-routing.md) shows the full flow.

### Query Classification

The query planner (`backend/app/search/query_planner.py`) sorts each part of the query into one of four groups:

- **Index fields** go to Meilisearch: words, `title`, `content`, `author`, `tag`, `type`, `media`, `lang`, `words`, `date`, and `is:` starred / read / unread / bookmarked / noted.
- **Feed filters** are looked up in PostgreSQL and turned into a list of feeds: `feed`, `category`, `feed.reliability`, `feed.timeliness`, `feed.relevance`, `is:muted`.
- **Database article filters** are looked up in PostgreSQL and turned into a list of articles: `signal`, `url`, `is:translated`, `is:image`.
- **Entity fields** query the intelligence tables in PostgreSQL.

A query with words and no entity filter also searches entity names, so typing `lockbit` shows the LockBit records next to the articles.

### Execution

1. Feed filters become a list of feed IDs.
2. Database article filters become a list of article IDs.
3. Entity filters return the matching records and the IDs of the articles linked to them.
4. The article ID lists are intersected.
5. Meilisearch searches the words and index filters, limited to those IDs.

### When the query bypasses Meilisearch

The search reads articles straight from PostgreSQL in three cases:

- The query uses `sort:radar`.
- There is an ID list and nothing for the index to search (for example a query of only entity filters, or only `signal:under_reported`).
- The ID list has more than 500 articles.

On this path:

- Counts are exact.
- `sort:relevance` becomes newest first.
- The article facets on the results page are empty.
- Words and index filters are not applied (see [Limitations](#limitations), item 7).

### Result Limits & Pagination

- Articles: 20 per page by default, up to 500 per request.
- Entity records: `entity_limit` defaults to 200, maximum 500. The records with the most articles come first. The linked articles come from every match, not just the records returned.
- `entity_group_limit` defaults to 25, maximum 500: how many records of each type the response carries.
- `entities.counts` is counted before that per-type cut, so the facet rail can say "Threat Actors 57" while showing 25.
- Article totals from Meilisearch are estimates. From PostgreSQL they are exact.
- A query that runs several searches (because of OR) adds the totals together. An article that matches two branches is counted twice. Each branch fetches at most 1,000 results, which limits how far you can page.

### Direct Matches vs Mentions

Each entity result has a `match_kind`:

- **`direct`**: the query matched the record's name, an alias, or its ID (technique ID, CVE ID, MITRE ID).
- **`mention`**: the query matched something the record only talks about, like its description or tags.

A rule or report title counts as a direct match only when it starts with the query. "Detects a backdoor used by LockBit affiliates" mentions LockBit; it is not LockBit.

Results from a field filter (like `cve.kev:true`) are always `direct`. The search page shows direct matches first, and the facet rail can filter on the difference. Results from `note:` are the exception: they have no `match_kind` and appear under Mentions.

### Notes as Results

Notes are found two ways: plain words search them, and `note:` filters them directly. Both kinds of note come back as one `note` result type, told apart by `note_source`:

| `note_source` | Where the note is | Extra fields |
|---------------|-------------------|--------------|
| `note` | On an article, or on nothing | `entry_id`, `entry_title`, `is_pinned` |
| `entity_note` | On an actor, malware, CVE, TTP, campaign, vendor or product | `entity_type`, `entity_id`, `entity_name`, `note_type` |

Every note result also has `title`, `tags` and `match_field`.

- The description is a short piece of text (about 190 characters) around the match, not the start of the note.
- An entity note with no title is named after its subject, for example "Note on CVE-2026-20262".
- For plain-word searches, a title match is `direct` and a body or tag match is `mention`.
- Notes are listed after all other entity types.

**Anyone on the instance can find any note.** Search shows every note, the same as the notes browser. Only the author or an admin can edit or delete one. Don't write anything in a note you wouldn't want a colleague to read.

---

## The Search Surface

There is one search box, in the app header. Typing in it opens `/search`, the page that shows results.

### Scope (`in:`)

The box has a scope chip. Press Tab (or click the chip) to change it:

| Scope | Shows |
|-------|-------|
| `everything` | Entities and articles |
| `workbench` | Entities only |
| `feeds` | Articles only |

The scope only changes what the results page shows. It starts at `everything` and stays where you put it.

### The Facet Rail

The left side of the results page has filters:

- **Scope** and **entity type**, with counts. Notes appear as their own type when a note matches.
- **Matched on**: direct or mention.
- **Article facets**: date, read state, feed, content type, tags, media, language.

Ticking an article facet writes the filter into the search box. "Last 7 days" and "Unread" become `date:>=… is:unread`, which you can edit and save.

On a phone, the rail opens from a **Filters** button.

### Opening a Note Result

| Note | Opens |
|------|-------|
| On an entity | That entity's profile, **Notes** tab |
| On an article | The article, with the **Notes** panel |
| Standalone | The notes browser, filtered to that note's title |

### Did You Mean

`country:North Korea` searches `country:North` plus the word `Korea`, and returns a plausible but wrong answer. When a value followed by the next word is a real value for that field, the results page offers the quoted version: `country:"North Korea"`. `threat_actor:APT29 ransomware` gets no suggestion, because no actor is called "APT29 ransomware".

Picking a value from the autocomplete adds the quotes for you.

### Autocomplete

Field names and values complete as you type. The suggestions come from two lists: `GET /api/search/autocomplete` (`FIELD_SUGGESTIONS` in `backend/app/api/search.py`) and `frontend/src/components/search/queryFields.ts`, which also drives the syntax help card. Neither list is checked against the planner, so a suggestion can be a field that does not work. When they disagree, the planner's `ENTRY_FIELDS` / `ENTITY_FIELDS` decide.

### The Rule Library's own search

The Rules Library (Workbench → Detection → Rules Library) has its own search and does not use this language. It uses a separate Meilisearch index through `GET /api/detection-rules/search`. Use `rule:` filters in the main search box to find rules next to other intelligence.

---

## Worked Examples

### Example 1: Recent Critical CVEs

```text
cve.cvss:>=9.0 date:>=2025-04-01
```

Articles linked to a CVE scoring 9.0 or more, published on or after April 1, 2025. Change the date to suit.

### Example 2: Articles About APT29

```text
threat_actor:APT29
```

Aliases are checked, so if "Cozy Bear" is an alias of APT29, articles linked to APT29 are found either way.

### Example 3: Unread Ransomware Articles from RSS Feeds

```text
ransomware is:unread type:rss
```

The word `ransomware`, not marked read, from RSS feeds.

### Example 4: High-Severity Detection Rules

```text
rule.severity:high rule.type:sigma
```

Both filters are on rules, so a rule must match both. Add critical rules too: `rule.type:sigma (rule.severity:critical OR rule.severity:high)`.

### Example 5: Techniques Outside a Tactic

```text
ttp:* NOT ttp.tactic:impact
```

Articles linked to at least one technique whose main tactic is not Impact.

### Example 6: Spanish-Language Actor Reporting

```text
threat_actor:* lang:es
```

Articles in Spanish that are linked to any threat actor.

### Example 7: Recent YouTube Videos

```text
type:youtube date:>=2025-03-27
```

### Example 8: Bookmarked Articles

```text
is:bookmarked
is:noted OR is:bookmarked
```

### Example 9: Known-Exploited CVEs with High CVSS

```text
cve.kev:true cve.cvss:>=8.5 date:>=2025-03-20
```

Both CVE filters apply to the same CVE. KEV status is a field on the CVE record, so this is more reliable than searching the words "CISA" or "KEV".

### Example 10: Two Actors, Without Digests

```text
(APT28 OR APT29) NOT tag:digest
(threat_actor:APT28 OR threat_actor:APT29) NOT tag:digest
```

The first searches the text. The second uses linked actor records.

### Example 11: Starred Articles with a Tag

```text
is:starred tag:critical
is:starred (tag:critical OR tag:urgent)
```

`tag:critical tag:urgent` needs both tags. Use OR for either.

### Example 12: CVEs Likely to Be Exploited

```text
cve.kev:true cve.epss:>0.5
```

In CISA KEV and an EPSS score above 50%.

### Example 13: Rules You Can Deploy

```text
rule.data_source:sysmon rule.tactic:persistence
```

Persistence rules that need Sysmon data.

### Example 14: The Engine's Own Queue

```text
signal:under_reported sort:radar
```

Answered from PostgreSQL: exact counts, priority order, unscored articles left out.

### Example 15: Leak-Site Monitoring

```text
ransomware_victim.group:lockbit ransomware_victim.sector:manufacturing
```

Manufacturing victims posted by LockBit.

### Example 16: Curation Backlog

```text
threat_actor.via:ai_extraction threat_actor.articles:>10
```

AI-created actors with more than 10 articles, worth reviewing.

### Example 17: Some Feeds, One Quarter

```text
(feed:Shodan OR feed:Censys) date:2025-01..2025-03
```

`feed:Shodan` already covers every feed with "Shodan" in its name.

---

## Saved Searches

A saved search stores a query under a name.

### Creating a Saved Search

1. Type a query in the search box.
2. Click **Save** and give it a name.

The query text is saved as typed. Opening a saved search runs it through `POST /api/search/unified`, the same as typing it.

### Match Counts

The `refresh_saved_search_counts` task recounts every saved search every 5 minutes (up to 5,000 matches each) and caches the counts in Redis for 10 minutes.

**The count next to a saved search can be wrong. The results are not.** The counter skips entity filters:

- A query of only entity filters (`threat_actor:APT29`, `cve.kev:true`) counts 0.
- Words plus an entity filter (`ransomware threat_actor:APT29`) counts the words alone, which is too high.
- `signal:` and `url:` count at most 500 matches.

Counts are right for queries built from words, `tag:`, `type:`, `feed:`, `category:`, `date:` and `is:`.

### Campaign Auto-Sync

A saved search can be attached to a campaign with auto-sync on. The `sync_campaign_saved_searches` task (every 5 minutes) reruns the query for active and monitoring campaigns and adds new matching articles to the campaign, up to 1,000 per run. This runs entity filters, so `threat_actor:APT29` works here.

### Query Validation

- A query that cannot be parsed, such as one with an unclosed bracket, is treated as an empty search and returns all articles.
- A field with no value, like `threat_actor:`, is still a filter and matches broadly.

---

## Entity Pivot Links

Clicking an entity in an article opens a popover. From there you can open the entity's profile or search for it.

### Pivot Query Pattern

The popover's **Search** button puts the entity name in the search box as a quoted phrase (for example `"Cozy Bear"`) and opens `/search`. For a filter instead, type it yourself:

```text
threat_actor:APT29
cve:CVE-2024-1234
ttp:T1566.001
```

### External Pivot Platforms

Entity profiles and the Workbench also link to outside sites (`frontend/src/utils/pivotLinks.ts`):

| Type | Sites |
|------|-------|
| `threat_actor` | MITRE ATT&CK, Google, Mandiant, CISA, Recorded Future |
| `malware` | VirusTotal, MalwareBazaar, Hybrid Analysis, MITRE ATT&CK, Google |
| `ttp` | MITRE ATT&CK, Google, Sigma rules on GitHub |
| `cve` | CVE.org, NVD, CVEDetails, MITRE, ExploitDB |
| `cwe` | MITRE CWE, CVEDetails, Google |
| `country` | Wikipedia, Google, CISA |
| `sector` | Google, CISA |

### Manual Pivot Construction

Link to `/search?q=` with a URL-encoded query to open the results page with that query filled in:

```text
/search?q=threat_actor%3AAPT29
```

---

## Tips & Limitations

### Best Practices

1. **Quote values with spaces.** `threat_actor:"Cozy Bear"` is one filter. `threat_actor:Cozy Bear` is a filter for `Cozy` plus the word `Bear`.
2. **Mix entity and article filters.** `threat_actor:APT29 is:unread date:>=2025-01-01` finds unread APT29 articles from 2025 on.
3. **Use wildcards to explore.** `cve:CVE-2024-*`, `ttp:T1*`, `tag:critical*`.
4. **Use OR for alternatives**, but check [the cases that don't work](#or-disjunction).
5. **Prefer a field to a phrase.** `cve.kev:true` checks the CVE record. `"known exploited vulnerability"` only finds articles that used those words.
6. **Let the facet rail write filters.** Tick facets and read the search box to learn the syntax.

### Limitations

1. **No NOT on plain words.** `ransomware NOT phishing` is the same as `ransomware`, and `NOT phishing` alone matches everything. `NOT` works on field filters, except `date:`.
2. **No regex.** Only `*`, and only in field values.
3. **No stemming.** `run` does not match `running`.
4. **Quoted entity values are strict.** `threat_actor:apt29` matches APT29 and its aliases. `threat_actor:"apt29"` must equal the main name exactly, including case, so it matches nothing.
5. **Filters on different entity types combine with OR.** `threat_actor:APT29 malware:Emotet` returns articles linked to APT29 *or* to Emotet, even with `AND` between them. Filters on the same type do combine with AND.
6. **NOT on an entity filter means "some other record".** `NOT threat_actor:APT28` returns articles linked to a different actor. Articles that also name APT28 are kept, and articles with no actor are dropped.
7. **Large or radar queries skip words and index filters.** When a query is answered from PostgreSQL (more than 500 linked articles, or `sort:radar`), words and the index filters (`tag:`, `type:`, `media:`, `lang:`, `date:`, `words:`, `feed:`, `category:`, `is:`) are not applied. `cve.kev:true date:>=2026-01-01` can return KEV articles from any date. Narrow the entity side, or use a filter from the same entity type, to stay under 500.
8. **NOT on a database filter needs something to subtract from.** `NOT signal:...`, `NOT url:...`, `NOT is:translated` and `NOT is:image` only work when the query also has an entity filter or a positive database filter. Next to words or index filters alone they are ignored.
9. **Feed grades are exact.** `feed.reliability:B` matches B only.
10. **Some OR combinations don't work.** See [OR](#or-disjunction).
11. **`note:` covers two tables.** Some note properties only apply to one kind of note (see [Notes](#entity-properties)).
12. **`is:starred` and friends are shared.** The starred, read, bookmarked and noted flags in the search index show the last change anyone made.
13. **Search history stays in your browser.** The last 10 searches are kept in this browser and shown when the box is empty. Save a search to keep it on the server.

### Debugging Queries

1. **Check the chips.** `POST /api/search/unified` returns a `parsed_filters` list, and the search page shows it as chips. Check that each filter is what you meant. A field name the search doesn't know appears in `unknown_fields` and is searched as text, so `titel:ransomware` searches for `ransomware`.
2. **Remove filters one at a time** until the results look right, then add them back.
3. **Check the record.** If `threat_actor:APT29` returns nothing, open the actor list and check the name and aliases.

---

## Cross-References

- [Searching (user guide)](guide/searching.md): using the search box, facet rail and saved searches.
- [Workers, search and dashboards](workers-search-dashboards.md): Meilisearch indexing and background tasks.
- `backend/app/api/search.py`: the search endpoints.
- `backend/app/search/query_parser.py`: the grammar.
- `backend/app/search/query_planner.py`: field lists, OR handling, and `resolve_deferred_filters()`.
- `backend/app/search/entity_builder.py`: how entity filters become SQL (`FIELD_MAP`).
- `frontend/src/components/search/queryFields.ts`: the field list used by autocomplete and the syntax help card.
- `backend/app/api/saved_searches.py`: saved searches.
