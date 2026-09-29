---
name: search-syntax
description: the search query language (filters, operators, sorting)
tools:
---
Used by search_entries (and search_unified). Filters narrow; bare words are matched in title, text, author, feed and tags.

Operators: AND (implicit between terms), OR, NOT (works on filters only, e.g. NOT type:youtube), ( ), "exact phrase", * wildcard inside a value (cve:CVE-2025-*), > >= < <=, and ranges with .. (date:2026-08-01..2026-09-01).

Article fields: title: content: author: feed:"Dark Reading" category: tag: type:rss|youtube|telegram|reddit lang:en words:>1500 date:>=2026-09-01 is:unread|read|starred|bookmarked|noted sector:healthcare signal:kev_added|under_reported
Entity filters (article must be linked to it):
- threat_actor:APT29 (also .country:Russia .motivation:espionage .type:ransomware .sector:finance)
- malware:Emotet (.type:loader) · tool:Mimikatz
- cve:CVE-2025-1234 (.severity:critical .cvss:>=9 .kev:true .epss:>0.5 .poc:>0 .product:fortios)
- ttp:T1059 (.tactic:persistence .platform:Windows) · cwe:CWE-79 · mitigation:M1036
- country:"North Korea" (.region:Asia) · vendor:Cisco · product:Exchange
- campaign:"Volt Typhoon" · rule:backdoor (.type:sigma) · pir:"ransomware" · observable:evil.com (.kind:sha256)
- ransomware_victim:Acme (.group:lockbit .sector:healthcare)
Sort (sort argument or sort: in the query): relevance (default), newest, oldest, radar (IntelFeed's priority score).

Examples:
- threat_actor:APT29 AND ttp.tactic:initial-access
- cve.kev:true AND date:>2026-09-20 sort:newest
- (phishing OR "device code") NOT type:youtube
- ransomware AND sector:healthcare date:>2026-09-01

Tips: dates are YYYY-MM-DD. Prefer an entity filter (actor:, malware:) over a bare name: it matches aliases. If a filter returns nothing, retry with plain words.
