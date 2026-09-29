---
name: iocs
description: look up indicators (IPs, domains, URLs, hashes) in the observables ledger
tools: get_observable, search_observables, pivot_entity, search_entries
---
- One indicator: get_observable(observable="<ip/domain/hash/url>") — role (c2, payload...), status, first/last seen, linked articles and entities.
- Find indicators: search_observables(query="<text>", kind="domain|ipv4|sha256|url|...", role="c2", limit=10).
- What it connects to: pivot_entity(entity_type="observable", entity_id=<id>).
- Articles mentioning it: search_entries(query="observable:<value>").
Defang indicators in answers (hxxp://, evil[.]com, 1.2.3[.]4).
