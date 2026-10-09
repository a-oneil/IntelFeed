---
name: iocs
description: look up indicators (IPs, domains, URLs, hashes) in the observables ledger
tools: get_observable, search_observables, get_entity_infrastructure, export_observables, pivot_entity, search_entries
---
- One indicator: get_observable(observable="<ip/domain/hash/url>") — role (c2, payload...), status, first/last seen, linked articles and entities.
- Find indicators: search_observables(query="<text>", kind="domain|ipv4|sha256|url|...", role="c2", min_reports=1, limit=10) — min_reports=1 keeps blocklist-only rows out.
- An actor's / family's infrastructure: get_entity_infrastructure(entity_type="threat_actor|malware|campaign|tool", entity_id=<id>) — "claimed" (attribution edges with evidence) vs "reported_alongside" (same articles, not a claim).
- Hand over a block list: export_observables(format="edl|csv|json", role="c2", min_reports=1) — refanged, dual-use infra excluded.
- What it connects to: pivot_entity(entity_type="observable", entity_id=<id>).
- Articles mentioning it: search_entries(query="observable:<value>").
Defang indicators in answers (hxxp://, evil[.]com, 1.2.3[.]4).
