---
name: actor-research
description: profile a threat actor, malware family or tool (aliases, TTPs, links, recent activity)
tools: search_entities, get_profile, get_entity_whats_new, pivot_entity, list_entity_relationships, get_entity_timeline, get_enrichment_data, get_ransomware_group_victims, list_entity_notes, search_entries, who_targets_sector
---
Steps for "tell me about <actor/malware>":
1. get_profile(entity_type, id=<name>) — a name works; if several match, pick the right id from the list it returns.
2. pivot_entity(entity_type, entity_id, window_days=90) — the malware, tools, CVEs, TTPs and victims seen with it.
   For "who targets <industry>?" start from the sector instead: who_targets_sector(sector="healthcare") ranks actors and malware by articles describing them hitting it.
3. list_entity_relationships — analyst-grade links (uses, attributed_to, variant_of...) with confidence.
4. search_entries(query="threat_actor:<name>", sort="newest", limit=5) — latest reporting. For malware use malware:<name>.
5. What changed lately: get_entity_whats_new(entity_type, entity_id, days=14) — first mentions, new techniques, new victim sectors on its recent articles.
6. Only if needed: get_entity_timeline (activity over time), get_enrichment_data (Wikipedia/Malpedia background), get_ransomware_group_victims (for ransomware groups), list_entity_notes (analyst notes).

Answer shape: aliases and attribution first, then TTPs (ATT&CK ids with names), tooling/malware, targeting (sectors, countries), recent activity with article dates. Separate "reported in IntelFeed" from general knowledge, and say when data is missing.
Aliases matter: APT29 = Cozy Bear = Midnight Blizzard. If a lookup fails, try an alias.
