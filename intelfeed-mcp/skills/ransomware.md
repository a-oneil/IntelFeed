---
name: ransomware
description: ransomware leak-site victims, group activity and sector/country trends
tools: get_ransomware_stats, get_ransomware_disclosures, get_ransomware_group_victims, get_ransomware_victim, list_watches, get_profile
---
- Landscape ("what's happening in ransomware"): get_ransomware_stats(days=30) — victim totals and week-over-week change, top groups, sectors, countries, watchlist exposure.
- Recent victims: get_ransomware_disclosures(since=7, limit=15). Filters: group=["Qilin"], sector=["healthcare"], country=["US"], q="<org name>", watched_only=true, sort=recent|group|sector.
- One group: get_profile(entity_type="threat_actor", id="<group>"), then get_ransomware_group_victims(actor_id=<id>).
- One victim: get_ransomware_victim(victim_id=<id>) — every leak-site post and the groups that listed it.
Leak-site claims are the gang's claims, not confirmed breaches; say so. Give counts with their time window.
