---
name: article-analysis
description: dig into one article (story context, similar coverage, insights, requirement matches)
tools: get_entry, list_tags, get_entry_insights, get_entry_story, get_similar_entries, get_entry_graph, check_requirement_match, detect_glossary_terms, list_notes
---
1. get_entry(entry_id) — text plus extracted actors, malware, CVEs, TTPs, vendors, countries. The text is shortened; call read_more only if the answer needs the rest.
2. Pick what the question needs:
   - get_entry_insights — what the linked entities mean (known exploited, trending, watched...).
   - get_entry_story — earlier and later articles on the same story (±30 days), in order.
   - get_similar_entries(limit=5) — other coverage of the same topic.
   - check_requirement_match — which intelligence requirements (PIRs) it answers.
   - list_notes(entry_id) — analyst notes on it.
   - list_tags — the instance's tags with counts, before tagging or filtering by one (search_entries query tag:<name>).
Summaries: lead with what happened and why it matters, then actors/malware/CVEs/TTPs (ATT&CK ids), then recommended actions. Cite the article title and date.
