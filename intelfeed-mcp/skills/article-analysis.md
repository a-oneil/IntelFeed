---
name: article-analysis
description: dig into one article (story context, similar coverage, detection gaps, requirement matches)
tools: get_entry, list_tags, get_entry_insights, get_entry_story, get_similar_entries, get_entry_graph, check_requirement_match, detect_glossary_terms, list_notes
---
1. get_entry(entry_id) — text plus extracted actors, malware, CVEs, TTPs, vendors, countries. The entities cover the whole article, but a long article's text comes one part at a time: if an entity matters and you can't see it in the text, read on with the `get_entry(entry_id, offset)` call in the footer.
2. Pick what the question needs:
   - get_entry_insights — detection gaps, campaign and requirement matches, and critical CVEs among the linked entities.
   - get_entry_story — earlier and later articles on the same story (±30 days), in order.
   - get_similar_entries(limit=5) — other coverage of the same topic.
   - check_requirement_match — which intelligence requirements (PIRs) it answers.
   - list_notes(entry_id) — analyst notes on it.
   - list_tags — the instance's tags with counts, before tagging or filtering by one (search_entries query tag:<name>).
Summaries: lead with what happened and why it matters, then actors/malware/CVEs/TTPs (ATT&CK ids), then recommended actions. Cite the article title and date.
