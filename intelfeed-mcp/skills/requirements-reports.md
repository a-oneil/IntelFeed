---
name: requirements-reports
description: intelligence requirements (PIRs), intel reports, analyst notes, watchlist, saved searches
tools: get_requirements, get_requirement_coverage, list_intel_reports, get_profile, list_notes, list_entity_notes, list_watches, list_saved_searches
---
- PIRs: get_requirement_coverage (summary, stale ones) and get_requirements(status="active").
- Reports: list_intel_reports(status="published"), then get_profile(entity_type="intel_report", id=<id>) for one report's content.
- Notes: list_notes(search="<text>") for article/standalone notes; list_entity_notes(entity_type, entity_id) for notes on an actor, CVE, etc.
- Watchlist: list_watches(mode="watch") — watched entities; mode="stack" — vendors/products the user runs; mode="mute" — muted.
- Saved searches: list_saved_searches — with unread counts; run one with search_entries using its query.
