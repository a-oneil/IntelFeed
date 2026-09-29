---
name: detection-coverage
description: detection rules, ATT&CK coverage gaps and telemetry feasibility
tools: check_detection_gaps, get_detection_rules, get_profile, get_detection_rule_versions, check_telemetry_feasibility, get_telemetry_sources, validate_detection_rule, get_campaign_detection_gaps, get_analytics
---
- Overall gaps: check_detection_gaps — observed techniques with no published rule, per tactic. Then get_analytics(metric="detection_coverage") for totals.
- Rules for a technique or topic: search_entries is for articles; for rules use search_entities(query="<technique or keyword>") and look for detection_rule results, or get_detection_rules(rule_type="sigma").
- One rule: get_profile(entity_type="detection_rule", id=<id>) — content, provenance, telemetry feasibility, validation.
- Can we run it: check_telemetry_feasibility(rule_id=<id>) and get_telemetry_sources.
- Checking a rule the user wrote: validate_detection_rule(rule_type, rule_content).
- A campaign's coverage: get_campaign_detection_gaps(campaign_id).
When writing a new rule yourself, base it on the technique's data sources and the article's observables, and label it as a draft to review. Use ATT&CK ids with names.
