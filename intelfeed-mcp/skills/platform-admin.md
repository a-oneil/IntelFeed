---
name: platform-admin
description: entity hygiene, AI extraction quality, autolinks and automation rules (admin views)
tools: get_hygiene_stats, get_hygiene_feed, get_entity_link_stats, list_entity_links, get_extraction_stats, list_extraction_entities, get_automation_rules, get_automation_logs, get_automation_templates
---
- Hygiene: get_hygiene_stats (pending merges/renames, orphans, last runs), get_hygiene_feed(pending=true, limit=15).
- AI-created entities: get_extraction_stats(window="7d"), list_extraction_entities(status="review", limit=15).
- Autolinks: get_entity_link_stats, list_entity_links(entity_type, entity_id, limit=15).
- Automation: get_automation_rules, get_automation_logs(rule_id, limit=10), get_automation_templates.
These are read-only views; applying changes happens in the IntelFeed web app.
