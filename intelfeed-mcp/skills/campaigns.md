---
name: campaigns
description: tracked campaigns (timeline, linked intel, detection gaps, suggested articles)
tools: get_campaigns, get_profile, get_campaign_timeline, get_campaign_detection_gaps, suggest_campaign_entries, export_campaign
---
- List: get_campaigns(status="active"). Status: active, monitoring, closed, historical.
- One campaign: get_profile(entity_type="campaign", id=<id or name>) — linked entries, entities and gaps.
- Chronology: get_campaign_timeline(campaign_id).
- Coverage: get_campaign_detection_gaps(campaign_id) — covered, blocked by missing telemetry, no rule.
- New articles that probably belong: suggest_campaign_entries(campaign_id, limit=5).
export_campaign returns a very large package; prefer the calls above.
