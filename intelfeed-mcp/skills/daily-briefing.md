---
name: daily-briefing
description: what's new and what to read first (priority queue, daily summary, story threads, correlations)
tools: get_priority_queue, get_triage_queue, get_daily_summary, get_story_threads, get_story_thread, get_correlation_events, get_temporal_clusters, get_dashboard_stats, get_trending_entities
---
For "what's new / brief me / what should I read":
1. get_daily_summary() — today's generated briefing, if one exists (null otherwise). date="YYYY-MM-DD" for another day.
2. get_priority_queue(limit=10) — unread articles ranked the way the Priority Queue page ranks them.
3. get_story_threads(status="open", limit=8) — developing stories; get_story_thread(slug) for one story's timeline.
4. get_correlation_events(unread_only=true, limit=10) — new TTPs for known actors, KEV additions, campaign/PIR matches.
5. get_trending_entities(entity_type="threat_actor", days=7) — repeat for malware / cve if useful.
Optional: get_temporal_clusters (articles sharing entities in a short window — possible new campaigns), get_triage_queue(days=1), get_dashboard_stats (volumes).
Don't call everything: 2–4 calls usually make a good briefing. Group by theme, most important first, with article dates.
