---
name: feeds-sources
description: feeds, their health and value, and what sources IntelFeed covers
tools: get_feeds, get_feed_entries, get_feed_value, get_source_reliability, get_search_facets, list_categories
---
- Feeds and health: get_feeds(limit=30). Latest from one feed: get_feed_entries(feed_id, limit=10).
- Which sources matter: get_feed_value(days=30) (0–100 score) or get_source_reliability(limit=10).
- What's in the system: get_search_facets (feed types, categories, top tags) and list_categories.
