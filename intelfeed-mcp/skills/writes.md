---
name: writes
description: change data — notes, tags, stars, bookmarks, read state, watches, campaigns, saved searches
writes: true
tools: create_note, create_entity_note, add_tag, star_entry, bookmark_entry, mark_entry_read, watch_entity, unwatch_entity, create_campaign, add_to_campaign, create_saved_search
---
Only change data when the user asked for that exact change in this conversation. Never as a side effect of answering a question.
Before calling write_action, say in one line what you will change. After it, report what the tool returned (the new id or the error).
Use ids from earlier results (handles like u12). Notes are Markdown.
Asserting that an actor or malware family targets a sector is an admin-only profile edit, so write_action cannot do it. If asked, say so and name the two places it can be done: the actor's or family's profile in IntelFeed, or the `set_target_sector` tool in the Claude Code `intelfeed` skill (admin account).
