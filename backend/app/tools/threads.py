"""Story thread tools — an unfolding story as one object, not twenty-three rows.

The same reads the Priority Queue and the reader use. A thread has no page of
its own in the UI, so ``/priority-queue?thread=<slug>`` is the address to hand
back to an analyst who wants to open one.
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.tools import _tool


@_tool(
    name="get_story_threads",
    description=(
        "List story threads — unfolding stories assembled from the articles that cover them, with "
        "the re-reports folded underneath. Each row carries its outlets, article and echo counts, "
        "key entities, how much is unread, and the priority score of its best unread beat. Use "
        "this instead of searching for a story twenty-three times."
    ),
    input_schema={
        "properties": {
            "status": {
                "type": "string",
                "enum": ["open", "dormant", "closed", "any"],
                "description": "open (still accepting articles), dormant, closed, or any. Default open",
            },
            "limit": {"type": "integer", "description": "Maximum threads returned (1-200, default 40)"},
        },
    },
    mutating=False,
)
async def _get_story_threads(
    db: AsyncSession,
    user_id: uuid.UUID,
    status: str = "open",
    limit: int = 40,
) -> dict:
    from app.intelligence.story_threads import list_threads

    if not 1 <= limit <= 200:
        return {"error": "limit must be between 1 and 200"}
    rows = await list_threads(db, user_id, status=status, limit=limit)
    return {
        "threads": [
            {
                "slug": r["slug"],
                "title": r["title"],
                "summary": r.get("summary"),
                "status": r["status"],
                "entry_count": r.get("entry_count") or 0,
                "source_count": r.get("source_count") or 0,
                "echo_count": r.get("echo_count") or 0,
                "unread_count": r.get("unread_count") or 0,
                "new_since_opened": r.get("new_since_opened") or 0,
                "top_score": r.get("top_score"),
                "first_seen": r.get("first_seen"),
                "last_seen": r.get("last_seen"),
                "key_entities": [
                    {"type": e.get("entity_type"), "label": e.get("label"), "articles": e.get("count")}
                    for e in (r.get("key_entities") or [])
                ],
            }
            for r in rows
        ],
        "total": len(rows),
    }


@_tool(
    name="get_story_thread",
    description=(
        "Read one story thread: its spine (one beat per wave of coverage — what broke, what each "
        "wave added), every member article with its role (origin, beat, or folded echo), what the "
        "story has yielded in techniques/CVEs/products/detection rules, and the threads it most "
        "resembles. Open it in the UI at /priority-queue?thread=<slug>."
    ),
    input_schema={
        "properties": {
            "slug": {"type": "string", "description": "Thread slug, from get_story_threads"},
            "include_members": {
                "type": "boolean",
                "description": "Include the full member article list (default true)",
            },
        },
        "required": ["slug"],
    },
    mutating=False,
)
async def _get_story_thread(
    db: AsyncSession,
    user_id: uuid.UUID,
    slug: str,
    include_members: bool = True,
) -> dict:
    from app.intelligence import story_threads

    row = await story_threads.get_thread(db, slug, user_id)
    if row is None:
        return {"error": f"No story thread with slug '{slug}'"}

    thread_id = row["id"]
    beats = await story_threads.thread_beats(db, thread_id)
    members = await story_threads.thread_members(db, thread_id, user_id)
    result = {
        "slug": row["slug"],
        "title": row["title"],
        "summary": row.get("summary"),
        "status": row["status"],
        "url": f"/priority-queue?thread={row['slug']}",
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "entry_count": row.get("entry_count") or 0,
        "source_count": row.get("source_count") or 0,
        # Null means the spine is the day-grouped fallback, not a written one.
        "narrated_at": row.get("narrated_at"),
        "key_entities": [
            {"type": e.get("entity_type"), "label": e.get("label"), "articles": e.get("count")}
            for e in (row.get("key_entities") or [])
        ],
        "spine": [
            {
                "kind": b["kind"],
                "occurred_at": b["occurred_at"],
                "headline": b["headline"],
                "body": b["body"],
                "lead_entry_id": b["lead_entry_id"],
                "folded_re_reports": b["collapsed_count"] or 0,
            }
            for b in beats
        ],
        "thread_yield": await story_threads.thread_yield(db, thread_id),
        "nearest": [
            {"slug": n["slug"], "title": n["title"], "similarity": round(float(n["similarity"] or 0), 3)}
            for n in await story_threads.nearest_threads(db, thread_id)
        ],
    }
    if include_members:
        result["members"] = [
            {
                "entry_id": str(m["entry_id"]),
                "title": m["title"],
                "url": m["url"],
                "published_at": m["published_at"],
                "source": m["source_key"],
                "role": m["role"],
                "similarity": round(float(m["similarity"] or 0), 3),
                "is_read": bool(m["is_read"]),
            }
            for m in members
        ]
    return result
