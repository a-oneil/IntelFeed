"""The spine of a story thread — what broke, and what each wave added.

Two writers, one contract. The sweeper writes a **heuristic** spine the moment a
thread exists: one beat per day of coverage, the day's strongest article as its
headline, the first day marked as the disclosure and the loudest as the peak.
The nightly AI pass then *replaces* that spine with a written one for threads
that have changed since it last ran.

The heuristic is not a placeholder to be embarrassed about — it is the default
rendering path. Dev runs with every AI provider inactive, prod runs on one
Ollama box, and a thread page that only works when a model answers is a thread
page that mostly does not work. AI narration upgrades the spine; it is never
required for one.

A spine is keyed by the hash of its member set, so a thread that gained nothing
since the last pass costs nothing to re-narrate.
"""

import hashlib
import html
import json
import logging
import re
import uuid
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.sanitizer import html_to_text

logger = logging.getLogger(__name__)

TASK_NAME = "story_thread_spine"
TARGET_TYPE = "story_thread"
SYSTEM_USER = uuid.UUID(int=0)

# Articles handed to the model. Beyond this the prompt stops being a story and
# starts being a corpus; the tail of a big thread is almost entirely echoes.
MAX_PROMPT_ENTRIES = 24
BODY_CHARS = 400


def member_hash(entry_ids: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(entry_ids)).encode()).hexdigest()[:16]


async def collect_members(db: AsyncSession, thread_id: uuid.UUID) -> list[dict]:
    """Thread members oldest first, with their echo counts and techniques.

    Echoes are folded into the article they echo rather than listed: they are by
    definition the same story told again, and they are what the thread exists to
    get out of the way.
    """
    rows = await db.execute(
        text(
            """
            SELECT ste.entry_id, ste.role, ste.source_key, ste.duplicate_of_entry_id,
                   e.title, e.summary, e.published_at, e.priority_score, e.priority_raw,
                   COALESCE(f.title, '') AS feed_title,
                   COALESCE(
                       (SELECT array_agg(DISTINCT t.technique_id)
                        FROM entry_ttps et JOIN ttps t ON t.id = et.ttp_id
                        WHERE et.entry_id = ste.entry_id),
                       '{}'
                   ) AS techniques
            FROM story_thread_entries ste
            JOIN entries e ON e.id = ste.entry_id
            LEFT JOIN feeds f ON f.id = e.feed_id
            WHERE ste.thread_id = :thread_id
            ORDER BY e.published_at ASC NULLS LAST
            """
        ),
        {"thread_id": thread_id},
    )
    return [dict(r) for r in rows.mappings().all()]


# A single word this long is not prose — it is a tracking URL or a base64 blob
# that survived tag-stripping. Google News items are mostly this.
_JUNK_TOKEN_CHARS = 60


def clean_body(raw: str | None) -> str | None:
    """Plain, readable prose from an entry summary — or nothing.

    Entry summaries are whatever the feed shipped: some are clean sentences,
    some are raw ``<p>`` markup, and Google News items are an anchor tag wrapped
    around a 400-character tracking token. A spine full of markup is worse than
    a spine of headlines alone, so anything that does not come out as prose is
    dropped rather than shown.
    """
    if not raw:
        return None
    text = html.unescape(html_to_text(html.unescape(raw)))
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return None
    if any(len(token) > _JUNK_TOKEN_CHARS for token in text.split(" ")):
        return None
    return text[:BODY_CHARS]


def _day(value: datetime | None) -> str:
    return value.date().isoformat() if value else "unknown"


def heuristic_beats(members: list[dict]) -> list[dict]:
    """One beat per day of coverage. No model involved."""
    spine_members = [m for m in members if m["role"] != "echo"] or members
    by_day: dict[str, list[dict]] = {}
    for member in spine_members:
        by_day.setdefault(_day(member["published_at"]), []).append(member)

    echoes_by_day: dict[str, int] = {}
    for member in members:
        if member["role"] == "echo":
            key = _day(member["published_at"])
            echoes_by_day[key] = echoes_by_day.get(key, 0) + 1

    days = sorted(by_day)
    if not days:
        return []
    peak_day = max(days, key=lambda d: len(by_day[d]) + echoes_by_day.get(d, 0))

    beats: list[dict] = []
    for position, day in enumerate(days):
        day_members = by_day[day]
        lead = max(day_members, key=lambda m: (m.get("priority_raw") or 0, len(m.get("title") or "")))
        if position == 0:
            kind = "first_disclosure"
        elif day == peak_day and len(day_members) + echoes_by_day.get(day, 0) > 1:
            kind = "peak"
        else:
            kind = "update"
        body = clean_body(lead.get("summary"))
        beats.append(
            {
                "position": position,
                "occurred_at": lead.get("published_at"),
                "kind": kind,
                "headline": (lead.get("title") or "Untitled")[:500],
                "body": body,
                "lead_entry_id": lead["entry_id"],
                "entry_ids": [str(m["entry_id"]) for m in day_members],
                "collapsed_count": echoes_by_day.get(day, 0),
                "is_ai": False,
            }
        )
    return beats


def _prompt_entries(members: list[dict]) -> list[dict]:
    spine_members = [m for m in members if m["role"] != "echo"] or members
    trimmed = spine_members[:MAX_PROMPT_ENTRIES]
    return [
        {
            "index": i + 1,
            "title": m.get("title") or "",
            "source": m.get("source_key") or m.get("feed_title") or "",
            "published_at": m["published_at"].strftime("%Y-%m-%d") if m.get("published_at") else "",
            "techniques": list(m.get("techniques") or []),
            "summary": (clean_body(m.get("summary")) or "")[:600],
        }
        for i, m in enumerate(trimmed)
    ]


def _ai_beats(payload: dict, members: list[dict]) -> list[dict]:
    """Map the model's index-referenced beats back onto real entries."""
    spine_members = [m for m in members if m["role"] != "echo"] or members
    trimmed = spine_members[:MAX_PROMPT_ENTRIES]
    beats: list[dict] = []
    for position, raw in enumerate(payload.get("beats") or []):
        if not isinstance(raw, dict):
            continue
        headline = str(raw.get("headline") or "").strip()
        if not headline:
            continue
        indexes = [int(i) for i in (raw.get("entry_indexes") or []) if str(i).isdigit()]
        cited = [trimmed[i - 1] for i in indexes if 1 <= i <= len(trimmed)]
        lead = cited[0] if cited else (trimmed[position] if position < len(trimmed) else None)
        kind = str(raw.get("kind") or "update").strip().lower()
        if kind not in {"first_disclosure", "new_tradecraft", "peak", "update"}:
            kind = "update"
        beats.append(
            {
                "position": position,
                "occurred_at": lead.get("published_at") if lead else None,
                "kind": kind,
                "headline": headline[:500],
                "body": (str(raw.get("body") or "").strip() or None),
                "lead_entry_id": lead["entry_id"] if lead else None,
                "entry_ids": [str(m["entry_id"]) for m in cited],
                "collapsed_count": 0,
                "is_ai": True,
            }
        )
    return beats


async def _write_beats(db: AsyncSession, thread_id: uuid.UUID, beats: list[dict]) -> None:
    await db.execute(text("DELETE FROM story_thread_beats WHERE thread_id = :t"), {"t": thread_id})
    for beat in beats:
        await db.execute(
            text(
                """
                INSERT INTO story_thread_beats
                    (id, thread_id, position, occurred_at, kind, headline, body,
                     lead_entry_id, entry_ids, collapsed_count, is_ai)
                VALUES (:id, :thread_id, :position, :occurred_at, :kind, :headline, :body,
                        :lead_entry_id, CAST(:entry_ids AS jsonb), :collapsed_count, :is_ai)
                """
            ),
            {
                "id": uuid.uuid4(),
                "thread_id": thread_id,
                "position": beat["position"],
                "occurred_at": beat["occurred_at"],
                "kind": beat["kind"],
                "headline": beat["headline"],
                "body": beat["body"],
                "lead_entry_id": beat["lead_entry_id"],
                "entry_ids": json.dumps(beat["entry_ids"]),
                "collapsed_count": beat["collapsed_count"],
                "is_ai": beat["is_ai"],
            },
        )


async def ensure_spine(db: AsyncSession, thread_id: uuid.UUID, allow_ai: bool = False) -> dict:
    """Bring one thread's spine up to date. Returns {"status": ...}.

    ``allow_ai=False`` (the sweeper) only fills a thread that has no spine or a
    heuristic one, and never overwrites written beats with generated-by-rule
    ones. ``allow_ai=True`` (the nightly job) re-narrates anything stale.
    """
    row = (
        (
            await db.execute(
                text("SELECT id, title, narrative_hash FROM story_threads WHERE id = :t"),
                {"t": thread_id},
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        return {"status": "missing"}

    members = await collect_members(db, thread_id)
    if not members:
        return {"status": "empty"}

    current_hash = member_hash([str(m["entry_id"]) for m in members])
    existing = (
        (
            await db.execute(
                text(
                    "SELECT COUNT(*) AS n, COALESCE(bool_or(is_ai), false) AS has_ai "
                    "FROM story_thread_beats WHERE thread_id = :t"
                ),
                {"t": thread_id},
            )
        )
        .mappings()
        .first()
    )
    has_beats = bool(existing and existing["n"])
    has_ai_beats = bool(existing and existing["has_ai"])

    # A hash match means the spine describes the current member set. That is the
    # whole answer for the sweeper, but not for the nightly pass: the sweeper
    # stamps the hash when it fills a *heuristic* spine, and a thread that never
    # gains another article would then be "current" forever and never be
    # written. The AI pass skips only what a model has actually written.
    if row["narrative_hash"] == current_hash and has_beats and (has_ai_beats or not allow_ai):
        return {"status": "cached"}
    if not allow_ai and has_ai_beats:
        # Written spine, new articles: leave it for the nightly pass rather than
        # demoting it to headlines.
        return {"status": "deferred"}

    payload = await _run_spine_task(db, thread_id, row["title"], members) if allow_ai else None
    beats = _ai_beats(payload, members) if payload else []
    used_ai = bool(beats)
    if not beats:
        beats = heuristic_beats(members)
    if not beats:
        return {"status": "empty"}

    await _write_beats(db, thread_id, beats)

    title = None
    summary = None
    if used_ai and payload:
        title = str(payload.get("title") or "").strip() or None
        summary = str(payload.get("summary") or "").strip() or None
    # ``narrated_at`` means "the spine on this thread right now was written by a
    # model" — the reader shows a "grouped by day, not yet written" note off it,
    # and an AI call that failed or was never made must not claim otherwise.
    await db.execute(
        text(
            """
            UPDATE story_threads
            SET title = COALESCE(:title, title),
                summary = COALESCE(:summary, summary),
                narrative_hash = :hash,
                narrated_at = CASE WHEN :used_ai THEN now() ELSE NULL END,
                updated_at = now()
            WHERE id = :t
            """
        ),
        {
            "title": title[:500] if title else None,
            "summary": summary,
            "hash": current_hash,
            "used_ai": used_ai,
            "t": thread_id,
        },
    )
    await db.commit()
    return {"status": "narrated" if used_ai else "heuristic"}


async def _run_spine_task(db: AsyncSession, thread_id: uuid.UUID, title: str, members: list[dict]) -> dict | None:
    from app.ai.engine import run_task

    entries = _prompt_entries(members)
    if not entries:
        return None
    try:
        result = await run_task(
            db,
            SYSTEM_USER,
            TASK_NAME,
            variables={
                "thread_title": title,
                "entries": entries,
                "entry_count": len(entries),
                "outlet_count": len({m.get("source_key") for m in members if m.get("source_key")}),
            },
            target_type=TARGET_TYPE,
            target_id=thread_id,
            force=True,
            # Generous because the wait is mostly not generation: on a
            # single-GPU host that unloads between requests, the model reload
            # alone is ~155s before a token is produced.
            timeout_seconds=420.0,
        )
    except Exception as exc:  # noqa: BLE001 — a thread without AI still renders
        logger.warning("thread spine generation failed for %s: %s", thread_id, exc)
        return None
    return result if isinstance(result, dict) else None
