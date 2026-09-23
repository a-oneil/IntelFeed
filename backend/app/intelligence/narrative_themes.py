"""Read the day briefing's own grouping back out of its markdown.

The `daily_summary` prompt makes two guarantees this module depends on:

1. Key Developments is written as `### Theme Heading` sections.
2. Every article reference is a markdown link to the in-app reader —
   ``[Title](/?entry=<uuid>)`` — because that is the URL
   ``_fetch_day_entries`` hands the model (app/api/entries.py).

So the cached briefing is already a map of *which articles the AI grouped
together*, and recovering it is a regex over text we have paid for once and
stored. No provider call, no embeddings, nothing to schedule on the AI queue.

What it is good for: the co-occurrence promotion gate. An entity pair whose
evidence articles all sit under one heading on one day is one reporting wave
told several ways; a pair re-asserted under headings on different days is the
real thing. That is the same judgement `evidence_structure` makes from
embeddings — this one works with embeddings off.

Degradation is deliberate and one-directional: days that were never parsed and
articles the briefing never cited produce no rows, and callers treat missing
data as "no opinion", never as "fails".
"""

from __future__ import annotations

import logging
import re
import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.narrative_theme import (
    SECTION_CLOSER,
    SECTION_NOTABLE,
    SECTION_THEME,
    SECTION_TLDR,
    NarrativeBriefing,
    NarrativeThemeMember,
)

logger = logging.getLogger(__name__)

#: In-app reader links carry the entry id; external source URLs never match.
_ENTRY_LINK_RE = re.compile(r"[?&]entry=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")
_H2_RE = re.compile(r"^\s{0,3}##\s+(.+?)\s*#*\s*$")
_H3_RE = re.compile(r"^\s{0,3}###\s+(.+?)\s*#*\s*$")

_THEME_MAX = 200


def themes_enabled() -> bool:
    return bool(settings.get("narrative_themes_enabled"))


def theme_gating_enabled() -> bool:
    return bool(settings.get("narrative_theme_gating"))


def _section_for_h2(heading: str) -> str:
    """Map a top-level briefing heading to its section kind.

    Matched loosely on purpose: the headings come from a prompt an operator can
    edit, so "Key Developments" must still be recognised if someone renames it
    "Key developments today".
    """
    h = heading.casefold()
    if "tl;dr" in h or "tldr" in h:
        return SECTION_TLDR
    if "notable" in h:
        return SECTION_NOTABLE
    if "closer look" in h or "worth a" in h:
        return SECTION_CLOSER
    # Key Developments — and anything unrecognised, since that is where a
    # renamed themed section would land and its `###` children are the payload.
    return SECTION_THEME


def parse_briefing(markdown: str) -> list[tuple[uuid.UUID, str, str]]:
    """Extract ``(entry_id, theme, section)`` citations from briefing markdown.

    A theme is only set for `###` headings inside a themed section; everything
    else carries an empty theme and its section kind. An article cited under two
    headings yields two rows — it genuinely belongs to both.
    """
    if not markdown:
        return []

    section = SECTION_TLDR
    theme = ""
    seen: set[tuple[uuid.UUID, str]] = set()
    out: list[tuple[uuid.UUID, str, str]] = []

    for line in markdown.splitlines():
        h2 = _H2_RE.match(line)
        if h2:
            section = _section_for_h2(h2.group(1))
            theme = ""
            continue
        h3 = _H3_RE.match(line)
        if h3:
            # Sub-headings only name a theme inside the themed section; a `###`
            # under "Notable Individual Items" is not a grouping of articles.
            theme = h3.group(1).strip()[:_THEME_MAX] if section == SECTION_THEME else ""
            continue

        for raw_id in _ENTRY_LINK_RE.findall(line):
            try:
                entry_id = uuid.UUID(raw_id)
            except ValueError:  # pragma: no cover - regex already constrains the shape
                continue
            # A themed citation and a leftover-bucket citation of the same
            # article are one row per (article, theme); the unique constraint
            # agrees, so dedupe on the same key here.
            key = (entry_id, theme)
            if key in seen:
                continue
            seen.add(key)
            out.append((entry_id, theme, section))
    return out


async def record_briefing_themes(db: AsyncSession, day_key: str, markdown: str) -> dict:
    """Parse one day's briefing and store its groupings. Best-effort.

    Re-parsing a day is safe: rows upsert on (day_key, entry_id, theme) and the
    bookkeeping row upserts on day_key, so a re-generated briefing overwrites
    its counts instead of accumulating.

    Citations of entries that no longer exist are dropped rather than failing
    the batch — a briefing outlives the articles retention prunes.
    """
    if not themes_enabled():
        return {"status": "disabled"}

    citations = parse_briefing(markdown)
    if not citations:
        return {"status": "no_citations", "day": day_key}

    from app.models.entry import Entry

    known = set((await db.execute(select(Entry.id).where(Entry.id.in_({c[0] for c in citations})))).scalars().all())
    rows = [
        {
            "id": uuid.uuid4(),
            "day_key": day_key,
            "entry_id": entry_id,
            "theme": theme,
            "section": section,
        }
        for entry_id, theme, section in citations
        if entry_id in known
    ]
    if not rows:
        return {"status": "no_known_entries", "day": day_key}

    stmt = pg_insert(NarrativeThemeMember).values(rows)
    await db.execute(
        stmt.on_conflict_do_update(
            constraint="uq_narrative_theme_member",
            set_={"section": stmt.excluded.section},
        )
    )

    theme_count = len({r["theme"] for r in rows if r["theme"]})
    brief = pg_insert(NarrativeBriefing).values(
        id=uuid.uuid4(),
        day_key=day_key,
        theme_count=theme_count,
        cited_entry_count=len({r["entry_id"] for r in rows}),
    )
    await db.execute(
        brief.on_conflict_do_update(
            index_elements=[NarrativeBriefing.day_key],
            set_={
                "theme_count": brief.excluded.theme_count,
                "cited_entry_count": brief.excluded.cited_entry_count,
                "parsed_at": brief.excluded.parsed_at,
            },
        )
    )
    await db.commit()
    return {
        "status": "ok",
        "day": day_key,
        "themes": theme_count,
        "citations": len(rows),
        "dropped": len(citations) - len(rows),
    }


async def theme_cohorts(db: AsyncSession, entry_ids: list[uuid.UUID]) -> dict[uuid.UUID, set[str]]:
    """``entry_id -> {"<day>|<theme>"}`` for articles placed under a heading.

    Leftover-bucket citations are deliberately excluded: the briefing read the
    day and chose not to group them, which is the opposite of corroboration.
    """
    if not entry_ids:
        return {}
    rows = await db.execute(
        select(NarrativeThemeMember.entry_id, NarrativeThemeMember.day_key, NarrativeThemeMember.theme).where(
            NarrativeThemeMember.entry_id.in_(set(entry_ids)),
            NarrativeThemeMember.section == SECTION_THEME,
            NarrativeThemeMember.theme != "",
        )
    )
    out: dict[uuid.UUID, set[str]] = {}
    for entry_id, day_key, theme in rows.all():
        out.setdefault(entry_id, set()).add(f"{day_key}|{theme}")
    return out


async def spans_multiple_themes(db: AsyncSession, entry_ids: list[uuid.UUID], min_placed: int = 2) -> bool | None:
    """Does this evidence set span two or more distinct briefing themes?

    Returns None when there isn't enough parsed coverage to have an opinion
    (fewer than ``min_placed`` of the articles were ever placed under a
    heading) — callers must read None as "no opinion", not as a failure.
    """
    cohorts = await theme_cohorts(db, entry_ids)
    if len(cohorts) < min_placed:
        return None
    distinct: set[str] = set()
    for values in cohorts.values():
        distinct |= values
    return len(distinct) >= 2
