"""Evidence structure: cluster an edge's evidence entries into stories.

Uses the entry embeddings that story threads already maintain to answer the
question the trust ladder can't: does the evidence behind a relationship hang
together as coherent stories, or is it scattered digest co-mentions?

Shapes (story clusters crossed with the per-entry proximity the pivot already
computes):

- recurring:     2+ asserting story clusters — the pair is independently
                 re-asserted across separate incidents. Strongest evidence.
- single_story:  exactly one asserting story cluster — one reporting wave.
- scattered:     3+ evidence entries but no asserting story — the classic
                 weekly-roundup co-mention pattern.
- thin:          one or two loose mentions; too little to say.

A cluster is "asserting" when it has 2+ entries and at least one of them
mentions the pair in close proximity (>= proximity_moderate_threshold) — a
story that only ever names the two entities paragraphs apart is coverage the
pair happens to share, not an assertion about the pair.

Degradation: evidence entries without embeddings are ignored; an edge left
with <2 vectors gets no structure and the UI falls back to plain counts.
Everything is gated on relationship_evidence_structure.

Threshold note: 0.75 was validated against real profiles — at 0.70 single-link
chaining pulls Patch Tuesday digests into incident clusters; at 0.75 incident
arcs cohere, roundups fall out as singletons, and distinct incidents for the
same pair separate cleanly.
"""

import logging
import math
import uuid
from collections import Counter

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings

logger = logging.getLogger(__name__)

# Newest evidence entries considered per edge; clustering is O(n^2) dot
# products so this caps per-edge cost at 45 pairs.
MAX_EVIDENCE_PER_EDGE = 10

# Unique embedding vectors fetched per pivot / per collector run. Evidence
# entries are shared entries with the source entity, so edges overlap heavily
# and the budget goes far; edges past it degrade to no structure.
_PIVOT_VECTOR_BUDGET = 1500
_COLLECTOR_VECTOR_BUDGET = 4000


def structure_enabled() -> bool:
    return bool(settings.get("relationship_evidence_structure"))


def story_threshold() -> float:
    raw = settings.get("relationship_story_threshold")
    return 0.75 if raw is None else float(raw)


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


def single_link_clusters(vectors: list[list[float]], threshold: float) -> list[list[int]]:
    """Greedy single-link clustering: an item joins the first cluster where it
    is within `threshold` of any member. Order-dependent by design — callers
    pass evidence newest-first so clusters anchor on recent reporting."""
    clusters: list[list[int]] = []
    for i in range(len(vectors)):
        joined = False
        for members in clusters:
            if any(_cosine(vectors[i], vectors[m]) >= threshold for m in members):
                members.append(i)
                joined = True
                break
        if not joined:
            clusters.append([i])
    return clusters


def classify_shape(story_count: int, evidence_count: int) -> str:
    if story_count >= 2:
        return "recurring"
    if story_count == 1:
        return "single_story"
    if evidence_count >= 3:
        return "scattered"
    return "thin"


def _parse_halfvec(literal: str) -> list[float]:
    return [float(x) for x in literal.strip("[]").split(",")]


async def _fetch_vectors(db: AsyncSession, entry_ids: list[uuid.UUID]) -> dict[str, list[float]]:
    if not entry_ids:
        return {}
    rows = await db.execute(
        text("SELECT entry_id, embedding::text FROM entry_embeddings WHERE entry_id = ANY(:ids)"),
        {"ids": entry_ids},
    )
    return {str(r[0]): _parse_halfvec(r[1]) for r in rows.all()}


async def _fetch_threads(db: AsyncSession, entry_ids: list[uuid.UUID]) -> dict[str, tuple[str, str]]:
    """entry_id -> (thread slug, thread title); one thread per entry."""
    if not entry_ids:
        return {}
    rows = await db.execute(
        text(
            """
            SELECT DISTINCT ON (ste.entry_id) ste.entry_id, st.slug, st.title
            FROM story_thread_entries ste
            JOIN story_threads st ON st.id = ste.thread_id
            WHERE ste.entry_id = ANY(:ids)
            ORDER BY ste.entry_id, ste.similarity DESC
            """
        ),
        {"ids": entry_ids},
    )
    return {str(r[0]): (r[1], r[2]) for r in rows.all()}


async def _fetch_feed_ids(db: AsyncSession, entry_ids: list[uuid.UUID]) -> dict[str, str]:
    """entry_id -> feed_id, for per-story outlet counts."""
    if not entry_ids:
        return {}
    rows = await db.execute(
        text("SELECT id, feed_id FROM entries WHERE id = ANY(:ids)"),
        {"ids": entry_ids},
    )
    return {str(r[0]): str(r[1]) for r in rows.all() if r[1]}


def _newest_evidence(item: dict) -> list[dict]:
    """Newest MAX_EVIDENCE_PER_EDGE proximity entries for a pivot row.

    proximity_entries is sorted by score; re-sort by published_at (None last)
    so the structure reflects the current reporting record.
    """
    ev = [e for e in (item.get("proximity_entries") or []) if isinstance(e, dict) and e.get("entry_id")]
    ev.sort(key=lambda e: e.get("published_at") or "", reverse=True)
    return ev[:MAX_EVIDENCE_PER_EDGE]


async def attach_evidence_structure(db: AsyncSession, items: list[dict]) -> None:
    """Attach `evidence_structure` to pivot rows (in place).

    Items arrive in strength order; the vector budget is spent front-to-back
    so the rows most likely to be read always get structure.
    """
    if not structure_enabled() or not items:
        return

    threshold = story_threshold()
    raw_moderate = settings.get("proximity_moderate_threshold")
    moderate = 0.3 if raw_moderate is None else float(raw_moderate)

    per_item: list[tuple[dict, list[dict]]] = []
    wanted: list[uuid.UUID] = []
    seen: set[str] = set()
    for item in items:
        ev = _newest_evidence(item)
        per_item.append((item, ev))
        if len(ev) < 2:
            continue
        for e in ev:
            eid = e["entry_id"]
            if eid not in seen and len(seen) < _PIVOT_VECTOR_BUDGET:
                seen.add(eid)
                wanted.append(uuid.UUID(eid))

    try:
        vectors = await _fetch_vectors(db, wanted)
        threads = await _fetch_threads(db, wanted)
        feeds = await _fetch_feed_ids(db, wanted)
    except Exception:
        logger.exception("evidence structure: vector fetch failed; skipping")
        return

    for item, ev in per_item:
        if len(ev) == 1:
            item["evidence_structure"] = {"shape": "thin", "stories": [], "loose": 1, "sampled": 1}
            continue
        sub = [e for e in ev if e["entry_id"] in vectors]
        if len(sub) < 2:
            continue  # no vectors (embeddings off / budget) — no claim either way

        clusters = single_link_clusters([vectors[e["entry_id"]] for e in sub], threshold)
        stories = []
        clustered = 0
        for members in clusters:
            if len(members) < 2:
                continue
            entries = [sub[m] for m in members]
            max_prox = max(float(e.get("score") or 0.0) for e in entries)
            if max_prox < moderate:
                continue  # shared coverage, not an assertion about the pair
            clustered += len(members)
            dates = sorted(e["published_at"] for e in entries if e.get("published_at"))
            slugs = Counter(threads[e["entry_id"]][0] for e in entries if e["entry_id"] in threads)
            slug = slugs.most_common(1)[0][0] if slugs else None
            title = next(
                (threads[e["entry_id"]][1] for e in entries if threads.get(e["entry_id"], ("",))[0] == slug),
                None,
            )
            stories.append(
                {
                    "entries": len(members),
                    "entry_ids": [e["entry_id"] for e in entries],
                    "sources": len({feeds[e["entry_id"]] for e in entries if e["entry_id"] in feeds}) or None,
                    "first": dates[0] if dates else None,
                    "last": dates[-1] if dates else None,
                    "slug": slug,
                    "title": title,
                }
            )

        stories.sort(key=lambda s: s["last"] or "", reverse=True)
        item["evidence_structure"] = {
            "shape": classify_shape(len(stories), len(sub)),
            "stories": stories[:4],
            "loose": len(sub) - clustered,
            "sampled": len(sub),
        }


async def story_cluster_counts(
    db: AsyncSession,
    evidence_by_key: dict,
    *,
    vector_budget: int = _COLLECTOR_VECTOR_BUDGET,
) -> dict:
    """Similarity-cluster counts (clusters of 2+) for raw evidence id lists.

    Used by the promotion floor and the adjudication collector, which have no
    per-pair proximity at hand — a 2+ cluster alone already rules out the pure
    roundup-scatter pattern. Returns None for a key with <2 vectors available
    (unknown, callers must not treat it as 0).
    """
    threshold = story_threshold()
    wanted: list[uuid.UUID] = []
    seen: set[uuid.UUID] = set()
    for ids in evidence_by_key.values():
        for eid in ids[-MAX_EVIDENCE_PER_EDGE:]:
            if eid not in seen and len(seen) < vector_budget:
                seen.add(eid)
                wanted.append(eid)

    vectors = await _fetch_vectors(db, wanted)

    out = {}
    for key, ids in evidence_by_key.items():
        vecs = [vectors[str(eid)] for eid in ids[-MAX_EVIDENCE_PER_EDGE:] if str(eid) in vectors]
        if len(vecs) < 2:
            out[key] = None
            continue
        out[key] = sum(1 for c in single_link_clusters(vecs, threshold) if len(c) >= 2)
    return out


async def has_story_cluster(db: AsyncSession, evidence_entry_ids: list[uuid.UUID]) -> bool | None:
    """Promotion-floor check for one edge. None = not enough vectors to say."""
    counts = await story_cluster_counts(db, {"edge": evidence_entry_ids})
    n = counts.get("edge")
    return None if n is None else n >= 1
