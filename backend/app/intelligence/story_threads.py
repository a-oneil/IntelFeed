"""Story threads — grouping an unfolding story into one narrative object.

The problem this replaces: the same story arrives twenty-three times, and the
only thing the platform could do about it was subtract score. ``feed_echo``
penalises the repeats and ``temporal_clusters`` recomputes a throwaway
entity-overlap cluster per request; neither leaves anything you can read, name,
follow, or come back to.

The algorithm is deliberately incremental and cheap. It never clusters the
corpus: it walks the entries that arrived since the last pass, oldest first, and
asks one question per entry — *does this continue a story we already have?*

    join    cosine to an open thread's centroid clears ``thread_join_similarity``
            AND the article shares an extracted entity with that thread. Without
            a shared entity the bar rises to ``thread_join_similarity_no_entity``,
            because embeddings alone will happily merge every ransomware article
            ever written into one thread.
    seed    otherwise, look at the article's unthreaded neighbours in the window.
            ``thread_min_entries`` of them above ``thread_seed_similarity``, from
            ``thread_min_sources`` distinct outlets, is a story breaking. Two
            articles from one outlet is not.
    echo    a joining article that is ``thread_duplicate_similarity`` close to an
            earlier member and introduces no entity the thread lacks is a
            re-report. It is kept, attributed to the article it echoes, and
            folded out of the way.

Everything vector lives in Postgres (pgvector); nothing is loaded into Python
except the few hundred floats of a centroid.
"""

import json
import logging
import re
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.intelligence.signals import _source_key

logger = logging.getLogger(__name__)

# Entity types that carry story identity. Countries and mitigations are too
# broad to distinguish one story from another; TTPs sit in between and are
# included because a technique shift is exactly what a new beat looks like.
IDENTITY_JUNCTIONS: list[tuple[str, str, str]] = [
    ("threat_actor", "entry_threat_actors", "threat_actor_id"),
    ("malware", "entry_malware", "malware_family_id"),
    ("tool", "entry_tools", "tool_id"),
    ("cve", "entry_cves", "cve_id"),
    ("product", "entry_products", "product_id"),
    ("ttp", "entry_ttps", "ttp_id"),
]

# Neighbours pulled per seed probe. Wide enough for a big first wave, small
# enough that the HNSW scan stays trivial.
SEED_FANOUT = 30

# Candidate threads compared per entry. The centroid ordering is exact, so the
# top few are the only ones that can clear the threshold.
THREAD_FANOUT = 5

# Articles one outlet may contribute to a thread, full stop. One newsroom filing
# three times is a story it is following; a fourth, fifth and sixth is a bulletin
# series, and AusCERT's package advisories chain into any thread at 0.9+ cosine
# to each other if allowed to. The cap once exempted echoes, on the theory that a
# re-report should still be folded — but "0.9 cosine and no new entity" is
# exactly what two unrelated Red Hat errata look like to an embedding, so the
# exemption was the hole the whole series climbed through. Past the cap the
# outlet contributes nothing further, in any role.
SAME_SOURCE_LIMIT = 3

# The join test is deliberately two-sided. Nearest-member alone is single-link
# clustering, which chains: A resembles B, B resembles C, and the thread walks
# away from its own subject one hop at a time. Requiring the article to also sit
# near the thread's centroid (at a slightly softer bar, since a centroid is an
# average and averages are further from everything) anchors it to what the
# thread is actually about.
CENTROID_MARGIN = 0.08

# No single outlet may carry more than this share of a thread at seed time. A
# story is by definition something more than one newsroom noticed. Two thirds,
# not a half: the smallest legitimate thread is three articles from two outlets.
DOMINANT_SOURCE_SHARE = 0.67

# An entity linked to more than this share of the window's articles is not
# identity, it is background. "Linux" sits on 16% of a three-week window and
# "Windows" on 15%; a thread held together by one of those is held together by
# nothing. Measured against the window rather than hardcoded, because which
# names are ambient depends on the feed set.
AMBIENT_ENTITY_SHARE = 0.02

# Below this many articles in the window, prevalence is noise rather than
# evidence: on a young install every entity looks ambient, and stripping them
# leaves the join rules with no identity signal at all.
AMBIENT_MIN_WINDOW = 200

# Thread size past which similarity alone stops being enough to join. Large
# threads have broad vocabulary and attract unrelated coverage; a shared actor,
# malware family, CVE, product or technique is required instead.
ENTITY_REQUIRED_ABOVE = 12

# A recurring roundup — "CISA adds ownCloud, Linux Kernel and JFrog flaws to
# KEV" — is entity-dense and entity-disjoint: each instalment carries half a
# dozen CVEs and products, and almost none of them are the ones the last
# instalment carried. One incidental overlap is enough to clear the shared-
# entity bar, so the format kept assembling itself into a "story" that was
# really ownCloud, PaperCut, Cisco, Citrix, Fortinet and RouterOS at once.
# Density is what makes the test safe: a thread whose articles name nothing
# extractable (a breach with no named actor) never trips it.
ROUNDUP_MIN_ENTITIES = 4
ROUNDUP_MIN_OVERLAP = 0.25
# At seed time the same shape is measured across the whole candidate set: if
# the members are entity-dense and no single entity reaches this share of them,
# they are instalments of a format rather than coverage of one event.
ROUNDUP_SEED_SHARE = 0.4

# Publisher advisory rows. AusCERT files one "package: CVSS (Max): 7.5" bulletin
# per package and Red Hat one RHSA-YYYY:NNNNN erratum per build — 16% of a
# three-week window between them. They clear the body floor comfortably (a Red
# Hat erratum runs to 20k characters of boilerplate) and sit at 0.9+ cosine to
# each other on that boilerplate alone, which is how six unrelated errata ended
# up folded into one "story". They are rows about a package version, not
# coverage of an event.
BULLETIN_TITLE_RE = r"(CVSS \(Max\)|^(RHSA|RHBA|RHEA)-[0-9]{4}:)"


def _knob(key: str, default: float) -> float:
    try:
        value = settings.get(key)
        return float(default if value is None else value)
    except (TypeError, ValueError):
        return default


# " ... - BleepingComputer", " ... | The Record": syndication and Google News
# staple the outlet onto the headline. A thread is named after the story, not
# after whichever newsroom happened to file first, so the tail comes off.
_OUTLET_SUFFIX_RE = re.compile(r"\s+[-|–—]\s+[^-|–—]{2,40}$")
_TITLE_MIN_AFTER_STRIP = 25


def thread_title(raw: str | None) -> str:
    """The name a thread takes from its opening article."""
    title = re.sub(r"\s+", " ", (raw or "").strip())
    stripped = _OUTLET_SUFFIX_RE.sub("", title)
    if len(stripped) >= _TITLE_MIN_AFTER_STRIP and not stripped.endswith((".", "?", "!", ":")):
        title = stripped
    return title[:500] or "Untitled story"


def slugify(value: str, max_len: int = 80) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
    return slug[:max_len].rstrip("-") or "thread"


async def _unique_slug(db: AsyncSession, base: str) -> str:
    slug = slugify(base)
    taken = set(
        (
            await db.execute(
                text("SELECT slug FROM story_threads WHERE slug = :s OR slug LIKE :p"),
                {"s": slug, "p": f"{slug}-%"},
            )
        )
        .scalars()
        .all()
    )
    if slug not in taken:
        return slug
    for n in range(2, 100):
        candidate = f"{slug}-{n}"
        if candidate not in taken:
            return candidate
    return f"{slug}-{uuid.uuid4().hex[:6]}"


async def ambient_entities(
    db: AsyncSession,
    cutoff: datetime,
    max_share: float = AMBIENT_ENTITY_SHARE,
    min_window: int = AMBIENT_MIN_WINDOW,
) -> set:
    """Entities too common in the window to mean anything as a shared identity."""
    total = (
        await db.execute(
            text(
                """
                SELECT COUNT(*) FROM entries e
                JOIN entry_embeddings ee ON ee.entry_id = e.id
                WHERE e.published_at >= :cutoff
                """
            ),
            {"cutoff": cutoff},
        )
    ).scalar() or 0
    if total < min_window:
        return set()
    ceiling = max(3, int(total * max_share))
    ambient: set[tuple[str, str]] = set()
    for etype, table, column in IDENTITY_JUNCTIONS:
        rows = await db.execute(
            text(  # noqa: S608 — table/column come from the module-level constant above
                f"""
                SELECT j.{column} AS entity_id, COUNT(*) AS n
                FROM {table} j
                JOIN entries e ON e.id = j.entry_id
                WHERE e.published_at >= :cutoff
                GROUP BY 1
                HAVING COUNT(*) > :ceiling
                """
            ),
            {"cutoff": cutoff, "ceiling": ceiling},
        )
        for entity_id, _ in rows.all():
            ambient.add((etype, str(entity_id)))
    return ambient


async def entry_entities(db: AsyncSession, entry_ids: list[uuid.UUID]) -> dict[uuid.UUID, set[tuple[str, str]]]:
    """(entity_type, entity_id) sets per entry, across the identity junctions."""
    out: dict[uuid.UUID, set[tuple[str, str]]] = defaultdict(set)
    if not entry_ids:
        return out
    for etype, table, column in IDENTITY_JUNCTIONS:
        rows = await db.execute(
            text(f"SELECT entry_id, {column} AS entity_id FROM {table} WHERE entry_id = ANY(:ids)"),  # noqa: S608
            {"ids": entry_ids},
        )
        for entry_id, entity_id in rows.all():
            out[entry_id].add((etype, str(entity_id)))
    return out


async def _candidate_entries(
    db: AsyncSession, cutoff: datetime, limit: int, min_body: int, gap_days: int
) -> list[dict]:
    """Embedded, unthreaded entries in the window — never-looked-at ones first.

    Oldest first *within* each half is load-bearing: a story's first article has
    to be present to seed the thread the later waves join, and it is also the
    "who published first" answer the spine reports.

    Never-looked-at first is what keeps the queue current. Entries inside the
    gap window are re-offered on every pass (the story they belong to may not
    have broken yet), and once that set outgrows ``limit`` a plain
    published_at ordering spends the whole budget re-examining the same
    five-day-old articles: measured on the live corpus, 494 of 500 candidates
    had already been checked and the newest one the sweep could reach was three
    days older than the newest unthreaded article. Today's pile — the thing the
    queue exists to fold — was never looked at until it was too old to fold.

    ``min_body`` excludes template rows — "kubernetes: CVSS (Max): None" and its
    thousand siblings. Their embeddings encode the bulletin format rather than
    any subject, so they sit at 0.8 cosine to everything and glue unrelated
    stories together. They are database rows, not articles; 41% of the window is
    made of them. ``BULLETIN_TITLE_RE`` catches the ones long enough to clear
    the floor anyway.
    """
    rows = await db.execute(
        text(
            """
            SELECT e.id, e.title, e.url, e.feed_id, e.published_at
            FROM entries e
            JOIN entry_embeddings ee ON ee.entry_id = e.id
            LEFT JOIN story_thread_entries ste ON ste.entry_id = e.id
            WHERE ste.entry_id IS NULL
              AND e.published_at IS NOT NULL
              AND e.published_at >= :cutoff
              AND length(COALESCE(e.content_text, e.summary, '')) >= :min_body
              AND e.title !~* :bulletin_re
              AND (
                    ee.threaded_checked_at IS NULL
                    -- Still inside its own gap window: the story it belongs to
                    -- may not have broken yet, so keep re-offering it.
                    OR e.published_at >= now() - make_interval(days => :gap_days)
              )
            -- Never-checked entries first, then oldest-first within each half:
            -- re-checks must never crowd out an article nothing has looked at.
            ORDER BY (ee.threaded_checked_at IS NOT NULL), e.published_at ASC
            LIMIT :limit
            """
        ),
        {
            "cutoff": cutoff,
            "limit": limit,
            "min_body": min_body,
            "gap_days": gap_days,
            "bulletin_re": BULLETIN_TITLE_RE,
        },
    )
    return [dict(r) for r in rows.mappings().all()]


async def _nearest_threads(
    db: AsyncSession,
    entry: dict,
    dormant_cutoff: datetime,
    gap_cutoff: datetime,
    source_key: str,
) -> list[dict]:
    """Open threads nearest this entry, with the two facts the join rules need.

    ``same_source_members`` is how many of the thread's articles come from the
    same outlet as this one: a publisher restating its own house format is the
    single loudest false positive in the corpus (a fortnight of ZDI advisories
    sit at 0.81 cosine to each other while describing unrelated bugs).
    """
    rows = await db.execute(
        text(
            """
            SELECT t.id, t.key_entities, t.last_seen, t.entry_count,
                   1 - (t.centroid <=> ee.embedding) AS similarity,
                   (SELECT COUNT(*) FROM story_thread_entries s2
                    WHERE s2.thread_id = t.id AND s2.source_key = :source_key) AS same_source_members
            FROM story_threads t
            JOIN entry_embeddings ee ON ee.entry_id = :entry_id
            WHERE t.centroid IS NOT NULL
              AND t.status = 'open'
              AND (t.last_seen IS NULL OR t.last_seen >= :dormant_cutoff)
              AND (t.last_seen IS NULL OR t.last_seen >= :gap_cutoff)
            ORDER BY t.centroid <=> ee.embedding
            LIMIT :fanout
            """
        ),
        {
            "entry_id": entry["id"],
            "dormant_cutoff": dormant_cutoff,
            "gap_cutoff": gap_cutoff,
            "source_key": source_key,
            "fanout": THREAD_FANOUT,
        },
    )
    return [dict(r) for r in rows.mappings().all()]


async def _nearest_unthreaded(
    db: AsyncSession, entry_id: uuid.UUID, cutoff: datetime, ceiling: datetime, min_body: int
) -> list[dict]:
    """Unthreaded neighbours within a gap window either side of the anchor.

    Bounded in both directions, not just the past: a story is bursty, and the
    same burstiness that stops an article joining a three-week-old thread has to
    stop three articles three weeks apart from seeding one together.
    """
    rows = await db.execute(
        text(
            """
            WITH anchor AS (SELECT embedding FROM entry_embeddings WHERE entry_id = :entry_id)
            SELECT e.id, e.title, e.url, e.feed_id, e.published_at,
                   1 - (ee.embedding <=> anchor.embedding) AS similarity
            FROM entry_embeddings ee
            JOIN entries e ON e.id = ee.entry_id
            CROSS JOIN anchor
            LEFT JOIN story_thread_entries ste ON ste.entry_id = e.id
            WHERE ste.entry_id IS NULL
              AND e.id <> :entry_id
              AND e.published_at IS NOT NULL
              AND e.published_at >= :cutoff
              AND e.published_at <= :ceiling
              AND length(COALESCE(e.content_text, e.summary, '')) >= :min_body
              AND e.title !~* :bulletin_re
            ORDER BY ee.embedding <=> anchor.embedding
            LIMIT :fanout
            """
        ),
        {
            "entry_id": entry_id,
            "cutoff": cutoff,
            "ceiling": ceiling,
            "fanout": SEED_FANOUT,
            "min_body": min_body,
            "bulletin_re": BULLETIN_TITLE_RE,
        },
    )
    return [dict(r) for r in rows.mappings().all()]


async def _closest_member(db: AsyncSession, thread_id: uuid.UUID, entry_id: uuid.UUID) -> dict | None:
    """The thread's single most similar article to this entry.

    This — not the centroid — is what decides a join. A centroid is an average,
    and the average of a twenty-article thread is a vector for "vulnerability
    news", which then attracts every vulnerability article in the corpus. On the
    first pass one thread ate 103 articles across three weeks that way. Asking
    "is this article close to a specific article already in the story" is a
    claim that survives the thread getting bigger; the centroid is kept only to
    retrieve candidates cheaply.
    """
    rows = await db.execute(
        text(
            """
            WITH anchor AS (SELECT embedding FROM entry_embeddings WHERE entry_id = :entry_id)
            SELECT ste.entry_id, 1 - (ee.embedding <=> anchor.embedding) AS similarity
            FROM story_thread_entries ste
            JOIN entry_embeddings ee ON ee.entry_id = ste.entry_id
            CROSS JOIN anchor
            WHERE ste.thread_id = :thread_id AND ste.role <> 'echo'
            ORDER BY ee.embedding <=> anchor.embedding
            LIMIT 1
            """
        ),
        {"thread_id": thread_id, "entry_id": entry_id},
    )
    row = rows.mappings().first()
    return dict(row) if row else None


async def _add_member(
    db: AsyncSession,
    thread_id: uuid.UUID,
    entry: dict,
    similarity: float,
    role: str,
    duplicate_of: uuid.UUID | None = None,
) -> None:
    await db.execute(
        text(
            """
            INSERT INTO story_thread_entries
                (id, thread_id, entry_id, role, similarity, duplicate_of_entry_id, source_key)
            VALUES (:id, :thread_id, :entry_id, :role, :similarity, :duplicate_of, :source_key)
            ON CONFLICT (entry_id) DO NOTHING
            """
        ),
        {
            "id": uuid.uuid4(),
            "thread_id": thread_id,
            "entry_id": entry["id"],
            "role": role,
            "similarity": float(similarity),
            "duplicate_of": duplicate_of,
            "source_key": _source_key(entry.get("url"), entry.get("feed_id"))[:255],
        },
    )


async def refresh_thread(db: AsyncSession, thread_id: uuid.UUID) -> None:
    """Recompute a thread's centroid, counts, dates and key entities from members."""
    await db.execute(
        text(
            """
            UPDATE story_threads t SET
                centroid = m.centroid,
                entry_count = m.entry_count,
                source_count = m.source_count,
                echo_count = m.echo_count,
                first_seen = m.first_seen,
                last_seen = m.last_seen,
                updated_at = now()
            FROM (
                SELECT AVG(ee.embedding) AS centroid,
                       COUNT(*) AS entry_count,
                       COUNT(DISTINCT ste.source_key) AS source_count,
                       COUNT(*) FILTER (WHERE ste.role = 'echo') AS echo_count,
                       MIN(e.published_at) AS first_seen,
                       MAX(e.published_at) AS last_seen
                FROM story_thread_entries ste
                JOIN entries e ON e.id = ste.entry_id
                JOIN entry_embeddings ee ON ee.entry_id = ste.entry_id
                WHERE ste.thread_id = :thread_id
            ) m
            WHERE t.id = :thread_id
            """
        ),
        {"thread_id": thread_id},
    )
    # Peak day: the day the story was loudest, used by the spine.
    await db.execute(
        text(
            """
            UPDATE story_threads SET peak_at = (
                SELECT date_trunc('day', e.published_at)
                FROM story_thread_entries ste
                JOIN entries e ON e.id = ste.entry_id
                WHERE ste.thread_id = :thread_id AND e.published_at IS NOT NULL
                GROUP BY 1
                ORDER BY COUNT(*) DESC, 1 ASC
                LIMIT 1
            )
            WHERE id = :thread_id
            """
        ),
        {"thread_id": thread_id},
    )
    await _refresh_key_entities(db, thread_id)


async def _refresh_key_entities(db: AsyncSession, thread_id: uuid.UUID) -> None:
    member_ids = list(
        (
            await db.execute(
                text("SELECT entry_id FROM story_thread_entries WHERE thread_id = :t"),
                {"t": thread_id},
            )
        )
        .scalars()
        .all()
    )
    if not member_ids:
        return
    counts: Counter[tuple[str, str]] = Counter()
    for entities in (await entry_entities(db, member_ids)).values():
        counts.update(entities)
    top = counts.most_common(12)
    labels = await _entity_labels(db, [key for key, _ in top])
    payload = [
        {"entity_type": etype, "entity_id": eid, "label": labels.get((etype, eid), ""), "count": count}
        for (etype, eid), count in top
        if labels.get((etype, eid))
    ]
    await db.execute(
        text("UPDATE story_threads SET key_entities = CAST(:payload AS jsonb) WHERE id = :t"),
        {"payload": json.dumps(payload), "t": thread_id},
    )


_LABEL_SOURCES: dict[str, tuple[str, str]] = {
    "threat_actor": ("threat_actors", "name"),
    "malware": ("malware_families", "name"),
    "tool": ("tools", "name"),
    "cve": ("cves", "cve_id"),
    "product": ("products", "name"),
    "ttp": ("ttps", "technique_id"),
}


async def _entity_labels(db: AsyncSession, keys: list[tuple[str, str]]) -> dict[tuple[str, str], str]:
    out: dict[tuple[str, str], str] = {}
    by_type: dict[str, list[str]] = defaultdict(list)
    for etype, eid in keys:
        by_type[etype].append(eid)
    for etype, ids in by_type.items():
        table, column = _LABEL_SOURCES[etype]
        rows = await db.execute(
            text(f"SELECT id, {column} AS label FROM {table} WHERE id = ANY(CAST(:ids AS uuid[]))"),  # noqa: S608
            {"ids": ids},
        )
        for row_id, label in rows.all():
            out[(etype, str(row_id))] = label
    return out


def _is_roundup_join(entry_ents: set, thread_ents: set) -> bool:
    """True when both sides name plenty of things and agree on almost none.

    The shared-entity bar asks "is there one thing in common", which a KEV
    roundup clears by accident: two instalments a week apart happen to list the
    same Citrix flaw among six unrelated ones each. Judging the overlap as a
    *proportion* separates "the same subject, described twice" from "two
    catalogues that intersect once".
    """
    if len(entry_ents) < ROUNDUP_MIN_ENTITIES or len(thread_ents) < ROUNDUP_MIN_ENTITIES:
        return False
    shared = len(entry_ents & thread_ents)
    return shared / min(len(entry_ents), len(thread_ents)) < ROUNDUP_MIN_OVERLAP


def _is_roundup_seed(member_entities: list[set]) -> bool:
    """The same test across a candidate seed set, before a thread exists.

    Only applies when most of the set is entity-dense. A story whose articles
    name nothing extractable — a breach with no named actor, malware or CVE —
    has no entities to agree on and must still be allowed to seed.
    """
    if not member_entities:
        return False
    dense = sum(1 for ents in member_entities if len(ents) >= ROUNDUP_MIN_ENTITIES)
    if dense * 2 < len(member_entities):
        return False
    counts: Counter = Counter()
    for ents in member_entities:
        counts.update(ents)
    best = max(counts.values(), default=0)
    return best / len(member_entities) < ROUNDUP_SEED_SHARE


def _cap_by_source(anchor: dict, neighbours: list[dict]) -> list[dict]:
    """Drop neighbours past ``SAME_SOURCE_LIMIT`` articles from one outlet.

    The dominance ratio alone lets a four-and-six split seed a ten-article
    "story" from two mirrors of the same advisory feed. Neighbours arrive in
    similarity order, so the ones kept are the closest the outlet filed.
    """
    seen: Counter = Counter({_source_key(anchor.get("url"), anchor.get("feed_id")): 1})
    kept: list[dict] = []
    for neighbour in neighbours:
        key = _source_key(neighbour.get("url"), neighbour.get("feed_id"))
        if seen[key] >= SAME_SOURCE_LIMIT:
            continue
        seen[key] += 1
        kept.append(neighbour)
    return kept


async def _create_thread(db: AsyncSession, origin: dict) -> uuid.UUID:
    thread_id = uuid.uuid4()
    title = thread_title(origin.get("title"))
    slug = await _unique_slug(db, title)
    await db.execute(
        text(
            """
            INSERT INTO story_threads (id, slug, title, status, entry_count, source_count, echo_count)
            VALUES (:id, :slug, :title, 'open', 0, 0, 0)
            """
        ),
        {"id": thread_id, "slug": slug, "title": title},
    )
    return thread_id


async def merge_overlapping(db: AsyncSession, rounds: int = 3, touched: set | None = None) -> int:
    """Fold threads that turn out to be the same story into one. Returns merges.

    Incremental clustering splits: two outlets break the same story hours apart,
    neither article is close enough to the other's seed set at the time, and the
    corpus ends up with "StyleSmuggler: Unpatched Magento Zero-Day" and
    "Unpatched Magento and Adobe Commerce Zero-Day Exploited" as separate
    threads. Their centroids sit at 0.94 once both have a few members, so the
    split is trivially visible after the fact even though it was not visible
    during assignment.

    Merging requires overlapping (or adjacent) time ranges as well as centroid
    similarity: the same subject a month apart is a sequel, not a continuation.
    """
    threshold = _knob("thread_merge_similarity", 0.92)
    gap_days = int(_knob("thread_gap_days", 5))
    merged = 0

    for _ in range(rounds):
        pair = (
            (
                await db.execute(
                    text(
                        """
                    SELECT a.id AS keep_id, b.id AS drop_id
                    FROM story_threads a
                    JOIN story_threads b
                      ON a.id <> b.id
                     AND a.status = 'open' AND b.status = 'open'
                     AND a.centroid IS NOT NULL AND b.centroid IS NOT NULL
                     AND (a.entry_count, a.id::text) > (b.entry_count, b.id::text)
                     AND 1 - (a.centroid <=> b.centroid) >= :threshold
                     AND b.first_seen <= a.last_seen + make_interval(days => :gap_days)
                     AND a.first_seen <= b.last_seen + make_interval(days => :gap_days)
                    ORDER BY a.centroid <=> b.centroid
                    LIMIT 1
                    """
                    ),
                    {"threshold": threshold, "gap_days": gap_days},
                )
            )
            .mappings()
            .first()
        )
        if pair is None:
            break

        keep_id, drop_id = pair["keep_id"], pair["drop_id"]
        await db.execute(
            text("UPDATE story_thread_entries SET thread_id = :keep WHERE thread_id = :drop"),
            {"keep": keep_id, "drop": drop_id},
        )
        await db.execute(text("DELETE FROM story_threads WHERE id = :drop"), {"drop": drop_id})
        # One story, one opening article: whichever of the two came first.
        await db.execute(
            text(
                """
                UPDATE story_thread_entries SET role = 'beat'
                WHERE thread_id = :keep AND role = 'origin'
                """
            ),
            {"keep": keep_id},
        )
        await db.execute(
            text(
                """
                UPDATE story_thread_entries SET role = 'origin'
                WHERE id = (
                    SELECT ste.id FROM story_thread_entries ste
                    JOIN entries e ON e.id = ste.entry_id
                    WHERE ste.thread_id = :keep AND ste.role <> 'echo'
                    ORDER BY e.published_at ASC NULLS LAST
                    LIMIT 1
                )
                """
            ),
            {"keep": keep_id},
        )
        # The spine describes a member set that just changed.
        await db.execute(text("UPDATE story_threads SET narrative_hash = NULL WHERE id = :keep"), {"keep": keep_id})
        await refresh_thread(db, keep_id)
        if touched is not None:
            # Every member of the survivor now belongs to a bigger story than
            # it was scored against.
            touched.add(keep_id)
        merged += 1

    return merged


async def prune_threads(db: AsyncSession, since: datetime, limit: int = 200) -> dict:
    """Reconcile threads with a membership that changed underneath them.

    Feed retention and feed deletion cascade through ``story_thread_entries``,
    which leaves the thread itself holding counts, a centroid and a spine for
    articles that no longer exist. A thread left holding fewer than two members
    is not a story that lost an article, it is the residue of one. Threads
    created during this pass are exempt — they are mid-assembly.
    """
    dropped = (
        (
            await db.execute(
                text(
                    """
                    DELETE FROM story_threads t
                    WHERE t.created_at < :since
                      AND (SELECT COUNT(*) FROM story_thread_entries ste WHERE ste.thread_id = t.id) < 2
                    RETURNING t.id
                    """
                ),
                {"since": since},
            )
        )
        .scalars()
        .all()
    )

    stale = (
        (
            await db.execute(
                text(
                    """
                    SELECT t.id FROM story_threads t
                    JOIN LATERAL (
                        SELECT COUNT(*) AS n FROM story_thread_entries ste WHERE ste.thread_id = t.id
                    ) m ON true
                    WHERE m.n <> t.entry_count
                    LIMIT :limit
                    """
                ),
                {"limit": limit},
            )
        )
        .scalars()
        .all()
    )
    for thread_id in stale:
        await refresh_thread(db, thread_id)
    if stale:
        # The spine describes a member set that no longer exists as described.
        await db.execute(
            text("UPDATE story_threads SET narrative_hash = NULL WHERE id = ANY(:ids)"),
            {"ids": list(stale)},
        )
    return {"pruned": len(dropped), "reconciled": len(stale)}


async def assign_entries(db: AsyncSession, limit: int = 500) -> dict:
    """One incremental pass: join, seed, or leave alone. Returns run stats."""
    window_days = int(_knob("thread_window_days", 21))
    dormancy_days = int(_knob("thread_dormancy_days", 14))
    join_sim = _knob("thread_join_similarity", 0.84)
    join_sim_no_entity = _knob("thread_join_similarity_no_entity", 0.90)
    seed_sim = _knob("thread_seed_similarity", 0.84)
    dup_sim = _knob("thread_duplicate_similarity", 0.90)
    min_entries = int(_knob("thread_min_entries", 3))
    min_sources = int(_knob("thread_min_sources", 2))
    gap_days = int(_knob("thread_gap_days", 5))
    min_body = int(_knob("thread_min_body_chars", 400))

    now = datetime.now(UTC)
    cutoff = now - timedelta(days=window_days)
    dormant_cutoff = now - timedelta(days=dormancy_days)

    candidates = await _candidate_entries(db, cutoff, limit, min_body, gap_days)
    stats = {"considered": len(candidates), "joined": 0, "echoed": 0, "seeded": 0, "unthreaded": 0}
    if not candidates:
        return stats

    touched: set[uuid.UUID] = set()
    ambient = await ambient_entities(db, cutoff)
    entity_map = {
        entry_id: ents - ambient for entry_id, ents in (await entry_entities(db, [c["id"] for c in candidates])).items()
    }

    for entry in candidates:
        # A neighbour processed earlier in this same pass may already have taken
        # this entry into a seeded thread.
        already = await db.execute(text("SELECT 1 FROM story_thread_entries WHERE entry_id = :e"), {"e": entry["id"]})
        if already.first():
            continue

        entry_ents = entity_map.get(entry["id"], set())
        entry_source = _source_key(entry.get("url"), entry.get("feed_id"))
        joined = False

        # A story is bursty. An article three weeks after the thread's last one
        # is a new story about an old subject, not the same story continuing.
        gap_cutoff = (entry["published_at"] or now) - timedelta(days=gap_days)

        for thread in await _nearest_threads(db, entry, dormant_cutoff, gap_cutoff, entry_source):
            thread_ents = {
                (e.get("entity_type"), e.get("entity_id")) for e in (thread.get("key_entities") or [])
            } - ambient
            shares_entity = bool(entry_ents & thread_ents)
            # Past this size a thread's pull is mostly its own gravity: it has
            # accumulated enough vocabulary to look like every article in its
            # field. Growth has to be evidenced by a shared entity from here on.
            if not shares_entity and int(thread["entry_count"] or 0) >= ENTITY_REQUIRED_ABOVE:
                continue
            # Entity-dense on both sides but barely overlapping: a catalogue,
            # not a continuation.
            if _is_roundup_join(entry_ents, thread_ents):
                continue
            # One outlet's own back catalogue. Past the cap it contributes
            # nothing further — not even as an echo, which is the exemption six
            # unrelated Red Hat errata used to chain themselves into one story.
            if int(thread["same_source_members"] or 0) >= SAME_SOURCE_LIMIT:
                continue
            closest = await _closest_member(db, thread["id"], entry["id"])
            similarity = float(closest["similarity"] or 0) if closest else 0.0
            centroid_similarity = float(thread["similarity"] or 0)
            required = join_sim if shares_entity else join_sim_no_entity
            if similarity < required or centroid_similarity < required - CENTROID_MARGIN:
                continue

            is_echo = similarity >= dup_sim and not (entry_ents - thread_ents)

            role, duplicate_of = ("echo", closest["entry_id"]) if is_echo else ("beat", None)

            await _add_member(db, thread["id"], entry, similarity, role, duplicate_of)
            touched.add(thread["id"])
            stats["echoed" if role == "echo" else "joined"] += 1
            joined = True
            break

        if joined:
            continue

        # Nothing to continue — is this the start of something?
        anchor_at = entry["published_at"] or now
        seed_floor = anchor_at - timedelta(days=gap_days)
        seed_ceiling = anchor_at + timedelta(days=gap_days)
        nearby = await _nearest_unthreaded(db, entry["id"], max(cutoff, seed_floor), seed_ceiling, min_body)
        neighbours = _cap_by_source(entry, [n for n in nearby if float(n["similarity"] or 0) >= seed_sim])
        members = [entry, *neighbours]
        source_counts = Counter(_source_key(m.get("url"), m.get("feed_id")) for m in members)
        # A publisher's own series clears every similarity bar there is, so the
        # seed gate is about independence, not closeness: enough distinct
        # outlets, and no single one carrying the thread on its own.
        dominant_share = max(source_counts.values()) / len(members)
        if len(members) < min_entries or len(source_counts) < min_sources or dominant_share > DOMINANT_SOURCE_SHARE:
            stats["unthreaded"] += 1
            continue

        member_ents = {
            entry_id: ents - ambient
            for entry_id, ents in (await entry_entities(db, [n["id"] for n in neighbours])).items()
        }
        # Entity-dense, entity-disjoint: instalments of a format rather than
        # coverage of one event.
        if _is_roundup_seed([entry_ents, *(member_ents.get(n["id"], set()) for n in neighbours)]):
            stats["unthreaded"] += 1
            continue

        thread_id = await _create_thread(db, entry)
        await _add_member(db, thread_id, entry, 1.0, "origin")
        for neighbour in neighbours:
            similarity = float(neighbour["similarity"] or 0)
            is_echo = similarity >= dup_sim and not (member_ents.get(neighbour["id"], set()) - entry_ents)
            await _add_member(
                db,
                thread_id,
                neighbour,
                similarity,
                "echo" if is_echo else "beat",
                entry["id"] if is_echo else None,
            )
            stats["echoed" if is_echo else "joined"] += 1
        touched.add(thread_id)
        stats["seeded"] += 1

    stats["merged"] = await merge_overlapping(db, touched=touched)

    # Every candidate has now been looked at, threaded or not. Without this the
    # next pass re-offers the same articles and never reaches the rest of the
    # window.
    await db.execute(
        text("UPDATE entry_embeddings SET threaded_checked_at = now() WHERE entry_id = ANY(:ids)"),
        {"ids": [c["id"] for c in candidates]},
    )

    for thread_id in touched:
        await refresh_thread(db, thread_id)

    stats.update(await prune_threads(db, since=now))

    # Whose score is now out of date. An article is always scored before the
    # platform knows which story it belongs to, and a thread gaining a member
    # changes the outlet count every other member was scored against.
    stats["touched_thread_ids"] = [str(t) for t in touched]

    # A thread that went quiet stops competing for new articles, but keeps its
    # page and its history.
    await db.execute(
        text(
            "UPDATE story_threads SET status = 'dormant', updated_at = now() "
            "WHERE status = 'open' AND last_seen IS NOT NULL AND last_seen < :cutoff"
        ),
        {"cutoff": dormant_cutoff},
    )
    await db.commit()
    return stats


async def fold_by_thread(db: AsyncSession, entries: list) -> tuple[list, dict]:
    """Collapse articles that are the same story into one, carrying its coverage.

    A briefing over 30 articles where 8 of them are the same PaperCut story
    spends most of the model's attention — and most of the reader's — saying
    that story eight times. The model has no way to know they are one event; it
    sees eight titles. Threads already know, so the batch is folded before the
    prompt is built: one article per story, the strongest one, plus how many
    outlets carried it.

    Takes anything with ``id`` and ``priority_score`` (ORM rows in both call
    sites). Returns the kept items in their original order and a coverage map
    keyed by the id of each representative. Items no thread holds pass through
    untouched and appear in neither map.
    """
    entry_ids = [e.id for e in entries]
    if not entry_ids:
        return entries, {}
    rows = (
        (
            await db.execute(
                text(
                    """
                SELECT ste.entry_id, ste.role, t.id AS thread_id, t.title, t.source_count
                FROM story_thread_entries ste
                JOIN story_threads t ON t.id = ste.thread_id
                WHERE ste.entry_id = ANY(:ids)
                """
                ),
                {"ids": entry_ids},
            )
        )
        .mappings()
        .all()
    )
    by_entry = {r["entry_id"]: dict(r) for r in rows}
    if not by_entry:
        return entries, {}

    groups: dict[tuple, list] = {}
    order: list[tuple] = []
    for entry in entries:
        row = by_entry.get(entry.id)
        key = ("thread", row["thread_id"]) if row else ("entry", entry.id)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(entry)

    kept: list = []
    coverage: dict = {}
    for key in order:
        members = groups[key]
        # The story's strongest article represents it, and a folded re-report
        # never represents the story it re-reports.
        representative = max(
            members,
            key=lambda e: (by_entry.get(e.id, {}).get("role") != "echo", e.priority_score or 0),
        )
        kept.append(representative)
        row = by_entry.get(representative.id)
        if row is None:
            continue  # no thread holds it; it is simply itself
        coverage[representative.id] = {
            "thread_title": row["title"] or "",
            "outlet_count": int(row["source_count"] or 0),
            "also_reported_by": len(members) - 1,
        }
    return kept, coverage


# --------------------------------------------------------------------- reads


async def list_threads(
    db: AsyncSession,
    user_id: uuid.UUID,
    status: str = "open",
    limit: int = 40,
    q: str | None = None,
) -> list[dict]:
    """Threads for the reading surfaces, most recently active first.

    ``top_score`` is the priority score of the best unread, non-echo member —
    the score the thread row takes in the ranked queue, because that member is
    what the reader would have read next anyway. ``unread_count`` counts every
    unread member including echoes, since those are the rows the thread folds.

    ``q`` filters on title, for the pickers that need to *find* a named story
    rather than read the most recent ones — following one onto a campaign, say.
    """
    rows = await db.execute(
        text(
            """
            SELECT t.id, t.slug, t.title, t.summary, t.status, t.entry_count, t.source_count,
                   t.echo_count, t.first_seen, t.last_seen, t.peak_at, t.key_entities,
                   t.narrated_at,
                   uts.last_opened_at,
                   m.unread_count, m.top_score, m.top_entry_id, m.new_since_opened, m.entry_ids
            FROM story_threads t
            LEFT JOIN user_thread_states uts ON uts.thread_id = t.id AND uts.user_id = :user_id
            JOIN LATERAL (
                SELECT COUNT(*) FILTER (WHERE ues.is_read IS NOT TRUE) AS unread_count,
                       MAX(e.priority_score) FILTER (
                           WHERE ues.is_read IS NOT TRUE AND ste.role <> 'echo'
                       ) AS top_score,
                       (ARRAY_AGG(e.id ORDER BY e.priority_score DESC NULLS LAST)
                        FILTER (WHERE ues.is_read IS NOT TRUE AND ste.role <> 'echo'))[1] AS top_entry_id,
                       COUNT(*) FILTER (
                           WHERE uts.last_opened_at IS NULL OR ste.added_at > uts.last_opened_at
                       ) AS new_since_opened,
                       ARRAY_AGG(e.id) AS entry_ids
                FROM story_thread_entries ste
                JOIN entries e ON e.id = ste.entry_id
                LEFT JOIN user_entry_states ues ON ues.entry_id = e.id AND ues.user_id = :user_id
                WHERE ste.thread_id = t.id
            ) m ON true
            WHERE (:status = 'any' OR t.status = :status)
              AND (CAST(:q AS text) IS NULL OR t.title ILIKE CAST(:q AS text))
            ORDER BY t.last_seen DESC NULLS LAST
            LIMIT :limit
            """
        ),
        {
            "user_id": user_id,
            "status": status,
            "limit": limit,
            "q": f"%{q.strip()}%" if q and q.strip() else None,
        },
    )
    return [dict(r) for r in rows.mappings().all()]


async def get_thread(db: AsyncSession, slug: str, user_id: uuid.UUID) -> dict | None:
    rows = await db.execute(
        text(
            """
            SELECT t.*, uts.last_opened_at
            FROM story_threads t
            LEFT JOIN user_thread_states uts ON uts.thread_id = t.id AND uts.user_id = :user_id
            WHERE t.slug = :slug
            """
        ),
        {"slug": slug, "user_id": user_id},
    )
    row = rows.mappings().first()
    return dict(row) if row else None


async def thread_members(db: AsyncSession, thread_id: uuid.UUID, user_id: uuid.UUID) -> list[dict]:
    rows = await db.execute(
        text(
            """
            SELECT ste.entry_id, ste.role, ste.similarity, ste.duplicate_of_entry_id, ste.source_key,
                   ste.added_at,
                   e.title, e.url, e.published_at, e.priority_score,
                   COALESCE(f.title, '') AS feed_title,
                   COALESCE(ues.is_read, false) AS is_read
            FROM story_thread_entries ste
            JOIN entries e ON e.id = ste.entry_id
            LEFT JOIN feeds f ON f.id = e.feed_id
            LEFT JOIN user_entry_states ues ON ues.entry_id = e.id AND ues.user_id = :user_id
            WHERE ste.thread_id = :thread_id
            ORDER BY e.published_at ASC NULLS LAST
            """
        ),
        {"thread_id": thread_id, "user_id": user_id},
    )
    return [dict(r) for r in rows.mappings().all()]


async def thread_beats(db: AsyncSession, thread_id: uuid.UUID) -> list[dict]:
    rows = await db.execute(
        text(
            """
            SELECT id, position, occurred_at, kind, headline, body, lead_entry_id,
                   entry_ids, collapsed_count, is_ai
            FROM story_thread_beats
            WHERE thread_id = :thread_id
            ORDER BY position ASC
            """
        ),
        {"thread_id": thread_id},
    )
    return [dict(r) for r in rows.mappings().all()]


async def thread_yield(db: AsyncSession, thread_id: uuid.UUID) -> dict:
    """What the thread has produced: techniques, CVEs, products, rules, echoes folded.

    The counts a reader uses to decide whether the story is worth working —
    every one of them from junction rows the platform already writes.
    """
    row = (
        (
            await db.execute(
                text(
                    """
                WITH members AS (
                    SELECT entry_id, role FROM story_thread_entries WHERE thread_id = :t
                )
                SELECT
                    (SELECT COUNT(DISTINCT ttp_id) FROM entry_ttps WHERE entry_id IN (SELECT entry_id FROM members))
                        AS techniques,
                    (SELECT COUNT(DISTINCT cve_id) FROM entry_cves WHERE entry_id IN (SELECT entry_id FROM members))
                        AS cves,
                    (SELECT COUNT(DISTINCT product_id) FROM entry_products
                     WHERE entry_id IN (SELECT entry_id FROM members)) AS products,
                    (SELECT COUNT(*) FROM detection_rules
                     WHERE entry_id IN (SELECT entry_id FROM members)) AS rules,
                    (SELECT COUNT(*) FROM members WHERE role = 'echo') AS echoes_folded
                """
                ),
                {"t": thread_id},
            )
        )
        .mappings()
        .first()
    )
    return dict(row or {})


async def nearest_threads(db: AsyncSession, thread_id: uuid.UUID, limit: int = 3) -> list[dict]:
    """Other stories this one resembles — the sideways pivot off a thread page."""
    rows = await db.execute(
        text(
            """
            WITH anchor AS (SELECT centroid FROM story_threads WHERE id = :t AND centroid IS NOT NULL)
            SELECT s.slug, s.title, s.status, s.entry_count,
                   1 - (s.centroid <=> anchor.centroid) AS similarity
            FROM story_threads s
            CROSS JOIN anchor
            WHERE s.id <> :t AND s.centroid IS NOT NULL
            ORDER BY s.centroid <=> anchor.centroid
            LIMIT :limit
            """
        ),
        {"t": thread_id, "limit": limit},
    )
    return [dict(r) for r in rows.mappings().all()]


# A neighbour below this cosine is not "more like this", it is merely the
# closest thing in the index — every entry has eight nearest neighbours whether
# or not any of them is related. The keyword path it replaced at least required
# a term in common; this is the equivalent bar.
SIMILAR_FLOOR = 0.7


async def similar_entries(
    db: AsyncSession,
    entry_id: uuid.UUID,
    limit: int = 8,
    min_similarity: float = SIMILAR_FLOOR,
    exclude_ids: list[uuid.UUID] | None = None,
) -> list[dict]:
    """ "More like this" — nearest neighbours across the whole embedded corpus.

    Not window-limited on purpose: the useful answer to "have we seen this
    before" is frequently a year old. ``exclude_ids`` carries the entry's own
    content-hash duplicates: the same article syndicated twice is a 1.0 match
    and tells the reader nothing.
    """
    rows = await db.execute(
        text(
            """
            WITH anchor AS (SELECT embedding FROM entry_embeddings WHERE entry_id = :entry_id)
            SELECT e.id AS entry_id, e.title, e.url, e.published_at, e.priority_score,
                   COALESCE(f.title, '') AS feed_title,
                   ste.thread_id,
                   1 - (ee.embedding <=> anchor.embedding) AS similarity
            FROM entry_embeddings ee
            JOIN entries e ON e.id = ee.entry_id
            LEFT JOIN feeds f ON f.id = e.feed_id
            LEFT JOIN story_thread_entries ste ON ste.entry_id = e.id
            CROSS JOIN anchor
            WHERE e.id <> ALL(:exclude)
            ORDER BY ee.embedding <=> anchor.embedding
            LIMIT :limit
            """
        ),
        {"entry_id": entry_id, "limit": limit, "exclude": [entry_id, *(exclude_ids or [])]},
    )
    # Filtered after the index scan rather than inside it: a predicate on the
    # distance expression turns the HNSW lookup into a filtered scan.
    return [dict(r) for r in rows.mappings().all() if float(r["similarity"] or 0) >= min_similarity]


async def mark_opened(db: AsyncSession, thread_id: uuid.UUID, user_id: uuid.UUID) -> None:
    await db.execute(
        text(
            """
            INSERT INTO user_thread_states (id, user_id, thread_id, last_opened_at)
            VALUES (:id, :user_id, :thread_id, now())
            ON CONFLICT (user_id, thread_id) DO UPDATE SET last_opened_at = now()
            """
        ),
        {"id": uuid.uuid4(), "user_id": user_id, "thread_id": thread_id},
    )
    await db.commit()
