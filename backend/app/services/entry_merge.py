"""Collapse copies of one article in a feed onto a single surviving entry.

A feed that churns guids stores the same post many times (one row per fetch).
``plan_same_url_merges`` groups a feed's rows by the same item key the fetcher
dedups on (normalised link + title + enclosure, see ``app.services.dedup``) and
picks the earliest row of each group as the keeper. ``merge_entries`` then
moves everything that references the copies onto the keeper and deletes the
copies.

What references an entry is read from the database catalog, not a hand-kept
list: every foreign key to ``entries.id`` is repointed, and where the column is
part of a unique key (``entry_tags``, ``entry_threat_actors``, ``user_entry_states``,
``story_thread_entries`` …) a copy's row that would collide with the keeper's —
or with another copy's — is dropped instead. Entity ``article_count`` is
decremented for every junction row dropped that way, since each link bumped it
once. A few columns hold entry ids without a foreign key (uuid[] and JSONB
arrays); those are listed in ``_ARRAY_REFS`` and rewritten in place.

Special cases:
- ``user_entry_states``: read / starred / bookmarked / hidden are OR-ed onto the
  keeper per user, so reading any copy counts as reading the article.
- ``ai_results``: each AI task keeps one entry's results — the keeper's if it
  has any for that task, else the copy with the newest result. Moving all of
  them would leave several ``is_current`` rows per task on one entry.
- ``entry_media``: not moved. The keeper has its own enclosure; the copies'
  rows go with them.

The caller commits, then removes the deleted ids from Meilisearch and re-pushes
the keepers' tag fields.
"""

import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entry import Entry
from app.models.entry_media import EntryMedia
from app.services.dedup import item_key

_MAP = "_entry_merge_map"

# Tables whose entry FK is handled outside the generic repoint.
_SPECIAL_FK_TABLES = {"entry_media", "ai_results"}

# Entry ids held without a foreign key: (table, column, kind).
_ARRAY_REFS = (
    ("detection_rules", "source_entries", "uuid[]"),
    ("detection_summaries", "entry_ids", "uuid[]"),
    ("entity_relationships", "evidence_entry_ids", "uuid[]"),
    ("entity_relationships", "reviewer_kept_entry_ids", "uuid[]"),
    ("intel_reports", "entry_ids", "uuid[]"),
    ("story_thread_beats", "entry_ids", "jsonb"),
    ("ai_conversations", "entry_ids", "jsonb"),
    ("ai_analysis_requests", "reused_from_entry_id", "uuid"),
)


@dataclass
class FeedMergePlan:
    feed_id: uuid.UUID
    rows: int = 0
    #: dupe id -> keeper id
    mapping: dict = field(default_factory=dict)
    #: keys (normalised URL) whose rows were left alone because titles or
    #: enclosures differ — distinct items sharing a link
    distinct_items_sharing_url: int = 0
    rows_sharing_url_not_merged: int = 0

    @property
    def groups(self) -> int:
        return len(set(self.mapping.values()))


async def plan_same_url_merges(db: AsyncSession, feed_id, *, ignore_title: bool = False) -> FeedMergePlan:
    """Group a feed's entries by item key; the earliest row of each group keeps.

    ``ignore_title`` merges rows without an enclosure on the link alone (for a
    feed known to retitle posts). Rows with an enclosure always need the same
    title and audio, so distinct podcast episodes sharing a show-notes URL are
    never merged.
    """
    plan = FeedMergePlan(feed_id=feed_id)
    rows = (
        await db.execute(
            select(Entry.id, Entry.url, Entry.title, Entry.created_at)
            .where(Entry.feed_id == feed_id)
            .order_by(Entry.created_at, Entry.id)
        )
    ).all()
    plan.rows = len(rows)
    if not rows:
        return plan

    enclosures: dict = {}
    media = await db.execute(
        select(EntryMedia.entry_id, EntryMedia.url)
        .join(Entry, Entry.id == EntryMedia.entry_id)
        .where(Entry.feed_id == feed_id)
    )
    for entry_id, media_url in media.all():
        # One enclosure per item in practice; min() keeps the choice stable.
        enclosures[entry_id] = min(media_url, enclosures.get(entry_id, media_url))

    groups: dict[tuple, list] = defaultdict(list)
    for row in rows:
        enclosure = enclosures.get(row.id)
        key = item_key(row.url, row.title, enclosure)
        if key is None:
            continue
        if ignore_title and enclosure is None:
            key = (key[0], None, None)
        groups[key].append(row.id)

    keys_per_url: Counter = Counter()
    rows_per_url: Counter = Counter()
    for key, ids in groups.items():
        keys_per_url[key[0]] += 1
        rows_per_url[key[0]] += len(ids)
        keeper = ids[0]
        for dupe in ids[1:]:
            plan.mapping[dupe] = keeper

    for url, n_keys in keys_per_url.items():
        if n_keys > 1:
            plan.distinct_items_sharing_url += n_keys
            plan.rows_sharing_url_not_merged += rows_per_url[url]
    return plan


def batch_by_keeper(mapping: dict, size: int):
    """Split a dupe -> keeper mapping into batches of about ``size`` dupes, never splitting a keeper."""
    by_keeper: dict = defaultdict(list)
    for dupe, keeper in mapping.items():
        by_keeper[keeper].append(dupe)
    batch: dict = {}
    for keeper, dupes in by_keeper.items():
        if batch and len(batch) + len(dupes) > size:
            yield batch
            batch = {}
        batch.update(dict.fromkeys(dupes, keeper))
    if batch:
        yield batch


async def _fetch(db: AsyncSession, sql: str, **params) -> list:
    return list((await db.execute(text(sql), params)).all())


async def _fk_references(db: AsyncSession) -> list[tuple[str, str, bool]]:
    """(table, column, not_null) for every single-column foreign key to entries.id."""
    rows = await _fetch(
        db,
        """
        SELECT c.conrelid::regclass::text, a.attname, a.attnotnull
        FROM pg_constraint c
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
        WHERE c.contype = 'f' AND c.confrelid = 'entries'::regclass AND cardinality(c.conkey) = 1
        ORDER BY 1, 2
        """,
    )
    return [(r[0], r[1], r[2]) for r in rows]


async def _unique_keys(db: AsyncSession, table: str, column: str) -> list[tuple[list[str], bool, list[bool]]]:
    """Unique indexes on ``table`` that include ``column``: (other columns, nulls_not_distinct, other_not_null)."""
    rows = await _fetch(
        db,
        """
        SELECT i.indnullsnotdistinct,
               array(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY k(n, o)
                     JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.n
                     ORDER BY k.o) AS cols,
               array(SELECT a.attnotnull FROM unnest(i.indkey) WITH ORDINALITY k(n, o)
                     JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.n
                     ORDER BY k.o) AS notnull
        FROM pg_index i
        JOIN pg_attribute ca ON ca.attrelid = i.indrelid AND ca.attname = :col
        WHERE i.indrelid = CAST(:tbl AS regclass) AND i.indisunique AND i.indpred IS NULL
          AND ca.attnum = ANY(i.indkey)
        """,
        tbl=table,
        col=column,
    )
    keys = []
    for nulls_not_distinct, cols, notnull in rows:
        others = [(c, nn) for c, nn in zip(cols, notnull, strict=True) if c != column]
        keys.append(([c for c, _ in others], bool(nulls_not_distinct), [nn for _, nn in others]))
    return keys


async def _counted_partners(db: AsyncSession, table: str) -> list[tuple[str, str]]:
    """(column, entity table) for this table's FKs to tables that keep an article_count."""
    rows = await _fetch(
        db,
        """
        SELECT a.attname, c.confrelid::regclass::text
        FROM pg_constraint c
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
        WHERE c.contype = 'f' AND c.conrelid = CAST(:tbl AS regclass)
          AND c.confrelid <> 'entries'::regclass AND cardinality(c.conkey) = 1
          AND EXISTS (SELECT 1 FROM pg_attribute x WHERE x.attrelid = c.confrelid
                      AND x.attname = 'article_count' AND NOT x.attisdropped)
        """,
        tbl=table,
    )
    return [(r[0], r[1]) for r in rows]


async def _table_exists(db: AsyncSession, table: str) -> bool:
    return (await db.execute(text("SELECT to_regclass(:t) IS NOT NULL"), {"t": table})).scalar()


async def merge_entries(db: AsyncSession, mapping: dict) -> dict[str, int]:
    """Move everything referencing each dupe onto its keeper, then delete the dupes.

    ``mapping`` is dupe id -> keeper id. Returns per-reference counts. Runs in
    the caller's transaction; nothing is committed here.
    """
    stats: Counter = Counter()
    if not mapping:
        return dict(stats)
    if set(mapping) & set(mapping.values()):
        raise ValueError("a keeper cannot also be a dupe")

    await db.execute(text(f"DROP TABLE IF EXISTS {_MAP}"))
    await db.execute(text(f"CREATE TEMP TABLE {_MAP} (dupe uuid PRIMARY KEY, keeper uuid NOT NULL)"))
    pairs = [{"d": str(d), "k": str(k)} for d, k in mapping.items()]
    await db.execute(text(f"INSERT INTO {_MAP} (dupe, keeper) VALUES (CAST(:d AS uuid), CAST(:k AS uuid))"), pairs)
    await db.execute(text(f"ANALYZE {_MAP}"))

    touched_threads = [
        r[0]
        for r in await _fetch(
            db,
            f"""
            SELECT DISTINCT thread_id FROM story_thread_entries
            WHERE entry_id IN (SELECT dupe FROM {_MAP} UNION SELECT keeper FROM {_MAP})
            """,
        )
    ]

    # Read state: OR every copy's flags onto the keeper, per user.
    agg = f"""
        SELECT m.keeper, s.user_id, bool_or(s.is_read) r, bool_or(s.is_starred) st,
               bool_or(s.is_bookmarked) b, bool_or(s.is_hidden) h, min(s.read_at) ra
        FROM user_entry_states s JOIN {_MAP} m ON m.dupe = s.entry_id
        GROUP BY m.keeper, s.user_id
    """
    res = await db.execute(
        text(f"""
        UPDATE user_entry_states k SET
            is_read = k.is_read OR a.r, is_starred = k.is_starred OR a.st,
            is_bookmarked = k.is_bookmarked OR a.b, is_hidden = k.is_hidden OR a.h,
            read_at = COALESCE(k.read_at, a.ra)
        FROM ({agg}) a WHERE k.entry_id = a.keeper AND k.user_id = a.user_id
        """)
    )
    stats["user_entry_states.merged"] += res.rowcount or 0
    res = await db.execute(
        text(f"""
        INSERT INTO user_entry_states (id, user_id, entry_id, is_read, is_starred, is_bookmarked, is_hidden, read_at)
        SELECT gen_random_uuid(), a.user_id, a.keeper, a.r, a.st, a.b, a.h, a.ra FROM ({agg}) a
        ON CONFLICT (user_id, entry_id) DO NOTHING
        """)
    )
    stats["user_entry_states.merged"] += res.rowcount or 0

    # AI results: per task, one entry's results survive.
    res = await db.execute(
        text(f"""
        WITH donor AS (
            SELECT DISTINCT ON (m.keeper, r.task_id) m.keeper, r.task_id, r.entry_id AS dupe
            FROM ai_results r JOIN {_MAP} m ON m.dupe = r.entry_id
            WHERE NOT EXISTS (SELECT 1 FROM ai_results k WHERE k.entry_id = m.keeper AND k.task_id = r.task_id)
            ORDER BY m.keeper, r.task_id, r.created_at DESC
        )
        UPDATE ai_results r SET entry_id = d.keeper,
            target_id = CASE WHEN r.target_type = 'entry' AND r.target_id = d.dupe THEN d.keeper ELSE r.target_id END
        FROM donor d WHERE r.entry_id = d.dupe AND r.task_id = d.task_id
        """)
    )
    stats["ai_results.entry_id"] += res.rowcount or 0

    decrements: dict[str, Counter] = defaultdict(Counter)
    for table, column, _not_null in await _fk_references(db):
        if table in _SPECIAL_FK_TABLES:
            continue
        partners = await _counted_partners(db, table)
        for others, nulls_not_distinct, others_not_null in await _unique_keys(db, table, column):
            partition = ", ".join([f"COALESCE(m.keeper, t.{column})", *[f"t.{c}" for c in others]])
            nullable_others = [c for c, nn in zip(others, others_not_null, strict=True) if not nn]
            null_guard = (
                ""
                if nulls_not_distinct or not nullable_others
                else " AND " + " AND ".join(f"t.{c} IS NOT NULL" for c in nullable_others)
            )
            returning = ", ".join(c for c, _ in partners) or "1"
            res = await db.execute(
                text(f"""
                DELETE FROM {table} WHERE ctid IN (
                    SELECT ctid FROM (
                        SELECT t.ctid, row_number() OVER (
                            PARTITION BY {partition}
                            ORDER BY (m.dupe IS NULL) DESC, t.ctid
                        ) AS rn
                        FROM {table} t LEFT JOIN {_MAP} m ON m.dupe = t.{column}
                        WHERE (t.{column} IN (SELECT dupe FROM {_MAP})
                               OR t.{column} IN (SELECT keeper FROM {_MAP})){null_guard}
                    ) ranked WHERE rn > 1
                ) RETURNING {returning}
                """)
            )
            dropped = res.all()
            stats[f"{table}.{column}.dropped"] += len(dropped)
            for i, (_partner_col, entity_table) in enumerate(partners):
                for row in dropped:
                    if row[i] is not None:
                        decrements[entity_table][row[i]] += 1
        res = await db.execute(
            text(f"UPDATE {table} t SET {column} = m.keeper FROM {_MAP} m WHERE t.{column} = m.dupe")
        )
        stats[f"{table}.{column}"] += res.rowcount or 0

    for entity_table, counts in decrements.items():
        by_n: dict[int, list] = defaultdict(list)
        for entity_id, n in counts.items():
            by_n[n].append(str(entity_id))
        for n, ids in by_n.items():
            await db.execute(
                text(f"""
                UPDATE {entity_table} SET article_count = GREATEST(COALESCE(article_count, 0) - :n, 0)
                WHERE id = ANY(CAST(:ids AS uuid[]))
                """),
                {"n": n, "ids": ids},
            )
        stats[f"{entity_table}.article_count_decrements"] += sum(counts.values())

    for table, column, kind in _ARRAY_REFS:
        if not await _table_exists(db, table):
            continue
        if kind == "uuid":
            sql = f"UPDATE {table} t SET {column} = m.keeper FROM {_MAP} m WHERE t.{column} = m.dupe"
        elif kind == "uuid[]":
            sql = f"""
            UPDATE {table} SET {column} = ARRAY(
                SELECT x FROM (
                    SELECT COALESCE(m.keeper, u.x) AS x, u.o
                    FROM unnest({table}.{column}) WITH ORDINALITY AS u(x, o)
                    LEFT JOIN {_MAP} m ON m.dupe = u.x
                ) s GROUP BY x ORDER BY min(o))
            WHERE {column} && (SELECT array_agg(dupe) FROM {_MAP})
            """
        else:
            sql = f"""
            UPDATE {table} SET {column} = COALESCE((
                SELECT jsonb_agg(x ORDER BY o) FROM (
                    SELECT x, min(o) AS o FROM (
                        SELECT COALESCE(to_jsonb(m.keeper::text), u.x) AS x, u.o
                        FROM jsonb_array_elements({table}.{column}) WITH ORDINALITY AS u(x, o)
                        LEFT JOIN {_MAP} m ON m.dupe::text = u.x #>> '{{}}'
                    ) s GROUP BY x
                ) s2), '[]'::jsonb)
            WHERE CASE WHEN jsonb_typeof({column}) = 'array' THEN EXISTS (
                SELECT 1 FROM jsonb_array_elements({column}) e JOIN {_MAP} m ON m.dupe::text = e #>> '{{}}'
            ) ELSE false END
            """
        res = await db.execute(text(sql))
        stats[f"{table}.{column}"] += res.rowcount or 0

    if touched_threads:
        await db.execute(
            text("""
            UPDATE story_threads t SET entry_count = (
                SELECT count(*) FROM story_thread_entries e WHERE e.thread_id = t.id)
            WHERE t.id = ANY(CAST(:ids AS uuid[]))
            """),
            {"ids": [str(t) for t in touched_threads]},
        )

    res = await db.execute(text(f"DELETE FROM entries WHERE id IN (SELECT dupe FROM {_MAP})"))
    stats["entries.deleted"] += res.rowcount or 0
    await db.execute(text(f"DROP TABLE {_MAP}"))
    return {k: v for k, v in sorted(stats.items()) if v}
