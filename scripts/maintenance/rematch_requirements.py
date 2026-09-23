"""Re-match all entries against intelligence requirements using whole-word matching.

Run inside the API container:
    docker compose -f docker-compose.dev.yml exec api python /app/scripts/maintenance/rematch_requirements.py
"""

import asyncio
import re
import sys
import time

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# Adjust path so we can import app modules
sys.path.insert(0, "/app")

from app.config import settings
from app.models.entry import Entry
from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch


async def rematch_all():
    engine = create_async_engine(settings.database_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        # Load all active auto-match requirements
        result = await db.execute(
            sa.select(IntelligenceRequirement).where(
                IntelligenceRequirement.status == "active",
                IntelligenceRequirement.auto_match == True,  # noqa: E712
            )
        )
        requirements = result.scalars().all()
        print(f"Found {len(requirements)} active auto-match requirements")

        # Build a single combined regex per requirement (much faster than per-keyword)
        req_patterns = []
        for req in requirements:
            keywords = [k for k in (req.keywords or []) if k.strip()]
            if not keywords:
                continue
            # Combine all keywords into one alternation pattern
            escaped = [re.escape(k.lower()) for k in keywords]
            combined = re.compile(r"(?<!\w)(?:" + "|".join(escaped) + r")(?!\w)")
            req_patterns.append((req, keywords, combined))

        print(f"  {len(req_patterns)} requirements have keywords")

        # Delete all existing keyword matches
        delete_result = await db.execute(sa.delete(RequirementMatch).where(RequirementMatch.match_type == "keyword"))
        deleted = delete_result.rowcount
        print(f"Deleted {deleted} existing keyword matches")

        # Reset all match counts to 0 (only keyword matches existed)
        await db.execute(sa.update(IntelligenceRequirement).values(match_count=0, last_matched_at=None))

        # Stream entries in batches using keyset (cursor) pagination
        total_entries = (await db.execute(sa.select(sa.func.count()).select_from(Entry))).scalar() or 0
        print(f"Re-matching against {total_entries} entries...")

        batch_size = 2000
        total_matches = 0
        match_counts = {req.id: 0 for req, _, _ in req_patterns}
        start = time.time()
        processed = 0
        last_id = None
        insert_buf = []
        seen_pairs = set()  # track (requirement_id, entry_id) to avoid PK violations
        flush_threshold = 5000

        while True:
            query = (
                sa.select(Entry.id, Entry.title, Entry.summary, Entry.content_text, Entry.feed_id)
                .order_by(Entry.id)
                .limit(batch_size)
            )
            if last_id is not None:
                query = query.where(Entry.id > last_id)

            result = await db.execute(query)
            rows = result.all()
            if not rows:
                break

            last_id = rows[-1][0]

            for entry_id, title, summary, content_text, feed_id in rows:
                combined_text = " ".join(filter(None, [title, summary, content_text])).lower()
                if not combined_text.strip():
                    continue

                for req, keywords, combined_pattern in req_patterns:
                    # Check feed filter
                    if req.linked_feed_ids and feed_id not in req.linked_feed_ids:
                        continue

                    # Single regex check for all keywords at once
                    m = combined_pattern.search(combined_text)
                    if m:
                        pair = (req.id, entry_id)
                        if pair not in seen_pairs:
                            seen_pairs.add(pair)
                            insert_buf.append(
                                {
                                    "requirement_id": req.id,
                                    "entry_id": entry_id,
                                    "match_type": "keyword",
                                    "matched_on": m.group(),
                                }
                            )
                            match_counts[req.id] += 1

            # Flush insert buffer periodically to keep memory bounded
            if len(insert_buf) >= flush_threshold:
                stmt = pg_insert(RequirementMatch.__table__).values(insert_buf).on_conflict_do_nothing()
                await db.execute(stmt)
                total_matches += len(insert_buf)
                insert_buf = []

            processed += len(rows)
            elapsed = time.time() - start
            rate = processed / elapsed if elapsed > 0 else 0
            print(
                f"  Processed {processed}/{total_entries} entries "
                f"({total_matches + len(insert_buf)} matches so far, {rate:.0f} entries/s)"
            )

        # Flush remaining
        if insert_buf:
            await db.execute(sa.insert(RequirementMatch), insert_buf)
            total_matches += len(insert_buf)
            insert_buf = []

        # Update match counts and last_matched_at
        for req, _, _ in req_patterns:
            count = match_counts[req.id]
            req.match_count = count
            if count > 0:
                latest = await db.execute(
                    sa.select(sa.func.max(RequirementMatch.matched_at)).where(RequirementMatch.requirement_id == req.id)
                )
                req.last_matched_at = latest.scalar()

        await db.commit()

        elapsed = time.time() - start
        print(f"\nDone in {elapsed:.1f}s")
        print(f"Total matches: {total_matches} (was {deleted})")
        print("\nPer-requirement breakdown:")
        for req, _, _ in req_patterns:
            print(f"  {req.title}: {match_counts[req.id]}")


if __name__ == "__main__":
    asyncio.run(rematch_all())
