"""One-time backfill: fetch og:image for entries missing image_url."""

import asyncio
import logging
import re

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("backfill")

OG_RE = re.compile(
    r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
OG_RE_ALT = re.compile(
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']',
    re.IGNORECASE,
)


async def backfill():
    engine = create_async_engine(settings.database_url)
    factory = async_sessionmaker(engine, class_=AsyncSession)

    async with factory() as db:
        rows = (
            await db.execute(
                text("""
                    SELECT e.id, e.url FROM entries e
                    JOIN feeds f ON e.feed_id = f.id
                    WHERE e.image_url IS NULL
                      AND e.url IS NOT NULL
                      AND f.feed_type IN ('rss', 'atom')
                    ORDER BY e.published_at DESC NULLS LAST
                    LIMIT 1000
                """)
            )
        ).all()

    log.info(f"Backfilling OG images for {len(rows)} entries")
    updated = 0

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=10.0,
        headers={"User-Agent": settings.user_agent},
    ) as client:
        for entry_id, url in rows:
            try:
                async with client.stream("GET", url) as resp:
                    if resp.status_code != 200:
                        continue
                    ct = resp.headers.get("content-type", "")
                    if "html" not in ct:
                        continue
                    chunks = []
                    total = 0
                    async for chunk in resp.aiter_bytes(4096):
                        chunks.append(chunk)
                        total += len(chunk)
                        if total >= 51200:
                            break
                    head = b"".join(chunks).decode("utf-8", errors="ignore")
                    m = OG_RE.search(head) or OG_RE_ALT.search(head)
                    if m:
                        og_url = m.group(1)
                        async with factory() as db:
                            await db.execute(
                                text("UPDATE entries SET image_url = :img WHERE id = :id"),
                                {"img": og_url, "id": entry_id},
                            )
                            await db.commit()
                        updated += 1
            except Exception:
                pass
            await asyncio.sleep(0.1)

    log.info(f"Backfill complete: {updated}/{len(rows)} entries updated with OG images")


if __name__ == "__main__":
    asyncio.run(backfill())
