"""Re-derive Entry.image_url for entries whose lead image is a tracking pixel
or a relative URL.

Decodes proxy URLs in content_html back to originals, re-runs
extract_first_image with the new tracker/dimension filter, and resolves
relative srcs against the entry URL.

Run inside the API container:
    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/refix_entry_image_urls.py
"""

import asyncio
import re
import sys
from urllib.parse import unquote

sys.path.insert(0, "/app")

from sqlalchemy import func, or_, select

from app.database import async_session
from app.models.entry import Entry
from app.services.sanitizer import extract_first_image
from app.workers.feed_tasks import _fetch_og_image

BATCH_SIZE = 500

_PROXY_SRC_RE = re.compile(r'src="/api/proxy/image\?url=([^"]+)"')


def _decode_proxy_srcs(html: str) -> str:
    """Revert proxy-wrapped <img src> back to the original URL for re-extraction."""
    return _PROXY_SRC_RE.sub(lambda m: f'src="{unquote(m.group(1))}"', html)


def _looks_broken(image_url: str | None) -> bool:
    if not image_url:
        return False
    if image_url.startswith("/") and not image_url.startswith("//"):
        return True
    lower = image_url.lower()
    return any(
        pat in lower
        for pat in (
            "matomo.php",
            "/piwik",
            "wp-piwik",
            "/__track",
            "/pixel.gif",
            "/pixel.png",
            "google-analytics.com",
            "googletagmanager.com",
            "doubleclick.net",
            "/utm.gif",
            "feedburner.com/~ff",
            "feeds.feedburner.com",
        )
    )


async def recover_null_images(feed_ids: list[str]) -> None:
    """For entries with image_url IS NULL in the given feeds, try og:image fetch."""
    async with async_session() as db:
        q = select(Entry).where(Entry.image_url.is_(None), Entry.feed_id.in_(feed_ids))
        entries = (await db.execute(q)).scalars().all()
        print(f"Recovering og:image for {len(entries)} null-image entries in {feed_ids}")
        recovered = 0
        for i, entry in enumerate(entries, 1):
            if not entry.url:
                continue
            try:
                img = await _fetch_og_image(entry.url)
            except Exception:
                img = None
            if img:
                entry.image_url = img
                recovered += 1
            if i % 25 == 0:
                await db.commit()
                print(f"  {i}/{len(entries)} recovered={recovered}")
        await db.commit()
        print(f"Done. recovered={recovered}/{len(entries)}")


async def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--recover-null":
        await recover_null_images(sys.argv[2].split(","))
        return
    async with async_session() as db:
        count_q = select(func.count(Entry.id)).where(
            or_(
                Entry.image_url.like("/%"),
                Entry.image_url.ilike("%matomo.php%"),
                Entry.image_url.ilike("%wp-piwik%"),
                Entry.image_url.ilike("%/piwik%"),
                Entry.image_url.ilike("%/__track%"),
                Entry.image_url.ilike("%google-analytics.com%"),
                Entry.image_url.ilike("%googletagmanager.com%"),
                Entry.image_url.ilike("%doubleclick.net%"),
                Entry.image_url.ilike("%feedburner.com/~ff%"),
                Entry.image_url.ilike("%feeds.feedburner.com%"),
            )
        )
        total = (await db.execute(count_q)).scalar() or 0
        print(f"Found {total} entries with broken image_url to refix")
        if total == 0:
            return

        last_id = None
        processed = 0
        updated = 0
        cleared = 0
        while True:
            q = (
                select(Entry)
                .where(
                    or_(
                        Entry.image_url.like("/%"),
                        Entry.image_url.ilike("%matomo.php%"),
                        Entry.image_url.ilike("%wp-piwik%"),
                        Entry.image_url.ilike("%/piwik%"),
                        Entry.image_url.ilike("%/__track%"),
                        Entry.image_url.ilike("%google-analytics.com%"),
                        Entry.image_url.ilike("%googletagmanager.com%"),
                        Entry.image_url.ilike("%doubleclick.net%"),
                        Entry.image_url.ilike("%feedburner.com/~ff%"),
                        Entry.image_url.ilike("%feeds.feedburner.com%"),
                    )
                )
                .order_by(Entry.id)
                .limit(BATCH_SIZE)
            )
            if last_id is not None:
                q = q.where(Entry.id > last_id)
            entries = (await db.execute(q)).scalars().all()
            if not entries:
                break

            for entry in entries:
                last_id = entry.id
                processed += 1
                if not _looks_broken(entry.image_url):
                    continue
                source_html = _decode_proxy_srcs(entry.content_html or "")
                new_image = extract_first_image(source_html, base_url=entry.url)
                if not new_image and entry.url:
                    try:
                        new_image = await _fetch_og_image(entry.url)
                    except Exception:
                        new_image = None
                if new_image and new_image != entry.image_url:
                    entry.image_url = new_image
                    updated += 1
                elif not new_image:
                    entry.image_url = None
                    cleared += 1

            await db.commit()
            print(f"  processed={processed}/{total} updated={updated} cleared={cleared}")

        print(f"Done. updated={updated} cleared={cleared} processed={processed}")


if __name__ == "__main__":
    asyncio.run(main())
