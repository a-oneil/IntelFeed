"""Re-sanitize all entry content_html to fix broken proxy image URLs.

Run inside the API container:
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/resanitize_entries.py
"""

import asyncio
import re
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func, select

from app.database import async_session
from app.models.entry import Entry
from app.services.sanitizer import rewrite_image_urls

# Match existing proxy image URLs to extract the original URL
PROXY_RE = re.compile(r'/api/proxy/image\?url=([^"&]+)', re.IGNORECASE)

BATCH_SIZE = 500


def strip_proxy_urls(html: str) -> str:
    """Revert proxy image URLs back to original URLs for re-sanitization."""
    from urllib.parse import unquote

    def restore(match: re.Match) -> str:
        return unquote(match.group(1))

    return re.sub(
        r'src="/api/proxy/image\?url=([^"]+)"',
        lambda m: f'src="{restore(m)}"',
        html,
    )


async def main():
    async with async_session() as db:
        # Count entries with proxy URLs
        count_result = await db.execute(
            select(func.count(Entry.id)).where(Entry.content_html.ilike("%/api/proxy/image%"))
        )
        total = count_result.scalar() or 0
        print(f"Found {total} entries with proxy image URLs to re-sanitize")

        if total == 0:
            return

        offset = 0
        updated = 0
        while offset < total:
            result = await db.execute(
                select(Entry)
                .where(Entry.content_html.ilike("%/api/proxy/image%"))
                .order_by(Entry.id)
                .offset(offset)
                .limit(BATCH_SIZE)
            )
            entries = result.scalars().all()
            if not entries:
                break

            for entry in entries:
                original_html = strip_proxy_urls(entry.content_html)
                new_html = rewrite_image_urls(original_html, "/api/proxy/image")
                if new_html != entry.content_html:
                    entry.content_html = new_html
                    updated += 1

            await db.commit()
            offset += BATCH_SIZE
            print(f"  Processed {min(offset, total)}/{total} entries ({updated} updated)")

        print(f"Done. Updated {updated} entries.")


if __name__ == "__main__":
    asyncio.run(main())
