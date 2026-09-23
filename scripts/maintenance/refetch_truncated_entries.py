"""Re-fetch full text for entries with truncated content (e.g. "Continue reading on Medium »").

Uses curl_cffi with browser impersonation to bypass Cloudflare bot protection.

Run inside the API container:
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/refetch_truncated_entries.py
"""

import asyncio
import hashlib
import re
import sys
import time

sys.path.insert(0, "/app")

from curl_cffi import requests as cffi_requests
from sqlalchemy import func, select

from app.database import async_session
from app.models.entry import Entry
from app.services.sanitizer import extract_og_image, html_to_text, sanitize_html

BATCH_SIZE = 100
MIN_EXTRACTED_LENGTH = 100


def compute_content_hash(title: str | None, content_text: str | None) -> str | None:
    if not title and not content_text:
        return None
    raw = (title or "") + (content_text or "")
    return hashlib.sha256(raw.encode()).hexdigest()


MEDIUM_DOMAINS = {
    "medium.com",
    "towardsdatascience.com",
    "betterprogramming.pub",
    "levelup.gitconnected.com",
    "blog.devgenius.io",
    "infosecwriteups.com",
    "systemweakness.com",
    "blog.securitybreak.io",
    "detect.fyi",
    "detecteng.com",
    "meetcyber.net",
    "blog.grumpygoose.io",
    "blog.opentide.org",
    "medium.engineering",
    "koifsec.medium.com",
}


def _is_medium(url: str) -> bool:
    """Check if URL is a Medium-hosted site (including custom domains)."""
    from urllib.parse import urlparse

    host = urlparse(url).hostname or ""
    if host in MEDIUM_DOMAINS or host.endswith(".medium.com"):
        return True
    return False


def _extract_medium_article(raw_html: str) -> str | None:
    """Extract article content from Medium's <article><section> structure.

    Resolves <picture> blocks by pulling srcSet URLs into <img> src attributes.
    """
    article_match = re.search(r"<article[^>]*>(.*?)</article>", raw_html, re.DOTALL)
    if not article_match:
        return None

    section_match = re.search(r"<section[^>]*>(.*?)</section>", article_match.group(1), re.DOTALL)
    content_html = section_match.group(1) if section_match else article_match.group(1)

    if not content_html or len(content_html) <= MIN_EXTRACTED_LENGTH:
        return None

    # Resolve Medium <picture> blocks: pull src from <source> srcSet into <img>
    def _resolve_picture(match: re.Match) -> str:
        picture_html = match.group(0)
        source_match = re.search(r'<source[^>]+data-testid="og"[^>]+srcSet="([^"]+)"', picture_html)
        if not source_match:
            source_match = re.search(r'<source[^>]+srcSet="([^"]+)"', picture_html)
        if not source_match:
            return picture_html
        srcset = source_match.group(1)
        urls = [part.strip().split()[0] for part in srcset.split(",") if part.strip()]
        img_url = urls[-1] if urls else None
        if not img_url:
            return picture_html
        img_match = re.search(r"<img\b([^>]*)(/?>)", picture_html)
        if not img_match:
            return picture_html
        img_attrs = img_match.group(1)
        if 'src="' not in img_attrs and "src='" not in img_attrs:
            img_attrs = f' src="{img_url}"' + img_attrs
        return f"<img{img_attrs}{img_match.group(2)}"

    content_html = re.sub(r"<picture[^>]*>.*?</picture>", _resolve_picture, content_html, flags=re.DOTALL)
    return content_html


def extract_full_text(url: str) -> tuple[str | None, str | None]:
    """Fetch URL with browser impersonation and extract article content."""
    try:
        response = cffi_requests.get(url, impersonate="chrome", timeout=15)
        if response.status_code != 200:
            return None, None

        content_type = response.headers.get("content-type", "")
        if "html" not in content_type:
            return None, None

        raw_html = response.text
        og_image = extract_og_image(raw_html)

        # Medium-specific extraction (readability misses most of their content)
        if _is_medium(url):
            content = _extract_medium_article(raw_html)
            if content and len(content) > MIN_EXTRACTED_LENGTH:
                return content, og_image

        # Fallback to readability for non-Medium sites
        from readability import Document

        doc = Document(raw_html)
        content = doc.summary()

        if content and len(content) > MIN_EXTRACTED_LENGTH:
            return content, og_image

        return None, og_image

    except Exception as e:
        print(f"  Failed to extract {url}: {e}")

    return None, None


async def main():
    # Accept optional feed_id as CLI argument to re-fetch all entries for a feed,
    # otherwise fall back to truncation pattern matching
    feed_id = sys.argv[1] if len(sys.argv) > 1 else None

    async with async_session() as db:
        if feed_id:
            condition = Entry.feed_id == feed_id
            label = f"feed {feed_id}"
        else:
            condition = Entry.content_html.op("~*")(r"Continue reading on .+ »")
            label = "truncation pattern"

        count_result = await db.execute(select(func.count(Entry.id)).where(condition))
        total = count_result.scalar() or 0
        print(f"Found {total} entries to re-fetch ({label})")

        if total == 0:
            return

        updated = 0
        failed = 0
        skipped = 0
        result = await db.execute(select(Entry).where(condition).order_by(Entry.published_at.desc()))
        entries = result.scalars().all()

        for entry in entries:
            if not entry.url:
                failed += 1
                continue

            extracted_html, og_image = extract_full_text(entry.url)
            if not extracted_html:
                print(f"  Could not extract: {entry.url}")
                failed += 1
                continue

            content_text = html_to_text(extracted_html)
            old_len = len(entry.content_text) if entry.content_text else 0
            new_len = len(content_text) if content_text else 0

            # Only update if we got more content
            if new_len <= old_len:
                skipped += 1
                continue

            sanitized = sanitize_html(extracted_html)
            word_count = len(content_text.split()) if content_text else None
            content_hash = compute_content_hash(entry.title, content_text)

            entry.content_html = sanitized
            entry.content_text = content_text
            entry.word_count = word_count
            entry.content_hash = content_hash

            if not entry.image_url and og_image:
                entry.image_url = og_image

            updated += 1
            print(f"  Updated: {entry.title[:70]} ({old_len} -> {new_len} chars)")

            # Be polite between fetches
            time.sleep(1)

        await db.commit()
        print(f"Done. {updated} updated, {skipped} skipped (already full), {failed} failed.")


if __name__ == "__main__":
    asyncio.run(main())
