"""Re-clean the stored HTML of PDF entries with today's ``sanitize_pdf_html``.

PDF text is stored as the HTML PyMuPDF writes. Older entries kept its inline
styles (the PDF's font family, size and color on every span, plus fixed page
sizes and positions), which override the reader's theme: black text on a dark
background. Running the sanitizer again removes those styles. It only removes
markup, so running it twice changes nothing.

PDF entries are the ones whose guid starts with ``manual:pdf:``. Only
``content_html`` changes; the text, search documents and dedup hash stay the
same.

Dry-run by default; pass --apply to write.

Run inside the api container:

    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/restyle_pdf_entries.py
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/restyle_pdf_entries.py --apply
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import select

import app.models  # noqa: F401  (register every mapper)
from app.database import async_session
from app.models.entry import Entry
from app.services.ingest_parsers import sanitize_pdf_html

BATCH_SIZE = 200


async def main(apply: bool) -> None:
    changed = seen = 0
    last_id = None
    async with async_session() as db:
        while True:
            query = (
                select(Entry)
                .where(Entry.guid.like("manual:pdf:%"), Entry.content_html.is_not(None))
                .order_by(Entry.id)
                .limit(BATCH_SIZE)
            )
            if last_id is not None:
                query = query.where(Entry.id > last_id)
            entries = (await db.execute(query)).scalars().all()
            if not entries:
                break
            for entry in entries:
                seen += 1
                cleaned = sanitize_pdf_html(entry.content_html)
                if cleaned != entry.content_html:
                    changed += 1
                    print(f"{'restyle' if apply else 'would restyle'} {entry.id}  {(entry.title or '')[:80]}")
                    if apply:
                        entry.content_html = cleaned
            last_id = entries[-1].id
            if apply:
                await db.commit()
    verb = "Restyled" if apply else "Would restyle"
    print(f"{verb} {changed} of {seen} PDF entries.{'' if apply else ' Pass --apply to write.'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--apply", action="store_true", help="write the changes (default: dry run)")
    asyncio.run(main(parser.parse_args().apply))
