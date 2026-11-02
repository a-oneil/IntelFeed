"""Re-derive stored entries' ``content_text`` from their ``content_html``.

``sanitizer.html_to_text`` now separates text at block and table-cell
boundaries. Before that, neighbouring elements ran together, which split IPs
wrongly (46.233.40.20 + 4... read as 46.233.40.204), glued a CVSS score onto a
CVE id and made "power" + "Source:" read as "powerSource". Entries stored
before the fix keep the glued text until this script rewrites them.

For each entry:

    new = html_to_text(content_html) + the stored tail

The tail is what ingest appends after the HTML-derived text, kept exactly as
stored: ``\\n\\nTranscript:\\n...`` (YouTube; that transcript is also appended
to content_html as ``<div class="transcript">``, which is cut off before
deriving so it is not doubled) and ``\\n\\n[Image OCR]\\n...`` (Telegram). A
translation is never stored in content_text — readers append it at read time.

Only rows whose text changes are written, and only when the change is
whitespace alone: the old and new text must have the same characters once
whitespace is removed. A row that differs in more than whitespace was not
derived from this HTML (a re-listed copy, an upload whose text came from the
file) and is reported as ``differs``, not written. ``--include-differing``
writes those too. An empty content_text is filled from the HTML.

``content_hash`` is left alone. It hashes the title plus the first 500
characters of content_text and is what cross-feed dedup and the entry list's
DISTINCT ON fold match on; re-hashing could fold existing entries together
and would not stop the next fetch of an old article being stored again.
``word_count`` is updated to match the new text.

On --apply the changed entries' search documents get the new text (partial
update: content_text and word_count only). ``--rerun`` also queues the
autolink, observables and extract stages for each changed entry, followed by
its co-occurrence stage (Celery tasks; no AI call, no automation rules), at
most ``--rerun-max`` entries.

Dry-run by default; --apply writes, in batches of 500. Idempotent.

Run inside the api container:

    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/rederive_content_text.py --since 2026-01-01
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/rederive_content_text.py --apply --rerun
    # one feed, or one entry
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/rederive_content_text.py --feed <uuid> --apply
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/rederive_content_text.py --entry <uuid> --apply
"""

import argparse
import asyncio
import re
import sys
import uuid
from collections import Counter
from datetime import UTC, datetime

sys.path.insert(0, "/app")

from sqlalchemy import select, update

import app.models  # noqa: F401  (register every mapper)
from app.database import async_session
from app.models.entry import Entry
from app.services.sanitizer import html_to_text

BATCH_SIZE = 500
# What ingest appends to content_text after the HTML-derived text
# (app/workers/feed_tasks.py: the YouTube transcript and Telegram OCR).
TAIL_MARKERS = ("\n\nTranscript:\n", "\n\n[Image OCR]\n")
# The YouTube transcript is appended to content_html too, as this div.
_TRANSCRIPT_DIV_RE = re.compile(r'<div class="transcript">', re.IGNORECASE)
_WS_RE = re.compile(r"\s+")


# --------------------------------------------------------------------------- pure helpers


def split_tail(text: str | None) -> tuple[str, str]:
    """(html-derived head, appended tail) of a stored content_text."""
    text = text or ""
    cut = min((i for i in (text.find(m) for m in TAIL_MARKERS) if i >= 0), default=-1)
    return (text, "") if cut < 0 else (text[:cut], text[cut:])


def body_html(html: str, tail: str) -> str:
    """content_html without the transcript div ingest appended, when the
    stored text carries that transcript as its tail."""
    if "Transcript:\n" not in tail:
        return html
    m = None
    for m in _TRANSCRIPT_DIV_RE.finditer(html):  # the appended one is the last
        pass
    return html[: m.start()] if m else html


def _squeeze(text: str) -> str:
    return _WS_RE.sub("", text)


def rederive(html: str | None, stored: str | None) -> tuple[str, str | None]:
    """(status, new_text). status: no_html | unchanged | changed | filled |
    differs. new_text is set for changed / filled / differs."""
    if not html:
        return "no_html", None
    head, tail = split_tail(stored)
    new_head = html_to_text(body_html(html, tail))
    if not (stored or "").strip():
        return ("filled", new_head) if new_head.strip() else ("unchanged", None)
    new = new_head + tail
    if new == stored:
        return "unchanged", None
    if _squeeze(new_head) != _squeeze(head):
        return "differs", new
    return "changed", new


# --------------------------------------------------------------------------- db


def _update_search(rows: list[tuple[uuid.UUID, str, int]]) -> None:
    from app.services.meilisearch_client import INDEX_NAME, _get_client

    index = _get_client().index(INDEX_NAME)
    docs = [{"id": str(eid), "content_text": text[:50000], "word_count": wc} for eid, text, wc in rows]
    for i in range(0, len(docs), 1000):
        index.update_documents(docs[i : i + 1000])


def _rerun(entry_ids: list[uuid.UUID]) -> None:
    from celery import chord, group

    from app.pipeline.registry import PIPELINE_STAGES
    from app.workers.celery_app import celery_app

    def sig(stage: str, eid: str):
        return celery_app.signature(PIPELINE_STAGES[stage].task_path, args=[eid], immutable=True)

    for eid in entry_ids:
        e = str(eid)
        chord(group(sig("autolink", e), sig("observables", e), sig("extract", e)), sig("cooccurrence", e)).apply_async()


async def main(args) -> None:
    since = datetime.fromisoformat(args.since).replace(tzinfo=UTC) if args.since else None
    writable = {"changed", "filled"} | ({"differs"} if args.include_differing else set())
    stats: Counter = Counter()
    samples: list[str] = []
    changed_ids: list[uuid.UUID] = []
    search_failed = False
    last_id: uuid.UUID | None = None

    async with async_session() as db:
        while True:
            q = select(Entry.id, Entry.content_html, Entry.content_text).order_by(Entry.id).limit(BATCH_SIZE)
            if last_id is not None:
                q = q.where(Entry.id > last_id)
            if since is not None:
                q = q.where(Entry.created_at >= since)
            if args.feed:
                q = q.where(Entry.feed_id == uuid.UUID(args.feed))
            if args.entry:
                q = q.where(Entry.id == uuid.UUID(args.entry))
            rows = (await db.execute(q)).all()
            if not rows:
                break
            last_id = rows[-1][0]

            writes: list[tuple[uuid.UUID, str, int]] = []
            for eid, html, stored in rows:
                status, new = rederive(html, stored)
                stats[status] += 1
                if status == "differs" and len(samples) < 5:
                    samples.append(str(eid))
                if status in writable and new is not None:
                    writes.append((eid, new, len(new.split())))

            if args.apply and writes:
                for eid, text, wc in writes:
                    await db.execute(update(Entry).where(Entry.id == eid).values(content_text=text, word_count=wc))
                await db.commit()
                changed_ids.extend(eid for eid, _t, _w in writes)
                if not search_failed:
                    try:
                        _update_search(writes)
                    except Exception as e:
                        search_failed = True
                        print(f"Search update failed ({e}); run rebuild_search_indexes.py --entries-only.")
            stats["written" if args.apply else "would_write"] += len(writes)
            seen = sum(v for k, v in stats.items() if k not in ("written", "would_write"))
            if seen % (BATCH_SIZE * 20) < BATCH_SIZE:
                print(f"  scanned {seen} entries")

    print("\nEntries:")
    for k in ("unchanged", "changed", "filled", "differs", "no_html"):
        print(f"  {stats[k]:>8}  {k}")
    if samples:
        print(f"  differs, e.g.: {', '.join(samples)}" + ("" if args.include_differing else " (not written)"))
    if not args.apply:
        print(f"\n{stats['would_write']} entries would be rewritten. DRY RUN — re-run with --apply.")
        return
    print(f"\n{stats['written']} entries rewritten; content_hash left as it was.")
    if args.rerun and changed_ids:
        todo = changed_ids[: args.rerun_max]
        _rerun(todo)
        print(f"Queued autolink/observables/extract + co-occurrence for {len(todo)} entries.")
        rest = changed_ids[len(todo) :]
        if rest:
            path = "/tmp/rederive_not_queued.txt"
            with open(path, "w") as fh:
                fh.write("\n".join(str(e) for e in rest) + "\n")
            print(f"{len(rest)} more changed but not queued (--rerun-max); their ids are in {path}.")


def cli() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Write the new text (default: report only).")
    ap.add_argument("--since", help="Only entries created on or after this date (YYYY-MM-DD).")
    ap.add_argument("--feed", help="Only this feed (UUID).")
    ap.add_argument("--entry", help="Only this entry (UUID).")
    ap.add_argument("--include-differing", action="store_true", help="Also write rows that differ beyond whitespace.")
    ap.add_argument("--rerun", action="store_true", help="With --apply: queue the link stages for changed entries.")
    ap.add_argument("--rerun-max", type=int, default=5000, help="Queue at most this many entries (default 5000).")
    args = ap.parse_args()
    if args.rerun and not args.apply:
        ap.error("--rerun needs --apply")
    asyncio.run(main(args))


if __name__ == "__main__":
    cli()
