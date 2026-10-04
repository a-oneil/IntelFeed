"""Re-audit the shipped starter feed packs: is every source still alive?

A committed feed list rots. Sources move their RSS path, get absorbed by an
acquirer, or just stop publishing, and shipping a dead URL to every new install
is worse than shipping nothing — the user sees a feed with a red error count on
their first day and concludes the platform is broken.

Run this before a release and prune what it flags. It talks only to the public
internet, reads nothing from the database, and writes nothing anywhere, so it
runs fine on a laptop:

    python scripts/maintenance/audit_feed_packs.py
    python scripts/maintenance/audit_feed_packs.py --packs core,github-rules
    python scripts/maintenance/audit_feed_packs.py --stale-days 365 --json report.json

What it checks, per feed type:
  rss / atom / youtube / podcast  fetch it, parse out the newest item date
  github_repo                     the GitHub API's pushed_at, and archived
  reddit                          the subreddit's hot feed responds
  web_scraper                     the blog page responds
  nvd                             the NVD API responds

Caveats worth knowing before you delete anything:

  * Cloudflare-fronted sources answer a plain GET with 403 while IntelFeed's own
    fetcher gets through, and some date their items in a tag this script doesn't
    read. Those come back WARN, not DEAD — check the feed in the UI before
    cutting it.
  * GitHub and Reddit rate-limit a burst from one IP. Set GITHUB_TOKEN to raise
    the GitHub ceiling from 60/hour to 5,000; Reddit is paced automatically.
  * It runs from wherever you run it. A source that 403s a datacenter IP (CISA
    does) may pass from your laptop and fail in production.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))

from app.feed_packs import INTELFEED_NS, load_packs  # noqa: E402

UA = "IntelFeed-feed-pack-audit/1.0 (+https://github.com/a-oneil/IntelFeed)"
DATE_TAGS = re.compile(rb"<(?:pubDate|published|updated|dc:date)[^>]*>([^<]{6,60})</", re.I)

OK, WARN, DEAD = "OK", "WARN", "DEAD"


def ext(outline: ET.Element, name: str, default=None):
    return outline.get(f"{{{INTELFEED_NS}}}{name}", default)


def fetch(url: str, timeout: int = 45, limit: int = 400_000) -> bytes:
    headers = {"User-Agent": UA, "Accept": "*/*"}
    if "api.github.com" in url and (token := os.environ.get("GITHUB_TOKEN")):
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read(limit)


def parse_date(raw: str):
    for parser in (parsedate_to_datetime, datetime.fromisoformat):
        try:
            parsed = parser(raw.strip())
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except Exception:  # noqa: BLE001 — any unparseable date is just a miss
            continue
    return None


def check(job: tuple[str, ET.Element], cutoff: datetime) -> dict:
    pack_id, outline = job
    title = outline.get("text") or ""
    url = outline.get("xmlUrl") or ""
    feed_type = ext(outline, "feedType") or outline.get("type", "rss")
    config = json.loads(ext(outline, "config") or "{}")
    row = {"pack": pack_id, "title": title, "type": feed_type, "url": url}

    try:
        if feed_type == "github_repo":
            meta = json.loads(fetch(f"https://api.github.com/repos/{config['owner']}/{config['repo']}"))
            pushed = (meta.get("pushed_at") or "")[:10]
            if meta.get("archived"):
                return {**row, "status": DEAD, "detail": f"archived (last push {pushed})"}
            if pushed and pushed < cutoff.date().isoformat():
                return {**row, "status": DEAD, "detail": f"no push since {pushed}"}
            return {**row, "status": OK, "detail": f"pushed {pushed}"}

        if feed_type == "reddit":
            fetch(f"https://www.reddit.com/r/{config['subreddit']}/hot.rss?limit=1", timeout=25)
            return {**row, "status": OK, "detail": "hot feed responds"}

        if feed_type == "nvd":
            fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1")
            return {**row, "status": OK, "detail": "API responds"}

        if feed_type == "web_scraper":
            fetch(config.get("blog_url") or url)
            return {**row, "status": OK, "detail": "page responds"}

        body = fetch(url)
    except urllib.error.HTTPError as e:
        # 403/429 is very often bot protection or rate limiting rather than a
        # dead source, so it is a prompt to look, not a verdict.
        status = WARN if e.code in (403, 429) else DEAD
        return {**row, "status": status, "detail": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {**row, "status": WARN, "detail": type(e).__name__}

    dates = [d for raw in DATE_TAGS.findall(body) if (d := parse_date(raw.decode("utf-8", "replace")))]
    if not dates:
        return {**row, "status": WARN, "detail": "served no dated items"}
    newest = max(dates)
    if newest < cutoff:
        return {**row, "status": DEAD, "detail": f"newest item {newest.date()}"}
    return {**row, "status": OK, "detail": f"newest item {newest.date()}"}


def main(args: argparse.Namespace) -> int:
    packs = [p for p in load_packs() if not args.packs or p.id in args.packs]
    if unknown := set(args.packs or []) - {p.id for p in load_packs()}:
        sys.exit(f"Unknown pack(s): {', '.join(sorted(unknown))}")

    jobs = [
        (pack.id, outline)
        for pack in packs
        for outline in ET.parse(pack.path()).getroot().iter("outline")
        if outline.get("xmlUrl")
    ]
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.stale_days)
    print(f"Auditing {len(jobs)} feeds in {len(packs)} pack(s); stale after {args.stale_days} days.\n")

    # Reddit and GitHub both rate-limit bursts from one address, so their feeds
    # go through one at a time while the rest fan out.
    paced = [j for j in jobs if (ext(j[1], "feedType") or "") in ("reddit", "github_repo")]
    parallel = [j for j in jobs if j not in paced]

    rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows.extend(pool.map(lambda j: check(j, cutoff), parallel))
    for job in paced:
        rows.append(check(job, cutoff))
        time.sleep(args.pace)

    for status in (DEAD, WARN, OK):
        group = [r for r in rows if r["status"] == status]
        if not group or (status == OK and not args.verbose):
            continue
        print(f"--- {status} ({len(group)}) ---")
        for r in sorted(group, key=lambda r: (r["pack"], r["title"])):
            print(f"  {r['pack']:<22} {r['title'][:44]:<46} {r['detail']}")
        print()

    dead = sum(1 for r in rows if r["status"] == DEAD)
    warn = sum(1 for r in rows if r["status"] == WARN)
    print(f"{len(rows) - dead - warn} OK, {warn} to check by hand, {dead} to prune.")

    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2))
        print(f"Wrote {args.json}")

    # Non-zero only on a confirmed dead source, so this can gate a release
    # without WARN noise failing it.
    return 1 if dead else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--packs",
        type=lambda s: [p.strip() for p in s.split(",") if p.strip()],
        default=[],
        help="Only audit these pack ids (comma-separated). Default: all.",
    )
    parser.add_argument(
        "--stale-days", type=int, default=180, help="Call a source dead if nothing is newer than this (default 180)."
    )
    parser.add_argument("--workers", type=int, default=12, help="Parallel probes for the non-paced feeds.")
    parser.add_argument("--pace", type=float, default=3.0, help="Seconds between Reddit/GitHub probes.")
    parser.add_argument("--verbose", action="store_true", help="List the healthy feeds too.")
    parser.add_argument("--json", metavar="PATH", help="Also write the full result as JSON.")
    sys.exit(main(parser.parse_args()))
