"""Seed an observables-extraction fixture case from an article's own IOC section.

Finds the entry, renders it the way the analysis prompt does, locates the
indicator appendix (``find_indicator_section``), and nominates every
hash / IP / defanged token in it as an ``expected`` item — with the role text
the publisher printed beside it (parenthetical, or the table's description
cell) carried into ``note`` so you can set ``role`` by hand. Publisher
self-links and reference domains found anywhere in the article are written to
``must_not``. The output is a *draft*: review every line before committing.

Run inside the api container (``docker compose -f docker-compose.dev.yml exec api``):
    python scripts/dev/build_observable_fixture.py --title-like "China-nexus UAT-11587%" --slug talos-uat-11587 \
        --publisher "Cisco Talos" --actor UAT-11587 --malware Antino
    python scripts/dev/build_observable_fixture.py --title-like "Linux kernel: CVSS%" --slug neg-auscert --negative
"""

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, "/app")

from sqlalchemy import func, select  # noqa: E402

import app.models  # noqa: E402,F401
from app.database import async_session  # noqa: E402
from app.intelligence.observables import classify_value, is_defanged, refang, scan_candidates  # noqa: E402
from app.models.entry import Entry  # noqa: E402
from app.models.feed import Feed  # noqa: E402
from app.services.analysis_window import find_indicator_section, html_to_analysis_text  # noqa: E402

CASES_DIR = Path("/app/tests/fixtures/observables/cases")

#: Domains that are never indicators in a research article: the publishers,
#: the reference sites, the platforms authors link to.
REFERENCE_DOMAINS = (
    "talosintelligence.com",
    "bitdefender.com",
    "datadoghq.com",
    "huntress.com",
    "paloaltonetworks.com",
    "unit42.paloaltonetworks.com",
    "thedfirreport.com",
    "elastic.co",
    "microsoft.com",
    "sekoia.io",
    "attack.mitre.org",
    "nvd.nist.gov",
    "cve.org",
    "virustotal.com",
    "github.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "youtube.com",
    "wikipedia.org",
    "learn.microsoft.com",
    "docs.microsoft.com",
    "google.com",
    "snort.org",
    "clamav.net",
)

_ROLE_HINTS = (
    ("c2", r"\b(c2|command[- ]and[- ]control|beacon|controller|dead[- ]drop)\b"),
    ("exfil", r"\b(exfil|exfiltration)\b"),
    ("phishing", r"\b(phish|lure|decoy|sender)\b"),
    ("delivery", r"\b(deliver|delivery|staging|stager|download|dropper|loader|distribution|cdn|tracking)\b"),
    ("payload", r"\b(payload|backdoor|implant|agent|binary|sample|archive|dll|loader|module|script)\b"),
    ("exploit", r"\b(exploit)\b"),
    ("scanning", r"\b(scan|scanner)\b"),
)


def _role_from_note(note: str) -> str:
    low = note.lower()
    for role, pat in _ROLE_HINTS:
        if re.search(pat, low):
            return role
    return ""


def _label_after(line: str, token: str) -> str:
    """The description the publisher printed beside the value on the same line."""
    rest = line.split(token, 1)[1] if token in line else ""
    rest = rest.strip(" |:-–—\t")
    m = re.match(r"\(([^)]{3,160})\)", rest)
    if m:
        return m.group(1).strip()
    return rest[:160].strip()


async def build(args) -> dict:
    async with async_session() as db:
        q = (
            select(Entry, Feed.title)
            .join(Feed, Feed.id == Entry.feed_id)
            .where(Entry.title.like(args.title_like))
            .order_by(func.length(Entry.content_html).desc().nulls_last())
            .limit(1)
        )
        row = (await db.execute(q)).first()
        if row is None:
            raise SystemExit(f"no entry matches {args.title_like!r}")
        entry, feed_title = row
    text = html_to_analysis_text(entry.content_html) if entry.content_html else (entry.content_text or "")
    case = {
        "slug": args.slug,
        "title_like": args.title_like,
        "title": entry.title,
        "url": entry.url,
        "publisher": args.publisher or feed_title,
        "kind": "negative" if args.negative else "positive",
        "attribution": [{"type": "threat_actor", "name": a} for a in args.actor]
        + [{"type": "malware", "name": m} for m in args.malware],
        "expected": [],
        "optional": [],
        "must_not": [],
    }
    section = find_indicator_section(text) if not args.negative else None
    if not args.negative:
        region = text[section[0] : section[1]] if section else text[int(len(text) * 0.6) :]
        seen: set[tuple[str, str]] = set()
        for line in region.splitlines():
            for cand in scan_candidates(line, max_candidates=50):
                key = (cand.kind, cand.value)
                if key in seen:
                    continue
                seen.add(key)
                note = _label_after(line, cand.surface_form)
                case["expected"].append(
                    {"kind": cand.kind, "value": cand.value, "role": _role_from_note(note), "note": note}
                )
            # Fanged domains/URLs in a typed table row ("Domain | cdnorigin.net | …").
            if " | " in line:
                cells = [c.strip() for c in line.split("|")]
                for cell in cells:
                    classified = classify_value(cell)
                    if classified and classified not in seen and not is_defanged(cell):
                        host = classified[1].split("/")[2] if "://" in classified[1] else classified[1]
                        if any(host == d or host.endswith("." + d) for d in REFERENCE_DOMAINS):
                            continue
                        seen.add(classified)
                        note = " ".join(c for c in cells if c not in (cell,))[:160]
                        case["expected"].append(
                            {"kind": classified[0], "value": classified[1], "role": _role_from_note(note), "note": note}
                        )
        # Everything the body nominates *outside* the IOC section goes to
        # ``optional``: hashes and defanged values quoted in prose are usually
        # real, but whether each one belongs in the ledger is the reviewer's
        # call — neutral in scoring until promoted to ``expected``.
        if not args.negative:
            outside = (text[: section[0]] + "\n" + text[section[1] :]) if section else ""
            for cand in scan_candidates(outside, max_candidates=100):
                key = (cand.kind, cand.value)
                if key in seen:
                    continue
                seen.add(key)
                idx = outside.find(cand.surface_form)
                ctx = outside[max(0, idx - 80) : idx + len(cand.surface_form) + 80].replace("\n", " ")
                case["optional"].append({"kind": cand.kind, "value": cand.value, "note": ctx.strip()[:200]})
    # Garbage list: every reference-domain URL/host the article links to.
    hosts: set[str] = set()
    for m in re.finditer(r"https?://([a-z0-9.-]+)", refang(text), re.IGNORECASE):
        host = m.group(1).lower()
        if any(host == d or host.endswith("." + d) for d in REFERENCE_DOMAINS):
            hosts.add(host)
    for host in sorted(hosts)[:25]:
        case["must_not"].append({"kind": "domain", "value": host, "why": "publisher / reference link"})
    return case


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--title-like", required=True)
    ap.add_argument("--slug", required=True)
    ap.add_argument("--publisher", default="")
    ap.add_argument("--actor", action="append", default=[])
    ap.add_argument("--malware", action="append", default=[])
    ap.add_argument("--negative", action="store_true")
    ap.add_argument("--out-dir", default=str(CASES_DIR))
    args = ap.parse_args()
    case = await build(args)
    out = Path(args.out_dir) / f"{args.slug}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(case, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out}: {len(case['expected'])} expected, {len(case['must_not'])} must_not — review before committing")


if __name__ == "__main__":
    asyncio.run(main())
