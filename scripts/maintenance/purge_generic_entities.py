"""Remove generic-name entities from the actor / malware / tool / vendor / product catalogs.

The creation gate (``generic_name_reason`` in
``app/intelligence/entity_resolution.py``) stops the extractor minting
"the threat actor", "North America", "Iranian hackers" or "remote access
trojan" as entities. Rows created before a rule existed are still in the
catalogue, and every article that mentions the phrase links to them — which
is what fills the review queues with remove-link and reclassify proposals
about the same junk names. This script applies today's gate to what is
already on file and deletes what fails it.

Three checks, the same ones the live gate runs, in this order:

    denylist      the name (or an alias) is on the analyst do-not-recreate list
    generic       ``generic_name_reason`` says so (head-noun phrases, regions,
                  AV strings, filenames, CVE ids, code symbols, and the
                  non-entity rules: protocols, cipher names, install
                  commands, code tokens, OS APIs, categories, technique
                  names, attribution descriptors, number-only actors)
    country       the name is a catalogue country, alias or demonym

Deletion goes through the review queues' own path
(``delete_named_entity`` in ``app/api/extraction.py``): entry links and
relationships go with the row, pending proposals about it are cleared, and
its names are denylisted so the pipeline never re-creates it. Nothing is
re-linked: a phrase like "the threat actor" carries no intelligence to keep.

Run inside the api container (scripts/ is read-only in prod, so the CSV goes
to /tmp there — the path is printed). A dry run is the default; nothing is
deleted without ``--apply``:

    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/purge_generic_entities.py

    # only rows a given rule flags (reason slugs, comma-separated)
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/purge_generic_entities.py \\
        --only protocol,shell_command,code_token,os_api

    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/purge_generic_entities.py \\
        --apply --plan /tmp/generic_entities.csv

CSV columns: ``action`` is the only one meant to be edited.
    action          delete (default) | skip | review
    entity_type     threat_actor | malware | tool | vendor | product
    entity_id
    name
    reason          denylist | generic:<slug> | country:<country name>
    aliases         pipe-separated
    entries         entry links on the row
    relationships   entity_relationships that go with it

Rows with many entry links are still defaulted to ``delete`` — a junk
phrase is junk however often it was matched — but ``--min-entries`` lists
them first in the report so they are the ones you read. The exception is a
heavily linked row flagged by a non-entity rule (``NON_ENTITY_REASONS``):
it defaults to ``review``, which ``--apply`` skips, because a concept with
hundreds of links (WebRTC, Kerberos) may be better reclassified to a product
than deleted. Change it to ``delete`` to remove it.
"""

import argparse
import asyncio
import csv
import os
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func, or_, select

from app.database import async_session
from app.intelligence.autolinker import refresh_vocabulary
from app.intelligence.correlation import ENTITY_CONFIG
from app.intelligence.entity_resolution import (
    NON_ENTITY_REASONS,
    RESOLVED_MODELS,
    _country_named,
    _denylist_hit,
    generic_name_reason,
    normalize_entity_name,
)
from app.models.entity_relationship import EntityRelationship

TYPES = ("threat_actor", "malware", "tool", "vendor", "product")
COUNTRY_GATED = {"threat_actor", "malware", "tool"}
DEFAULT_CSV = "generic_entities.csv"


def _csv_path(given: str | None) -> str:
    if given:
        return given
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(os.path.dirname(here), "out")
    try:
        os.makedirs(out, exist_ok=True)
        probe = os.path.join(out, ".w")
        open(probe, "w").close()
        os.remove(probe)
        return os.path.join(out, DEFAULT_CSV)
    except OSError:
        return os.path.join("/tmp", DEFAULT_CSV)


async def _reason(db, entity_type: str, entity) -> str | None:
    norm = normalize_entity_name(entity.name, entity_type)
    if await _denylist_hit(db, entity_type, norm) is not None:
        return "denylist"
    for alias in entity.aliases or []:
        if await _denylist_hit(db, entity_type, normalize_entity_name(alias, entity_type)) is not None:
            return "denylist"
    junk = generic_name_reason(entity_type, entity.name, norm)
    if junk:
        return f"generic:{junk}"
    if entity_type in COUNTRY_GATED:
        country = await _country_named(db, entity.name)
        if country:
            return f"country:{country}"
    return None


def reason_slug(reason: str) -> str:
    """'generic:protocol' -> 'protocol'; 'country:Iran' -> 'country'; 'denylist' -> 'denylist'."""
    head, _, tail = reason.partition(":")
    return tail if head == "generic" else head


def default_action(reason: str, entries: int, min_entries: int) -> str:
    if reason_slug(reason) in NON_ENTITY_REASONS and entries >= min_entries:
        return "review"
    return "delete"


async def scan(csv_path: str, min_entries: int, only: set[str] | None = None) -> None:
    rows: list[dict] = []
    async with async_session() as db:
        for entity_type in TYPES:
            model = RESOLVED_MODELS[entity_type]
            _m, junction, fk_col = ENTITY_CONFIG[entity_type]
            entities = (await db.execute(select(model).order_by(model.name))).scalars().all()
            for entity in entities:
                reason = await _reason(db, entity_type, entity)
                if reason is None or (only and reason_slug(reason) not in only):
                    continue
                entries = (
                    await db.execute(select(func.count()).select_from(junction).where(fk_col == entity.id))
                ).scalar_one()
                rels = (
                    await db.execute(
                        select(func.count())
                        .select_from(EntityRelationship)
                        .where(
                            or_(
                                (EntityRelationship.source_type == entity_type)
                                & (EntityRelationship.source_id == entity.id),
                                (EntityRelationship.target_type == entity_type)
                                & (EntityRelationship.target_id == entity.id),
                            )
                        )
                    )
                ).scalar_one()
                rows.append(
                    {
                        "action": default_action(reason, int(entries), min_entries),
                        "entity_type": entity_type,
                        "entity_id": str(entity.id),
                        "name": entity.name,
                        "reason": reason,
                        "aliases": "|".join(entity.aliases or []),
                        "entries": int(entries),
                        "relationships": int(rels),
                    }
                )
    rows.sort(key=lambda r: (-r["entries"], r["entity_type"], r["name"].lower()))
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["action"])
        w.writeheader()
        w.writerows(rows)
    by_type: dict[str, int] = {}
    by_reason: dict[str, int] = {}
    for r in rows:
        by_type[r["entity_type"]] = by_type.get(r["entity_type"], 0) + 1
        key = r["reason"].split(":")[0]
        by_reason[key] = by_reason.get(key, 0) + 1
    print(f"{len(rows)} generic-name entities found -> {csv_path}")
    for t, n in sorted(by_type.items()):
        print(f"  {t:13} {n}")
    print("  by check:", ", ".join(f"{k} {n}" for k, n in sorted(by_reason.items())))
    heavy = [r for r in rows if r["entries"] >= min_entries]
    if heavy:
        print(f"\nrows with >= {min_entries} entry links (read these first):")
        for r in heavy[:40]:
            print(f"  {r['entries']:6}  {r['entity_type']:13} {r['name']!r:45} {r['reason']:28} {r['action']}")
    review = sum(1 for r in rows if r["action"] == "review")
    if review:
        print(f"\n{review} rows default to action=review (heavily linked, non-entity rule): set delete or skip.")
    print("\nReview the CSV (set action=skip to keep a row), then re-run with --apply --plan <csv>.")


async def apply(plan_path: str) -> None:
    from app.api.extraction import delete_named_entity

    with open(plan_path, newline="") as fh:
        plan = [r for r in csv.DictReader(fh) if r.get("action", "").strip().lower() == "delete"]
    deleted = denied = missing = 0
    async with async_session() as db:
        for r in plan:
            entity_type = r["entity_type"]
            model = RESOLVED_MODELS[entity_type]
            entity = await db.get(model, r["entity_id"])
            if entity is None:
                missing += 1
                continue
            denied += await delete_named_entity(
                db, entity_type, entity, deny=True, reason=f"Generic name ({r['reason']}) purged by maintenance"
            )
            deleted += 1
        await db.commit()
        if deleted:
            await refresh_vocabulary(db)
    print(f"deleted {deleted}, denylisted {denied} names, {missing} already gone")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Scan the catalogs and write the review CSV (default).")
    mode.add_argument("--apply", action="store_true", help="Execute a reviewed plan CSV.")
    ap.add_argument("--csv", help="Where the dry run writes its plan (default scripts/out/, or /tmp when read-only).")
    ap.add_argument("--plan", help="Reviewed CSV to execute with --apply.")
    ap.add_argument("--min-entries", type=int, default=20, help="Report rows with at least this many links first.")
    ap.add_argument(
        "--only",
        help="Comma-separated reason slugs to keep (e.g. protocol,shell_command,denylist,country). Dry run only.",
    )
    args = ap.parse_args()
    if args.apply:
        if not args.plan:
            ap.error("--apply needs --plan <csv>")
        asyncio.run(apply(args.plan))
    else:
        only = {s.strip() for s in args.only.split(",") if s.strip()} if args.only else None
        asyncio.run(scan(_csv_path(args.csv), args.min_entries, only))


if __name__ == "__main__":
    main()
