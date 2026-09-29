"""Remove CVE identifiers from the actor / malware / tool / vendor / product catalogs.

CVEs are their own entity type with their own ingest pipeline. When AI
extraction also mints a *malware family* called "CVE-2026-55193", the same
identifier is in the Aho-Corasick vocabulary twice: every mention of it links
to the CVE **and** to the impostor, the two then share every entry, and they
correlate with each other forever. The prod malware catalog had collected a
run of these (CVE-2026-11332 ... CVE-2026-81642).

Two shapes, both handled here:

    name   malware  "CVE-2026-55193"                      -> delete the row
    alias  malware  "Spring4Shell" aliases {CVE-2022-22965} -> strip the alias

The alias case is the subtler one. Spring4Shell genuinely *is* CVE-2022-22965,
so the alias looks harmless — but it is what produces the duplicate link. That
connection belongs in entity_relationships, not in an alias list.

Nothing is dropped on the floor. Before a name row is deleted, each of its
entries is re-linked to the real CVE entity for that id (created rows are never
invented: if no CVE row exists the entry links are reported as ``orphaned`` and
the row defaults to ``skip`` so an analyst decides). For alias rows only the
links that alias alone produced are purged — a junction row whose matched_names
also include the entity's real name would have existed anyway. Analyst-sourced
links are never touched.

Entity relationships attached to a deleted row go with it, as they do on the
API's delete path. The CSV reports the count so a row with real relationship
evidence can be flipped to ``skip`` and handled by hand.

:func:`app.intelligence.entity_resolution.cve_shaped_name` is the same
predicate the live gate uses, so this script and the gate can never disagree
about what counts as a CVE identifier.

Run inside the api container (scripts/ is read-only in prod, so the CSV goes
to /tmp there — the path is printed):

    docker compose -f docker-compose.prod.yml exec -T api \
        python scripts/maintenance/purge_cve_named_entities.py --dry-run

    docker compose -f docker-compose.prod.yml exec -T api \
        python scripts/maintenance/purge_cve_named_entities.py \
        --apply --plan /tmp/cve_named_entities.csv

CSV columns: action is the only one meant to be edited.
    action          delete / strip (default for the row's kind) | skip
    kind            name (the entity is a CVE id) | alias (it carries one)
    cve             the identifier found
    cve_row         the matching CVE entity's uuid, or "" if none exists
    entries         entry links on the entity
    links_moved     name rows: links the CVE entity does NOT already have, which
                    will be re-pointed at it. Usually 0 — see links_already.
    links_already   name rows: links the CVE entity already carries, i.e. the
                    duplicate pairs this whole exercise is about. Deleting the
                    impostor loses nothing for these.
    links_orphaned  name rows: links with nowhere to go (no CVE row) — these
                    are lost on delete, so such rows default to skip
    links_purged    alias rows: links attributable to this alias alone
    links_protected analyst-sourced links, never touched
    relationships   entity_relationships that go with a deleted row
"""

import argparse
import asyncio
import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, "/app")

from sqlalchemy import delete, or_, select

from app.database import async_session
from app.intelligence.correlation_cache import invalidate_entity_cache
from app.intelligence.entity_resolution import (
    _CVE_IN_NAME_RE,
    cve_shaped_name,
    normalize_entity_name,
)
from app.models.cve import CVE, EntryCVE
from app.models.entity_relationship import EntityRelationship
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.product import EntryProduct, Product
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.vendor import EntryVendor, Vendor
from app.services.entity_indexer import delete_entity_document

TYPES: dict[str, tuple] = {
    "threat_actor": (ThreatActor, EntryThreatActor, "threat_actor_id"),
    "malware": (MalwareFamily, EntryMalware, "malware_family_id"),
    "tool": (Tool, EntryTool, "tool_id"),
    "vendor": (Vendor, EntryVendor, "vendor_id"),
    "product": (Product, EntryProduct, "product_id"),
}

DEFAULT_OUT = "/app/scripts/out/cve_named_entities.csv"

# Links an analyst made or confirmed are evidence, not autolinker noise.
PROTECTED_SOURCES = {"manual", "analyst", "analyst_created", "analyst_confirmed"}

FIELDNAMES = [
    "action",
    "kind",
    "entity_type",
    "entity_name",
    "entity_id",
    "cve",
    "cve_row",
    "entries",
    "links_moved",
    "links_already",
    "links_orphaned",
    "links_purged",
    "links_protected",
    "relationships",
]


def _writable_out(path: str) -> str:
    """Resolve the CSV path, falling back to /tmp on a read-only mount."""
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, exist_ok=True)
        probe = os.path.join(directory, ".write-probe")
        with open(probe, "w"):
            pass
        os.unlink(probe)
        return path
    except OSError:
        fallback = os.path.join("/tmp", os.path.basename(path))
        print(f"{directory} is not writable (read-only mount?) — writing to {fallback} instead")
        return fallback


def _cve_id(text: str) -> str:
    """The canonical CVE-YYYY-NNNN form inside ``text``, uppercased.

    The gate also accepts "CVE 2026-55193" and "CVE_2026-55193", so the
    separator is normalized back to a hyphen before lookup.
    """
    m = _CVE_IN_NAME_RE.search(text or "")
    if not m:
        return ""
    return "CVE-" + m.group(0)[3:].lstrip("-_ ").upper()


async def _cve_rows(db) -> dict[str, CVE]:
    rows = (await db.execute(select(CVE))).scalars().all()
    return {r.cve_id.upper(): r for r in rows}


async def _relationship_count(db, entity_type: str, entity_id) -> int:
    rows = (
        await db.execute(
            select(EntityRelationship.id).where(
                or_(
                    (EntityRelationship.source_type == entity_type) & (EntityRelationship.source_id == entity_id),
                    (EntityRelationship.target_type == entity_type) & (EntityRelationship.target_id == entity_id),
                )
            )
        )
    ).all()
    return len(rows)


async def _uncovered(db, links, cve_row) -> int:
    """How many of ``links`` the CVE entity does NOT already cover.

    The common case is zero: the autolinker linked the entry to the CVE *and*
    to the impostor, which is the whole bug. Reporting the raw link count as
    "will move" would tell an operator 70 links are about to be rescued when in
    fact all 70 are already on the CVE and the delete is a pure de-duplication.
    A non-zero value here is the interesting one — it means the CVE genuinely
    lacks entries the impostor was holding.
    """
    n = 0
    for j in links:
        exists = (
            await db.execute(
                select(EntryCVE.entry_id).where(EntryCVE.entry_id == j.entry_id, EntryCVE.cve_id == cve_row.id)
            )
        ).scalar_one_or_none()
        if exists is None:
            n += 1
    return n


async def _links(db, entity_type: str, entity_id):
    _model, junction, fk = TYPES[entity_type]
    return (await db.execute(select(junction).where(getattr(junction, fk) == entity_id))).scalars().all()


def _attributable(rows, entity_type: str, alias_norm: str) -> tuple[list, int]:
    """Links this alias alone produced: (purgeable rows, analyst-protected count).

    A junction row counts only when every surface form it recorded normalizes
    to this alias — a row that also matched the entity's real name would have
    existed anyway, so removing it would destroy a good link.
    """
    purgeable, protected = [], 0
    for j in rows:
        matched = list(getattr(j, "matched_names", None) or [])
        if not matched:
            continue
        if not all(normalize_entity_name(m, entity_type).norm_exact == alias_norm for m in matched):
            continue
        if (getattr(j, "source", None) or "") in PROTECTED_SOURCES:
            protected += 1
        else:
            purgeable.append(j)
    return purgeable, protected


async def propose(out_path: str) -> None:
    rows: list[dict] = []
    async with async_session() as db:
        cves = await _cve_rows(db)

        for entity_type, (model, _junction, _fk) in TYPES.items():
            for entity in (await db.execute(select(model))).scalars().all():
                links = None

                if cve_shaped_name(entity.name):
                    cve = _cve_id(entity.name)
                    cve_row = cves.get(cve)
                    links = await _links(db, entity_type, entity.id)
                    protected = sum(1 for j in links if (getattr(j, "source", None) or "") in PROTECTED_SOURCES)
                    orphaned = 0 if cve_row else len(links)
                    uncovered = await _uncovered(db, links, cve_row) if cve_row else 0
                    rows.append(
                        {
                            # No CVE row means the entry links have nowhere to
                            # go and deleting would lose them — make that the
                            # analyst's call, not the script's.
                            "action": "delete" if cve_row else "skip",
                            "kind": "name",
                            "entity_type": entity_type,
                            "entity_name": entity.name,
                            "entity_id": str(entity.id),
                            "cve": cve,
                            "cve_row": str(cve_row.id) if cve_row else "",
                            "entries": len(links),
                            "links_moved": uncovered,
                            "links_already": len(links) - uncovered if cve_row else 0,
                            "links_orphaned": orphaned,
                            "links_purged": 0,
                            "links_protected": protected,
                            "relationships": await _relationship_count(db, entity_type, entity.id),
                        }
                    )
                    # The whole row is going; its aliases go with it.
                    continue

                for alias in entity.aliases or []:
                    if not cve_shaped_name(alias):
                        continue
                    if links is None:
                        links = await _links(db, entity_type, entity.id)
                    alias_norm = normalize_entity_name(alias, entity_type).norm_exact
                    purgeable, protected = _attributable(links, entity_type, alias_norm)
                    cve = _cve_id(alias)
                    rows.append(
                        {
                            "action": "strip",
                            "kind": "alias",
                            "entity_type": entity_type,
                            "entity_name": entity.name,
                            "entity_id": str(entity.id),
                            "cve": cve,
                            "cve_row": str(cves[cve].id) if cve in cves else "",
                            "entries": len(links),
                            "links_moved": 0,
                            "links_already": 0,
                            "links_orphaned": 0,
                            "links_purged": len(purgeable),
                            "links_protected": protected,
                            "relationships": 0,
                        }
                    )

    rows.sort(key=lambda r: (r["kind"], -int(r["entries"])))
    out_path = _writable_out(out_path)
    with open(out_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    names = [r for r in rows if r["kind"] == "name"]
    aliases = [r for r in rows if r["kind"] == "alias"]
    by_type: dict[str, int] = defaultdict(int)
    for r in names:
        by_type[r["entity_type"]] += 1
    print(f"{len(names)} entities whose NAME is a CVE identifier")
    for t, n in sorted(by_type.items(), key=lambda kv: -kv[1]):
        print(f"  {t}: {n}")
    print(
        f"  {sum(int(r['links_moved']) for r in names)} entry links will move to the real CVE entity "
        f"({sum(int(r['links_already']) for r in names)} already on it — pure duplicates)"
    )
    orphans = [r for r in names if int(r["links_orphaned"])]
    if orphans:
        print(f"  {len(orphans)} have no CVE row to move their links to — defaulted to skip:")
        for r in orphans[:20]:
            print(f"    {r['entity_type']}:{r['entity_name']} ({r['links_orphaned']} links)")
    rel = sum(int(r["relationships"]) for r in names if r["action"] == "delete")
    if rel:
        print(f"  {rel} entity relationships will be deleted along with the rows")
    print(f"\n{len(aliases)} entities carrying a CVE identifier as an ALIAS")
    print(f"  {sum(int(r['links_purged']) for r in aliases)} entry links attributable to those aliases alone")
    print(f"  {sum(int(r['links_protected']) for r in rows)} analyst-sourced links, kept either way")

    print(f"\nwrote {out_path}")
    print("Review the `action` column (delete / strip / skip), then re-run with --apply --plan <csv>")


async def apply(plan_path: str) -> None:
    with open(plan_path, newline="") as fh:
        plan = list(csv.DictReader(fh))
    todo = [r for r in plan if (r.get("action") or "").strip().lower() in {"delete", "strip"}]
    print(f"{len(todo)} rows to act on ({len(plan) - len(todo)} skipped by the plan)")

    deleted = stripped = moved = purged = missing = 0
    touched: list[tuple[str, str]] = []

    async with async_session() as db:
        cves = await _cve_rows(db)

        for i, r in enumerate(todo, 1):
            entity_type = r["entity_type"]
            model, junction, fk = TYPES[entity_type]
            entity = await db.get(model, r["entity_id"])
            if entity is None:
                missing += 1
                continue

            if r["kind"] == "name":
                cve_row = cves.get(r["cve"].upper())
                links = await _links(db, entity_type, entity.id)
                row_moved = 0
                if cve_row is not None:
                    for j in links:
                        # Re-point the entry at the real CVE before the
                        # impostor goes, so the article keeps the reference.
                        exists = (
                            await db.execute(
                                select(EntryCVE.entry_id).where(
                                    EntryCVE.entry_id == j.entry_id,
                                    EntryCVE.cve_id == cve_row.id,
                                )
                            )
                        ).scalar_one_or_none()
                        if exists is None:
                            # entry_cves is a bare (entry_id, cve_id) join —
                            # no source or matched_names to carry across.
                            db.add(EntryCVE(entry_id=j.entry_id, cve_id=cve_row.id))
                            row_moved += 1
                moved += row_moved

                await db.execute(delete(junction).where(getattr(junction, fk) == entity.id))
                await db.execute(
                    delete(EntityRelationship).where(
                        or_(
                            (EntityRelationship.source_type == entity_type)
                            & (EntityRelationship.source_id == entity.id),
                            (EntityRelationship.target_type == entity_type)
                            & (EntityRelationship.target_id == entity.id),
                        )
                    )
                )
                await db.delete(entity)
                deleted += 1
                touched.append((entity_type, r["entity_id"]))
                print(
                    f"[{i}/{len(todo)}] deleted {entity_type}:{r['entity_name']} "
                    f"— moved {row_moved} links to {r['cve']}"
                )
                continue

            alias_norm = normalize_entity_name(r["cve"], entity_type).norm_exact
            remaining = [
                a for a in (entity.aliases or []) if normalize_entity_name(a, entity_type).norm_exact != alias_norm
            ]
            if len(remaining) == len(entity.aliases or []):
                missing += 1
                continue
            entity.aliases = remaining
            stripped += 1

            links = await _links(db, entity_type, entity.id)
            purgeable, _protected = _attributable(links, entity_type, alias_norm)
            for j in purgeable:
                await db.delete(j)
            purged += len(purgeable)
            if hasattr(entity, "article_count") and purgeable:
                entity.article_count = max((entity.article_count or 0) - len(purgeable), 0)
            touched.append((entity_type, r["entity_id"]))
            print(f"[{i}/{len(todo)}] {entity_type}:{entity.name} -[{r['cve']}]- purged {len(purgeable)} links")

        await db.commit()

    for entity_type, entity_id in touched:
        await invalidate_entity_cache(entity_type, entity_id)
    for r in todo:
        if r["kind"] == "name" and (r.get("action") or "").strip().lower() == "delete":
            delete_entity_document(r["entity_type"], r["entity_id"])

    print(f"\ndeleted {deleted} CVE-named entities, moved {moved} entry links onto the real CVE rows")
    print(f"stripped {stripped} CVE aliases, purged {purged} entry links, {missing} already gone")
    if deleted or stripped:
        print("Next: python scripts/maintenance/reconcile_search_index.py")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Propose the purge and write the review CSV (default).",
    )
    mode.add_argument("--apply", action="store_true", help="Execute a reviewed plan CSV.")
    ap.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help=f"CSV path for --dry-run (default {DEFAULT_OUT}).",
    )
    ap.add_argument("--plan", help="Reviewed CSV to execute with --apply.")
    args = ap.parse_args()

    if args.apply:
        if not args.plan:
            ap.error("--apply requires --plan <csv> (review the dry-run output first)")
        asyncio.run(apply(args.plan))
    else:
        asyncio.run(propose(args.out))


if __name__ == "__main__":
    main()
