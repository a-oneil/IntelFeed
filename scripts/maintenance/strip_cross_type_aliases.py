"""Strip aliases that borrow another entity type's name.

The sibling problem to fold_cross_type_twins.py, with the opposite fix. There,
two entities were one thing wearing two types. Here the two entities are
genuinely different and must stay separate — the bug is that one of them
carries the other's name as an alias:

    threat_actor  Agrius    aliases {AMERICIUM, Agonizing Serpens, ...}
    malware       DEADWOOD  aliases {Agrius, SQLShred, DETBOSIT}

Agrius is the group, DEADWOOD is its wiper. Folding them would be wrong. But
the alias makes the autolinker match "Agrius" in an article and link it to
both, which puts the pair back in Hot Correlations correlating with itself.
That relationship belongs in entity_relationships, not in an alias list.

Stripping the alias only stops future mislinks, so this also purges the entry
links that alias actually created — junction rows whose matched_names are
nothing but the stripped form. Analyst-sourced links are never touched, and a
row with no matched_names is left alone because it can't be attributed.

Detection is alias-vs-primary-name only: an alias on one entity that equals the
*canonical name* of an entity of another type. Alias-vs-alias collisions are
reported by --report-ambiguous but never auto-stripped — with neither side
canonical there is no rule for which one is wrong.

Run inside the api container (scripts/ is read-only in prod, so the CSV goes
to /tmp there — the path is printed):

    docker compose -f docker-compose.prod.yml exec -T api \
        python scripts/maintenance/strip_cross_type_aliases.py --dry-run

    docker compose -f docker-compose.prod.yml exec -T api \
        python scripts/maintenance/strip_cross_type_aliases.py \
        --apply --plan /tmp/cross_type_aliases.csv

CSV columns: action is the only one meant to be edited.
    action          strip (default) | skip. Rows hinted fold_candidate default
                    to skip — they belong in fold_cross_type_twins.py instead.
    hint            contaminating (borrowed name) | fold_candidate (same brand,
                    descriptor apart — "Interlock Ransomware" vs "Interlock") |
                    ambiguous (neither side canonical; only with
                    --include-ambiguous, always defaulted to skip)
    owner_entries   how well-covered the owner is. A thin owner means the alias
                    is probably right and the owner is the junk entity.
    holder_*        the entity losing the alias
    owner_*         the entity whose canonical name the alias duplicates
    links_*         entry links attributable to this alias alone, and how many
                    of those are analyst-sourced (those are never purged)
"""

import argparse
import asyncio
import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, "/app")

from sqlalchemy import select

from app.database import async_session
from app.intelligence.correlation_cache import invalidate_entity_cache
from app.intelligence.entity_resolution import normalize_entity_name
from app.models.entity_index import EntityAliasIndex
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool

TYPES: dict[str, tuple] = {
    "threat_actor": (ThreatActor, EntryThreatActor, "threat_actor_id"),
    "malware": (MalwareFamily, EntryMalware, "malware_family_id"),
    "tool": (Tool, EntryTool, "tool_id"),
}

DEFAULT_OUT = "/app/scripts/out/cross_type_aliases.csv"

# Links an analyst made or confirmed are evidence, not autolinker noise.
PROTECTED_SOURCES = {"manual", "analyst", "analyst_created", "analyst_confirmed"}

FIELDNAMES = [
    "action",
    "alias",
    "holder_type",
    "holder_name",
    "holder_id",
    "owner_type",
    "owner_name",
    "owner_id",
    "owner_entries",
    "hint",
    "links_attributable",
    "links_protected",
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


async def _entry_links(db, entity_type: str, entity_id) -> int:
    _model, junction, fk = TYPES[entity_type]
    rows = (await db.execute(select(junction).where(getattr(junction, fk) == entity_id))).scalars().all()
    return len(rows)


def _hint(holder_type: str, holder_name: str, owner_type: str, owner_name: str) -> str:
    """Why this pair collides — the reviewer's first question.

    fold_candidate: the two canonical names are the same brand once descriptors
    are stripped ("Interlock Ransomware" the actor vs "Interlock" the malware).
    That is a cross-type twin the fold script missed because it matches on
    norm_exact; it wants reclassify, not an alias strip.

    contaminating: the names are genuinely different things and one has simply
    borrowed the other's name ("DEADWOOD" carrying "Agrius").
    """
    h = normalize_entity_name(holder_name, holder_type)
    o = normalize_entity_name(owner_name, owner_type)
    forms_h = {h.norm_exact, h.norm_stripped, h.norm_codename_stripped or ""}
    forms_o = {o.norm_exact, o.norm_stripped, o.norm_codename_stripped or ""}
    if (forms_h & forms_o) - {""}:
        return "fold_candidate"
    return "contaminating"


async def _index_rows(db):
    rows = (await db.execute(select(EntityAliasIndex).where(EntityAliasIndex.entity_type.in_(TYPES)))).scalars().all()
    names: dict[str, list] = defaultdict(list)
    aliases: dict[str, list] = defaultdict(list)
    for r in rows:
        (names if r.is_name else aliases)[r.normalized].append(r)
    return names, aliases


async def _attributable_links(db, holder_type: str, holder_id, alias_norm: str) -> tuple[int, int]:
    """Entry links this alias alone produced: (purgeable, analyst-protected).

    A junction row counts only when every surface form it recorded normalizes
    to this alias — a row that also matched the entity's real name would have
    existed anyway, so removing it would destroy a good link.
    """
    _model, junction, fk = TYPES[holder_type]
    rows = (await db.execute(select(junction).where(getattr(junction, fk) == holder_id))).scalars().all()
    purgeable = protected = 0
    for j in rows:
        matched = list(getattr(j, "matched_names", None) or [])
        if not matched:
            continue
        if not all(normalize_entity_name(m, holder_type).norm_exact == alias_norm for m in matched):
            continue
        if (getattr(j, "source", None) or "") in PROTECTED_SOURCES:
            protected += 1
        else:
            purgeable += 1
    return purgeable, protected


async def _ambiguous_row(db, alias_row, peer_row, norm: str) -> dict:
    """One holder of a collision nobody owns canonically.

    Emitted as ``skip`` with hint ``ambiguous``: the analyst flips the wrong
    holder to ``strip``. Both holders appear as their own row, so the decision
    is "which of these two should lose it", not a yes/no on a pair.
    """
    holder = await db.get(TYPES[alias_row.entity_type][0], alias_row.entity_id)
    peer = await db.get(TYPES[peer_row.entity_type][0], peer_row.entity_id)
    purgeable, protected = await _attributable_links(db, alias_row.entity_type, alias_row.entity_id, norm)
    return {
        "action": "skip",
        "alias": alias_row.surface,
        "holder_type": alias_row.entity_type,
        "holder_name": holder.name if holder else "?",
        "holder_id": str(alias_row.entity_id),
        "owner_type": peer_row.entity_type,
        "owner_name": peer.name if peer else "?",
        "owner_id": str(peer_row.entity_id),
        "owner_entries": await _entry_links(db, peer_row.entity_type, peer_row.entity_id),
        "hint": "ambiguous",
        "links_attributable": purgeable,
        "links_protected": protected,
    }


async def propose(out_path: str, report_ambiguous: bool, include_ambiguous: bool = False) -> None:
    rows: list[dict] = []
    ambiguous: list[str] = []
    async with async_session() as db:
        names, aliases = await _index_rows(db)

        for norm, alias_rows in sorted(aliases.items()):
            owners = [n for n in names.get(norm, [])]
            for a in alias_rows:
                cross_owners = [o for o in owners if o.entity_type != a.entity_type]
                if not cross_owners:
                    # No canonical owner of another type. If some *other* type
                    # also carries it as an alias, that is the ambiguous class:
                    # neither side is canonical, so there is no rule for which
                    # holder is wrong — but an analyst can still decide, so
                    # --include-ambiguous emits both holders as skip rows.
                    peers = [x for x in alias_rows if x.entity_type != a.entity_type]
                    if peers:
                        ambiguous.append(norm)
                        if include_ambiguous:
                            rows.append(await _ambiguous_row(db, a, peers[0], norm))
                    continue
                if len(cross_owners) > 1:
                    # Two different types both claim it canonically — no rule.
                    ambiguous.append(norm)
                    if include_ambiguous:
                        rows.append(await _ambiguous_row(db, a, cross_owners[0], norm))
                    continue
                owner = cross_owners[0]
                holder = await db.get(TYPES[a.entity_type][0], a.entity_id)
                owner_entity = await db.get(TYPES[owner.entity_type][0], owner.entity_id)
                if holder is None or owner_entity is None:
                    continue
                purgeable, protected = await _attributable_links(db, a.entity_type, a.entity_id, norm)
                hint = _hint(a.entity_type, holder.name, owner.entity_type, owner_entity.name)
                rows.append(
                    {
                        "alias": a.surface,
                        "holder_type": a.entity_type,
                        "holder_name": holder.name,
                        "holder_id": str(a.entity_id),
                        "owner_type": owner.entity_type,
                        "owner_name": owner_entity.name,
                        "owner_id": str(owner.entity_id),
                        "owner_entries": await _entry_links(db, owner.entity_type, owner.entity_id),
                        "hint": hint,
                        # A fold_candidate is not ours to strip — default it to
                        # skip so a careless apply can't silently delete the
                        # short form of a brand the two entities share.
                        "action": "skip" if hint == "fold_candidate" else "strip",
                        "links_attributable": purgeable,
                        "links_protected": protected,
                    }
                )

    rows.sort(key=lambda r: -int(r["links_attributable"]))
    out_path = _writable_out(out_path)
    with open(out_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    folds = [r for r in rows if r["hint"] == "fold_candidate"]
    total_links = sum(int(r["links_attributable"]) for r in rows if r["action"] == "strip")
    protected = sum(int(r["links_protected"]) for r in rows)
    print(f"{len(rows)} contaminating aliases (alias duplicates another type's canonical name)")
    by_dir: dict[str, int] = defaultdict(int)
    for r in rows:
        by_dir[f"{r['holder_type']} carrying a {r['owner_type']} name"] += 1
    for d, n in sorted(by_dir.items(), key=lambda kv: -kv[1]):
        print(f"  {d}: {n}")
    print(f"{len(folds)} look like cross-type twins the fold script missed — defaulted to skip, not stripped")
    print(f"{total_links} entry links attributable to the strip rows alone ({protected} analyst-sourced, kept)")
    print(
        "Check `owner_entries` before accepting a row: when the owner is a thin junk entity "
        "(a browser named Chromium vs the actor alias CHROMIUM), the alias is right and the owner "
        "is what should go."
    )
    if report_ambiguous:
        uniq = sorted(set(ambiguous))
        print(f"\n{len(uniq)} ambiguous collisions (no canonical owner) — review by hand, not stripped:")
        for n in uniq[:40]:
            print(f"  {n}")
    print(f"\nwrote {out_path}")
    print("Review the `action` column (strip / skip), then re-run with --apply --plan <csv>")


async def apply(plan_path: str) -> None:
    with open(plan_path, newline="") as fh:
        plan = list(csv.DictReader(fh))
    todo = [r for r in plan if (r.get("action") or "").strip().lower() == "strip"]
    print(f"{len(todo)} aliases to strip ({len(plan) - len(todo)} skipped by the plan)")

    stripped = purged = missing = 0
    async with async_session() as db:
        for i, r in enumerate(todo, 1):
            holder_type = r["holder_type"]
            model, junction, fk = TYPES[holder_type]
            holder = await db.get(model, r["holder_id"])
            if holder is None:
                missing += 1
                continue

            alias_norm = normalize_entity_name(r["alias"], holder_type).norm_exact
            remaining = [
                a for a in (holder.aliases or []) if normalize_entity_name(a, holder_type).norm_exact != alias_norm
            ]
            if len(remaining) == len(holder.aliases or []):
                missing += 1
                continue
            holder.aliases = remaining
            stripped += 1

            # Purge the links this alias alone created. The alias is gone, so a
            # left-behind link has nothing left to justify it.
            rows = (await db.execute(select(junction).where(getattr(junction, fk) == r["holder_id"]))).scalars().all()
            row_purged = 0
            for j in rows:
                matched = list(getattr(j, "matched_names", None) or [])
                if not matched:
                    continue
                if not all(normalize_entity_name(m, holder_type).norm_exact == alias_norm for m in matched):
                    continue
                if (getattr(j, "source", None) or "") in PROTECTED_SOURCES:
                    continue
                await db.delete(j)
                row_purged += 1
            purged += row_purged
            if hasattr(holder, "article_count") and row_purged:
                holder.article_count = max((holder.article_count or 0) - row_purged, 0)

            print(f"[{i}/{len(todo)}] {holder_type}:{holder.name} -[{r['alias']}]- purged {row_purged} links")

        await db.commit()

    for r in todo:
        await invalidate_entity_cache(r["holder_type"], r["holder_id"])

    print(f"\nstripped {stripped} aliases, purged {purged} entry links, {missing} already gone")
    if stripped:
        print("Next: python scripts/maintenance/reconcile_search_index.py")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Propose strips and write the review CSV (default).")
    mode.add_argument("--apply", action="store_true", help="Execute a reviewed plan CSV.")
    ap.add_argument("--out", default=DEFAULT_OUT, help=f"CSV path for --dry-run (default {DEFAULT_OUT}).")
    ap.add_argument("--plan", help="Reviewed CSV to execute with --apply.")
    ap.add_argument(
        "--report-ambiguous",
        action="store_true",
        help="Also list collisions with no canonical owner (alias vs alias) — reported, never stripped.",
    )
    ap.add_argument(
        "--include-ambiguous",
        action="store_true",
        help="Emit alias-vs-alias collisions into the CSV as skip rows so an analyst can decide them.",
    )
    args = ap.parse_args()

    if args.apply:
        if not args.plan:
            ap.error("--apply requires --plan <csv> (review the dry-run output first)")
        asyncio.run(apply(args.plan))
    else:
        asyncio.run(propose(args.out, args.report_ambiguous or args.include_ambiguous, args.include_ambiguous))


if __name__ == "__main__":
    main()
