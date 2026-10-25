"""Move platforms and products out of the tool catalog, and delete concept rows.

The autolinker tags every catalog name it finds, so a tool row that is really
a platform ("Linux", "Chrome", "Kubernetes") or a concept ("SHA-256", "SQL
injection", "Payload") lands on every article that uses the word. On NVD,
AusCERT and Red Hat alone that was 34,598 tool links from autolink against
163 from the AI (feed audit, item 5).

Driven by two explicit lists below, each extendable from the command line
(scripts/ is read-only in prod):

  RECLASSIFY  Tool rows that are a product or a vendor. Replayed through
              app.api.entity_merge.perform_reclassify — the same path as the
              Engine's reclassify — which merges into the existing product or
              vendor of that name (or alias) when there is one, otherwise
              creates it; moves the entry links, repoints relationships, writes
              a reclassify tombstone so AI extraction links the survivor
              instead of re-minting the tool, and deletes the tool row.

  DELETE      Concept rows. Their names and aliases go onto the analyst
              do-not-recreate list (deny_entity_names, as the Engine's delete
              with "don't re-create" ticked), then the row and its links are
              deleted. TOOL_CONCEPT_NAMES — the resolver's own concept guard —
              is always part of this list.

Only rows whose tool *name* matches a list entry (normalized: case,
punctuation, spacing) are touched; a list entry with no row is reported and
skipped. The report ends with the top tool rows by link count so the operator
can see what else should be on either list.

Dry run is the default and writes nothing. Run inside the api container:

    # 1. preview
    docker compose -f docker-compose.prod.yml exec api \\
        python scripts/maintenance/clean_tool_catalog.py

    # 2. extend the lists if the report shows more (repeatable flags), preview again
    docker compose -f docker-compose.prod.yml exec api \\
        python scripts/maintenance/clean_tool_catalog.py \\
        --reclassify "Ubuntu=product" --reclassify "Red Hat=vendor" --delete "Encryption"

    # 3. apply (same flags)
    docker compose -f docker-compose.prod.yml exec api \\
        python scripts/maintenance/clean_tool_catalog.py --apply

    # 4. afterwards
    docker compose -f docker-compose.prod.yml exec api \\
        python scripts/maintenance/reconcile_search_index.py
"""

import argparse
import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, "/app")
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sqlalchemy import func, select

from app.api.entity_merge import ReclassifyRequest, _get_type_spec, perform_reclassify
from app.intelligence.entity_resolution import (
    TOOL_CONCEPT_NAMES,
    deniable_names,
    deny_entity_names,
)
from app.intelligence.entity_resolution import normalize_entity_name as _normalize
from app.models.entity_index import EntityAliasIndex
from app.models.tool import EntryTool, Tool

# tool name -> (target type, preferred target name or None for the tool's own).
# Canonical spellings come before their variants, so a variant run later in
# the same --apply merges into the product the canonical one just created.
RECLASSIFY: dict[str, tuple[str, str | None]] = {
    "Linux": ("product", None),
    "Linux Kernel": ("product", None),
    "SUSE Linux Enterprise": ("product", None),
    "Google Chrome": ("product", None),
    "Chrome": ("product", "Google Chrome"),
    "Java": ("product", None),
    "Kubernetes": ("product", None),
    "Microsoft Azure": ("product", None),
    "Azure": ("product", "Microsoft Azure"),
    "Node.js": ("product", None),
    "KVM": ("product", None),
    "NVIDIA": ("vendor", None),
    "Cursor": ("product", None),
    "Python": ("product", None),
    "python3": ("product", "Python"),
}

DELETE: tuple[str, ...] = tuple(TOOL_CONCEPT_NAMES) + (
    "SHA256",
    "Payload",
    "spi",
    "WebSocket",
)

DENY_REASON = "tool-catalog cleanup: a concept, not software anyone wields"
RECLASSIFY_REASON = "tool-catalog cleanup: a platform or product, not a wielded tool"


def norm(name: str) -> str:
    return _normalize(name or "", "tool").norm_exact


@dataclass
class Plan:
    reclassify: list[dict] = field(default_factory=list)
    delete: list[dict] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    missing_deletes: int = 0
    ambiguous: list[str] = field(default_factory=list)
    top: list[dict] = field(default_factory=list)


async def _link_count(db, entity_type: str, entity_id) -> int:
    spec = _get_type_spec(entity_type)
    fk = getattr(spec["junction_model"], spec["junction_fk"])
    return (await db.execute(select(func.count()).where(fk == entity_id))).scalar_one()


async def _find_target(db, target_type: str, names: list[str]):
    """The existing product/vendor owning one of ``names`` (canonical name
    first, then alias). Returns (entity_id, display name), None, or "ambiguous"."""
    spec = _get_type_spec(target_type)
    model = spec["model"]
    for candidate in names:
        key = _normalize(candidate, target_type).norm_exact
        if not key:
            continue
        rows = (
            await db.execute(
                select(EntityAliasIndex.entity_id, EntityAliasIndex.is_name).where(
                    EntityAliasIndex.entity_type == target_type,
                    EntityAliasIndex.normalized == key,
                )
            )
        ).all()
        ids = {r.entity_id for r in rows if r.is_name} or {r.entity_id for r in rows}
        if len(ids) > 1:
            return "ambiguous"
        if ids:
            eid = ids.pop()
            name = (await db.execute(select(model.name).where(model.id == eid))).scalar_one()
            return eid, name
    return None


async def build_plan(
    db,
    reclassify: dict[str, tuple[str, str | None]],
    delete: tuple[str, ...],
    top_n: int,
) -> Plan:
    plan = Plan()
    link_counts = dict((await db.execute(select(EntryTool.tool_id, func.count()).group_by(EntryTool.tool_id))).all())
    tools = (await db.execute(select(Tool))).scalars().all()
    by_norm: dict[str, list[Tool]] = {}
    for t in tools:
        by_norm.setdefault(norm(t.name), []).append(t)

    planned: dict = {}
    new_targets: set[tuple[str, str]] = set()
    for name, (target_type, target_name) in reclassify.items():
        rows = by_norm.get(norm(name), [])
        if not rows:
            plan.missing.append(name)
        for tool in rows:
            if tool.id in planned:
                continue
            target = await _find_target(db, target_type, [n for n in (target_name, tool.name) if n])
            if target == "ambiguous":
                plan.ambiguous.append(f"{tool.name} -> {target_type}")
                continue
            row = {
                "tool_id": tool.id,
                "tool_name": tool.name,
                "links": link_counts.get(tool.id, 0),
                "target_type": target_type,
                "target_id": target[0] if target else None,
                "target_name": target[1] if target else (target_name or tool.name),
                "target_links": await _link_count(db, target_type, target[0]) if target else 0,
                "merges_new": False,
            }
            if not target:
                key = (target_type, norm(row["target_name"]))
                row["merges_new"] = key in new_targets
                new_targets.add(key)
            plan.reclassify.append(row)
            planned[tool.id] = "reclassify"

    seen_deletes: set[str] = set()
    for name in delete:
        key = norm(name)
        if not key or key in seen_deletes:
            continue
        seen_deletes.add(key)
        rows = by_norm.get(key, [])
        if not rows:
            plan.missing_deletes += 1
        for tool in rows:
            if tool.id in planned:
                continue
            plan.delete.append(
                {
                    "tool_id": tool.id,
                    "tool_name": tool.name,
                    "links": link_counts.get(tool.id, 0),
                    "deny": deniable_names("tool", tool),
                }
            )
            planned[tool.id] = "delete"

    ranked = sorted(tools, key=lambda t: link_counts.get(t.id, 0), reverse=True)[:top_n]
    plan.top = [
        {
            "tool_name": t.name,
            "links": link_counts.get(t.id, 0),
            "tool_type": t.tool_type or "",
            "mitre_id": t.mitre_id or "",
            "created_via": t.created_via or "",
            "planned": planned.get(t.id, ""),
        }
        for t in ranked
    ]
    return plan


def print_plan(plan: Plan, *, applying: bool) -> None:
    verb = "Applying" if applying else "Dry run — would apply"
    print(f"{verb}: {len(plan.reclassify)} reclassify, {len(plan.delete)} delete\n")

    if plan.reclassify:
        print("RECLASSIFY (tool -> product/vendor; entry links move to the target)")
        for r in plan.reclassify:
            target = (
                f"existing {r['target_type']} {r['target_name']!r} ({r['target_links']} links)"
                if r["target_id"]
                else f"{r['target_type']} {r['target_name']!r} created by the row above"
                if r["merges_new"]
                else f"new {r['target_type']} {r['target_name']!r}"
            )
            print(f"  {r['tool_name']!r:34s} {r['links']:7d} links  ->  {target}")
        total = sum(r["links"] for r in plan.reclassify)
        print(f"  {'':34s} {total:7d} tool links moved off the tool type\n")

    if plan.delete:
        print("DELETE (row and its links removed; names go on the do-not-recreate list)")
        for r in plan.delete:
            print(f"  {r['tool_name']!r:34s} {r['links']:7d} links  deny: {', '.join(r['deny'])}")
        total = sum(r["links"] for r in plan.delete)
        print(f"  {'':34s} {total:7d} tool links removed\n")

    if plan.ambiguous:
        print("SKIPPED — several products/vendors own the name; reclassify by hand in the Engine:")
        for a in plan.ambiguous:
            print(f"  {a}")
        print()
    if plan.missing:
        print(f"No tool row for {len(plan.missing)} reclassify entries: {', '.join(sorted(set(plan.missing)))}")
    if plan.missing_deletes:
        print(f"No tool row for {plan.missing_deletes} concept names (the creation guard keeps them out)")
    if plan.missing or plan.missing_deletes:
        print()

    if plan.top:
        print(f"Top {len(plan.top)} tool rows by entry links (extend the lists with --reclassify / --delete):")
        print(f"  {'links':>7s}  {'planned':10s} {'tool_type':18s} {'mitre':8s} {'created_via':16s} name")
        for t in plan.top:
            print(
                f"  {t['links']:7d}  {t['planned'] or '-':10s} {t['tool_type'][:18]:18s} "
                f"{t['mitre_id'][:8]:8s} {t['created_via'][:16]:16s} {t['tool_name']}"
            )


async def apply_plan(plan: Plan) -> dict[str, int]:
    from app.database import async_session
    from purge_junk_tools import _delete_tool  # same delete the Engine table runs

    done = {"reclassify": 0, "delete": 0, "failed": 0}
    for r in plan.reclassify:
        async with async_session() as db:
            try:
                tool = await db.get(Tool, r["tool_id"])
                if tool is None:
                    continue
                target_id = r["target_id"]
                if target_id is None:
                    # An earlier row in this run may have created the target
                    # ("Chrome" and "Google Chrome" both land on one product).
                    found = await _find_target(db, r["target_type"], [r["target_name"], tool.name])
                    if isinstance(found, tuple):
                        target_id = found[0]
                if target_id is None and r["target_name"] != tool.name:
                    # Create the product under its readable name ("python3" ->
                    # "Python") with the tool's spelling kept as an alias.
                    clash = (
                        await db.execute(select(Tool.id).where(Tool.name == r["target_name"]))
                    ).scalar_one_or_none()
                    if clash is None:
                        tool.aliases = [*(tool.aliases or []), tool.name]
                        tool.name = r["target_name"]
                        await db.flush()
                await perform_reclassify(
                    db,
                    ReclassifyRequest(
                        source_type="tool",
                        source_id=r["tool_id"],
                        target_type=r["target_type"],
                        target_id=target_id,
                        mode="apply",
                        reasoning=RECLASSIFY_REASON,
                    ),
                )
                await db.commit()
                done["reclassify"] += 1
            except Exception as exc:  # noqa: BLE001 — one bad row must not stop the run
                await db.rollback()
                done["failed"] += 1
                print(f"  !! reclassify {r['tool_name']}: {type(exc).__name__}: {exc}")

    for r in plan.delete:
        async with async_session() as db:
            try:
                await deny_entity_names(db, "tool", r["deny"], reason=DENY_REASON)
                await _delete_tool(db, r["tool_id"], deny=False)
                await db.commit()
                done["delete"] += 1
            except Exception as exc:  # noqa: BLE001
                await db.rollback()
                done["failed"] += 1
                print(f"  !! delete {r['tool_name']}: {type(exc).__name__}: {exc}")

    # The vocabulary is built from live entities — rebuild so the autolinker
    # stops matching the moved and deleted rows now, not at the next sync.
    if done["reclassify"] or done["delete"]:
        from app.intelligence.autolinker import refresh_vocabulary

        async with async_session() as db:
            await refresh_vocabulary(db)
    return done


def _parse_reclassify(values: list[str]) -> dict[str, tuple[str, str | None]]:
    out: dict[str, tuple[str, str | None]] = {}
    for raw in values:
        name, _, target = raw.partition("=")
        target_type, _, target_name = target.partition(":")
        if not name.strip() or target_type.strip() not in ("product", "vendor"):
            raise SystemExit(
                f"--reclassify expects 'Tool Name=product' or 'Tool Name=vendor[:Target Name]', got {raw!r}"
            )
        out[name.strip()] = (target_type.strip(), target_name.strip() or None)
    return out


async def main_async(args) -> None:
    from app.database import async_session

    reclassify = {**RECLASSIFY, **_parse_reclassify(args.reclassify)}
    delete = DELETE + tuple(n.strip() for n in args.delete if n.strip())
    async with async_session() as db:
        plan = await build_plan(db, reclassify, delete, args.top)
    print_plan(plan, applying=args.apply)
    if not args.apply:
        print("\nNothing written. Re-run with --apply to make these changes.")
        return
    done = await apply_plan(plan)
    print(f"\nDone: {done['reclassify']} reclassified, {done['delete']} deleted, {done['failed']} failed")
    print("Now run: python scripts/maintenance/reconcile_search_index.py")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Make the changes. Without it this is a dry run.",
    )
    ap.add_argument(
        "--reclassify",
        action="append",
        default=[],
        metavar="NAME=TYPE[:TARGET]",
        help="Add a tool to reclassify, e.g. 'Ubuntu=product' or 'Chromium=product:Google Chrome'. Repeatable.",
    )
    ap.add_argument(
        "--delete",
        action="append",
        default=[],
        metavar="NAME",
        help="Add a concept to delete. Repeatable.",
    )
    ap.add_argument(
        "--top",
        type=int,
        default=60,
        help="How many top tool rows by links to list (default 60).",
    )
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()
