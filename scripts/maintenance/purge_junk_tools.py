"""Clean the tool catalog: reclassify misfiled products/vendors, purge the rest.

Eleven weeks of unscoped AI extraction grew `tools` from a 104-row curated
ATT&CK seed to ~2,240 rows. Most of it is not tooling: dependency names from
NVD and distro advisories, API symbols, vulnerable packages, and vendor or
product names. See planning/tool-extraction-cleanup.md for the measurements.

The creation-side fixes (semantic gates, the evidence door, per-feed scoping)
ship separately — run them FIRST, or this just cleans a catalog that refills.

Three stages, each independently selectable:

  reclassify  Tool rows whose name is already claimed by a product or vendor —
              as that entity's canonical name OR as one of its aliases. The
              alias half matters: `Amazon Web Services` owns "AWS" as an alias
              while a separate tool row is *named* AWS, so the autolinker wrote
              both edges on the same article (492 of Azure's 496 tool links
              duplicated the product's; CloudTrail, FortiGate and Tomcat were
              100% duplicated). Name-only matching missed every one.
              GitHub, Chrome, CrowdStrike and friends hold 36% of all
              entry_tools links, and they are vendors/products, not tools.
              Replayed through app.api.entity_merge.perform_reclassify, which
              moves the entry links onto the survivor, repoints relationships,
              writes a reclassify tombstone so extraction can't resurrect the
              tool, and deletes the source. DUAL_USE below is exempt: software
              that is legitimately both (Metasploit, AnyDesk, WinRAR).

  purge       Tool rows with no evidence anyone ever wielded them: no ATT&CK
              mitre_id, and no relationship to a threat actor, malware or TTP.
              Deleted and added to the analyst do-not-recreate denylist so the
              pipeline can't mint them again. Rows created before SEED_CUTOFF
              are exempt — that is the curated seed, and a missing relationship
              there means nobody has written one yet, not that it's junk.

  orphans     Tool rows with zero entry links that the keep-list above did
              not already vouch for. Deleted, not denylisted: an unlinked row
              is usually a merge leftover, not a bad name. The keep-list runs
              FIRST — an ATT&CK entry with no articles is a catalog row nobody
              has written about yet, not junk.

Run inside the api container. --dry-run writes a review CSV and touches
nothing; scripts/ is read-only in prod, so point --out at /tmp there.

    # 1. propose
    docker compose -f docker-compose.prod.yml exec api \
        python scripts/maintenance/purge_junk_tools.py --dry-run --out /tmp/tools_plan.csv
    docker compose -f docker-compose.prod.yml exec -T api cat /tmp/tools_plan.csv > tools_plan.csv

    # 2. review the CSV — set action=skip on anything that should stay — then
    docker compose -f docker-compose.prod.yml exec -T api \
        python scripts/maintenance/purge_junk_tools.py --apply --plan /tmp/tools_plan.csv

    # 3. afterwards
    docker compose -f docker-compose.prod.yml exec api \
        python scripts/maintenance/reconcile_search_index.py

CSV columns — `action` is the only one meant to be edited:
    action        reclassify | purge | orphan | skip
    reason        why the row was proposed
    links         entry_tools rows this tool holds (what you lose on a purge)
    offensive     y when tool_type is an offensive slug. NVD labels anything
                  with a CVE "exploitation", so most are mislabelled advisory
                  software — but real tooling hides here. Review these first.
"""

import argparse
import asyncio
import csv
import sys

sys.path.insert(0, "/app")

from sqlalchemy import delete as sql_delete
from sqlalchemy import func, or_, select

from app.api.entity_merge import ReclassifyRequest, perform_reclassify
from app.database import async_session
from app.intelligence.correlation_cache import invalidate_entity_cache
from app.intelligence.entity_resolution import (
    deniable_names,
    deny_entity_names,
    normalize_entity_name,
)
from app.models.entity_relationship import EntityRelationship
from app.models.product import Product
from app.models.tool import EntryTool, Tool
from app.models.vendor import Vendor
from app.services.entity_indexer import delete_entity_document

# Rows older than this are the curated ATT&CK seed import. Exempt from purge.
SEED_CUTOFF = "2026-04-01"

# Names that collide with a product or vendor but are genuinely tools an
# operator wields. Lowercased compare. Everything else in that collision set
# is a vendor or a product wearing a tool row.
DUAL_USE = frozenset(
    {
        "metasploit",
        "anydesk",
        "autoit",
        "winrar",
        "wireguard",
        "openvpn",
        "fortigate",
        "forest druid",
        "ansible",
        "ngrok",
        "rclone",
        "tailscale",
        "netsupport manager",
    }
)

OFFENSIVE_TYPES = frozenset(
    {
        "c2_framework",
        "credential_access",
        "lateral_movement",
        "reconnaissance",
        "exploitation",
        "persistence",
        "defense_evasion",
        "lolbas",
        "phishing_kit",
        "tunneling",
        "remote_access",
        "framework",
    }
)

# Aliases this short are initialisms that collide by accident ("Net", "AD"),
# not a catalog claim worth reclassifying a tool over.
MIN_ALIAS_LEN = 3


def _index_by_name_and_alias(rows) -> dict[str, tuple]:
    """Map hardened normal form -> (id, canonical name, 'name' | 'alias').

    Keyed on ``norm_exact`` so it lines up with the DB's ``normalized_name``
    generated column rather than a naive ``.lower()``. Canonical names are
    indexed in a first pass and never overwritten by a second pass of aliases:
    owning a name outright is a stronger claim on the string than an alias
    another entity happens to hang off it.
    """
    by_norm: dict[str, tuple] = {}
    for eid, name, _aliases in rows:
        key = normalize_entity_name(name or "").norm_exact
        if key:
            by_norm[key] = (eid, name, "name")
    for eid, name, aliases in rows:
        for alias in aliases or []:
            if len(alias.strip()) < MIN_ALIAS_LEN:
                continue
            key = normalize_entity_name(alias).norm_exact
            if key and key not in by_norm:
                by_norm[key] = (eid, name, "alias")
    return by_norm


DEFAULT_OUT = "/app/scripts/out/purge_junk_tools.csv"

FIELDNAMES = [
    "action",
    "reason",
    "tool_name",
    "tool_type",
    "links",
    "article_count",
    "offensive",
    "first_seen",
    "created_via",
    "target_type",
    "target_name",
    "tool_id",
    "target_id",
]


async def build_plan(db) -> list[dict]:
    link_counts = dict((await db.execute(select(EntryTool.tool_id, func.count()).group_by(EntryTool.tool_id))).all())

    # Evidence = ATT&CK id, or a typed edge to an adversary/technique in either direction.
    evidenced: set = set()
    for row in (
        await db.execute(
            select(EntityRelationship.source_id).where(
                EntityRelationship.source_type == "tool",
                EntityRelationship.target_type.in_(("threat_actor", "malware", "ttp")),
            )
        )
    ).scalars():
        evidenced.add(row)
    for row in (
        await db.execute(
            select(EntityRelationship.target_id).where(
                EntityRelationship.target_type == "tool",
                EntityRelationship.source_type.in_(("threat_actor", "malware")),
            )
        )
    ).scalars():
        evidenced.add(row)

    products = _index_by_name_and_alias((await db.execute(select(Product.id, Product.name, Product.aliases))).all())
    vendors = _index_by_name_and_alias((await db.execute(select(Vendor.id, Vendor.name, Vendor.aliases))).all())

    tools = (await db.execute(select(Tool).order_by(Tool.name))).scalars().all()
    plan: list[dict] = []

    for t in tools:
        links = link_counts.get(t.id, 0)
        lowered = (t.name or "").strip().lower()
        norm = normalize_entity_name(t.name or "").norm_exact
        base = {
            "tool_name": t.name,
            "tool_type": t.tool_type or "",
            "links": links,
            "article_count": t.article_count,
            "offensive": "y" if (t.tool_type or "") in OFFENSIVE_TYPES else "",
            "first_seen": t.first_seen_at.date().isoformat() if t.first_seen_at else "",
            "created_via": t.created_via or "",
            "tool_id": str(t.id),
            "target_type": "",
            "target_name": "",
            "target_id": "",
        }

        # Stage 1 — misfiled as a tool when a product/vendor of that name exists.
        # The catalog states the same name two ways: `Amazon Web Services` owns
        # "AWS" as an alias while a tool row is *named* AWS. Matching canonical
        # names alone missed every one of those (492 of Azure's 496 entry links
        # duplicated the product's on the same article), so aliases count too.
        hit = products.get(norm) or vendors.get(norm)
        if lowered not in DUAL_USE and hit is not None:
            tgt_type = "product" if norm in products else "vendor"
            tgt_id, tgt_name, match_kind = hit
            plan.append(
                {
                    **base,
                    "action": "reclassify",
                    "reason": f"{tgt_type} {tgt_name!r} already claims this name as its {match_kind}",
                    "target_type": tgt_type,
                    "target_name": tgt_name,
                    "target_id": str(tgt_id),
                }
            )
            continue

        # Keep-list FIRST. Getting this after the orphan branch cost 50 real
        # tools on the 2026-09-20 prod run — ATT&CK catalog entries and seeded
        # offensive tooling (SILENTTRINITY, pwdump, PowerUpSQL, Infection
        # Monkey) have zero entry links precisely because nobody has written
        # an article about them yet. "No links" is not evidence of junk.
        if t.mitre_id or t.id in evidenced:
            continue
        if t.first_seen_at and t.first_seen_at.date().isoformat() < SEED_CUTOFF:
            continue

        # Stage 3 — no entry links, and nothing above vouched for it.
        if links == 0:
            plan.append({**base, "action": "orphan", "reason": "no entry links"})
            continue
        plan.append(
            {
                **base,
                "action": "purge",
                "reason": "no mitre_id and no actor/malware/ttp relationship",
            }
        )

    return plan


async def do_dry_run(out_path: str) -> None:
    async with async_session() as db:
        plan = await build_plan(db)

    with open(out_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        w.writeheader()
        for row in plan:
            w.writerow(row)

    counts: dict[str, int] = {}
    links: dict[str, int] = {}
    for r in plan:
        counts[r["action"]] = counts.get(r["action"], 0) + 1
        links[r["action"]] = links.get(r["action"], 0) + r["links"]
    print(f"Wrote {len(plan)} proposed rows to {out_path}")
    for action in ("reclassify", "purge", "orphan"):
        if counts.get(action):
            print(f"  {action:11s} {counts[action]:5d} rows, {links[action]:6d} entry links")
    offensive = sum(1 for r in plan if r["action"] == "purge" and r["offensive"])
    print(f"\n  {offensive} purge rows carry an offensive tool_type — review those before applying.")


async def do_apply(plan_path: str, batch: int) -> None:
    with open(plan_path, newline="") as fh:
        rows = [r for r in csv.DictReader(fh) if r.get("action") in ("reclassify", "purge", "orphan")]

    print(f"Applying {len(rows)} rows from {plan_path}")
    done = {"reclassify": 0, "purge": 0, "orphan": 0, "failed": 0}

    for i, row in enumerate(rows, 1):
        action = row["action"]
        async with async_session() as db:
            try:
                if action == "reclassify":
                    await perform_reclassify(
                        db,
                        ReclassifyRequest(
                            source_type="tool",
                            source_id=row["tool_id"],
                            target_type=row["target_type"],
                            target_id=row["target_id"] or None,
                            mode="apply",
                            reasoning="tool-catalog cleanup 2026-09: name is a product/vendor, not a wielded tool",
                        ),
                    )
                else:
                    await _delete_tool(db, row["tool_id"], deny=(action == "purge"))
                await db.commit()
                done[action] += 1
            except Exception as exc:  # noqa: BLE001 — one bad row must not stop the run
                await db.rollback()
                done["failed"] += 1
                print(f"  !! {row['tool_name']}: {type(exc).__name__}: {exc}")

        if batch and i % batch == 0:
            print(f"  … {i}/{len(rows)}")
            await asyncio.sleep(2)

    print(
        f"Done: {done['reclassify']} reclassified, {done['purge']} purged, "
        f"{done['orphan']} orphans removed, {done['failed']} failed"
    )
    print("Now run: python scripts/maintenance/reconcile_search_index.py")


async def _delete_tool(db, tool_id: str, *, deny: bool) -> None:
    """Delete one tool the way the Engine table does, optionally denylisting it."""
    tool = (await db.execute(select(Tool).where(Tool.id == tool_id))).scalar_one_or_none()
    if tool is None:
        return
    if deny:
        await deny_entity_names(
            db,
            "tool",
            deniable_names("tool", tool),
            reason="tool-catalog cleanup 2026-09: no evidence of adversary use",
        )
    await db.execute(sql_delete(EntryTool).where(EntryTool.tool_id == tool.id))
    await db.execute(
        sql_delete(EntityRelationship).where(
            or_(
                (EntityRelationship.source_type == "tool") & (EntityRelationship.source_id == tool.id),
                (EntityRelationship.target_type == "tool") & (EntityRelationship.target_id == tool.id),
            )
        )
    )
    await db.delete(tool)
    await db.flush()
    delete_entity_document("tool", tool.id)
    await invalidate_entity_cache("tool", str(tool.id))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Propose actions and write the review CSV.",
    )
    mode.add_argument("--apply", action="store_true", help="Execute a reviewed plan CSV.")
    ap.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help=f"CSV path for --dry-run (default {DEFAULT_OUT}).",
    )
    ap.add_argument("--plan", help="Reviewed CSV to execute with --apply.")
    ap.add_argument(
        "--batch",
        type=int,
        default=50,
        help="Pause 2s every N rows during --apply (0 = never).",
    )
    args = ap.parse_args()

    if args.apply and not args.plan:
        ap.error("--apply requires --plan")
    if args.dry_run:
        asyncio.run(do_dry_run(args.out))
    else:
        asyncio.run(do_apply(args.plan, args.batch))


if __name__ == "__main__":
    main()
