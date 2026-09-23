"""Fold same-name entities that exist under two types into one survivor.

A ransomware brand is one name doing two jobs: "Qilin" the gang (threat_actor,
minted by the leak-site sync) and "Qilin" the payload (malware, minted by AI
extraction reading "Qilin ransomware encrypted..."). Nothing reconciles the two,
so the autolinker links every article to both and the pair shows up forever in
Hot Correlations, correlating with itself.

This finds those collisions across the actor/malware/tool trio, picks a default
survivor, and writes a review CSV. Nothing is written to the database in this
mode. An analyst edits the CSV, then --apply replays it through the normal
reclassify path (app.api.entity_merge.perform_reclassify), which moves entry
links onto the survivor, unions aliases, repoints relationships, deletes the
loser, drops its search document, and writes a reclassify tombstone so AI
extraction and the feed syncs can't resurrect it.

Default survivor = more entry links, ties broken by earlier first_seen_at. That
rule is right for gang-named ransomware brands (Qilin actor 1141 links vs
malware 285) and wrong for things that were never a gang (Shai-Hulud is an npm
worm, QakBot is malware) — which is exactly why the CSV exists.

Type-specific fields do NOT survive a reclassify: malware_type, tool_type,
motivation, origin country and so on are dropped when their entity is the loser.
Common fields (name, aliases, description, article_count, first/last_seen_at)
carry across. Fix specifics afterwards on the survivor's profile.

Run inside the api container:

    # 1. propose (no DB writes). scripts/ is mounted read-only in prod, so the
    #    CSV lands in /tmp there; `docker compose exec -T api cat <path>` pulls it.
    docker compose -f docker-compose.prod.yml exec api \
        python scripts/maintenance/fold_cross_type_twins.py --dry-run

    # 2. review the CSV, set action=skip / flip per row, then
    docker compose -f docker-compose.prod.yml exec api \
        python scripts/maintenance/fold_cross_type_twins.py \
        --apply --plan scripts/out/cross_type_twins.csv --batch 25

    # 3. recover mentions that earlier enforced holds dropped (preview, then write)
    docker compose -f docker-compose.prod.yml exec api \
        python scripts/maintenance/fold_cross_type_twins.py --replay-holds [--apply]

    # 4. afterwards
    docker compose -f docker-compose.prod.yml exec api \
        python scripts/maintenance/reconcile_search_index.py

CSV columns: action is the only one meant to be edited.
    action          fold (default) | skip | flip (reverse survivor and loser)
    match_kind      name (both primary names collide; the only tier that
                    defaults to fold) | stripped (same brand a descriptor word
                    apart — "Interlock Ransomware" vs "Interlock"; real often
                    enough to surface, wrong often enough to confirm) | alias
                    (one side matched only through an alias)
    survivor_rename optional: rename the survivor to this after the fold, so a
                    lowercase stub ("royal") inherits the readable spelling
                    ("Royal"). Prefilled only for case-only differences; clear
                    it to keep the survivor's own name. Ignored on flip rows.
"""

import argparse
import asyncio
import csv
import os
import sys
from collections import defaultdict
from dataclasses import dataclass

sys.path.insert(0, "/app")

from sqlalchemy import func, select

from app.api.entity_merge import ReclassifyRequest, perform_reclassify
from app.database import async_session
from app.intelligence.correlation_cache import invalidate_entity_cache
from app.intelligence.entity_dedup import link_entry_to_entity
from app.intelligence.entity_resolution import (
    _TYPE_DESCRIPTORS,
    _fold,
    _strip_phrases,
    _tokens,
    normalize_entity_name,
)
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool

# The trio that shares a namespace in the wild. vendor/product are excluded on
# purpose: "Apache" the vendor and "Apache" the product are legitimately two
# entities, not a duplicate.
TYPES: dict[str, tuple] = {
    "threat_actor": (ThreatActor, EntryThreatActor, EntryThreatActor.threat_actor_id),
    "malware": (MalwareFamily, EntryMalware, EntryMalware.malware_family_id),
    "tool": (Tool, EntryTool, EntryTool.tool_id),
}

DEFAULT_OUT = "/app/scripts/out/cross_type_twins.csv"

FIELDNAMES = [
    "action",
    "match_kind",
    "matched_on",
    "survivor_type",
    "survivor_name",
    "survivor_rename",
    "survivor_entries",
    "survivor_created_via",
    "survivor_id",
    "loser_type",
    "loser_name",
    "loser_entries",
    "loser_created_via",
    "loser_id",
    "loser_type_fields",
    "reason",
]


@dataclass
class Candidate:
    entity_type: str
    id: str
    name: str
    aliases: list[str]
    entries: int
    created_via: str | None
    first_seen: object
    type_fields: str
    malware_type: str | None = None


def _type_fields(entity_type: str, e) -> str:
    """Type-specific values that a reclassify would drop, for the CSV."""
    bits = []
    if entity_type == "malware" and e.malware_type:
        bits.append(f"malware_type={e.malware_type}")
    if entity_type == "tool" and e.tool_type:
        bits.append(f"tool_type={e.tool_type}")
    if entity_type == "threat_actor":
        if e.motivation:
            bits.append(f"motivation={e.motivation}")
        if e.country:
            bits.append(f"country={e.country}")
        if e.mitre_id:
            bits.append(f"mitre_id={e.mitre_id}")
    return "; ".join(bits)


async def _load(db, entity_type: str) -> list[Candidate]:
    model, junction, fk = TYPES[entity_type]
    counts = dict((await db.execute(select(fk, func.count(junction.entry_id)).group_by(fk))).all())
    out = []
    for e in (await db.execute(select(model))).scalars().all():
        out.append(
            Candidate(
                entity_type=entity_type,
                id=str(e.id),
                name=e.name,
                aliases=list(e.aliases or []),
                entries=int(counts.get(e.id, 0)),
                created_via=e.created_via,
                first_seen=e.first_seen_at,
                type_fields=_type_fields(entity_type, e),
                malware_type=getattr(e, "malware_type", None),
            )
        )
    return out


# Descriptor-stripped forms are a weaker signal than exact ones: stripping
# turns "Gunra ransomware" into "gunra", but it also turns "X loader" and
# "X group" into "x". Require some substance left over so short fragments
# cannot collapse unrelated entities into one another.
_MIN_STRIPPED_LEN = 4

# name > alias > stripped. A pair is only as strong as its weakest side.
_KIND_RANK = {"name": 0, "alias": 1, "stripped": 2}


def _descriptor_stripped(name: str, entity_type: str) -> str:
    """The name with only its descriptor words removed — no version stripping.

    normalize_entity_name's ``norm_stripped`` also drops trailing numeric
    tokens. That is right for "XMRig 6.25.0" and disastrous for cross-type
    pairing: every Storm-#### designation collapses to "storm" and every
    CVE-2026-* to a single form, so unrelated entities pair up by the dozen.
    Descriptor stripping alone is what finds "Interlock Ransomware" ->
    "Interlock", and it leaves "Storm-0501 Ransomware" -> "Storm-0501" intact
    so it can still meet the actor of that name head on.

    Reaches into entity_resolution's private descriptor vocabulary on purpose:
    duplicating the word lists here would let the two drift apart silently.
    """
    leading, trailing = _TYPE_DESCRIPTORS.get(entity_type, ((), ()))
    return _fold(" ".join(_strip_phrases(_tokens(name), leading, trailing)))


def _forms(c: Candidate) -> dict[str, str]:
    """normalized form -> 'name' | 'alias' | 'stripped' (strongest kind wins).

    ``stripped`` carries the descriptor-stripped spelling of the canonical name,
    which is how "Interlock Ransomware" the actor reaches "Interlock" the
    malware. Exact matching alone misses every twin separated by a descriptor
    word, and those are common: a gang and its payload are usually named the
    same thing with "ransomware" on one of them.
    """
    forms: dict[str, str] = {}

    def offer(form: str, kind: str) -> None:
        if not form:
            return
        if kind == "stripped" and len(form) < _MIN_STRIPPED_LEN:
            return
        if form not in forms or _KIND_RANK[kind] < _KIND_RANK[forms[form]]:
            forms[form] = kind

    for alias in c.aliases:
        offer(normalize_entity_name(alias, c.entity_type).norm_exact, "alias")
    norm = normalize_entity_name(c.name, c.entity_type)
    offer(norm.norm_exact, "name")
    offer(_descriptor_stripped(c.name, c.entity_type), "stripped")
    return forms


def _pick(a: Candidate, b: Candidate) -> tuple[Candidate, Candidate, str]:
    """Survivor, loser, and why.

    Ransomware brands first: when an actor and a ransomware family share a name,
    the gang is the entity worth tracking and the payload is a facet of it. That
    rule is applied before link counts on purpose — otherwise LockBit and Akira
    (payload better-covered) would fold the opposite way from Qilin and Cl0p
    (gang better-covered), which is the same situation with a different answer.

    Everything else: more entry links wins, ties go to the older profile.
    """
    types = {a.entity_type, b.entity_type}
    if types == {"threat_actor", "malware"}:
        actor, malware = (a, b) if a.entity_type == "threat_actor" else (b, a)
        if (malware.malware_type or "").lower() == "ransomware":
            return actor, malware, "ransomware brand — the gang is the entity, the payload folds in"

    if a.entries != b.entries:
        s, loser = (a, b) if a.entries > b.entries else (b, a)
        return s, loser, f"more entry links ({s.entries} vs {loser.entries})"
    if a.first_seen and b.first_seen and a.first_seen != b.first_seen:
        s, loser = (a, b) if a.first_seen < b.first_seen else (b, a)
        return s, loser, f"equal entry links ({a.entries}); older profile wins"
    # Fully tied: prefer the actor, then malware — a brand is more often the
    # group than the payload, and it is the reviewer's call either way.
    order = {"threat_actor": 0, "malware": 1, "tool": 2}
    s, loser = (a, b) if order[a.entity_type] <= order[b.entity_type] else (b, a)
    return s, loser, f"fully tied ({a.entries} entry links); defaulted by type"


def _better_name(survivor: Candidate, loser: Candidate) -> str:
    """The display name to keep, when the two differ only in casing/punctuation.

    Survivors are picked by type and coverage, not by how well they are spelled:
    an empty "royal" actor stub can legitimately win over a 191-entry "Royal"
    malware family. Carrying the loser's casing over keeps the surviving profile
    readable. Returns "" when the survivor's own name is already fine.
    """
    if survivor.name == loser.name:
        return ""
    # All-lowercase or all-uppercase survivor vs a mixed-case loser: take theirs.
    if survivor.name.islower() and not loser.name.islower():
        return loser.name
    if survivor.name.isupper() and not loser.name.isupper() and not loser.name.islower():
        return loser.name
    return ""


def _writable_out(path: str) -> str:
    """Resolve the CSV path, falling back to /tmp on a read-only mount.

    docker-compose.prod.yml bind-mounts ./scripts read-only, so the default
    scripts/out/ location works in dev and fails on the prod host. Fall back
    rather than making the operator rediscover this mid-run.
    """
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


def _carry_key(row: dict) -> tuple[str, str]:
    """Identify a pair across two runs: the normalized name + the two types.

    Entity ids match between a prod-synced dev DB and prod, but coverage moves,
    so the default survivor can differ between runs. Keying on the name and the
    type pair lets a review done against one snapshot carry onto the next.
    """
    return (row["matched_on"], "|".join(sorted((row["survivor_type"], row["loser_type"]))))


def _load_prior(path: str) -> dict[tuple[str, str], dict]:
    with open(path, newline="") as fh:
        return {_carry_key(r): r for r in csv.DictReader(fh)}


async def propose(out_path: str, include_aliases: bool, carry_from: str | None = None) -> list[dict]:
    async with async_session() as db:
        by_form: dict[str, list[tuple[Candidate, str]]] = defaultdict(list)
        for entity_type in TYPES:
            for c in await _load(db, entity_type):
                for form, kind in _forms(c).items():
                    if kind == "alias" and not include_aliases:
                        continue
                    by_form[form].append((c, kind))

    rows: list[dict] = []
    # A pair can collide on several forms at once ("Interlock Ransomware" meets
    # "Interlock" both as a stripped name and, once aliases are in, as an alias).
    # Keep the STRONGEST match per pair — recording whichever form sorted first
    # would downgrade an exact twin to a review row on alphabetical luck.
    best: dict[tuple[str, str], tuple[int, str, Candidate, Candidate, str]] = {}
    for form, members in sorted(by_form.items()):
        types = {c.entity_type for c, _ in members}
        if len(types) < 2:
            continue
        for i, (a, kind_a) in enumerate(members):
            for b, kind_b in members[i + 1 :]:
                if a.entity_type == b.entity_type:
                    continue
                # The pair is only as strong as its weaker side.
                match_kind = kind_a if _KIND_RANK[kind_a] >= _KIND_RANK[kind_b] else kind_b
                key = tuple(sorted((a.id, b.id)))
                rank = _KIND_RANK[match_kind]
                if key not in best or rank < best[key][0]:
                    best[key] = (rank, form, a, b, match_kind)

    for _rank, form, a, b, match_kind in best.values():
        survivor, loser, reason = _pick(a, b)
        rows.append(
            {
                # Only an exact name-on-name collision is safe to default
                # to fold. A descriptor-stripped match is a genuine twin
                # often enough to surface, and wrong often enough
                # ("X loader" vs "X group") to make an analyst confirm.
                "action": "fold" if match_kind == "name" else "skip",
                "match_kind": match_kind,
                "matched_on": form,
                "survivor_type": survivor.entity_type,
                "survivor_name": survivor.name,
                "survivor_rename": _better_name(survivor, loser),
                "survivor_entries": survivor.entries,
                "survivor_created_via": survivor.created_via or "",
                "survivor_id": survivor.id,
                "loser_type": loser.entity_type,
                "loser_name": loser.name,
                "loser_entries": loser.entries,
                "loser_created_via": loser.created_via or "",
                "loser_id": loser.id,
                "loser_type_fields": loser.type_fields,
                "reason": reason,
            }
        )

    if carry_from:
        prior = _load_prior(carry_from)
        carried = 0
        for r in rows:
            old_row = prior.get(_carry_key(r))
            if not old_row:
                continue
            # The reviewer decided which type wins; re-point that onto whichever
            # side this run defaulted to, so a flip stays a flip.
            if old_row["survivor_type"] != r["survivor_type"] and old_row["action"].strip().lower() == "fold":
                r["action"] = "flip"
            else:
                r["action"] = old_row["action"]
            r["survivor_rename"] = old_row.get("survivor_rename", "")
            carried += 1
        print(f"carried {carried} prior decisions from {carry_from} ({len(rows) - carried} rows are new)")

    # Biggest blast radius first — that is the order a reviewer wants to read in.
    rows.sort(key=lambda r: -(int(r["survivor_entries"]) + int(r["loser_entries"])))

    out_path = _writable_out(out_path)
    with open(out_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    folds = sum(1 for r in rows if r["action"] == "fold")
    stripped = sum(1 for r in rows if r["match_kind"] == "stripped")
    print(f"{len(rows)} cross-type pairs ({folds} defaulted to fold, {len(rows) - folds} to skip)")
    if stripped:
        print(f"  {stripped} matched only after descriptor stripping — review these, they default to skip")
    by_pair: dict[str, int] = defaultdict(int)
    for r in rows:
        by_pair[" + ".join(sorted((r["survivor_type"], r["loser_type"])))] += 1
    for pair, n in sorted(by_pair.items(), key=lambda kv: -kv[1]):
        print(f"  {pair}: {n}")
    print(f"\nwrote {out_path}")
    print("Review the `action` column (fold / skip / flip), then re-run with --apply --plan <csv>")
    return rows


async def replay_holds(write: bool) -> None:
    """Recover mentions that enforced cross-type holds dropped on the floor.

    With the gates on, a cross-type hit correctly declined to mint a duplicate
    profile — but until the link_target change in entity_resolution.py it also
    declined to link the entry to the entity that already existed, so the
    article lost the mention entirely. Every one of those decisions was logged
    with the entry and the survivor, so they can be replayed. Idempotent: the
    junction insert is on-conflict-do-nothing, so re-running is safe.
    """
    linked = 0
    stale = 0
    ambiguous = 0
    async with async_session() as db:
        rows = (
            (
                await db.execute(
                    select(EntityMaintenanceLog)
                    .where(
                        EntityMaintenanceLog.action == "resolution_held",
                        EntityMaintenanceLog.mode == "apply",
                        EntityMaintenanceLog.after["reason"].astext == "cross_type_hit",
                    )
                    .order_by(EntityMaintenanceLog.created_at)
                )
            )
            .scalars()
            .all()
        )
        print(f"{len(rows)} enforced cross-type holds in the maintenance log")

        for row in rows:
            entry_id = (row.before or {}).get("entry_id")
            name = (row.before or {}).get("name")
            candidates = (row.after or {}).get("cross_type_candidates") or []
            if not entry_id or not candidates:
                stale += 1
                continue
            targets = {(c["entity_type"], c["entity_id"]) for c in candidates}
            if len(targets) != 1:
                ambiguous += 1
                continue
            t_type, t_id = targets.pop()
            if t_type not in TYPES:
                stale += 1
                continue
            # The entry or the survivor may have been deleted or folded since.
            if await db.get(Entry, entry_id) is None or await db.get(TYPES[t_type][0], t_id) is None:
                stale += 1
                continue
            if write:
                await link_entry_to_entity(db, entry_id, t_type, t_id, source="ai", matched_name=name)
            linked += 1

        if write:
            await db.commit()

    verb = "linked" if write else "would link"
    print(f"{verb} {linked} entries to their existing cross-type entity")
    print(f"  {ambiguous} skipped (more than one candidate survivor), {stale} skipped (entity or entry is gone)")
    if not write:
        print("\nRe-run with --replay-holds --apply to write them.")


async def apply(plan_path: str, batch: int, limit: int | None) -> None:
    with open(plan_path, newline="") as fh:
        rows = list(csv.DictReader(fh))

    todo = [r for r in rows if (r.get("action") or "").strip().lower() in ("fold", "flip")]
    if limit:
        todo = todo[:limit]
    skipped = len(rows) - len([r for r in rows if (r.get("action") or "").strip().lower() in ("fold", "flip")])
    print(f"{len(todo)} pairs to fold ({skipped} skipped by the plan)")

    done = 0
    failed = 0
    for i, r in enumerate(todo, 1):
        flip = r["action"].strip().lower() == "flip"
        survivor_type = r["loser_type"] if flip else r["survivor_type"]
        survivor_id = r["loser_id"] if flip else r["survivor_id"]
        loser_type = r["survivor_type"] if flip else r["loser_type"]
        loser_id = r["survivor_id"] if flip else r["loser_id"]
        label = f"{loser_type}:{r['loser_name']} -> {survivor_type}:{r['survivor_name']}"

        async with async_session() as db:
            try:
                res = await perform_reclassify(
                    db,
                    ReclassifyRequest(
                        source_type=loser_type,
                        source_id=loser_id,
                        target_type=survivor_type,
                        target_id=survivor_id,
                        mode="apply",
                        reasoning=(
                            f"Cross-type same-name fold (fold_cross_type_twins.py): matched on '{r['matched_on']}'"
                        ),
                    ),
                )
                rename = (r.get("survivor_rename") or "").strip()
                if rename and not flip:
                    survivor = await db.get(TYPES[survivor_type][0], survivor_id)
                    if survivor is not None and survivor.name != rename:
                        survivor.name = rename
                        label += f" (renamed to '{rename}')"
                await db.commit()
                await invalidate_entity_cache(survivor_type, str(survivor_id))
                done += 1
                print(f"[{i}/{len(todo)}] {label} — moved {res.moved_entry_links} entry links")
            except Exception as exc:  # one bad row must not abort the run
                await db.rollback()
                failed += 1
                print(f"[{i}/{len(todo)}] {label} — FAILED: {exc}")

        if batch and i % batch == 0 and i < len(todo):
            print(f"-- batch boundary ({i}/{len(todo)}), pausing 5s --")
            await asyncio.sleep(5)

    print(f"\nfolded {done}, failed {failed}")
    if done:
        print("Next: python scripts/maintenance/reconcile_search_index.py")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Propose folds and write the review CSV (default).")
    mode.add_argument("--apply", action="store_true", help="Execute a reviewed plan CSV.")
    ap.add_argument(
        "--replay-holds",
        action="store_true",
        help=(
            "Recover entry links that enforced cross-type holds dropped, from the maintenance log. "
            "Previews by default; add --apply to write."
        ),
    )
    ap.add_argument("--out", default=DEFAULT_OUT, help=f"CSV path for --dry-run (default {DEFAULT_OUT}).")
    ap.add_argument("--plan", help="Reviewed CSV to execute with --apply.")
    ap.add_argument(
        "--include-aliases",
        action="store_true",
        help="Also report pairs that only collide through an alias (default action=skip).",
    )
    ap.add_argument(
        "--carry",
        help="Re-apply the action/rename decisions from an earlier reviewed CSV (match by name + type pair).",
    )
    ap.add_argument("--batch", type=int, default=25, help="Pause 5s every N folds during --apply (0 = never).")
    ap.add_argument("--limit", type=int, help="Only process the first N plan rows during --apply.")
    args = ap.parse_args()

    if args.replay_holds:
        asyncio.run(replay_holds(args.apply))
    elif args.apply:
        if not args.plan:
            ap.error("--apply requires --plan <csv> (review the dry-run output first)")
        asyncio.run(apply(args.plan, args.batch, args.limit))
    else:
        asyncio.run(propose(args.out, args.include_aliases, args.carry))


if __name__ == "__main__":
    main()
