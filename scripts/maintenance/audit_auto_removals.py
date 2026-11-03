"""List the link removals the adjudicate stage applied on its own, for review and restore.

With ``adjudication_mode = apply`` the stage removed links and dropped
indicators without a person in the loop. Some of what it removed matches
patterns now known to be wrong (the prompt was corrected in e4e9c654):

    sector              any sector link (sectors are inferred from who the
                        victims are, so the article rarely names them)
    legit_tool          a tool link whose tool_type is defensive / legitimate
                        software, or whose reason calls it legitimate/defensive
    ttp_rule_mapping    a TTP the article's detection rule tags (attack.tNNNN,
                        source_ttps) — the rule's own ATT&CK mapping
    ttp_attack_table    a TTP id printed in a table, list or code block of the
                        article (an ATT&CK mapping table)
    ioc_hash            a dropped md5/sha1/sha256 the article prints in a table,
                        list or code block (an indicator table); `ioc_hash_text`
                        when it is only in prose
    bystander_reason    the reason says "legitimate", "defensive", "victim",
                        "publisher", "metadata", "just a sector" ... — reasons
                        the reviewer is now told never to use

Sources, both since --since:
    entity_link_validation_log   action='removed' (minus "Promoted from
                                 proposal" rows, which an analyst applied)
    entity_maintenance_log       applied adjudication_unlink / adjudication_veto
                                 / adjudication_ioc_drop rows. Queue-applied
                                 rows look the same as auto-applied ones here,
                                 so a few analyst decisions can appear.
Already-restored rows are left out.

Step 1 writes a CSV. ``restore`` is prefilled ``y`` on rows matching a
strong pattern (every one above except ioc_hash_text and bystander_reason,
which are prefilled blank); edit it, then

Step 2: ``--restore <csv>`` re-creates the rows marked y through the queue's
own Restore paths (``restore_from_log`` / ``restore_adjudication_row``):
the junction row comes back with its original snapshot, article_count goes
back up, a dropped sighting is re-recorded, a vetoed entity is re-created.
Dry-run unless --apply. Idempotent: a restored row is never restored twice.

Run inside the api container (scripts/ is read-only in prod, so the CSV goes
to /tmp there — the path is printed; `docker compose cp` it out to edit):

    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/audit_auto_removals.py --since 2026-10-08
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/audit_auto_removals.py --restore /tmp/auto_removals.csv
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/audit_auto_removals.py --restore /tmp/auto_removals.csv --apply

--all lists every auto-applied removal, not only the pattern matches.
"""

import argparse
import asyncio
import csv
import json
import os
import re
import sys
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime

sys.path.insert(0, "/app")

from sqlalchemy import or_, select

import app.models  # noqa: F401  (register every mapper)
from app.database import async_session
from app.models.detection_rule import DetectionRule
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entry import Entry
from app.models.observable import HASH_KINDS

DEFAULT_CSV = "auto_removals.csv"
LOOKUP_BATCH = 200
WRITE_BATCH = 100
YES = {"y", "yes", "1", "true", "x"}

# The stage's action codes (app/services/entry_adjudication.py).
ACTION_UNLINK = "adjudication_unlink"
ACTION_VETO = "adjudication_veto"
ACTION_IOC_DROP = "adjudication_ioc_drop"
MAINT_ACTIONS = (ACTION_UNLINK, ACTION_VETO, ACTION_IOC_DROP)

# tool_type values for software that is not attacker tooling (app/models/tool.py).
LEGIT_TOOL_TYPES = {
    "defensive",
    "observability",
    "identity",
    "cloud",
    "dev_tool",
    "service",
    "software",
    "ai_model",
    "remote_access",
    "lolbas",
    "tunneling",
}
BYSTANDER_REASON_RE = re.compile(
    r"\b(legitimate|legit|defensive|defender|security (?:vendor|product|tool|company|firm|researcher)s?|"
    r"victim|publisher|benign|not (?:an? )?(?:adversary|threat|attacker|malicious)|"
    r"just a sector|metadata|system (?:file|path|binary)|analytic story)\b",
    re.IGNORECASE,
)
STRONG = {"sector", "legit_tool", "ttp_rule_mapping", "ttp_attack_table", "ioc_hash"}

FIELDS = [
    "restore",
    "patterns",
    "log_table",
    "log_id",
    "created_at",
    "action",
    "entity_type",
    "entity_id",
    "entity_name",
    "detail",
    "entry_id",
    "entry_title",
    "reason",
]


# --------------------------------------------------------------------------- pure helpers

_BLOCKS = {
    "table": re.compile(r"<table\b.*?</table\s*>", re.IGNORECASE | re.DOTALL),
    "pre": re.compile(r"<(pre|code)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL),
    "list": re.compile(r"<(ul|ol)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL),
}


def html_context(html: str | None, needle: str, text: str | None = None) -> str | None:
    """Where an article prints ``needle``: table, pre (code block), list, text,
    or None when it does not print it at all. The strongest context wins."""
    if not needle:
        return None
    low = needle.lower()
    if html and low in html.lower():
        for name, block in _BLOCKS.items():
            if any(low in m.group(0).lower() for m in block.finditer(html)):
                return name
        return "text"
    if text and low in text.lower():
        return "text"
    return None


def technique_pattern(technique_id: str) -> re.Pattern:
    """Matches T1059 in "T1059", "attack.t1059" and "T1059.001", never in T10590."""
    return re.compile(rf"(?<![a-z0-9]){re.escape(technique_id)}(?!\d)", re.IGNORECASE)


def classify(
    entity_type: str,
    reason: str | None,
    *,
    tool_type: str | None = None,
    technique_id: str | None = None,
    rule_text: str = "",
    entry_html: str | None = None,
    entry_text: str | None = None,
    ioc_kind: str | None = None,
    ioc_value: str | None = None,
) -> tuple[list[str], str]:
    """(patterns, detail) for one applied removal."""
    patterns: list[str] = []
    detail = ""
    if entity_type == "sector":
        patterns.append("sector")
    elif entity_type == "tool":
        detail = f"tool_type={tool_type or ''}"
        if (tool_type or "") in LEGIT_TOOL_TYPES or (reason and BYSTANDER_REASON_RE.search(reason)):
            patterns.append("legit_tool")
    elif entity_type == "ttp" and technique_id:
        detail = technique_id
        pat = technique_pattern(technique_id)
        if rule_text and pat.search(rule_text):
            patterns.append("ttp_rule_mapping")
        if entry_html:
            for name in ("table", "list", "pre"):
                if any(pat.search(m.group(0)) for m in _BLOCKS[name].finditer(entry_html)):
                    patterns.append("ttp_attack_table")
                    detail += f" in {name}"
                    break
    elif entity_type == "observable" and ioc_kind:
        detail = f"{ioc_kind}:{ioc_value or ''}"
        if ioc_kind in HASH_KINDS:
            where = html_context(entry_html, ioc_value or "", entry_text)
            if where in ("table", "pre", "list"):
                patterns.append("ioc_hash")
                detail += f" in {where}"
            elif where == "text":
                patterns.append("ioc_hash_text")
    if reason and BYSTANDER_REASON_RE.search(reason) and "legit_tool" not in patterns:
        patterns.append("bystander_reason")
    return patterns, detail


def prefill_restore(patterns: list[str]) -> str:
    return "y" if STRONG & set(patterns) else ""


# --------------------------------------------------------------------------- scan


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


def _model_for(entity_type: str):
    from app.services.entry_adjudication import _model_for as model_for

    return model_for(entity_type)


async def _collect(db, since: datetime) -> list[dict]:
    """Normalised rows from both logs: one dict per applied removal."""
    rows: list[dict] = []

    restored_from = {
        r
        for (r,) in (
            await db.execute(
                select(EntityLinkValidationLog.reason).where(
                    EntityLinkValidationLog.action == "restored", EntityLinkValidationLog.created_at >= since
                )
            )
        ).all()
        if r
    }
    links = (
        (
            await db.execute(
                select(EntityLinkValidationLog)
                .where(EntityLinkValidationLog.action == "removed", EntityLinkValidationLog.created_at >= since)
                .order_by(EntityLinkValidationLog.created_at)
            )
        )
        .scalars()
        .all()
    )
    for r in links:
        if (r.reason or "").startswith("Promoted from proposal") or f"restored from {r.id}" in restored_from:
            continue
        rows.append(
            {
                "log_table": "link_log",
                "log_id": r.id,
                "created_at": r.created_at,
                "action": "removed",
                "entity_type": r.entity_type,
                "entity_id": r.entity_id,
                "entity_name": r.entity_name_snapshot or "",
                "entry_id": r.entry_id,
                "reason": r.reason or "",
                "ioc_kind": None,
                "ioc_value": None,
                "snapshot": {},
            }
        )

    maint = (
        (
            await db.execute(
                select(EntityMaintenanceLog)
                .where(
                    EntityMaintenanceLog.action.in_(MAINT_ACTIONS),
                    EntityMaintenanceLog.applied.is_(True),
                    EntityMaintenanceLog.mode == "apply",
                    EntityMaintenanceLog.created_at >= since,
                )
                .order_by(EntityMaintenanceLog.created_at)
            )
        )
        .scalars()
        .all()
    )
    for r in maint:
        before, after = r.before or {}, r.after or {}
        if after.get("restored"):
            continue
        entry_id = before.get("entry_id")
        rows.append(
            {
                "log_table": "maintenance",
                "log_id": r.id,
                "created_at": r.created_at,
                "action": r.action,
                "entity_type": r.entity_type,
                "entity_id": r.entity_id,
                "entity_name": ((before.get("entity") or {}).get("name") or ""),
                "entry_id": uuid.UUID(entry_id) if entry_id else None,
                "reason": after.get("reason") or r.reasoning or "",
                "ioc_kind": after.get("kind"),
                "ioc_value": after.get("value"),
                # A veto that deleted the entity keeps its columns here.
                "snapshot": before.get("entity") or {},
            }
        )
    return rows


async def _entity_info(db, rows: list[dict]) -> dict[tuple[str, uuid.UUID], dict]:
    by_type: dict[str, set] = defaultdict(set)
    for r in rows:
        if r["entity_id"] and r["entity_type"] != "observable":
            by_type[r["entity_type"]].add(r["entity_id"])
    info: dict[tuple[str, uuid.UUID], dict] = {}
    for etype, ids in by_type.items():
        model = _model_for(etype)
        if model is None:
            continue
        ids = list(ids)
        for i in range(0, len(ids), 1000):
            for obj in (await db.execute(select(model).where(model.id.in_(ids[i : i + 1000])))).scalars():
                info[(etype, obj.id)] = {
                    "name": getattr(obj, "name", None) or getattr(obj, "technique_id", None) or "",
                    "tool_type": getattr(obj, "tool_type", None),
                    "technique_id": getattr(obj, "technique_id", None),
                }
    return info


async def _entry_info(db, entry_ids: list[uuid.UUID], need_body: set[uuid.UUID]) -> dict[uuid.UUID, dict]:
    out: dict[uuid.UUID, dict] = {}
    for i in range(0, len(entry_ids), LOOKUP_BATCH):
        chunk = entry_ids[i : i + LOOKUP_BATCH]
        body_ids = [e for e in chunk if e in need_body]
        for eid, title in (await db.execute(select(Entry.id, Entry.title).where(Entry.id.in_(chunk)))).all():
            out[eid] = {"title": title or "", "html": None, "text": None, "rules": ""}
        if not body_ids:
            continue
        for eid, html, text in (
            await db.execute(select(Entry.id, Entry.content_html, Entry.content_text).where(Entry.id.in_(body_ids)))
        ).all():
            out[eid]["html"], out[eid]["text"] = html, text
        rules = await db.execute(
            select(
                DetectionRule.entry_id,
                DetectionRule.source_entries,
                DetectionRule.tags,
                DetectionRule.source_ttps,
                DetectionRule.rule_content,
            ).where(or_(DetectionRule.entry_id.in_(body_ids), DetectionRule.source_entries.overlap(body_ids)))
        )
        wanted = set(body_ids)
        for entry_id, sources, tags, ttps, content in rules.all():
            blob = " ".join([" ".join(tags or []), json.dumps(ttps or [], default=str), content or ""])
            for eid in {entry_id, *(sources or [])} & wanted:
                out[eid]["rules"] += "\n" + blob
    return out


async def scan(since: datetime, csv_path: str, include_all: bool) -> None:
    async with async_session() as db:
        rows = await _collect(db, since)
        print(f"{len(rows)} auto-applied removals since {since.date()}")
        info = await _entity_info(db, rows)
        need_body = {r["entry_id"] for r in rows if r["entry_id"] and r["entity_type"] in ("ttp", "observable")}
        entries = await _entry_info(db, list({r["entry_id"] for r in rows if r["entry_id"]}), need_body)

    out: list[dict] = []
    tally: Counter = Counter()
    by_source: Counter = Counter()
    for r in rows:
        ent = info.get((r["entity_type"], r["entity_id"])) or r["snapshot"]
        entry = entries.get(r["entry_id"], {})
        patterns, detail = classify(
            r["entity_type"],
            r["reason"],
            tool_type=ent.get("tool_type"),
            technique_id=ent.get("technique_id"),
            rule_text=entry.get("rules", ""),
            entry_html=entry.get("html"),
            entry_text=entry.get("text"),
            ioc_kind=r["ioc_kind"],
            ioc_value=r["ioc_value"],
        )
        by_source[f"{r['log_table']}:{r['action']}:{r['entity_type']}"] += 1
        tally.update(patterns)
        if not patterns and not include_all:
            continue
        out.append(
            {
                "restore": prefill_restore(patterns),
                "patterns": "|".join(patterns),
                "log_table": r["log_table"],
                "log_id": str(r["log_id"]),
                "created_at": r["created_at"].isoformat(timespec="seconds") if r["created_at"] else "",
                "action": r["action"],
                "entity_type": r["entity_type"],
                "entity_id": str(r["entity_id"] or ""),
                "entity_name": ent.get("name") or r["entity_name"],
                "detail": detail,
                "entry_id": str(r["entry_id"] or ""),
                "entry_title": entry.get("title", "(entry gone)") if r["entry_id"] else "",
                "reason": r["reason"][:500],
            }
        )

    out.sort(key=lambda x: (x["restore"] != "y", x["patterns"], x["entity_type"], x["entity_name"].lower()))
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(out)

    print("\nBy log / action / type:")
    for k, n in by_source.most_common():
        print(f"  {n:>6}  {k}")
    print("\nPattern matches (a row can match more than one):")
    for k, n in tally.most_common():
        print(f"  {n:>6}  {k}")
    marked = sum(1 for x in out if x["restore"] == "y")
    print(f"\n{len(out)} rows -> {csv_path} ({marked} prefilled restore=y).")
    print("Review the restore column, then run --restore <csv> (add --apply to write).")


# --------------------------------------------------------------------------- restore


async def _already_restored_link(db, log_id: uuid.UUID) -> bool:
    return (
        await db.scalar(
            select(EntityLinkValidationLog.id)
            .where(
                EntityLinkValidationLog.action == "restored",
                EntityLinkValidationLog.reason == f"restored from {log_id}",
            )
            .limit(1)
        )
    ) is not None


async def restore(csv_path: str, apply: bool) -> None:
    from app.intelligence.link_validation_apply import restore_from_log
    from app.services.entry_adjudication import restore_adjudication_row

    with open(csv_path, newline="") as fh:
        plan = [r for r in csv.DictReader(fh) if (r.get("restore") or "").strip().lower() in YES]
    print(f"{len(plan)} rows marked for restore in {csv_path}")
    done: Counter = Counter()
    touched: dict[str, set] = defaultdict(set)
    async with async_session() as db:
        for i, r in enumerate(plan, 1):
            log_id = uuid.UUID(r["log_id"])
            if r["log_table"] == "link_log":
                if await _already_restored_link(db, log_id):
                    done["already restored"] += 1
                    continue
                if not apply:
                    done["would restore"] += 1
                    continue
                try:
                    async with db.begin_nested():
                        ok, message = await restore_from_log(db, log_id)
                except Exception as e:
                    ok, message = False, f"error: {str(e)[:80]}"
            else:
                row = await db.get(EntityMaintenanceLog, log_id)
                if row is None:
                    done["log row gone"] += 1
                    continue
                if (row.after or {}).get("restored"):
                    done["already restored"] += 1
                    continue
                if not apply:
                    done["would restore"] += 1
                    continue
                try:
                    async with db.begin_nested():
                        outcome = await restore_adjudication_row(db, row)
                    ok, message = bool(outcome.get("restored")), outcome.get("reason") or "restored"
                except Exception as e:
                    ok, message = False, f"error: {str(e)[:80]}"
            done["restored" if ok else message] += 1
            if ok and r.get("entity_id"):
                touched[r["entity_type"]].add(uuid.UUID(r["entity_id"]))
            if i % WRITE_BATCH == 0:
                await db.commit()
                print(f"  {i}/{len(plan)}")
        if apply:
            await db.commit()
            if touched:
                from app.services.entity_indexer import index_entities

                try:
                    await index_entities(db, {k: list(v) for k, v in touched.items()})
                except Exception as e:
                    print(f"Search re-index failed ({e}); run rebuild_search_indexes.py --entities-only.")
        else:
            await db.rollback()

    print("Restore:", ", ".join(f"{k} {n}" for k, n in done.most_common()) or "nothing to do")
    if not apply:
        print("DRY RUN — nothing written. Re-run with --apply.")
        return
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        n = 0
        async for key in r.scan_iter(match="intelfeed:corr:*", count=500):
            await r.delete(key)
            n += 1
        print(f"Flushed {n} correlation cache keys.")
    except Exception as e:
        print(f"Correlation cache flush failed ({e}); it expires on its own.")


def _date(value: str) -> datetime:
    return datetime.fromisoformat(value).replace(tzinfo=UTC)


def cli() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", type=_date, help="Only removals on or after this date (YYYY-MM-DD).")
    ap.add_argument("--csv", help="Where to write the review CSV (default scripts/out/, or /tmp when read-only).")
    ap.add_argument("--all", action="store_true", help="List every auto-applied removal, not only pattern matches.")
    ap.add_argument("--restore", metavar="CSV", help="Re-create the rows marked restore=y in a reviewed CSV.")
    ap.add_argument("--apply", action="store_true", help="With --restore: write (default: report only).")
    args = ap.parse_args()
    if args.restore:
        asyncio.run(restore(args.restore, args.apply))
    elif args.since:
        asyncio.run(scan(args.since, _csv_path(args.csv), args.all))
    else:
        ap.error("--since <date> or --restore <csv> is required")


if __name__ == "__main__":
    cli()
