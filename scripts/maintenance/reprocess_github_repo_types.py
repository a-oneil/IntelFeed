"""Re-detect the file type of github_repo entries stored as generic or untyped, and import their rules.

A repo file's type comes from a per-repo path pattern, then its extension, then
(for generic YAML/TOML) its content. Entries ingested before a pattern or a
content check existed keep the type they were stored with: LOLDrivers files
that came in as `yaml_file` under the magicsword-io org, `.kql` files stored as
`unknown`, Sentinel and Anvilogic Armory rules outside the listed repos stored
as `yaml_file`. They never became rules and never got their ATT&CK/CVE links.

This re-runs detection over every github_repo entry whose stored type is
`yaml_file`, `toml_file`, `unknown` or empty. For each entry whose type
changes it rewrites `content_type`, `extracted`, the rendered card and the
title (when the title is still the bare file name), then runs the same import
the ingest pipeline runs (`process_github_entry`: rule creation, TTP/CVE
linking) — but only for feeds with "Extract intel" or "Save detection rules"
on, the same gate ingest uses. Entries whose type doesn't change are left
alone, so a re-run is a no-op.

Dry run by default: prints per-feed counts of old type → new type and how many
entries would import a rule. Run inside the API container:

    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/reprocess_github_repo_types.py
    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/reprocess_github_repo_types.py --apply
    # one feed only
    docker compose -f docker-compose.prod.yml exec api \\
        python scripts/maintenance/reprocess_github_repo_types.py --feed-id <uuid> --apply
"""

import argparse
import asyncio
import sys
import uuid
from collections import Counter
from pathlib import PurePosixPath

sys.path.insert(0, "/app")

from sqlalchemy import or_, select

from app.adapters.github_content_types import derive_title, detect_content_type, extract_metadata, render_content
from app.database import async_session
from app.models.entry import Entry
from app.models.feed import Feed
from app.services.github_rule_import import process_github_entry, rule_type_for
from app.services.system_user import get_system_user_id

GENERIC_TYPES = ("yaml_file", "toml_file", "unknown")
BATCH = 100


def _retitle_search_docs(updates: list[dict]) -> None:
    """Push new titles to the Meilisearch entries index (partial update)."""
    if not updates:
        return
    try:
        from app.services.meilisearch_client import INDEX_NAME, _get_client

        _get_client().index(INDEX_NAME).update_documents(updates)
    except Exception as exc:  # search is best-effort; the DB is the record
        print(f"  ! search title update failed ({exc}); run rebuild_search_indexes.py --entries-only")


async def reprocess(db, apply: bool, feed_id: str | None = None) -> Counter:
    """Retype (and with ``apply``, import) one session's worth; returns the totals."""
    feed_q = select(Feed).where(Feed.feed_type == "github_repo")
    if feed_id:
        feed_q = feed_q.where(Feed.id == uuid.UUID(feed_id))
    feeds = (await db.execute(feed_q.order_by(Feed.title))).scalars().all()

    user_id = await get_system_user_id(db) if apply else None
    if apply and not user_id:
        print("No system/admin user to attribute imported rules to; aborting.")
        return Counter()

    totals: Counter = Counter()
    for feed in feeds:
        cfg = feed.adapter_config or {}
        content_type_col = Entry.metadata_["content_type"].astext
        entries = (
            (
                await db.execute(
                    select(Entry).where(
                        Entry.feed_id == feed.id,
                        or_(
                            content_type_col.in_(GENERIC_TYPES),
                            content_type_col.is_(None),
                            content_type_col == "",
                        ),
                    )
                )
            )
            .scalars()
            .all()
        )
        if not entries:
            continue

        import_on = bool(feed.auto_extract_on_ingest or feed.extract_detection_rules)
        transitions: Counter = Counter()
        would_import = 0
        would_link = 0
        results: Counter = Counter()
        title_updates: list[dict] = []
        changed_in_batch = 0

        for entry in entries:
            meta = dict(entry.metadata_ or {})
            owner = meta.get("owner") or cfg.get("owner", "")
            repo = meta.get("repo") or cfg.get("repo", "")
            file_path = meta.get("file_path", "")
            raw = meta.get("raw_content")
            old_type = meta.get("content_type") or ""

            new_type = detect_content_type(owner, repo, file_path, raw)
            if new_type == old_type:
                continue
            transitions[(old_type or "(none)", new_type)] += 1

            extracted = extract_metadata(raw, new_type)
            if rule_type_for(new_type, extracted) and raw:
                would_import += 1
            if extracted.get("mitre_attack_ids") or extracted.get("cve_ids"):
                would_link += 1
            if not apply:
                continue

            meta["content_type"] = new_type
            meta["extracted"] = extracted
            entry.metadata_ = meta
            if raw:
                entry.content_html = render_content(file_path, raw, new_type, extracted)
                if entry.title == PurePosixPath(file_path).name:
                    new_title = derive_title(file_path, raw, new_type)
                    if new_title and new_title != entry.title:
                        entry.title = new_title
                        title_updates.append({"id": str(entry.id), "title": new_title})

            if import_on:
                try:
                    async with db.begin_nested():
                        result = await process_github_entry(db, entry, user_id)
                    results["rules"] += result.get("rule_count", 1 if result.get("rule_id") else 0)
                    results["ttps_linked"] += result.get("ttps_linked", 0)
                    results["cves_linked"] += result.get("cves_linked", 0)
                except Exception as exc:
                    results["import_failed"] += 1
                    print(f"  ! import failed for entry {entry.id} ({file_path}): {exc}")

            changed_in_batch += 1
            if changed_in_batch >= BATCH:
                await db.commit()
                changed_in_batch = 0

        if not transitions:
            continue

        changed = sum(transitions.values())
        label = f"{feed.title} ({cfg.get('owner', '?')}/{cfg.get('repo', '?')})"
        gate = "import on" if import_on else "import OFF (extract and rule flags both off): retype only"
        print(f"\n{label}: {changed} of {len(entries)} candidate entries change type; {gate}")
        for (old, new), n in sorted(transitions.items()):
            print(f"    {old:>12} -> {new:<18} {n}")
        skipped = "" if import_on else " (skipped)"
        print(f"    entries with a rule to import: {would_import}{skipped}")
        print(f"    entries with ATT&CK/CVE ids to link: {would_link}{skipped}")
        if apply:
            await db.commit()
            _retitle_search_docs(title_updates)
            print(
                f"    applied: rules {results['rules']}, TTP links {results['ttps_linked']}, "
                f"CVE links {results['cves_linked']}, retitled {len(title_updates)}, "
                f"import failures {results['import_failed']}"
            )
        totals["entries"] += changed
        totals["would_import"] += would_import if import_on else 0
        totals["would_link"] += would_link if import_on else 0
        for k, v in results.items():
            totals[k] += v

    # A dry run never touches an entry (every write sits behind `apply`), so
    # there is nothing to roll back.
    print(f"\ntotals: {dict(totals)}")
    if not apply:
        print("-- dry run, nothing written; pass --apply to write --")
    return totals


async def _main(apply: bool, feed_id: str | None) -> None:
    async with async_session() as db:
        await reprocess(db, apply, feed_id)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Write the changes (default is a dry run)")
    ap.add_argument("--feed-id", help="Only this github_repo feed")
    args = ap.parse_args()
    asyncio.run(_main(apply=args.apply, feed_id=args.feed_id))


if __name__ == "__main__":
    main()
