"""Drop system_settings overrides that no longer do anything.

Every knob tuned in Settings → Engine / System lands in the singleton
`system_settings.settings` row and wins over the shipped default forever —
including after the shipped default catches up with it. At that point the
override is dead weight with a cost: when the default moves again, this
install stays pinned to the stale copy. The row also collects keys for
settings the code has since dropped, and job-schedule overrides for jobs that
no longer exist.

This lists (and, without --dry-run, removes) all three:

  * overrides whose value equals the shipped default
  * keys that are not in CONFIGURABLE_KEYS (nothing reads them)
  * `_job_schedule_overrides` entries for jobs missing from JOB_REGISTRY, or
    that repeat the job's default schedule / enabled flag

It never touches secrets, `_public_rss_token`, `_default_theme_id`, or any
override that actually differs from the default.

    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/prune_setting_overrides.py --dry-run
    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/prune_setting_overrides.py

After a real run, restart celery-beat (or save any job in Engine → Jobs) so
beat rebuilds its schedule from the pruned overrides.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

sys.path.insert(0, "/app")

from sqlalchemy import select  # noqa: E402

from app.database import async_session  # noqa: E402
from app.models.system_setting import SystemSettings  # noqa: E402
from app.services.system_settings import (  # noqa: E402
    find_redundant_overrides,
    prune_redundant_overrides,
)
from app.workers.job_registry import read_overrides_from_redis, write_overrides_to_redis  # noqa: E402

LABELS = {
    "equal_to_default": "overrides equal to the shipped default",
    "unknown": "keys no setting reads any more",
    "job_overrides_orphaned": "job overrides for jobs that no longer exist",
    "job_overrides_equal_to_default": "job overrides that repeat the job's default",
}


def print_report(report: dict[str, list]) -> int:
    total = 0
    for kind, label in LABELS.items():
        keys = report.get(kind) or []
        total += len(keys)
        print(f"{label}: {len(keys)}")
        for key in keys:
            print(f"  - {key}")
    return total


async def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="report only; change nothing"
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args()

    async with async_session() as db:
        row = (
            await db.execute(select(SystemSettings).where(SystemSettings.id == 1))
        ).scalar_one_or_none()
        if not row:
            print("no system_settings row — nothing to prune")
            return

        if args.dry_run:
            report = find_redundant_overrides(dict(row.settings or {}))
        else:
            report = await prune_redundant_overrides(db)
            await db.commit()
            # Beat reads its overrides from Redis; keep that copy in step.
            if (
                report["job_overrides_orphaned"]
                or report["job_overrides_equal_to_default"]
            ):
                redis_overrides = read_overrides_from_redis()
                for job_name in (
                    report["job_overrides_orphaned"]
                    + report["job_overrides_equal_to_default"]
                ):
                    redis_overrides.pop(job_name, None)
                write_overrides_to_redis(redis_overrides)

    if args.json:
        print(json.dumps(report, indent=2))
        return
    total = print_report(report)
    verb = "would remove" if args.dry_run else "removed"
    print(f"\n{verb} {total} override(s)")


if __name__ == "__main__":
    asyncio.run(main())
