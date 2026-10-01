"""Run every reference-data seeder, in dependency order.

A fresh install starts with an empty autolinker vocabulary: entries ingest, but
nothing links to anything, because there are no countries, techniques, vendors,
or actors to match against. This runs the whole seed set in the order the later
steps need — country aliases need countries, actor attribution needs both.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_all.py --dry-run
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_all.py

Every step is idempotent, so re-running fills gaps rather than duplicating.
Steps run as subprocesses: one failing seeder cannot poison another's database
session, and a crash mid-run leaves the completed steps committed.

All ten seeders support --dry-run, so `seed_all.py --dry-run` is a genuine
preview of the whole set rather than just a plan. The two Wikipedia steps skip
their network lookups when dry, so the preview is fast; the ATT&CK step still
downloads its bundles, because that is the only way to know what would change.

Useful flags:
    --dry-run              Run every step in its own dry-run mode. Nothing is written.
    --offline              Skip the three steps that download from MITRE/Wikipedia.
    --only countries,cpe   Run just these steps (comma-separated, see --list).
    --skip vendors         Run everything except these.
    --overwrite            Let steps that fill blanks also replace existing values.
    --continue-on-error    Keep going after a failure instead of stopping.
    --list                 Show the step names and exit.

On a partial failure the summary names the failed steps, so you can resume with
`--only <those steps>` once you've fixed the cause.
"""

import argparse
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

SEED_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Step:
    name: str
    script: str
    what: str
    network: bool = False
    # Flags this seeder actually accepts — passing one it doesn't know is a hard
    # argparse error, so pass-through is opt-in per step rather than assumed.
    accepts: tuple[str, ...] = field(default=())


DRY = ("--dry-run",)
DRY_OVERWRITE = ("--dry-run", "--overwrite")

STEPS: tuple[Step, ...] = (
    Step("countries", "seed_countries.py", "UN-recognized countries with ISO codes and regions", accepts=DRY),
    Step("aliases", "seed_country_aliases.py", "Country demonyms, so 'Iranian' matches Iran", accepts=DRY),
    Step("sectors", "seed_sectors.py", "The 21 victim-sector entities (closed vocabulary)", accepts=DRY),
    Step("attack", "seed_mitre_attack.py", "MITRE ATT&CK catalog (Enterprise + Mobile + ICS)", True, DRY),
    # Before vendors/cpe: the catalog has to exist before backfill_cve_weaknesses
    # can resolve the NVD refs already sitting in cves.nvd_data.
    Step("cwe", "seed_cwe_catalog.py", "MITRE CWE catalog (969 weaknesses + 422 categories)", True, DRY),
    Step("vendors", "seed_vendors_products.py", "107 vendors and 862 products", True, DRY),
    Step("descriptions", "seed_vendor_descriptions.py", "Markdown descriptions for vendors/products", True, DRY),
    Step("cpe", "seed_cpe_names.py", "CPE curation so NVD pairs resolve", accepts=DRY),
    Step("attribution", "seed_actor_countries.py", "Origin-country attribution for ~530 actors", accepts=DRY_OVERWRITE),
    Step("attributes", "seed_entity_attributes.py", "Actor motivation and malware type", accepts=DRY_OVERWRITE),
)

OK, FAILED, SKIPPED = "ok", "failed", "skipped"


def select(args: argparse.Namespace) -> list[Step]:
    """Resolve --only/--skip/--offline into the ordered list of steps to run."""
    names = {s.name for s in STEPS}
    for flag, raw in (("--only", args.only), ("--skip", args.skip)):
        unknown = {n for n in raw if n not in names}
        if unknown:
            sys.exit(
                f"Error: {flag} got unknown step(s): {', '.join(sorted(unknown))}\n"
                f"Known steps: {', '.join(s.name for s in STEPS)}"
            )

    chosen = [s for s in STEPS if (not args.only or s.name in args.only) and s.name not in args.skip]
    if args.offline:
        chosen = [s for s in chosen if not s.network]
    return chosen


def run(step: Step, args: argparse.Namespace) -> tuple[str, float]:
    extra = [
        flag
        for flag in ("--dry-run", "--overwrite")
        if getattr(args, flag[2:].replace("-", "_"), False) and flag in step.accepts
    ]
    cmd = [sys.executable, str(SEED_DIR / step.script), *extra]

    print(f"\n\033[1m── {step.name}\033[0m  {step.what}")
    print(f"   $ {' '.join(cmd)}", flush=True)

    started = time.monotonic()
    result = subprocess.run(cmd)  # noqa: S603 — fixed argv, no shell
    elapsed = time.monotonic() - started

    if result.returncode == 0:
        print(f"   \033[32m✓ {step.name}\033[0m ({elapsed:.1f}s)")
        return OK, elapsed
    print(f"   \033[31m✗ {step.name} exited {result.returncode}\033[0m ({elapsed:.1f}s)")
    return FAILED, elapsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Print the plan and exit without running anything.")
    parser.add_argument("--offline", action="store_true", help="Skip steps that download from MITRE/Wikipedia.")
    parser.add_argument("--only", default="", help="Comma-separated step names to run.")
    parser.add_argument("--skip", default="", help="Comma-separated step names to skip.")
    parser.add_argument("--overwrite", action="store_true", help="Replace existing values, not just fill blanks.")
    parser.add_argument("--continue-on-error", action="store_true", help="Keep going after a step fails.")
    parser.add_argument("--list", action="store_true", help="List step names and exit.")
    args = parser.parse_args()

    if args.list:
        for s in STEPS:
            print(f"{s.name:<13} {s.what}{'  [network]' if s.network else ''}")
        return 0

    args.only = [n.strip() for n in args.only.split(",") if n.strip()]
    args.skip = [n.strip() for n in args.skip.split(",") if n.strip()]
    steps = select(args)

    if not steps:
        print("Nothing to do — every step was filtered out.")
        return 0

    print(f"\033[1mSeed plan\033[0m ({len(steps)} of {len(STEPS)} steps, in order):")
    for i, s in enumerate(steps, 1):
        print(f"  {i}. {s.name:<13} {s.what}{'  [downloads]' if s.network else ''}")
    if args.overwrite:
        print("\n  --overwrite: attribution and attributes will replace existing values.")
    if any(s.network for s in steps):
        print("\n  The [downloads] steps fetch from MITRE and Wikipedia and take a few minutes each.")

    if args.dry_run:
        print("\n  --dry-run: every step runs in its own dry-run mode. Nothing is written.")

    results: list[tuple[Step, str, float]] = []
    for i, step in enumerate(steps):
        try:
            status, elapsed = run(step, args)
        except KeyboardInterrupt:
            state = "Nothing was written." if args.dry_run else "Completed steps are committed."
            print(f"\n\033[33mInterrupted during '{step.name}'.\033[0m {state}")
            remaining = [s.name for s in steps[i:]]
            print(f"Resume with: --only {','.join(remaining)}")
            return 130
        results.append((step, status, elapsed))
        if status == FAILED and not args.continue_on_error:
            for skipped in steps[i + 1 :]:
                results.append((skipped, SKIPPED, 0.0))
            break

    print(f"\n\033[1m{'Step':<15}{'Result':<10}{'Time':>8}\033[0m")
    for step, status, elapsed in results:
        colour = {OK: "\033[32m", FAILED: "\033[31m", SKIPPED: "\033[33m"}[status]
        print(f"{step.name:<15}{colour}{status:<10}\033[0m{elapsed:>7.1f}s")

    failed = [s.name for s, status, _ in results if status == FAILED]
    succeeded = sum(1 for _, status, _ in results if status == OK)
    total = sum(e for _, _, e in results)
    print(f"\n{succeeded}/{len(steps)} succeeded in {total:.1f}s")

    if failed:
        print(f"\033[31mFailed: {', '.join(failed)}\033[0m")
        print(f"Fix the cause, then resume with: --only {','.join(failed)}")
        return 1
    print("\033[32mSeeding complete.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
