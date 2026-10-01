"""Score the one-pass analysis's observables judgment against the fixture.

For every ``tests/fixtures/observables/cases/*.json`` case this finds the
article in the corpus DB, renders the prompt exactly as ingest does
(``build_analysis_variables`` — so the indicator-appendix window is part of
what is measured), runs ``entry_analysis`` through the configured provider,
and scores the ``iocs`` / ``scripts`` / ``relationships`` arrays after the
same validators the ledger applies:

* per-kind precision / recall against ``expected`` (``optional`` items are
  neither credited nor penalised),
* hard failures for any ``must_not`` hit,
* attribution-edge recall: did the model assert ``<actor|malware> → observable``
  for the expected values?

Nothing is persisted unless ``--store`` is given: the session is rolled back
after each run so the eval never rewrites the entry's current AIResult.
``--offline`` scores the entry's *existing* current result instead of calling
the model (free; measures what production already produced).

Run inside the api container (``docker compose -f docker-compose.dev.yml exec api``):
    python scripts/dev/eval_observable_extraction.py --offline --report /app/planning/observables-eval-offline.md
    python scripts/dev/eval_observable_extraction.py --report /app/planning/observables-eval.md
    python scripts/dev/eval_observable_extraction.py --only talos-uat-11587 --dump-prompt
"""

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, "/app")

from sqlalchemy import func, select  # noqa: E402

import app.models  # noqa: E402,F401
from app.database import async_session  # noqa: E402
from app.intelligence.observables import refang, validate_kind_value  # noqa: E402
from app.models.ai_result import AIResult  # noqa: E402
from app.models.ai_task import AITask  # noqa: E402
from app.models.entry import Entry  # noqa: E402
from app.models.observable import HASH_KINDS, HOST_KINDS, NETWORK_KINDS  # noqa: E402
from app.models.user import User  # noqa: E402

CASES_DIR = Path("/app/tests/fixtures/observables/cases")

GATE = {
    "network_precision": 0.95,
    "network_recall": 0.80,
    "host_precision": 0.90,
    "attribution_recall": 0.6,
}


def _canon(kind: str, value: str) -> tuple[str, str] | None:
    kind = (kind or "").strip()
    value = (value or "").strip()
    if not kind or not value:
        return None
    canonical = validate_kind_value(kind, value)
    return (kind, canonical) if canonical else None


def _group(kind: str) -> str:
    if kind in NETWORK_KINDS or kind in HASH_KINDS:
        return "network"
    if kind in HOST_KINDS or kind == "script":
        return "host"
    return "other"


def score_case(case: dict, parsed: dict) -> dict:
    expected = {(i["kind"], i["value"]): i for i in case.get("expected", [])}
    optional = {(i["kind"], i["value"]) for i in case.get("optional", [])}
    must_not = {(i["kind"], i["value"]): i for i in case.get("must_not", [])}
    must_not_values = {refang(i["value"]).lower() for i in case.get("must_not", [])}

    produced: dict[tuple[str, str], dict] = {}
    rejected: list[dict] = []
    for item in parsed.get("iocs") or []:
        if not isinstance(item, dict):
            continue
        key = _canon(item.get("kind"), item.get("value"))
        if key is None:
            rejected.append(item)
            continue
        produced[key] = item

    tp = [k for k in produced if k in expected]
    fp = [k for k in produced if k not in expected and k not in optional]
    fn = [k for k in expected if k not in produced]
    garbage = [k for k in produced if k in must_not or k[1].lower() in must_not_values]

    by_group: dict[str, dict] = {}
    for grp in ("network", "host"):
        e = [k for k in expected if _group(k[0]) == grp]
        p = [k for k in produced if _group(k[0]) == grp and k not in optional]
        tpg = [k for k in p if k in expected]
        by_group[grp] = {
            "expected": len(e),
            "produced": len(p),
            "tp": len(tpg),
            "precision": (len(tpg) / len(p)) if p else None,
            "recall": (len(tpg) / len(e)) if e else None,
        }

    role_ok = role_total = 0
    for k in tp:
        want = (expected[k].get("role") or "").strip()
        if want:
            role_total += 1
            role_ok += int((produced[k].get("role") or "").strip() == want)

    # Attribution: a relationship whose target resolves to an expected value and
    # whose source names one of the case's attribution entities.
    attribution = case.get("attribution") or []
    attr_names = {a["name"].lower() for a in attribution}
    expected_values = {v.lower() for _, v in expected}
    asserted: set[str] = set()
    for rel in parsed.get("relationships") or []:
        if not isinstance(rel, dict) or (rel.get("target_type") or "") != "observable":
            continue
        tgt = refang((rel.get("target_name") or "").strip()).lower()
        if (
            rel.get("source_name") or ""
        ).strip().lower() in attr_names and tgt in expected_values:
            asserted.add(tgt)
    attribution_recall = (
        (len(asserted) / len(expected_values))
        if (attribution and expected_values)
        else None
    )

    return {
        "slug": case["slug"],
        "kind": case["kind"],
        "expected": len(expected),
        "produced": len(produced),
        "rejected_by_validator": len(rejected),
        "tp": len(tp),
        "fp": [
            {
                "kind": k,
                "value": v,
                "role": produced[(k, v)].get("role"),
                "evidence": (produced[(k, v)].get("evidence") or "")[:120],
            }
            for k, v in fp
        ],
        "fn": [{"kind": k, "value": v} for k, v in fn],
        "garbage": [{"kind": k, "value": v} for k, v in garbage],
        "by_group": by_group,
        "role_accuracy": (role_ok / role_total) if role_total else None,
        "attribution_recall": attribution_recall,
        "scripts": len(parsed.get("scripts") or []),
        "negative_clean": (case["kind"] == "negative" and not produced),
    }


async def _entry_for(db, case: dict) -> Entry | None:
    q = (
        select(Entry)
        .where(Entry.title.like(case["title_like"]))
        .order_by(func.length(Entry.content_html).desc().nulls_last())
        .limit(1)
    )
    return (await db.execute(q)).scalar_one_or_none()


async def _offline_result(db, entry_id) -> dict | None:
    task_id = (
        await db.execute(select(AITask.id).where(AITask.name == "entry_analysis"))
    ).scalar_one_or_none()
    if task_id is None:
        return None
    return (
        await db.execute(
            select(AIResult.parsed_result)
            .where(
                AIResult.target_type == "entry",
                AIResult.target_id == entry_id,
                AIResult.task_id == task_id,
                AIResult.is_current.is_(True),
            )
            .order_by(AIResult.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def run(args) -> list[dict]:
    from app.ai.engine import run_task
    from app.services.entry_analysis import build_analysis_variables

    cases = sorted(CASES_DIR.glob("*.json"))
    if args.only:
        cases = [c for c in cases if c.stem in set(args.only)]
    results: list[dict] = []
    async with async_session() as db:
        user_id = (
            await db.execute(select(User.id).where(User.role == "admin").limit(1))
        ).scalar_one_or_none()
        for path in cases:
            case = json.loads(path.read_text())
            entry = await _entry_for(db, case)
            if entry is None:
                print(f"- {case['slug']}: entry not in corpus, skipped")
                continue
            # Read before the run: a rollback expires the ORM row and a lazy
            # reload outside the greenlet context raises MissingGreenlet.
            entry_title, entry_id = entry.title, entry.id
            if args.offline:
                parsed = await _offline_result(db, entry_id)
                if parsed is None:
                    print(f"- {case['slug']}: no stored analysis, skipped")
                    continue
            else:
                variables = await build_analysis_variables(db, entry)
                if args.dump_prompt:
                    out = (
                        Path(args.report).with_suffix("")
                        if args.report
                        else Path("/tmp/observables-eval")
                    )
                    out.mkdir(parents=True, exist_ok=True)
                    (out / f"{case['slug']}.prompt.txt").write_text(
                        variables["entry"]["content_text"]
                    )
                parsed = await run_task(
                    db=db,
                    user_id=user_id,
                    task_name="entry_analysis",
                    variables=variables,
                    entry_id=entry_id,
                    force=True,
                )
                if not isinstance(parsed, dict) or parsed.get(
                    "_extraction_status"
                ) not in (None, "success"):
                    status = (
                        parsed.get("_extraction_status")
                        if isinstance(parsed, dict)
                        else parsed
                    )
                    print(f"- {case['slug']}: provider returned {status}")
                    raw = parsed.get("raw") if isinstance(parsed, dict) else None
                    if raw:
                        print(
                            f"    raw response: {len(raw)} chars; tail: {raw[-300:]!r}"
                        )
                    await db.rollback()
                    continue
                if args.store:
                    await db.commit()
                else:
                    await db.rollback()
            scored = score_case(case, parsed)
            scored["title"] = entry_title
            results.append(scored)
            g = scored["by_group"]
            net = f"{_fmt(g['network']['precision'])}/{_fmt(g['network']['recall'])}"
            host = f"{_fmt(g['host']['precision'])}/{_fmt(g['host']['recall'])}"
            attr = _fmt(scored["attribution_recall"])
            print(
                f"- {case['slug']}: tp={scored['tp']} fp={len(scored['fp'])} fn={len(scored['fn'])} "
                f"garbage={len(scored['garbage'])} net P/R={net} host P/R={host} attr={attr}"
            )
    return results


def _fmt(x) -> str:
    return "—" if x is None else f"{x:.2f}"


def _agg(results: list[dict], grp: str, field: str) -> float | None:
    tp = sum(r["by_group"][grp]["tp"] for r in results)
    denom = sum(
        r["by_group"][grp]["produced" if field == "precision" else "expected"]
        for r in results
    )
    return (tp / denom) if denom else None


def render_report(results: list[dict], mode: str) -> str:
    lines = [
        f"# Observables extraction eval — {datetime.now(UTC):%Y-%m-%d %H:%M} UTC ({mode})",
        "",
    ]
    net_p, net_r = (
        _agg(results, "network", "precision"),
        _agg(results, "network", "recall"),
    )
    host_p, host_r = _agg(results, "host", "precision"), _agg(results, "host", "recall")
    attrs = [
        r["attribution_recall"] for r in results if r["attribution_recall"] is not None
    ]
    attr = (sum(attrs) / len(attrs)) if attrs else None
    garbage = sum(len(r["garbage"]) for r in results)
    neg_fail = [
        r["slug"]
        for r in results
        if r["kind"] == "negative" and not r["negative_clean"]
    ]

    def _row(name: str, value, target: str, ok: bool) -> str:
        return f"| {name} | {value} | {target} | {'✅' if ok else '❌'} |"

    negatives = "all" if not neg_fail else ", ".join(neg_fail)
    lines += [
        "| Gate | Value | Target | Pass |",
        "|---|---|---|---|",
        _row(
            "network precision",
            _fmt(net_p),
            f"≥ {GATE['network_precision']}",
            (net_p or 0) >= GATE["network_precision"],
        ),
        _row(
            "network recall",
            _fmt(net_r),
            f"≥ {GATE['network_recall']}",
            (net_r or 0) >= GATE["network_recall"],
        ),
        _row(
            "host precision",
            _fmt(host_p),
            f"≥ {GATE['host_precision']}",
            host_p is None or host_p >= GATE["host_precision"],
        ),
        f"| host recall | {_fmt(host_r)} | (reported) | — |",
        _row(
            "attribution recall",
            _fmt(attr),
            f"≥ {GATE['attribution_recall']}",
            attr is None or attr >= GATE["attribution_recall"],
        ),
        _row("must_not hits", garbage, "0", garbage == 0),
        _row("negatives clean", negatives, "all", not neg_fail),
        "",
        "| Case | Expected | Produced | TP | FP | FN | Garbage | Net P/R | Host P/R | Role acc | Attr |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        g = r["by_group"]
        net = f"{_fmt(g['network']['precision'])}/{_fmt(g['network']['recall'])}"
        host = f"{_fmt(g['host']['precision'])}/{_fmt(g['host']['recall'])}"
        lines.append(
            f"| {r['slug']} | {r['expected']} | {r['produced']} | {r['tp']} | {len(r['fp'])} | {len(r['fn'])} | "
            f"{len(r['garbage'])} | {net} | {host} | {_fmt(r['role_accuracy'])} | {_fmt(r['attribution_recall'])} |"
        )
    for r in results:
        if not (r["fp"] or r["fn"] or r["garbage"]):
            continue
        lines += ["", f"## {r['slug']} — {r.get('title', '')}"]
        if r["garbage"]:
            lines += ["", "**Garbage (must_not hits):**"] + [
                f"- `{x['kind']}` `{x['value']}`" for x in r["garbage"]
            ]
        if r["fp"]:
            lines += ["", "**False positives:**"] + [
                f"- `{x['kind']}` `{x['value']}` role={x['role']} — {x['evidence']}"
                for x in r["fp"]
            ]
        if r["fn"]:
            lines += ["", "**Missed:**"] + [
                f"- `{x['kind']}` `{x['value']}`" for x in r["fn"]
            ]
    return "\n".join(lines) + "\n"


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--offline",
        action="store_true",
        help="score the stored current analysis instead of calling the model",
    )
    ap.add_argument(
        "--store",
        action="store_true",
        help="commit the new AIResult rows (default: roll back)",
    )
    ap.add_argument("--only", action="append", default=None, help="case slug(s) to run")
    ap.add_argument(
        "--dump-prompt",
        action="store_true",
        help="write each rendered prompt body next to the report",
    )
    ap.add_argument("--report", default="")
    args = ap.parse_args()
    results = await run(args)
    report = render_report(results, "offline" if args.offline else "live")
    if args.report:
        Path(args.report).write_text(report)
        print(f"\nreport: {args.report}")
    else:
        print("\n" + report)


if __name__ == "__main__":
    asyncio.run(main())
