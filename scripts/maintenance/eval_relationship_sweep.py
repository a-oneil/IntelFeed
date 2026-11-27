"""Measure the edge sweep against hand labels before letting it apply.

The sweep (app/services/relationship_sweep.py) changes the graph only in
apply mode. Before switching that on, run its prompt over edges someone has
labeled against their articles and see how often it is right. Nothing is
written to the graph: each edge is judged exactly as a sweep run would judge
it (same passages, same quote rule), and the answer is compared with the
label.

Labels are a JSON list of objects:

    {"edge_id": "...", "decision": "correct" | "wrong_verb" | "wrong_direction"
                                   | "not_asserted" | "wrong_entity" | "cannot_tell",
     "right_verb": "attributed_to" | null}

Answers are appended to ``--out`` (JSON lines) as they come, so a long run
can stop and pick up where it left off; ``--report`` prints the scores from
that file without calling the model.

Each edge is one model call on the instance's assigned provider, competing
with the AI worker for it. Start with --limit.

    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/eval_relationship_sweep.py /tmp/labels.json --out /tmp/sweep_eval.jsonl --limit 100
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/eval_relationship_sweep.py /tmp/labels.json --out /tmp/sweep_eval.jsonl --report
"""

import argparse
import asyncio
import json
import random
import sys
import uuid
from collections import Counter
from pathlib import Path

sys.path.insert(0, "/app")

# The sweep's decision for each label: what a right answer looks like.
_RIGHT = {
    "correct": {"asserted"},
    "wrong_verb": {"wrong_verb"},
    "wrong_direction": {"wrong_direction", "wrong_verb"},
    "not_asserted": {"not_asserted", "wrong_entity"},
    "wrong_entity": {"wrong_entity", "not_asserted"},
    "cannot_tell": {"unsure"},
}
_REJECTS = {"not_asserted", "wrong_entity"}
_CORRECTIONS = {"wrong_verb", "wrong_direction"}


def _load(path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                out[row["edge_id"]] = row
    return out


def report(rows: list[dict], floor: str) -> None:
    rank = {"low": 0, "medium": 1, "high": 2}
    acted = [r for r in rows if r["decision"] != "unsure" and rank.get(r["confidence"], 0) >= rank[floor]]
    print(f"answers: {len(rows)}   acted on at {floor}: {len(acted)} ({len(acted) / max(1, len(rows)):.0%})")
    print("\nlabel × answer (all confidences):")
    grid = Counter((r["label"], r["decision"]) for r in rows)
    answers = sorted({d for _, d in grid})
    print(f"  {'label':<16}" + "".join(f"{a:>16}" for a in answers))
    for label in sorted({lab for lab, _ in grid}):
        print(f"  {label:<16}" + "".join(f"{grid.get((label, a), 0):>16}" for a in answers))

    def precision(name: str, picked: list[dict], ok) -> None:
        right = sum(1 for r in picked if ok(r))
        share = f"{right / len(picked):.1%}" if picked else "n/a"
        print(f"  {name:<38} {right:>4} / {len(picked):<4} {share}")

    print(f"\nprecision of what it would change (at {floor}):")
    precision(
        "keeps (label correct)",
        [r for r in acted if r["decision"] == "asserted"],
        lambda r: r["label"] == "correct",
    )
    precision(
        "hides (label not stated / wrong end)",
        [r for r in acted if r["decision"] in _REJECTS],
        lambda r: r["label"] in _REJECTS,
    )
    precision(
        "hides (label anything but correct)",
        [r for r in acted if r["decision"] in _REJECTS],
        lambda r: r["label"] != "correct",
    )

    def same_fix(r: dict) -> bool:
        if r["label"] == "wrong_direction":
            return bool(r.get("flip"))
        return r["label"] == "wrong_verb" and r.get("right_verb") == r.get("suggested_verb")

    precision(
        "corrections (same corrected verb)",
        [r for r in acted if r["decision"] in _CORRECTIONS],
        same_fix,
    )
    labeled_correct = [r for r in rows if r["label"] == "correct"]
    kept = sum(1 for r in acted if r["decision"] == "asserted" and r["label"] == "correct")
    print(f"\nrecall: true claims it would keep  {kept} / {len(labeled_correct)}")
    rejected = [r for r in rows if r.get("rejected")]
    if rejected:
        print(f"answers not accepted (quote rule): {len(rejected)}  {Counter(r['rejected'] for r in rejected)}")


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("labels", type=Path)
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="answers, one JSON object per line (appended)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="judge at most this many new edges (0 = all)",
    )
    parser.add_argument("--seed", type=int, default=7, help="shuffle seed, so a --limit run is a sample")
    parser.add_argument("--floor", default="high", choices=["high", "medium", "low"])
    parser.add_argument(
        "--report",
        action="store_true",
        help="score the answers in --out; no model calls",
    )
    args = parser.parse_args()

    labels = {row["edge_id"]: row for row in json.loads(args.labels.read_text())}
    done = _load(args.out)
    if args.report:
        report([r for r in done.values() if r["edge_id"] in labels], args.floor)
        return 0

    from app.database import async_session
    from app.models.entity_relationship import EntityRelationship
    from app.services.relationship_sweep import build_case, judge
    from app.services.system_settings import _ensure_cache
    from app.services.system_user import get_system_user_id

    todo = [eid for eid in labels if eid not in done]
    random.Random(args.seed).shuffle(todo)
    if args.limit:
        todo = todo[: args.limit]
    print(f"{len(done)} answered already, judging {len(todo)}", flush=True)
    async with async_session() as db:
        await _ensure_cache(db)
        user_id = await get_system_user_id(db)
        with args.out.open("a") as out:
            for n, edge_id in enumerate(todo, 1):
                edge = await db.get(EntityRelationship, uuid.UUID(edge_id))
                case = await build_case(db, edge) if edge is not None else None
                if case is None or not case.passages:
                    print(f"  {edge_id}: gone or no articles", flush=True)
                    continue
                j, _ai_result_id, status = await judge(db, case, user_id)
                await db.commit()
                if j is None:
                    print(f"  {edge_id}: {status}", flush=True)
                    continue
                label = labels[edge_id]
                row = {
                    "edge_id": edge_id,
                    "claim": case.claim,
                    "label": label["decision"],
                    "right_verb": label.get("right_verb"),
                    "decision": j.decision,
                    "confidence": j.confidence,
                    "suggested_verb": j.suggested_verb,
                    "flip": j.flip,
                    "quote": j.quote,
                    "reason": j.reason,
                    "rejected": j.rejected,
                    "right": j.decision in _RIGHT.get(label["decision"], set()),
                }
                out.write(json.dumps(row) + "\n")
                out.flush()
                done[edge_id] = row
                if n % 10 == 0:
                    print(f"  {n}/{len(todo)}", flush=True)
    report([r for r in done.values() if r["edge_id"] in labels], args.floor)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
