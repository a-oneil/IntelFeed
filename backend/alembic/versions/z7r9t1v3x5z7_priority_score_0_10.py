"""Priority score on a 0–10 scale; the raw signal sum moves to priority_raw.

Revision ID: z7r9t1v3x5z7
Revises: y6q8s0u2w4y6
Create Date: 2026-10-09

`entries.priority_score` held the signal engine's unbounded weighted sum. That
sum moves to the new `priority_raw` column (still the ordering key), and
`priority_score` becomes the sum placed on a 0–10 scale by rank against the
trailing 30 days of signal-bearing entries — the same mapping as
`app.intelligence.signals.scale_score`, copied here so this revision keeps its
meaning if the live anchors are retuned later.

Automation rules store `priority_score_above` minimums in raw units; they are
converted with the same cutoffs, wherever the condition sits (top-level
conditions or inside a branch action).
"""

import json
from decimal import ROUND_HALF_UP, Decimal

import sqlalchemy as sa
from sqlalchemy import text

from alembic import op

revision = "z7r9t1v3x5z7"
down_revision = "y6q8s0u2w4y6"
branch_labels = None
depends_on = None

# (scale value, percentile of positive raw scores) — mirrors signals.SCALE_ANCHORS.
ANCHORS = (
    (1.0, 0.00),
    (2.0, 0.15),
    (3.0, 0.30),
    (4.0, 0.45),
    (5.0, 0.60),
    (6.0, 0.72),
    (7.0, 0.82),
    (8.0, 0.90),
    (9.0, 0.95),
    (10.0, 0.99),
)
DEFAULT_CUTOFFS = (0.002, 0.19, 0.192, 0.198, 0.51, 0.82, 1.36, 1.7, 2.8, 4.9)
MIN_SAMPLE = 50


def _cutoffs(conn, column: str) -> list[float]:
    """Same rule as signals.compute_scale_cutoffs: trailing 30 days, else the defaults."""
    pcts = ", ".join(str(p) for _, p in ANCHORS)
    row = conn.execute(
        text(
            f"SELECT percentile_cont(ARRAY[{pcts}]::float8[]) WITHIN GROUP (ORDER BY {column}), count(*) "
            f"FROM entries WHERE {column} > 0 AND scored_at >= now() - interval '30 days'"
        )
    ).one()
    if row[0] and row[1] >= MIN_SAMPLE:
        return [round(float(c), 4) for c in row[0]]
    return list(DEFAULT_CUTOFFS)


def scale(raw: float, cuts: list[float]) -> float:
    if raw <= 0:
        return 0.0
    if raw <= cuts[0]:
        return 1.0
    for i in range(1, len(cuts)):
        lo, hi = cuts[i - 1], cuts[i]
        if raw < hi:
            value = ANCHORS[i - 1][0] + (raw - lo) / (hi - lo)
            # Rounded like the SQL below (half away from zero, 15 digits), not round()'s half-to-even.
            return float(Decimal(format(value, ".15g")).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))
    return 10.0


def unscale(value: float, cuts: list[float]) -> float:
    if value <= 0:
        return 0.0
    if value <= 1.0:
        return cuts[0]
    if value >= 10.0:
        return cuts[-1]
    i = int(value)
    return round(cuts[i - 1] + (value - i) * (cuts[i] - cuts[i - 1]), 4)


def _scale_case_sql(column: str, cuts: list[float]) -> str:
    parts = [f"WHEN {column} <= 0 THEN 0.0", f"WHEN {column} <= {cuts[0]} THEN 1.0"]
    for i in range(1, len(cuts)):
        lo, hi = cuts[i - 1], cuts[i]
        if hi <= lo:
            continue
        parts.append(
            f"WHEN {column} < {hi} THEN round(({ANCHORS[i - 1][0]} + ({column} - {lo}) / {hi - lo})::numeric, 1)::float8"
        )
    return "CASE " + " ".join(parts) + " ELSE 10.0 END"


def convert_rule_json(node, convert):
    """Rewrite every priority_score_above `min` found anywhere in a rule's JSON."""
    changed = False
    if isinstance(node, dict):
        if node.get("type") == "priority_score_above" and isinstance(node.get("config"), dict):
            cfg = node["config"]
            try:
                old = float(cfg.get("min", 1.0))
            except (TypeError, ValueError):
                old = None
            if old is not None:
                cfg["min"] = convert(old)
                changed = True
        for value in node.values():
            changed = convert_rule_json(value, convert) or changed
    elif isinstance(node, list):
        for value in node:
            changed = convert_rule_json(value, convert) or changed
    return changed


def _convert_rules(conn, convert) -> None:
    rows = conn.execute(
        text(
            "SELECT id, conditions, actions FROM automation_rules "
            "WHERE conditions::text LIKE '%priority_score_above%' OR actions::text LIKE '%priority_score_above%'"
        )
    ).all()
    for rule_id, conditions, actions in rows:
        conditions = conditions or {}
        actions = actions or []
        if convert_rule_json(conditions, convert) | convert_rule_json(actions, convert):
            conn.execute(
                text(
                    "UPDATE automation_rules SET conditions = CAST(:c AS jsonb), actions = CAST(:a AS jsonb) "
                    "WHERE id = :id"
                ),
                {"c": json.dumps(conditions), "a": json.dumps(actions), "id": rule_id},
            )


def upgrade() -> None:
    op.add_column("entries", sa.Column("priority_raw", sa.Float(), nullable=True))
    conn = op.get_bind()
    cuts = _cutoffs(conn, "priority_score")
    # One pass: the raw sum moves over and the scaled value replaces it.
    conn.execute(
        text(
            "UPDATE entries SET priority_raw = priority_score, "
            f"priority_score = {_scale_case_sql('priority_score', cuts)} "
            "WHERE priority_score IS NOT NULL"
        )
    )
    op.create_index("ix_entries_priority_raw", "entries", ["priority_raw"])
    _convert_rules(conn, lambda raw: scale(raw, cuts))


def downgrade() -> None:
    conn = op.get_bind()
    cuts = _cutoffs(conn, "priority_raw")
    _convert_rules(conn, lambda value: unscale(value, cuts))
    conn.execute(text("UPDATE entries SET priority_score = priority_raw WHERE priority_raw IS NOT NULL"))
    op.drop_index("ix_entries_priority_raw", table_name="entries")
    op.drop_column("entries", "priority_raw")
