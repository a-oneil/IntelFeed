"""seed heatmap CSS variables into existing themes for Atlas calendar

Revision ID: n1a2b3c4d5f4
Revises: n1a2b3c4d5f3
Create Date: 2026-05-02 00:00:01.000000

"""

import json

from sqlalchemy import text

from alembic import op

revision = "n1a2b3c4d5f4"
down_revision = "n1a2b3c4d5f3"
branch_labels = None
depends_on = None


DARK_PALETTE = {
    "heatmap-empty": "rgba(255,255,255,0.04)",
    "heatmap-1": "#0e4429",
    "heatmap-2": "#006d32",
    "heatmap-3": "#26a641",
    "heatmap-4": "#39d353",
    "heatmap-5": "#56e373",
}

LIGHT_PALETTE = {
    "heatmap-empty": "rgba(0,0,0,0.04)",
    "heatmap-1": "#d4e9d4",
    "heatmap-2": "#a3d9a5",
    "heatmap-3": "#6bbf76",
    "heatmap-4": "#3a9b4f",
    "heatmap-5": "#1d6e2c",
}

DARK_KEYWORDS = (
    "dark",
    "dracula",
    "nord",
    "tokyo night",
    "catppuccin",
    "gruvbox dark",
    "solarized dark",
    "one dark",
    "github dark",
)

HEATMAP_KEYS = (
    "heatmap-empty",
    "heatmap-1",
    "heatmap-2",
    "heatmap-3",
    "heatmap-4",
    "heatmap-5",
)


def _is_dark_theme(name: str) -> bool:
    lowered = (name or "").lower()
    return any(keyword in lowered for keyword in DARK_KEYWORDS)


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(text("SELECT id, name, css_variables FROM themes")).fetchall()

    for row in rows:
        theme_id = row[0]
        name = row[1] or ""
        css_variables = row[2] or {}

        if isinstance(css_variables, str):
            try:
                css_variables = json.loads(css_variables)
            except (TypeError, ValueError):
                css_variables = {}

        # Idempotent: skip themes that already have heatmap-1 set.
        if "heatmap-1" in css_variables:
            continue

        palette = DARK_PALETTE if _is_dark_theme(name) else LIGHT_PALETTE
        merged = dict(css_variables)
        for key, value in palette.items():
            if key not in merged:
                merged[key] = value

        bind.execute(
            text("UPDATE themes SET css_variables = :merged WHERE id = :id"),
            {"merged": json.dumps(merged), "id": theme_id},
        )


def downgrade() -> None:
    bind = op.get_bind()
    expression = "css_variables"
    for key in HEATMAP_KEYS:
        expression += f" - '{key}'"
    bind.execute(text(f"UPDATE themes SET css_variables = {expression}"))
