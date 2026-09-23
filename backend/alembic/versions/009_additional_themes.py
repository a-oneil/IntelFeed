"""Add new themes (GitHub Dark, One Dark Pro), accent-text variable, user_id on themes

Revision ID: 009
Revises: 008
Create Date: 2026-03-04
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None

# accent-text values for existing themes (keyed by theme name)
ACCENT_TEXT_VALUES = {
    "Dark": "#ffffff",
    "Light": "#ffffff",
    "Nord": "#2e3440",
    "Dracula": "#282a36",
    "Solarized Dark": "#ffffff",
    "Solarized Light": "#ffffff",
    "Catppuccin Mocha": "#1e1e2e",
    "Gruvbox Dark": "#282828",
    "Tokyo Night": "#1a1b26",
}

NEW_THEMES = [
    {
        "name": "GitHub Dark",
        "css_variables": {
            "bg-primary": "#0d1117",
            "bg-secondary": "#161b22",
            "bg-tertiary": "#21262d",
            "bg-hover": "#30363d",
            "text-primary": "#e6edf3",
            "text-secondary": "#8b949e",
            "text-muted": "#484f58",
            "accent": "#f78166",
            "accent-hover": "#ffa28b",
            "accent-text": "#ffffff",
            "border": "#30363d",
            "danger": "#f85149",
            "success": "#3fb950",
            "warning": "#d29922",
            "sidebar-bg": "#010409",
            "sidebar-hover": "#161b22",
            "sidebar-active": "#21262d",
            "card-bg": "#161b22",
            "card-border": "#30363d",
            "severity-critical": "#f85149",
            "severity-high": "#f0883e",
            "severity-medium": "#d29922",
            "severity-low": "#3fb950",
            "severity-info": "#58a6ff",
        },
    },
    {
        "name": "One Dark Pro",
        "css_variables": {
            "bg-primary": "#282c34",
            "bg-secondary": "#21252b",
            "bg-tertiary": "#2c313a",
            "bg-hover": "#383e4a",
            "text-primary": "#abb2bf",
            "text-secondary": "#828997",
            "text-muted": "#5c6370",
            "accent": "#61afef",
            "accent-hover": "#82c4f8",
            "accent-text": "#282c34",
            "border": "#3e4452",
            "danger": "#e06c75",
            "success": "#98c379",
            "warning": "#e5c07b",
            "sidebar-bg": "#21252b",
            "sidebar-hover": "#2c313a",
            "sidebar-active": "#383e4a",
            "card-bg": "#21252b",
            "card-border": "#3e4452",
            "severity-critical": "#e06c75",
            "severity-high": "#d19a66",
            "severity-medium": "#e5c07b",
            "severity-low": "#98c379",
            "severity-info": "#61afef",
        },
    },
]


def upgrade() -> None:
    # 1. Add user_id column to themes (nullable, for user-created themes)
    op.add_column(
        "themes",
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )

    # 2. Drop the unique constraint on theme name (users can have same-named custom themes)
    op.drop_constraint("themes_name_key", "themes", type_="unique")

    # 3. Add accent-text to existing themes
    conn = op.get_bind()
    for theme_name, accent_text in ACCENT_TEXT_VALUES.items():
        conn.execute(
            sa.text(
                "UPDATE themes SET css_variables = css_variables || :patch WHERE name = :name AND is_system = TRUE"
            ),
            {"patch": f'{{"accent-text": "{accent_text}"}}', "name": theme_name},
        )

    # 4. Insert new system themes
    themes_table = sa.table(
        "themes",
        sa.column("name", sa.String),
        sa.column("css_variables", sa.JSON),
        sa.column("is_system", sa.Boolean),
    )
    op.bulk_insert(
        themes_table,
        [{"name": t["name"], "css_variables": t["css_variables"], "is_system": True} for t in NEW_THEMES],
    )


def downgrade() -> None:
    # Remove new themes
    conn = op.get_bind()
    for t in NEW_THEMES:
        conn.execute(sa.text("DELETE FROM themes WHERE name = :name AND is_system = TRUE"), {"name": t["name"]})

    # Remove accent-text from existing themes
    for theme_name in ACCENT_TEXT_VALUES:
        conn.execute(
            sa.text(
                "UPDATE themes SET css_variables = css_variables - 'accent-text' WHERE name = :name AND is_system = TRUE"
            ),
            {"name": theme_name},
        )

    # Re-add unique constraint
    op.create_unique_constraint("themes_name_key", "themes", ["name"])

    # Remove user_id column
    op.drop_column("themes", "user_id")
