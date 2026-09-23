"""Phase 6: Dashboards, themes, newsletters

Revision ID: 008
Revises: 007
Create Date: 2026-03-04
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


# Built-in theme definitions
SYSTEM_THEMES = [
    {
        "name": "Dark",
        "css_variables": {
            "bg-primary": "#0f1419",
            "bg-secondary": "#1a1f2e",
            "bg-tertiary": "#242938",
            "bg-hover": "#2a3040",
            "text-primary": "#e4e8f0",
            "text-secondary": "#8b95a5",
            "text-muted": "#5c6575",
            "accent": "#4f8ff7",
            "accent-hover": "#3a7be0",
            "border": "#2a3040",
            "danger": "#e74c3c",
            "success": "#27ae60",
            "warning": "#f39c12",
            "sidebar-bg": "#1a1f2e",
            "sidebar-hover": "#242938",
            "sidebar-active": "#2a3040",
            "card-bg": "#1a1f2e",
            "card-border": "#2a3040",
            "severity-critical": "#ef4444",
            "severity-high": "#f97316",
            "severity-medium": "#eab308",
            "severity-low": "#22c55e",
            "severity-info": "#3b82f6",
        },
    },
    {
        "name": "Light",
        "css_variables": {
            "bg-primary": "#ffffff",
            "bg-secondary": "#f8f9fa",
            "bg-tertiary": "#e9ecef",
            "bg-hover": "#dee2e6",
            "text-primary": "#212529",
            "text-secondary": "#495057",
            "text-muted": "#868e96",
            "accent": "#1a56db",
            "accent-hover": "#1648b8",
            "border": "#dee2e6",
            "danger": "#dc3545",
            "success": "#28a745",
            "warning": "#ffc107",
            "sidebar-bg": "#f8f9fa",
            "sidebar-hover": "#e9ecef",
            "sidebar-active": "#dee2e6",
            "card-bg": "#ffffff",
            "card-border": "#dee2e6",
            "severity-critical": "#dc3545",
            "severity-high": "#fd7e14",
            "severity-medium": "#ffc107",
            "severity-low": "#28a745",
            "severity-info": "#0d6efd",
        },
    },
    {
        "name": "Nord",
        "css_variables": {
            "bg-primary": "#2e3440",
            "bg-secondary": "#3b4252",
            "bg-tertiary": "#434c5e",
            "bg-hover": "#4c566a",
            "text-primary": "#eceff4",
            "text-secondary": "#d8dee9",
            "text-muted": "#81a1c1",
            "accent": "#88c0d0",
            "accent-hover": "#8fbcbb",
            "border": "#4c566a",
            "danger": "#bf616a",
            "success": "#a3be8c",
            "warning": "#ebcb8b",
            "sidebar-bg": "#3b4252",
            "sidebar-hover": "#434c5e",
            "sidebar-active": "#4c566a",
            "card-bg": "#3b4252",
            "card-border": "#4c566a",
            "severity-critical": "#bf616a",
            "severity-high": "#d08770",
            "severity-medium": "#ebcb8b",
            "severity-low": "#a3be8c",
            "severity-info": "#5e81ac",
        },
    },
    {
        "name": "Dracula",
        "css_variables": {
            "bg-primary": "#282a36",
            "bg-secondary": "#21222c",
            "bg-tertiary": "#343746",
            "bg-hover": "#44475a",
            "text-primary": "#f8f8f2",
            "text-secondary": "#c0c0c0",
            "text-muted": "#6272a4",
            "accent": "#bd93f9",
            "accent-hover": "#caa9fa",
            "border": "#44475a",
            "danger": "#ff5555",
            "success": "#50fa7b",
            "warning": "#f1fa8c",
            "sidebar-bg": "#21222c",
            "sidebar-hover": "#343746",
            "sidebar-active": "#44475a",
            "card-bg": "#21222c",
            "card-border": "#44475a",
            "severity-critical": "#ff5555",
            "severity-high": "#ffb86c",
            "severity-medium": "#f1fa8c",
            "severity-low": "#50fa7b",
            "severity-info": "#8be9fd",
        },
    },
    {
        "name": "Solarized Dark",
        "css_variables": {
            "bg-primary": "#002b36",
            "bg-secondary": "#073642",
            "bg-tertiary": "#0a4050",
            "bg-hover": "#0d4f5f",
            "text-primary": "#fdf6e3",
            "text-secondary": "#93a1a1",
            "text-muted": "#657b83",
            "accent": "#268bd2",
            "accent-hover": "#2aa1f5",
            "border": "#0d4f5f",
            "danger": "#dc322f",
            "success": "#859900",
            "warning": "#b58900",
            "sidebar-bg": "#073642",
            "sidebar-hover": "#0a4050",
            "sidebar-active": "#0d4f5f",
            "card-bg": "#073642",
            "card-border": "#0d4f5f",
            "severity-critical": "#dc322f",
            "severity-high": "#cb4b16",
            "severity-medium": "#b58900",
            "severity-low": "#859900",
            "severity-info": "#268bd2",
        },
    },
    {
        "name": "Solarized Light",
        "css_variables": {
            "bg-primary": "#fdf6e3",
            "bg-secondary": "#eee8d5",
            "bg-tertiary": "#ddd6c1",
            "bg-hover": "#d0c9b5",
            "text-primary": "#073642",
            "text-secondary": "#586e75",
            "text-muted": "#93a1a1",
            "accent": "#268bd2",
            "accent-hover": "#2176ad",
            "border": "#d0c9b5",
            "danger": "#dc322f",
            "success": "#859900",
            "warning": "#b58900",
            "sidebar-bg": "#eee8d5",
            "sidebar-hover": "#ddd6c1",
            "sidebar-active": "#d0c9b5",
            "card-bg": "#fdf6e3",
            "card-border": "#d0c9b5",
            "severity-critical": "#dc322f",
            "severity-high": "#cb4b16",
            "severity-medium": "#b58900",
            "severity-low": "#859900",
            "severity-info": "#268bd2",
        },
    },
    {
        "name": "Catppuccin Mocha",
        "css_variables": {
            "bg-primary": "#1e1e2e",
            "bg-secondary": "#181825",
            "bg-tertiary": "#313244",
            "bg-hover": "#45475a",
            "text-primary": "#cdd6f4",
            "text-secondary": "#bac2de",
            "text-muted": "#6c7086",
            "accent": "#cba6f7",
            "accent-hover": "#b4befe",
            "border": "#45475a",
            "danger": "#f38ba8",
            "success": "#a6e3a1",
            "warning": "#f9e2af",
            "sidebar-bg": "#181825",
            "sidebar-hover": "#313244",
            "sidebar-active": "#45475a",
            "card-bg": "#181825",
            "card-border": "#45475a",
            "severity-critical": "#f38ba8",
            "severity-high": "#fab387",
            "severity-medium": "#f9e2af",
            "severity-low": "#a6e3a1",
            "severity-info": "#89b4fa",
        },
    },
    {
        "name": "Gruvbox Dark",
        "css_variables": {
            "bg-primary": "#282828",
            "bg-secondary": "#1d2021",
            "bg-tertiary": "#3c3836",
            "bg-hover": "#504945",
            "text-primary": "#ebdbb2",
            "text-secondary": "#d5c4a1",
            "text-muted": "#928374",
            "accent": "#d79921",
            "accent-hover": "#fabd2f",
            "border": "#504945",
            "danger": "#cc241d",
            "success": "#98971a",
            "warning": "#d79921",
            "sidebar-bg": "#1d2021",
            "sidebar-hover": "#3c3836",
            "sidebar-active": "#504945",
            "card-bg": "#1d2021",
            "card-border": "#504945",
            "severity-critical": "#cc241d",
            "severity-high": "#d65d0e",
            "severity-medium": "#d79921",
            "severity-low": "#98971a",
            "severity-info": "#458588",
        },
    },
    {
        "name": "Tokyo Night",
        "css_variables": {
            "bg-primary": "#1a1b26",
            "bg-secondary": "#16161e",
            "bg-tertiary": "#24283b",
            "bg-hover": "#2f3549",
            "text-primary": "#c0caf5",
            "text-secondary": "#a9b1d6",
            "text-muted": "#565f89",
            "accent": "#7aa2f7",
            "accent-hover": "#89b4fa",
            "border": "#2f3549",
            "danger": "#f7768e",
            "success": "#9ece6a",
            "warning": "#e0af68",
            "sidebar-bg": "#16161e",
            "sidebar-hover": "#24283b",
            "sidebar-active": "#2f3549",
            "card-bg": "#16161e",
            "card-border": "#2f3549",
            "severity-critical": "#f7768e",
            "severity-high": "#ff9e64",
            "severity-medium": "#e0af68",
            "severity-low": "#9ece6a",
            "severity-info": "#7aa2f7",
        },
    },
]


def upgrade() -> None:
    # Themes
    themes_table = op.create_table(
        "themes",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("css_variables", JSONB, nullable=False),
        sa.Column("is_system", sa.Boolean, server_default=sa.text("FALSE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Seed system themes
    op.bulk_insert(
        themes_table,
        [{"name": t["name"], "css_variables": t["css_variables"], "is_system": True} for t in SYSTEM_THEMES],
    )

    # Add theme columns to users
    op.add_column(
        "users",
        sa.Column("theme_id", UUID(as_uuid=True), sa.ForeignKey("themes.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column("users", sa.Column("custom_css", sa.Text, nullable=True))

    # Dashboards
    op.create_table(
        "dashboards",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("layout", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("is_default", sa.Boolean, server_default=sa.text("FALSE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_dashboards_user", "dashboards", ["user_id"])

    # Dashboard Widgets
    op.create_table(
        "dashboard_widgets",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "dashboard_id", UUID(as_uuid=True), sa.ForeignKey("dashboards.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("widget_type", sa.String(50), nullable=False),
        sa.Column("title", sa.String(255), nullable=True),
        sa.Column("config", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("position_x", sa.Integer, server_default=sa.text("0"), nullable=False),
        sa.Column("position_y", sa.Integer, server_default=sa.text("0"), nullable=False),
        sa.Column("width", sa.Integer, server_default=sa.text("4"), nullable=False),
        sa.Column("height", sa.Integer, server_default=sa.text("3"), nullable=False),
    )
    op.create_index("idx_dashboard_widgets_dashboard", "dashboard_widgets", ["dashboard_id"])


def downgrade() -> None:
    op.drop_table("dashboard_widgets")
    op.drop_table("dashboards")
    op.drop_column("users", "custom_css")
    op.drop_column("users", "theme_id")
    op.drop_table("themes")
