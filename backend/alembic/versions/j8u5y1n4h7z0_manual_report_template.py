"""Add the builtin Manual report template: no sections, free text only.

Revision ID: j8u5y1n4h7z0
Revises: i7t4x0m3g6y9
Create Date: 2026-11-24

Every other builtin template carries a fixed section list. This one has none,
so a report built from it is a single free-text body that the analyst writes
or pastes.
"""

import uuid

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "j8u5y1n4h7z0"
down_revision = "i7t4x0m3g6y9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    exists = conn.execute(sa.text("SELECT 1 FROM report_templates WHERE template_slug = 'manual'")).fetchone()
    if exists:
        return

    templates_table = sa.table(
        "report_templates",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("template_slug", sa.String),
        sa.column("sections", JSONB),
        sa.column("is_builtin", sa.Boolean),
        sa.column("is_shared", sa.Boolean),
    )
    op.bulk_insert(
        templates_table,
        [
            {
                "id": str(uuid.uuid4()),
                "name": "Manual",
                "description": "Blank report with no sections. Write or paste your own content.",
                "template_slug": "manual",
                "sections": [],
                "is_builtin": True,
                "is_shared": False,
            }
        ],
    )


def downgrade() -> None:
    # Only the builtin row: a user template that took the slug first is left alone.
    op.execute("DELETE FROM report_templates WHERE template_slug = 'manual' AND is_builtin = true")
