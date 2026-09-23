"""Add execution_mode to ai_task_assignments

Revision ID: 029_add_execution_mode
Revises: 028_enrichment_budget_conf
Create Date: 2026-03-12
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "029_add_execution_mode"
down_revision: str | None = "028_enrichment_budget_conf"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "ai_task_assignments",
        sa.Column("execution_mode", sa.String(10), server_default="api", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("ai_task_assignments", "execution_mode")
