"""make correlation_event entry_id nullable

Revision ID: cf799bf83445
Revises: f3b5239577e0
Create Date: 2026-03-17 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "cf799bf83445"
down_revision: str | None = "051_paragraph_indices"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "correlation_event_records",
        "entry_id",
        existing_type=sa.UUID(),
        nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "correlation_event_records",
        "entry_id",
        existing_type=sa.UUID(),
        nullable=False,
    )
