"""Add job_runs.detail — clipped task args/kwargs/result so run history shows
what a job ran against, not just its name.

Revision ID: t6h8i9j0k1l2
Revises: s5g7h8i9j0k1
Create Date: 2026-07-11
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "t6h8i9j0k1l2"
down_revision = "s5g7h8i9j0k1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("job_runs", sa.Column("detail", JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("job_runs", "detail")
