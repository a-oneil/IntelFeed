"""Add extract_detection_rules to feeds

Revision ID: 043
Revises: 042
Create Date: 2026-03-15

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "043"
down_revision: str | None = "042"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("feeds", sa.Column("extract_detection_rules", sa.Boolean(), nullable=False, server_default="false"))


def downgrade() -> None:
    op.drop_column("feeds", "extract_detection_rules")
