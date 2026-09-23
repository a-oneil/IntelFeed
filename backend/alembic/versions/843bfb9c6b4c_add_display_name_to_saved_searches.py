"""add display_name to saved_searches

Revision ID: 843bfb9c6b4c
Revises: 015
Create Date: 2026-03-07 23:22:30.378162

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "843bfb9c6b4c"
down_revision: str | None = "015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("saved_searches", sa.Column("display_name", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("saved_searches", "display_name")
