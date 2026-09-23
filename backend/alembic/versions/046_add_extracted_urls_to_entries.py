"""Add extracted_urls JSONB column to entries

Revision ID: 046
Revises: 045
Create Date: 2026-03-15

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "046"
down_revision: str | None = "045"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("entries", sa.Column("extracted_urls", JSONB, server_default="[]", nullable=False))


def downgrade() -> None:
    op.drop_column("entries", "extracted_urls")
