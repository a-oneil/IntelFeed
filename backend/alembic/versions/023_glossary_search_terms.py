"""Add search_terms column to glossary_terms

Revision ID: 023_glossary_search_terms
Revises: 022_glossary_additional_terms
Create Date: 2026-03-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "023_glossary_search_terms"
down_revision: str | None = "022_glossary_additional_terms"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "glossary_terms",
        sa.Column("search_terms", JSONB, server_default="[]", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("glossary_terms", "search_terms")
