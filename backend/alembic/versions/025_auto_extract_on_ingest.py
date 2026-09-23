"""Add auto_extract_on_ingest to feeds

Revision ID: 025_auto_extract_on_ingest
Revises: 024_glossary_search_terms_seed
Create Date: 2026-03-10
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "025_auto_extract_on_ingest"
down_revision: str | None = "024_glossary_search_terms_seed"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "feeds",
        sa.Column(
            "auto_extract_on_ingest",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("feeds", "auto_extract_on_ingest")
