"""Categories hold pipeline defaults that new feeds in them inherit.

``feed_defaults`` maps any of intel_extraction_mode, ai_analysis_enabled,
extract_tools, auto_extract_on_ingest and extract_detection_rules to the value
a feed added to the category starts with. A key that is absent falls back to
the global default. See app/services/feed_defaults.py.

Revision ID: e2f3a4b5c6d7
Revises: d1e2f3a4b5c6
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "e2f3a4b5c6d7"
down_revision = "d1e2f3a4b5c6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "categories",
        sa.Column("feed_defaults", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("categories", "feed_defaults")
