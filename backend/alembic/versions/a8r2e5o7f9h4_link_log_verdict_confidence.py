"""entity_link_validation_log.verdict_confidence: the adjudicator's confidence in a link verdict.

Revision ID: a8r2e5o7f9h4
Revises: z7q1d4n6e8g3
"""

import sqlalchemy as sa

from alembic import op

revision = "a8r2e5o7f9h4"
down_revision = "z7q1d4n6e8g3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("entity_link_validation_log", sa.Column("verdict_confidence", sa.String(10), nullable=True))


def downgrade() -> None:
    op.drop_column("entity_link_validation_log", "verdict_confidence")
