"""Add source column to entry_threat_actors and entry_malware junction tables

Revision ID: 013
Revises: 012
"""

import sqlalchemy as sa

from alembic import op

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("entry_threat_actors", sa.Column("source", sa.String(20), nullable=True))
    op.add_column("entry_malware", sa.Column("source", sa.String(20), nullable=True))
    # Backfill existing records as "ai" since that was the only extraction method
    op.execute("UPDATE entry_threat_actors SET source = 'ai' WHERE source IS NULL")
    op.execute("UPDATE entry_malware SET source = 'ai' WHERE source IS NULL")


def downgrade():
    op.drop_column("entry_malware", "source")
    op.drop_column("entry_threat_actors", "source")
