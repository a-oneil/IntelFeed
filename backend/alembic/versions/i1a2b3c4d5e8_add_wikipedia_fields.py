"""add wikipedia_url and wikipedia_content to entity tables

Revision ID: i1a2b3c4d5e8
Revises: h1a2b3c4d5e7
Create Date: 2026-04-20 06:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "i1a2b3c4d5e8"
down_revision = "h1a2b3c4d5e7"
branch_labels = None
depends_on = None

TABLES = [
    "threat_actors",
    "malware_families",
    "cves",
    "ttps",
    "countries",
    "mitigations",
    "offensive_tools",
    "vendors",
    "products",
]


def upgrade() -> None:
    for table in TABLES:
        op.add_column(table, sa.Column("wikipedia_url", sa.Text(), nullable=True))
        op.add_column(table, sa.Column("wikipedia_content", sa.Text(), nullable=True))


def downgrade() -> None:
    for table in TABLES:
        op.drop_column(table, "wikipedia_content")
        op.drop_column(table, "wikipedia_url")
