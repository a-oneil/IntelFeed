"""add wikipedia_image_url to entity tables

Revision ID: k1a2b3c4d5f0
Revises: j1a2b3c4d5e9
Create Date: 2026-04-22 04:30:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "k1a2b3c4d5f0"
down_revision = "j1a2b3c4d5e9"
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
        op.add_column(table, sa.Column("wikipedia_image_url", sa.Text(), nullable=True))


def downgrade() -> None:
    for table in TABLES:
        op.drop_column(table, "wikipedia_image_url")
