"""add paragraph_indices to junction tables

Revision ID: 051_paragraph_indices
Revises: f3b5239577e0
Create Date: 2026-03-17 00:00:00.000000
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY

from alembic import op

# revision identifiers, used by Alembic.
revision = "051_paragraph_indices"
down_revision = "f3b5239577e0"
branch_labels = None
depends_on = None

TABLES = [
    "entry_threat_actors",
    "entry_malware",
    "entry_ttps",
    "entry_cves",
    "entry_countries",
    "entry_tools",
    "entry_mitigations",
    "entry_iocs",
]


def upgrade() -> None:
    for table in TABLES:
        op.add_column(
            table,
            sa.Column("paragraph_indices", ARRAY(sa.SmallInteger), nullable=True),
        )


def downgrade() -> None:
    for table in TABLES:
        op.drop_column(table, "paragraph_indices")
