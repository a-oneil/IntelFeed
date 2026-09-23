"""replace matched_name with matched_names array on junction tables

Revision ID: 061_matched_names_array
Revises: m1a2b3c4d5f2
Create Date: 2026-04-28 00:00:00.000000
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY

from alembic import op

revision = "061_matched_names_array"
down_revision = "m1a2b3c4d5f2"
branch_labels = None
depends_on = None

TABLES = [
    "entry_threat_actors",
    "entry_malware",
    "entry_countries",
    "entry_tools",
    "entry_vendors",
    "entry_products",
]


def upgrade() -> None:
    for table in TABLES:
        op.add_column(table, sa.Column("matched_names", ARRAY(sa.Text), nullable=True))
        op.execute(f"UPDATE {table} SET matched_names = ARRAY[matched_name] WHERE matched_name IS NOT NULL")
        op.drop_column(table, "matched_name")


def downgrade() -> None:
    for table in TABLES:
        op.add_column(table, sa.Column("matched_name", sa.String(255), nullable=True))
        op.execute(
            f"UPDATE {table} SET matched_name = matched_names[1] "
            f"WHERE matched_names IS NOT NULL AND array_length(matched_names, 1) > 0"
        )
        op.drop_column(table, "matched_names")
