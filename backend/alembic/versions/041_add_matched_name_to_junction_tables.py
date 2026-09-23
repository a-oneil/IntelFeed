"""add matched_name to entry junction tables

Revision ID: 041_matched_name
Revises: 040_seed_mitre_mitigations
Create Date: 2026-03-15 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "041_matched_name"
down_revision: str | None = "040_seed_mitre_mitigations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("entry_threat_actors", sa.Column("matched_name", sa.String(255), nullable=True))
    op.add_column("entry_malware", sa.Column("matched_name", sa.String(255), nullable=True))
    op.add_column("entry_countries", sa.Column("matched_name", sa.String(255), nullable=True))
    op.add_column("entry_tools", sa.Column("matched_name", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("entry_tools", "matched_name")
    op.drop_column("entry_countries", "matched_name")
    op.drop_column("entry_malware", "matched_name")
    op.drop_column("entry_threat_actors", "matched_name")
