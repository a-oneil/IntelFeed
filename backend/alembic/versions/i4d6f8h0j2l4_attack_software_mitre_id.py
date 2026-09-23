"""Add mitre_id to malware_families and tools

ATT&CK publishes software IDs (S0039) for the malware and tool objects it
tracks, the same way it publishes G-numbers for groups. ThreatActor already had
a mitre_id column; malware and tools did not, so the catalog hydration had
nowhere to put the identifier.

Revision ID: i4d6f8h0j2l4
Revises: h3c5e7g9i1k3
Create Date: 2026-08-30
"""

import sqlalchemy as sa

from alembic import op

revision = "i4d6f8h0j2l4"
down_revision = "h3c5e7g9i1k3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("malware_families", "tools"):
        op.add_column(table, sa.Column("mitre_id", sa.String(20), nullable=True))
        op.create_index(f"ix_{table}_mitre_id", table, ["mitre_id"])


def downgrade() -> None:
    for table in ("malware_families", "tools"):
        op.drop_index(f"ix_{table}_mitre_id", table_name=table)
        op.drop_column(table, "mitre_id")
