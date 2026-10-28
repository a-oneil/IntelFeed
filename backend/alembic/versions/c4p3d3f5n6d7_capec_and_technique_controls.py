"""capec_patterns, and the security controls on techniques.

``capec_patterns`` holds MITRE's CAPEC catalog (the ``capec`` source), so the
CAPEC ids CWEs carry resolve to names. ``ttps.nist_controls`` and
``ttps.cis_controls`` hold the NIST 800-53 and CIS controls CTID maps to each
technique (the ``ctid`` source).

Revision ID: c4p3d3f5n6d7
Revises: f7n2e3t4c5x6
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c4p3d3f5n6d7"
down_revision = "f7n2e3t4c5x6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "capec_patterns",
        sa.Column("capec_id", sa.String(20), primary_key=True),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("abstraction", sa.String(20), nullable=True),
        sa.Column("status", sa.String(20), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cwe_ids", postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("technique_ids", postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.add_column("ttps", sa.Column("nist_controls", postgresql.ARRAY(sa.Text()), nullable=True))
    op.add_column("ttps", sa.Column("cis_controls", postgresql.ARRAY(sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column("ttps", "cis_controls")
    op.drop_column("ttps", "nist_controls")
    op.drop_table("capec_patterns")
