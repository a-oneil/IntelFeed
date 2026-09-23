"""known_alias_map — reference alias knowledge for entity resolution (guardrails Phase 4)

Populated by run_misp_galaxy_sync (MISP Galaxy threat-actor cluster) and the
weekly MITRE ATT&CK sync (intrusion-set aliases). The resolver consults it
between string matching and the creation gates so vendor names resolve to
existing profiles without an AI call (F4). Read-only reference data — never
auto-writes aliases to profiles.

Revision ID: f6h8j0l2n4p6
Revises: e5g7i9k1m3o5
Create Date: 2026-08-16
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "f6h8j0l2n4p6"
down_revision = "e5g7i9k1m3o5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "known_alias_map",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("canonical_name", sa.Text(), nullable=False),
        sa.Column("alias", sa.Text(), nullable=False),
        sa.Column("normalized_canonical", sa.String(255), nullable=False),
        sa.Column("normalized_alias", sa.String(255), nullable=False),
        sa.Column("source", sa.String(30), nullable=False),
        sa.UniqueConstraint("source", "normalized_canonical", "normalized_alias", name="uq_known_alias_map_row"),
    )
    op.create_index("ix_known_alias_map_alias", "known_alias_map", ["normalized_alias"])
    op.create_index("ix_known_alias_map_canonical", "known_alias_map", ["normalized_canonical"])


def downgrade() -> None:
    op.drop_table("known_alias_map")
