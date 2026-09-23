"""TTP ATT&CK catalog fields

Adds columns needed for full MITRE ATT&CK catalog hydration (Enterprise +
Mobile + ICS): multi-tactic list, parent/sub-technique linkage, a
deprecated/revoked flag with the replacement technique, and the matrix
domain the technique belongs to.

Bulk hydration itself is NOT done here — it runs via
scripts/seed/seed_mitre_attack.py or the weekly mitre-attack-sync beat task so it
can also be (re)run on prod without a migration.

Revision ID: e2a2b3c4d5g1
Revises: d2a2b3c4d5g0
Create Date: 2026-07-04

"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "e2a2b3c4d5g1"
down_revision = "d2a2b3c4d5g0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ttps", sa.Column("tactics", JSONB(), nullable=True))
    op.add_column("ttps", sa.Column("parent_technique_id", sa.String(length=20), nullable=True))
    op.add_column(
        "ttps",
        sa.Column("is_deprecated", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("ttps", sa.Column("superseded_by", sa.String(length=20), nullable=True))
    op.add_column("ttps", sa.Column("matrix_domain", sa.String(length=20), nullable=True))
    op.create_index("ix_ttps_parent_technique_id", "ttps", ["parent_technique_id"])
    op.create_index("ix_ttps_matrix_domain", "ttps", ["matrix_domain"])


def downgrade() -> None:
    op.drop_index("ix_ttps_matrix_domain", table_name="ttps")
    op.drop_index("ix_ttps_parent_technique_id", table_name="ttps")
    op.drop_column("ttps", "matrix_domain")
    op.drop_column("ttps", "superseded_by")
    op.drop_column("ttps", "is_deprecated")
    op.drop_column("ttps", "parent_technique_id")
    op.drop_column("ttps", "tactics")
