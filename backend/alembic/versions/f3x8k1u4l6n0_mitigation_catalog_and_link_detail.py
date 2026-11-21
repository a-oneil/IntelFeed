"""Mitigations: mark the ATT&CK catalog, keep the article's wording on the link.

Revision ID: f3x8k1u4l6n0
Revises: e2w7j0t3k5m9
Create Date: 2026-11-20

Only ATT&CK catalog mitigations are entities; an article's own advice
("upgrade X to 1.3.2") is stored as ``entry_mitigations.detail`` on its link to
the catalog mitigation it falls under. ``is_catalog`` marks the rows the
ATT&CK import owns: a current M-ID whose URL is that M-ID's ATT&CK page. An
AI-written row with an invented M-ID has no such URL, and the old
"<technique> Mitigation" rows carry T-numbers, so neither is backfilled.
"""

import sqlalchemy as sa

from alembic import op

revision = "f3x8k1u4l6n0"
down_revision = "e2w7j0t3k5m9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "mitigations",
        sa.Column("is_catalog", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_mitigations_is_catalog", "mitigations", ["is_catalog"])
    op.execute(
        "UPDATE mitigations SET is_catalog = true "
        "WHERE mitre_id ~ '^M[0-9]{4}$' "
        "AND mitre_url = 'https://attack.mitre.org/mitigations/' || mitre_id"
    )
    op.add_column("entry_mitigations", sa.Column("detail", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("entry_mitigations", "detail")
    op.drop_index("ix_mitigations_is_catalog", table_name="mitigations")
    op.drop_column("mitigations", "is_catalog")
