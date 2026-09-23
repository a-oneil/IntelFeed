"""Converted rules become real rows instead of a blob on the parent

A KQL conversion of a SIGMA rule currently lives in
metadata.rule_conversions on the parent: absent from /detection-rules/search,
absent from detection_rule_versions, not exportable on its own, and deleted with
the parent. That is precisely the feature IntelFeed exists to provide — coverage
in whatever engine you actually run — implemented as a throwaway.

derived_from makes each conversion a first-class detection_rules row sharing one
lineage. ON DELETE SET NULL rather than CASCADE: deleting a SIGMA rule should
orphan its KQL sibling, not silently destroy work someone may have edited.

Revision ID: m8h0j2l4n6p8
Revises: l7g9i1k3m5o7
Create Date: 2026-09-02
"""

import sqlalchemy as sa

from alembic import op

revision = "m8h0j2l4n6p8"
down_revision = "l7g9i1k3m5o7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "detection_rules",
        sa.Column(
            "derived_from",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("detection_rules.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_detection_rules_derived_from", "detection_rules", ["derived_from"])


def downgrade() -> None:
    op.drop_index("ix_detection_rules_derived_from", table_name="detection_rules")
    op.drop_column("detection_rules", "derived_from")
