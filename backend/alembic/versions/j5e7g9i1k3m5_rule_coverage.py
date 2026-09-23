"""Materialised rule → entity resolution

The coverage board counts library rules with DetectionRule.source_actors /
source_cves / source_ttps .contains(), one COUNT per row inside the loop. Those
JSONB columns are only written by in-app authoring and by importers whose
upstream format happens to carry the field, so they resolve 3,996 of 11,517
rules and *zero* actors — the Actors tab reports "no rule in library yet" for
every row while the library holds 36 rules naming APT29 and 34 naming LockBit.

rule_coverage is the resolved answer, rebuilt on rule write and repo sync by
app.services.rule_coverage. `via` records which writer produced the row so a
body-text hit is never laundered into the same confidence as a repo tag.

Revision ID: j5e7g9i1k3m5
Revises: i4d6f8h0j2l4
Create Date: 2026-09-02
"""

import sqlalchemy as sa

from alembic import op

revision = "j5e7g9i1k3m5"
down_revision = "i4d6f8h0j2l4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rule_coverage",
        sa.Column(
            "rule_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("detection_rules.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("entity_type", sa.String(30), nullable=False),
        sa.Column("entity_key", sa.String(255), nullable=False),
        sa.Column("via", sa.String(10), nullable=False),
        sa.Column("confidence", sa.String(10), nullable=False),
        sa.Column("matched_on", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("rule_id", "entity_type", "entity_key"),
    )
    # The board's hot path: "which rules resolve to this entity?"
    op.create_index("ix_rule_coverage_entity", "rule_coverage", ["entity_type", "entity_key"])
    # Lets the resolver rebuild one writer's rows without touching the others.
    op.create_index("ix_rule_coverage_via", "rule_coverage", ["via"])


def downgrade() -> None:
    op.drop_index("ix_rule_coverage_via", table_name="rule_coverage")
    op.drop_index("ix_rule_coverage_entity", table_name="rule_coverage")
    op.drop_table("rule_coverage")
