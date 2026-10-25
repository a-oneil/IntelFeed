"""Dismissals that stick: "not a duplicate" pairs and "stop proposing this reclassify".

Also clears two kinds of leftovers from the retired link validator: reclassify
advisories whose suggested type is the type the entity already has ("Linux:
product → product" — the adjudicate stage never files those), and any of its
proposals older than 30 days, which nothing re-judges. The nightly
engine-tables prune keeps expiring the latter from here on. And remove-link
proposals that were applied but never left the queue.

Revision ID: f3a4b5c6d7e8
Revises: e2f3a4b5c6d7
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "f3a4b5c6d7e8"
down_revision = "e2f3a4b5c6d7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "proposal_dismissals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("entity_type", sa.String(30), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("other_key", sa.String(100), nullable=False, server_default=""),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("kind", "entity_type", "entity_id", "other_key", name="uq_proposal_dismissal"),
    )
    op.create_index("ix_proposal_dismissals_entity_id", "proposal_dismissals", ["entity_id"])
    op.execute(
        "DELETE FROM entity_link_validation_log "
        "WHERE action = 'needs_reclassification' AND suggested_entity_type = entity_type"
    )
    op.execute(
        """
        DELETE FROM entity_link_validation_log l
        WHERE l.action IN ('shadow_remove', 'needs_reclassification')
          AND l.created_at < now() - interval '30 days'
          AND NOT EXISTS (
            SELECT 1 FROM ai_results r JOIN ai_tasks t ON t.id = r.task_id
            WHERE r.id = l.ai_result_id AND t.name = 'entry_adjudication'
          )
        """
    )
    # Remove-link proposals that were applied but never left the queue.
    op.execute(
        """
        DELETE FROM entity_link_validation_log s
        WHERE s.action = 'shadow_remove'
          AND EXISTS (
            SELECT 1 FROM entity_link_validation_log r
            WHERE r.action = 'removed' AND r.entry_id = s.entry_id AND r.entity_id = s.entity_id
              AND r.created_at > s.created_at
          )
        """
    )


def downgrade() -> None:
    op.drop_index("ix_proposal_dismissals_entity_id", table_name="proposal_dismissals")
    op.drop_table("proposal_dismissals")
