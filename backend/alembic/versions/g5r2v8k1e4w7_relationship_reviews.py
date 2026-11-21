"""Per-article relationship reviews, and a retry counter on review rows.

Revision ID: g5r2v8k1e4w7
Revises: f3x8k1u4l6n0
Create Date: 2026-11-21

An edge recorded only its settled verdict, so "asked and kept once", "asked
and demoted by one of three articles" and "asked and the model said nothing"
all read as NULL. relationship_reviews holds one row per reviewer judgment;
app/services/edge_settlement.py derives the edge's verdict from them.
Existing keeps (reviewer_kept_entry_ids) and applied demotes
(entity_maintenance_log) are copied in as counted rows.
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "g5r2v8k1e4w7"
down_revision = "f3x8k1u4l6n0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "relationship_reviews",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "relationship_id",
            UUID(as_uuid=True),
            sa.ForeignKey("entity_relationships.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("entry_id", UUID(as_uuid=True)),
        sa.Column("feed_id", UUID(as_uuid=True)),
        sa.Column("reviewer", sa.String(20), nullable=False),
        sa.Column("verdict", sa.String(20), nullable=False),
        sa.Column("confidence", sa.String(10)),
        sa.Column("reason", sa.Text()),
        sa.Column("quote", sa.Text()),
        sa.Column("suggested_verb", sa.String(30)),
        sa.Column("flipped", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("counted", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("ai_result_id", UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_relationship_reviews_relationship_id", "relationship_reviews", ["relationship_id"])
    op.create_index("ix_relationship_reviews_entry_id", "relationship_reviews", ["entry_id"])
    op.add_column(
        "ai_analysis_requests",
        sa.Column("adjudication_retries", sa.Integer(), nullable=False, server_default="0"),
    )
    # History: every counted keep, and every applied demote still standing.
    op.execute(
        """
        INSERT INTO relationship_reviews (id, relationship_id, entry_id, feed_id, reviewer, verdict,
                                          confidence, counted, created_at)
        SELECT gen_random_uuid(), r.id, k.entry_id, e.feed_id, 'adjudicator', 'keep', 'high', true,
               coalesce(r.adjudicated_at, r.updated_at)
        FROM entity_relationships r
        CROSS JOIN LATERAL unnest(r.reviewer_kept_entry_ids) AS k(entry_id)
        LEFT JOIN entries e ON e.id = k.entry_id
        """
    )
    op.execute(
        """
        INSERT INTO relationship_reviews (id, relationship_id, entry_id, feed_id, reviewer, verdict,
                                          confidence, reason, counted, ai_result_id, created_at)
        SELECT gen_random_uuid(), r.id, (l.before->>'entry_id')::uuid, e.feed_id, 'adjudicator', 'demote',
               'high', l.reasoning, true, l.ai_result_id, l.created_at
        FROM entity_maintenance_log l
        JOIN entity_relationships r ON r.id = l.entity_id AND r.adjudication_verdict = 'coincidental'
        LEFT JOIN entries e ON e.id = (l.before->>'entry_id')::uuid
        WHERE l.action = 'adjudication_edge_demote' AND l.applied
          AND l.before->>'entry_id' ~ '^[0-9a-f-]{36}$'
        """
    )


def downgrade() -> None:
    op.drop_column("ai_analysis_requests", "adjudication_retries")
    op.drop_index("ix_relationship_reviews_entry_id", table_name="relationship_reviews")
    op.drop_index("ix_relationship_reviews_relationship_id", table_name="relationship_reviews")
    op.drop_table("relationship_reviews")
