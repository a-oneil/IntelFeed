"""campaign_sources — the things that feed a campaign, beyond a saved search

A campaign's only automatic intake was a linked saved search: a query kept in
parallel with the campaign and drifting away from it. This table lets a campaign
feed on what it has already declared — the entity it names as its subject, or a
story it has already accepted part of — so intake follows curation instead of a
second query language.

Revision ID: c4e6g8i0k2m4
Revises: w8y0z2a4c6e8
Create Date: 2026-09-15
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "c4e6g8i0k2m4"
down_revision = "w8y0z2a4c6e8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "campaign_sources",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_id",
            UUID(as_uuid=True),
            sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        # entity | story
        sa.Column("kind", sa.String(20), nullable=False),
        # For kind=entity: the entity type slug. Null for a story.
        sa.Column("entity_type", sa.String(32), nullable=True),
        # The entity's UUID, or the story thread's UUID.
        sa.Column("ref_id", UUID(as_uuid=True), nullable=False),
        # A label frozen at link time so the row still reads after the target is
        # renamed, merged away, or pruned — the audit trail outlives the target.
        sa.Column("label", sa.Text(), nullable=False, server_default=""),
        sa.Column("auto_sync", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("entries_added", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("added_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        # One row per target per campaign: linking the same actor twice is a
        # no-op, not two sources racing to add the same articles.
        sa.UniqueConstraint("campaign_id", "kind", "entity_type", "ref_id", name="uq_campaign_sources_target"),
    )


def downgrade() -> None:
    op.drop_table("campaign_sources")
