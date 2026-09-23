"""add campaign_saved_searches table

Revision ID: 034_campaign_saved_searches
Revises: 033_add_sdk_session_id
Create Date: 2026-03-13

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "034_campaign_saved_searches"
down_revision: str | None = "033_add_sdk_session_id"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "campaign_saved_searches",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "campaign_id",
            UUID(as_uuid=True),
            sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "saved_search_id",
            UUID(as_uuid=True),
            sa.ForeignKey("saved_searches.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("auto_sync", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("entries_added", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("added_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("campaign_id", "saved_search_id", name="uq_campaign_saved_search"),
    )


def downgrade() -> None:
    op.drop_table("campaign_saved_searches")
