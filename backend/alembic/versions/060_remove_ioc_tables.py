"""remove IOC tables

Revision ID: 060_remove_ioc_tables
Revises: f3b5239577e0
Create Date: 2026-04-18

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "060_remove_ioc_tables"
down_revision: str | None = "059_shared_data_model"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(sa.text('DROP TABLE IF EXISTS "entry_iocs" CASCADE'))
    op.execute(sa.text('DROP TABLE IF EXISTS "iocs" CASCADE'))


def downgrade() -> None:
    op.create_table(
        "iocs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("ioc_type", sa.String(), nullable=False, index=True),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("context", sa.Text()),
        sa.Column("confidence", sa.String(), index=True),
        sa.Column("source", sa.String()),
        sa.Column("source_text", sa.Text()),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("enrichment", JSONB, server_default="{}"),
        sa.Column("status", sa.String(), server_default="active", index=True),
        sa.Column("base_confidence", sa.Float()),
        sa.Column("current_confidence", sa.Float()),
        sa.Column("confidence_pinned", sa.Boolean(), server_default="false"),
        sa.Column("confidence_override", sa.Float()),
        sa.Column("decay_profile", sa.String()),
        sa.Column("is_false_positive", sa.Boolean(), server_default="false"),
        sa.Column("false_positive_reason", sa.Text()),
        sa.Column("false_positive_marked_by", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("false_positive_marked_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("ioc_type", "value"),
    )
    op.create_table(
        "entry_iocs",
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True),
        sa.Column(
            "ioc_id", UUID(as_uuid=True), sa.ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True, index=True
        ),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("paragraph_indices", sa.ARRAY(sa.SmallInteger())),
    )
