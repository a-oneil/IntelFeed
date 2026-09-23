"""Per-entry pipeline stage run records (engine phase 5)."""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "q3e5f6g7h8i9"
down_revision = "p2d4e5f6g7h9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entry_pipeline_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "entry_id",
            UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("stage", sa.String(30), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("detail", JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_entry_pipeline_runs_entry_id", "entry_pipeline_runs", ["entry_id"])
    op.create_index("ix_pipeline_runs_entry_created", "entry_pipeline_runs", ["entry_id", "created_at"])


def downgrade() -> None:
    op.drop_table("entry_pipeline_runs")
