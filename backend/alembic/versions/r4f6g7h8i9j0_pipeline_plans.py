"""Pipeline plans (engine phase 6, step c — data-defined stage composition).

Creates the table and a global default plan. The legacy Feed booleans stay
authoritative as the resolution base layer until a follow-up migration drops
them (after the pipeline_engine_enabled verification window).
"""

import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "r4f6g7h8i9j0"
down_revision = "q3e5f6g7h8i9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pipeline_plans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("scope_type", sa.String(10), nullable=False),
        sa.Column("scope_id", UUID(as_uuid=True), nullable=True),
        sa.Column("stages", JSONB(), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("scope_type", "scope_id", name="uq_pipeline_plan_scope"),
    )
    op.execute(
        text(
            """
            INSERT INTO pipeline_plans (id, name, scope_type, scope_id, stages, is_active)
            VALUES (gen_random_uuid(), 'Global default', 'global', NULL, '{}', true)
            """
        )
    )


def downgrade() -> None:
    op.drop_table("pipeline_plans")
