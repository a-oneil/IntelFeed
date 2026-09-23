"""Fix global pipeline-plan upsert: make NULL scope_id conflict.

uq_pipeline_plan_scope treated NULLs as distinct, so the PUT /engine/plans
upsert never matched the global row (scope_id NULL) and every save inserted a
new "Global default" plan. Dedupe the accumulated rows (keep the most recently
updated per scope) and recreate the constraint with NULLS NOT DISTINCT.
"""

from alembic import op

revision = "v8j0k1l2m3n4"
down_revision = "u7i9j0k1l2m3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DELETE FROM pipeline_plans a
        USING pipeline_plans b
        WHERE a.scope_type = b.scope_type
          AND a.scope_id IS NOT DISTINCT FROM b.scope_id
          AND a.id != b.id
          AND (a.updated_at, a.created_at, a.id) < (b.updated_at, b.created_at, b.id)
        """
    )
    op.execute("ALTER TABLE pipeline_plans DROP CONSTRAINT uq_pipeline_plan_scope")
    op.execute(
        "ALTER TABLE pipeline_plans ADD CONSTRAINT uq_pipeline_plan_scope "
        "UNIQUE NULLS NOT DISTINCT (scope_type, scope_id)"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE pipeline_plans DROP CONSTRAINT uq_pipeline_plan_scope")
    op.execute("ALTER TABLE pipeline_plans ADD CONSTRAINT uq_pipeline_plan_scope UNIQUE (scope_type, scope_id)")
