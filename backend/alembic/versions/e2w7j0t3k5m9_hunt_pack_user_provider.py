"""Let the hunt_pack task run on a user's own AI provider.

Revision ID: e2w7j0t3k5m9
Revises: d1u5h8r0i2k7
Create Date: 2026-11-18

The Threats board's hunt pack is a per-user read (queries in that analyst's
preferred language) and writes no shared state, so it joins the tasks a
personal key may serve. Mirrors USER_PROVIDER_ELIGIBLE_TASKS in
app/ai/capabilities.py; spelled out here because a migration must not import
app code, and the eligibility test unions every migration's tuple.
"""

import sqlalchemy as sa

from alembic import op

revision = "e2w7j0t3k5m9"
down_revision = "d1u5h8r0i2k7"
branch_labels = None
depends_on = None

ELIGIBLE_TASKS = ("hunt_pack",)


def upgrade() -> None:
    op.execute(
        sa.text("UPDATE ai_tasks SET allows_user_provider = true WHERE name IN :names").bindparams(
            sa.bindparam("names", value=ELIGIBLE_TASKS, expanding=True)
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text("UPDATE ai_tasks SET allows_user_provider = false WHERE name IN :names").bindparams(
            sa.bindparam("names", value=ELIGIBLE_TASKS, expanding=True)
        )
    )
