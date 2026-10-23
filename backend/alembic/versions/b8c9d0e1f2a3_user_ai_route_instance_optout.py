"""A personal route may name no key: "use the instance's provider for this task".

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-10-23

With a default key set, every allowed task runs on it. A person whose default
key has no tool loop still wants copilot on the instance's Ollama, and the
only escape was deleting the default. user_ai_routes.provider_id becomes
nullable: a per-task row with no provider is that task's opt-out back to the
instance's provider. The lookup treats it as "no key" for the task (so the
Required policy still refuses), without a fallback reason, since it is the
person's choice rather than a key that failed.
"""

import sqlalchemy as sa

from alembic import op

revision = "b8c9d0e1f2a3"
down_revision = "a7b8c9d0e1f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("user_ai_routes", "provider_id", nullable=True)
    op.alter_column("user_ai_routes", "model_name", nullable=True)


def downgrade() -> None:
    # Opt-out rows have no provider to keep; they go with the column's NOT NULL.
    op.execute(sa.text("DELETE FROM user_ai_routes WHERE provider_id IS NULL"))
    op.alter_column("user_ai_routes", "model_name", nullable=False)
    op.alter_column("user_ai_routes", "provider_id", nullable=False)
