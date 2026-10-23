"""Attribute every AI result to who asked for it and whose key paid.

Revision ID: f5a6b7c8d9e0
Revises: e4f5a6b7c8d9
Create Date: 2026-10-23

Schema:
  ai_results.user_id       the user the call is attributed to: the person who
                           clicked, the automation rule's author, or the
                           sharer. NULL for pipeline work and for rows older
                           than this migration. SET NULL when the user goes.
  ai_results.key_owner_id  whose personal provider answered. NULL while the
                           instance's own providers answer everything; per-user
                           caps count on this column once personal keys exist.
  ai_results.caller_kind   user | system | automation | share. Automation and
                           share traffic record a user_id but are billed as
                           pipeline, so the kind — not the id — is what the
                           cost dashboard and the provider lookup branch on.
  ai_results.provider_name the provider's name at call time, so a result still
                           says who answered after the provider row is renamed
                           or deleted.

Two indexes back the per-person lookups to come: a cap counts one person's
spend over a window, and a personal settings page lists one person's recent
calls. The dashboard's by-caller rollup reads the whole 30-day window and
uses the existing created_at index.

Rows from before this migration keep NULLs: there is no record of who ran
them, and the dashboard shows them as unattributed rather than guessing.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "f5a6b7c8d9e0"
down_revision = "e4f5a6b7c8d9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_results",
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL", name="fk_ai_results_user_id_users"),
            nullable=True,
        ),
    )
    op.add_column(
        "ai_results",
        sa.Column(
            "key_owner_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL", name="fk_ai_results_key_owner_id_users"),
            nullable=True,
        ),
    )
    op.add_column("ai_results", sa.Column("caller_kind", sa.String(length=12), nullable=True))
    op.add_column("ai_results", sa.Column("provider_name", sa.String(length=255), nullable=True))
    op.create_index("ix_ai_results_user_created", "ai_results", ["user_id", "created_at"])
    op.create_index("ix_ai_results_key_owner_created", "ai_results", ["key_owner_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_ai_results_key_owner_created", table_name="ai_results")
    op.drop_index("ix_ai_results_user_created", table_name="ai_results")
    op.drop_column("ai_results", "provider_name")
    op.drop_column("ai_results", "caller_kind")
    op.drop_column("ai_results", "key_owner_id")
    op.drop_column("ai_results", "user_id")
