"""Personal AI providers: who owns a key, which tasks may use one, and who routes where.

Revision ID: a7b8c9d0e1f2
Revises: f5a6b7c8d9e0
Create Date: 2026-10-23

Schema:
  ai_providers.user_id            NULL = the instance's provider, as every row is
                                  today. A uuid = one person's key: listed, tested
                                  and routed by them alone, deleted with them.
  ai_tasks.allows_user_provider   whether a person's key may answer this task. Set
                                  here for the fourteen tasks whose result belongs
                                  to the person who clicked; false for everything
                                  that writes shared state (entity links, verdicts,
                                  briefs, spines) and for custom tasks until the
                                  admin turns it on.
  user_ai_routes                  one person's routing, separate from the site's
                                  ai_task_assignments so every admin reader that
                                  assumes one row per task stays correct. A row
                                  with task_id NULL is that person's default key
                                  for every allowed task.
  user_ai_preferences             one row per person who touched My AI: whether
                                  to fall back to the site's provider when their
                                  key can't answer, and a monthly cap below the
                                  admin's default.

ai_results.provider_id becomes ON DELETE SET NULL. A result outlives its
provider (it keeps provider_name and key_owner_id); before this the plain
FK meant a provider with results could not be deleted at the DB level, which
the user→ai_providers cascade above would hit the first time a person with
a key and a result was removed.

Nothing moves: every existing provider stays the instance's, and no route
exists until a person makes one.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "a7b8c9d0e1f2"
down_revision = "f5a6b7c8d9e0"
branch_labels = None
depends_on = None

# One test decides each task: does the result belong to the person who
# clicked? Mirrors USER_PROVIDER_ELIGIBLE_TASKS in app/ai/capabilities.py;
# spelled out here because a migration must not import app code.
ELIGIBLE_TASKS = (
    "copilot",
    "detection_rules",
    "article_summary",
    "threat_assessment",
    "intelligence_briefing",
    "detection_engineering_summary",
    "video_transcript_summary",
    "report_section",
    "report_section_exposure",
    "report_section_flash_alert",
    "report_section_actor_profile",
    "report_section_campaign_tracker",
    "report_section_landscape",
    "report_section_detection",
)


def upgrade() -> None:
    op.add_column(
        "ai_providers",
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE", name="fk_ai_providers_user_id_users"),
            nullable=True,
        ),
    )
    op.create_index("ix_ai_providers_user_id", "ai_providers", ["user_id"])

    op.drop_constraint("ai_results_provider_id_fkey", "ai_results", type_="foreignkey")
    op.create_foreign_key(
        "ai_results_provider_id_fkey", "ai_results", "ai_providers", ["provider_id"], ["id"], ondelete="SET NULL"
    )

    op.add_column(
        "ai_tasks",
        sa.Column("allows_user_provider", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute(
        sa.text("UPDATE ai_tasks SET allows_user_provider = true WHERE name IN :names").bindparams(
            sa.bindparam("names", value=ELIGIBLE_TASKS, expanding=True)
        )
    )

    op.create_table(
        "user_ai_routes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE", name="fk_user_ai_routes_user_id_users"),
            nullable=False,
        ),
        sa.Column(
            "task_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_tasks.id", ondelete="CASCADE", name="fk_user_ai_routes_task_id_ai_tasks"),
            nullable=True,
        ),
        sa.Column(
            "provider_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_providers.id", ondelete="CASCADE", name="fk_user_ai_routes_provider_id_ai_providers"),
            nullable=False,
        ),
        sa.Column("model_name", sa.String(length=100), nullable=False),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_user_ai_routes_user", "user_ai_routes", ["user_id"])
    op.create_index("ix_user_ai_routes_provider", "user_ai_routes", ["provider_id"])
    op.create_index(
        "uq_user_ai_routes_task",
        "user_ai_routes",
        ["user_id", "task_id"],
        unique=True,
        postgresql_where=sa.text("task_id IS NOT NULL"),
    )
    op.create_index(
        "uq_user_ai_routes_default",
        "user_ai_routes",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("task_id IS NULL"),
    )

    op.create_table(
        "user_ai_preferences",
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE", name="fk_user_ai_preferences_user_id_users"),
            primary_key=True,
        ),
        sa.Column("fallback_to_site", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("monthly_cap_usd", sa.Numeric(10, 4), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("user_ai_preferences")
    op.drop_index("uq_user_ai_routes_default", table_name="user_ai_routes")
    op.drop_index("uq_user_ai_routes_task", table_name="user_ai_routes")
    op.drop_index("ix_user_ai_routes_provider", table_name="user_ai_routes")
    op.drop_index("ix_user_ai_routes_user", table_name="user_ai_routes")
    op.drop_table("user_ai_routes")
    op.drop_column("ai_tasks", "allows_user_provider")
    # Personal keys go with the column that marks them as personal; left in
    # place they would surface as the instance's providers. Their results
    # keep provider_name and lose provider_id (still ON DELETE SET NULL here).
    op.execute("DELETE FROM ai_providers WHERE user_id IS NOT NULL")
    op.drop_constraint("ai_results_provider_id_fkey", "ai_results", type_="foreignkey")
    op.create_foreign_key("ai_results_provider_id_fkey", "ai_results", "ai_providers", ["provider_id"], ["id"])
    op.drop_index("ix_ai_providers_user_id", table_name="ai_providers")
    op.drop_column("ai_providers", "user_id")
