"""shared_data_model - convert from per-user isolation to shared workspace

Revision ID: 059_shared_data_model
Revises: 058_automation_labels
Create Date: 2026-04-17 00:00:00.000000

"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "059_shared_data_model"
down_revision: str | None = "058_automation_labels"
branch_labels: str | None = None
depends_on: str | None = None


# Tables where user_id is renamed to created_by (nullable audit column)
SHARED_TABLES = [
    "categories",
    "tags",
    "dashboards",
    "automation_rules",
    "detection_rules",
    "detection_summaries",
    "campaigns",
    "intel_reports",
    "intelligence_requirements",
    "saved_searches",
    "notes",
    "boards",
    "telemetry_sources",
    "webhook_presets",
    "ai_task_assignments",
]

# Tables that already have nullable user_id (just rename)
ALREADY_NULLABLE_TABLES = [
    "glossary_terms",
    "themes",
    "ai_prompt_templates",
    "user_enrichment_overrides",
]


def upgrade() -> None:
    conn = op.get_bind()

    def _has_column(tbl, col):
        return (
            conn.execute(
                sa.text("SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"),
                {"t": tbl, "c": col},
            ).fetchone()
            is not None
        )

    # ---------------------------------------------------------------
    # Step 1: Add subscription-level fields to feeds table
    # ---------------------------------------------------------------
    if not _has_column("feeds", "category_id"):
        op.add_column("feeds", sa.Column("category_id", UUID(as_uuid=True), nullable=True))
    if not _has_column("feeds", "custom_title"):
        op.add_column("feeds", sa.Column("custom_title", sa.String(500), nullable=True))
    if not _has_column("feeds", "is_muted"):
        op.add_column("feeds", sa.Column("is_muted", sa.Boolean(), server_default="false", nullable=False))
    if not _has_column("feeds", "retention_days"):
        op.add_column("feeds", sa.Column("retention_days", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_feeds_category_id",
        "feeds",
        "categories",
        ["category_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_feeds_category_id", "feeds", ["category_id"])

    # ---------------------------------------------------------------
    # Step 2: Migrate subscription data to feeds
    # ---------------------------------------------------------------
    conn.execute(
        sa.text("""
        UPDATE feeds SET
            category_id = sub.category_id,
            custom_title = sub.custom_title,
            is_muted = COALESCE(sub.is_muted, false),
            retention_days = sub.retention_days
        FROM (
            SELECT DISTINCT ON (feed_id)
                feed_id, category_id, custom_title, is_muted, retention_days
            FROM user_feed_subscriptions
            ORDER BY feed_id, added_at ASC
        ) sub
        WHERE feeds.id = sub.feed_id
    """)
    )

    # ---------------------------------------------------------------
    # Step 3: Deduplicate categories by name
    # ---------------------------------------------------------------
    # Keep the oldest category per name, update all references
    conn.execute(
        sa.text("""
        WITH dupes AS (
            SELECT id, name,
                   ROW_NUMBER() OVER (PARTITION BY LOWER(name) ORDER BY created_at ASC, id) AS rn
            FROM categories
        ),
        keeper AS (
            SELECT id AS keep_id, name FROM dupes WHERE rn = 1
        ),
        victim AS (
            SELECT d.id AS victim_id, k.keep_id
            FROM dupes d
            JOIN keeper k ON LOWER(d.name) = LOWER(k.name)
            WHERE d.rn > 1
        )
        UPDATE feeds SET category_id = v.keep_id
        FROM victim v
        WHERE feeds.category_id = v.victim_id
    """)
    )
    conn.execute(
        sa.text("""
        WITH dupes AS (
            SELECT id, name,
                   ROW_NUMBER() OVER (PARTITION BY LOWER(name) ORDER BY created_at ASC, id) AS rn
            FROM categories
        ),
        keeper AS (
            SELECT id AS keep_id, name FROM dupes WHERE rn = 1
        ),
        victim AS (
            SELECT d.id AS victim_id, k.keep_id
            FROM dupes d
            JOIN keeper k ON LOWER(d.name) = LOWER(k.name)
            WHERE d.rn > 1
        )
        UPDATE categories SET parent_id = v.keep_id
        FROM victim v
        WHERE categories.parent_id = v.victim_id
    """)
    )
    conn.execute(
        sa.text("""
        WITH dupes AS (
            SELECT id,
                   ROW_NUMBER() OVER (PARTITION BY LOWER(name) ORDER BY created_at ASC, id) AS rn
            FROM categories
        )
        DELETE FROM categories WHERE id IN (SELECT id FROM dupes WHERE rn > 1)
    """)
    )

    # ---------------------------------------------------------------
    # Step 4: Deduplicate tags by name
    # ---------------------------------------------------------------
    # Keep oldest tag per name, update entry_tags references
    conn.execute(
        sa.text("""
        WITH dupes AS (
            SELECT id, name,
                   ROW_NUMBER() OVER (PARTITION BY LOWER(name) ORDER BY created_at ASC, id) AS rn
            FROM tags
        ),
        keeper AS (
            SELECT id AS keep_id, LOWER(name) AS lname FROM dupes WHERE rn = 1
        ),
        victim AS (
            SELECT d.id AS victim_id, k.keep_id
            FROM dupes d
            JOIN keeper k ON LOWER(d.name) = k.lname
            WHERE d.rn > 1
        )
        UPDATE entry_tags SET tag_id = v.keep_id
        FROM victim v
        WHERE entry_tags.tag_id = v.victim_id
    """)
    )
    conn.execute(
        sa.text("""
        WITH dupes AS (
            SELECT id,
                   ROW_NUMBER() OVER (PARTITION BY LOWER(name) ORDER BY created_at ASC, id) AS rn
            FROM tags
        )
        DELETE FROM tags WHERE id IN (SELECT id FROM dupes WHERE rn > 1)
    """)
    )

    # ---------------------------------------------------------------
    # Step 5: Deduplicate entry_tags and remove user_id from PK
    # ---------------------------------------------------------------
    # Remove duplicate (entry_id, tag_id) pairs
    conn.execute(
        sa.text("""
        DELETE FROM entry_tags a USING entry_tags b
        WHERE a.ctid < b.ctid
            AND a.entry_id = b.entry_id
            AND a.tag_id = b.tag_id
    """)
    )
    # Recreate PK without user_id
    if _has_column("entry_tags", "user_id"):
        op.drop_constraint("entry_tags_pkey", "entry_tags", type_="primary")
        op.drop_column("entry_tags", "user_id")
        op.create_primary_key("entry_tags_pkey", "entry_tags", ["entry_id", "tag_id"])

    # ---------------------------------------------------------------
    # Step 6: Deduplicate ai_task_assignments by task_id
    # ---------------------------------------------------------------
    conn.execute(
        sa.text("""
        WITH dupes AS (
            SELECT id,
                   ROW_NUMBER() OVER (PARTITION BY task_id ORDER BY id) AS rn
            FROM ai_task_assignments
        )
        DELETE FROM ai_task_assignments WHERE id IN (SELECT id FROM dupes WHERE rn > 1)
    """)
    )

    # ---------------------------------------------------------------
    # Step 7: Deduplicate user_enrichment_overrides by source_id
    # ---------------------------------------------------------------
    conn.execute(
        sa.text("""
        WITH dupes AS (
            SELECT id,
                   ROW_NUMBER() OVER (PARTITION BY source_id ORDER BY created_at ASC, id) AS rn
            FROM user_enrichment_overrides
        )
        DELETE FROM user_enrichment_overrides WHERE id IN (SELECT id FROM dupes WHERE rn > 1)
    """)
    )

    # ---------------------------------------------------------------
    # Step 8: Deduplicate glossary_terms by name
    # ---------------------------------------------------------------
    conn.execute(
        sa.text("""
        WITH dupes AS (
            SELECT id,
                   ROW_NUMBER() OVER (PARTITION BY LOWER(name) ORDER BY created_at ASC, id) AS rn
            FROM glossary_terms
        )
        DELETE FROM glossary_terms WHERE id IN (SELECT id FROM dupes WHERE rn > 1)
    """)
    )

    # ---------------------------------------------------------------
    # Step 9: Rename user_id -> created_by on all shared tables
    # ---------------------------------------------------------------
    for table in SHARED_TABLES:
        if _has_column(table, "user_id"):
            op.alter_column(table, "user_id", new_column_name="created_by")
        if _has_column(table, "created_by"):
            op.alter_column(table, "created_by", nullable=True)
        # Update FK: drop CASCADE, add SET NULL
        old_constraint = f"{table}_user_id_fkey"
        new_constraint = f"{table}_created_by_fkey"
        try:
            with op.get_bind().begin_nested():
                op.drop_constraint(old_constraint, table, type_="foreignkey")
        except Exception:
            pass  # constraint name may vary
        op.create_foreign_key(new_constraint, table, "users", ["created_by"], ["id"], ondelete="SET NULL")

    for table in ALREADY_NULLABLE_TABLES:
        if _has_column(table, "user_id"):
            op.alter_column(table, "user_id", new_column_name="created_by")
        old_constraint = f"{table}_user_id_fkey"
        new_constraint = f"{table}_created_by_fkey"
        try:
            with op.get_bind().begin_nested():
                op.drop_constraint(old_constraint, table, type_="foreignkey")
        except Exception:
            pass
        op.create_foreign_key(new_constraint, table, "users", ["created_by"], ["id"], ondelete="SET NULL")

    # ---------------------------------------------------------------
    # Step 10: Update unique constraints
    # ---------------------------------------------------------------
    conn = op.get_bind()

    # Tags: (user_id, name) -> (name)
    try:
        with conn.begin_nested():
            op.drop_constraint("uq_tags_user_name", "tags", type_="unique")
    except Exception:
        pass
    op.create_unique_constraint("uq_tags_name", "tags", ["name"])

    # Glossary terms: (user_id, name) -> (name)
    try:
        with conn.begin_nested():
            op.drop_constraint("uq_glossary_terms_user_name", "glossary_terms", type_="unique")
    except Exception:
        pass
    op.create_unique_constraint("uq_glossary_terms_name", "glossary_terms", ["name"])

    # AI task assignments: (user_id, task_id) -> (task_id)
    try:
        with conn.begin_nested():
            op.drop_constraint("ai_task_assignments_user_id_task_id_key", "ai_task_assignments", type_="unique")
    except Exception:
        pass
    op.create_unique_constraint("uq_ai_task_assignments_task_id", "ai_task_assignments", ["task_id"])

    # Enrichment overrides: (user_id, source_id) -> (source_id)
    try:
        with conn.begin_nested():
            op.drop_constraint(
                "user_enrichment_overrides_user_id_source_id_key", "user_enrichment_overrides", type_="unique"
            )
    except Exception:
        pass
    op.create_unique_constraint("uq_enrichment_overrides_source_id", "user_enrichment_overrides", ["source_id"])

    # ---------------------------------------------------------------
    # Step 11: Drop user_feed_subscriptions table
    # ---------------------------------------------------------------
    op.execute(sa.text('DROP TABLE IF EXISTS "user_feed_subscriptions" CASCADE'))


def downgrade() -> None:
    # This is a one-way migration. Downgrade would require recreating
    # the subscription table and re-splitting shared data per-user,
    # which is not feasible automatically.
    raise NotImplementedError("Downgrade from shared data model is not supported. Restore from backup if needed.")
