"""multi_user_ownership — seed the system user and give ownerless rows an owner

Two things multi-user scoping needs from the data:

1. A dedicated `system` service account (not loginable) so background workers
   stop attributing auto-extracted rules and maintenance actions to "whichever
   user row Postgres returns first".

2. No NULL owners on tables whose queries now filter or guard by owner
   (saved searches, notes, dashboards, automation rules, themes, share links,
   categories, tags). Legacy rows predate ownership and de-facto belong to the
   instance's original account, so they are assigned to the earliest admin.

Revision ID: d5f7h9j1l3n5
Revises: c4e6g8i0k2m4
Create Date: 2026-09-15
"""

import uuid

import sqlalchemy as sa

from alembic import op

revision = "d5f7h9j1l3n5"
down_revision = "c4e6g8i0k2m4"
branch_labels = None
depends_on = None

SYSTEM_USERNAME = "system"

_OWNER_BACKFILLS = [
    ("saved_searches", "created_by"),
    ("notes", "created_by"),
    ("dashboards", "created_by"),
    ("automation_rules", "created_by"),
    ("themes", "created_by"),
    ("shared_entries", "created_by"),
    ("categories", "created_by"),
    ("tags", "created_by"),
]


def upgrade() -> None:
    conn = op.get_bind()

    # 0. The role enum check (added by a3b7c9d2e4f1, absent on installs restored
    # from older dumps) must admit 'system' before the seed below.
    conn.execute(sa.text("ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_role"))
    conn.execute(sa.text("ALTER TABLE users ADD CONSTRAINT ck_users_role CHECK (role IN ('user', 'admin', 'system'))"))

    # 1. Seed the system service account (skip if the name is somehow taken)
    exists = conn.execute(sa.text("SELECT 1 FROM users WHERE username = :u"), {"u": SYSTEM_USERNAME}).scalar()
    if not exists:
        import bcrypt

        # Random password nobody knows; is_active=false blocks login regardless
        unusable = bcrypt.hashpw(uuid.uuid4().hex.encode(), bcrypt.gensalt()).decode()
        conn.execute(
            sa.text(
                "INSERT INTO users (id, username, password_hash, role, is_active, settings, created_at, updated_at) "
                "VALUES (:id, :u, :ph, 'system', false, '{}'::jsonb, now(), now())"
            ),
            {"id": str(uuid.uuid4()), "u": SYSTEM_USERNAME, "ph": unusable},
        )

    # 2. Assign ownerless rows to the earliest admin (no-op if no admin exists yet)
    admin_id = conn.execute(
        sa.text("SELECT id FROM users WHERE role = 'admin' ORDER BY created_at ASC LIMIT 1")
    ).scalar()
    if admin_id:
        for table, column in _OWNER_BACKFILLS:
            conn.execute(
                sa.text(f"UPDATE {table} SET {column} = :admin WHERE {column} IS NULL"),  # noqa: S608
                {"admin": admin_id},
            )


def downgrade() -> None:
    # Owner backfills are not reversible (the original NULLs carried no information).
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM users WHERE username = :u AND role = 'system'"),
        {"u": SYSTEM_USERNAME},
    )
    conn.execute(sa.text("ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_role"))
    conn.execute(sa.text("ALTER TABLE users ADD CONSTRAINT ck_users_role CHECK (role IN ('user', 'admin'))"))
