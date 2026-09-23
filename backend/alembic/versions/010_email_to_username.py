"""Rename email to username for auth

Revision ID: 010
Revises: 009
Create Date: 2026-03-04
"""

import sqlalchemy as sa

from alembic import op

revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade():
    # Migrate data: extract username from email (part before @), lowercase, truncate to 30
    op.execute("UPDATE users SET email = LOWER(LEFT(split_part(email, '@', 1), 30))")

    # Drop old index
    op.drop_index("ix_users_email", table_name="users")

    # Rename column and change type
    op.alter_column("users", "email", new_column_name="username", type_=sa.String(30), existing_type=sa.String(255))

    # Create new unique index
    op.create_index("ix_users_username", "users", ["username"], unique=True)


def downgrade():
    op.drop_index("ix_users_username", table_name="users")
    op.alter_column("users", "username", new_column_name="email", type_=sa.String(255), existing_type=sa.String(30))
    op.create_index("ix_users_email", "users", ["email"], unique=True)
