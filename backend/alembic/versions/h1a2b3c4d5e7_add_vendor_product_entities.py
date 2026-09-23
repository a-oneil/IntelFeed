"""add vendor and product entities

Revision ID: h1a2b3c4d5e7
Revises: g1a2b3c4d5e6
Create Date: 2026-04-19 18:00:00.000000

"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "h1a2b3c4d5e7"
down_revision = "g1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vendors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), unique=True, nullable=False, index=True),
        sa.Column("aliases", postgresql.ARRAY(sa.Text()), server_default="{}"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("website", sa.Text(), nullable=True),
        sa.Column("vendor_type", sa.String(50), nullable=True, index=True),
        sa.Column("article_count", sa.Integer(), server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("metadata_", postgresql.JSONB(), server_default="{}"),
    )

    op.create_table(
        "products",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vendor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vendors.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        sa.Column("name", sa.String(255), unique=True, nullable=False, index=True),
        sa.Column("aliases", postgresql.ARRAY(sa.Text()), server_default="{}"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("product_type", sa.String(50), nullable=True, index=True),
        sa.Column("website", sa.Text(), nullable=True),
        sa.Column("article_count", sa.Integer(), server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("metadata_", postgresql.JSONB(), server_default="{}"),
    )

    op.create_table(
        "entry_vendors",
        sa.Column(
            "entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "vendor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vendors.id", ondelete="CASCADE"),
            primary_key=True,
            index=True,
        ),
        sa.Column("confidence", sa.String(10), nullable=True),
        sa.Column("source", sa.String(20), nullable=True),
        sa.Column("matched_name", sa.String(255), nullable=True),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("paragraph_indices", postgresql.ARRAY(sa.SmallInteger()), nullable=True),
    )

    op.create_table(
        "entry_products",
        sa.Column(
            "entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "product_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("products.id", ondelete="CASCADE"),
            primary_key=True,
            index=True,
        ),
        sa.Column("confidence", sa.String(10), nullable=True),
        sa.Column("source", sa.String(20), nullable=True),
        sa.Column("matched_name", sa.String(255), nullable=True),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("paragraph_indices", postgresql.ARRAY(sa.SmallInteger()), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("entry_products")
    op.drop_table("entry_vendors")
    op.drop_table("products")
    op.drop_table("vendors")
