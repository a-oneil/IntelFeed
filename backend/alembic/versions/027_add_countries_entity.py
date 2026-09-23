"""Add countries entity tables

Revision ID: 027_add_countries_entity
Revises: 026_downgrade_benign_ioc_conf
Create Date: 2026-03-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "027_add_countries_entity"
down_revision: str = "026_downgrade_benign_ioc_conf"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "countries",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), unique=True, nullable=False, index=True),
        sa.Column("iso_code", sa.String(3)),
        sa.Column("aliases", ARRAY(sa.Text), server_default="{}"),
        sa.Column("region", sa.String(100)),
        sa.Column("description", sa.Text),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("article_count", sa.Integer, server_default="1"),
        sa.Column("metadata_", JSONB, server_default="{}"),
    )

    op.create_table(
        "entry_countries",
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True),
        sa.Column(
            "country_id",
            UUID(as_uuid=True),
            sa.ForeignKey("countries.id", ondelete="CASCADE"),
            primary_key=True,
            index=True,
        ),
        sa.Column("confidence", sa.String(10)),
        sa.Column("source", sa.String(20)),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("entry_countries")
    op.drop_table("countries")
