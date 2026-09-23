"""Country foundation: role on entry_countries, origin_country_id on threat_actors,
threat_actor_target_countries and campaign_countries junction tables.

Revision ID: 048_country_foundation
Revises: 047_add_metadata
Create Date: 2026-03-15
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "048_country_foundation"
down_revision = "047_add_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add role column to entry_countries
    op.add_column(
        "entry_countries",
        sa.Column("role", sa.String(20), nullable=True),
    )

    # Add origin_country_id FK to threat_actors
    op.add_column(
        "threat_actors",
        sa.Column(
            "origin_country_id",
            UUID(as_uuid=True),
            sa.ForeignKey("countries.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_threat_actors_origin_country_id",
        "threat_actors",
        ["origin_country_id"],
    )

    # Create threat_actor_target_countries junction table
    op.create_table(
        "threat_actor_target_countries",
        sa.Column(
            "threat_actor_id",
            UUID(as_uuid=True),
            sa.ForeignKey("threat_actors.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "country_id", UUID(as_uuid=True), sa.ForeignKey("countries.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_threat_actor_target_countries_country_id",
        "threat_actor_target_countries",
        ["country_id"],
    )

    # Create campaign_countries junction table
    op.create_table(
        "campaign_countries",
        sa.Column(
            "campaign_id", UUID(as_uuid=True), sa.ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column(
            "country_id", UUID(as_uuid=True), sa.ForeignKey("countries.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column("role", sa.String(20), server_default="target"),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_campaign_countries_country_id",
        "campaign_countries",
        ["country_id"],
    )


def downgrade() -> None:
    op.drop_table("campaign_countries")
    op.drop_table("threat_actor_target_countries")
    op.drop_index("ix_threat_actors_origin_country_id", table_name="threat_actors")
    op.drop_column("threat_actors", "origin_country_id")
    op.drop_column("entry_countries", "role")
