"""Add mitigations, offensive_tools, vulnerability_advisories, targeted_sectors on threat_actors

Revision ID: 036_new_entity_types
Revises: 035_ci_entity_names
Create Date: 2026-03-13

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "036_new_entity_types"
down_revision: str | None = "035_ci_entity_names"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- mitigations ---
    op.create_table(
        "mitigations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("mitre_id", sa.String(20), nullable=True, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("mitre_url", sa.Text, nullable=True),
        sa.Column("cis_controls", postgresql.ARRAY(sa.Text), nullable=False, server_default="{}"),
        sa.Column("nist_controls", postgresql.ARRAY(sa.Text), nullable=False, server_default="{}"),
        sa.Column("article_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_mitigations_mitre_id", "mitigations", ["mitre_id"])
    op.create_index("ix_mitigations_name", "mitigations", ["name"])

    op.create_table(
        "entry_mitigations",
        sa.Column(
            "entry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column(
            "mitigation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("mitigations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("confidence", sa.String(10), nullable=True),
        sa.Column("source", sa.String(20), nullable=True),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_entry_mitigations_mitigation_id", "entry_mitigations", ["mitigation_id"])

    op.create_table(
        "ttp_mitigations",
        sa.Column(
            "ttp_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ttps.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column(
            "mitigation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("mitigations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_ttp_mitigations_mitigation_id", "ttp_mitigations", ["mitigation_id"])

    # --- offensive_tools ---
    op.create_table(
        "offensive_tools",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("aliases", postgresql.ARRAY(sa.Text), nullable=False, server_default="{}"),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("tool_type", sa.String(50), nullable=True),
        sa.Column("platforms", postgresql.ARRAY(sa.Text), nullable=False, server_default="{}"),
        sa.Column("malpedia_url", sa.Text, nullable=True),
        sa.Column("github_url", sa.Text, nullable=True),
        sa.Column("detection_artifacts", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("article_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("metadata_", postgresql.JSONB, nullable=False, server_default="{}"),
    )
    op.create_index("ix_offensive_tools_name", "offensive_tools", ["name"])
    op.create_index("ix_offensive_tools_tool_type", "offensive_tools", ["tool_type"])

    op.create_table(
        "entry_tools",
        sa.Column(
            "entry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column(
            "tool_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("offensive_tools.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("confidence", sa.String(10), nullable=True),
        sa.Column("source", sa.String(20), nullable=True),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_entry_tools_tool_id", "entry_tools", ["tool_id"])

    # --- vulnerability_advisories ---
    op.create_table(
        "vulnerability_advisories",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("advisory_id", sa.String(100), nullable=False, unique=True),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("title", sa.Text, nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("cvss_score", sa.Numeric(3, 1), nullable=True),
        sa.Column("affected_products", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("cve_refs", postgresql.ARRAY(sa.Text), nullable=False, server_default="{}"),
        sa.Column("exploit_status", sa.String(30), nullable=True),
        sa.Column("references_", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("article_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_vulnerability_advisories_advisory_id", "vulnerability_advisories", ["advisory_id"])
    op.create_index("ix_vulnerability_advisories_source", "vulnerability_advisories", ["source"])
    op.create_index("ix_vulnerability_advisories_severity", "vulnerability_advisories", ["severity"])

    op.create_table(
        "entry_vulnerability_advisories",
        sa.Column(
            "entry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column(
            "advisory_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerability_advisories.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_entry_vulnerability_advisories_advisory_id", "entry_vulnerability_advisories", ["advisory_id"])

    # --- targeted_sectors on threat_actors ---
    op.add_column(
        "threat_actors",
        sa.Column("targeted_sectors", postgresql.ARRAY(sa.Text), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("threat_actors", "targeted_sectors")
    op.drop_table("entry_vulnerability_advisories")
    op.drop_table("vulnerability_advisories")
    op.drop_table("entry_tools")
    op.drop_table("offensive_tools")
    op.drop_table("ttp_mitigations")
    op.drop_table("entry_mitigations")
    op.drop_table("mitigations")
