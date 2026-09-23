"""Add report_templates table for user-defined custom report templates.

Revision ID: 050_report_templates
Revises: 049_seed_countries
Create Date: 2026-03-15
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "050_report_templates"
down_revision = "049_seed_countries"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "report_templates",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("template_slug", sa.String(50), unique=True, nullable=False, index=True),
        sa.Column("sections", JSONB, server_default="[]"),
        sa.Column("is_builtin", sa.Boolean, server_default="false"),
        sa.Column("is_shared", sa.Boolean, server_default="false"),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Seed the 5 builtin templates + new country_threat_brief
    import uuid

    from app.intelligence.reporting import REPORT_TEMPLATES

    templates_table = sa.table(
        "report_templates",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("template_slug", sa.String),
        sa.column("sections", JSONB),
        sa.column("is_builtin", sa.Boolean),
        sa.column("is_shared", sa.Boolean),
    )

    rows = []
    for slug, tmpl in REPORT_TEMPLATES.items():
        sections = [
            {"name": s, "title": s.replace("_", " ").title(), "description": "", "required": True, "type": "narrative"}
            for s in tmpl["sections"]
        ]
        # Mark data sections appropriately
        for sec in sections:
            if sec["name"] in (
                "iocs",
                "ioc_table",
                "ttps",
                "references",
                "timeline",
                "aliases_attribution",
                "vulnerability_highlights",
                "notable_threats",
            ):
                sec["type"] = "data"
        rows.append(
            {
                "id": str(uuid.uuid4()),
                "name": tmpl["name"],
                "description": tmpl["description"],
                "template_slug": slug,
                "sections": sections,
                "is_builtin": True,
                "is_shared": True,
            }
        )

    # Add country_threat_brief template
    rows.append(
        {
            "id": str(uuid.uuid4()),
            "name": "Country Threat Brief",
            "description": "Intelligence assessment for a specific country or region's threat landscape",
            "template_slug": "country_threat_brief",
            "sections": [
                {
                    "name": "executive_summary",
                    "title": "Executive Summary",
                    "description": "High-level overview",
                    "required": True,
                    "type": "narrative",
                },
                {
                    "name": "active_threat_actors",
                    "title": "Active Threat Actors",
                    "description": "Actors attributed to or targeting this country",
                    "required": True,
                    "type": "narrative",
                },
                {
                    "name": "current_campaigns",
                    "title": "Current Campaigns",
                    "description": "Active campaigns linked to this country",
                    "required": False,
                    "type": "narrative",
                },
                {
                    "name": "iocs",
                    "title": "Indicators of Compromise",
                    "description": "IOCs from country-linked entries",
                    "required": False,
                    "type": "data",
                },
                {
                    "name": "ttp_coverage",
                    "title": "TTP Coverage Assessment",
                    "description": "ATT&CK techniques and detection coverage",
                    "required": True,
                    "type": "narrative",
                },
                {
                    "name": "targeted_sectors",
                    "title": "Targeted Sectors",
                    "description": "Industries targeted by actors from this country",
                    "required": False,
                    "type": "narrative",
                },
                {
                    "name": "outlook",
                    "title": "Outlook",
                    "description": "Forward-looking threat assessment",
                    "required": True,
                    "type": "narrative",
                },
                {
                    "name": "references",
                    "title": "References",
                    "description": "Source articles and references",
                    "required": False,
                    "type": "data",
                },
            ],
            "is_builtin": True,
            "is_shared": True,
        }
    )

    op.bulk_insert(templates_table, rows)


def downgrade() -> None:
    op.drop_table("report_templates")
