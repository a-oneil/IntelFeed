"""Add detection_report builtin template.

Revision ID: 055_detection_report
Revises: 054_drop_orphaned_tables
Create Date: 2026-03-30
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision: str | None = "055_detection_report"
down_revision: str | None = "054_drop_orphaned"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    conn = op.get_bind()
    exists = conn.execute(sa.text("SELECT 1 FROM report_templates WHERE template_slug = 'detection_report'")).fetchone()
    if exists:
        return

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

    op.bulk_insert(
        templates_table,
        [
            {
                "id": str(uuid.uuid4()),
                "name": "Detection Engineering Report",
                "description": "Detection-focused analysis mapping threats to techniques, detection opportunities, coverage gaps, and log source requirements",
                "template_slug": "detection_report",
                "sections": [
                    {
                        "name": "executive_summary",
                        "title": "Executive Summary",
                        "description": "Detection-focused overview of the threat",
                        "required": True,
                        "type": "narrative",
                    },
                    {
                        "name": "attack_chain",
                        "title": "Attack Chain",
                        "description": "Phase-by-phase attack flow with MITRE ATT&CK mapping",
                        "required": True,
                        "type": "narrative",
                    },
                    {
                        "name": "ttps",
                        "title": "Tactics, Techniques & Procedures",
                        "description": "Linked ATT&CK techniques from source material",
                        "required": True,
                        "type": "data",
                    },
                    {
                        "name": "detection_opportunities",
                        "title": "Detection Opportunities",
                        "description": "Concrete detection strategies per TTP/IOC with telemetry sources and maturity levels",
                        "required": True,
                        "type": "narrative",
                    },
                    {
                        "name": "coverage_gaps",
                        "title": "Coverage Gaps",
                        "description": "Techniques lacking viable detection and compensating controls",
                        "required": True,
                        "type": "narrative",
                    },
                    {
                        "name": "iocs",
                        "title": "Indicators of Compromise",
                        "description": "Actionable indicators from source material",
                        "required": False,
                        "type": "data",
                    },
                    {
                        "name": "log_source_requirements",
                        "title": "Log Source Requirements",
                        "description": "Required telemetry sources grouped by category with minimum configurations",
                        "required": True,
                        "type": "narrative",
                    },
                    {
                        "name": "recommended_actions",
                        "title": "Recommended Actions",
                        "description": "Prioritized next steps for detection engineering and SOC teams",
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
        ],
    )


def downgrade() -> None:
    op.execute("DELETE FROM report_templates WHERE template_slug = 'detection_report' AND is_builtin = true")
