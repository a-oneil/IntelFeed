"""Add exposure_report builtin template.

Without this row, GET /intel-reports/templates (DB-backed) never lists the
exposure template, so the report builder shows no section tabs for exposure
drafts and the wizard can't offer it.

Revision ID: n3e5g7i9k1m3
Revises: m2c4e6g8i0k2
Create Date: 2026-09-20
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision: str | None = "n3e5g7i9k1m3"
down_revision: str | None = "m2c4e6g8i0k2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    conn = op.get_bind()
    exists = conn.execute(sa.text("SELECT 1 FROM report_templates WHERE template_slug = 'exposure_report'")).fetchone()
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
                "name": "Threat Exposure Report",
                "description": (
                    "Exposure profile for a saved scope (regions × verticals): the matched threat surface "
                    "with why-matched evidence, plus TTPs and indicators from the backing entries"
                ),
                "template_slug": "exposure_report",
                "sections": [
                    {
                        "name": "executive_summary",
                        "title": "Executive Summary",
                        "description": "The most material changes to this profile's threat surface this window",
                        "required": True,
                        "type": "narrative",
                    },
                    {
                        "name": "scope",
                        "title": "Scope",
                        "description": "The intel profile's regions, verticals, and window",
                        "required": True,
                        "type": "data",
                    },
                    {
                        "name": "threat_surface",
                        "title": "Threat Surface",
                        "description": "Curated actors and malware matched to the scope, with evidence",
                        "required": True,
                        "type": "data",
                    },
                    {
                        "name": "ttps",
                        "title": "Tactics, Techniques & Procedures",
                        "description": "ATT&CK techniques observed across the backing entries",
                        "required": False,
                        "type": "data",
                    },
                    {
                        "name": "iocs",
                        "title": "Indicators of Compromise",
                        "description": "Judged observables sighted in the backing entries, with attribution",
                        "required": False,
                        "type": "data",
                    },
                    {
                        "name": "outlook",
                        "title": "Outlook",
                        "description": "Forward-looking assessment scoped to the profile; watch items for next issue",
                        "required": True,
                        "type": "narrative",
                    },
                    {
                        "name": "references",
                        "title": "References",
                        "description": "Backing articles",
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
    op.execute("DELETE FROM report_templates WHERE template_slug = 'exposure_report' AND is_builtin = true")
