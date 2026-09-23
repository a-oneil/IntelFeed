"""CWE as a first-class entity: catalog, entry junction, CVE link table.

Three tables. `cwes` is the seeded MITRE catalog (weaknesses + the categories
NVD used to tag against). `entry_cwes` is the entry junction every correlatable
entity type has. `cve_weaknesses` is the authoritative NVD link, shaped like
`cve_affected` — raw ref always kept, FK filled only when it resolves — because
this is catalog fact, not an adjudicated claim.

Nothing is backfilled here: the catalog is loaded by
scripts/seed/seed_cwe_catalog.py and the 50k NVD links by
scripts/maintenance/backfill_cve_weaknesses.py, both idempotent.

Revision ID: p1q3r5s7t9v1
Revises: n9i1k3m5o7q9
Create Date: 2026-09-12
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "p1q3r5s7t9v1"
down_revision = "n9i1k3m5o7q9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cwes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("cwe_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False, server_default="weakness"),
        sa.Column("abstraction", sa.String(20), nullable=True),
        sa.Column("status", sa.String(20), nullable=True),
        sa.Column("mapping_usage", sa.String(24), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("extended_description", sa.Text(), nullable=True),
        sa.Column("parent_cwe_id", sa.String(20), nullable=True),
        sa.Column("likelihood_of_exploit", sa.String(20), nullable=True),
        sa.Column("alternate_terms", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("capec_ids", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("consequences", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("mitigations", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("detection_methods", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("cwe_url", sa.Text(), nullable=True),
        sa.Column("is_deprecated", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("superseded_by", sa.String(20), nullable=True),
        sa.Column("article_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("wikipedia_url", sa.Text(), nullable=True),
        sa.Column("wikipedia_content", sa.Text(), nullable=True),
        sa.Column("wikipedia_image_url", sa.Text(), nullable=True),
        sa.Column("created_via", sa.String(20), nullable=True),
        sa.Column(
            "created_from_entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_confidence", sa.String(10), nullable=True),
        sa.Column("needs_review", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.create_index("ix_cwes_cwe_id", "cwes", ["cwe_id"], unique=True)
    op.create_index("ix_cwes_kind", "cwes", ["kind"])
    op.create_index("ix_cwes_abstraction", "cwes", ["abstraction"])
    op.create_index("ix_cwes_mapping_usage", "cwes", ["mapping_usage"])
    op.create_index("ix_cwes_parent_cwe_id", "cwes", ["parent_cwe_id"])
    op.create_index("ix_cwes_created_via", "cwes", ["created_via"])

    op.create_table(
        "entry_cwes",
        sa.Column(
            "entry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "cwe_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("cwes.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("confidence", sa.String(10), nullable=True),
        sa.Column("source", sa.String(20), nullable=True),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("paragraph_indices", postgresql.ARRAY(sa.SmallInteger()), nullable=True),
        sa.PrimaryKeyConstraint("entry_id", "cwe_id"),
    )
    op.create_index("ix_entry_cwes_cwe_id", "entry_cwes", ["cwe_id"])

    op.create_table(
        "cve_weaknesses",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "cve_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("cwe_ref", sa.String(40), nullable=False),
        sa.Column(
            "cwe_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("cwes.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("assigner", sa.String(120), nullable=True),
        sa.Column("source", sa.String(20), nullable=False, server_default="nvd"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("cve_id", "cwe_ref", name="uq_cve_weakness_pair"),
    )
    op.create_index("ix_cve_weaknesses_cve_id", "cve_weaknesses", ["cve_id"])
    op.create_index("ix_cve_weaknesses_cwe_ref", "cve_weaknesses", ["cwe_ref"])
    op.create_index("ix_cve_weaknesses_cwe_id", "cve_weaknesses", ["cwe_id"])


def downgrade() -> None:
    op.drop_table("cve_weaknesses")
    op.drop_table("entry_cwes")
    op.drop_table("cwes")
