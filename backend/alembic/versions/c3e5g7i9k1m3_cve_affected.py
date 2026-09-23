"""cve_affected — authoritative CVE->vendor/product affects-links from NVD CPE data

Revision ID: c3e5g7i9k1m3
Revises: b2d4f6h8j0l2
Create Date: 2026-08-15
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c3e5g7i9k1m3"
down_revision = "b2d4f6h8j0l2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cve_affected",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "cve_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cves.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cpe_vendor", sa.Text(), nullable=False),
        sa.Column("cpe_product", sa.Text(), nullable=False),
        sa.Column(
            "vendor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vendors.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "product_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("products.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("version_start", sa.Text(), nullable=True),
        sa.Column("version_end", sa.Text(), nullable=True),
        sa.Column("source", sa.String(20), nullable=False, server_default="nvd"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("cve_id", "cpe_vendor", "cpe_product", name="uq_cve_affected_pair"),
    )
    op.create_index("ix_cve_affected_cve_id", "cve_affected", ["cve_id"])
    op.create_index("ix_cve_affected_vendor_id", "cve_affected", ["vendor_id"])
    op.create_index("ix_cve_affected_product_id", "cve_affected", ["product_id"])


def downgrade() -> None:
    op.drop_index("ix_cve_affected_product_id", table_name="cve_affected")
    op.drop_index("ix_cve_affected_vendor_id", table_name="cve_affected")
    op.drop_index("ix_cve_affected_cve_id", table_name="cve_affected")
    op.drop_table("cve_affected")
