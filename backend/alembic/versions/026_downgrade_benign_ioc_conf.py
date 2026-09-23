"""Downgrade confidence for benign domain/URL/email IOCs

Revision ID: 026_downgrade_benign_ioc_conf
Revises: 025_auto_extract_on_ingest
Create Date: 2026-03-12
"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "026_downgrade_benign_ioc_conf"
down_revision: str = "025_auto_extract_on_ingest"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """No-op: IOC tables have been removed from the platform."""
    pass


def downgrade() -> None:
    """No-op: IOC tables have been removed from the platform."""
    pass
