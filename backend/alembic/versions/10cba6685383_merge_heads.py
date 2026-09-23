"""Merge heads: reunify branch created at 843bfb9c6b4c.

Branch A: 843bfb9c6b4c -> 016 (glossary_terms)
Branch B: 843bfb9c6b4c -> 017 (detection_summaries) -> 018 (fp_records_correlation_enhancements)

Both branches diverged from 843bfb9c6b4c (add_display_name_to_saved_searches),
which itself descends from 015 (cybersecurity_enhancements).

Revision ID: 10cba6685383
Revises: 016, 018_fp_corr_enhancements
Create Date: 2026-03-08 18:28:49.248040

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "10cba6685383"
down_revision: str | None = ("016", "018_fp_corr_enhancements")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
