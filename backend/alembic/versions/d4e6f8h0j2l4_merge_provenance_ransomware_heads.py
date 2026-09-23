"""merge detection_rule_provenance and ransomware_victim_tracker heads

Both b3d5f7h9j1k3 (detection rule provenance) and c3d5e7f9a1b3 (ransomware
victim tracker) branch off a1b2c3d4e5f6, creating two Alembic heads. This is an
empty merge revision that unifies them so `alembic upgrade head` is unambiguous.

Revision ID: d4e6f8h0j2l4
Revises: b3d5f7h9j1k3, c3d5e7f9a1b3
Create Date: 2026-08-19 00:00:00.000000

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "d4e6f8h0j2l4"
down_revision: tuple[str, str] = ("b3d5f7h9j1k3", "c3d5e7f9a1b3")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
