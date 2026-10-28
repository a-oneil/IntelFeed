"""enrichment_sources: NVD's default rate is its keyless limit, 5 per 30 s.

NVD allows 50 requests per rolling 30 s with an API key and 5 without. The
NVD manifest's quota is 5/30 with a keyed 50/30 that the gateway uses while a
key is set and the row is at the keyless default. Rows still at the 50/30
default move to 5/30, so a keyed install keeps 50/30 through the keyed quota
and a keyless one sends at NVD's real limit. A rate an admin chose is left
alone. Downgrade moves rows at 5/30 back to 50/30, so it can't tell an admin's
5/30 from the default.

Revision ID: n5v6d7k8l9q0
Revises: r8e1a2t3c4l5
"""

import sqlalchemy as sa

from alembic import op

revision = "n5v6d7k8l9q0"
down_revision = "r8e1a2t3c4l5"
branch_labels = None
depends_on = None

_KEYED = '{"requests_per_period": 50, "period_seconds": 30}'
_KEYLESS = '{"requests_per_period": 5, "period_seconds": 30}'


def _nvd_rate(old: str, new: str) -> None:
    op.get_bind().execute(
        sa.text(
            "UPDATE enrichment_sources SET rate_limit_config = CAST(:new AS jsonb) "
            "WHERE source_type = 'nvd' AND rate_limit_config = CAST(:old AS jsonb)"
        ),
        {"old": old, "new": new},
    )


def upgrade() -> None:
    _nvd_rate(_KEYED, _KEYLESS)


def downgrade() -> None:
    _nvd_rate(_KEYLESS, _KEYED)
