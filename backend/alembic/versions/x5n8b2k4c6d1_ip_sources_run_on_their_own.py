"""Enrichment: Shodan, GreyNoise and Team Cymru run on their own; other sharing sources wait to be asked.

- ``shodan``, ``greynoise`` and ``cymru`` rows are turned on with automatic
  lookups, including rows an admin had switched off or set to manual. The
  ledger's IPs come from published reporting, and these sources are what fill
  the IP columns (infra tag, noise class, ASN). Fresh installs seed them the
  same way (``default_enabled`` / ``default_trigger_mode`` on each adapter).
- Every other source that sends an observable to a third party (VirusTotal and
  the abuse.ch lookups) goes to ``manual`` if it is on ``auto``: it runs when a
  person asks.

Downgrade reverses both moves for rows still where the upgrade left them:
shodan, greynoise and cymru back to ``manual``, VirusTotal and the abuse.ch
lookups back to ``auto``. ``is_enabled`` stays as it is.

Revision ID: x5n8b2k4c6d1
Revises: w4k9e2s7v1c3
"""

from alembic import op

revision = "x5n8b2k4c6d1"
down_revision = "w4k9e2s7v1c3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "UPDATE enrichment_sources SET is_enabled = true, trigger_mode = 'auto' "
        "WHERE source_type IN ('shodan', 'greynoise', 'cymru')"
    )
    op.execute(
        "UPDATE enrichment_sources SET trigger_mode = 'manual' "
        "WHERE source_type IN ('virustotal', 'threatfox', 'urlhaus', 'malwarebazaar') AND trigger_mode = 'auto'"
    )


def downgrade() -> None:
    op.execute(
        "UPDATE enrichment_sources SET trigger_mode = 'manual' "
        "WHERE source_type IN ('shodan', 'greynoise', 'cymru') AND trigger_mode = 'auto'"
    )
    op.execute(
        "UPDATE enrichment_sources SET trigger_mode = 'auto' "
        "WHERE source_type IN ('virustotal', 'threatfox', 'urlhaus', 'malwarebazaar') AND trigger_mode = 'manual'"
    )
