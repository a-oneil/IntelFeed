"""Retire the instance-global ``my_sectors`` setting in favour of per-user sector watches.

``my_sectors`` was one comma-separated list for the whole install — at odds with
the per-user watch model and with scopes being plural named intel profiles. Its
only two readers (the Leak Watch exposure panel and the disclosure alert
broadcast) now read ``user_entity_watches`` rows of type ``sector``, which also
gives sector interest the Priority Queue boost the setting always claimed to
have and never did.

The migration turns whatever the setting held into ``watch`` rows for every
admin user (the setting was instance-wide; admins are the only defensible
owners) and removes the key from the settings JSON. Unknown or empty values
produce no rows. Downgrade only restores the key as an empty string: the
original CSV is not recoverable once users have edited their watches.

Revision ID: r7i9k1m3o5q7
Revises: q6h8j0l2n4p6
Create Date: 2026-10-01
"""

import uuid

import sqlalchemy as sa

from alembic import op

revision = "r7i9k1m3o5q7"
down_revision = "q6h8j0l2n4p6"
branch_labels = None
depends_on = None

# Frozen copy of the vocabulary's alias map at migration time, limited to what
# the setting's parser accepted; the live module is the source of truth.
_SECTOR_NAMESPACE = uuid.UUID("4e6a30ee-1eeb-5751-b76b-5c4de806fec1")


def _slugs(raw: str) -> list[str]:
    from app.intelligence.sectors import parse_sector_setting

    return parse_sector_setting(raw)


def upgrade() -> None:
    conn = op.get_bind()
    raw = conn.execute(sa.text("SELECT settings->>'my_sectors' FROM system_settings WHERE id = 1")).scalar()
    slugs = _slugs(raw or "")
    if slugs:
        admins = [row[0] for row in conn.execute(sa.text("SELECT id FROM users WHERE role = 'admin'")).all()]
        for admin_id in admins:
            for slug in slugs:
                conn.execute(
                    sa.text(
                        "INSERT INTO user_entity_watches (id, created_by, entity_type, entity_id, mode, boost) "
                        "VALUES (:id, :uid, 'sector', :sid, 'watch', 1.0) "
                        "ON CONFLICT ON CONSTRAINT uq_user_entity_watch DO NOTHING"
                    ),
                    {"id": uuid.uuid4(), "uid": admin_id, "sid": uuid.uuid5(_SECTOR_NAMESPACE, slug)},
                )
    conn.execute(sa.text("UPDATE system_settings SET settings = settings - 'my_sectors' WHERE id = 1"))


def downgrade() -> None:
    op.execute(
        "UPDATE system_settings SET settings = jsonb_set(settings, '{my_sectors}', '\"\"'::jsonb, true) WHERE id = 1"
    )
