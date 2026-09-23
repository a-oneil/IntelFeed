"""Anti-join predicates over `user_entry_states`.

Every "entries this user hasn't read" count used to be written as
``~Entry.id.in_(select(UserEntryState.entry_id).where(...))``. Postgres does
not flatten ``NOT IN (subquery)`` into an anti-join; it plans a hashed SubPlan,
and once the subquery result outgrows ``work_mem`` (4MB — ~283k read-state
rows on prod blew straight past it) it degrades to an un-hashed SubPlan that
rescans the materialized id list for every outer row. The widget counts that
depended on it went from milliseconds to minutes, which is what the frontend
saw as `timeout of 15000ms exceeded`.

``NOT EXISTS`` is the correlated form Postgres always flattens into a
(Parallel) Hash Anti Join, so it stays sub-second at any table size. Use these
helpers instead of hand-rolling the subquery.
"""

import uuid

from sqlalchemy import ColumnElement, select

from app.models.entry import Entry
from app.models.entry_state import UserEntryState


def unread_by_user(user_id: uuid.UUID) -> ColumnElement[bool]:
    """Entries with no `is_read` state row for this user.

    Entries the user has never opened have no `user_entry_states` row at all,
    so "unread" is the absence of a read-flagged row, not `is_read == False`.
    """
    return ~(
        select(UserEntryState.id)
        .where(
            UserEntryState.entry_id == Entry.id,
            UserEntryState.user_id == user_id,
            UserEntryState.is_read.is_(True),
        )
        .exists()
    )


def has_no_state_for_user(user_id: uuid.UUID) -> ColumnElement[bool]:
    """Entries with no `user_entry_states` row for this user at all.

    The insert half of mark-as-read: rows to create, as opposed to update.
    """
    return ~(
        select(UserEntryState.id)
        .where(
            UserEntryState.entry_id == Entry.id,
            UserEntryState.user_id == user_id,
        )
        .exists()
    )
