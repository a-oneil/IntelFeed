"""The person behind the current request, for audit rows written deep in a
service. Set once by the auth dependency (or by a worker task that acts on a
person's behalf) and read by the session hook in ``app/models/applied_by.py``,
which stamps ``applied_by`` on the maintenance logs."""

from __future__ import annotations

import uuid
from contextvars import ContextVar

_acting_user_id: ContextVar[uuid.UUID | None] = ContextVar("acting_user_id", default=None)


def set_acting_user(user_id: uuid.UUID | None) -> None:
    _acting_user_id.set(user_id)


def current_acting_user() -> uuid.UUID | None:
    return _acting_user_id.get()
