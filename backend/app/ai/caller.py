"""Who is asking for an AI call.

Every AI result records the *kind* of caller alongside the user it is
attributed to. A bare user id can't carry that distinction: automation
rules run as their author, share links run as the sharer, and workers
run as the ``system`` account or a sentinel UUID — but none of those is a
person clicking a button, and per-user provider routing must never treat
them as one.

Build a ``Caller`` at the boundary that knows the answer (the API route,
the Celery task, the automation engine) and pass it down. ``run_task``
derives ``Caller.user`` from a bare ``user_id`` when no caller is given,
with the all-zero sentinel UUID mapping to ``system``.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal

CallerKind = Literal["user", "system", "automation", "share"]

#: Every ``kind`` an AIResult.caller_kind column can hold.
CALLER_KINDS: tuple[CallerKind, ...] = ("user", "system", "automation", "share")

#: Sentinel "user" some workers pass instead of a user row (the shared daily
#: briefing, thread spines, threat briefs). It matches no users row, so it
#: must never be written to a foreign key.
SENTINEL_USER_ID = uuid.UUID(int=0)


def _real(user_id: uuid.UUID | None) -> uuid.UUID | None:
    return None if user_id is None or user_id == SENTINEL_USER_ID else user_id


@dataclass(frozen=True, slots=True)
class Caller:
    """The principal an AI call runs for.

    ``user_id`` is who the work is attributed to: the human for ``user``,
    the rule author for ``automation``, the sharer for ``share``, and the
    ``system`` account (or nothing) for ``system``. Only ``user`` callers
    are eligible for a personal provider.
    """

    kind: CallerKind
    user_id: uuid.UUID | None = None

    @classmethod
    def user(cls, user_id: uuid.UUID | None) -> Caller:
        """A signed-in person acting in their own request."""
        if _real(user_id) is None:
            return cls.system()
        return cls("user", user_id)

    @classmethod
    def system(cls, user_id: uuid.UUID | None = None) -> Caller:
        """Background work: pipeline stages, maintenance jobs, shared output."""
        return cls("system", _real(user_id))

    @classmethod
    def automation(cls, rule_author: uuid.UUID | None) -> Caller:
        """An automation rule running as its author. Billed as pipeline."""
        return cls("automation", _real(rule_author))

    @classmethod
    def share(cls, sharer: uuid.UUID | None) -> Caller:
        """A public share link. The sharer is recorded, never charged."""
        return cls("share", _real(sharer))

    @classmethod
    def of_kind(cls, kind: str, user_id: uuid.UUID | None) -> Caller:
        """Rebuild a caller from a serialized kind (Celery kwargs)."""
        if kind not in CALLER_KINDS:
            raise ValueError(f"unknown caller kind: {kind!r}")
        if kind == "user":
            return cls.user(user_id)
        return cls(kind, _real(user_id))  # type: ignore[arg-type]

    @property
    def is_user(self) -> bool:
        return self.kind == "user"


#: The caller every ``run_task`` call in the current context runs for when
#: the call site names none. Set at a boundary that owns the answer for
#: everything beneath it — the automation dispatcher — so a new action can't
#: bill its rule's author as a person by forgetting a keyword argument.
current_caller: ContextVar[Caller | None] = ContextVar("current_caller", default=None)


@contextmanager
def caller_scope(caller: Caller) -> Iterator[Caller]:
    """Make ``caller`` the default for AI calls inside the block."""
    token = current_caller.set(caller)
    try:
        yield caller
    finally:
        current_caller.reset(token)
