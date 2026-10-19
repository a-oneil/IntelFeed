"""Priority Queue — the ranked reading queue, entries and story threads in one list.

The queue is not just a sorted entry list: a story covered by eleven outlets is
one row, not eleven, and the thread row ranks by the best unread beat it holds.
Assembling that server-side means every consumer (the reader, the CLI, an agent)
sees the same queue in the same order.
"""

import uuid
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.entry import EntryResponse
from app.schemas.thread import ThreadSummary


class PriorityQueueRow(BaseModel):
    """One row of the queue: either a single entry or a folded story thread."""

    kind: Literal["entry", "thread"] = Field(description="Which of `entry` / `thread` is populated")
    score: float = Field(
        description=(
            "Rank of this row on the 0–10 priority scale. For an entry it is its stored priority "
            "score; for a thread, the score of its best "
            "unread beat. Rows arrive sorted by this score, highest first."
        )
    )
    entry: EntryResponse | None = Field(None, description="Populated when kind is `entry`")
    thread: ThreadSummary | None = Field(None, description="Populated when kind is `thread`")
    absorbed_entry_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Thread rows only: members this row stands for, kept out of the queue as standalone entries",
    )


class PriorityQueueResponse(BaseModel):
    items: list[PriorityQueueRow]
    next_cursor: str | None = Field(None, description="Pass back as `cursor` for the next page")
    has_more: bool
    radar_threshold: float | None = Field(
        None,
        description=(
            "Score (0–10) an entry must clear to enter the queue. Null when the signal engine is not surfacing, "
            "in which case the queue is every unread entry ranked by score rather than a filtered set."
        ),
    )
