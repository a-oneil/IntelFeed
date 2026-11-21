"""Evidence shown beside a Review row: an article and the paragraph behind it."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class EvidenceArticle(BaseModel):
    entry_id: uuid.UUID
    title: str
    feed_title: str
    published_at: datetime | None
    # The paragraphs the match came from (or the first mentioning it), whole
    # up to EVIDENCE_PARAGRAPH_MAX (app/api/hygiene.py) characters.
    paragraphs: list[str]
    highlight: list[str] = Field(description="Names to mark in the paragraphs")
