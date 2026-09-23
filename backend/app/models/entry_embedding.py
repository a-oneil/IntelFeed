import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.vector_types import HalfVec

# nomic-embed-text's native width. Changing this is a re-embed of the corpus,
# not a config tweak — the column type is fixed at the schema level.
EMBEDDING_DIM = 768


class EntryEmbedding(Base):
    """One dense vector per entry — the substrate under Story Threads.

    Written only by the embedding sweeper, keyed by ``content_hash`` so an entry
    whose text has not changed is never re-embedded. Rows cascade with their
    entry.
    """

    __tablename__ = "entry_embeddings"

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
    )
    embedding: Mapped[list[float]] = mapped_column(HalfVec(EMBEDDING_DIM), nullable=False)
    model: Mapped[str] = mapped_column(String(80), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # When the thread sweeper last considered this entry. Null means never; see
    # app.intelligence.story_threads._candidate_entries for the recheck rule.
    threaded_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # When ``content_hash`` was last confirmed to match the entry's current text.
    # Null sorts first in the re-hash pass; see app.services.embeddings.sweep.
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_entry_embeddings_model", "model"),)
