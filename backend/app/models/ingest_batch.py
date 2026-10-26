"""Bulk ingest: a batch, its items, and the original files they came from.

A batch is a grouping object over ordinary entries, never an entry itself.
Every item that parses becomes one entry on the singleton Manual Uploads feed
(services/manual_ingest.py) and goes through the same pipeline as a polled
entry; search, the reader, story threads and scoring never learn that batches
exist. The only trace on the entry is ``metadata_.batch_id`` and the file
bookkeeping keys written by services/ingest_batches.py.

Every outcome is a status on the item row. A duplicate, a scanned PDF or an
oversize file is a row in the batch, not a failed request.
"""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

# --- item kinds -------------------------------------------------------------
KIND_URL = "url"  # one web page, fetched like POST /ingest/url
KIND_FILE = "file"  # an uploaded file (or a member expanded out of a .zip)
KIND_TEXT = "text"  # a paste; stored as a .txt original so it downloads like a file
KIND_GITHUB_REPO = "github_repo"  # a repo link; expands into one github_file item per file
KIND_GITHUB_FILE = "github_file"  # one file the repo adapter returned, already rendered
ITEM_KINDS = frozenset({KIND_URL, KIND_FILE, KIND_TEXT, KIND_GITHUB_REPO, KIND_GITHUB_FILE})

# --- item statuses ----------------------------------------------------------
ITEM_QUEUED = "queued"  # stored, waiting for a worker
ITEM_PARSING = "parsing"  # a worker owns it
ITEM_CREATED = "created"  # the entry exists; the pipeline and AI analysis follow on their own
ITEM_EXPANDED = "expanded"  # a .zip or repo that became child items (terminal for the parent)
ITEM_DUPLICATE = "duplicate"  # same URL / same bytes already ingested; entry_id points at the twin
ITEM_NO_TEXT = "no_text"  # parsed fine, nothing to read (scanned PDF, empty file)
ITEM_UNSUPPORTED = "unsupported"  # no parser for this type
ITEM_TOO_LARGE = "too_large"  # over the per-file cap; bytes were not stored
ITEM_FAILED = "failed"  # fetch or parse raised; ``error`` says why; retryable
ITEM_CANCELLED = "cancelled"  # removed by the analyst before a worker took it

ACTIVE_ITEM_STATUSES = frozenset({ITEM_QUEUED, ITEM_PARSING})
RETRYABLE_ITEM_STATUSES = frozenset({ITEM_FAILED, ITEM_CANCELLED, ITEM_NO_TEXT, ITEM_UNSUPPORTED})
ITEM_STATUSES = frozenset(
    {
        ITEM_QUEUED,
        ITEM_PARSING,
        ITEM_CREATED,
        ITEM_EXPANDED,
        ITEM_DUPLICATE,
        ITEM_NO_TEXT,
        ITEM_UNSUPPORTED,
        ITEM_TOO_LARGE,
        ITEM_FAILED,
        ITEM_CANCELLED,
    }
)


class IngestBatch(Base):
    __tablename__ = "ingest_batches"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Who dropped the pile. Entries have no owner column, so this is the only
    # place "uploaded by" lives.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    label: Mapped[str | None] = mapped_column(String(200))
    # ui | api | tool | legacy (the one-item batches the old URL/PDF endpoints make)
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="ui", server_default="ui")
    options: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    items = relationship(
        "IngestBatchItem", back_populates="batch", cascade="all, delete-orphan", order_by="IngestBatchItem.position"
    )


class IngestBatchItem(Base):
    __tablename__ = "ingest_batch_items"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ingest_batches.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # The .zip or repo item this one was expanded out of.
    parent_item_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ingest_batch_items.id", ondelete="SET NULL")
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=ITEM_QUEUED, index=True)
    filename: Mapped[str | None] = mapped_column(String(500))
    content_type: Mapped[str | None] = mapped_column(String(120))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    # Analyst-supplied title override; the parser's own title is used when empty.
    title: Mapped[str | None] = mapped_column(String(2000))
    # The URL for url/github items; the optional "where this came from" for pastes.
    source_url: Mapped[str | None] = mapped_column(Text)
    # Routes the body through the curated indicator-list door (observables
    # stage reads metadata.content_type == "ioc_list"). Opt-in per item: regex
    # never creates a ledger row, and a bulk paste does not change that.
    is_ioc_list: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    # The entry this item produced — or, for a duplicate, the entry it duplicates.
    entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL"), index=True
    )
    error: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    # Kind-specific payload: github owner/repo/branch/path for repo items; the
    # adapter's rendered html + metadata for github_file items; zip member name.
    extra: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    batch = relationship("IngestBatch", back_populates="items")
    file = relationship("IngestFile", back_populates="item", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (Index("ix_ingest_batch_items_batch_position", "batch_id", "position"),)


class IngestFile(Base):
    """The original bytes of one item, on disk under ``settings.ingest_files_dir``.

    ``path`` is relative to that directory (``<batch_id>/<file_id>.<ext>``).
    Served by app/api/ingest_files.py; evicted by the TTL sweep in
    workers/maintenance.py, which clears the file and stamps ``evicted_at`` but
    keeps this row and the entry, so the reader can say "original not kept"
    instead of offering a dead link.
    """

    __tablename__ = "ingest_files"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    item_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ingest_batch_items.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ingest_batches.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL"), index=True
    )
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    content_type: Mapped[str] = mapped_column(String(120), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String(600), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    evicted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    item = relationship("IngestBatchItem", back_populates="file")
