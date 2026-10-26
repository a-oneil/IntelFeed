"""Manual ingest: the two synchronous one-item doors, and batches.

``POST /ingest/url`` and ``POST /ingest/pdf`` answer with the entry in the
same request (the Android client and the ``ingest_url`` registry tool rely on
that). Everything else is a batch: the request validates and stores, a Celery
task per item parses, and ``GET /ingest/batches/{id}`` reports one status per
item. Mounted under ``/api/entries``.
"""

import logging
import uuid

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.ingest_batch import ITEM_CREATED, RETRYABLE_ITEM_STATUSES, IngestBatch, IngestBatchItem
from app.models.user import User
from app.schemas.ingest import (
    IngestBatchCreate,
    IngestBatchListItem,
    IngestBatchResponse,
    IngestCapabilities,
    IngestFileInfo,
    IngestItemResponse,
    IngestResponse,
    IngestTextRequest,
    IngestURLRequest,
    IngestURLsRequest,
)
from app.services import ingest_batches as batches
from app.services import ingest_files as store
from app.services.ingest_parsers import SUPPORTED_EXTENSIONS

router = APIRouter()
logger = logging.getLogger(__name__)


# --- the one-item doors (unchanged contract) ----------------------------------


@router.post("/ingest/url", response_model=IngestResponse)
async def ingest_url(
    body: IngestURLRequest,
    _user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Ingest a web page/article URL as a manual entry, synchronously."""
    from app.services.manual_ingest import ingest_url as do_ingest_url

    entry = await do_ingest_url(db, body.url.strip())
    await db.commit()

    # Dispatch the full intelligence pipeline
    from app.workers.feed_tasks import dispatch_entry_pipeline

    dispatch_entry_pipeline(str(entry.id), run_extraction=True)

    # Index in Meilisearch
    _index_entry(entry)

    # Broadcast SSE event
    try:
        from app.api.events import broadcast_event

        broadcast_event(
            "entry_ingested",
            {
                "entry_id": str(entry.id),
                "feed_id": str(entry.feed_id),
                "title": entry.title,
                "source": "url",
            },
        )
    except Exception:
        logger.debug("Failed to broadcast ingest event", exc_info=True)

    return IngestResponse(
        id=entry.id,
        title=entry.title,
        url=entry.url,
        word_count=entry.word_count,
        feed_id=entry.feed_id,
        content_hash=entry.content_hash,
        message="Entry created",
    )


@router.post("/ingest/pdf", response_model=IngestResponse)
async def ingest_pdf(
    file: UploadFile = File(..., description="The PDF document to ingest"),
    title: str = Form(None, description="Optional title override; defaults to the PDF's metadata title or filename"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Ingest one PDF as a manual entry, synchronously.

    Runs as a one-item batch so the original file is kept and downloadable,
    but answers with the entry like it always has. Duplicate (409), scanned
    PDF (422), oversize (413) and bad file (400) stay request-level errors
    here; the batch endpoints report those per item instead.
    """
    if file.content_type and file.content_type not in ("application/pdf", "application/octet-stream"):
        raise AppError(code="invalid_file", message="File must be a PDF", status_code=400)

    content = await file.read()
    if not content[:5].startswith(b"%PDF-"):
        raise AppError(code="invalid_file", message="File does not appear to be a valid PDF", status_code=400)

    batch = await batches.create_batch(db, user.id, source="legacy")
    item = await batches.add_file_item(
        db,
        batch,
        data=content,
        filename=file.filename or "upload.pdf",
        content_type="application/pdf",
        title=(title or "").strip() or None,
    )
    if item.status == "too_large":
        raise AppError(code="file_too_large", message=item.error or "PDF is too large", status_code=413)
    await db.commit()

    item = await batches.process_item(db, item.id)
    if item.status != ITEM_CREATED:
        code, status = {
            "duplicate": ("duplicate", 409),
            "no_text": ("extraction_failed", 422),
            "unsupported": ("invalid_file", 400),
            "too_large": ("file_too_large", 413),
        }.get(item.status, ("ingest_failed", 500))
        raise AppError(code=code, message=item.error or "Could not ingest this PDF", status_code=status)

    from app.models.entry import Entry

    entry = (await db.execute(select(Entry).where(Entry.id == item.entry_id))).scalar_one()
    return IngestResponse(
        id=entry.id,
        title=entry.title,
        url=entry.url,
        word_count=entry.word_count,
        feed_id=entry.feed_id,
        content_hash=entry.content_hash,
        message="Entry created",
    )


# --- batches ----------------------------------------------------------------------


@router.get("/ingest/capabilities", response_model=IngestCapabilities)
async def ingest_capabilities(_user: User = Depends(get_current_user)):
    """Accepted file types and the current caps, for the modal's hint text."""
    return IngestCapabilities(
        extensions=list(SUPPORTED_EXTENSIONS),
        max_file_mb=store.max_file_bytes() // (1024 * 1024),
        max_batch_items=store.max_batch_items(),
        zip_max_members=store.zip_max_members(),
    )


@router.post("/ingest/batches", response_model=IngestBatchResponse, status_code=201)
async def create_batch(
    body: IngestBatchCreate | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Open a batch. Add files, URLs and pastes to it with the item endpoints; each item
    is queued as soon as it is added, there is no separate submit step."""
    body = body or IngestBatchCreate()
    batch = await batches.create_batch(db, user.id, label=body.label, source=body.source)
    await db.commit()
    return await _batch_response(db, batch.id)


@router.get("/ingest/batches", response_model=list[IngestBatchListItem])
async def list_batches(
    limit: int = Query(20, ge=1, le=100),
    mine: bool = Query(False, description="Only batches this user created"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Recent batches, newest first. The manual feed is shared, so by default everyone's show."""
    query = select(IngestBatch).order_by(IngestBatch.created_at.desc()).limit(limit)
    if mine:
        query = query.where(IngestBatch.user_id == user.id)
    rows = (await db.execute(query)).scalars().all()
    if not rows:
        return []
    items_rows = (
        (await db.execute(select(IngestBatchItem).where(IngestBatchItem.batch_id.in_([b.id for b in rows]))))
        .scalars()
        .all()
    )
    by_batch: dict[uuid.UUID, list[IngestBatchItem]] = {b.id: [] for b in rows}
    for item in items_rows:
        by_batch[item.batch_id].append(item)
    return [
        IngestBatchListItem(
            id=b.id,
            user_id=b.user_id,
            label=b.label,
            source=b.source,
            created_at=b.created_at,
            summary=batches.summarize_items(by_batch[b.id]),
        )
        for b in rows
    ]


@router.get("/ingest/batches/{batch_id}", response_model=IngestBatchResponse)
async def get_batch(
    batch_id: uuid.UUID,
    _user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """One batch with every item's status. Poll this, or listen for the
    ``ingest_item_updated`` SSE event and refetch on each."""
    return await _batch_response(db, batch_id)


@router.post("/ingest/batches/{batch_id}/files", response_model=IngestItemResponse, status_code=201)
async def add_file(
    batch_id: uuid.UUID,
    file: UploadFile = File(..., description="PDF, DOCX, TXT, MD, HTML, CSV, EML, ZIP and friends"),
    title: str | None = Form(None, description="Title override for the entry"),
    is_ioc_list: bool = Form(False, description="Treat the body as a curated indicator list"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add one file to a batch. One request per file: production sits behind an
    edge that caps a request at 100 MB, so a forty-file multipart form would
    never arrive. The item is stored, queued and returned at once; its status
    changes as the worker gets to it."""
    batch = await _own_batch(db, batch_id, user)
    content = await file.read()
    if not content:
        raise AppError(code="empty_file", message="The file is empty", status_code=400)
    item = await batches.add_file_item(
        db,
        batch,
        data=content,
        filename=file.filename,
        content_type=file.content_type,
        title=(title or "").strip() or None,
        is_ioc_list=is_ioc_list,
    )
    await db.commit()
    batches.dispatch_item(item)
    return await _item_response(db, item.id)


@router.post("/ingest/batches/{batch_id}/urls", response_model=list[IngestItemResponse], status_code=201)
async def add_urls(
    batch_id: uuid.UUID,
    body: IngestURLsRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add URLs, one item each. A ``github.com/owner/repo`` link (optionally
    ``/tree/<branch>/<path>``) is fetched once through the repo adapter and
    expands into one item per file; no feed is created and nothing polls."""
    batch = await _own_batch(db, batch_id, user)
    items = await batches.add_url_items(db, batch, body.urls, is_ioc_list=body.is_ioc_list)
    await db.commit()
    batches.dispatch_items(items)
    return [await _item_response(db, i.id) for i in items]


@router.post("/ingest/batches/{batch_id}/text", response_model=IngestItemResponse, status_code=201)
async def add_text(
    batch_id: uuid.UUID,
    body: IngestTextRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add pasted text. One paste is one entry; the paste is kept as a .txt original."""
    batch = await _own_batch(db, batch_id, user)
    item = await batches.add_text_item(
        db, batch, text=body.text, title=body.title, source_url=body.source_url, is_ioc_list=body.is_ioc_list
    )
    await db.commit()
    batches.dispatch_item(item)
    return await _item_response(db, item.id)


@router.post("/ingest/batches/{batch_id}/items/{item_id}/retry", response_model=IngestItemResponse)
async def retry_item(
    batch_id: uuid.UUID,
    item_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Re-queue a failed item. Files re-run from the stored original."""
    await _own_batch(db, batch_id, user)
    item = await batches.get_item(db, item_id)
    if item is None or item.batch_id != batch_id:
        raise AppError(code="not_found", message="Ingest item not found", status_code=404)
    await batches.retry_item(db, item)
    await db.commit()
    batches.dispatch_item(item)
    return await _item_response(db, item.id)


@router.delete("/ingest/batches/{batch_id}/items/{item_id}", status_code=204)
async def delete_item(
    batch_id: uuid.UUID,
    item_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove an item and its stored file. The entry it produced, if any, is kept."""
    await _own_batch(db, batch_id, user)
    item = await batches.get_item(db, item_id)
    if item is None or item.batch_id != batch_id:
        raise AppError(code="not_found", message="Ingest item not found", status_code=404)
    await batches.cancel_item(db, item)
    await db.commit()
    return None


# --- helpers ---------------------------------------------------------------------


async def _own_batch(db: AsyncSession, batch_id: uuid.UUID, user: User) -> IngestBatch:
    batch = (await db.execute(select(IngestBatch).where(IngestBatch.id == batch_id))).scalar_one_or_none()
    if batch is None:
        raise AppError(code="not_found", message="Ingest batch not found", status_code=404)
    if batch.user_id != user.id and user.role != "admin":
        raise AppError(code="forbidden", message="This batch belongs to another user", status_code=403)
    return batch


def _file_info(item: IngestBatchItem) -> IngestFileInfo | None:
    f = item.file
    if f is None:
        return None
    return IngestFileInfo(
        id=f.id,
        filename=f.filename,
        content_type=f.content_type,
        size_bytes=f.size_bytes,
        retained=f.evicted_at is None,
        download_url=f"/api/ingest-files/{f.id}",
    )


def _item_to_response(item: IngestBatchItem, *, analysis_done: set, titles: dict) -> IngestItemResponse:
    phase = None
    if item.status == ITEM_CREATED and item.entry_id:
        phase = "done" if item.entry_id in analysis_done else "analyzing"
    return IngestItemResponse(
        id=item.id,
        batch_id=item.batch_id,
        parent_item_id=item.parent_item_id,
        position=item.position,
        kind=item.kind,
        status=item.status,
        phase=phase,
        filename=item.filename,
        content_type=item.content_type,
        size_bytes=item.size_bytes,
        title=item.title,
        source_url=item.source_url,
        is_ioc_list=item.is_ioc_list,
        entry_id=item.entry_id,
        entry_title=titles.get(item.entry_id) if item.entry_id else None,
        error=item.error,
        attempts=item.attempts,
        retryable=item.status in RETRYABLE_ITEM_STATUSES,
        file=_file_info(item),
        created_at=item.created_at,
        started_at=item.started_at,
        finished_at=item.finished_at,
    )


async def _batch_response(db: AsyncSession, batch_id: uuid.UUID) -> IngestBatchResponse:
    batch = await batches.get_batch(db, batch_id)
    if batch is None:
        raise AppError(code="not_found", message="Ingest batch not found", status_code=404)
    items = list(batch.items)
    if await batches.mark_stale_parsing(db, items):
        await db.commit()
    entry_ids = [i.entry_id for i in items if i.entry_id]
    analysis_done = await batches.analysis_done_entry_ids(db, entry_ids)
    titles = await batches.entry_titles(db, entry_ids)
    return IngestBatchResponse(
        id=batch.id,
        user_id=batch.user_id,
        label=batch.label,
        source=batch.source,
        created_at=batch.created_at,
        summary=batches.summarize_items(items),
        items=[_item_to_response(i, analysis_done=analysis_done, titles=titles) for i in items],
    )


async def _item_response(db: AsyncSession, item_id: uuid.UUID) -> IngestItemResponse:
    item = await batches.get_item(db, item_id)
    if item is None:
        raise AppError(code="not_found", message="Ingest item not found", status_code=404)
    entry_ids = [item.entry_id] if item.entry_id else []
    return _item_to_response(
        item,
        analysis_done=await batches.analysis_done_entry_ids(db, entry_ids),
        titles=await batches.entry_titles(db, entry_ids),
    )


def _index_entry(entry):
    """Index a manually ingested entry in Meilisearch."""
    try:
        from app.services.meilisearch_client import index_entry

        index_entry(
            entry_id=entry.id,
            feed_id=entry.feed_id,
            title=entry.title,
            content_text=entry.content_text,
            summary=entry.summary,
            author=entry.author,
            published_at=entry.published_at.isoformat() if entry.published_at else None,
            feed_type="manual",
            feed_title="Manual Uploads",
            word_count=entry.word_count,
        )
    except Exception:
        logger.warning("Meilisearch indexing failed for entry %s, queuing for retry", entry.id, exc_info=True)
        try:
            import redis as _redis

            from app.config import settings

            r = _redis.from_url(settings.redis_url)
            try:
                r.sadd("meili:failed_entry_ids", str(entry.id))
            finally:
                r.close()
        except Exception:
            pass
