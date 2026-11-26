"""Manual ingest: single items, the browser extension's endpoints, and batches.

``POST /ingest/url``, ``POST /ingest/pdf`` and ``POST /ingest/page`` answer
with the entry in the same request (the Android client, the browser extension
and the ``ingest_url`` registry tool rely on that). Everything else is a
batch: the request validates and stores, a Celery task per item parses, and
``GET /ingest/batches/{id}`` reports one status per item. Mounted under
``/api/entries``.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, File, Form, Query, Response, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.ingest_batch import ITEM_CREATED, RETRYABLE_ITEM_STATUSES, IngestBatch, IngestBatchItem
from app.models.user import User
from app.schemas.ingest import (
    EntryByURLResponse,
    EntryResultsResponse,
    IngestBatchCreate,
    IngestBatchListItem,
    IngestBatchResponse,
    IngestCapabilities,
    IngestFileInfo,
    IngestItemResponse,
    IngestPageRequest,
    IngestPageResponse,
    IngestResponse,
    IngestTextRequest,
    IngestURLRequest,
    IngestURLsRequest,
    PageCoverageResponse,
)
from app.services import ingest_batches as batches
from app.services import ingest_files as store
from app.services.ingest_parsers import SUPPORTED_EXTENSIONS

router = APIRouter()
logger = logging.getLogger(__name__)


# --- single items: the entry is returned in the same request -----------------


@router.post("/ingest/url", response_model=IngestResponse)
async def ingest_url(
    body: IngestURLRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Ingest a web page/article URL as a manual entry, synchronously."""
    from app.services.manual_ingest import ingest_url as do_ingest_url

    entry = await do_ingest_url(db, body.url.strip(), user.id)
    await db.commit()
    _after_create(entry, "url")

    return IngestResponse(
        id=entry.id,
        title=entry.title,
        url=entry.url,
        word_count=entry.word_count,
        feed_id=entry.feed_id,
        content_hash=entry.content_hash,
        message="Entry created",
    )


@router.post("/ingest/page", response_model=IngestPageResponse, status_code=201)
async def ingest_page(
    body: IngestPageRequest,
    response: Response,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create an entry for the page the sender is reading (the browser extension's Send).

    With ``html`` (the page's rendered DOM) the server does not fetch the URL,
    so pages behind a login, a paywall or robots.txt can be sent. The HTML is
    extracted and sanitized the same way as a fetched page. Without ``html``
    the URL is fetched, as ``/ingest/url`` does.

    The entry goes on the shared Manual Uploads feed, which every user can see.

    Sending a page that is already in IntelFeed returns ``200`` with the
    existing entry and ``created: false``. Tags and the note (saved as a Note
    on the entry) are applied in both cases.
    """
    from app.services.manual_ingest import ingest_page as do_ingest_page

    entry, created = await do_ingest_page(
        db,
        url=body.url.strip(),
        user_id=user.id,
        html=body.html,
        title=(body.title or "").strip() or None,
        selection=body.selection,
        published_at=body.published_at,
        author=(body.author or "").strip() or None,
        client=body.client,
    )
    await _apply_send_extras(db, entry, user, tag_ids=body.tag_ids, note=body.note)
    await db.commit()
    if created:
        _after_create(entry, "page")
    else:
        response.status_code = 200

    return IngestPageResponse(
        id=entry.id,
        title=entry.title,
        url=entry.url,
        word_count=entry.word_count,
        feed_id=entry.feed_id,
        content_hash=entry.content_hash,
        message="Entry created" if created else "Already collected",
        created=created,
    )


@router.get("/ingest/lookup", response_model=EntryByURLResponse)
async def lookup_entry_by_url(
    url: str = Query(..., max_length=4000, description="The page URL; a #fragment is ignored"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The newest entry the caller can see for this exact URL, on any feed. 404 when none."""
    from app.models.feed import Feed
    from app.services.manual_ingest import find_entry_by_url

    entry = await find_entry_by_url(db, url.strip(), user.id)
    if entry is None:
        raise AppError(code="not_found", message="No entry for this URL", status_code=404)
    from app.services.entry_results import entry_thread

    feed_title = (await db.execute(select(Feed.title).where(Feed.id == entry.feed_id))).scalar_one_or_none()
    return EntryByURLResponse(
        id=entry.id,
        title=entry.title,
        url=entry.url,
        feed_id=entry.feed_id,
        feed_title=feed_title,
        published_at=entry.published_at,
        fetched_at=entry.fetched_at,
        thread=await entry_thread(db, entry.id),
    )


@router.get("/ingest/coverage", response_model=PageCoverageResponse)
async def page_coverage(
    title: str = Query(..., max_length=1000, description="The page's title"),
    url: str | None = Query(None, max_length=4000, description="The page's URL; an entry at this URL is left out"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Recent entries about the same story as a page that is not in IntelFeed yet.

    Searches entries from the last 14 days for the page title's keywords and
    keeps those whose titles share at least 40% of the keywords (at least two).
    Returns up to five of them, how many different sites they come from, and
    the story thread most of them belong to."""
    from app.services.entry_results import page_coverage as coverage

    return PageCoverageResponse(**await coverage(db, user.id, title=title.strip(), url=url))


async def _apply_send_extras(
    db: AsyncSession, entry, user: User, *, tag_ids: list[uuid.UUID], note: str | None
) -> None:
    """Apply the tags and note sent with a page or PDF: the tags as the sender's
    own assignments, and the note as a Note on the entry (the same kind the
    reader's Notes panel makes)."""
    if tag_ids:
        from app.services.entry_tags import add_tags_by_id

        await add_tags_by_id(db, entry.id, tag_ids, user.id)
    if note and note.strip():
        from app.models.note import Note
        from app.services.markdown import render_markdown

        content = note.strip()
        db.add(
            Note(
                created_by=user.id,
                entry_id=entry.id,
                title=(entry.title or "Untitled")[:500],
                content_markdown=content,
                content_html=render_markdown(content),
            )
        )
        await db.flush()


def _after_create(entry, source: str) -> None:
    """After a new entry is committed: start the pipeline, index it in search, and send the SSE event."""
    from app.workers.feed_tasks import dispatch_entry_pipeline

    dispatch_entry_pipeline(str(entry.id), run_extraction=True)
    _index_entry(entry)
    try:
        from app.api.events import broadcast_event

        broadcast_event(
            "entry_ingested",
            {
                "entry_id": str(entry.id),
                "feed_id": str(entry.feed_id),
                "title": entry.title,
                "source": source,
            },
        )
    except Exception:
        logger.debug("Failed to broadcast ingest event", exc_info=True)


@router.post("/ingest/pdf", response_model=IngestResponse)
async def ingest_pdf(
    file: UploadFile = File(..., description="The PDF document to ingest"),
    title: str = Form(None, description="Optional title override; defaults to the PDF's metadata title or filename"),
    url: str = Form(None, description="Where the PDF was opened from; stored as the entry's URL"),
    note: str = Form(None, description="Saved as a Note on the entry"),
    tag_ids: list[uuid.UUID] = Form([], description="The sender's tags for the entry (repeat the field)"),
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

    from app.services.manual_ingest import strip_fragment

    source_url = strip_fragment((url or "").strip()) or None
    if source_url and not source_url.lower().startswith(("http://", "https://")):
        # Keep only http(s) URLs: file:// and blob: URLs work only on the sender's machine.
        source_url = None

    batch = await batches.create_batch(db, user.id, source="legacy")
    item = await batches.add_file_item(
        db,
        batch,
        data=content,
        filename=file.filename or "upload.pdf",
        content_type="application/pdf",
        title=(title or "").strip() or None,
        source_url=source_url,
    )
    if item.status == "too_large":
        raise AppError(code="file_too_large", message=item.error or "PDF is too large", status_code=413)
    await db.commit()

    item = await batches.process_item(db, item.id)
    if item.status == "duplicate" and item.entry_id and (note or tag_ids):
        from app.models.entry import Entry

        existing = (await db.execute(select(Entry).where(Entry.id == item.entry_id))).scalar_one_or_none()
        if existing is not None:
            await _apply_send_extras(db, existing, user, tag_ids=tag_ids, note=note)
            await db.commit()
    if item.status != ITEM_CREATED:
        code, status = {
            "duplicate": ("duplicate", 409),
            "no_text": ("extraction_failed", 422),
            "unsupported": ("invalid_file", 400),
            "too_large": ("file_too_large", 413),
        }.get(item.status, ("ingest_failed", 500))
        raise AppError(
            code=code,
            message=item.error or "Could not ingest this PDF",
            status_code=status,
            # The existing entry, so a client can open it instead.
            details=[{"entry_id": str(item.entry_id)}] if item.entry_id else None,
        )

    from app.models.entry import Entry

    entry = (await db.execute(select(Entry).where(Entry.id == item.entry_id))).scalar_one()
    if note or tag_ids:
        await _apply_send_extras(db, entry, user, tag_ids=tag_ids, note=note)
        await db.commit()
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


# --- results, for the client that sent a page -------------------------------------


@router.get("/ingest/{entry_id}/results", response_model=EntryResultsResponse)
async def entry_results(
    entry_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """What the pipeline found in an entry, and whether it is finished.

    The browser extension polls this after a send until ``state`` is no longer
    ``processing``, then tells the sender what came out of the page.
    """
    from app.api.engine import entry_pipeline_status
    from app.services.entry_results import entry_findings, entry_thread, visible_entry

    entry = await visible_entry(db, entry_id, user.id)
    if entry is None:
        raise AppError(code="not_found", message="Entry not found", status_code=404)
    status = (await entry_pipeline_status(db, entry_id))["status"]
    state = {"complete": "done", "errored": "errored"}.get(status, "processing")
    if status == "unknown" and not _recently_created(entry):
        # No pipeline record yet is normal for a new entry: run rows are written
        # only when a stage starts, and the queue may be behind.
        state = "unknown"
    return EntryResultsResponse(
        entry_id=entry_id,
        state=state,
        thread=await entry_thread(db, entry_id),
        **await entry_findings(db, entry_id),
    )


# How long a new entry with no pipeline record counts as waiting in the queue.
# The extension stops polling after 30 minutes.
PIPELINE_START_GRACE = timedelta(minutes=30)


def _recently_created(entry) -> bool:
    created = entry.created_at or entry.fetched_at
    if created is None:
        return False
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    return datetime.now(UTC) - created < PIPELINE_START_GRACE
