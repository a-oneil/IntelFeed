import logging
import uuid

from fastapi import APIRouter, Depends, File, Form, UploadFile
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.user import User

router = APIRouter()
logger = logging.getLogger(__name__)


class IngestURLRequest(BaseModel):
    url: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"url": "https://www.bleepingcomputer.com/news/security/lockbit-returns-with-new-encryptor/"}
        }
    )


class IngestResponse(BaseModel):
    id: uuid.UUID
    title: str
    url: str | None
    word_count: int | None
    feed_id: uuid.UUID
    content_hash: str | None
    message: str


@router.post("/ingest/url", response_model=IngestResponse)
async def ingest_url(
    body: IngestURLRequest,
    _user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Ingest a web page/article URL as a manual entry."""
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
    _user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Ingest a PDF file as a manual entry."""
    # Validate file type
    if file.content_type and file.content_type != "application/pdf":
        # Also accept octet-stream since some clients don't set the correct type
        if file.content_type != "application/octet-stream":
            raise AppError(code="invalid_file", message="File must be a PDF", status_code=400)

    content = await file.read()

    # Validate it's actually a PDF (magic bytes check)
    if not content[:5].startswith(b"%PDF-"):
        raise AppError(code="invalid_file", message="File does not appear to be a valid PDF", status_code=400)

    from app.services.manual_ingest import ingest_pdf as do_ingest_pdf

    filename = file.filename or "upload.pdf"
    entry = await do_ingest_pdf(db, content, filename, title)
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
                "source": "pdf",
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
