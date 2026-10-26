"""Bulk ingest orchestration: batches of files, URLs, pastes and one-time GitHub repos.

The request path validates, stores the original and queues one Celery task
per item (workers/ingest_tasks.py). The task parses, creates one ordinary
entry on the Manual Uploads feed and dispatches the same pipeline a polled
entry gets. Every outcome is a status on the item row — a duplicate or a
scanned PDF never fails the batch.

Three rules this module keeps, by design (GitHub issue #13):

* One entry per item, never one per batch or per repo.
* Bulk items take the normal AI path with the normal entity-creation gates.
  A forty-file dump is exactly when a bypass would flood the entity tables.
* Regex never creates an observable. An item marked as an indicator list is
  stamped ``metadata.content_type = "ioc_list"`` and the observables stage
  routes it through the curated-list door; unmarked prose stays on the
  candidate path.
"""

import hashlib
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import AppError
from app.models.entry import Entry
from app.models.ingest_batch import (
    ACTIVE_ITEM_STATUSES,
    ITEM_CANCELLED,
    ITEM_CREATED,
    ITEM_DUPLICATE,
    ITEM_EXPANDED,
    ITEM_FAILED,
    ITEM_NO_TEXT,
    ITEM_PARSING,
    ITEM_QUEUED,
    ITEM_TOO_LARGE,
    ITEM_UNSUPPORTED,
    KIND_FILE,
    KIND_GITHUB_FILE,
    KIND_GITHUB_REPO,
    KIND_TEXT,
    KIND_URL,
    RETRYABLE_ITEM_STATUSES,
    IngestBatch,
    IngestBatchItem,
    IngestFile,
)
from app.services import ingest_files as store
from app.services.ingest_parsers import (
    KIND_PDF,
    KIND_ZIP,
    EmptyDocument,
    ParsedDocument,
    UnsupportedFormat,
    ZipLimitExceeded,
    decode_text,
    detect_kind,
    iter_zip_members,
    parse_document,
)
from app.services.manual_ingest import (
    DuplicateEntry,
    bytes_guid,
    create_manual_entry,
    fetch_url_document,
    url_guid,
    validate_http_url,
)

logger = logging.getLogger(__name__)

#: A worker that died mid-parse leaves an item in ``parsing`` forever; reads
#: older than this flip it to failed so the analyst gets a retry button.
STALE_PARSING_AFTER = timedelta(hours=1)

GITHUB_REPO_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?"
    r"(?:/(?:tree|blob)/(?P<ref>[^/]+)(?:/(?P<path>.*?))?)?/?$"
)

# Source labels written to entry metadata. ``url_ingest`` / ``pdf_upload`` are
# the historical values and stay, so nothing that filtered on them changes.
SOURCE_BY_KIND = {KIND_URL: "url_ingest", KIND_FILE: "file_upload", KIND_TEXT: "text_paste"}


def parse_github_repo_url(url: str) -> dict | None:
    """``github.com/owner/repo[/tree/<ref>[/path]]`` → owner/repo/branch/path, else None."""
    match = GITHUB_REPO_RE.match(url.strip())
    if not match:
        return None
    owner, repo = match.group("owner"), match.group("repo")
    if owner.lower() in ("orgs", "topics", "settings", "marketplace", "features", "sponsors"):
        return None
    path = (match.group("path") or "").strip("/")
    return {"owner": owner, "repo": repo, "branch": match.group("ref"), "path": path or None}


# --- building a batch ---------------------------------------------------------


async def create_batch(
    db: AsyncSession,
    user_id: uuid.UUID | None,
    *,
    label: str | None = None,
    source: str = "ui",
    options: dict | None = None,
) -> IngestBatch:
    batch = IngestBatch(user_id=user_id, label=(label or None), source=source, options=options or {})
    db.add(batch)
    await db.flush()
    return batch


async def get_batch(db: AsyncSession, batch_id: uuid.UUID) -> IngestBatch | None:
    result = await db.execute(
        select(IngestBatch)
        .options(selectinload(IngestBatch.items).selectinload(IngestBatchItem.file))
        .where(IngestBatch.id == batch_id)
    )
    return result.scalar_one_or_none()


async def get_item(db: AsyncSession, item_id: uuid.UUID) -> IngestBatchItem | None:
    result = await db.execute(
        select(IngestBatchItem)
        .options(selectinload(IngestBatchItem.file), selectinload(IngestBatchItem.batch))
        .where(IngestBatchItem.id == item_id)
    )
    return result.scalar_one_or_none()


async def _next_position(db: AsyncSession, batch_id: uuid.UUID) -> int:
    result = await db.execute(
        select(func.coalesce(func.max(IngestBatchItem.position), -1)).where(IngestBatchItem.batch_id == batch_id)
    )
    return int(result.scalar_one()) + 1


async def _ensure_room(db: AsyncSession, batch_id: uuid.UUID, adding: int = 1) -> None:
    result = await db.execute(
        select(func.count()).select_from(IngestBatchItem).where(IngestBatchItem.batch_id == batch_id)
    )
    cap = store.max_batch_items()
    if int(result.scalar_one()) + adding > cap:
        raise AppError(code="batch_full", message=f"A batch holds at most {cap} items", status_code=400)


def _new_item(batch: IngestBatch, position: int, **fields) -> IngestBatchItem:
    item = IngestBatchItem(batch_id=batch.id, position=position, **fields)
    return item


async def add_file_item(
    db: AsyncSession,
    batch: IngestBatch,
    *,
    data: bytes,
    filename: str | None,
    content_type: str | None,
    title: str | None = None,
    source_url: str | None = None,
    is_ioc_list: bool = False,
    kind: str = KIND_FILE,
    parent: IngestBatchItem | None = None,
    extra: dict | None = None,
) -> IngestBatchItem:
    """Store one upload and queue it. Over the cap → a ``too_large`` row, no bytes kept."""
    await _ensure_room(db, batch.id)
    filename = (filename or "upload.bin").strip()[:500]
    content_type = (content_type or "application/octet-stream").split(";", 1)[0].strip()[:120]
    position = await _next_position(db, batch.id)
    item = _new_item(
        batch,
        position,
        kind=kind,
        status=ITEM_QUEUED,
        filename=filename,
        content_type=content_type,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        title=(title or None),
        source_url=(source_url or None),
        is_ioc_list=bool(is_ioc_list),
        parent_item_id=parent.id if parent else None,
        extra=extra or {},
    )
    cap = store.max_file_bytes()
    if len(data) > cap:
        item.status = ITEM_TOO_LARGE
        item.error = f"{len(data) // (1024 * 1024)} MB is over the {cap // (1024 * 1024)} MB per-file cap"
        item.finished_at = datetime.now(UTC)
        db.add(item)
        await db.flush()
        return item

    db.add(item)
    await db.flush()
    file_id = uuid.uuid4()
    file_row = IngestFile(
        id=file_id,
        item_id=item.id,
        batch_id=batch.id,
        filename=filename,
        content_type=content_type,
        size_bytes=len(data),
        sha256=item.sha256,
        path=store.relative_path(batch.id, file_id, filename),
    )
    store.write_bytes(file_row.path, data)
    db.add(file_row)
    await db.flush()
    item.file = file_row
    return item


def _slug(text: str | None) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", text or "").strip("-").lower()
    return slug[:60] or "pasted-text"


async def add_text_item(
    db: AsyncSession,
    batch: IngestBatch,
    *,
    text: str,
    title: str | None = None,
    source_url: str | None = None,
    is_ioc_list: bool = False,
) -> IngestBatchItem:
    """A paste is stored as a .txt original, so it downloads like any file."""
    if not text or not text.strip():
        raise AppError(code="empty_text", message="Paste some text first", status_code=400)
    if source_url:
        validate_http_url(source_url)
    return await add_file_item(
        db,
        batch,
        data=text.encode("utf-8"),
        filename=f"{_slug(title)}.txt",
        content_type="text/plain",
        title=title,
        source_url=source_url,
        is_ioc_list=is_ioc_list,
        kind=KIND_TEXT,
    )


async def add_url_items(
    db: AsyncSession,
    batch: IngestBatch,
    urls: list[str],
    *,
    is_ioc_list: bool = False,
) -> list[IngestBatchItem]:
    """One item per distinct URL. A GitHub repo link becomes a ``github_repo``
    item; a non-http line becomes a ``failed`` row rather than a 400 — the
    other thirty-nine lines still go through."""
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in urls:
        url = (raw or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        cleaned.append(url)
    if not cleaned:
        raise AppError(code="no_urls", message="Add at least one URL", status_code=400)
    await _ensure_room(db, batch.id, adding=len(cleaned))

    items: list[IngestBatchItem] = []
    position = await _next_position(db, batch.id)
    for url in cleaned:
        repo = parse_github_repo_url(url)
        if repo:
            item = _new_item(
                batch,
                position,
                kind=KIND_GITHUB_REPO,
                status=ITEM_QUEUED,
                source_url=url,
                filename=f"{repo['owner']}/{repo['repo']}",
                is_ioc_list=bool(is_ioc_list),
                extra={"github": repo},
            )
        else:
            item = _new_item(
                batch, position, kind=KIND_URL, status=ITEM_QUEUED, source_url=url, is_ioc_list=bool(is_ioc_list)
            )
            try:
                validate_http_url(url)
            except AppError as exc:
                item.status = ITEM_FAILED
                item.error = exc.message
                item.finished_at = datetime.now(UTC)
        db.add(item)
        items.append(item)
        position += 1
    await db.flush()
    return items


def dispatch_item(item: IngestBatchItem) -> None:
    """Queue the worker task. Call after the transaction that created the item commits."""
    if item.status != ITEM_QUEUED:
        return
    from app.workers.ingest_tasks import process_ingest_item

    process_ingest_item.delay(str(item.id))


def dispatch_items(items: list[IngestBatchItem]) -> None:
    for item in items:
        if item.status == ITEM_QUEUED:
            dispatch_item(item)


# --- processing one item ---------------------------------------------------


def _entry_metadata(item: IngestBatchItem, *, source: str, doc_meta: dict | None = None, user_id=None) -> dict:
    meta: dict = {
        "source": source,
        "batch_id": str(item.batch_id),
        "ingest_item_id": str(item.id),
    }
    if item.filename:
        meta["filename"] = item.filename
    if item.content_type:
        meta["file_content_type"] = item.content_type
    if item.size_bytes is not None:
        meta["size_bytes"] = int(item.size_bytes)
    if item.file is not None:
        meta["ingest_file_id"] = str(item.file.id)
        meta["original_retained"] = True
    if user_id:
        meta["uploaded_by"] = str(user_id)
    if item.is_ioc_list:
        # The curated-list door: workers/intel_feed_tasks.py reads this.
        meta["content_type"] = "ioc_list"
    if doc_meta:
        for key in ("from", "to", "date", "attachments", "rows", "truncated"):
            if key in doc_meta:
                meta[key] = doc_meta[key]
    return meta


async def _create_from_document(
    db: AsyncSession,
    item: IngestBatchItem,
    doc: ParsedDocument,
    *,
    guid: str,
    source: str,
    url: str | None,
    user_id,
) -> Entry:
    title = (item.title or "").strip() or (doc.title or "").strip()
    if not title:
        title = re.sub(r"\.[A-Za-z0-9]{1,8}$", "", item.filename or "") or url or "Untitled"
    metadata = _entry_metadata(item, source=source, doc_meta=doc.meta, user_id=user_id)
    if item.is_ioc_list:
        # store_ioc_list_observables parses metadata.raw_content first; the
        # pristine text beats HTML-stripped text for a one-value-per-line file.
        metadata["raw_content"] = doc.text
    return await create_manual_entry(
        db,
        guid=guid,
        title=title,
        html=doc.html,
        text=doc.text,
        url=url,
        image_url=doc.meta.get("image_url"),
        metadata=metadata,
    )


async def _expand_zip(db: AsyncSession, item: IngestBatchItem, data: bytes) -> list[IngestBatchItem]:
    batch = item.batch
    members = list(iter_zip_members(data, max_members=store.zip_max_members(), max_member_bytes=store.max_file_bytes()))
    if not members:
        raise EmptyDocument("the archive holds no readable files")
    children: list[IngestBatchItem] = []
    for name, payload in members:
        child = await add_file_item(
            db,
            batch,
            data=payload,
            filename=name.rsplit("/", 1)[-1],
            content_type="application/octet-stream",
            is_ioc_list=item.is_ioc_list,
            parent=item,
            extra={"zip_member": name, "archive": item.filename},
        )
        children.append(child)
    return children


async def _expand_github_repo(db: AsyncSession, item: IngestBatchItem) -> list[IngestBatchItem]:
    """Run the repo adapter's full-tree import once, with a throwaway config,
    and turn each returned file into a ``github_file`` item. No feed row is
    created and nothing polls afterwards."""
    from app.adapters.github_repo import GitHubRepoAdapter

    repo = dict(item.extra.get("github") or {})
    if not repo.get("owner") or not repo.get("repo"):
        raise UnsupportedFormat("not a GitHub repository link")
    paths = [f"{repo['path'].rstrip('/')}/**"] if repo.get("path") else []
    adapter = GitHubRepoAdapter()
    branches = [repo["branch"]] if repo.get("branch") else ["main", "master"]
    parsed_entries = []
    used_branch = branches[0]
    for branch in branches:
        config = {"owner": repo["owner"], "repo": repo["repo"], "branch": branch, "paths": paths}
        _meta, parsed_entries = await adapter.fetch_full_tree(config)
        used_branch = branch
        if parsed_entries:
            break
    if not parsed_entries:
        raise EmptyDocument("the repository returned no readable files (private, empty, or the branch does not exist)")

    cap = store.max_batch_items()
    batch = item.batch
    children: list[IngestBatchItem] = []
    for parsed in parsed_entries:
        if len(children) >= cap:
            item.extra = {**item.extra, "truncated_at": cap}
            break
        meta = dict(parsed.metadata or {})
        raw = meta.pop("raw_content", None)
        file_path = meta.get("file_path") or parsed.title
        payload = (raw or "").encode("utf-8")
        child = await add_file_item(
            db,
            batch,
            data=payload,
            filename=file_path.rsplit("/", 1)[-1],
            content_type="text/plain",
            source_url=parsed.url,
            is_ioc_list=item.is_ioc_list,
            kind=KIND_GITHUB_FILE,
            parent=item,
            extra={
                "github": {**repo, "branch": used_branch, "file_path": file_path},
                "title": parsed.title,
                "content_html": parsed.content_html,
                "summary": parsed.summary,
                "adapter_metadata": meta,
            },
        )
        children.append(child)
    return children


async def _create_github_file_entry(db: AsyncSession, item: IngestBatchItem, user_id) -> Entry:
    from app.services.sanitizer import html_to_text, sanitize_html

    gh = item.extra.get("github") or {}
    adapter_meta = dict(item.extra.get("adapter_metadata") or {})
    content_html = item.extra.get("content_html") or ""
    sanitized = sanitize_html(content_html) if content_html else None
    text = html_to_text(content_html) if content_html else ""
    if not text.strip() and item.file is not None:
        try:
            text = decode_text(store.read_bytes(item.file.path))
        except FileNotFoundError:
            text = ""
    if not text.strip():
        raise EmptyDocument("empty file")
    metadata = _entry_metadata(item, source="github_repo", user_id=user_id)
    # The adapter's own classification (sigma / yara / ioc_list for repos it
    # knows) rides along; the analyst's explicit indicator-list mark wins.
    for key in ("owner", "repo", "file_path", "commit_sha", "content_type", "extracted"):
        if key in adapter_meta and key not in metadata:
            metadata[key] = adapter_meta[key]
    if item.is_ioc_list:
        metadata["content_type"] = "ioc_list"
        metadata["raw_content"] = text
    guid = f"manual:github:{gh.get('owner')}/{gh.get('repo')}/{gh.get('file_path')}"
    return await create_manual_entry(
        db,
        guid=guid,
        title=(item.title or item.extra.get("title") or item.filename or "Untitled").strip(),
        html=sanitized or f"<pre><code>{text}</code></pre>",
        text=text,
        url=item.source_url,
        author="manual-repo-import",
        metadata=metadata,
    )


async def process_item(db: AsyncSession, item_id: uuid.UUID) -> IngestBatchItem:
    """Parse one item into an entry (or a terminal status). Commits.

    Safe to call again for an item left in ``parsing`` by a dead worker.
    After the commit, dispatches the entry pipeline, indexes for search and
    broadcasts ``entry_ingested`` + ``ingest_item_updated``.
    """
    item = await get_item(db, item_id)
    if item is None:
        raise AppError(code="not_found", message="Ingest item not found", status_code=404)
    if item.status not in ACTIVE_ITEM_STATUSES:
        return item

    user_id = item.batch.user_id if item.batch else None
    item.status = ITEM_PARSING
    item.attempts = (item.attempts or 0) + 1
    item.started_at = datetime.now(UTC)
    item.error = None
    await db.commit()
    _broadcast_item(item)

    entry: Entry | None = None
    children: list[IngestBatchItem] = []
    try:
        if item.kind == KIND_URL:
            url = (item.source_url or "").strip()
            doc = await fetch_url_document(url)
            entry = await _create_from_document(
                db, item, doc, guid=url_guid(url), source=SOURCE_BY_KIND[KIND_URL], url=url, user_id=user_id
            )
        elif item.kind in (KIND_FILE, KIND_TEXT):
            if item.file is None:
                raise UnsupportedFormat("the original file was not stored")
            data = store.read_bytes(item.file.path)
            kind = detect_kind(item.filename, item.content_type, data[:4096])
            if kind is None:
                raise UnsupportedFormat(f"no parser for {item.filename!r} ({item.content_type})")
            if kind == KIND_ZIP:
                children = await _expand_zip(db, item, data)
            else:
                doc = parse_document(kind, data, item.filename)
                guid = bytes_guid(data, kind="pdf" if kind == KIND_PDF else "file")
                source = "pdf_upload" if kind == KIND_PDF else SOURCE_BY_KIND[item.kind]
                entry = await _create_from_document(
                    db, item, doc, guid=guid, source=source, url=item.source_url or None, user_id=user_id
                )
        elif item.kind == KIND_GITHUB_REPO:
            children = await _expand_github_repo(db, item)
        elif item.kind == KIND_GITHUB_FILE:
            entry = await _create_github_file_entry(db, item, user_id)
        else:
            raise UnsupportedFormat(f"unknown item kind {item.kind!r}")

        if entry is not None:
            item.entry_id = entry.id
            if item.file is not None:
                item.file.entry_id = entry.id
            item.status = ITEM_CREATED
        else:
            item.status = ITEM_EXPANDED
            item.extra = {**(item.extra or {}), "children": len(children)}
    except DuplicateEntry as dup:
        item.status = ITEM_DUPLICATE
        item.entry_id = dup.entry_id
        item.error = "Already ingested"
    except EmptyDocument as exc:
        item.status = ITEM_NO_TEXT
        item.error = str(exc) or "Nothing to read"
    except (UnsupportedFormat, ZipLimitExceeded) as exc:
        item.status = ITEM_UNSUPPORTED
        item.error = str(exc)
    except AppError as exc:
        item.status = {
            "duplicate": ITEM_DUPLICATE,
            "extraction_failed": ITEM_NO_TEXT,
            "file_too_large": ITEM_TOO_LARGE,
        }.get(exc.code, ITEM_FAILED)
        item.error = exc.message
    except Exception as exc:  # the item row is the error report; never crash the batch
        logger.exception("Ingest item %s failed", item.id)
        item.status = ITEM_FAILED
        item.error = f"{type(exc).__name__}: {exc}"[:1000]
    item.finished_at = datetime.now(UTC)
    await db.commit()

    if entry is not None:
        _after_entry_created(entry)
    for child in children:
        dispatch_item(child)
    _broadcast_item(item)
    return item


def _after_entry_created(entry: Entry) -> None:
    """Pipeline, search index and SSE — the same three things the one-item doors do."""
    from app.api.ingest import _index_entry
    from app.workers.feed_tasks import dispatch_entry_pipeline

    try:
        dispatch_entry_pipeline(str(entry.id), run_extraction=True)
    except Exception:
        logger.warning("Pipeline dispatch failed for manual entry %s", entry.id, exc_info=True)
    _index_entry(entry)
    try:
        from app.api.events import broadcast_event

        broadcast_event(
            "entry_ingested",
            {
                "entry_id": str(entry.id),
                "feed_id": str(entry.feed_id),
                "title": entry.title,
                "source": (entry.metadata_ or {}).get("source", "batch"),
            },
        )
    except Exception:
        logger.debug("Failed to broadcast ingest event", exc_info=True)


def _broadcast_item(item: IngestBatchItem) -> None:
    try:
        from app.api.events import broadcast_event

        broadcast_event(
            "ingest_item_updated",
            {
                "batch_id": str(item.batch_id),
                "item_id": str(item.id),
                "status": item.status,
                "entry_id": str(item.entry_id) if item.entry_id else None,
                "error": item.error,
            },
        )
    except Exception:
        logger.debug("Failed to broadcast ingest item event", exc_info=True)


# --- retry / cancel -------------------------------------------------------------


async def retry_item(db: AsyncSession, item: IngestBatchItem) -> IngestBatchItem:
    if item.status not in RETRYABLE_ITEM_STATUSES:
        raise AppError(
            code="not_retryable", message=f"An item in state '{item.status}' cannot be retried", status_code=409
        )
    if item.kind in (KIND_FILE, KIND_TEXT, KIND_GITHUB_FILE) and (
        item.file is None or item.file.evicted_at is not None
    ):
        raise AppError(code="original_not_kept", message="The original file is no longer stored", status_code=409)
    item.status = ITEM_QUEUED
    item.error = None
    item.finished_at = None
    await db.flush()
    return item


async def cancel_item(db: AsyncSession, item: IngestBatchItem) -> None:
    """Drop an item that has not produced an entry. The entry, if any, stays."""
    if item.status == ITEM_PARSING:
        raise AppError(
            code="in_progress", message="A worker is parsing this item; wait for it to finish", status_code=409
        )
    if item.file is not None:
        store.remove(item.file.path)
    if item.status == ITEM_QUEUED:
        item.status = ITEM_CANCELLED
    await db.delete(item)
    await db.flush()


# --- reading a batch back -------------------------------------------------------


async def mark_stale_parsing(db: AsyncSession, items: list[IngestBatchItem]) -> bool:
    """A worker that died leaves ``parsing`` behind. Flip it so retry lights up."""
    cutoff = datetime.now(UTC) - STALE_PARSING_AFTER
    changed = False
    for item in items:
        if item.status == ITEM_PARSING and item.started_at and item.started_at < cutoff:
            item.status = ITEM_FAILED
            item.error = "The worker stopped before this item finished"
            item.finished_at = datetime.now(UTC)
            changed = True
    if changed:
        await db.flush()
    return changed


async def analysis_done_entry_ids(db: AsyncSession, entry_ids: list[uuid.UUID]) -> set[uuid.UUID]:
    """Entries whose one-pass AI analysis has landed (a current entry_analysis result)."""
    if not entry_ids:
        return set()
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    rows = await db.execute(
        select(AIResult.entry_id)
        .join(AITask, AITask.id == AIResult.task_id)
        .where(
            AITask.name == "entry_analysis",
            AIResult.is_current.is_(True),
            AIResult.entry_id.in_(entry_ids),
        )
    )
    return {row[0] for row in rows.all()}


async def entry_titles(db: AsyncSession, entry_ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not entry_ids:
        return {}
    rows = await db.execute(select(Entry.id, Entry.title).where(Entry.id.in_(entry_ids)))
    return {row[0]: row[1] for row in rows.all()}


def summarize_items(items: list[IngestBatchItem]) -> dict:
    counts: dict[str, int] = {}
    for item in items:
        counts[item.status] = counts.get(item.status, 0) + 1
    active = sum(counts.get(s, 0) for s in ACTIVE_ITEM_STATUSES)
    return {
        "total": len(items),
        "active": active,
        "created": counts.get(ITEM_CREATED, 0),
        "duplicate": counts.get(ITEM_DUPLICATE, 0),
        "failed": sum(counts.get(s, 0) for s in (ITEM_FAILED, ITEM_NO_TEXT, ITEM_UNSUPPORTED, ITEM_TOO_LARGE)),
        "status": "processing" if active else "complete",
        "by_status": counts,
    }
