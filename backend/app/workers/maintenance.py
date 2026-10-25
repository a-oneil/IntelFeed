import logging
import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.metrics import (
    CELERY_TASK_DURATION_SECONDS,
    CELERY_TASKS_TOTAL,
    ENTRIES_CLEANED_TOTAL,
    IMAGES_EVICTED_TOTAL,
    TELEGRAM_MEDIA_EVICTED_TOTAL,
)
from app.models.entry import Entry
from app.models.feed import Feed
from app.services.system_settings import warm_settings_cache
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)


def _get_worker_session():
    return worker_session()


async def _setting(key: str, default: int) -> int:
    """Read one int knob with the settings cache freshly warmed.

    For sweeps that hold no DB session of their own (filesystem eviction).
    """
    async with _get_worker_session() as db:
        await warm_settings_cache(db)
    try:
        return int(settings.get(key) or default)
    except (TypeError, ValueError):
        return default


@celery_app.task(name="app.workers.maintenance.cleanup_expired_entries", soft_time_limit=300, time_limit=360)
def cleanup_expired_entries():
    """Delete entries older than their retention policy."""
    start = time.monotonic()
    try:
        run_async(_cleanup_expired_entries())
        CELERY_TASKS_TOTAL.labels(task_name="cleanup_expired_entries", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="cleanup_expired_entries", status="error").inc()
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="cleanup_expired_entries").observe(time.monotonic() - start)


async def _cleanup_expired_entries():
    async with _get_worker_session() as db:
        # Find feeds with retention policies
        result = await db.execute(select(Feed).where(Feed.retention_days.isnot(None)))
        feeds = result.scalars().all()

        total_deleted = 0
        all_entry_ids = []
        for feed in feeds:
            cutoff = datetime.now(UTC) - timedelta(days=feed.retention_days)
            # Collect entry IDs before deleting so we can remove from search index
            expired = await db.execute(
                select(Entry.id).where(
                    Entry.feed_id == feed.id,
                    Entry.published_at < cutoff,
                )
            )
            entry_ids = list(expired.scalars().all())
            if entry_ids:
                all_entry_ids.extend(entry_ids)
                deleted = await db.execute(delete(Entry).where(Entry.id.in_(entry_ids)))
                total_deleted += deleted.rowcount

        await db.commit()

        # Remove deleted entries from search index
        if all_entry_ids:
            from app.services.meilisearch_client import delete_entries_batch

            delete_entries_batch(all_entry_ids)

        if total_deleted:
            ENTRIES_CLEANED_TOTAL.inc(total_deleted)
            logger.info(f"Cleaned up {total_deleted} expired entries")


@celery_app.task(name="app.workers.maintenance.cleanup_telegram_media", soft_time_limit=600, time_limit=660)
def cleanup_telegram_media():
    """Delete telegram-downloaded media files whose parent entry is gone or aged out.

    Walks settings.telegram_media_dir which is laid out as
        <root>/<channel_id>/<message_id>.<ext>
        <root>/<channel_id>/<message_id>.thumb.jpg

    For each file, derives the (channel_id, message_id) pair, looks up whether an
    entry exists with metadata_["channel_id"] == channel_id and metadata_["message_id"] == msg_id,
    and deletes the file if no matching entry exists. Files for entries past their feed's
    retention_days are also pruned (the entry itself is deleted by cleanup_expired_entries).

    Soft-deleted entries (metadata_.telegram_deleted_at set) keep their media until the
    parent entry is hard-deleted, so analysts can still inspect the artefact.
    """
    start = time.monotonic()
    media_root = Path(settings.telegram_media_dir)
    if not media_root.is_dir():
        CELERY_TASKS_TOTAL.labels(task_name="cleanup_telegram_media", status="success").inc()
        return

    deleted = run_async(_cleanup_telegram_media(media_root))

    CELERY_TASKS_TOTAL.labels(task_name="cleanup_telegram_media", status="success").inc()
    CELERY_TASK_DURATION_SECONDS.labels(task_name="cleanup_telegram_media").observe(time.monotonic() - start)
    if deleted:
        logger.info("Pruned %d orphaned telegram media files", deleted)


async def _cleanup_telegram_media(media_root: Path) -> int:
    """Implementation: walk media root, prune files without a matching entry."""
    from sqlalchemy import text as _sql_text

    deleted = 0
    async with _get_worker_session() as db:
        for channel_dir in media_root.iterdir():
            if not channel_dir.is_dir():
                continue
            try:
                channel_id = int(channel_dir.name)
            except ValueError:
                continue

            # Build the set of (channel_id, message_id) pairs we know about for this channel
            result = await db.execute(
                _sql_text(
                    """
                    SELECT (metadata->>'message_id')::bigint AS msg_id
                    FROM entries
                    WHERE (metadata->>'channel_id')::bigint = :channel_id
                      AND metadata->>'message_id' IS NOT NULL
                    """
                ),
                {"channel_id": channel_id},
            )
            known_msg_ids: set[int] = {int(row.msg_id) for row in result if row.msg_id is not None}

            for media_file in channel_dir.iterdir():
                if not media_file.is_file():
                    continue
                stem = media_file.name.split(".", 1)[0]
                try:
                    msg_id = int(stem)
                except ValueError:
                    continue
                if msg_id in known_msg_ids:
                    continue
                try:
                    media_file.unlink()
                    deleted += 1
                except OSError:
                    pass

            # Remove the channel directory itself if it's now empty
            try:
                if not any(channel_dir.iterdir()):
                    channel_dir.rmdir()
            except OSError:
                pass

    return deleted


@celery_app.task(name="app.workers.maintenance.evict_old_telegram_media", soft_time_limit=600, time_limit=660)
def evict_old_telegram_media():
    """Delete downloaded Telegram media files older than telegram_media_ttl_days.

    Pure TTL-by-mtime sweep, independent of entry lifecycle — the entry and its
    extracted intel are kept forever, only the local video/image file is evicted.
    Complements cleanup_telegram_media (which prunes media for entries that no
    longer exist at all).
    """
    start = time.monotonic()
    media_root = Path(settings.telegram_media_dir)
    if not media_root.is_dir():
        CELERY_TASKS_TOTAL.labels(task_name="evict_old_telegram_media", status="success").inc()
        return

    ttl_days = run_async(_setting("telegram_media_ttl_days", 30))
    cutoff = time.time() - ttl_days * 86400
    evicted = 0
    for channel_dir in media_root.iterdir():
        if not channel_dir.is_dir():
            continue
        for media_file in channel_dir.iterdir():
            if not media_file.is_file():
                continue
            try:
                if media_file.stat().st_mtime < cutoff:
                    media_file.unlink()
                    evicted += 1
            except OSError:
                pass
        try:
            if not any(channel_dir.iterdir()):
                channel_dir.rmdir()
        except OSError:
            pass

    CELERY_TASKS_TOTAL.labels(task_name="evict_old_telegram_media", status="success").inc()
    CELERY_TASK_DURATION_SECONDS.labels(task_name="evict_old_telegram_media").observe(time.monotonic() - start)
    if evicted:
        TELEGRAM_MEDIA_EVICTED_TOTAL.inc(evicted)
        logger.info("Evicted %d Telegram media files past %dd TTL", evicted, ttl_days)


@celery_app.task(name="app.workers.maintenance.evict_image_cache", soft_time_limit=300, time_limit=360)
def evict_image_cache():
    """Delete cached images older than the configured TTL."""
    start = time.monotonic()
    cache_dir = Path(settings.image_proxy_cache_dir)
    if not cache_dir.exists():
        CELERY_TASKS_TOTAL.labels(task_name="evict_image_cache", status="success").inc()
        return

    ttl_seconds = run_async(_setting("image_proxy_cache_ttl_days", settings.image_proxy_cache_ttl_days)) * 86400
    cutoff = time.time() - ttl_seconds
    evicted = 0

    for file_path in cache_dir.rglob("*"):
        if file_path.is_file():
            try:
                if file_path.stat().st_mtime < cutoff:
                    file_path.unlink()
                    evicted += 1
            except OSError:
                pass

    CELERY_TASKS_TOTAL.labels(task_name="evict_image_cache", status="success").inc()
    CELERY_TASK_DURATION_SECONDS.labels(task_name="evict_image_cache").observe(time.monotonic() - start)
    if evicted:
        IMAGES_EVICTED_TOTAL.inc(evicted)
        logger.info(f"Evicted {evicted} expired images from cache")


@celery_app.task(name="app.workers.maintenance.evict_tts_cache", soft_time_limit=300, time_limit=360)
def evict_tts_cache():
    """Bound the server-side read-aloud (Piper) audio cache.

    TTL first (drop audio not accessed within tts_cache_ttl_days), then an LRU
    size cap (delete oldest-accessed until under tts_cache_max_bytes). Disk is the
    binding constraint on the prod host, so unlike telegram_media this is bounded.
    """
    start = time.monotonic()
    cache_dir = Path(settings.tts_media_dir)
    if not cache_dir.exists():
        CELERY_TASKS_TOTAL.labels(task_name="evict_tts_cache", status="success").inc()
        return

    evicted = run_async(_evict_tts_cache())

    # Sweep abandoned temp files from interrupted writes.
    for tmp in cache_dir.rglob("*.tmp"):
        try:
            if tmp.is_file() and tmp.stat().st_mtime < time.time() - 3600:
                tmp.unlink()
        except OSError:
            pass

    CELERY_TASKS_TOTAL.labels(task_name="evict_tts_cache", status="success").inc()
    CELERY_TASK_DURATION_SECONDS.labels(task_name="evict_tts_cache").observe(time.monotonic() - start)
    if evicted:
        logger.info("Evicted %d cached TTS audio files", evicted)


async def _evict_tts_cache() -> int:
    from app.models.tts_audio import TTSAudio
    from app.services.tts import audio_path

    def _unlink(path: Path) -> None:
        try:
            path.unlink()
        except OSError:
            pass

    now = datetime.now(UTC)
    evicted = 0

    async with _get_worker_session() as db:
        await warm_settings_cache(db)
        default_ttl_days = int(settings.get("tts_cache_ttl_days") or 30)
        cap = int(settings.get("tts_cache_max_bytes") or 2 * 1024 * 1024 * 1024)
        rows = (await db.execute(select(TTSAudio).order_by(TTSAudio.last_accessed_at.asc()))).scalars().all()

        survivors: list[tuple[TTSAudio, int]] = []
        total_size = 0
        for row in rows:
            path = audio_path(row.cache_key)
            size = path.stat().st_size if path.is_file() else 0
            # Per-row TTL override (share pre-gen sets ttl_days=1) falls back to the global default.
            ttl_days = row.ttl_days if row.ttl_days is not None else default_ttl_days
            ttl_cutoff = now - timedelta(days=ttl_days)
            if row.last_accessed_at and row.last_accessed_at < ttl_cutoff:
                _unlink(path)
                await db.delete(row)
                evicted += 1
                continue
            survivors.append((row, size))
            total_size += size

        # LRU size cap — survivors are ordered oldest-accessed first.
        idx = 0
        while total_size > cap and idx < len(survivors):
            row, size = survivors[idx]
            _unlink(audio_path(row.cache_key))
            await db.delete(row)
            total_size -= size
            evicted += 1
            idx += 1

        await db.commit()

    return evicted


@celery_app.task(name="app.workers.maintenance.refresh_correlation_cache", soft_time_limit=300, time_limit=360)
def refresh_correlation_cache():
    """Pre-warm correlation cache for high-activity entities."""
    start = time.monotonic()
    try:
        run_async(_refresh_correlation_cache())
        CELERY_TASKS_TOTAL.labels(task_name="refresh_correlation_cache", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="refresh_correlation_cache", status="error").inc()
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="refresh_correlation_cache").observe(time.monotonic() - start)


@celery_app.task(name="app.workers.maintenance.sync_entity_search_indexes", soft_time_limit=300, time_limit=360)
def sync_entity_search_indexes():
    """Sync all intelligence entities to Meilisearch indexes.

    Uses a Redis lock to prevent concurrent/queued duplicates from saturating
    the worker pool.  If another instance is already running or queued, this
    invocation exits early.
    """
    import redis as _redis

    from app.config import settings

    r = _redis.from_url(settings.redis_url)
    lock_key = "sync_entity_search_indexes:lock"
    try:
        # Only one sync at a time; TTL = soft_time_limit as a safety net
        if not r.set(lock_key, "1", nx=True, ex=300):
            logger.info("sync_entity_search_indexes already running/queued — skipping")
            return
    finally:
        r.close()

    start = time.monotonic()
    try:
        counts = run_async(_sync_entity_indexes())
        CELERY_TASKS_TOTAL.labels(task_name="sync_entity_search_indexes", status="success").inc()
        return counts
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="sync_entity_search_indexes", status="error").inc()
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="sync_entity_search_indexes").observe(time.monotonic() - start)
        # Release lock so the next scheduled/triggered run can proceed
        r2 = _redis.from_url(settings.redis_url)
        try:
            r2.delete(lock_key)
        finally:
            r2.close()


async def _sync_entity_indexes():
    from app.services.entity_indexer import sync_all_entities

    async with _get_worker_session() as session:
        return await sync_all_entities(session)


@celery_app.task(name="app.workers.maintenance.backup_database", soft_time_limit=600, time_limit=660)
def backup_database():
    """Run pg_dump and retain the last N backups."""
    import subprocess

    start = time.monotonic()
    backup_dir = Path("backups")
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"intelfeed_{timestamp}.sql.gz"

    try:
        env = {
            "PGPASSWORD": settings.postgres_password,
            "PATH": "/usr/bin:/usr/local/bin",
        }
        cmd = [
            "pg_dump",
            "-h",
            settings.postgres_host,
            "-p",
            str(settings.postgres_port),
            "-U",
            settings.postgres_user,
            "-d",
            settings.postgres_db,
            "--no-owner",
            "--no-privileges",
        ]
        # Stream pg_dump straight through gzip to disk rather than buffering the
        # whole (multi-GB) dump in memory. Write to a temp file and only promote
        # it to the final name once the dump exits cleanly, so a failure never
        # leaves a 0-byte or truncated backup behind.
        import gzip

        tmp_file = backup_file.with_name(backup_file.name + ".partial")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            assert proc.stdout is not None
            with open(tmp_file, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb") as gz:
                for chunk in iter(lambda: proc.stdout.read(1024 * 1024), b""):
                    gz.write(chunk)
            _, stderr = proc.communicate(timeout=600)
            if proc.returncode != 0:
                raise RuntimeError(f"pg_dump failed: {stderr.decode(errors='replace')}")
            tmp_file.replace(backup_file)
        except BaseException:
            proc.kill()
            proc.wait()
            tmp_file.unlink(missing_ok=True)
            raise

        logger.info(f"Database backup created: {backup_file}")

        # Enforce retention policy
        retention_days = run_async(_setting("backup_retention_days", settings.backup_retention_days))
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        for old_backup in sorted(backup_dir.glob("intelfeed_*.sql.gz")):
            try:
                file_time = datetime.fromtimestamp(old_backup.stat().st_mtime, tz=UTC)
                if file_time < cutoff:
                    old_backup.unlink()
                    logger.info(f"Deleted old backup: {old_backup.name}")
            except OSError:
                pass

        CELERY_TASKS_TOTAL.labels(task_name="backup_database", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="backup_database", status="error").inc()
        logger.exception("Database backup failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="backup_database").observe(time.monotonic() - start)


@celery_app.task(name="app.workers.maintenance.reconcile_meilisearch", soft_time_limit=300, time_limit=360)
def reconcile_meilisearch():
    """Detect and repair Meilisearch/PostgreSQL sync drift.

    Compares document counts and samples entries to find missing or stale documents.
    Queues missing entries for re-indexing.
    """
    start = time.monotonic()
    try:
        stats = run_async(_reconcile_meilisearch())
        logger.info("Meilisearch reconciliation: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="reconcile_meilisearch", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="reconcile_meilisearch", status="error").inc()
        logger.exception("Meilisearch reconciliation failed")
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="reconcile_meilisearch").observe(time.monotonic() - start)


async def _reconcile_meilisearch():
    from sqlalchemy import func

    from app.services import meilisearch_client

    stats = {"pg_count": 0, "meili_count": 0, "missing": 0, "reindexed": 0}

    async with _get_worker_session() as db:
        # Count entries in PostgreSQL
        result = await db.execute(select(func.count(Entry.id)))
        stats["pg_count"] = result.scalar() or 0

        # Count documents in Meilisearch
        try:
            client = meilisearch_client._get_client()
            index = client.index(meilisearch_client.INDEX_NAME)
            meili_stats = index.get_stats()
            stats["meili_count"] = meili_stats.number_of_documents
        except Exception:
            logger.warning("Cannot reach Meilisearch for reconciliation")
            return {**stats, "error": "meilisearch_unavailable"}

        drift = abs(stats["pg_count"] - stats["meili_count"])
        if drift < 10:
            return stats

        # Sample recent entries and check if they're in Meilisearch
        result = await db.execute(
            select(Entry.id, Entry.title, Entry.feed_id).order_by(Entry.created_at.desc()).limit(500)
        )
        sample_entries = result.all()

        missing_ids = []
        for entry_row in sample_entries:
            try:
                index.get_document(str(entry_row.id))
            except Exception:
                missing_ids.append(entry_row)

        stats["missing"] = len(missing_ids)

        # Re-index missing entries directly
        if missing_ids:
            from app.services.meilisearch_client import index_entry

            entry_uuids = [row.id for row in missing_ids]
            result = await db.execute(select(Entry).where(Entry.id.in_(entry_uuids)))
            entries = result.scalars().all()

            feed_ids = {e.feed_id for e in entries}
            feed_result = await db.execute(select(Feed).where(Feed.id.in_(feed_ids)))
            feeds = {f.id: f for f in feed_result.scalars().all()}

            for entry in entries:
                feed = feeds.get(entry.feed_id)
                try:
                    index_entry(
                        entry_id=entry.id,
                        feed_id=entry.feed_id,
                        title=entry.title or "",
                        content_text=entry.content_text,
                        summary=entry.summary,
                        author=entry.author,
                        published_at=entry.published_at.isoformat() if entry.published_at else None,
                        feed_type=feed.feed_type if feed else "rss",
                        feed_title=feed.title if feed else None,
                        language=entry.language,
                        word_count=entry.word_count,
                    )
                    stats["reindexed"] += 1
                except Exception:
                    logger.warning("Reconciliation: failed to re-index entry %s", entry.id)

    return stats


@celery_app.task(name="app.workers.maintenance.retry_failed_indexing", soft_time_limit=120, time_limit=180)
def retry_failed_indexing():
    """Re-index entries that failed Meilisearch indexing.

    Consumes the meili:failed_entry_ids Redis set and re-indexes from PostgreSQL.
    """
    start = time.monotonic()
    try:
        stats = run_async(_retry_failed_indexing())
        if stats.get("retried"):
            logger.info("Retried failed Meilisearch indexing: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="retry_failed_indexing", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="retry_failed_indexing", status="error").inc()
        logger.exception("Failed indexing retry task failed")
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="retry_failed_indexing").observe(time.monotonic() - start)


async def _retry_failed_indexing():
    import uuid

    import redis as _redis

    from app.services.meilisearch_client import index_entry

    stats = {"pending": 0, "retried": 0, "failed": 0}

    r = _redis.from_url(settings.redis_url)
    try:
        entry_ids = []
        for _ in range(200):
            eid = r.spop("meili:failed_entry_ids")
            if eid is None:
                break
            entry_ids.append(eid.decode() if isinstance(eid, bytes) else eid)

        stats["pending"] = len(entry_ids)
        if not entry_ids:
            return stats

        uuids = [uuid.UUID(eid) for eid in entry_ids]

        async with _get_worker_session() as db:
            result = await db.execute(select(Entry).where(Entry.id.in_(uuids)))
            entries = result.scalars().all()

            feed_ids = {e.feed_id for e in entries}
            feed_result = await db.execute(select(Feed).where(Feed.id.in_(feed_ids)))
            feeds = {f.id: f for f in feed_result.scalars().all()}

            re_failed = []
            for entry in entries:
                feed = feeds.get(entry.feed_id)
                try:
                    index_entry(
                        entry_id=entry.id,
                        feed_id=entry.feed_id,
                        title=entry.title or "",
                        content_text=entry.content_text,
                        summary=entry.summary,
                        author=entry.author,
                        published_at=entry.published_at.isoformat() if entry.published_at else None,
                        feed_type=feed.feed_type if feed else "rss",
                        feed_title=feed.title if feed else None,
                        language=entry.language,
                        word_count=entry.word_count,
                    )
                    stats["retried"] += 1
                except Exception:
                    re_failed.append(str(entry.id))
                    stats["failed"] += 1

            if re_failed:
                for eid in re_failed:
                    r.sadd("meili:failed_entry_ids", eid)
    finally:
        r.close()

    return stats


async def _refresh_correlation_cache():
    from app.intelligence.correlation_cache import refresh_top_entities_cache

    async with _get_worker_session() as db:
        await warm_settings_cache(db)
        refreshed = await refresh_top_entities_cache(db, limit=100)
        if refreshed:
            logger.info(f"Refreshed correlation cache for {refreshed} entities")


@celery_app.task(name="app.workers.maintenance.cleanup_orphaned_references", soft_time_limit=120, time_limit=180)
def cleanup_orphaned_references():
    """Remove polymorphic references (CampaignEntity, Comment) pointing to deleted entities."""
    start = time.monotonic()
    try:
        count = run_async(_cleanup_orphaned_references())
        if count:
            logger.info(f"Cleaned up {count} orphaned polymorphic references")
        CELERY_TASKS_TOTAL.labels(task_name="cleanup_orphaned_references", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="cleanup_orphaned_references", status="error").inc()
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="cleanup_orphaned_references").observe(time.monotonic() - start)


async def _cleanup_orphaned_references():
    from app.models.campaign import CampaignEntity
    from app.models.comment import Comment
    from app.models.cve import CVE
    from app.models.malware_family import MalwareFamily
    from app.models.threat_actor import ThreatActor
    from app.models.ttp import TTP

    entity_model_map = {
        "ttp": TTP,
        "cve": CVE,
        "threat_actor": ThreatActor,
        "malware": MalwareFamily,
    }

    total_deleted = 0
    async with _get_worker_session() as db:
        # Clean orphaned CampaignEntity rows
        for entity_type, model_cls in entity_model_map.items():
            orphans = await db.execute(
                select(CampaignEntity.id).where(
                    CampaignEntity.entity_type == entity_type,
                    ~CampaignEntity.entity_id.in_(select(model_cls.id)),
                )
            )
            orphan_ids = [row[0] for row in orphans.all()]
            if orphan_ids:
                await db.execute(delete(CampaignEntity).where(CampaignEntity.id.in_(orphan_ids)))
                total_deleted += len(orphan_ids)

        # Clean orphaned Comment rows for entity types
        commentable_model_map = {
            "ttp": TTP,
            "cve": CVE,
            "threat_actor": ThreatActor,
            "malware": MalwareFamily,
        }
        for commentable_type, model_cls in commentable_model_map.items():
            orphans = await db.execute(
                select(Comment.id).where(
                    Comment.commentable_type == commentable_type,
                    ~Comment.commentable_id.in_(select(model_cls.id)),
                )
            )
            orphan_ids = [row[0] for row in orphans.all()]
            if orphan_ids:
                await db.execute(delete(Comment).where(Comment.id.in_(orphan_ids)))
                total_deleted += len(orphan_ids)

        await db.commit()
    return total_deleted


@celery_app.task(name="app.workers.maintenance.decay_relationship_confidence", soft_time_limit=300, time_limit=360)
def decay_relationship_confidence():
    """Demote stale co-occurrence relationships from probable back to possible.

    Strength/recency already decay live in the pivot payload; this keeps the
    stored typed-confidence ladder honest for relationships whose newest
    evidence is older than twice the recency half-life. Analyst-touched rows
    (confirmed / created / rejected) are never demoted.
    """
    start = time.monotonic()
    try:
        count = run_async(_decay_relationship_confidence())
        if count:
            logger.info(f"Demoted {count} stale relationships from probable to possible")
        CELERY_TASKS_TOTAL.labels(task_name="decay_relationship_confidence", status="success").inc()
        return {"demoted": count}
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="decay_relationship_confidence", status="error").inc()
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="decay_relationship_confidence").observe(time.monotonic() - start)


async def decay_stale_relationships(db: AsyncSession, cutoff: datetime) -> int:
    """Demote co_occurrence-sourced 'probable' rows with no evidence newer than cutoff."""
    from sqlalchemy import text

    result = await db.execute(
        text(
            """
            UPDATE entity_relationships rel
            SET confidence = 'possible'
            WHERE rel.source = 'co_occurrence'
              AND rel.confidence = 'probable'
              AND NOT EXISTS (
                  SELECT 1 FROM entries e
                  WHERE e.id = ANY(rel.evidence_entry_ids)
                    AND e.published_at >= :cutoff
              )
            """
        ),
        {"cutoff": cutoff},
    )
    return result.rowcount or 0


async def _decay_relationship_confidence() -> int:
    async with _get_worker_session() as db:
        await warm_settings_cache(db)
        half_life = int(settings.get("relationship_recency_half_life_days") or 90)
        cutoff = datetime.now(UTC) - timedelta(days=half_life * 2)
        count = await decay_stale_relationships(db, cutoff)
        await db.commit()
        return count


# ---------------------------------------------------------------------------
# Stale entity review flagging
# ---------------------------------------------------------------------------

# (entity_type, model class name). One slug now covers the maintenance log and
# EntityRelationship rows alike — see app/entity_types.py.
STALE_ENTITY_TYPES: list[tuple[str, str]] = [
    ("threat_actor", "ThreatActor"),
    ("malware", "MalwareFamily"),
    ("tool", "Tool"),
    ("vendor", "Vendor"),
    ("product", "Product"),
]

_STALE_FLAGS_PER_TYPE_CAP = 500  # bound one run's log growth


@celery_app.task(name="app.workers.maintenance.prune_engine_tables", soft_time_limit=300, time_limit=360)
def prune_engine_tables():
    """Daily: delete engine bookkeeping rows older than 30 days.

    Covers job_runs now; entry_pipeline_runs / ai_analysis_requests /
    ai_batch_jobs join this list in later engine phases.
    """
    start = time.monotonic()
    try:
        deleted = run_async(_prune_engine_tables())
        logger.info("Pruned %d engine bookkeeping rows", deleted)
        CELERY_TASKS_TOTAL.labels(task_name="prune_engine_tables", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="prune_engine_tables", status="error").inc()
        logger.exception("Engine table pruning failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="prune_engine_tables").observe(time.monotonic() - start)


async def _prune_engine_tables() -> int:
    from app.models.ai_analysis import AIAnalysisRequest, AIBatchJob
    from app.models.entry_pipeline_run import EntryPipelineRun
    from app.models.job_run import JobRun

    total = 0
    async with _get_worker_session() as db:
        await warm_settings_cache(db)
        cutoff = datetime.now(UTC) - timedelta(days=int(settings.get("engine_run_retention_days") or 30))
        result = await db.execute(delete(EntryPipelineRun).where(EntryPipelineRun.created_at < cutoff))
        total += result.rowcount or 0
        result = await db.execute(delete(JobRun).where(JobRun.finished_at < cutoff))
        total += result.rowcount or 0
        result = await db.execute(
            delete(AIAnalysisRequest).where(
                AIAnalysisRequest.created_at < cutoff,
                AIAnalysisRequest.status != "pending",
            )
        )
        total += result.rowcount or 0
        result = await db.execute(delete(AIBatchJob).where(AIBatchJob.created_at < cutoff))
        total += result.rowcount or 0
        # Pending autolink matches: resolved rows age out at 30d; unresolved rows
        # expire at 14d (their entry never got an AI pass — junk-gated, budget, or
        # feed policy — so there is no promotion path and the hold just lapses).
        from app.models.pending_autolink import PendingAutolinkMatch

        unresolved_cutoff = datetime.now(UTC) - timedelta(days=14)
        result = await db.execute(
            delete(PendingAutolinkMatch).where(
                PendingAutolinkMatch.resolved_at.isnot(None),
                PendingAutolinkMatch.created_at < cutoff,
            )
        )
        total += result.rowcount or 0
        result = await db.execute(
            delete(PendingAutolinkMatch).where(
                PendingAutolinkMatch.resolved_at.is_(None),
                PendingAutolinkMatch.created_at < unresolved_cutoff,
            )
        )
        total += result.rowcount or 0
        await db.commit()
    return total


@celery_app.task(name="app.workers.maintenance.backfill_cve_affected", soft_time_limit=3600, time_limit=3660)
def backfill_cve_affected():
    """One-shot/backfill sweep: derive cve_affected rows from stored nvd_data blobs.

    Idempotent (upsert on the pair unique key) and NVD-free — it re-parses the
    raw configurations already stored on each CVE. Also repairs empty
    affected_products JSONB when the blob parses to something.
    """
    start = time.monotonic()
    try:
        stats = run_async(_backfill_cve_affected())
        CELERY_TASKS_TOTAL.labels(task_name="backfill_cve_affected", status="success").inc()
        logger.info(
            "cve_affected backfill: %s CVEs scanned, %s pairs upserted, %s affected_products repaired",
            stats["cves"],
            stats["pairs"],
            stats["repaired"],
        )
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="backfill_cve_affected", status="error").inc()
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="backfill_cve_affected").observe(time.monotonic() - start)


async def _backfill_cve_affected() -> dict:
    from app.intelligence.cpe_resolver import build_cpe_index
    from app.intelligence.cve import parse_cpe_affected, sync_cve_affected
    from app.models.cve import CVE

    stats = {"cves": 0, "pairs": 0, "repaired": 0}
    batch_size = 500
    async with _get_worker_session() as db:
        index = await build_cpe_index(db)
        last_id = None
        while True:
            query = (
                select(CVE.id, CVE.nvd_data, CVE.affected_products)
                .where(CVE.nvd_data.isnot(None))
                .order_by(CVE.id)
                .limit(batch_size)
            )
            if last_id is not None:
                query = query.where(CVE.id > last_id)
            rows = (await db.execute(query)).all()
            if not rows:
                break
            for cve_pk, nvd_data, affected_products in rows:
                last_id = cve_pk
                parsed = parse_cpe_affected(nvd_data or {})
                if not parsed:
                    continue
                stats["cves"] += 1
                stats["pairs"] += await sync_cve_affected(db, cve_pk, parsed, index)
                if not affected_products:
                    from sqlalchemy import update

                    await db.execute(update(CVE).where(CVE.id == cve_pk).values(affected_products=parsed))
                    stats["repaired"] += 1
            await db.commit()
    return stats


@celery_app.task(name="app.workers.maintenance.resolve_cve_affected", soft_time_limit=600, time_limit=660)
def resolve_cve_affected():
    """Re-resolve unmatched cve_affected rows against current entities.

    Runs after entity/alias/cpe_names changes so CVE history attaches
    retroactively — e.g. creating a vCenter product picks up all its stored
    CPE pairs on the next sweep.
    """
    start = time.monotonic()
    try:
        stats = run_async(_resolve_cve_affected())
        CELERY_TASKS_TOTAL.labels(task_name="resolve_cve_affected", status="success").inc()
        if stats["vendor_rows"] or stats["product_rows"]:
            logger.info(
                "cve_affected re-resolution: %s pairs checked, %s vendor rows + %s product rows resolved",
                stats["pairs"],
                stats["vendor_rows"],
                stats["product_rows"],
            )
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="resolve_cve_affected", status="error").inc()
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="resolve_cve_affected").observe(time.monotonic() - start)


async def _resolve_cve_affected() -> dict:
    from sqlalchemy import func as sa_func
    from sqlalchemy import or_, update

    from app.intelligence.cpe_resolver import build_cpe_index
    from app.models.cve_affected import CVEAffected

    stats = {"pairs": 0, "vendor_rows": 0, "product_rows": 0}
    async with _get_worker_session() as db:
        index = await build_cpe_index(db)
        pairs = (
            await db.execute(
                select(CVEAffected.cpe_vendor, CVEAffected.cpe_product)
                .where(or_(CVEAffected.vendor_id.is_(None), CVEAffected.product_id.is_(None)))
                .distinct()
            )
        ).all()
        stats["pairs"] = len(pairs)
        now = datetime.now(UTC)
        for cpe_vendor, cpe_product in pairs:
            vendor_id, product_id = index.resolve_pair(cpe_vendor, cpe_product)
            if vendor_id:
                result = await db.execute(
                    update(CVEAffected)
                    .where(
                        CVEAffected.cpe_vendor == cpe_vendor,
                        CVEAffected.cpe_product == cpe_product,
                        CVEAffected.vendor_id.is_(None),
                    )
                    .values(vendor_id=vendor_id, resolved_at=sa_func.coalesce(CVEAffected.resolved_at, now))
                )
                stats["vendor_rows"] += result.rowcount or 0
            if product_id:
                result = await db.execute(
                    update(CVEAffected)
                    .where(
                        CVEAffected.cpe_vendor == cpe_vendor,
                        CVEAffected.cpe_product == cpe_product,
                        CVEAffected.product_id.is_(None),
                    )
                    .values(product_id=product_id, resolved_at=sa_func.coalesce(CVEAffected.resolved_at, now))
                )
                stats["product_rows"] += result.rowcount or 0
        await db.commit()
    return stats


@celery_app.task(name="app.workers.maintenance.reenrich_cve_nvd", soft_time_limit=3300, time_limit=3360)
def reenrich_cve_nvd():
    """Nightly sweep re-fetching NVD data for CVEs stuck without it.

    Targets two groups, KEV/EPSS-priority first, bounded per run:
      1. Never-enriched CVEs (empty nvd_data — e.g. the 2026-03 bulk import,
         which set descriptions and so never trips the ingest re-enrich guard).
      2. Previously-fetched CVEs NVD hadn't analyzed yet (blob without
         configurations, vulnStatus awaiting/undergoing) untouched for 14+ days.

    Failed fetches get an attempt stamp in nvd_data (max 3 tries, 7-day gaps)
    so junk CVE ids extracted by regex can't burn quota forever.
    """
    start = time.monotonic()
    try:
        stats = run_async(_reenrich_cve_nvd())
        CELERY_TASKS_TOTAL.labels(task_name="reenrich_cve_nvd", status="success").inc()
        logger.info(
            "cve nvd re-enrichment: %s attempted, %s enriched, %s got configurations, %s affected pairs",
            stats["attempted"],
            stats["enriched"],
            stats["with_config"],
            stats["pairs"],
        )
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="reenrich_cve_nvd", status="error").inc()
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="reenrich_cve_nvd").observe(time.monotonic() - start)


_REENRICH_PENDING_STATUSES = ("Awaiting Analysis", "Undergoing Analysis", "Received")


async def _reenrich_cve_nvd(batch_size: int | None = None) -> dict:
    import asyncio

    from sqlalchemy import and_, or_

    from app.intelligence.cpe_resolver import build_cpe_index
    from app.intelligence.cve import (
        NVDRateLimited,
        enrich_from_nvd,
        nvd_request_pace,
        nvd_retry_allowed,
        stamp_nvd_miss,
        sync_cve_affected,
    )
    from app.models.cve import CVE

    if batch_size is None:
        async with _get_worker_session() as db:
            await warm_settings_cache(db)
        try:
            batch_size = int(settings.get("cve_reenrich_batch_size") or 150)
        except (TypeError, ValueError):
            batch_size = 150

    now = datetime.now(UTC)
    stale_cutoff = (now - timedelta(days=14)).isoformat()
    last_attempt = CVE.nvd_data["_enrich_last_attempt"].astext
    vuln_status = CVE.nvd_data["vulnStatus"].astext

    empty_blob = or_(CVE.nvd_data.is_(None), ~CVE.nvd_data.has_key("id"))
    never_or_retryable = and_(empty_blob, nvd_retry_allowed(now))
    # Fetched before, but NVD hadn't analyzed it yet — recheck every 14 days.
    # Staleness uses the blob-internal stamp, NOT CVE.updated_at: article
    # mentions touch updated_at constantly, which would starve hot CVEs.
    pending_analysis = and_(
        CVE.nvd_data.has_key("id"),
        ~CVE.nvd_data.has_key("configurations"),
        vuln_status.in_(_REENRICH_PENDING_STATUSES),
        or_(~CVE.nvd_data.has_key("_enrich_last_attempt"), last_attempt < stale_cutoff),
    )

    stats = {"attempted": 0, "enriched": 0, "with_config": 0, "pairs": 0}
    async with _get_worker_session() as db:
        index = await build_cpe_index(db)
        rows = (
            (
                await db.execute(
                    select(CVE)
                    .where(or_(never_or_retryable, pending_analysis))
                    .order_by(CVE.is_kev.desc(), CVE.epss_score.desc().nulls_last())
                    .limit(batch_size)
                )
            )
            .scalars()
            .all()
        )
        pace = nvd_request_pace()
        for i, cve in enumerate(rows):
            if i:
                await asyncio.sleep(pace)  # stay under NVD's rolling window
            stats["attempted"] += 1
            try:
                nvd = await enrich_from_nvd(cve.cve_id, raise_on_rate_limit=True)
            except NVDRateLimited:
                # Throttled even after backoff — abort the batch WITHOUT
                # stamping this CVE; the nightly rerun picks it back up.
                logger.warning("reenrich_cve_nvd aborting batch at %s/%s: NVD rate limit", i, len(rows))
                break
            if not nvd:
                stamp_nvd_miss(cve, now)
                continue
            stats["enriched"] += 1
            if nvd.get("cvss_score") is not None:
                cve.cvss_score = nvd["cvss_score"]
            if nvd.get("severity"):
                cve.severity = nvd["severity"]
            if nvd.get("description") and not cve.description:
                cve.description = nvd["description"]
            if nvd.get("references"):
                cve.references_ = nvd["references"]
            blob = dict(nvd.get("nvd_data") or {})
            if not blob.get("configurations"):
                # Still unanalyzed at NVD — stamp so the pending arm waits 14d
                blob["_enrich_last_attempt"] = now.isoformat()
            cve.nvd_data = blob
            products = nvd.get("affected_products") or []
            if products:
                stats["with_config"] += 1
                cve.affected_products = products
                stats["pairs"] += await sync_cve_affected(db, cve.id, products, index)
        await db.commit()
    return stats


@celery_app.task(name="app.workers.maintenance.rollup_targeted_sectors", soft_time_limit=900, time_limit=960)
def rollup_targeted_sectors():
    """Derive actor/malware targeted_sectors from the victim sectors on their articles."""
    start = time.monotonic()
    try:
        stats = run_async(_rollup_targeted_sectors())
        logger.info("Targeted-sector rollup stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="rollup_targeted_sectors", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="rollup_targeted_sectors", status="error").inc()
        logger.exception("Targeted-sector rollup failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="rollup_targeted_sectors").observe(time.monotonic() - start)


# How many sectors the rollup may assert per entity, and how many distinct
# articles must describe a sector as hit before it counts. min_articles=1 would
# let a single mis-tagged article put a sector chip on a major actor's profile.
_SECTOR_ROLLUP_LIMIT = 8
_SECTOR_ROLLUP_MIN_ARTICLES = 2


async def _rollup_targeted_sectors() -> dict:
    async with worker_session() as db:
        stats = await rollup_targeted_sectors_for_session(db)
        await db.commit()
    return stats


async def rollup_targeted_sectors_for_session(db) -> dict:
    """Aggregate entry_sectors through the entry junctions onto the target-sector junctions.

    The one-pass entry analysis writes victim sectors to `entry_sectors`; this
    turns "N of this actor's articles describe sector S as hit" into a
    ``source="rollup"`` row on ``threat_actor_target_sectors`` /
    ``malware_target_sectors`` carrying N as its evidence. The rollup owns only
    its own rows: sectors asserted by enrichment, the seed backfill or an
    analyst are kept (their evidence count is refreshed), and a rollup row whose
    evidence dropped below the floor is removed again.

    The legacy ``targeted_sectors`` label array is then rebuilt from the
    junction (``refresh_targeted_sectors_cache`` is its only writer) and a
    provenance claim records the resulting list, so the profile labels these
    chips as derived from the entity's own articles rather than as a citation.
    """
    from app.models.entry_sector import EntrySector
    from app.models.malware_family import EntryMalware, MalwareFamily
    from app.models.threat_actor import EntryThreatActor, ThreatActor
    from app.services.claim_provenance import record_claim
    from app.services.sector_links import junction_for, refresh_targeted_sectors_cache, set_rollup_sectors

    stats: dict = {}

    for label, model, junction, fk in (
        ("threat_actor", ThreatActor, EntryThreatActor, EntryThreatActor.threat_actor_id),
        ("malware", MalwareFamily, EntryMalware, EntryMalware.malware_family_id),
    ):
        article_count = func.count(func.distinct(EntrySector.entry_id)).label("c")
        rows = (
            await db.execute(
                select(fk, EntrySector.sector_id, article_count)
                .join(EntrySector, EntrySector.entry_id == junction.entry_id)
                .group_by(fk, EntrySector.sector_id)
                .having(article_count >= _SECTOR_ROLLUP_MIN_ARTICLES)
                .order_by(fk, article_count.desc())
            )
        ).all()

        observed: dict = {}
        for entity_id, sector_id, count in rows:
            per_entity = observed.setdefault(entity_id, {})
            if len(per_entity) < _SECTOR_ROLLUP_LIMIT:
                per_entity[sector_id] = count

        # Entities that only carry stale rollup rows still need a pass so those
        # rows are pruned once the evidence behind them is gone.
        _, target_junction, fk_attr = junction_for(label)
        stale_q = await db.execute(
            select(getattr(target_junction, fk_attr)).where(target_junction.source == "rollup").distinct()
        )
        touched = set(observed) | {row for row in stale_q.scalars().all()}

        updated = 0
        if touched:
            entities = (await db.execute(select(model).where(model.id.in_(list(touched))))).scalars().all()
            for entity in entities:
                changed = await set_rollup_sectors(db, label, entity.id, observed.get(entity.id, {}))
                labels = await refresh_targeted_sectors_cache(db, label, entity)
                if changed:
                    await record_claim(
                        db,
                        entity_type=label,
                        entity_id=entity.id,
                        field="targeted_sectors",
                        value=labels,
                        source_kind="enrichment",
                        source_ref="sector_rollup",
                    )
                    updated += 1

        stats[label] = {"with_observed_sectors": len(observed), "updated": updated}

    return stats


@celery_app.task(name="app.workers.maintenance.backfill_rule_data_sources", soft_time_limit=1800, time_limit=1860)
def backfill_rule_data_sources():
    """Derive data_sources for rules that have a log source but no telemetry names."""
    start = time.monotonic()
    try:
        stats = run_async(_backfill_rule_data_sources())
        logger.info("Rule data_sources backfill stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="backfill_rule_data_sources", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="backfill_rule_data_sources", status="error").inc()
        logger.exception("Rule data_sources backfill failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="backfill_rule_data_sources").observe(time.monotonic() - start)


async def _backfill_rule_data_sources() -> dict:
    """Project stored log-source metadata into the field coverage actually reads.

    Telemetry feasibility joins `DetectionRule.data_sources` against the
    telemetry inventory, but only Elastic and Sentinel rules ever populated it.
    Sigma rules carry their `logsource` in `log_sources`, and Splunk searches
    declare index/sourcetype inline — both were being ignored, so most of the
    library counted as unevaluatable rather than covered-or-gapped.

    Artifact-scanning formats (YARA, nuclei) are skipped, not flagged: they have
    no log stream to satisfy.
    """
    from sqlalchemy import update

    from app.intelligence.rule_metadata import NON_TELEMETRY_RULE_TYPES, derive_data_sources
    from app.models.detection_rule import DetectionRule

    stats = {"scanned": 0, "updated": 0, "skipped_non_telemetry": 0}
    batch_size = 500

    async with worker_session() as db:
        # Select columns, not ORM instances: DetectionRule.entry is lazy="joined",
        # so loading whole rows for the full library pulls every linked entry's
        # content along with it and OOMs the worker.
        offset = 0
        while True:
            rows = (
                await db.execute(
                    select(
                        DetectionRule.id,
                        DetectionRule.rule_type,
                        DetectionRule.log_sources,
                        DetectionRule.rule_content,
                    )
                    .where(DetectionRule.data_sources.is_(None) | (DetectionRule.data_sources == []))
                    .order_by(DetectionRule.id)
                    .limit(batch_size)
                    .offset(offset)
                )
            ).all()
            if not rows:
                break

            untouched = 0
            for rule_id, rule_type, log_sources, rule_content in rows:
                stats["scanned"] += 1
                derived = (
                    []
                    if rule_type in NON_TELEMETRY_RULE_TYPES
                    else derive_data_sources(rule_type, log_sources, rule_content)
                )
                if rule_type in NON_TELEMETRY_RULE_TYPES:
                    stats["skipped_non_telemetry"] += 1
                if derived:
                    await db.execute(
                        update(DetectionRule).where(DetectionRule.id == rule_id).values(data_sources=derived)
                    )
                    stats["updated"] += 1
                else:
                    untouched += 1

            await db.commit()
            # Updated rows drop out of the WHERE clause; everything we left alone
            # stays in it, so the window has to step past exactly those.
            offset += untouched
            if len(rows) < batch_size:
                break

    return stats


@celery_app.task(name="app.workers.maintenance.backfill_rule_attack_mappings", soft_time_limit=3300, time_limit=3360)
def backfill_rule_attack_mappings(limit: int | None = None):
    """Re-extract ATT&CK mappings for GitHub-sourced rules, and derive tactics."""
    start = time.monotonic()
    try:
        stats = run_async(_backfill_rule_attack_mappings(limit))
        logger.info("Rule ATT&CK mapping backfill stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="backfill_rule_attack_mappings", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="backfill_rule_attack_mappings", status="error").inc()
        logger.exception("Rule ATT&CK mapping backfill failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="backfill_rule_attack_mappings").observe(time.monotonic() - start)


async def _derive_tactics_from_techniques(db, rules_by_id: dict) -> int:
    """Fill mitre_tactics from source_ttps using the hydrated ATT&CK catalog.

    Upstream rule formats publish the technique but rarely the tactic — the
    tactic is a property of the technique, so it's a lookup rather than an
    inference. Only fills rules that have techniques and no tactics.
    """
    from sqlalchemy import update as sa_update

    from app.models.detection_rule import DetectionRule
    from app.models.ttp import TTP

    if not rules_by_id:
        return 0

    wanted = {str(t).upper() for ttps in rules_by_id.values() for t in ttps or []}
    if not wanted:
        return 0

    rows = (
        await db.execute(select(TTP.technique_id, TTP.tactic, TTP.tactics).where(TTP.technique_id.in_(wanted)))
    ).all()
    tactics_by_technique = {
        tid: [t for t in (tactics or ([tactic] if tactic else [])) if t] for tid, tactic, tactics in rows
    }

    updated = 0
    for rule_id, ttps in rules_by_id.items():
        tactics: list[str] = []
        for technique in ttps or []:
            for tactic in tactics_by_technique.get(str(technique).upper(), []):
                # Sub-techniques inherit the parent's tactics; dedupe.
                normalized = tactic.lower().replace(" ", "_")
                if normalized not in tactics:
                    tactics.append(normalized)
        if tactics:
            await db.execute(sa_update(DetectionRule).where(DetectionRule.id == rule_id).values(mitre_tactics=tactics))
            updated += 1
    return updated


# Rule formats whose upstream files declare ATT&CK techniques.
_ATTACK_MAPPED_RULE_TYPES = ("splunk_spl", "sigma", "elastic_ql", "kql")

# Azure/Azure-Sentinel migrated its detection library out of `Detections/` into
# `Solutions/<name>/Analytic Rules/`, leaving behind stub YAMLs whose only real
# content is a sentence pointing at the new file. Those stubs carry no tactics or
# techniques, so every rule ingested from the old path lost its ATT&CK mapping.
# The stub names its replacement, so follow it once.
_MIGRATION_STUB_RE = re.compile(r"content migration|moved to (?:a )?new location", re.IGNORECASE)
_GITHUB_BLOB_RE = re.compile(r"https://github\.com/([^/\s]+)/([^/\s]+)/blob/([^/\s]+)/([^\s'\"]+)")


def _follow_migration_stub(content: str) -> str | None:
    """Raw URL a migration-stub rule file points at, if this is one."""
    if not content or not _MIGRATION_STUB_RE.search(content):
        return None
    match = _GITHUB_BLOB_RE.search(content)
    if not match:
        return None
    owner, repo, ref, path = match.groups()
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path.rstrip('\'")')}"


async def _backfill_rule_attack_mappings(limit: int | None = None) -> dict:
    """Re-fetch GitHub-sourced rule files and re-run metadata extraction.

    Rules ingested from a GitHub repo store their `metadata` as extracted at
    ingest time. When an upstream project restructures its schema — as
    splunk/security_content did by moving `mitre_attack_id`, `analytic_story`
    and `data_source` from `tags` to the top level — the stored metadata is
    permanently missing those fields, and re-running extraction over the DB
    can't recover them because only the search body is kept in `rule_content`.

    So this re-fetches the original file at the exact commit it was ingested
    from, re-extracts, and writes back source_ttps / mitre_tactics /
    data_sources. Then derives tactics for every rule that has techniques but
    no tactics, whether or not it was re-fetched.
    """
    import asyncio

    import httpx
    from sqlalchemy import update as sa_update

    from app.intelligence.rule_metadata import (
        RULE_TYPE_TO_CONTENT_TYPE,
        extract_rule_metadata,
        map_metadata_to_fields,
    )
    from app.models.detection_rule import DetectionRule

    stats = {
        "candidates": 0,
        "refetched": 0,
        "stubs_followed": 0,
        "ttps_filled": 0,
        "data_sources_filled": 0,
        "tactics_derived": 0,
    }
    batch_limit = limit
    headers = {"Accept": "application/vnd.github.raw"}

    async with worker_session() as db:
        # Warm first: batch limit and the GitHub token are both DB-overridable,
        # and settings.get() only sees an override once the cache is loaded.
        await warm_settings_cache(db)
        batch_limit = batch_limit or int(settings.get("rule_attack_backfill_limit") or 1500)
        token = settings.get("github_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # Column select, not ORM rows — DetectionRule.entry is lazy="joined".
        rows = (
            await db.execute(
                select(
                    DetectionRule.id,
                    DetectionRule.rule_type,
                    DetectionRule.metadata_,
                )
                .where(
                    DetectionRule.source_ttps.is_(None) | (DetectionRule.source_ttps == []),
                    DetectionRule.metadata_.isnot(None),
                    # Only formats whose upstream schema carries an ATT&CK
                    # mapping. YARA and nuclei don't publish one (22 of 5,961
                    # YARA rules even mention a technique id), so re-fetching
                    # them just burns the batch without filling anything.
                    DetectionRule.rule_type.in_(_ATTACK_MAPPED_RULE_TYPES),
                )
                .limit(batch_limit)
            )
        ).all()

        candidates = []
        for rule_id, rule_type, meta in rows:
            if not isinstance(meta, dict) or not RULE_TYPE_TO_CONTENT_TYPE.get(rule_type):
                continue
            owner, repo, path = meta.get("owner"), meta.get("repo"), meta.get("file_path")
            if owner and repo and path:
                candidates.append((rule_id, rule_type, owner, repo, path, meta.get("commit_sha") or "HEAD"))
        stats["candidates"] = len(candidates)

        async with httpx.AsyncClient(timeout=30.0, headers=headers, follow_redirects=True) as client:
            for rule_id, rule_type, owner, repo, path, sha in candidates:
                url = f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        continue
                    body = resp.text
                    # Upstream may have replaced the file with a pointer to its
                    # new home; the mapping lives there, not here.
                    redirect = _follow_migration_stub(body)
                    if redirect:
                        stats["stubs_followed"] += 1
                        redirected = await client.get(redirect)
                        if redirected.status_code == 200:
                            body = redirected.text
                    metadata = extract_rule_metadata(rule_type, body)
                except Exception as e:
                    logger.debug("Rule re-fetch failed for %s: %s", url, e)
                    continue

                if not metadata:
                    continue
                stats["refetched"] += 1
                mapped = map_metadata_to_fields(metadata)
                values = {}
                if mapped.get("source_ttps"):
                    values["source_ttps"] = mapped["source_ttps"]
                    stats["ttps_filled"] += 1
                if mapped.get("data_sources"):
                    values["data_sources"] = mapped["data_sources"]
                    stats["data_sources_filled"] += 1
                if values:
                    values["metadata_"] = metadata
                    await db.execute(sa_update(DetectionRule).where(DetectionRule.id == rule_id).values(**values))
                await asyncio.sleep(0.05)

        await db.commit()

        # Tactics: derivable for anything with techniques, re-fetched or not.
        need_tactics = (
            await db.execute(
                select(DetectionRule.id, DetectionRule.source_ttps).where(
                    DetectionRule.source_ttps.isnot(None),
                    DetectionRule.source_ttps != [],
                    DetectionRule.mitre_tactics.is_(None) | (DetectionRule.mitre_tactics == []),
                )
            )
        ).all()
        stats["tactics_derived"] = await _derive_tactics_from_techniques(db, dict(need_tactics))
        await db.commit()

    return stats


@celery_app.task(name="app.workers.maintenance.rebuild_rule_coverage", soft_time_limit=1800, time_limit=1860)
def rebuild_rule_coverage(since_hours: int | None = None):
    """Re-resolve the rule library into `rule_coverage`.

    Nightly backstop for the incremental paths (single-rule on save, changed
    rows on repo sync). `since_hours` narrows the pass to rules whose
    upstream_updated_at moved inside that window.
    """
    start = time.monotonic()
    try:
        stats = run_async(_rebuild_rule_coverage(since_hours))
        logger.info("Rule coverage rebuild stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="rebuild_rule_coverage", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="rebuild_rule_coverage", status="error").inc()
        logger.exception("Rule coverage rebuild failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="rebuild_rule_coverage").observe(time.monotonic() - start)


async def _rebuild_rule_coverage(since_hours: int | None = None) -> dict:
    from app.services.rule_coverage import resolve_all

    since = datetime.now(UTC) - timedelta(hours=since_hours) if since_hours else None
    async with _get_worker_session() as db:
        return await resolve_all(db, since=since)


@celery_app.task(name="app.workers.maintenance.rank_threat_board", soft_time_limit=900, time_limit=960)
def rank_threat_board():
    """Recompute the Intel→Rules board and reconcile the decisions pinned to it.

    The board itself is computed per request — four queries over entries, TTP
    junctions and `rule_coverage` — so this is not a cache warm. It exists
    because two things the board decides on read are never written back:

    * a `handled` threat reopens when new tradecraft postdates the decision, but
      only in the response. The stored row keeps saying `handled`, so anything
      reading `threat_board_state` directly (a digest, a notification) sees the
      opposite of what the board shows.
    * a decision outlives the entity it was made about. Merging two actors, or
      deleting an extraction artefact, orphans its row forever.

    Runs after `rebuild-rule-coverage`, because the ranking reads that table.
    """
    start = time.monotonic()
    try:
        stats = run_async(_rank_threat_board())
        logger.info("Threat board ranking stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="rank_threat_board", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="rank_threat_board", status="error").inc()
        logger.exception("Threat board ranking failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="rank_threat_board").observe(time.monotonic() - start)


async def _rank_threat_board() -> dict:
    from sqlalchemy import text as sa_text

    from app import entity_types
    from app.services.threat_board import WINDOW_HOURS, build_threat_board

    stats: dict = {"windows": {}, "reopened": 0, "pruned": 0}
    async with _get_worker_session() as db:
        reopen: set[tuple[str, str]] = set()
        for window in WINDOW_HOURS:
            # min_attention=1 and a wide limit: the point is to see every row a
            # user could have decided on, not the shortlist the UI renders.
            rows = await build_threat_board(db, window=window, limit=200, min_attention=1, include_handled=True)
            stats["windows"][window] = len(rows)
            reopen.update((r.entity_type, r.entity_key) for r in rows if r.state == "open")

        if reopen:
            result = await db.execute(
                sa_text(
                    "UPDATE threat_board_state SET state = 'open' "
                    "WHERE state = 'handled' AND (entity_type, entity_key) IN "
                    "(SELECT unnest(CAST(:types AS text[])), unnest(CAST(:keys AS text[])))"
                ),
                {"types": [t for t, _ in reopen], "keys": [k for _, k in reopen]},
            )
            stats["reopened"] = result.rowcount or 0

        # `muted` is a standing decision about the entity, so it is pruned by
        # the same rule: if the entity is gone, so is anything said about it.
        pruned = await db.execute(
            sa_text(
                "DELETE FROM threat_board_state WHERE "
                "(entity_type = :actor_type AND entity_key NOT IN (SELECT id::text FROM threat_actors)) OR "
                "(entity_type = :malware_type AND entity_key NOT IN (SELECT id::text FROM malware_families))"
            ),
            {"actor_type": entity_types.THREAT_ACTOR, "malware_type": entity_types.MALWARE},
        )
        stats["pruned"] = pruned.rowcount or 0
        await db.commit()

    return stats


@celery_app.task(name="app.workers.maintenance.promote_watchlist_threats", soft_time_limit=300, time_limit=360)
def promote_watchlist_threats():
    """Watched actors/malware with window activity enter the Threats board as tracked.

    Watch already means "I care"; the board should believe it without a second
    gesture. Only rows with no standing decision are promoted — a handled or
    muted threat was decided by a human, and a beat task doesn't outrank that.
    """
    start = time.monotonic()
    try:
        stats = run_async(_promote_watchlist_threats())
        logger.info("Watchlist promote stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="promote_watchlist_threats", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="promote_watchlist_threats", status="error").inc()
        logger.exception("Watchlist promote failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="promote_watchlist_threats").observe(time.monotonic() - start)


async def _promote_watchlist_threats() -> dict:
    from sqlalchemy import text as sa_text

    async with _get_worker_session() as db:
        result = await db.execute(
            sa_text(
                """
                INSERT INTO threat_board_state (entity_type, entity_key, state, new_count_at_decision)
                SELECT DISTINCT w.entity_type, w.entity_id::text, 'tracked', 0
                FROM user_entity_watches w
                WHERE w.mode = 'watch'
                  AND w.entity_type IN ('threat_actor', 'malware')
                  -- Window activity: any linked entry in the board's default window.
                  AND EXISTS (
                    SELECT 1 FROM entries e
                    LEFT JOIN entry_threat_actors ea
                      ON w.entity_type = 'threat_actor' AND ea.entry_id = e.id AND ea.threat_actor_id = w.entity_id
                    LEFT JOIN entry_malware em
                      ON w.entity_type = 'malware' AND em.entry_id = e.id AND em.malware_family_id = w.entity_id
                    WHERE e.published_at > now() - interval '14 days'
                      AND (ea.entry_id IS NOT NULL OR em.entry_id IS NOT NULL)
                  )
                ON CONFLICT (entity_type, entity_key) DO NOTHING
                """
            )
        )
        await db.commit()
        return {"promoted": result.rowcount or 0}


@celery_app.task(name="app.workers.maintenance.generate_threat_briefs", soft_time_limit=1800, time_limit=1860)
def generate_threat_briefs(limit: int | None = None):
    """Nightly story lines for the board's open rows.

    Runs after rank_threat_board. Each brief is built only from the row's own
    window entries and cached in ai_results keyed by a hash of that entry set,
    so an unchanged week regenerates nothing. The board reads the cache and
    falls back to the lead headline — this task is the only writer.
    """
    start = time.monotonic()
    try:
        stats = run_async(_generate_threat_briefs(limit))
        logger.info("Threat brief stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="generate_threat_briefs", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="generate_threat_briefs", status="error").inc()
        logger.exception("Threat brief generation failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="generate_threat_briefs").observe(time.monotonic() - start)


async def _generate_threat_briefs(limit: int | None = None) -> dict:
    from app import entity_types
    from app.services.threat_board import WINDOW_HOURS, build_cve_board, build_threat_board
    from app.services.threat_brief import (
        BRIEF_WINDOW,
        collect_brief_entries,
        collect_cve_facts,
        ensure_threat_brief,
    )

    stats = {"rows": 0, "generated": 0, "cached": 0, "skipped": 0}
    hours = WINDOW_HOURS[BRIEF_WINDOW]
    async with _get_worker_session() as db:
        await warm_settings_cache(db)
        if limit is None:
            limit = int(settings.get("threat_brief_limit") or 30)
        # Both halves of the board get story lines. Vulnerability rows were
        # ranked and rendered from the start but never briefed, because this
        # fan-out only ever walked build_threat_board — so every CVE row fell
        # back to its lead headline no matter how much was written about it.
        rows = await build_threat_board(db, window=BRIEF_WINDOW, limit=limit, include_handled=False)
        # No user_id: a brief is one shared artefact per CVE, so it is generated
        # against the unweighted ranking rather than any one analyst's stack.
        # A stacked user's top rows sort differently, so the tail of a large
        # board can be a headline until the next run reaches it.
        rows += await build_cve_board(db, window=BRIEF_WINDOW, limit=limit, include_handled=False)
        for row in rows:
            if row.is_generic:
                continue
            stats["rows"] += 1
            try:
                entries = await collect_brief_entries(db, row.entity_type, row.entity_key, hours)
                facts = await collect_cve_facts(db, row.entity_key) if row.entity_type == entity_types.CVE else None
                result = await ensure_threat_brief(db, row.entity_type, row.entity_key, row.label, entries, facts=facts)
                stats[result.get("status", "skipped")] = stats.get(result.get("status", "skipped"), 0) + 1
            except Exception:
                # One bad row must not starve the rest of the board of briefs.
                logger.exception("Threat brief failed for %s %s", row.entity_type, row.entity_key)
                stats["skipped"] += 1
    return stats


@celery_app.task(name="app.workers.maintenance.decay_observable_confidence", soft_time_limit=300, time_limit=360)
def decay_observable_confidence():
    """Nightly confidence decay + lifecycle transitions for the observables ledger."""
    start = time.monotonic()
    try:
        stats = run_async(_decay_observable_confidence())
        if stats.get("changed"):
            logger.info("Observable decay pass: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="decay_observable_confidence", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="decay_observable_confidence", status="error").inc()
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="decay_observable_confidence").observe(time.monotonic() - start)


async def _decay_observable_confidence():
    from app.intelligence.observables import compute_confidence, status_for
    from app.models.observable import DECAY_HALF_LIFE_DAYS, Observable
    from app.services.system_settings import get_setting

    async with _get_worker_session() as db:
        if str(await get_setting("observables_decay_enabled", db)).lower() in ("false", "0", "no"):
            return {"changed": 0, "skipped": "disabled"}
        # Only kinds that actually decay, and only unpinned live rows.
        decaying_kinds = [k for k, hl in DECAY_HALF_LIFE_DAYS.items() if hl is not None]
        rows = (
            await db.execute(
                select(Observable).where(
                    Observable.kind.in_(decaying_kinds),
                    Observable.confidence_pinned.is_(False),
                    Observable.is_denied.is_(False),
                    Observable.status != "expired",
                )
            )
        ).scalars()
        changed = 0
        now = datetime.now(UTC)
        for obs in rows:
            new_conf = compute_confidence(obs.base_confidence, obs.kind, obs.last_seen_at, now)
            new_status = status_for(new_conf)
            if abs(new_conf - obs.current_confidence) > 1e-4 or new_status != obs.status:
                obs.current_confidence = new_conf
                obs.status = new_status
                changed += 1
        await db.commit()
        return {"changed": changed}


@celery_app.task(name="app.workers.maintenance.reconcile_observable_counters", soft_time_limit=300, time_limit=360)
def reconcile_observable_counters():
    """Recount observable sighting/article counters from the junction table.

    ``record_sighting`` increments; only the manual unlink endpoint recounts.
    Entry deletion (retention cleanup) cascades ``entry_observables`` rows at
    the database, so the increment-only counters drift upward over time — this
    nightly recount is the ground truth pass.
    """
    start = time.monotonic()
    try:
        stats = run_async(_reconcile_observable_counters())
        if stats.get("changed"):
            logger.info("Observable counter reconcile: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="reconcile_observable_counters", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="reconcile_observable_counters", status="error").inc()
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="reconcile_observable_counters").observe(time.monotonic() - start)


async def _reconcile_observable_counters():
    from sqlalchemy import exists, or_, update

    from app.intelligence.observables import corroboration_counts_subquery
    from app.models.observable import EntryObservable, Observable

    async with _get_worker_session() as db:
        counts = corroboration_counts_subquery()
        fixed = await db.execute(
            update(Observable)
            .where(
                Observable.id == counts.c.observable_id,
                or_(
                    Observable.sighting_count != counts.c.cnt,
                    Observable.article_count.is_(None),
                    Observable.article_count != counts.c.cnt,
                    Observable.report_count != counts.c.reports,
                    Observable.feed_source_count != counts.c.feeds,
                ),
            )
            .values(
                sighting_count=counts.c.cnt,
                article_count=counts.c.cnt,
                report_count=counts.c.reports,
                feed_source_count=counts.c.feeds,
            )
        )
        zeroed = await db.execute(
            update(Observable)
            .where(
                or_(
                    Observable.sighting_count != 0,
                    Observable.article_count != 0,
                    Observable.report_count != 0,
                    Observable.feed_source_count != 0,
                ),
                ~exists(select(EntryObservable.observable_id).where(EntryObservable.observable_id == Observable.id)),
            )
            .values(sighting_count=0, article_count=0, report_count=0, feed_source_count=0)
        )
        await db.commit()
        return {"changed": (fixed.rowcount or 0) + (zeroed.rowcount or 0)}


@celery_app.task(name="app.workers.maintenance.retro_sight_observables", soft_time_limit=600, time_limit=660)
def retro_sight_observables():
    """Retro-sight recently confirmed observables across the existing corpus.

    Forward sightings happen at ingest (the observables stage); this closes the
    other direction — a value confirmed today gets its historical mentions via
    exact-string search, never regex discovery.
    """
    start = time.monotonic()
    try:
        stats = run_async(_retro_sight_observables())
        if stats.get("sighted"):
            logger.info("Retro-sighting pass: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="retro_sight_observables", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="retro_sight_observables", status="error").inc()
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="retro_sight_observables").observe(time.monotonic() - start)


async def _retro_sight_observables():
    from app.intelligence.observables import retro_sight_observable
    from app.models.observable import HASH_KINDS, NETWORK_KINDS, Observable

    async with _get_worker_session() as db:
        cutoff = datetime.now(UTC) - timedelta(days=7)
        rows = (
            (
                await db.execute(
                    select(Observable)
                    .where(
                        Observable.first_seen_at >= cutoff,
                        Observable.sighting_count <= 2,
                        Observable.is_denied.is_(False),
                        Observable.kind.in_(list(NETWORK_KINDS | HASH_KINDS)),
                    )
                    .order_by(Observable.first_seen_at.desc())
                    .limit(200)
                )
            )
            .scalars()
            .all()
        )
        scanned = sighted = 0
        for obs in rows:
            scanned += 1
            sighted += await retro_sight_observable(db, obs)
        await db.commit()
        return {"scanned": scanned, "sighted": sighted}
