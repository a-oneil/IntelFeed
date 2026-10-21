import logging
import time as _time
import uuid
from datetime import UTC

from sqlalchemy import select

from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.models.saved_search import SavedSearch
from app.workers.celery_app import celery_app
from app.workers.db import run_async

logger = logging.getLogger(__name__)

MAX_IDS_FOR_UNREAD = 5000  # cap entry IDs fetched for unread calculation


@celery_app.task(name="app.workers.saved_search_tasks.refresh_saved_search_counts", soft_time_limit=120, time_limit=180)
def refresh_saved_search_counts():
    """Refresh saved search match counts."""
    start = _time.monotonic()
    try:
        run_async(_refresh_counts())
        CELERY_TASKS_TOTAL.labels(task_name="refresh_saved_search_counts", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="refresh_saved_search_counts", status="error").inc()
        logger.exception("Failed to refresh saved search counts")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="refresh_saved_search_counts").observe(_time.monotonic() - start)


async def _refresh_counts():
    """Warm each owner's saved-search count cache.

    Saved searches are per-user, and the readers (saved-searches list, triage
    widget) read ``saved_search_counts:{user_id}`` — so counts are computed per
    owner with that user's real unread state, via the same helper the API uses
    on a cache miss.
    """
    from app.api.saved_searches import _compute_counts_inline
    from app.workers.db import worker_session

    async with worker_session() as db:
        result = await db.execute(select(SavedSearch).where(SavedSearch.created_by.isnot(None)))
        searches = result.scalars().all()

        if not searches:
            return

        by_owner: dict[uuid.UUID, list[SavedSearch]] = {}
        for s in searches:
            by_owner.setdefault(s.created_by, []).append(s)

        for owner_id, owned in by_owner.items():
            try:
                # Caches to saved_search_counts:{owner_id} itself
                await _compute_counts_inline(owned, owner_id, db)
            except Exception:
                # One analyst's searches failing must not cost everyone else
                # their refresh — the next run retries them.
                logger.warning("Failed to refresh saved-search counts for user %s", owner_id, exc_info=True)

    logger.info("Refreshed saved search counts for %d searches across %d users", len(searches), len(by_owner))


async def _get_search_total_and_ids(
    query_str: str,
    db,
    limit: int = MAX_IDS_FOR_UNREAD,
) -> tuple[int, list[str]]:
    """Run a saved search's query and return (total_hits, list_of_entry_ids).

    The per-owner count refresh above gets its hits through
    ``_compute_counts_inline`` (which also resolves each owner's read state);
    this is the plain hit-list form the campaign auto-sync needs. It lives in
    ``app.search.entry_query`` so the campaign-source service can run the same
    query without importing Celery.
    """
    from app.search.entry_query import search_entry_ids

    return await search_entry_ids(query_str, db, limit=limit)


@celery_app.task(
    name="app.workers.saved_search_tasks.sync_campaign_saved_searches", soft_time_limit=120, time_limit=180
)
def sync_campaign_saved_searches():
    """Auto-sync campaign saved searches that have auto_sync enabled."""
    start = _time.monotonic()
    try:
        run_async(_sync_campaign_saved_searches())
        CELERY_TASKS_TOTAL.labels(task_name="sync_campaign_saved_searches", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="sync_campaign_saved_searches", status="error").inc()
        logger.exception("Failed to sync campaign saved searches")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="sync_campaign_saved_searches").observe(_time.monotonic() - start)


async def _sync_campaign_saved_searches():
    from datetime import datetime

    from app.models.campaign import Campaign, CampaignEntry, CampaignSavedSearch
    from app.models.saved_search import SavedSearch as SavedSearchModel
    from app.workers.db import worker_session

    async with worker_session() as db:
        # Only sync for active/monitoring campaigns with auto_sync enabled
        result = await db.execute(
            select(CampaignSavedSearch)
            .join(Campaign, Campaign.id == CampaignSavedSearch.campaign_id)
            .where(
                CampaignSavedSearch.auto_sync.is_(True),
                Campaign.status.in_(["active", "monitoring"]),
            )
        )
        css_list = result.scalars().all()

        if not css_list:
            return

        total_added = 0
        for css in css_list:
            try:
                ss = await db.get(SavedSearchModel, css.saved_search_id)
                if not ss:
                    continue

                query_str = ss.query or ss.name or ""
                if not query_str.strip():
                    continue

                _, hit_ids = await _get_search_total_and_ids(query_str, db, limit=1000)

                if not hit_ids:
                    css.last_synced_at = datetime.now(UTC)
                    db.add(css)
                    continue

                # Get existing campaign entry IDs
                existing_result = await db.execute(
                    select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == css.campaign_id)
                )
                existing_ids = {str(row[0]) for row in existing_result.all()}

                new_count = 0
                for eid_str in hit_ids:
                    if eid_str not in existing_ids:
                        try:
                            entry_uuid = uuid.UUID(eid_str)
                        except ValueError:
                            continue
                        db.add(
                            CampaignEntry(
                                campaign_id=css.campaign_id,
                                entry_id=entry_uuid,
                                added_by=css.added_by,
                                notes=f"Auto-added from saved search: {ss.name}",
                            )
                        )
                        new_count += 1

                css.last_synced_at = datetime.now(UTC)
                css.entries_added = css.entries_added + new_count
                db.add(css)
                total_added += new_count

            except Exception:
                logger.warning("Failed to sync campaign saved search %s", css.id, exc_info=True)

        await db.commit()

    logger.info(
        "Campaign saved search auto-sync: processed %d links, added %d entries",
        len(css_list),
        total_added,
    )


@celery_app.task(name="app.workers.saved_search_tasks.sync_campaign_sources", soft_time_limit=300, time_limit=360)
def sync_campaign_sources():
    """Pull in what each campaign follows: its named entities and its stories.

    Separate from the saved-search sweep and given a longer limit: following a
    prolific actor resolves to hundreds of articles on the first run, where a
    saved search is capped by its own result page.
    """
    start = _time.monotonic()
    try:
        added = run_async(_sync_campaign_sources())
        logger.info("campaign_sources_synced %s", added)
        CELERY_TASKS_TOTAL.labels(task_name="sync_campaign_sources", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="sync_campaign_sources", status="error").inc()
        logger.exception("Failed to sync campaign sources")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="sync_campaign_sources").observe(_time.monotonic() - start)


async def _sync_campaign_sources() -> dict:
    from app.services.campaign_sources import sync_campaign_sources as _run
    from app.workers.db import worker_session

    async with worker_session() as db:
        result = await _run(db)
        await db.commit()
        return result
