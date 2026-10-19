import logging as _logging

from celery import Celery
from celery.signals import after_setup_task_logger

from app.config import settings
from app.core.logging import setup_logging
from app.workers.job_registry import build_beat_schedule

# Configure structlog + file handlers BEFORE Celery touches logging.
setup_logging()

celery_app = Celery(
    "intelfeed",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.workers.feed_tasks",
        "app.workers.maintenance",
        "app.workers.automation_tasks",
        "app.workers.intel_feed_tasks",
        "app.workers.saved_search_tasks",
        "app.workers.enrichment_tasks",
        "app.workers.report_tasks",
        "app.workers.reddit_digest_tasks",
        "app.workers.telegram_link_tasks",
        "app.workers.translation_tasks",
        "app.workers.telegram_backfill_tasks",
        "app.workers.entity_maintenance_tasks",
        "app.workers.daily_summary_tasks",
        "app.workers.copilot_tasks",
        "app.workers.copilot_auth_tasks",
        "app.workers.signal_tasks",
        "app.workers.ai_batch_tasks",
        "app.workers.adjudication_tasks",
        "app.workers.tts_tasks",
        "app.workers.embedding_tasks",
        "app.workers.thread_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    # Cap result-backend retention (default is 24h). Task results share the same
    # Redis as the broker/copilot streams; a long TTL let them accumulate until
    # Redis hit maxmemory and rejected all writes ("OOM command not allowed").
    result_expires=3600,
    timezone="UTC",
    enable_utc=True,
    beat_schedule=build_beat_schedule(),
    # Prevent Celery from replacing the root logger we just configured.
    worker_hijack_root_logger=False,
    task_default_queue="celery",
    task_routes={
        # The "ai" queue (formerly "claude_code") is served by the dedicated
        # celery-worker-ai service with --concurrency=1: AI calls run one at a
        # time regardless of provider (paces a single Ollama GPU; for the
        # claude_code CLI provider it also avoids OAuth-session corruption —
        # that worker is the only one mounting the CLI credentials volume).
        # One-pass entry analysis is the heaviest generative task in the app
        # (150-300s per entry on Ollama). Left on the default queue it fills
        # both of that worker's slots and starves poll_due_feeds, which stops
        # ingest outright.
        "app.workers.ai_batch_tasks.run_entry_analysis_task": {"queue": "ai"},
        # The post-analysis review is one more generative call per entry;
        # same worker, same serialization, never alongside the analysis.
        "app.workers.adjudication_tasks.adjudicate_entry_task": {"queue": "ai"},
        "app.workers.adjudication_tasks.backfill_entry_adjudications": {"queue": "ai"},
        "app.workers.entity_maintenance_tasks.refresh_actor_profile": {"queue": "ai"},
        "app.workers.entity_maintenance_tasks.process_name_normalization_batch": {"queue": "ai"},
        "app.workers.entity_maintenance_tasks.ai_enrich_gap_batch": {"queue": "ai"},
        # Thread spines are generative; the sweeper that builds the threads
        # themselves is pure SQL and stays on the default queue.
        "app.workers.thread_tasks.narrate_story_threads": {"queue": "ai"},
        # Interactive global copilot CLI turns — same dedicated worker (owns the
        # OAuth credentials volume), streamed back to the api over Redis.
        "app.workers.copilot_tasks.run_copilot_stream": {"queue": "ai"},
        # Re-auth + credential-health checks read/write the CLI credentials
        # volume, which only celery-worker-ai mounts.
        "app.workers.copilot_auth_tasks.run_claude_auth": {"queue": "ai"},
        "app.workers.copilot_auth_tasks.refresh_claude_auth_status": {"queue": "ai"},
    },
)


@after_setup_task_logger.connect
def _clean_task_logger(logger, **kwargs):
    """Strip Celery's plain-text handler from the task logger."""
    logger.handlers.clear()
    logger.propagate = True
    # Also clean any other celery loggers that got handlers added.
    for name in ("celery", "celery.task", "celery.worker", "celery.beat", "celery.redirected", "celery.app.trace"):
        cel = _logging.getLogger(name)
        cel.handlers.clear()
        cel.propagate = True


# Register job_runs signal handlers (import has side effects on purpose)
from app.workers import task_tracking  # noqa: E402, F401
