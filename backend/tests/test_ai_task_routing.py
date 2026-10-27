"""Every task that calls an AI provider runs on the `ai` queue.

The default worker runs two tasks at a time and also polls feeds. An AI task
left there holds a slot for minutes per call, and enough of them stop ingest
(prod, 2026-09-23). celery-worker-ai serves the `ai` queue one task at a time.
"""

import pytest

from app.workers.celery_app import celery_app

AI_TASKS = [
    "app.workers.ai_batch_tasks.run_entry_analysis_task",
    "app.workers.adjudication_tasks.adjudicate_entry_task",
    "app.workers.adjudication_tasks.backfill_entry_adjudications",
    "app.workers.entity_maintenance_tasks.refresh_actor_profile",
    "app.workers.entity_maintenance_tasks.process_name_normalization_batch",
    "app.workers.entity_maintenance_tasks.ai_enrich_gap_batch",
    "app.workers.thread_tasks.narrate_story_threads",
    "app.workers.copilot_tasks.run_copilot_stream",
    "app.workers.maintenance.generate_threat_briefs",
    "app.workers.daily_summary_tasks.generate_daily_summaries",
    "app.workers.reddit_digest_tasks.generate_reddit_digest",
    "app.workers.report_tasks.generate_full_report",
]


@pytest.mark.parametrize("task_name", AI_TASKS)
def test_ai_task_is_routed_to_ai_queue(task_name):
    celery_app.loader.import_default_modules()  # register the tasks in `include`
    assert task_name in celery_app.tasks, f"{task_name} is not a registered task"
    assert celery_app.conf.task_routes.get(task_name, {}).get("queue") == "ai"
