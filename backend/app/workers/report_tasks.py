"""Celery tasks for full AI-powered report generation."""

import asyncio
import logging

from celery.exceptions import SoftTimeLimitExceeded

from app.ai.caller import Caller
from app.api.events import publish_event
from app.intelligence.reporting import (
    REPORT_TEMPLATES,
    generate_section_content,
)
from app.models.intel_report import IntelReport
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)

# Transient error substrings that warrant retry
_TRANSIENT_ERROR_PATTERNS = ("529", "overloaded", "rate limit", "503", "502", "504")
MAX_SECTION_RETRIES = 3
RETRY_BASE_DELAY = 5  # seconds


@celery_app.task(
    name="app.workers.report_tasks.generate_full_report",
    bind=True,
    soft_time_limit=600,
    time_limit=720,
    max_retries=1,
)
def generate_full_report(self, report_id: str, user_id: str, caller_kind: str = "user"):
    """Generate all narrative sections of a report via AI.

    Iterates through template sections sequentially, generating AI prose
    for each empty narrative section. Publishes SSE events for progress.

    ``caller_kind`` travels with the job because the worker can't tell a
    person's report from a scheduled one by the user id alone, and only a
    person's run may use that person's provider.
    """
    run_async(_generate_full_report(self, report_id, user_id, caller_kind))


async def _generate_full_report(task, report_id: str, user_id: str, caller_kind: str = "user"):
    import uuid

    report_uuid = uuid.UUID(report_id)
    user_uuid = uuid.UUID(user_id)

    async with worker_session() as db:
        try:
            # A "user" run still derives: the id may be the service account
            # (an agentic task made the report) or a user deleted since enqueue.
            from app.ai.engine import derive_caller

            existing = await derive_caller(db, user_uuid)
            caller = existing if caller_kind == "user" else Caller.of_kind(caller_kind, existing.user_id)
            report = await db.get(IntelReport, report_uuid)
            if not report:
                logger.error("Report %s not found for full generation", report_id)
                return

            # Read focus/audience from metadata
            metadata = (report.content or {}).get("metadata", {})
            focus = metadata.get("focus")
            audience = metadata.get("audience")

            # Get template sections
            template = REPORT_TEMPLATES.get(report.template_type)
            if template:
                section_names = template["sections"]
            else:
                # DB template or fallback: use sections from content
                section_names = list((report.content or {}).get("sections", {}).keys())

            # Identify narrative sections (empty body, not data-only with items)
            narrative_sections = []
            sections = (report.content or {}).get("sections", {})
            for name in section_names:
                section = sections.get(name, {})
                if isinstance(section, dict):
                    # Skip sections that have items (data sections like IOC tables)
                    if section.get("items"):
                        continue
                    # Include sections with empty body
                    if not section.get("body"):
                        narrative_sections.append(name)

            if not narrative_sections:
                publish_event(
                    user_id,
                    "report_generation_complete",
                    {
                        "report_id": report_id,
                        "message": "No narrative sections to generate",
                    },
                )
                return

            total = len(narrative_sections)

            for i, section_name in enumerate(narrative_sections):
                # Reload report to get latest content (prior sections)
                await db.refresh(report)

                # Retry with exponential backoff for transient API errors
                result = None
                for attempt in range(MAX_SECTION_RETRIES + 1):
                    result = await generate_section_content(
                        db=db,
                        user_id=user_uuid,
                        report=report,
                        section_name=section_name,
                        focus=focus,
                        audience=audience,
                        caller=caller,
                    )
                    if "error" not in result:
                        break
                    error_msg = result.get("error", "").lower()
                    is_transient = any(p in error_msg for p in _TRANSIENT_ERROR_PATTERNS)
                    if is_transient and attempt < MAX_SECTION_RETRIES:
                        delay = RETRY_BASE_DELAY * (2**attempt)
                        logger.info(
                            "Transient error for section %s (attempt %d/%d), retrying in %ds: %s",
                            section_name,
                            attempt + 1,
                            MAX_SECTION_RETRIES + 1,
                            delay,
                            result["error"],
                        )
                        await asyncio.sleep(delay)
                    else:
                        break

                if "error" in result:
                    logger.warning(
                        "AI generation failed for section %s of report %s: %s",
                        section_name,
                        report_id,
                        result["error"],
                    )
                    # Continue to next section rather than failing entirely
                    publish_event(
                        user_id,
                        "report_section_generated",
                        {
                            "report_id": report_id,
                            "section_name": section_name,
                            "done": i + 1,
                            "total": total,
                            "error": result["error"],
                        },
                    )
                    continue

                # Update section body in report content
                content = dict(report.content or {})
                sections = dict(content.get("sections", {}))
                section = dict(sections.get(section_name, {}))
                section["body"] = result.get("content", "")
                sections[section_name] = section
                content["sections"] = sections
                report.content = content

                db.add(report)
                await db.commit()

                publish_event(
                    user_id,
                    "report_section_generated",
                    {
                        "report_id": report_id,
                        "section_name": section_name,
                        "done": i + 1,
                        "total": total,
                    },
                )

            publish_event(
                user_id,
                "report_generation_complete",
                {
                    "report_id": report_id,
                },
            )

        except SoftTimeLimitExceeded:
            logger.error("Report generation timed out for %s", report_id)
            publish_event(
                user_id,
                "report_generation_error",
                {
                    "report_id": report_id,
                    "error": "Report generation timed out",
                },
            )
        except Exception as e:
            logger.exception("Report generation failed for %s", report_id)
            publish_event(
                user_id,
                "report_generation_error",
                {
                    "report_id": report_id,
                    "error": str(e),
                },
            )
