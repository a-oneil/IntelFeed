"""Job schedules API — admin-only management of Celery beat scheduled tasks."""

from typing import Any

from fastapi import APIRouter, Body, Depends, Path
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_admin_user
from app.database import get_db
from app.models.system_setting import SystemSettings
from app.models.user import User
from app.workers.celery_app import celery_app
from app.workers.job_registry import (
    CATEGORY_LABELS,
    CATEGORY_ORDER,
    JOB_REGISTRY,
    read_overrides_from_redis,
    schedule_to_human,
    write_overrides_to_redis,
)

router = APIRouter()

DB_KEY = "_job_schedule_overrides"


async def _load_overrides(db: AsyncSession) -> dict:
    """Load overrides from Redis, falling back to DB."""
    overrides = read_overrides_from_redis()
    if overrides:
        return overrides
    result = await db.execute(select(SystemSettings).where(SystemSettings.id == 1))
    row = result.scalar_one_or_none()
    if row and row.settings:
        overrides = row.settings.get(DB_KEY, {})
        if overrides:
            write_overrides_to_redis(overrides)
        return overrides
    return {}


async def _save_overrides(db: AsyncSession, overrides: dict) -> None:
    """Persist overrides to both Redis and DB."""
    write_overrides_to_redis(overrides)
    result = await db.execute(select(SystemSettings).where(SystemSettings.id == 1))
    row = result.scalar_one_or_none()
    if row:
        settings_dict = dict(row.settings or {})
        settings_dict[DB_KEY] = overrides
        await db.execute(update(SystemSettings).where(SystemSettings.id == 1).values(settings=settings_dict))
        await db.flush()


class JobScheduleUpdate(BaseModel):
    enabled: bool | None = None
    schedule: dict[str, Any] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "enabled": True,
                "schedule": {"type": "interval", "seconds": 900},
            }
        }
    )


def _job_response(name: str, override: dict, job: dict) -> dict:
    effective_schedule = override.get("schedule") or job["default_schedule"]
    return {
        "name": name,
        "task": job["task"],
        "description": job["description"],
        "category": job["category"],
        "uses_ai": job.get("uses_ai", False),
        "settings_keys": job.get("settings_keys", []),
        "enabled": override.get("enabled", job.get("enabled_by_default", True)),
        "default_schedule": job["default_schedule"],
        "effective_schedule": effective_schedule,
        "is_customized": bool(override),
        "human_schedule": schedule_to_human(effective_schedule),
        "human_default_schedule": schedule_to_human(job["default_schedule"]),
    }


@router.get("")
async def list_job_schedules(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """List all scheduled jobs with their current configuration."""
    overrides = await _load_overrides(db)

    jobs = []
    for name, job in JOB_REGISTRY.items():
        override = overrides.get(name, {})
        jobs.append(_job_response(name, override, job))

    return {
        "jobs": jobs,
        "categories": CATEGORY_LABELS,
        "category_order": CATEGORY_ORDER,
    }


@router.patch("/{job_name}")
async def update_job_schedule(
    job_name: str = Path(..., description="Job name from the scheduled-job registry"),
    body: JobScheduleUpdate = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a job's schedule or enabled state."""
    if job_name not in JOB_REGISTRY:
        raise AppError(code="unknown_job", message=f"Unknown job: {job_name}", status_code=404)

    overrides = await _load_overrides(db)
    override = overrides.get(job_name, {})

    if body.enabled is not None:
        override["enabled"] = body.enabled

    if body.schedule is not None:
        stype = body.schedule.get("type")
        if stype not in ("interval", "crontab"):
            raise AppError(
                code="invalid_schedule",
                message="Schedule type must be 'interval' or 'crontab'",
                status_code=400,
            )
        if stype == "interval":
            try:
                secs = float(body.schedule.get("seconds", 0))
                if secs < 5:
                    raise ValueError
            except (TypeError, ValueError):
                raise AppError(
                    code="invalid_schedule",
                    message="Interval requires 'seconds' >= 5",
                    status_code=400,
                )
        override["schedule"] = body.schedule

    overrides[job_name] = override
    await _save_overrides(db, overrides)

    resp = _job_response(job_name, override, JOB_REGISTRY[job_name])
    resp["restart_required"] = True
    return resp


@router.delete("/{job_name}")
async def reset_job_schedule(
    job_name: str = Path(..., description="Job name from the scheduled-job registry"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Reset a job's schedule to defaults."""
    if job_name not in JOB_REGISTRY:
        raise AppError(code="unknown_job", message=f"Unknown job: {job_name}", status_code=404)

    overrides = await _load_overrides(db)
    overrides.pop(job_name, None)
    await _save_overrides(db, overrides)

    return _job_response(job_name, {}, JOB_REGISTRY[job_name])


@router.post("/{job_name}/run")
async def run_job_now(
    job_name: str = Path(..., description="Job name from the scheduled-job registry"),
    user: User = Depends(get_admin_user),
):
    """Manually trigger a job to run immediately."""
    if job_name not in JOB_REGISTRY:
        raise AppError(code="unknown_job", message=f"Unknown job: {job_name}", status_code=404)

    task_name = JOB_REGISTRY[job_name]["task"]
    result = celery_app.send_task(task_name)

    return {
        "name": job_name,
        "task_id": str(result.id),
        "message": f"Job '{job_name}' queued for immediate execution",
    }
