"""AI Results API — polymorphic AI result retrieval and execution on any entity."""

import uuid
from datetime import timedelta
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.core.exceptions import AppError
from app.core.security import get_admin_user, get_current_user
from app.database import get_db
from app.models.ai_provider import AIProvider
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment
from app.models.user import User
from app.schemas.ai import (
    AICallerCostRow,
    AICostBreakdown,
    AICostBreakdownRow,
    AIRunEntityRequest,
    AITaskBudgetRow,
)

router = APIRouter()

VALID_TARGET_TYPES = {
    "entry",
    "threat_actor",
    "malware",
    "campaign",
    "cve",
    "cwe",
    "ttp",
    "tool",
    "mitigation",
    "country",
    "sector",
    "vendor",
    "product",
    "observable",
}


def _validate_target_type(target_type: str) -> None:
    if target_type not in VALID_TARGET_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid target_type: {target_type}")


def _to_response(r: AIResult) -> dict:
    """Convert AIResult to response dict, including task_name from relationship."""
    return {
        "id": r.id,
        "entry_id": r.entry_id,
        "target_type": r.target_type,
        "target_id": r.target_id,
        "is_current": r.is_current,
        "task_id": r.task_id,
        "task_name": r.task.name if r.task else None,
        "provider_id": r.provider_id,
        "model_name": r.model_name,
        "parsed_result": r.parsed_result,
        "tokens_input": r.tokens_input,
        "tokens_output": r.tokens_output,
        "cost_estimate": r.cost_estimate,
        "processing_time_ms": r.processing_time_ms,
        "created_at": r.created_at,
    }


@router.get("/ai/results/{target_type}/{target_id}")
async def get_results_for_target(
    target_type: str = Path(
        ..., description="Entity kind of the target (e.g. entry, threat_actor, malware, cve, ttp, tool)"
    ),
    target_id: uuid.UUID = Path(..., description="ID of the target entity"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Get all current AI results for a target entity."""
    _validate_target_type(target_type)
    result = await db.execute(
        select(AIResult)
        .options(joinedload(AIResult.task))
        .where(
            AIResult.target_type == target_type,
            AIResult.target_id == target_id,
            AIResult.is_current == True,  # noqa: E712
        )
        .order_by(AIResult.created_at.desc())
    )
    rows = result.unique().scalars().all()
    return [_to_response(r) for r in rows]


@router.get("/ai/results/{target_type}/{target_id}/{task_name}")
async def get_result_for_task(
    target_type: str = Path(
        ..., description="Entity kind of the target (e.g. entry, threat_actor, malware, cve, ttp, tool)"
    ),
    target_id: uuid.UUID = Path(..., description="ID of the target entity"),
    task_name: str = Path(..., description="Name of the AI task (e.g. summarize)"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict | None:
    """Get the current AI result for a specific task on a target."""
    _validate_target_type(target_type)
    task = await db.execute(select(AITask).where(AITask.name == task_name))
    task_obj = task.scalar_one_or_none()
    if not task_obj:
        raise HTTPException(status_code=404, detail=f"Task '{task_name}' not found")

    result = await db.execute(
        select(AIResult)
        .options(joinedload(AIResult.task))
        .where(
            AIResult.target_type == target_type,
            AIResult.target_id == target_id,
            AIResult.task_id == task_obj.id,
            AIResult.is_current == True,  # noqa: E712
        )
        .order_by(AIResult.created_at.desc())
        .limit(1)
    )
    row = result.unique().scalars().first()
    if not row:
        return None
    return _to_response(row)


@router.get("/ai/results/{target_type}/{target_id}/{task_name}/history")
async def get_result_history(
    target_type: str = Path(
        ..., description="Entity kind of the target (e.g. entry, threat_actor, malware, cve, ttp, tool)"
    ),
    target_id: uuid.UUID = Path(..., description="ID of the target entity"),
    task_name: str = Path(..., description="Name of the AI task (e.g. summarize)"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Get all AI results (current + old) for a specific task on a target."""
    _validate_target_type(target_type)
    task = await db.execute(select(AITask).where(AITask.name == task_name))
    task_obj = task.scalar_one_or_none()
    if not task_obj:
        raise HTTPException(status_code=404, detail=f"Task '{task_name}' not found")

    result = await db.execute(
        select(AIResult)
        .options(joinedload(AIResult.task))
        .where(
            AIResult.target_type == target_type,
            AIResult.target_id == target_id,
            AIResult.task_id == task_obj.id,
        )
        .order_by(AIResult.created_at.desc())
    )
    rows = result.unique().scalars().all()
    return [_to_response(r) for r in rows]


@router.post("/ai/results/{target_type}/{target_id}/run")
async def run_ai_on_entity(
    target_type: str = Path(
        ..., description="Entity kind of the target (e.g. entry, threat_actor, malware, cve, ttp, tool)"
    ),
    target_id: uuid.UUID = Path(..., description="ID of the target entity"),
    body: AIRunEntityRequest = ...,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Run an AI task on any entity type."""
    _validate_target_type(target_type)

    from app.ai.engine import run_task

    # Build variables from entity data
    variables = await _load_entity_variables(db, target_type, target_id)

    # Optional steering: focusable prompts render `{% if focus %}` when provided.
    if body.focus and body.focus.strip():
        variables["focus"] = body.focus.strip()

    parsed = await run_task(
        db=db,
        user_id=user.id,
        task_name=body.task_name,
        variables=variables,
        entry_id=target_id if target_type == "entry" else None,
        target_type=target_type,
        target_id=target_id,
        # A focus is a steering re-run — bypass dedup so it replaces any prior result.
        force=body.force or "focus" in variables,
    )
    if parsed is None:
        raise AppError(
            code="not_configured",
            message=f"AI task '{body.task_name}' is not configured. Assign a provider and model in Settings > AI.",
            status_code=422,
        )
    # Fetch the freshly-saved AIResult to include model/cost metadata
    latest = (
        await db.execute(
            select(AIResult)
            .where(
                AIResult.target_type == target_type,
                AIResult.target_id == target_id,
                AIResult.is_current == True,  # noqa: E712
                AIResult.task_id.in_(select(AITask.id).where(AITask.name == body.task_name)),
            )
            .order_by(AIResult.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    return {
        "task_name": body.task_name,
        "target_type": target_type,
        "target_id": str(target_id),
        "result": parsed,
        "model_name": latest.model_name if latest else None,
        "cost_estimate": str(latest.cost_estimate) if latest and latest.cost_estimate else None,
    }


@router.get("/ai/cost-breakdown", response_model=AICostBreakdown)
async def get_cost_breakdown(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> AICostBreakdown:
    """Trailing-30-day AI spend, broken down by task, by provider/model and by
    who asked, plus per-task-assignment budget vs. current spend for
    over/near-budget flagging in the Cost Dashboard.

    Admin-only: this is the instance-wide bill, including what every other
    user ran. A user's own figures belong on their own settings page.

    Budgets live in AITaskAssignment.config["max_budget_usd"] (the same key the
    claude_code provider reads); a null/absent value means "no budget set".
    """
    thirty_days_ago = func.now() - timedelta(days=30)

    # --- Totals ---
    on_instance = AIResult.key_owner_id.is_(None)
    totals = (
        await db.execute(
            select(
                func.coalesce(func.sum(AIResult.cost_estimate), 0),
                func.count(AIResult.id),
                func.coalesce(func.sum(AIResult.tokens_input), 0),
                func.coalesce(func.sum(AIResult.tokens_output), 0),
                func.coalesce(func.sum(AIResult.cost_estimate).filter(on_instance), 0),
                func.coalesce(func.sum(AIResult.cost_estimate).filter(~on_instance), 0),
                # Answered at $0 (Ollama, an unpriced endpoint). Error rows are
                # also $0 but moved no tokens, and are not "usage".
                func.count(AIResult.id).filter(
                    func.coalesce(AIResult.cost_estimate, 0) == 0,
                    func.coalesce(AIResult.tokens_input, 0) + func.coalesce(AIResult.tokens_output, 0) > 0,
                ),
            ).where(AIResult.created_at >= thirty_days_ago)
        )
    ).first()

    # --- By task (display name) ---
    by_task_rows = (
        await db.execute(
            select(
                AITask.display_name,
                func.count(AIResult.id),
                func.coalesce(func.sum(AIResult.tokens_input), 0),
                func.coalesce(func.sum(AIResult.tokens_output), 0),
                func.coalesce(func.sum(AIResult.cost_estimate), 0),
            )
            .join(AITask, AITask.id == AIResult.task_id)
            .where(AIResult.created_at >= thirty_days_ago)
            .group_by(AITask.display_name)
            .order_by(func.coalesce(func.sum(AIResult.cost_estimate), 0).desc())
        )
    ).all()

    by_task = [
        AICostBreakdownRow(
            label=name or "(unnamed task)",
            requests=reqs,
            tokens_input=tin,
            tokens_output=tout,
            cost=Decimal(str(cost)),
        )
        for name, reqs, tin, tout, cost in by_task_rows
    ]

    # --- By model ---
    # Build the coalesce label ONCE and reuse it in select + group_by so Postgres
    # sees identical expressions (separate func.coalesce() calls get distinct bind
    # params → "must appear in GROUP BY" error).
    model_label = func.coalesce(AIResult.model_name, "(unknown model)")
    by_model_rows = (
        await db.execute(
            select(
                model_label,
                func.count(AIResult.id),
                func.coalesce(func.sum(AIResult.tokens_input), 0),
                func.coalesce(func.sum(AIResult.tokens_output), 0),
                func.coalesce(func.sum(AIResult.cost_estimate), 0),
            )
            .where(AIResult.created_at >= thirty_days_ago)
            .group_by(model_label)
            .order_by(func.coalesce(func.sum(AIResult.cost_estimate), 0).desc())
        )
    ).all()

    by_model = [
        AICostBreakdownRow(
            label=model,
            requests=reqs,
            tokens_input=tin,
            tokens_output=tout,
            cost=Decimal(str(cost)),
        )
        for model, reqs, tin, tout, cost in by_model_rows
    ]

    # --- By caller ---
    # Pipeline, automation and share rows carry no person to bill (automation
    # and share do record a user_id, but as provenance, not as the payer), so
    # they fold into one row per kind. People get a row each.
    kind_label = func.coalesce(AIResult.caller_kind, "unattributed")
    billed_user = case((AIResult.caller_kind == "user", AIResult.user_id), else_=None)
    from app.ai.engine import utc_day_start

    today_start = utc_day_start()
    by_caller_rows = (
        await db.execute(
            select(
                kind_label,
                billed_user,
                User.username,
                func.count(AIResult.id),
                func.coalesce(func.sum(AIResult.tokens_input), 0),
                func.coalesce(func.sum(AIResult.tokens_output), 0),
                func.coalesce(func.sum(AIResult.cost_estimate).filter(on_instance), 0),
                func.coalesce(func.sum(AIResult.cost_estimate).filter(~on_instance), 0),
                func.count(AIResult.id).filter(on_instance, AIResult.created_at >= today_start),
            )
            .outerjoin(User, User.id == billed_user)
            .where(AIResult.created_at >= thirty_days_ago)
            .group_by(kind_label, billed_user, User.username)
            .order_by(func.coalesce(func.sum(AIResult.cost_estimate), 0).desc(), func.count(AIResult.id).desc())
        )
    ).all()

    by_caller = [
        AICallerCostRow(
            caller_kind=kind,
            user_id=uid,
            username=username,
            requests=reqs,
            tokens_input=tin,
            tokens_output=tout,
            instance_cost=Decimal(str(inst)),
            own_key_cost=Decimal(str(own)),
            requests_today=today,
        )
        for kind, uid, username, reqs, tin, tout, inst, own, today in by_caller_rows
    ]
    from app.services.system_settings import get_setting

    site_allowance = int(await get_setting("site_ai_user_daily_requests", db) or 0)

    # --- Per-task budgets vs. spend ---
    # Spend per task_id in the window, keyed for a cheap in-memory join.
    spend_rows = (
        await db.execute(
            select(
                AIResult.task_id,
                func.coalesce(func.sum(AIResult.cost_estimate), 0),
                func.count(AIResult.id),
            )
            .where(AIResult.created_at >= thirty_days_ago)
            .group_by(AIResult.task_id)
        )
    ).all()
    spend_by_task: dict[uuid.UUID, tuple[Decimal, int]] = {
        task_id: (Decimal(str(cost)), reqs) for task_id, cost, reqs in spend_rows
    }

    assignment_rows = (
        await db.execute(
            select(AITaskAssignment, AITask, AIProvider)
            .join(AITask, AITask.id == AITaskAssignment.task_id)
            .join(AIProvider, AIProvider.id == AITaskAssignment.provider_id)
        )
    ).all()

    budgets: list[AITaskBudgetRow] = []
    for assignment, task, provider in assignment_rows:
        raw_budget = (assignment.config or {}).get("max_budget_usd")
        max_budget: Decimal | None = None
        if raw_budget is not None:
            try:
                max_budget = Decimal(str(raw_budget))
            except (ArithmeticError, ValueError, TypeError):
                max_budget = None

        spend, reqs = spend_by_task.get(task.id, (Decimal("0"), 0))
        pct: float | None = None
        if max_budget and max_budget > 0:
            pct = float(spend / max_budget)

        budgets.append(
            AITaskBudgetRow(
                task_id=task.id,
                task_name=task.name,
                display_name=task.display_name,
                provider_name=provider.name,
                model_name=assignment.model_name,
                max_budget_usd=max_budget,
                spend_30d=spend,
                requests_30d=reqs,
                percent_of_budget=pct,
            )
        )

    # Surface budget rows most-at-risk first.
    budgets.sort(key=lambda b: (b.percent_of_budget is None, -(b.percent_of_budget or 0)))

    return AICostBreakdown(
        total_cost_30d=Decimal(str(totals[0])),
        total_requests_30d=totals[1],
        total_tokens_30d={"input": totals[2], "output": totals[3]},
        instance_cost_30d=Decimal(str(totals[4])),
        user_key_cost_30d=Decimal(str(totals[5])),
        unpriced_requests_30d=totals[6],
        site_allowance_per_user=site_allowance,
        by_task=by_task,
        by_model=by_model,
        by_caller=by_caller,
        budgets=budgets,
    )


async def _load_entity_variables(db: AsyncSession, target_type: str, target_id: uuid.UUID) -> dict:
    """Load entity data and return template variables for prompt rendering."""
    if target_type == "entry":
        from app.models.entry import Entry

        result = await db.execute(select(Entry).where(Entry.id == target_id))
        entry = result.scalar_one_or_none()
        if not entry:
            raise HTTPException(status_code=404, detail="Entry not found")
        return {
            "entry": {
                "title": entry.title,
                "author": entry.author,
                "url": entry.url,
                "content": entry.content_text or entry.content_html or entry.summary or "",
                "summary": entry.summary or "",
                "published_at": str(entry.published_at) if entry.published_at else "",
            }
        }

    if target_type == "threat_actor":
        from app.models.threat_actor import ThreatActor

        result = await db.execute(select(ThreatActor).where(ThreatActor.id == target_id))
        entity = result.scalar_one_or_none()
        if not entity:
            raise HTTPException(status_code=404, detail="Threat actor not found")
        return {
            "entity": {
                "type": "threat_actor",
                "name": entity.name,
                "aliases": entity.aliases or [],
                "description": entity.description or "",
            }
        }

    if target_type == "malware":
        from app.models.malware_family import MalwareFamily

        result = await db.execute(select(MalwareFamily).where(MalwareFamily.id == target_id))
        entity = result.scalar_one_or_none()
        if not entity:
            raise HTTPException(status_code=404, detail="Malware not found")
        return {
            "entity": {
                "type": "malware",
                "name": entity.name,
                "aliases": entity.aliases or [],
                "description": entity.description or "",
            }
        }

    if target_type == "observable":
        from app.models.observable import Observable

        result = await db.execute(select(Observable).where(Observable.id == target_id))
        entity = result.scalar_one_or_none()
        if not entity:
            raise HTTPException(status_code=404, detail="Observable not found")
        return {
            "entity": {
                "type": "observable",
                "name": entity.label or entity.value,
                "kind": entity.kind,
                "value": entity.value,
                "role": entity.role or "",
                "evidence": entity.evidence or "",
                "description": entity.description or "",
            }
        }

    if target_type == "campaign":
        from app.models.campaign import Campaign

        result = await db.execute(select(Campaign).where(Campaign.id == target_id))
        entity = result.scalar_one_or_none()
        if not entity:
            raise HTTPException(status_code=404, detail="Campaign not found")
        return {"entity": {"type": "campaign", "name": entity.name, "description": entity.description or ""}}

    if target_type == "cve":
        from app.models.cve import CVE

        result = await db.execute(select(CVE).where(CVE.id == target_id))
        entity = result.scalar_one_or_none()
        if not entity:
            raise HTTPException(status_code=404, detail="CVE not found")
        return {
            "entity": {
                "type": "cve",
                "cve_id": entity.cve_id,
                "description": entity.description or "",
                "severity": entity.severity,
            }
        }

    if target_type == "ttp":
        from app.models.ttp import TTP

        result = await db.execute(select(TTP).where(TTP.id == target_id))
        entity = result.scalar_one_or_none()
        if not entity:
            raise HTTPException(status_code=404, detail="TTP not found")
        return {
            "entity": {
                "type": "ttp",
                "technique_id": entity.technique_id,
                "name": entity.name,
                "description": entity.description or "",
            }
        }

    if target_type == "tool":
        from app.models.tool import Tool

        result = await db.execute(select(Tool).where(Tool.id == target_id))
        entity = result.scalar_one_or_none()
        if not entity:
            raise HTTPException(status_code=404, detail="Tool not found")
        return {"entity": {"type": "tool", "name": entity.name, "description": entity.description or ""}}

    if target_type == "cwe":
        from app.models.cwe import CWE

        result = await db.execute(select(CWE).where(CWE.id == target_id))
        entity = result.scalar_one_or_none()
        if not entity:
            raise HTTPException(status_code=404, detail="Weakness not found")
        return {
            "entity": {
                "type": "cwe",
                "cwe_id": entity.cwe_id,
                "name": entity.name,
                "abstraction": entity.abstraction,
                "description": entity.description or "",
            }
        }

    if target_type == "mitigation":
        from app.models.mitigation import Mitigation

        result = await db.execute(select(Mitigation).where(Mitigation.id == target_id))
        entity = result.scalar_one_or_none()
        if not entity:
            raise HTTPException(status_code=404, detail="Mitigation not found")
        return {
            "entity": {
                "type": "mitigation",
                "mitigation_id": entity.mitigation_id,
                "name": entity.name,
                "description": entity.description or "",
            }
        }

    raise HTTPException(status_code=400, detail=f"Unsupported target_type: {target_type}")
