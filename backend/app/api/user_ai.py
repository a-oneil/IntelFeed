"""Settings → My AI: one person's keys, routes, spend and fallback.

Keys themselves are ``ai_providers`` rows with ``user_id`` set and live
under ``/api/ai/providers``. This router covers what hangs off them: which
of my keys answers which task, what I've spent, and what should happen
when my key can't answer. Everything here is scoped to the caller; there
is no admin view, because the admin's view of personal keys is the cost
dashboard and the User keys tab.
"""

import uuid
from datetime import timedelta
from decimal import Decimal

from fastapi import APIRouter, Depends, Path
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.engine import (
    _route_blocked,
    allowed_personal_types,
    site_requests_today,
    user_key_usage,
    user_monthly_cap,
    utc_month_start,
)
from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.ai_provider import AIProvider
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment
from app.models.user import User
from app.models.user_ai_route import UserAIPreferences, UserAIRoute
from app.schemas.ai import (
    UserAIKeyUsage,
    UserAIOverview,
    UserAIPolicy,
    UserAIPolicyStatus,
    UserAIPreferencesUpdate,
    UserAIRouteResponse,
    UserAIRouteUpsert,
    UserAITaskRow,
    UserAIUsage,
)
from app.services.system_settings import get_setting

router = APIRouter()


async def _policy(db: AsyncSession) -> UserAIPolicy:
    return UserAIPolicy(
        allow_user_ai_providers=bool(await get_setting("allow_user_ai_providers", db)),
        require_user_ai_provider=bool(await get_setting("require_user_ai_provider", db)),
        provider_types=sorted(allowed_personal_types(await get_setting("user_ai_provider_types", db))),
        allow_private_endpoints=bool(await get_setting("user_ai_allow_private_endpoints", db)),
        daily_request_cap=int(await get_setting("user_ai_daily_request_cap", db) or 0),
        site_allowance_per_user=int(await get_setting("site_ai_user_daily_requests", db) or 0),
    )


async def _own_provider(db: AsyncSession, user: User, provider_id: uuid.UUID) -> AIProvider:
    provider = (
        await db.execute(select(AIProvider).where(AIProvider.id == provider_id, AIProvider.user_id == user.id))
    ).scalar_one_or_none()
    if provider is None:
        # Someone else's key, or the instance's: neither is routable by this person.
        raise AppError(code="not_found", message="Provider not found", status_code=404)
    return provider


def _route_response(route: UserAIRoute, task_name: str | None, provider_name: str | None) -> UserAIRouteResponse:
    return UserAIRouteResponse(
        id=route.id,
        task_id=route.task_id,
        task_name=task_name,
        provider_id=route.provider_id,
        provider_name=provider_name,
        model_name=route.model_name,
        config=route.config or {},
        updated_at=route.updated_at,
    )


async def _routes(db: AsyncSession, user: User) -> list[tuple[UserAIRoute, str | None, str | None]]:
    rows = (
        await db.execute(
            select(UserAIRoute, AITask.name, AIProvider.name)
            .outerjoin(AITask, AITask.id == UserAIRoute.task_id)
            .outerjoin(AIProvider, AIProvider.id == UserAIRoute.provider_id)
            .where(UserAIRoute.user_id == user.id)
            .order_by(UserAIRoute.task_id.is_not(None), AITask.name)
        )
    ).all()
    return [(route, task_name, provider_name) for route, task_name, provider_name in rows]


@router.get("/policy", response_model=UserAIPolicyStatus)
async def my_ai_policy(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The admin's personal-key policy and whether I have any routes: the cheap read a reader
    panel makes before fetching the overview. Settings come from the in-process cache; the
    one query is an existence check on my routes."""
    policy = await _policy(db)
    has_routes = (await db.scalar(select(UserAIRoute.id).where(UserAIRoute.user_id == user.id).limit(1))) is not None
    return UserAIPolicyStatus(**policy.model_dump(), has_routes=has_routes)


@router.get("/overview", response_model=UserAIOverview)
async def my_ai_overview(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Everything the My AI page shows: the admin's policy, my fallback and cap, my spend this
    month and today (split by whose provider answered, and by key), and every task I may route
    with where it runs now."""
    policy = await _policy(db)
    prefs = await db.get(UserAIPreferences, user.id)
    month_start = utc_month_start()

    by_key_rows = (
        await db.execute(
            select(
                AIProvider.id,
                AIProvider.name,
                AIProvider.provider_type,
                func.coalesce(func.sum(AIResult.cost_estimate), 0),
                func.count(AIResult.id),
            )
            .outerjoin(
                AIResult,
                (AIResult.provider_id == AIProvider.id)
                & (AIResult.key_owner_id == user.id)
                & (AIResult.created_at >= month_start),
            )
            .where(AIProvider.user_id == user.id)
            .group_by(AIProvider.id, AIProvider.name, AIProvider.provider_type)
            .order_by(AIProvider.name)
        )
    ).all()

    month_cost, requests_today = await user_key_usage(db, user.id)
    usage = UserAIUsage(
        month_cost=month_cost,
        monthly_cap_usd=await user_monthly_cap(db, prefs),
        requests_today=requests_today,
        daily_request_cap=policy.daily_request_cap,
        site_requests_today=await site_requests_today(db, user.id),
        site_allowance_per_user=policy.site_allowance_per_user,
        month_resets_at=(month_start.replace(day=28) + timedelta(days=4)).replace(day=1),
        by_key=[
            UserAIKeyUsage(
                provider_id=pid,
                provider_name=name,
                provider_type=ptype,
                month_cost=Decimal(str(cost)),
                month_requests=int(count),
            )
            for pid, name, ptype, cost, count in by_key_rows
        ],
    )

    all_routes = await _routes(db, user)
    routes = {route.task_id: (route, task_name, provider_name) for route, task_name, provider_name in all_routes}
    default_route = routes.get(None)

    # Spend per task on my keys this month, so each row can show what it cost.
    task_cost = dict(
        (
            await db.execute(
                select(AIResult.task_id, func.coalesce(func.sum(AIResult.cost_estimate), 0))
                .where(AIResult.key_owner_id == user.id, AIResult.created_at >= month_start)
                .group_by(AIResult.task_id)
            )
        ).all()
    )

    task_rows = (
        await db.execute(
            select(AITask, AITaskAssignment.model_name, AIProvider.name)
            .outerjoin(AITaskAssignment, AITaskAssignment.task_id == AITask.id)
            .outerjoin(AIProvider, AIProvider.id == AITaskAssignment.provider_id)
            .where(AITask.allows_user_provider.is_(True), AITask.is_deprecated.is_(False))
            .order_by(AITask.category, AITask.display_name)
        )
    ).all()

    # What a click would do, by the lookup's own rule (``resolve_assignment``),
    # so the row says "your key" only when the key can answer. A key is
    # checked once however many tasks follow it.
    my_keys = {
        p.id: p for p in (await db.execute(select(AIProvider).where(AIProvider.user_id == user.id))).scalars().all()
    }
    blocked_by_key: dict[uuid.UUID, str | None] = {}
    fallback = prefs.fallback_to_site if prefs is not None else True

    async def _will_run(route: UserAIRoute | None, has_site: bool) -> tuple[str, str | None]:
        if not policy.allow_user_ai_providers:
            return "site", None
        reason: str | None = None
        if route is not None and route.provider_id is not None:
            key = my_keys.get(route.provider_id)
            if key is not None:
                if route.provider_id not in blocked_by_key:
                    blocked_by_key[route.provider_id] = await _route_blocked(
                        db, route, key, prefs, usage=(month_cost, requests_today)
                    )
                reason = blocked_by_key[route.provider_id]
                if reason is None:
                    return "user", None
            else:
                route = None
        if route is not None and route.provider_id is None:
            route = None  # the opt-out row: the instance answers by choice
        if policy.require_user_ai_provider or (route is not None and not fallback):
            return "refused", reason or "no_key"
        if reason is not None and not has_site:
            # Their key is this prompt's only provider and it can't answer:
            # the lookup refuses with the reason rather than "not configured".
            return "refused", reason
        return "site", reason

    tasks = []
    for task, site_model, site_provider in task_rows:
        route = routes.get(task.id)
        effective = route[0] if route else (default_route[0] if default_route else None)
        will_run_on, blocked_reason = await _will_run(effective, site_provider is not None)
        tasks.append(
            UserAITaskRow(
                task_id=task.id,
                task_name=task.name,
                display_name=task.display_name,
                category=task.category,
                requires_tools=task.requires_tools,
                site_provider_name=site_provider,
                site_model_name=site_model,
                route=_route_response(*route) if route else None,
                month_cost=Decimal(str(task_cost.get(task.id, 0))),
                will_run_on=will_run_on,
                blocked_reason=blocked_reason,
            )
        )

    return UserAIOverview(
        policy=policy,
        fallback_to_site=prefs.fallback_to_site if prefs is not None else True,
        monthly_cap_usd=prefs.monthly_cap_usd if prefs is not None else None,
        usage=usage,
        tasks=tasks,
        default_route=_route_response(*default_route) if default_route else None,
    )


@router.patch("/preferences", response_model=UserAIOverview)
async def update_my_ai_preferences(
    body: UserAIPreferencesUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Set whether my tasks fall back to the instance's providers when my key can't answer, and
    my own monthly cap on my keys' spend. It is mine alone: the admin sets no ceiling, and null
    removes it."""
    updates = body.model_dump(exclude_unset=True)
    prefs = await db.get(UserAIPreferences, user.id)
    if prefs is None:
        prefs = UserAIPreferences(user_id=user.id)
        db.add(prefs)
    if "fallback_to_site" in updates and updates["fallback_to_site"] is not None:
        prefs.fallback_to_site = updates["fallback_to_site"]
    if "monthly_cap_usd" in updates:
        prefs.monthly_cap_usd = updates["monthly_cap_usd"]
    await db.flush()
    return await my_ai_overview(user=user, db=db)


@router.get("/routes", response_model=list[UserAIRouteResponse])
async def list_my_routes(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """My routes: the default key (task_id null) first, then per-task overrides."""
    return [_route_response(*row) for row in await _routes(db, user)]


@router.put("/routes", response_model=UserAIRouteResponse)
async def upsert_my_route(
    body: UserAIRouteUpsert,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Point a task at one of my keys, or set my default key with task_id null. One route per
    task and one default per person: sending the same target again replaces it. The key must be
    mine, and the task must be one the admin has opened to personal keys. A per-task route with
    no provider sends that task back to the instance's provider despite a default key."""
    provider = None
    if body.provider_id is not None:
        provider = await _own_provider(db, user, body.provider_id)
        if not body.model_name:
            raise AppError(code="validation_error", message="Choose a model for this key.", status_code=400)
    elif body.task_id is None:
        raise AppError(
            code="validation_error",
            message="The default route needs a key; remove it to go back to the instance's providers.",
            status_code=400,
        )

    task_name: str | None = None
    if body.task_id is not None:
        task = await db.get(AITask, body.task_id)
        if task is None or task.is_deprecated:
            raise AppError(code="not_found", message="Task not found", status_code=404)
        if not task.allows_user_provider:
            raise AppError(
                code="task_site_only",
                message=f"'{task.display_name}' always runs on the instance's providers.",
                status_code=400,
            )
        task_name = task.name

    existing = (
        await db.execute(
            select(UserAIRoute).where(
                UserAIRoute.user_id == user.id,
                UserAIRoute.task_id == body.task_id if body.task_id is not None else UserAIRoute.task_id.is_(None),
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        existing = UserAIRoute(user_id=user.id, task_id=body.task_id)
        db.add(existing)
    existing.provider_id = provider.id if provider else None
    existing.model_name = body.model_name if provider else None
    existing.config = body.config or {}
    await db.flush()
    await db.refresh(existing)
    return _route_response(existing, task_name, provider.name if provider else None)


@router.delete("/routes/{route_id}", status_code=204)
async def delete_my_route(
    route_id: uuid.UUID = Path(..., description="ID of my route to remove"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove one of my routes; the task goes back to my default key, or to the instance's
    provider when I have none."""
    route = (
        await db.execute(select(UserAIRoute).where(UserAIRoute.id == route_id, UserAIRoute.user_id == user.id))
    ).scalar_one_or_none()
    if route is None:
        raise AppError(code="not_found", message="Route not found", status_code=404)
    await db.delete(route)
    await db.flush()
