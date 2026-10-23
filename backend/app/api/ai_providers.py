"""AI Provider management API routes.

Two kinds of row live in ``ai_providers``. The instance's providers
(``user_id`` NULL) are the admin's: every signed-in person can see them,
only the admin changes them. A personal key (``user_id`` set) is one
person's: they alone list, test, edit, route and delete it, and nobody
else's key is visible to them, so a request against someone else's row is
a 404 rather than a 403 that confirms the row exists. The admin can list,
disable, resume and delete personal keys from the User keys tab (the
author-or-admin rule), but never tests or runs one: that would call the
person's endpoint with the person's key.
"""

import uuid

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.engine import _get_provider_instance as build_provider_instance
from app.ai.engine import allowed_personal_types
from app.ai.providers.base import AIProvider as AIProviderInterface
from app.ai.provisioning import model_choice_problem, route_tasks_to_provider
from app.core.encryption import encrypt_value
from app.core.exceptions import AppError
from app.core.outbound import check_outbound_url
from app.core.security import get_admin_user, get_current_user
from app.database import get_db
from app.models.ai_provider import AIProvider
from app.models.user import User
from app.schemas.ai import (
    AIProviderCommissionResult,
    AIProviderCreate,
    AIProviderResponse,
    AIProviderTestResult,
    AIProviderUpdate,
)
from app.services.system_settings import get_setting

router = APIRouter()


def _get_provider_instance(provider: AIProvider) -> AIProviderInterface:
    # Shared engine factory — routes claude / claude_code / ollama / openai_compatible by provider_type.
    return build_provider_instance(provider)


def _not_found() -> AppError:
    return AppError(code="not_found", message="Provider not found", status_code=404)


async def _load(db: AsyncSession, provider_id: uuid.UUID) -> AIProvider:
    provider = (await db.execute(select(AIProvider).where(AIProvider.id == provider_id))).scalar_one_or_none()
    if not provider:
        raise _not_found()
    return provider


def _owned(provider: AIProvider, user: User, *, use: bool = False) -> AIProvider:
    """A row the caller may act on: their own key, or a site provider if they are the admin.

    ``use`` marks the calls that contact the provider (test, model listing).
    The admin may change or delete anyone's key (author-or-admin), but a
    call with someone else's key is theirs alone to make, so for ``use`` a
    key that isn't the caller's own is a 404 for everyone.
    """
    if provider.user_id is None:
        if user.role != "admin":
            raise AppError(code="forbidden", message="Admin access required", status_code=403)
        return provider
    if provider.user_id != user.id and (use or user.role != "admin"):
        raise _not_found()
    return provider


async def _usable_personal_endpoint(db: AsyncSession, provider: AIProvider) -> str | None:
    """Re-check a personal key's endpoint before the server contacts it on demand.

    The engine re-checks on every routed call; the test and model-listing
    routes contact the provider too, and a hostname that now resolves to the
    LAN, or a switch the admin has since turned off, must stop them as well.
    """
    if not provider.is_personal:
        return None
    if provider.provider_type in ("ollama", "openai_compatible") and not (provider.base_url or "").strip():
        return "This key has no endpoint address."
    return await _personal_url_problem(db, provider.base_url)


async def _personal_url_problem(db: AsyncSession, base_url: str | None) -> str | None:
    """Why a personal key may not point at ``base_url``, or None."""
    if not base_url or not base_url.strip():
        return None
    allow_private = bool(await get_setting("user_ai_allow_private_endpoints", db))
    reason = await check_outbound_url(base_url.strip(), allow_private=allow_private)
    if reason is None:
        return None
    if allow_private or not ("private" in reason or "localhost" in reason):
        # A bad scheme, a missing hostname or a name that doesn't resolve:
        # the admin's switch would not help.
        return f"{reason}."
    return (
        f"{reason}. This instance doesn't allow private endpoints for personal keys. "
        "Use a public URL, or ask your admin to turn on private endpoints."
    )


async def _check_personal_policy(db: AsyncSession, provider_type: str, base_url: str | None) -> None:
    """The refusals a person sees when adding a key, in the order they are checked."""
    if not await get_setting("allow_user_ai_providers", db):
        raise AppError(
            code="user_ai_disabled",
            message="Your admin hasn't enabled personal AI keys on this instance.",
            status_code=403,
        )
    if provider_type == "claude_code":
        raise AppError(
            code="provider_type_not_allowed",
            message=(
                "Claude Code can't be a personal key. It runs one CLI sign-in shared by the whole "
                "instance, so it can't be yours alone. Use a Claude API key instead."
            ),
            status_code=400,
        )
    allowed = allowed_personal_types(await get_setting("user_ai_provider_types", db))
    if provider_type not in allowed:
        names = " and ".join(sorted(allowed)) if allowed else "none"
        raise AppError(
            code="provider_type_not_allowed",
            message=f"This instance allows personal keys of type {names} only.",
            status_code=400,
        )
    if provider_type in ("ollama", "openai_compatible") and not (base_url or "").strip():
        # Without an address the provider would default to the server's own
        # localhost Ollama, which is the instance's GPU under a personal key.
        raise AppError(
            code="validation_error",
            message="A personal key of this type needs the address of your own endpoint.",
            status_code=400,
        )
    problem = await _personal_url_problem(db, base_url)
    if problem:
        raise AppError(code="endpoint_not_allowed", message=problem, status_code=400)


@router.get("", response_model=list[AIProviderResponse])
async def list_providers(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the instance's AI providers plus the caller's own personal keys, ordered by name.
    Other people's keys are never listed here."""
    result = await db.execute(
        select(AIProvider)
        .where(or_(AIProvider.user_id.is_(None), AIProvider.user_id == user.id))
        .order_by(AIProvider.name)
    )
    return result.scalars().all()


@router.get("/user-keys", response_model=list[AIProviderResponse])
async def list_user_keys(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Every personal key on the instance with its owner's username (admin only). Keys themselves are
    never returned; this is the User keys tab's list, which the admin can delete from but not use."""
    rows = (
        await db.execute(
            select(AIProvider, User.username)
            .join(User, User.id == AIProvider.user_id)
            .where(AIProvider.user_id.is_not(None))
            .order_by(User.username, AIProvider.name)
        )
    ).all()
    out = []
    for provider, username in rows:
        item = AIProviderResponse.model_validate(provider)
        item.owner_username = username
        out.append(item)
    return out


@router.post("", response_model=AIProviderResponse, status_code=201)
async def create_provider(
    body: AIProviderCreate,
    test: bool = Query(False, description="Connect to the provider first and save only if it answers"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Register an AI provider. The API key, when supplied, is encrypted before storage and never
    returned in responses.

    An admin registers the instance's providers. Anyone may register a personal key (``personal``
    is implied for non-admins) when the admin allows it: the type must be one the admin permits,
    never ``claude_code``, and the endpoint must not resolve to a private address unless the admin
    allows those. With ``test`` set, the provider is contacted before anything is written, so a
    key that can't answer is never saved.
    """
    personal = body.personal or user.role != "admin"
    if personal:
        await _check_personal_policy(db, body.provider_type, body.base_url)
    elif body.provider_type == "claude_code":
        raise AppError(
            code="provider_type_not_allowed",
            message="Claude Code is set up by the instance at startup and can't be added here.",
            status_code=400,
        )

    provider = AIProvider(
        name=body.name,
        provider_type=body.provider_type,
        base_url=body.base_url,
        api_key_encrypted=encrypt_value(body.api_key) if body.api_key else None,
        config=body.config,
        user_id=user.id if personal else None,
    )

    if test:
        # Not in the session yet: a failure here leaves nothing behind.
        try:
            instance = _get_provider_instance(provider)
            if not await instance.check_health():
                raise RuntimeError("health check failed")
            provider.models = await instance.list_models()
        except Exception as e:
            raise AppError(
                code="provider_unreachable",
                message=f"The provider answered: {e}. Check the key and the address and try again. Nothing was saved.",
                status_code=400,
            ) from e

    db.add(provider)
    await db.flush()
    await db.refresh(provider)
    return provider


@router.put("/{provider_id}", response_model=AIProviderResponse)
async def update_provider(
    provider_id: uuid.UUID = Path(..., description="ID of the AI provider to update"),
    body: AIProviderUpdate = ...,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update an AI provider: the instance's (admin only), the caller's own key, or any personal key
    for the admin. Only the fields present in the body are changed; a non-empty api_key is
    re-encrypted before storage."""
    provider = _owned(await _load(db, provider_id), user)

    if body.name is not None:
        provider.name = body.name
    if body.base_url is not None:
        if not body.base_url.strip() and provider.provider_type in ("ollama", "openai_compatible"):
            raise AppError(
                code="validation_error", message="base_url cannot be empty for this provider type", status_code=400
            )
        if provider.is_personal:
            problem = await _personal_url_problem(db, body.base_url)
            if problem:
                raise AppError(code="endpoint_not_allowed", message=problem, status_code=400)
        provider.base_url = body.base_url
    if body.api_key is not None:
        provider.api_key_encrypted = encrypt_value(body.api_key) if body.api_key else None
    if body.is_active is not None:
        provider.is_active = body.is_active
    if body.config is not None:
        provider.config = body.config

    db.add(provider)
    await db.flush()
    await db.refresh(provider)
    return provider


@router.post("/{provider_id}/resume", response_model=AIProviderResponse)
async def resume_provider(
    provider_id: uuid.UUID = Path(..., description="ID of the paused AI provider to resume"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Clear paused_until on a provider — undoes a quota-triggered auto-pause. The instance's
    providers are the admin's to resume; a personal key is its owner's, or the admin's."""
    provider = _owned(await _load(db, provider_id), user)
    provider.paused_until = None
    provider.paused_reason = None
    db.add(provider)
    await db.flush()
    await db.refresh(provider)
    return provider


@router.delete("/{provider_id}", status_code=204)
async def delete_provider(
    provider_id: uuid.UUID = Path(..., description="ID of the AI provider to delete"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete an AI provider. The instance's providers and anyone's personal key are the admin's
    to delete; a person deletes their own. Routes on the key go with it."""
    provider = await _load(db, provider_id)
    if provider.user_id is None or provider.user_id != user.id:
        if user.role != "admin":
            # A site provider is forbidden to a non-admin; someone else's key is invisible.
            if provider.user_id is None:
                raise AppError(code="forbidden", message="Admin access required", status_code=403)
            raise _not_found()
    # Results outlive the provider (ON DELETE SET NULL keeps provider_name
    # and key_owner_id on them); assignments and routes cascade.
    await db.delete(provider)
    await db.flush()


@router.post("/{provider_id}/test", response_model=AIProviderTestResult)
async def test_provider(
    provider_id: uuid.UUID = Path(..., description="ID of the AI provider to test"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run a connectivity check against the provider: health check, then model listing. The
    instance's providers are the admin's to test; a personal key is its owner's alone. On success
    the fetched model list is cached on the provider row. Failures are returned as success=false
    rather than an error status."""
    provider = _owned(await _load(db, provider_id), user, use=True)
    problem = await _usable_personal_endpoint(db, provider)
    if problem:
        return AIProviderTestResult(success=False, message=problem)

    try:
        instance = _get_provider_instance(provider)
        healthy = await instance.check_health()
        if not healthy:
            return AIProviderTestResult(success=False, message="Provider health check failed")

        models = await instance.list_models()
        # Cache models
        provider.models = models
        db.add(provider)
        await db.flush()

        return AIProviderTestResult(success=True, message="Connected", models=models)
    except Exception as e:
        return AIProviderTestResult(success=False, message=str(e))


@router.post("/{provider_id}/commission", response_model=AIProviderCommissionResult)
async def commission_provider(
    provider_id: uuid.UUID = Path(..., description="ID of the AI provider to put to work"),
    take_over: bool = Query(
        False,
        description="Also re-point tasks already assigned to another provider, not just unassigned ones",
    ),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Test a provider and route the AI tasks at it, in one admin action (admin only).

    Registering a provider does not configure AI: work runs off `ai_task_assignments`,
    and nothing writes those rows except the startup seeder and a per-task PUT. The
    seeder only fills gaps, and only from a provider that already existed when the
    API booted — so a provider added through the UI did nothing at all until the
    next restart. This closes that gap.

    The connectivity check runs first and a failure stops there: assigning 30 tasks
    to a host that cannot be reached would just move the error somewhere harder to
    find. On success the live model list is cached and each assignment gets a model
    this provider actually serves. Agentic tasks are left alone when the provider
    cannot run tools, and are named in the response.

    Only the instance's providers can be commissioned: a personal key answers its
    owner's tasks through their routes, never the site's assignments.
    """
    provider = await _load(db, provider_id)
    if provider.is_personal:
        raise AppError(
            code="personal_provider",
            message="A personal key can't run the instance's tasks; route it from Settings > My AI instead.",
            status_code=400,
        )

    instance = _get_provider_instance(provider)
    try:
        if not await instance.check_health():
            return AIProviderCommissionResult(success=False, message="Provider health check failed")
        models = await instance.list_models()
    except Exception as e:
        return AIProviderCommissionResult(success=False, message=str(e))

    provider.models = models
    provider.is_active = True
    db.add(provider)
    await db.flush()

    problem = model_choice_problem(provider)
    if problem:
        return AIProviderCommissionResult(success=False, message=problem, models=models)

    routing = await route_tasks_to_provider(db, provider, created_by=user.id, take_over=take_over)

    return AIProviderCommissionResult(
        success=True,
        message="Connected",
        models=models,
        model=routing.model,
        tasks_assigned=len(routing.assigned),
        tasks_reassigned=len(routing.reassigned),
        tasks_skipped_agentic=routing.skipped_agentic,
    )


@router.get("/{provider_id}/models", response_model=list[str])
async def list_provider_models(
    provider_id: uuid.UUID = Path(..., description="ID of the AI provider to list models for"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the model names available on a provider. Returns the cached list when present;
    otherwise fetches from the provider and caches the result. The instance's providers are the
    admin's to list; a personal key is its owner's alone, since answering means calling the
    provider with that key."""
    provider = _owned(await _load(db, provider_id), user, use=True)
    problem = await _usable_personal_endpoint(db, provider)
    if problem:
        raise AppError(code="endpoint_not_allowed", message=problem, status_code=400)

    # Return cached models, or fetch fresh
    if provider.models:
        return provider.models

    try:
        instance = _get_provider_instance(provider)
        models = await instance.list_models()
    except Exception as e:
        raise AppError(code="provider_error", message=str(e), status_code=400) from e
    provider.models = models
    db.add(provider)
    await db.flush()
    return models
