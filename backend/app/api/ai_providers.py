"""AI Provider management API routes."""

import uuid

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.engine import _get_provider_instance as build_provider_instance
from app.ai.providers.base import AIProvider as AIProviderInterface
from app.ai.provisioning import route_tasks_to_provider
from app.core.encryption import encrypt_value
from app.core.exceptions import AppError
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

router = APIRouter()


def _get_provider_instance(provider: AIProvider) -> AIProviderInterface:
    # Shared engine factory — routes claude / claude_code / ollama by provider_type.
    return build_provider_instance(provider)


@router.get("", response_model=list[AIProviderResponse])
async def list_providers(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all configured AI providers, ordered by name."""
    result = await db.execute(select(AIProvider).order_by(AIProvider.name))
    return result.scalars().all()


@router.post("", response_model=AIProviderResponse, status_code=201)
async def create_provider(
    body: AIProviderCreate,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Register a new AI provider (admin only). The API key, when supplied, is encrypted before storage
    and never returned in responses."""
    provider = AIProvider(
        name=body.name,
        provider_type=body.provider_type,
        base_url=body.base_url,
        api_key_encrypted=encrypt_value(body.api_key) if body.api_key else None,
        config=body.config,
    )
    db.add(provider)
    await db.flush()
    await db.refresh(provider)
    return provider


@router.put("/{provider_id}", response_model=AIProviderResponse)
async def update_provider(
    provider_id: uuid.UUID = Path(..., description="ID of the AI provider to update"),
    body: AIProviderUpdate = ...,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Update an AI provider (admin only). Only the fields present in the body are changed;
    a non-empty api_key is re-encrypted before storage."""
    result = await db.execute(select(AIProvider).where(AIProvider.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise AppError(code="not_found", message="Provider not found", status_code=404)

    if body.name is not None:
        provider.name = body.name
    if body.base_url is not None:
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
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Clear paused_until on a provider — undoes a quota-triggered auto-pause."""
    result = await db.execute(select(AIProvider).where(AIProvider.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise AppError(code="not_found", message="Provider not found", status_code=404)
    provider.paused_until = None
    provider.paused_reason = None
    db.add(provider)
    await db.flush()
    await db.refresh(provider)
    return provider


@router.delete("/{provider_id}", status_code=204)
async def delete_provider(
    provider_id: uuid.UUID = Path(..., description="ID of the AI provider to delete"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete an AI provider (admin only)."""
    result = await db.execute(select(AIProvider).where(AIProvider.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise AppError(code="not_found", message="Provider not found", status_code=404)
    await db.delete(provider)
    await db.flush()


@router.post("/{provider_id}/test", response_model=AIProviderTestResult)
async def test_provider(
    provider_id: uuid.UUID = Path(..., description="ID of the AI provider to test"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Run a connectivity check against the provider (admin only): health check, then model listing.
    On success the fetched model list is cached on the provider row. Failures are returned as
    success=false rather than an error status."""
    result = await db.execute(select(AIProvider).where(AIProvider.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise AppError(code="not_found", message="Provider not found", status_code=404)

    instance = _get_provider_instance(provider)
    try:
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
    """
    result = await db.execute(select(AIProvider).where(AIProvider.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise AppError(code="not_found", message="Provider not found", status_code=404)

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
    otherwise fetches from the provider and caches the result."""
    result = await db.execute(select(AIProvider).where(AIProvider.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise AppError(code="not_found", message="Provider not found", status_code=404)

    # Return cached models, or fetch fresh
    if provider.models:
        return provider.models

    instance = _get_provider_instance(provider)
    models = await instance.list_models()
    provider.models = models
    db.add(provider)
    await db.flush()
    return models
