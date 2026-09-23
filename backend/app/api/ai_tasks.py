"""AI Task and Assignment management API routes."""

import uuid

import jsonschema
from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.capabilities import provider_type_supports_tools, task_requires_tools
from app.core.exceptions import AppError
from app.core.security import get_admin_user, get_current_user
from app.database import get_db
from app.models.ai_provider import AIProvider
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment
from app.models.user import User
from app.schemas.ai import (
    AITaskAssignmentCreate,
    AITaskAssignmentResponse,
    AITaskCreate,
    AITaskResponse,
    AITaskUpdate,
)

router = APIRouter()


@router.get("", response_model=list[AITaskResponse])
async def list_tasks(
    include_deprecated: bool = Query(False, description="Include tasks flagged as deprecated in the listing"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List AI tasks (system and custom), ordered by category then name. Deprecated tasks are
    hidden unless include_deprecated is set."""
    query = select(AITask).order_by(AITask.category, AITask.name)
    if not include_deprecated:
        query = query.where(AITask.is_deprecated == False)  # noqa: E712
    result = await db.execute(query)
    return result.scalars().all()


@router.post("", response_model=AITaskResponse, status_code=201)
async def create_custom_task(
    body: AITaskCreate,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a custom (non-system) AI task. Task names must be unique (409 on conflict), and a
    supplied output_schema must be a valid JSON Schema object with at least one top-level property."""
    # Check for duplicate name
    existing = await db.execute(select(AITask).where(AITask.name == body.name))
    if existing.scalar_one_or_none():
        raise AppError(code="conflict", message="Task name already exists", status_code=409)

    if body.output_schema is not None:
        _validate_output_schema(body.output_schema)

    task = AITask(
        name=body.name,
        display_name=body.display_name,
        description=body.description,
        category=body.category or "custom",
        default_prompt_template=body.default_prompt_template,
        default_system_template=body.default_system_template,
        output_schema=body.output_schema,
        variables=body.variables,
        is_system=False,
    )
    db.add(task)
    await db.flush()
    await db.refresh(task)
    return task


def _validate_output_schema(schema: dict) -> None:
    """Reject schemas that would break structured-output providers."""
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as e:
        raise AppError(
            code="invalid_schema",
            message=f"Not a valid JSON Schema: {e.message}",
            status_code=400,
        ) from e

    if schema.get("type") != "object":
        raise AppError(
            code="invalid_schema",
            message='Output schema must have "type": "object" at the top level',
            status_code=400,
        )
    properties = schema.get("properties")
    if not isinstance(properties, dict) or not properties:
        raise AppError(
            code="invalid_schema",
            message='Output schema must declare at least one top-level property under "properties"',
            status_code=400,
        )
    required = schema.get("required")
    if required is not None:
        if not isinstance(required, list) or not all(isinstance(f, str) for f in required):
            raise AppError(
                code="invalid_schema",
                message='"required" must be a list of property names',
                status_code=400,
            )
        missing_props = [f for f in required if f not in properties]
        if missing_props:
            raise AppError(
                code="invalid_schema",
                message=f"Required fields not declared in properties: {', '.join(missing_props)}",
                status_code=400,
            )


def _validate_output_schema_override(task: AITask, override: dict) -> None:
    """Reject overrides that would break the pipeline code parsing this task."""
    _validate_output_schema(override)

    # Tasks whose defaults mark fields required are parsed by pipeline code
    # (one-pass extraction, link validation, entity maintenance). Dropping
    # one of those fields would break the worker that reads the result.
    default_required = set((task.output_schema or {}).get("required") or [])
    dropped = default_required - set(override.get("required") or [])
    if dropped:
        raise AppError(
            code="invalid_schema",
            message=(
                "This task's output is parsed by pipeline code; these fields must stay "
                f"required: {', '.join(sorted(dropped))}"
            ),
            status_code=400,
        )


@router.patch("/{task_id}", response_model=AITaskResponse)
async def update_task(
    task_id: uuid.UUID = Path(..., description="ID of the AI task to update"),
    body: AITaskUpdate = ...,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Update reader AI-panel presentation fields and the output schema override."""
    result = await db.execute(select(AITask).where(AITask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise AppError(code="not_found", message="Task not found", status_code=404)

    updates = body.model_dump(exclude_unset=True)
    if "category" in updates and task.is_system:
        raise AppError(
            code="forbidden",
            message="System task categories cannot be changed",
            status_code=403,
        )
    if "output_schema" in updates:
        # Custom tasks own their schema outright; system defaults are code-owned
        # (the startup seeder would clobber an edit on the next deploy anyway).
        if task.is_system:
            raise AppError(
                code="forbidden",
                message="System task default schemas cannot be edited; set an override instead",
                status_code=403,
            )
        schema = updates["output_schema"]
        if schema is not None:
            _validate_output_schema(schema)
    if "output_schema_override" in updates:
        override = updates["output_schema_override"]
        if override is not None:
            if task.output_schema is None:
                raise AppError(
                    code="invalid_schema",
                    message="This task returns free-form text; there is no output schema to override",
                    status_code=400,
                )
            _validate_output_schema_override(task, override)
    for field, value in updates.items():
        setattr(task, field, value)

    await db.flush()
    await db.refresh(task)
    return task


@router.delete("/{task_id}", status_code=204)
async def delete_custom_task(
    task_id: uuid.UUID = Path(..., description="ID of the custom AI task to delete"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a custom AI task. System tasks cannot be deleted (403)."""
    result = await db.execute(select(AITask).where(AITask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise AppError(code="not_found", message="Task not found", status_code=404)
    if task.is_system:
        raise AppError(code="forbidden", message="Cannot delete system tasks", status_code=403)
    await db.delete(task)
    await db.flush()


@router.get("/assignments/all", response_model=list[AITaskAssignmentResponse])
async def get_all_task_assignments(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all task assignments in a single request."""
    result = await db.execute(
        select(AITaskAssignment, AITask.name, AIProvider.name)
        .join(AITask, AITask.id == AITaskAssignment.task_id)
        .join(AIProvider, AIProvider.id == AITaskAssignment.provider_id)
    )
    return [
        AITaskAssignmentResponse(
            id=a.id,
            created_by=a.created_by,
            task_id=a.task_id,
            provider_id=a.provider_id,
            model_name=a.model_name,
            is_enabled=a.is_enabled,
            config=a.config,
            task_name=task_name,
            provider_name=provider_name,
        )
        for a, task_name, provider_name in result.all()
    ]


@router.get("/{task_id}/assignments", response_model=AITaskAssignmentResponse | None)
async def get_task_assignment(
    task_id: uuid.UUID = Path(..., description="ID of the AI task to fetch the assignment for"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the provider/model assignment for a task, or null when the task has no assignment yet."""
    result = await db.execute(
        select(AITaskAssignment, AITask.name, AIProvider.name)
        .join(AITask, AITask.id == AITaskAssignment.task_id)
        .join(AIProvider, AIProvider.id == AITaskAssignment.provider_id)
        .where(
            AITaskAssignment.task_id == task_id,
        )
    )
    row = result.first()
    if not row:
        return None

    assignment, task_name, provider_name = row
    return AITaskAssignmentResponse(
        id=assignment.id,
        created_by=assignment.created_by,
        task_id=assignment.task_id,
        provider_id=assignment.provider_id,
        model_name=assignment.model_name,
        is_enabled=assignment.is_enabled,
        config=assignment.config,
        task_name=task_name,
        provider_name=provider_name,
    )


@router.put("/{task_id}/assignments", response_model=AITaskAssignmentResponse)
async def upsert_task_assignment(
    task_id: uuid.UUID = Path(..., description="ID of the AI task to assign a provider/model to"),
    body: AITaskAssignmentCreate = ...,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Create or replace the provider/model assignment for a task. Rejects assigning an agentic
    (tool-requiring) task to a provider type that cannot run tools. Omitting config leaves any
    stored assignment config untouched."""
    # Verify task exists
    task_result = await db.execute(select(AITask).where(AITask.id == task_id))
    task = task_result.scalar_one_or_none()
    if not task:
        raise AppError(code="not_found", message="Task not found", status_code=404)

    # Verify provider exists
    prov_result = await db.execute(select(AIProvider).where(AIProvider.id == body.provider_id))
    provider = prov_result.scalar_one_or_none()
    if not provider:
        raise AppError(code="not_found", message="Provider not found", status_code=404)

    if task_requires_tools(task.name) and not provider_type_supports_tools(provider.provider_type):
        raise AppError(
            code="provider_incompatible",
            message=(
                f"'{task.display_name}' is agentic and requires a tool-capable provider "
                f"(Claude Code CLI); '{provider.name}' ({provider.provider_type}) cannot run tools."
            ),
            status_code=400,
        )

    # Upsert
    result = await db.execute(
        select(AITaskAssignment).where(
            AITaskAssignment.task_id == task_id,
        )
    )
    assignment = result.scalar_one_or_none()

    if assignment:
        assignment.provider_id = body.provider_id
        assignment.model_name = body.model_name
        assignment.is_enabled = body.is_enabled
        if body.config is not None:
            assignment.config = body.config
    else:
        assignment = AITaskAssignment(
            created_by=user.id,
            task_id=task_id,
            provider_id=body.provider_id,
            model_name=body.model_name,
            is_enabled=body.is_enabled,
            config=body.config or {},
        )
        db.add(assignment)

    await db.flush()
    await db.refresh(assignment)

    return AITaskAssignmentResponse(
        id=assignment.id,
        created_by=assignment.created_by,
        task_id=assignment.task_id,
        provider_id=assignment.provider_id,
        model_name=assignment.model_name,
        is_enabled=assignment.is_enabled,
        config=assignment.config,
        task_name=task.name,
        provider_name=provider.name,
    )
