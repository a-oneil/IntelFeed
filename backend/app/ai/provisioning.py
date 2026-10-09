"""Turning a provider row into a working AI configuration.

Registering a provider is not configuring AI. Work only runs when a task has a
row in ``ai_task_assignments`` naming a provider *and* a model, and nothing
creates those rows except the startup seeder and an explicit per-task PUT. So an
admin could add an Ollama host, be told it saved, and have the instance do zero
AI — the onboarding wizard's AI step did exactly that.

The startup seeder can't cover it either: it only fills assignments that are
missing, and it only reaches for a non-``claude_code`` provider that already
existed *when the API booted*. A provider added afterwards gets nothing until
the next restart, which a Docker install doesn't do after onboarding.

This module holds the two pieces both paths need: choosing a model name the
provider actually serves, and routing tasks at it.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.capabilities import provider_type_supports_tools, task_requires_tools
from app.ai.prompts.defaults import (
    DEFAULT_ASSIGNMENT_CONFIGS,
    DEFAULT_MODEL_ASSIGNMENTS,
)
from app.models.ai_provider import AIProvider
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment


def usable_models(models: list[str] | None) -> list[str]:
    """The provider's models minus the ones that can't answer a prompt.

    Embedding models sit alongside chat models in an Ollama ``/api/tags`` listing
    (Story Threads needs one there), and picking one produces a task that fails
    on every call.
    """
    return [m for m in (models or []) if "embed" not in m.lower()]


def pick_model(preferred: str, available: list[str] | None) -> str:
    """Resolve the model name to assign, given what the provider actually serves.

    ``DEFAULT_MODEL_ASSIGNMENTS`` names Claude-family models, so on an Ollama
    host every one of them is a 404 waiting to happen. Fall back in order:
    the preferred name if the provider serves it, then a model whose id contains
    it (``"sonnet"`` → ``"claude-sonnet-4-6"``), then the first usable model.

    With no model list at all, keep the preferred name: an un-tested provider is
    no reason to invent a model, and the engine's error names the real problem.
    """
    models = usable_models(available)
    if not models or preferred in models:
        return preferred
    return next((m for m in models if preferred in m), models[0])


class TaskRouting:
    """What routing tasks at a provider did, in terms the UI can show.

    ``skipped_agentic`` is not a failure: an agentic task on a provider with no
    tool execution path produces tool-less output that *reads* like success —
    the entity merge task reporting merges it never applied. Those stay where
    they are, and saying so is the point.
    """

    def __init__(self) -> None:
        self.assigned: list[str] = []
        self.reassigned: list[str] = []
        self.skipped_agentic: list[str] = []
        self.model: str | None = None

    @property
    def total(self) -> int:
        return len(self.assigned) + len(self.reassigned)


async def route_tasks_to_provider(
    db: AsyncSession,
    provider: AIProvider,
    *,
    created_by: uuid.UUID | None,
    take_over: bool,
) -> TaskRouting:
    """Point every compatible system task at ``provider``.

    ``take_over=False`` only fills tasks that have no assignment, which is what a
    first-run install wants: nothing the operator set up by hand gets moved.
    ``take_over=True`` additionally re-points tasks already assigned elsewhere —
    the only way an instance whose tasks were seeded onto the startup CLI
    provider can be moved onto a real one without 30 clicks.

    Agentic tasks are never moved to a provider that cannot run tools, whichever
    mode this is in.
    """
    out = TaskRouting()

    tasks = (await db.execute(select(AITask).where(AITask.is_system.is_(True)))).scalars().all()
    existing = {a.task_id: a for a in (await db.execute(select(AITaskAssignment))).scalars().all()}
    supports_tools = provider_type_supports_tools(provider.provider_type)

    for task in tasks:
        preferred = DEFAULT_MODEL_ASSIGNMENTS.get(task.name)
        if preferred is None or task.is_deprecated:
            continue
        if task_requires_tools(task.name) and not supports_tools:
            out.skipped_agentic.append(task.name)
            continue

        model_name = pick_model(preferred, provider.models)
        out.model = out.model or model_name
        assignment = existing.get(task.id)

        if assignment is None:
            db.add(
                AITaskAssignment(
                    created_by=created_by,
                    task_id=task.id,
                    provider_id=provider.id,
                    model_name=model_name,
                    is_enabled=True,
                    config=dict(DEFAULT_ASSIGNMENT_CONFIGS.get(task.name) or {}),
                )
            )
            out.assigned.append(task.name)
        elif take_over and assignment.provider_id != provider.id:
            assignment.provider_id = provider.id
            assignment.model_name = model_name
            assignment.is_enabled = True
            out.reassigned.append(task.name)

    await db.flush()
    return out
