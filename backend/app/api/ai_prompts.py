"""AI Prompt Template management API routes."""

import uuid

import jinja2
from fastapi import APIRouter, Depends, Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_admin_user, get_current_user
from app.database import get_db
from app.models.ai_prompt_template import AIPromptTemplate
from app.models.ai_task import AITask
from app.models.entry import Entry
from app.models.user import User
from app.schemas.ai import (
    AIPromptPreviewRequest,
    AIPromptPreviewResponse,
    AIPromptTemplateResponse,
    AIPromptTemplateUpdate,
)

router = APIRouter()


@router.get("", response_model=list[AIPromptTemplateResponse])
async def list_prompts(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List every stored prompt template override across all tasks (all versions, newest first
    within each task). Overrides are per-task and apply platform-wide."""
    # Overrides are per-task (shared by everyone), so return all of them.
    result = await db.execute(
        select(AIPromptTemplate).order_by(AIPromptTemplate.task_id, AIPromptTemplate.version.desc())
    )
    return result.scalars().all()


@router.get("/{task_id}", response_model=AIPromptTemplateResponse)
async def get_active_prompt(
    task_id: uuid.UUID = Path(..., description="ID of the AI task whose active prompt to fetch"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the prompt template currently in effect for a task: the newest active override, or a
    synthesized version-0 response built from the task's shipped defaults when no override exists."""
    # Newest active template for the task, regardless of author — prompt
    # overrides apply platform-wide (workers included).
    result = await db.execute(
        select(AIPromptTemplate)
        .where(
            AIPromptTemplate.task_id == task_id,
            AIPromptTemplate.is_active == True,  # noqa: E712
        )
        .order_by(AIPromptTemplate.version.desc(), AIPromptTemplate.created_at.desc())
        .limit(1)
    )
    prompt = result.scalars().first()
    if prompt:
        return prompt

    # Fall back to task default
    task_result = await db.execute(select(AITask).where(AITask.id == task_id))
    task = task_result.scalar_one_or_none()
    if not task:
        raise AppError(code="not_found", message="Task not found", status_code=404)

    return AIPromptTemplateResponse(
        id=uuid.uuid4(),
        task_id=task.id,
        created_by=None,
        name=f"{task.display_name} Default",
        template_text=task.default_prompt_template,
        system_text=task.default_system_template,
        variables=["entry"],
        is_active=True,
        version=0,
        created_at=task.created_at,
    )


@router.put("/{task_id}", response_model=AIPromptTemplateResponse)
async def update_prompt(
    task_id: uuid.UUID = Path(..., description="ID of the AI task whose prompt to override"),
    body: AIPromptTemplateUpdate = ...,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Save a new prompt override for a task. Deactivates all previous versions and creates a new
    active row with an incremented version number; the override applies platform-wide (workers
    included). An empty system_text clears the system block; omitting it keeps the task default."""
    # Deactivate every active prompt for this task (any author) — the new
    # version becomes the task-wide override. Version counter spans all
    # historical rows so restores after a reset keep incrementing.
    result = await db.execute(select(AIPromptTemplate).where(AIPromptTemplate.task_id == task_id))
    max_version = 0
    for p in result.scalars().all():
        if p.is_active:
            p.is_active = False
        max_version = max(max_version, p.version)

    # Get task for default name
    task_result = await db.execute(select(AITask).where(AITask.id == task_id))
    task = task_result.scalar_one_or_none()
    if not task:
        raise AppError(code="not_found", message="Task not found", status_code=404)

    # Create new version. `system_text=None` clears the system block; an
    # explicit empty string also clears it. Anything else is stored as-is.
    if body.system_text is None:
        system_text = task.default_system_template
    elif body.system_text == "":
        system_text = None
    else:
        system_text = body.system_text

    new_prompt = AIPromptTemplate(
        task_id=task_id,
        created_by=user.id,
        name=body.name or f"{task.display_name} v{max_version + 1}",
        template_text=body.template_text or task.default_prompt_template,
        system_text=system_text,
        variables=["entry"],
        is_active=True,
        version=max_version + 1,
    )
    db.add(new_prompt)
    await db.flush()
    await db.refresh(new_prompt)
    return new_prompt


@router.post("/{task_id}/reset", response_model=AIPromptTemplateResponse)
async def reset_prompt(
    task_id: uuid.UUID = Path(..., description="ID of the AI task whose prompt overrides to reset"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate every stored prompt override for a task so its shipped defaults apply again.
    History rows are kept (inactive) and the resulting default prompt is returned."""
    # Deactivate all prompts for this task (any author) so the task's shipped
    # defaults become authoritative again.
    result = await db.execute(select(AIPromptTemplate).where(AIPromptTemplate.task_id == task_id))
    for p in result.scalars().all():
        p.is_active = False

    await db.flush()

    # Return the task default
    return await get_active_prompt(task_id, user, db)


# Representative placeholders for tasks that aren't entry-scoped, so the
# rendered preview is legible without hitting the DB for real entities.
_PLACEHOLDER_VARIABLES: dict = {
    "question": "What TTPs does this describe?",
    "conversation_history": [],
    "text": "Sample selected text from an article for analysis.",
    "ttps": [{"technique_id": "T1566", "name": "Phishing"}],
    "existing_ttps": [{"technique_id": "T1059", "name": "Command and Scripting Interpreter"}],
    "existing_cves": [{"cve_id": "CVE-2024-0001", "severity": "critical"}],
    "threat_actor_profiles": [{"name": "APT29", "aliases": ["Cozy Bear"]}],
    "malware_profiles": [{"name": "Cobalt Strike"}],
    "existing_detection_rules": [],
    "related_articles": [{"title": "Related report", "url": "https://example.com/a"}],
    "rule_type": "sigma",
    "rule_formats": ["sigma", "spl"],
    "telemetry_sources": ["process_creation", "network"],
    "focus": "lateral movement",
    "entries": [
        {"title": "First sample article", "summary": "Summary of the first article."},
        {"title": "Second sample article", "summary": "Summary of the second article."},
    ],
    "entry_count": 2,
    "date_label": "2026-07-08",
    "scope_label": "Ransomware feeds",
    "fp_context": "Known-benign admin tooling in this environment.",
    "entity": {
        "type": "threat_actor",
        "name": "APT29",
        "aliases": ["Cozy Bear", "Nobelium"],
        "description": "A representative sample entity for template preview.",
    },
}


def _sample_entry_dict(entry: Entry) -> dict:
    """Build the same `entry` variable shape the engine/ask-agent uses."""
    return {
        "title": entry.title,
        "content_text": entry.content_text or "",
        "content_html": entry.content_html,
        "content": entry.content_text or entry.content_html or entry.summary or "",
        "summary": entry.summary or "",
        "author": entry.author,
        "url": entry.url,
        "published_at": str(entry.published_at) if entry.published_at else "",
        "feed_title": "",
    }


async def _build_preview_variables(
    db: AsyncSession,
    entry_id: uuid.UUID | None = None,
    use_sample: bool = False,
) -> tuple[dict, str]:
    """Return (variables, sample_source). Uses a real entry when one exists
    (a specific one when `entry_id` is given, else the most recent) so
    entry-scoped templates preview against live data, plus representative
    placeholders for every other catalog variable. `use_sample` forces the
    built-in placeholder entry."""
    variables: dict = dict(_PLACEHOLDER_VARIABLES)

    if not use_sample:
        query = select(Entry)
        if entry_id is not None:
            query = query.where(Entry.id == entry_id)
        else:
            query = query.order_by(Entry.created_at.desc()).limit(1)
        result = await db.execute(query)
        entry = result.scalar_one_or_none()
        if entry_id is not None and entry is None:
            raise AppError(code="not_found", message="Entry not found", status_code=404)
        if entry:
            variables["entry"] = _sample_entry_dict(entry)
            return variables, "entry"

    variables["entry"] = {
        "title": "Sample article title",
        "content_text": "Sample article body used for template preview.",
        "content_html": "<p>Sample article body used for template preview.</p>",
        "content": "Sample article body used for template preview.",
        "summary": "A short sample summary.",
        "author": "Jane Analyst",
        "url": "https://example.com/sample-article",
        "published_at": "2026-07-08 12:00:00+00:00",
        "feed_title": "Sample Feed",
    }
    return variables, "placeholder"


@router.post("/{task_id}/preview", response_model=AIPromptPreviewResponse)
async def preview_prompt(
    task_id: uuid.UUID = Path(..., description="ID of the AI task the templates belong to"),
    body: AIPromptPreviewRequest = ...,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Render the CURRENT editor's system + user templates against sample
    variables so the analyst sees the resolved prompt (and Jinja lint errors)
    without invoking the LLM. Templates are taken from the request body so
    unsaved edits preview too."""
    # Confirm the task exists (keeps behaviour consistent with the other routes).
    task_result = await db.execute(select(AITask).where(AITask.id == task_id))
    if task_result.scalar_one_or_none() is None:
        raise AppError(code="not_found", message="Task not found", status_code=404)

    variables, sample_source = await _build_preview_variables(db, entry_id=body.entry_id, use_sample=body.use_sample)

    from app.ai.engine import render_prompt

    def _render(text: str | None) -> str | None:
        if not text:
            return None
        # Match the engine's non-strict sandboxed rendering: undefined vars become "".
        return render_prompt(text, variables)

    try:
        rendered_system = _render(body.system_text)
        rendered_user = _render(body.template_text)
    except jinja2.TemplateError as e:
        line = getattr(e, "lineno", None)
        return AIPromptPreviewResponse(
            sample_source=sample_source,
            error=str(e),
            line=line,
        )

    return AIPromptPreviewResponse(
        rendered_system=rendered_system,
        rendered_user=rendered_user,
        sample_source=sample_source,
    )


@router.get("/{task_id}/history", response_model=list[AIPromptTemplateResponse])
async def get_prompt_history(
    task_id: uuid.UUID = Path(..., description="ID of the AI task whose prompt history to fetch"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List every stored prompt override version for a task, newest first (active and inactive)."""
    result = await db.execute(
        select(AIPromptTemplate).where(AIPromptTemplate.task_id == task_id).order_by(AIPromptTemplate.version.desc())
    )
    return result.scalars().all()
