"""AI Conversations API — server-side persistence for AI copilot chat threads.

All queries are scoped by the authenticated user; a user can only see or
modify their own conversations.
"""

import uuid

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.core.utils import now_iso
from app.database import get_db
from app.models.ai_conversation import AIConversation
from app.models.user import User
from app.schemas.ai_conversation import (
    AIConversation as AIConversationSchema,
)
from app.schemas.ai_conversation import (
    AIConversationCreate,
    AIConversationSummary,
    AIConversationUpdate,
    MessageIn,
)

router = APIRouter()

VALID_SCOPE_TYPES = {"entry", "multi_entry", "entity", "global"}


def _stamp_messages(messages: list[MessageIn]) -> list[dict]:
    """Convert incoming messages to stored dicts, stamping created_at server-side."""
    stamped = []
    for m in messages:
        msg: dict = {"role": m.role, "content": m.content, "created_at": now_iso()}
        if m.meta is not None:
            msg["meta"] = m.meta
        stamped.append(msg)
    return stamped


def _derive_title(messages: list[MessageIn]) -> str | None:
    for m in messages:
        if m.role == "user" and m.content.strip():
            text = m.content.strip()
            return text[:57] + "..." if len(text) > 60 else text
    return None


async def _get_owned(conversation_id: uuid.UUID, user: User, db: AsyncSession) -> AIConversation:
    result = await db.execute(
        select(AIConversation).where(
            AIConversation.id == conversation_id,
            AIConversation.user_id == user.id,
        )
    )
    conv = result.scalar_one_or_none()
    if conv is None:
        raise AppError(code="not_found", message="Conversation not found", status_code=404)
    return conv


@router.get("/", response_model=PaginatedResponse[AIConversationSummary])
async def list_conversations(
    scope_type: str | None = Query(None, description="Filter by scope kind: entry, multi_entry, entity, or global"),
    scope_id: str | None = Query(None, description="Filter by scope identifier (e.g. the entry or entity ID)"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of conversations to return"),
    offset: int = Query(0, ge=0, description="Number of conversations to skip (pagination offset)"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[AIConversationSummary]:
    """List the authenticated user's AI copilot conversations as summaries (no message bodies),
    most recently updated first. Optionally filtered by scope_type and/or scope_id."""
    filters = [AIConversation.user_id == user.id]
    if scope_type is not None:
        filters.append(AIConversation.scope_type == scope_type)
    if scope_id is not None:
        filters.append(AIConversation.scope_id == scope_id)

    total = (await db.execute(select(func.count()).select_from(AIConversation).where(*filters))).scalar_one()

    result = await db.execute(
        select(AIConversation).where(*filters).order_by(AIConversation.updated_at.desc()).limit(limit).offset(offset)
    )
    rows = result.scalars().all()

    items = [
        AIConversationSummary(
            id=c.id,
            title=c.title,
            scope_type=c.scope_type,
            scope_id=c.scope_id,
            message_count=len(c.messages or []),
            updated_at=c.updated_at,
        )
        for c in rows
    ]
    return PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=offset + len(items) < total,
    )


@router.post("/", response_model=AIConversationSchema)
async def create_conversation(
    body: AIConversationCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AIConversation:
    """Create a copilot conversation owned by the authenticated user. Message timestamps are
    stamped server-side, and when no title is given one is derived from the first user message."""
    if body.scope_type not in VALID_SCOPE_TYPES:
        raise AppError(
            code="invalid_scope_type",
            message=f"Invalid scope_type: {body.scope_type}",
            status_code=400,
        )

    incoming = body.messages or []
    title = body.title
    if not title and incoming:
        title = _derive_title(incoming)

    conv = AIConversation(
        user_id=user.id,
        title=title,
        scope_type=body.scope_type,
        scope_id=body.scope_id,
        entry_ids=body.entry_ids,
        messages=_stamp_messages(incoming),
    )
    db.add(conv)
    await db.commit()
    await db.refresh(conv)
    return conv


@router.get("/{conversation_id}", response_model=AIConversationSchema)
async def get_conversation(
    conversation_id: uuid.UUID = Path(..., description="ID of the conversation to fetch"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AIConversation:
    """Get one of the authenticated user's conversations, including its full message history."""
    return await _get_owned(conversation_id, user, db)


@router.patch("/{conversation_id}", response_model=AIConversationSchema)
async def update_conversation(
    conversation_id: uuid.UUID = Path(..., description="ID of the conversation to update"),
    body: AIConversationUpdate = ...,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AIConversation:
    """Rename a conversation and/or append messages to it. Appended messages are stamped with a
    server-side created_at; existing messages are never modified."""
    conv = await _get_owned(conversation_id, user, db)

    if body.title is not None:
        conv.title = body.title

    if body.append_messages:
        # Reassign the list so SQLAlchemy detects the JSONB mutation.
        conv.messages = (conv.messages or []) + _stamp_messages(body.append_messages)
        flag_modified(conv, "messages")

    await db.commit()
    await db.refresh(conv)
    return conv


@router.delete("/{conversation_id}", status_code=204)
async def delete_conversation(
    conversation_id: uuid.UUID = Path(..., description="ID of the conversation to delete"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Permanently delete one of the authenticated user's conversations."""
    conv = await _get_owned(conversation_id, user, db)
    await db.delete(conv)
    await db.commit()


@router.post("/{conversation_id}/share")
async def share_conversation(
    conversation_id: uuid.UUID = Path(..., description="ID of the conversation to share"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create (or return the existing) read-only public share link for a conversation."""
    conv = await _get_owned(conversation_id, user, db)
    if not conv.share_token:
        conv.share_token = uuid.uuid4().hex
        await db.commit()
        await db.refresh(conv)
    return {"share_token": conv.share_token, "path": f"/shared/copilot/{conv.share_token}"}


@router.delete("/{conversation_id}/share", status_code=204)
async def unshare_conversation(
    conversation_id: uuid.UUID = Path(..., description="ID of the conversation to unshare"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Revoke a conversation's public share link."""
    conv = await _get_owned(conversation_id, user, db)
    if conv.share_token:
        conv.share_token = None
        await db.commit()
