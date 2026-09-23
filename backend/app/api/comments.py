import re
import uuid

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.models.comment import Comment, CommentMention
from app.models.user import User
from app.schemas.comment import CommentCreate, CommentResponse, CommentUpdate

router = APIRouter()

MENTION_RE = re.compile(r"@(\w+)")


def _extract_mentions(content: str) -> list[str]:
    return MENTION_RE.findall(content)


@router.get("", response_model=PaginatedResponse[CommentResponse])
async def list_comments(
    commentable_type: str = Query(
        ..., description="Type of the commented object (e.g. entry, detection_rule, campaign, threat_actor)"
    ),
    commentable_id: uuid.UUID = Query(..., description="UUID of the commented object"),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of comments to return"),
    offset: int = Query(0, ge=0, description="Number of comments to skip for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List comments on one object, oldest first, with author usernames and per-comment reply counts."""
    base = select(Comment).where(
        Comment.commentable_type == commentable_type,
        Comment.commentable_id == commentable_id,
    )
    count_q = (
        select(func.count())
        .select_from(Comment)
        .where(
            Comment.commentable_type == commentable_type,
            Comment.commentable_id == commentable_id,
        )
    )
    total = (await db.execute(count_q)).scalar() or 0

    query = base.order_by(Comment.created_at.asc()).limit(limit).offset(offset)
    result = await db.execute(query)
    comments = result.scalars().all()

    # Fetch usernames
    user_ids = {c.user_id for c in comments}
    if user_ids:
        users_result = await db.execute(select(User.id, User.username).where(User.id.in_(user_ids)))
        user_map = {row.id: row.username for row in users_result.all()}
    else:
        user_map = {}

    # Count replies per comment
    comment_ids = [c.id for c in comments]
    reply_counts: dict[uuid.UUID, int] = {}
    if comment_ids:
        rc_result = await db.execute(
            select(Comment.parent_id, func.count())
            .where(Comment.parent_id.in_(comment_ids))
            .group_by(Comment.parent_id)
        )
        reply_counts = {row[0]: row[1] for row in rc_result.all()}

    items = [
        CommentResponse(
            id=c.id,
            commentable_type=c.commentable_type,
            commentable_id=c.commentable_id,
            user_id=c.user_id,
            content=c.content,
            parent_id=c.parent_id,
            created_at=c.created_at,
            updated_at=c.updated_at,
            username=user_map.get(c.user_id),
            reply_count=reply_counts.get(c.id, 0),
        )
        for c in comments
    ]

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.post("", response_model=CommentResponse, status_code=201)
async def create_comment(
    body: CommentCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a comment (or a reply, via parent_id) on an object.

    @username mentions in the content are extracted and recorded so mentioned
    users see the comment in their mentions feed. The parent comment, if given,
    must belong to the same object.
    """
    if body.parent_id:
        parent = await db.get(Comment, body.parent_id)
        if not parent:
            raise AppError(code="not_found", message="Parent comment not found", status_code=404)
        if parent.commentable_type != body.commentable_type or parent.commentable_id != body.commentable_id:
            raise AppError(code="invalid_parent", message="Parent comment belongs to a different entity")

    comment = Comment(
        commentable_type=body.commentable_type,
        commentable_id=body.commentable_id,
        user_id=user.id,
        content=body.content,
        parent_id=body.parent_id,
    )
    db.add(comment)
    await db.flush()

    # Process @mentions
    mentioned_usernames = _extract_mentions(body.content)
    if mentioned_usernames:
        mentioned_users = await db.execute(
            select(User.id).where(
                User.username.in_(mentioned_usernames),
                User.role != "system",
                User.is_active.is_(True),
            )
        )
        for row in mentioned_users.all():
            db.add(CommentMention(comment_id=comment.id, mentioned_user_id=row.id))
        await db.flush()

    await db.refresh(comment)
    return CommentResponse(
        id=comment.id,
        commentable_type=comment.commentable_type,
        commentable_id=comment.commentable_id,
        user_id=comment.user_id,
        content=comment.content,
        parent_id=comment.parent_id,
        created_at=comment.created_at,
        updated_at=comment.updated_at,
        username=user.username,
        reply_count=0,
    )


@router.patch("/{comment_id}", response_model=CommentResponse)
async def update_comment(
    comment_id: uuid.UUID = Path(..., description="UUID of the comment to edit"),
    body: CommentUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Replace a comment's content and re-extract its @username mentions."""
    result = await db.execute(select(Comment).where(Comment.id == comment_id))
    comment = result.scalar_one_or_none()
    if not comment:
        raise AppError(code="not_found", message="Comment not found", status_code=404)
    if user.role != "admin" and comment.user_id != user.id:
        raise AppError(code="forbidden", message="Only the comment's author or an admin can edit it", status_code=403)

    comment.content = body.content
    db.add(comment)

    # Update mentions
    await db.execute(CommentMention.__table__.delete().where(CommentMention.comment_id == comment_id))
    mentioned_usernames = _extract_mentions(body.content)
    if mentioned_usernames:
        mentioned_users = await db.execute(
            select(User.id).where(
                User.username.in_(mentioned_usernames),
                User.role != "system",
                User.is_active.is_(True),
            )
        )
        for row in mentioned_users.all():
            db.add(CommentMention(comment_id=comment.id, mentioned_user_id=row.id))

    await db.flush()
    await db.refresh(comment)
    return CommentResponse(
        id=comment.id,
        commentable_type=comment.commentable_type,
        commentable_id=comment.commentable_id,
        user_id=comment.user_id,
        content=comment.content,
        parent_id=comment.parent_id,
        created_at=comment.created_at,
        updated_at=comment.updated_at,
        username=user.username,
    )


@router.delete("/{comment_id}", status_code=204)
async def delete_comment(
    comment_id: uuid.UUID = Path(..., description="UUID of the comment to delete"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a comment. Returns 404 if it does not exist."""
    result = await db.execute(select(Comment).where(Comment.id == comment_id))
    comment = result.scalar_one_or_none()
    if not comment:
        raise AppError(code="not_found", message="Comment not found", status_code=404)
    if user.role != "admin" and comment.user_id != user.id:
        raise AppError(code="forbidden", message="Only the comment's author or an admin can delete it", status_code=403)
    await db.delete(comment)
    await db.flush()


@router.get("/mentions", response_model=PaginatedResponse[CommentResponse])
async def list_mentions(
    limit: int = Query(50, ge=1, le=500, description="Maximum number of comments to return"),
    offset: int = Query(0, ge=0, description="Number of comments to skip for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List comments that @mention the current user, newest first."""
    base = (
        select(Comment)
        .join(CommentMention, CommentMention.comment_id == Comment.id)
        .where(CommentMention.mentioned_user_id == user.id)
    )
    count_q = (
        select(func.count())
        .select_from(Comment)
        .join(CommentMention, CommentMention.comment_id == Comment.id)
        .where(CommentMention.mentioned_user_id == user.id)
    )
    total = (await db.execute(count_q)).scalar() or 0

    query = base.order_by(Comment.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    comments = result.scalars().all()

    user_ids = {c.user_id for c in comments}
    if user_ids:
        users_result = await db.execute(select(User.id, User.username).where(User.id.in_(user_ids)))
        user_map = {row.id: row.username for row in users_result.all()}
    else:
        user_map = {}

    items = [
        CommentResponse(
            id=c.id,
            commentable_type=c.commentable_type,
            commentable_id=c.commentable_id,
            user_id=c.user_id,
            content=c.content,
            parent_id=c.parent_id,
            created_at=c.created_at,
            updated_at=c.updated_at,
            username=user_map.get(c.user_id),
        )
        for c in comments
    ]

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)
