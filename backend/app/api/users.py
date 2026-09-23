import uuid

from fastapi import APIRouter, Depends, Path, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_admin_user, hash_password
from app.database import get_db
from app.models.user import User
from app.schemas.auth import AdminUserUpdateRequest, UserResponse

router = APIRouter()


@router.get("", response_model=list[UserResponse])
async def list_users(
    _admin: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """List all user accounts, oldest first. Admin only. The `system` service
    account is internal attribution plumbing, not an account to manage.

    Each row carries `feed_count` / `muted_feed_count` — how much of the shared
    pool that analyst actually reads. With per-user subscriptions off everyone
    still sees every feed, so the numbers are what their list would become the
    moment the flag is flipped.
    """
    from app.models.user_feed_subscription import UserFeedSubscription

    result = await db.execute(select(User).where(User.role != "system").order_by(User.created_at))
    users = result.scalars().all()

    counts = (
        await db.execute(
            select(
                UserFeedSubscription.user_id,
                func.count().label("total"),
                func.count().filter(UserFeedSubscription.is_muted.is_(True)).label("muted"),
            ).group_by(UserFeedSubscription.user_id)
        )
    ).all()
    by_user = {row.user_id: (row.total, row.muted) for row in counts}

    out = []
    for u in users:
        total, muted = by_user.get(u.id, (0, 0))
        resp = UserResponse.model_validate(u)
        resp.feed_count = total
        resp.muted_feed_count = muted
        out.append(resp)
    return out


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: uuid.UUID = Path(..., description="UUID of the user account"),
    _admin: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch a single user account by id. Admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise AppError(code="not_found", message="User not found", status_code=404)
    return user


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    request: AdminUserUpdateRequest,
    user_id: uuid.UUID = Path(..., description="UUID of the user account to update"),
    admin: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Partially update a user account: username, role, active flag, and/or password. Admin only.

    Admins cannot remove their own admin role or deactivate their own account.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise AppError(code="not_found", message="User not found", status_code=404)
    if user.role == "system":
        raise AppError(code="forbidden", message="The system service account cannot be modified", status_code=403)

    if request.username is not None and request.username != user.username:
        existing = await db.execute(select(func.count()).where(User.username == request.username, User.id != user_id))
        if existing.scalar():
            raise AppError(code="conflict", message="Username already taken", status_code=409)
        user.username = request.username

    if request.role is not None:
        # Prevent removing your own admin role
        if user.id == admin.id and request.role != "admin":
            raise AppError(
                code="validation_error",
                message="Cannot remove your own admin role",
                status_code=400,
            )
        user.role = request.role

    if request.is_active is not None:
        # Prevent deactivating yourself
        if user.id == admin.id and not request.is_active:
            raise AppError(
                code="validation_error",
                message="Cannot deactivate your own account",
                status_code=400,
            )
        user.is_active = request.is_active

    if request.password is not None:
        user.password_hash = hash_password(request.password)

    db.add(user)
    await db.flush()
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: uuid.UUID = Path(..., description="UUID of the user account to delete"),
    admin: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Permanently delete a user account. Admin only; admins cannot delete their own account."""
    if user_id == admin.id:
        raise AppError(
            code="validation_error",
            message="Cannot delete your own account",
            status_code=400,
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise AppError(code="not_found", message="User not found", status_code=404)
    if user.role == "system":
        raise AppError(code="forbidden", message="The system service account cannot be deleted", status_code=403)

    # Automation rules execute with their owner's identity; disable them rather
    # than letting the FK SET NULL leave them firing as nobody.
    from sqlalchemy import update as sa_update

    from app.models.automation_rule import AutomationRule

    await db.execute(sa_update(AutomationRule).where(AutomationRule.created_by == user_id).values(is_enabled=False))

    await db.delete(user)
    await db.flush()
