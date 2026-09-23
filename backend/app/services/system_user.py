"""Resolve the identity that background/automated work is attributed to.

Order: the dedicated `system` service account (seeded by migration, not
loginable), else the earliest admin, else the earliest user — the last two
only matter on installs that predate the seeded account.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User

SYSTEM_USERNAME = "system"


async def get_system_user(db: AsyncSession) -> User | None:
    result = await db.execute(select(User).where(User.username == SYSTEM_USERNAME).limit(1))
    user = result.scalar_one_or_none()
    if user:
        return user
    result = await db.execute(select(User).where(User.role == "admin").order_by(User.created_at.asc()).limit(1))
    user = result.scalar_one_or_none()
    if user:
        return user
    result = await db.execute(select(User).order_by(User.created_at.asc()).limit(1))
    return result.scalar_one_or_none()


async def get_system_user_id(db: AsyncSession) -> uuid.UUID | None:
    user = await get_system_user(db)
    return user.id if user else None
