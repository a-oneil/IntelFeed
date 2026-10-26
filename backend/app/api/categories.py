import uuid

from fastapi import APIRouter, Body, Depends, Path
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_admin_user, get_current_user, get_viewer
from app.database import get_db
from app.models.category import Category
from app.models.feed import Feed
from app.models.user import User
from app.schemas.category import (
    CategoryCreateRequest,
    CategoryReorderRequest,
    CategoryResponse,
    CategoryUpdateRequest,
)
from app.services.feed_defaults import clean_defaults

router = APIRouter()


@router.get("", response_model=list[CategoryResponse])
async def list_categories(
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List categories as a tree (top-level categories with nested children), each
    with its direct feed count."""
    result = await db.execute(select(Category).order_by(Category.position))
    categories = result.scalars().all()

    # Batch feed counts in a single query (avoids N+1) — counting the caller's
    # visible feeds so the number matches the list under the folder
    from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query

    vis = visible_feed_ids_query(user.id, enabled=await subscriptions_enabled(db), include_muted=True)
    count_result = await db.execute(
        select(Feed.category_id, func.count().label("cnt"))
        .where(Feed.category_id != None, Feed.id.in_(vis))  # noqa: E711
        .group_by(Feed.category_id)
    )
    count_map = {row.category_id: row.cnt for row in count_result.all()}

    # A visitor sees a folder only if it holds a feed they can see (the count
    # above already went through the visitor filter), or a child folder that
    # does; the names of the rest say what an instance follows. Pipeline
    # defaults are an admin's ingest settings, not theirs to read.
    if user.is_anonymous:
        shown = {cid for cid, n in count_map.items() if n}
        shown |= {cat.parent_id for cat in categories if cat.id in shown and cat.parent_id}
        categories = [cat for cat in categories if cat.id in shown]

    def defaults(cat: Category):
        return {} if user.is_anonymous else clean_defaults(cat.feed_defaults)

    # Build tree structure
    items = []
    for cat in categories:
        if cat.parent_id is None:
            children = [
                CategoryResponse(
                    id=child.id,
                    name=child.name,
                    parent_id=child.parent_id,
                    position=child.position,
                    created_at=child.created_at,
                    feed_count=count_map.get(child.id, 0),
                    feed_defaults=defaults(child),
                )
                for child in categories
                if child.parent_id == cat.id
            ]
            items.append(
                CategoryResponse(
                    id=cat.id,
                    name=cat.name,
                    parent_id=cat.parent_id,
                    position=cat.position,
                    created_at=cat.created_at,
                    children=children,
                    feed_count=count_map.get(cat.id, 0),
                    feed_defaults=defaults(cat),
                )
            )

    return items


@router.post("", response_model=CategoryResponse, status_code=201)
async def create_category(
    request: CategoryCreateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a feed category, optionally nested under a parent category."""
    category = Category(
        created_by=user.id,
        name=request.name,
        parent_id=request.parent_id,
        position=request.position,
    )
    db.add(category)
    await db.flush()
    return CategoryResponse(
        id=category.id,
        name=category.name,
        parent_id=category.parent_id,
        position=category.position,
        created_at=category.created_at,
        feed_count=0,
    )


@router.put("/{category_id}", response_model=CategoryResponse)
async def update_category(
    category_id: uuid.UUID = Path(..., description="Category UUID"),
    request: CategoryUpdateRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Partially update a category's name, parent, or sort position."""
    result = await db.execute(select(Category).where(Category.id == category_id))
    category = result.scalar_one_or_none()
    if not category:
        raise AppError(code="not_found", message="Category not found", status_code=404)

    if request.name is not None:
        category.name = request.name
    if request.parent_id is not None:
        category.parent_id = request.parent_id
    if request.position is not None:
        category.position = request.position
    if request.feed_defaults is not None:
        # The defaults decide what every future feed in the folder runs —
        # instance plumbing, like the bulk update that also writes them.
        if user.role != "admin":
            raise AppError(
                code="forbidden",
                message="Only an admin can change a category's feed defaults",
                status_code=403,
            )
        category.feed_defaults = clean_defaults(request.feed_defaults.model_dump())

    db.add(category)
    await db.flush()

    count_result = await db.execute(select(func.count()).select_from(Feed).where(Feed.category_id == category.id))
    feed_count = count_result.scalar() or 0

    return CategoryResponse(
        id=category.id,
        name=category.name,
        parent_id=category.parent_id,
        position=category.position,
        created_at=category.created_at,
        feed_count=feed_count,
        feed_defaults=clean_defaults(category.feed_defaults),
    )


@router.delete("/{category_id}", status_code=204)
async def delete_category(
    category_id: uuid.UUID = Path(..., description="Category UUID"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a category; its feeds are kept and moved to uncategorized.

    Admin only — the folder tree is shared by every user."""
    result = await db.execute(select(Category).where(Category.id == category_id))
    category = result.scalar_one_or_none()
    if not category:
        raise AppError(code="not_found", message="Category not found", status_code=404)

    # Move feeds to uncategorized
    from sqlalchemy import update

    await db.execute(update(Feed).where(Feed.category_id == category_id).values(category_id=None))

    await db.delete(category)
    await db.flush()


@router.put("/reorder")
async def reorder_categories(
    request: CategoryReorderRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Bulk-update category positions and parents from an ordered item list.
    Items with missing or invalid IDs are skipped silently."""
    for item in request.items:
        cat_id = item.get("id")
        if not cat_id:
            continue
        try:
            parsed_cat_id = uuid.UUID(str(cat_id))
        except ValueError:
            continue
        result = await db.execute(select(Category).where(Category.id == parsed_cat_id))
        category = result.scalar_one_or_none()
        if category:
            if "position" in item:
                category.position = item["position"]
            if "parent_id" in item:
                try:
                    category.parent_id = uuid.UUID(str(item["parent_id"])) if item["parent_id"] else None
                except ValueError:
                    pass  # Skip invalid parent_id
            db.add(category)

    await db.flush()
    return {"message": "Categories reordered"}
