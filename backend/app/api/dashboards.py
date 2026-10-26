"""Dashboard management API — CRUD for dashboards and widgets."""

import uuid

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user, get_viewer
from app.dashboard_defaults import DEFAULT_BOARDS
from app.database import get_db
from app.models.dashboard import Dashboard, DashboardWidget
from app.models.user import User
from app.schemas.dashboard import (
    DashboardCreate,
    DashboardResponse,
    DashboardUpdate,
    LayoutUpdate,
    WidgetCreate,
    WidgetResponse,
    WidgetUpdate,
)
from app.services.public_view import visitor_dashboards

router = APIRouter()


@router.get("", response_model=PaginatedResponse[DashboardResponse])
async def list_dashboards(
    limit: int = Query(50, ge=1, le=500, description="Maximum number of dashboards to return."),
    offset: int = Query(0, ge=0, description="Number of dashboards to skip for pagination."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the caller's dashboards with their widgets, ordered by sort order then creation time."""
    if user.is_anonymous:
        boards = visitor_dashboards()
        return PaginatedResponse(items=boards, total=len(boards), limit=limit, offset=0, has_more=False)
    base = select(Dashboard).where(Dashboard.created_by == user.id)
    total = (
        await db.execute(select(func.count()).select_from(Dashboard).where(Dashboard.created_by == user.id))
    ).scalar() or 0

    result = await db.execute(
        base.options(selectinload(Dashboard.widgets))
        .order_by(Dashboard.sort_order, Dashboard.created_at)
        .limit(limit)
        .offset(offset)
    )
    dashboards = result.scalars().unique().all()
    items = [DashboardResponse.model_validate(d) for d in dashboards]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.post("", response_model=DashboardResponse, status_code=201)
async def create_dashboard(
    body: DashboardCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new dashboard. If is_default is set, the caller's existing default is unset."""
    # If setting as default, unset the caller's other defaults
    if body.is_default:
        await _unset_defaults(db, user.id)

    dashboard = Dashboard(created_by=user.id, name=body.name, is_default=body.is_default)
    db.add(dashboard)
    await db.flush()
    # Re-fetch with widgets eagerly loaded to avoid lazy-load in async context
    result = await db.execute(
        select(Dashboard).options(selectinload(Dashboard.widgets)).where(Dashboard.id == dashboard.id)
    )
    dashboard = result.scalar_one()
    return DashboardResponse.model_validate(dashboard)


@router.post("/seed-defaults", response_model=PaginatedResponse[DashboardResponse])
async def seed_default_dashboards(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Give a user with no dashboards the instance's default board set.

    Idempotent and non-destructive: a user who already owns any dashboard — even
    a single renamed or emptied one — gets that back untouched instead. The
    defaults are only ever a starting point.
    """
    existing = await db.execute(
        select(Dashboard)
        .options(selectinload(Dashboard.widgets))
        .where(Dashboard.created_by == user.id)
        .order_by(Dashboard.sort_order, Dashboard.created_at)
    )
    dashboards = list(existing.scalars().unique().all())

    if not dashboards:
        for sort_order, board in enumerate(DEFAULT_BOARDS):
            dashboard = Dashboard(
                created_by=user.id,
                name=board["name"],
                is_default=(sort_order == 0),
                sort_order=sort_order,
            )
            db.add(dashboard)
            await db.flush()
            for widget in board["widgets"]:
                db.add(DashboardWidget(dashboard_id=dashboard.id, **widget))
        await db.flush()
        seeded = await db.execute(
            select(Dashboard)
            .options(selectinload(Dashboard.widgets))
            .where(Dashboard.created_by == user.id)
            .order_by(Dashboard.sort_order, Dashboard.created_at)
        )
        dashboards = list(seeded.scalars().unique().all())

    items = [DashboardResponse.model_validate(d) for d in dashboards]
    return PaginatedResponse(items=items, total=len(items), limit=len(items), offset=0, has_more=False)


@router.put("/reorder")
async def reorder_dashboards(
    body: dict = Body(
        ...,
        description="Ordered list of dashboard UUIDs; sort_order is assigned by list position.",
        json_schema_extra={
            "example": {
                "ids": [
                    "d5b2c3a4-1f2e-4a5b-9c8d-7e6f5a4b3c2d",
                    "a1b2c3d4-e5f6-4789-9abc-def012345678",
                ]
            }
        },
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Reorder dashboards by providing an ordered list of IDs."""
    ids = body.get("ids", [])
    for idx, dashboard_id in enumerate(ids):
        try:
            parsed_id = uuid.UUID(dashboard_id)
        except (ValueError, AttributeError):
            continue
        result = await db.execute(select(Dashboard).where(Dashboard.id == parsed_id, Dashboard.created_by == user.id))
        dash = result.scalar_one_or_none()
        if dash:
            dash.sort_order = idx
    await db.commit()
    return {"ok": True}


@router.get("/{dashboard_id}", response_model=DashboardResponse)
async def get_dashboard(
    dashboard_id: uuid.UUID = Path(..., description="Dashboard UUID."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Fetch a single dashboard with its widgets. Returns 404 if not found."""
    if user.is_anonymous:
        for board in visitor_dashboards():
            if board.id == dashboard_id:
                return board
        raise AppError(code="not_found", message="Dashboard not found", status_code=404)
    dashboard = await _get_dashboard(db, dashboard_id, user.id)
    return DashboardResponse.model_validate(dashboard)


@router.put("/{dashboard_id}", response_model=DashboardResponse)
async def update_dashboard(
    dashboard_id: uuid.UUID = Path(..., description="Dashboard UUID."),
    body: DashboardUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a dashboard's name and/or default flag. Setting is_default unsets the caller's other default."""
    dashboard = await _get_dashboard(db, dashboard_id, user.id)

    if body.name is not None:
        dashboard.name = body.name
    if body.is_default is not None:
        if body.is_default:
            await _unset_defaults(db, user.id)
        dashboard.is_default = body.is_default

    db.add(dashboard)
    await db.flush()
    await db.refresh(dashboard, attribute_names=["widgets"])
    return DashboardResponse.model_validate(dashboard)


@router.delete("/{dashboard_id}", status_code=204)
async def delete_dashboard(
    dashboard_id: uuid.UUID = Path(..., description="Dashboard UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a dashboard and its widgets. Returns 204 on success, 404 if not found."""
    dashboard = await _get_dashboard(db, dashboard_id, user.id)
    await db.delete(dashboard)
    await db.flush()


# --- Widget endpoints ---


@router.post("/{dashboard_id}/widgets", response_model=WidgetResponse, status_code=201)
async def add_widget(
    dashboard_id: uuid.UUID = Path(..., description="Dashboard UUID."),
    body: WidgetCreate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add a widget to a dashboard at the given grid position and size. Returns 404 if the dashboard is missing."""
    await _get_dashboard(db, dashboard_id, user.id)

    widget = DashboardWidget(
        dashboard_id=dashboard_id,
        widget_type=body.widget_type,
        title=body.title,
        config=body.config,
        position_x=body.position_x,
        position_y=body.position_y,
        width=body.width,
        height=body.height,
    )
    db.add(widget)
    await db.flush()
    await db.refresh(widget)
    return WidgetResponse.model_validate(widget)


@router.put("/{dashboard_id}/widgets/{widget_id}", response_model=WidgetResponse)
async def update_widget(
    dashboard_id: uuid.UUID = Path(..., description="Dashboard UUID."),
    widget_id: uuid.UUID = Path(..., description="Widget UUID."),
    body: WidgetUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a widget's title, config, or grid position/size. Only the provided fields are changed."""
    await _get_dashboard(db, dashboard_id, user.id)
    widget = await _get_widget(db, widget_id, dashboard_id)

    if body.title is not None:
        widget.title = body.title
    if body.config is not None:
        widget.config = body.config
    if body.position_x is not None:
        widget.position_x = body.position_x
    if body.position_y is not None:
        widget.position_y = body.position_y
    if body.width is not None:
        widget.width = body.width
    if body.height is not None:
        widget.height = body.height

    db.add(widget)
    await db.flush()
    await db.refresh(widget)
    return WidgetResponse.model_validate(widget)


@router.delete("/{dashboard_id}/widgets/{widget_id}", status_code=204)
async def remove_widget(
    dashboard_id: uuid.UUID = Path(..., description="Dashboard UUID."),
    widget_id: uuid.UUID = Path(..., description="Widget UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a widget from a dashboard. Returns 204 on success, 404 if the dashboard or widget is not found."""
    await _get_dashboard(db, dashboard_id, user.id)
    widget = await _get_widget(db, widget_id, dashboard_id)
    await db.delete(widget)
    await db.flush()


@router.put("/{dashboard_id}/layout", status_code=200)
async def update_layout(
    dashboard_id: uuid.UUID = Path(..., description="Dashboard UUID."),
    body: LayoutUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Bulk-update widget positions and sizes on a dashboard. Widget IDs not on the dashboard are ignored."""
    await _get_dashboard(db, dashboard_id, user.id)

    for item in body.items:
        result = await db.execute(
            select(DashboardWidget).where(DashboardWidget.id == item.id, DashboardWidget.dashboard_id == dashboard_id)
        )
        widget = result.scalar_one_or_none()
        if widget:
            widget.position_x = item.position_x
            widget.position_y = item.position_y
            widget.width = item.width
            widget.height = item.height
            db.add(widget)

    await db.flush()
    return {"status": "ok"}


# --- Helpers ---


async def _get_dashboard(db: AsyncSession, dashboard_id: uuid.UUID, user_id: uuid.UUID) -> Dashboard:
    """Fetch one of the caller's dashboards. Someone else's reads as missing."""
    result = await db.execute(
        select(Dashboard)
        .options(selectinload(Dashboard.widgets))
        .where(Dashboard.id == dashboard_id, Dashboard.created_by == user_id)
    )
    dashboard = result.scalar_one_or_none()
    if not dashboard:
        raise AppError(code="not_found", message="Dashboard not found", status_code=404)
    return dashboard


async def _get_widget(db: AsyncSession, widget_id: uuid.UUID, dashboard_id: uuid.UUID) -> DashboardWidget:
    result = await db.execute(
        select(DashboardWidget).where(DashboardWidget.id == widget_id, DashboardWidget.dashboard_id == dashboard_id)
    )
    widget = result.scalar_one_or_none()
    if not widget:
        raise AppError(code="not_found", message="Widget not found", status_code=404)
    return widget


async def _unset_defaults(db: AsyncSession, user_id: uuid.UUID) -> None:
    result = await db.execute(
        select(Dashboard).where(
            Dashboard.is_default == True,  # noqa: E712
            Dashboard.created_by == user_id,
        )
    )
    for d in result.scalars().all():
        d.is_default = False
        db.add(d)
