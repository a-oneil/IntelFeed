"""Widget data API — entity-focused widgets (vendors, products, countries, campaigns)."""

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.widgets import _parse_date_range
from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.campaign import Campaign, CampaignEntry
from app.models.country import Country, EntryCountry
from app.models.product import EntryProduct, Product
from app.models.user import User
from app.models.vendor import EntryVendor, Vendor

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/trending-vendors")
async def trending_vendors(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    limit: int = Query(10, ge=1, le=500, description="Maximum number of vendors to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Vendors ranked by distinct entries mentioning them in the window."""
    try:
        start, end = _parse_date_range(date_from, date_to)
        result = await db.execute(
            select(
                Vendor.id,
                Vendor.name,
                Vendor.vendor_type,
                func.count(func.distinct(EntryVendor.entry_id)).label("entry_count"),
            )
            .join(Vendor, Vendor.id == EntryVendor.vendor_id)
            .where(EntryVendor.extracted_at >= start, EntryVendor.extracted_at <= end)
            .group_by(Vendor.id, Vendor.name, Vendor.vendor_type)
            .order_by(func.count(func.distinct(EntryVendor.entry_id)).desc())
            .limit(limit)
        )
        return [
            {
                "id": str(row.id),
                "name": row.name,
                "vendor_type": row.vendor_type,
                "entry_count": int(row.entry_count or 0),
            }
            for row in result.all()
        ]
    except Exception as exc:
        logger.exception("Error in trending_vendors widget")
        raise AppError(
            code="widget_error",
            message="Failed to load trending vendors widget",
            status_code=500,
        ) from exc


@router.get("/trending-products")
async def trending_products(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    limit: int = Query(10, ge=1, le=500, description="Maximum number of products to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Products (with their vendor) ranked by distinct entries mentioning them in the window."""
    try:
        start, end = _parse_date_range(date_from, date_to)
        result = await db.execute(
            select(
                Product.id,
                Product.name,
                Product.product_type,
                Vendor.name.label("vendor_name"),
                func.count(func.distinct(EntryProduct.entry_id)).label("entry_count"),
            )
            .join(Product, Product.id == EntryProduct.product_id)
            .join(Vendor, Vendor.id == Product.vendor_id, isouter=True)
            .where(EntryProduct.extracted_at >= start, EntryProduct.extracted_at <= end)
            .group_by(Product.id, Product.name, Product.product_type, Vendor.name)
            .order_by(func.count(func.distinct(EntryProduct.entry_id)).desc())
            .limit(limit)
        )
        return [
            {
                "id": str(row.id),
                "name": row.name,
                "product_type": row.product_type,
                "vendor_name": row.vendor_name,
                "entry_count": int(row.entry_count or 0),
            }
            for row in result.all()
        ]
    except Exception as exc:
        logger.exception("Error in trending_products widget")
        raise AppError(
            code="widget_error",
            message="Failed to load trending products widget",
            status_code=500,
        ) from exc


@router.get("/targeted-countries")
async def targeted_countries(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    limit: int = Query(10, ge=1, le=500, description="Maximum number of countries to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Countries linked to entries in a "target" role, ranked by distinct entry count in the window."""
    try:
        start, end = _parse_date_range(date_from, date_to)
        result = await db.execute(
            select(
                Country.id,
                Country.name,
                Country.iso_code,
                Country.region,
                func.count(func.distinct(EntryCountry.entry_id)).label("entry_count"),
            )
            .join(Country, Country.id == EntryCountry.country_id)
            .where(
                EntryCountry.role == "target",
                EntryCountry.extracted_at >= start,
                EntryCountry.extracted_at <= end,
            )
            .group_by(Country.id, Country.name, Country.iso_code, Country.region)
            .order_by(func.count(func.distinct(EntryCountry.entry_id)).desc())
            .limit(limit)
        )
        return [
            {
                "id": str(row.id),
                "name": row.name,
                "iso_code": row.iso_code,
                "region": row.region,
                "entry_count": int(row.entry_count or 0),
            }
            for row in result.all()
        ]
    except Exception as exc:
        logger.exception("Error in targeted_countries widget")
        raise AppError(
            code="widget_error",
            message="Failed to load targeted countries widget",
            status_code=500,
        ) from exc


@router.get("/active-campaigns")
async def active_campaigns(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    limit: int = Query(10, ge=1, le=500, description="Maximum number of campaigns to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Non-closed campaigns ranked by entries added within the window, then by most recent update."""
    try:
        start, end = _parse_date_range(date_from, date_to)
        entry_count_subq = (
            select(
                CampaignEntry.campaign_id,
                func.count(func.distinct(CampaignEntry.entry_id)).label("entry_count"),
            )
            .where(CampaignEntry.added_at >= start, CampaignEntry.added_at <= end)
            .group_by(CampaignEntry.campaign_id)
            .subquery()
        )
        result = await db.execute(
            select(Campaign, entry_count_subq.c.entry_count)
            .outerjoin(entry_count_subq, entry_count_subq.c.campaign_id == Campaign.id)
            .where(Campaign.status != "closed")
            .order_by(
                func.coalesce(entry_count_subq.c.entry_count, 0).desc(),
                Campaign.updated_at.desc(),
            )
            .limit(limit)
        )
        return [
            {
                "id": str(c.id),
                "name": c.name,
                "status": c.status,
                "tlp_marking": c.tlp_marking,
                "entry_count": int(entry_count or 0),
                "updated_at": c.updated_at.isoformat() if c.updated_at else None,
            }
            for c, entry_count in result.all()
        ]
    except Exception as exc:
        logger.exception("Error in active_campaigns widget")
        raise AppError(
            code="widget_error",
            message="Failed to load active campaigns widget",
            status_code=500,
        ) from exc
