"""Exposure board — /api/intelligence/exposure.

Aggregates every CVE that affects what the user runs (vendors/products in
``UserEntityWatch`` mode="stack") with a detection posture from the telemetry
inventory. Kept in its own router/module so it doesn't touch the (heavily shared)
intelligence router. See docs/intelligence-engine.md "Intel profiles and exposure reports".
"""

import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.database import get_db
from app.intelligence.cve import get_epss_high_risk_threshold
from app.models.cve import CVE, EntryCVE
from app.models.cve_affected import CVEAffected
from app.models.product import Product
from app.models.user import User
from app.models.vendor import Vendor
from app.services.exposure import (
    EPSS_MULT,
    EXPOSURE_BASE,
    KEV_MULT,
    WEAPONIZED_MULT,
    WEAPONIZED_STATES,
    get_user_stack,
)
from app.services.system_settings import get_setting

router = APIRouter()


class StackAsset(BaseModel):
    name: str
    type: str  # vendor | product
    cve_count: int = 0
    kev_count: int = 0


class StackExposureItem(BaseModel):
    cve_id: str
    description: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    is_kev: bool = False
    exploited: bool = False
    kev_due_date: str | None = None
    published_at: str | None = None
    asset_name: str | None = None
    asset_type: str | None = None
    posture: str | None = None
    missing_data_sources: list[str] = []
    entry_count: int = 0
    lift: float = 0.0
    # Phase 7 heuristic (only set for no_rule CVEs when the flag is on):
    # {detectable, data_sources[], available[], missing[]}
    attack_visibility: dict | None = None


class StackSummary(BaseModel):
    vendors: list[str] = []
    products: list[str] = []
    count: int = 0


class StackExposureResponse(BaseModel):
    stack: StackSummary
    counts: dict[str, int]
    matrix: dict[str, int]
    assets: list[StackAsset]
    items: list[StackExposureItem]


def _severity_mult(is_kev: bool, epss: float | None, exploit: str | None, threshold: float) -> float:
    m = 1.0
    if is_kev:
        m = max(m, KEV_MULT)
    if epss is not None and epss >= threshold:
        m = max(m, EPSS_MULT)
    if exploit in WEAPONIZED_STATES:
        m = max(m, WEAPONIZED_MULT)
    return m


@router.get("", response_model=StackExposureResponse)
async def get_stack_exposure(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Every CVE affecting the user's stack, ranked by exposure lift, with a
    detection posture and the exposure × detectability matrix cell counts."""
    vendor_ids, product_ids = await get_user_stack(db, user.id)

    # Resolve stack names for the header.
    vendor_names: list[str] = []
    product_names: list[str] = []
    if vendor_ids:
        vendor_names = [n for (n,) in (await db.execute(select(Vendor.name).where(Vendor.id.in_(vendor_ids)))).all()]
    if product_ids:
        product_names = [
            n for (n,) in (await db.execute(select(Product.name).where(Product.id.in_(product_ids)))).all()
        ]
    stack = StackSummary(
        vendors=sorted(vendor_names),
        products=sorted(product_names),
        count=len(vendor_ids) + len(product_ids),
    )

    if not vendor_ids and not product_ids:
        return StackExposureResponse(stack=stack, counts={}, matrix={}, assets=[], items=[])

    affects = []
    if vendor_ids:
        affects.append(CVEAffected.vendor_id.in_(vendor_ids))
    if product_ids:
        affects.append(CVEAffected.product_id.in_(product_ids))

    rows = (
        await db.execute(
            select(
                CVE,
                CVEAffected.vendor_id,
                CVEAffected.product_id,
                Vendor.name.label("vendor_name"),
                Product.name.label("product_name"),
            )
            .join(CVEAffected, CVEAffected.cve_id == CVE.id)
            .outerjoin(Vendor, Vendor.id == CVEAffected.vendor_id)
            .outerjoin(Product, Product.id == CVEAffected.product_id)
            .where(or_(*affects))
        )
    ).all()

    threshold = get_epss_high_risk_threshold()
    vendor_id_set, product_id_set = set(vendor_ids), set(product_ids)

    # Collapse to one record per CVE (highest-lift matched asset), and tally CVEs
    # per stack asset across every affects-link (a CVE can touch multiple assets).
    per_cve: dict[uuid.UUID, dict] = {}
    asset_cves: dict[tuple[str, str], set[uuid.UUID]] = {}
    asset_kev: dict[tuple[str, str], set[uuid.UUID]] = {}
    for cve, vendor_id, product_id, vendor_name, product_name in rows:
        lift = EXPOSURE_BASE * _severity_mult(cve.is_kev, cve.epss_score, cve.exploit_availability, threshold)
        asset_name, asset_type = None, None
        if product_id and product_id in product_id_set:
            asset_name, asset_type = product_name, "product"
        elif vendor_id and vendor_id in vendor_id_set:
            asset_name, asset_type = vendor_name, "vendor"
        for key in (
            ("product", product_name) if product_id in product_id_set else None,
            ("vendor", vendor_name) if vendor_id in vendor_id_set else None,
        ):
            if key and key[1]:
                asset_cves.setdefault(key, set()).add(cve.id)
                if cve.is_kev:
                    asset_kev.setdefault(key, set()).add(cve.id)
        rec = per_cve.get(cve.id)
        if rec is None or lift > rec["lift"]:
            per_cve[cve.id] = {"cve": cve, "lift": lift, "asset_name": asset_name, "asset_type": asset_type}

    # Every declared asset, with its affected-CVE tally (0 if nothing hits it yet).
    assets: list[StackAsset] = []
    for atype, names in (("product", product_names), ("vendor", vendor_names)):
        for name in names:
            key = (atype, name)
            assets.append(
                StackAsset(
                    name=name,
                    type=atype,
                    cve_count=len(asset_cves.get(key, ())),
                    kev_count=len(asset_kev.get(key, ())),
                )
            )
    assets.sort(key=lambda a: a.cve_count, reverse=True)

    cve_ids = [rec["cve"].cve_id for rec in per_cve.values()]

    # Detection posture (org telemetry) + entry mention counts.
    from app.services.detection_coverage import classify_cves

    coverage = await classify_cves(db, cve_ids)
    _STATUS_TO_POSTURE = {"covered": "defended", "library_only": "blind", "no_rule": "no_rule"}

    # Phase 7 (heuristic, flag-gated): for CVEs with no rule, estimate whether the
    # org's telemetry could still detect exploitation via the CVE's co-occurring
    # ATT&CK techniques' data sources.
    attack_vis: dict[str, dict] = {}
    if await get_setting("exposure_attack_visibility_enabled", db):
        from app.services.attack_visibility import cve_attack_visibility

        no_rule_pks = {
            pk: rec["cve"].cve_id
            for pk, rec in per_cve.items()
            if _STATUS_TO_POSTURE.get(coverage.get(rec["cve"].cve_id, {}).get("status")) == "no_rule"
        }
        attack_vis = await cve_attack_visibility(db, no_rule_pks)

    entry_counts: dict[uuid.UUID, int] = {}
    count_rows = (
        await db.execute(
            select(EntryCVE.cve_id, func.count())
            .where(EntryCVE.cve_id.in_(list(per_cve.keys())))
            .group_by(EntryCVE.cve_id)
        )
    ).all()
    for cid, cnt in count_rows:
        entry_counts[cid] = cnt

    items: list[StackExposureItem] = []
    counts = {"affecting": 0, "kev": 0, "exploited": 0, "blind": 0, "no_rule": 0, "defended": 0}
    matrix: dict[str, int] = {}
    for pk, rec in per_cve.items():
        cve = rec["cve"]
        cov = coverage.get(cve.cve_id, {})
        posture = _STATUS_TO_POSTURE.get(cov.get("status"))
        exploited = cve.exploit_availability in WEAPONIZED_STATES
        published = (cve.nvd_data or {}).get("published") or (
            cve.first_seen_at.isoformat() if cve.first_seen_at else None
        )
        desc = (cve.description or "").strip()
        if len(desc) > 120:
            desc = desc[:117].rstrip() + "…"
        items.append(
            StackExposureItem(
                cve_id=cve.cve_id,
                description=desc or None,
                severity=cve.severity,
                cvss_score=float(cve.cvss_score) if cve.cvss_score is not None else None,
                epss_score=cve.epss_score,
                is_kev=bool(cve.is_kev),
                exploited=exploited,
                kev_due_date=cve.kev_due_date.isoformat() if cve.kev_due_date else None,
                published_at=published,
                asset_name=rec["asset_name"],
                asset_type=rec["asset_type"],
                posture=posture,
                missing_data_sources=cov.get("missing_data_sources", []),
                entry_count=entry_counts.get(pk, 0),
                lift=round(rec["lift"], 3),
                attack_visibility=attack_vis.get(cve.cve_id),
            )
        )
        counts["affecting"] += 1
        if cve.is_kev:
            counts["kev"] += 1
        if exploited:
            counts["exploited"] += 1
        if posture in counts:
            counts[posture] += 1
        # matrix cell: urgency tier × posture
        urgent = cve.is_kev or exploited or (cve.epss_score is not None and cve.epss_score >= threshold)
        tier = "urgent" if urgent else "affects"
        if posture:
            key = f"{tier}_{posture}"
            matrix[key] = matrix.get(key, 0) + 1

    items.sort(key=lambda i: (i.lift, i.epss_score or 0), reverse=True)
    return StackExposureResponse(stack=stack, counts=counts, matrix=matrix, assets=assets, items=items)
