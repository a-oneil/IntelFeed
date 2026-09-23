"""My Stack exposure scoring — per-user, read-time.

Answers two questions about every CVE in an entry:
  1. Do you run it?  — does a CVE affect a vendor/product in the user's stack
                       (``UserEntityWatch`` mode="stack" ⋈ ``cve_affected``)?
  2. Can you see it? — is that CVE covered by a rule whose required telemetry the
                       org actually collects (``detection_coverage.classify_cves``)?

The stored ``Entry.priority_score`` stays global. Exposure is a read-time boost
added to the Radar ordering (mirroring the watchlist boost) plus a detection
*posture* used to decorate the entry — never written back as an EntrySignal.

Ordering uses the severity-driven exposure lift (SQL, one grouped join). The
detection posture (blind / no-rule / defended) is computed only for the visible
page via ``classify_cves`` and decorates the response; it does not yet re-order
the queue — see planning/my-stack-exposure-scoring.md (coverage-in-ordering is a
documented follow-up).
"""

import uuid

from sqlalchemy import Float, and_, case, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE, EntryCVE
from app.models.cve_affected import CVEAffected
from app.models.product import Product
from app.models.user_entity_watch import UserEntityWatch
from app.models.vendor import Vendor

# --- scoring constants (see planning/my-stack-exposure-scoring.md) ---
EXPOSURE_BASE = 1.5
KEV_MULT = 2.5
EPSS_MULT = 2.0
WEAPONIZED_MULT = 1.8
WEAPONIZED_STATES = ("weaponized", "active_exploitation")

# coverage_mult by posture — applied to display/ordering in a later phase; kept
# here so the posture→weight mapping lives in one place.
COVERAGE_MULT = {"blind": 1.3, "no_rule": 1.2, "defended": 0.9}

# classify_cves status → posture label used across the UI.
_STATUS_TO_POSTURE = {"covered": "defended", "library_only": "blind", "no_rule": "no_rule"}
# Action urgency, worst first: a rule you can't feed (blind) > nothing authored
# (no_rule) > already positioned (defended).
_POSTURE_RANK = {"blind": 0, "no_rule": 1, "defended": 2}


async def get_user_stack(db: AsyncSession, user_id: uuid.UUID) -> tuple[list[uuid.UUID], list[uuid.UUID]]:
    """Return (vendor_ids, product_ids) the user has declared as their stack."""
    rows = (
        await db.execute(
            select(UserEntityWatch.entity_type, UserEntityWatch.entity_id).where(
                UserEntityWatch.created_by == user_id,
                UserEntityWatch.mode == "stack",
            )
        )
    ).all()
    vendor_ids = [eid for etype, eid in rows if etype == "vendor"]
    product_ids = [eid for etype, eid in rows if etype == "product"]
    return vendor_ids, product_ids


def _severity_mult_expr(epss_threshold: float):
    """SQL GREATEST(...) of the per-CVE severity multipliers."""
    return func.greatest(
        case((CVE.is_kev.is_(True), KEV_MULT), else_=1.0),
        case((CVE.epss_score >= epss_threshold, EPSS_MULT), else_=1.0),
        case((CVE.exploit_availability.in_(WEAPONIZED_STATES), WEAPONIZED_MULT), else_=1.0),
    )


def _stack_affects_clause(vendor_ids: list[uuid.UUID], product_ids: list[uuid.UUID]):
    parts = []
    if vendor_ids:
        parts.append(CVEAffected.vendor_id.in_(vendor_ids))
    if product_ids:
        parts.append(CVEAffected.product_id.in_(product_ids))
    return or_(*parts) if parts else None


def exposure_lift_subquery(vendor_ids: list[uuid.UUID], product_ids: list[uuid.UUID], epss_threshold: float):
    """Subquery of (entry_id, lift): MAX severity exposure lift across an entry's
    CVEs that affect a stack entity. Returns None when the stack is empty.
    """
    affects = _stack_affects_clause(vendor_ids, product_ids)
    if affects is None:
        return None
    lift_expr = cast(EXPOSURE_BASE * _severity_mult_expr(epss_threshold), Float)
    return (
        select(
            EntryCVE.entry_id.label("entry_id"),
            func.max(lift_expr).label("lift"),
        )
        .join(CVE, CVE.id == EntryCVE.cve_id)
        .join(CVEAffected, CVEAffected.cve_id == CVE.id)
        .where(affects)
        .group_by(EntryCVE.entry_id)
        .subquery()
    )


async def enrich_exposure(
    db: AsyncSession,
    entry_ids: list[uuid.UUID],
    vendor_ids: list[uuid.UUID],
    product_ids: list[uuid.UUID],
    epss_threshold: float,
    available_telemetry: set[str] | None = None,
) -> dict[uuid.UUID, dict]:
    """Per-entry exposure detail for a page of entries.

    Returns {entry_id: {lift, posture, asset_name, asset_type, cve_ids,
    missing_data_sources}}. Only entries with a stack-affecting CVE appear.
    """
    affects = _stack_affects_clause(vendor_ids, product_ids)
    if affects is None or not entry_ids:
        return {}

    rows = (
        await db.execute(
            select(
                EntryCVE.entry_id,
                CVE.cve_id,
                CVE.is_kev,
                CVE.epss_score,
                CVE.exploit_availability,
                CVEAffected.vendor_id,
                CVEAffected.product_id,
                Vendor.name.label("vendor_name"),
                Product.name.label("product_name"),
            )
            .join(CVE, CVE.id == EntryCVE.cve_id)
            .join(CVEAffected, CVEAffected.cve_id == CVE.id)
            .outerjoin(Vendor, Vendor.id == CVEAffected.vendor_id)
            .outerjoin(Product, Product.id == CVEAffected.product_id)
            .where(and_(EntryCVE.entry_id.in_(entry_ids), affects))
        )
    ).all()
    if not rows:
        return {}

    def _sev_mult(is_kev, epss, exploit) -> float:
        m = 1.0
        if is_kev:
            m = max(m, KEV_MULT)
        if epss is not None and epss >= epss_threshold:
            m = max(m, EPSS_MULT)
        if exploit in WEAPONIZED_STATES:
            m = max(m, WEAPONIZED_MULT)
        return m

    # Gather per entry; track the "worst" (highest-lift) CVE to name the asset.
    per_entry: dict[uuid.UUID, dict] = {}
    all_cve_ids: set[str] = set()
    for r in rows:
        all_cve_ids.add(r.cve_id)
        lift = EXPOSURE_BASE * _sev_mult(r.is_kev, r.epss_score, r.exploit_availability)
        asset_name = r.product_name if r.product_id and product_ids and r.product_id in product_ids else None
        asset_type = "product" if asset_name else None
        if asset_name is None and r.vendor_id and vendor_ids and r.vendor_id in vendor_ids:
            asset_name, asset_type = r.vendor_name, "vendor"
        bucket = per_entry.setdefault(
            r.entry_id,
            {"lift": 0.0, "cve_ids": set(), "asset_name": None, "asset_type": None, "_best": -1.0},
        )
        bucket["cve_ids"].add(r.cve_id)
        bucket["lift"] = max(bucket["lift"], lift)
        if lift > bucket["_best"] and asset_name:
            bucket["_best"] = lift
            bucket["asset_name"] = asset_name
            bucket["asset_type"] = asset_type

    # Detectability posture for the matched CVEs (one batched classify call).
    from app.services.detection_coverage import classify_cves

    coverage = await classify_cves(db, sorted(all_cve_ids), available=available_telemetry)

    out: dict[uuid.UUID, dict] = {}
    for entry_id, b in per_entry.items():
        best_posture = None
        missing: list[str] = []
        for cid in b["cve_ids"]:
            info = coverage.get(cid)
            if not info:
                continue
            posture = _STATUS_TO_POSTURE.get(info["status"])
            if posture is None:
                continue
            if best_posture is None or _POSTURE_RANK[posture] < _POSTURE_RANK[best_posture]:
                best_posture = posture
            if posture == "blind":
                for ds in info.get("missing_data_sources", []):
                    if ds not in missing:
                        missing.append(ds)
        out[entry_id] = {
            "lift": round(b["lift"], 3),
            "posture": best_posture,
            "asset_name": b["asset_name"],
            "asset_type": b["asset_type"],
            "cve_ids": sorted(b["cve_ids"]),
            "missing_data_sources": missing,
        }
    return out
