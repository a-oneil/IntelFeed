"""CVE extraction and NVD enrichment."""

import asyncio
import logging
import re
import uuid
from datetime import UTC, datetime

import httpx
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.intelligence.cpe_resolver import CPEIndex, build_cpe_index
from app.models.cve import CVE, EntryCVE
from app.models.cve_affected import CVEAffected
from app.models.cwe import CWE, CVEWeakness

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_MAX_RETRIES = 3
NVD_BACKOFF_BASE = 2  # seconds
# NVD rolling window is 5 req/30s unkeyed, 50 req/30s with an API key
NVD_PACE_UNKEYED = 6.5
NVD_PACE_KEYED = 0.7


class NVDRateLimited(Exception):
    """NVD kept returning 403/429 after all retries — back off, don't record
    the failure against the CVE's retry budget."""


def nvd_request_pace() -> float:
    """Seconds to sleep between consecutive NVD requests in sweep loops."""
    api_key = settings.get("nvd_api_key") or settings.nvd_api_key
    return NVD_PACE_KEYED if api_key else NVD_PACE_UNKEYED


def extract_cve_ids(text: str) -> list[str]:
    """Extract CVE IDs from text using regex."""
    if not text:
        return []
    return list(set(CVE_PATTERN.findall(text)))


async def enrich_from_nvd(cve_id: str, raise_on_rate_limit: bool = False) -> dict | None:
    """Fetch CVE details from NVD API 2.0 with optional API key and retry.

    With raise_on_rate_limit, exhausting retries on 403/429 raises
    NVDRateLimited instead of returning None, so sweep callers can
    distinguish "NVD has nothing for this id" from "we're being throttled".
    """
    headers: dict[str, str] = {}
    api_key = settings.get("nvd_api_key") or settings.nvd_api_key
    if api_key:
        headers["apiKey"] = api_key

    rate_limited = False
    for attempt in range(NVD_MAX_RETRIES):
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    NVD_API_URL,
                    params={"cveId": cve_id},
                    headers=headers,
                )

                if resp.status_code in (403, 429):
                    rate_limited = True
                    # Back off past the 30s rolling window on the last retry
                    wait = NVD_BACKOFF_BASE ** (attempt + 1) if attempt < NVD_MAX_RETRIES - 1 else 31
                    logger.warning(f"NVD rate limited for {cve_id}, retrying in {wait}s (attempt {attempt + 1})")
                    await asyncio.sleep(wait)
                    continue
                rate_limited = False

                if resp.status_code != 200:
                    logger.warning(f"NVD returned {resp.status_code} for {cve_id}")
                    return None

                data = resp.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            cve_data = vulns[0].get("cve", {})

            # Extract CVSS v3.1 score
            cvss_score = None
            severity = None
            metrics = cve_data.get("metrics", {})
            for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "").upper()
                    break

            # Description
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else None,
            )

            affected_products = parse_cpe_affected(cve_data)

            # References (tags drive the advisory/patch/analysis grouping in the UI)
            references = [
                {"url": r.get("url"), "source": r.get("source"), "tags": r.get("tags", [])}
                for r in cve_data.get("references", [])
            ]

            return {
                "cvss_score": cvss_score,
                "severity": severity or _severity_from_score(cvss_score),
                "description": description,
                "affected_products": affected_products,
                "references": references,
                "nvd_data": cve_data,
            }

        except httpx.TimeoutException:
            if attempt < NVD_MAX_RETRIES - 1:
                wait = NVD_BACKOFF_BASE ** (attempt + 1)
                logger.warning(f"NVD timeout for {cve_id}, retrying in {wait}s")
                await asyncio.sleep(wait)
                continue
            logger.warning(f"NVD enrichment timed out for {cve_id} after {NVD_MAX_RETRIES} attempts")
            return None
        except Exception as e:
            logger.warning(f"NVD enrichment failed for {cve_id}: {e}")
            return None

    if rate_limited and raise_on_rate_limit:
        raise NVDRateLimited(cve_id)
    return None


def parse_cpe_affected(cve_data: dict) -> list[dict]:
    """Parse NVD configurations/CPE into affected-product dicts.

    Merges per (vendor, product) so each product appears once with the broadest
    version range observed. Used both at enrichment time and by the
    backfill_cve_affected sweep re-deriving from stored nvd_data blobs.
    """
    grouped: dict[tuple[str, str], dict] = {}
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) < 5:
                    continue
                vendor = parts[3]
                product = parts[4]
                v_start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                v_end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                key = (vendor.lower(), product.lower())
                existing = grouped.get(key)
                if existing is None:
                    grouped[key] = {
                        "vendor": vendor,
                        "product": product,
                        "version_start": v_start,
                        "version_end": v_end,
                    }
                else:
                    if v_start and (not existing["version_start"] or str(v_start) < str(existing["version_start"])):
                        existing["version_start"] = v_start
                    if v_end and (not existing["version_end"] or str(v_end) > str(existing["version_end"])):
                        existing["version_end"] = v_end
    return list(grouped.values())


async def sync_cve_affected(
    db: AsyncSession,
    cve_pk: uuid.UUID,
    affected_products: list[dict],
    index: "CPEIndex",
) -> int:
    """Upsert cve_affected rows for a CVE from parsed CPE pairs.

    Idempotent on (cve_id, cpe_vendor, cpe_product). Existing rows get version
    ranges refreshed and null FKs filled when the pair now resolves — resolved
    FKs are never cleared by a later non-resolving pass.
    """
    count = 0
    seen: set[tuple[str, str]] = set()
    for item in affected_products:
        cpe_vendor = (item.get("vendor") or "").strip().lower()
        cpe_product = (item.get("product") or "").strip().lower()
        if not cpe_vendor or not cpe_product or (cpe_vendor, cpe_product) in seen:
            continue
        seen.add((cpe_vendor, cpe_product))
        vendor_id, product_id = index.resolve_pair(cpe_vendor, cpe_product)
        resolved_at = datetime.now(UTC) if (vendor_id or product_id) else None
        stmt = pg_insert(CVEAffected).values(
            id=uuid.uuid4(),
            cve_id=cve_pk,
            cpe_vendor=cpe_vendor,
            cpe_product=cpe_product,
            vendor_id=vendor_id,
            product_id=product_id,
            version_start=item.get("version_start"),
            version_end=item.get("version_end"),
            resolved_at=resolved_at,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_cve_affected_pair",
            set_={
                "version_start": stmt.excluded.version_start,
                "version_end": stmt.excluded.version_end,
                "vendor_id": func.coalesce(CVEAffected.vendor_id, stmt.excluded.vendor_id),
                "product_id": func.coalesce(CVEAffected.product_id, stmt.excluded.product_id),
                "resolved_at": func.coalesce(CVEAffected.resolved_at, stmt.excluded.resolved_at),
            },
        )
        await db.execute(stmt)
        count += 1
    return count


async def build_cwe_index(db: AsyncSession) -> dict[str, uuid.UUID]:
    """cwe_id -> catalog row id, for resolving NVD weakness refs in bulk.

    Small enough (~1,400 rows) to hold whole rather than querying per CVE, which
    is the same trade build_cpe_index makes.
    """
    rows = (await db.execute(select(CWE.cwe_id, CWE.id))).all()
    return {cwe_id: pk for cwe_id, pk in rows}


def parse_nvd_weaknesses(cve_data: dict) -> list[dict]:
    """Parse the NVD ``weaknesses`` block into one record per distinct ref.

    Several CNAs can each assign a weakness to the same CVE, so the same id can
    appear twice with different ``type`` values; they collapse to one record
    that is Primary if *any* assigner said so. The ``NVD-CWE-noinfo`` and
    ``NVD-CWE-Other`` sentinels are kept rather than dropped — they are the
    honest record that NVD declined to classify, and counting them is what makes
    the coverage gap visible.
    """
    merged: dict[str, dict] = {}
    for block in cve_data.get("weaknesses", []):
        is_primary = (block.get("type") or "").lower() == "primary"
        assigner = block.get("source")
        for desc in block.get("description", []):
            if desc.get("lang") not in (None, "en"):
                continue
            ref = (desc.get("value") or "").strip()
            if not ref:
                continue
            existing = merged.get(ref)
            if existing is None:
                merged[ref] = {"cwe_ref": ref, "is_primary": is_primary, "assigner": assigner}
            elif is_primary and not existing["is_primary"]:
                existing["is_primary"] = True
                existing["assigner"] = assigner
    return list(merged.values())


async def sync_cve_weaknesses(
    db: AsyncSession,
    cve_pk: uuid.UUID,
    weaknesses: list[dict],
    index: dict[str, uuid.UUID],
) -> int:
    """Upsert cve_weaknesses rows for a CVE from parsed NVD weakness records.

    Idempotent on (cve_id, cwe_ref). Mirrors sync_cve_affected: the raw ref is
    always stored, the FK is filled only when it resolves, and a resolved FK is
    never cleared by a later pass.
    """
    count = 0
    for item in weaknesses:
        ref = item["cwe_ref"]
        cwe_pk = index.get(ref)
        resolved_at = datetime.now(UTC) if cwe_pk else None
        stmt = pg_insert(CVEWeakness).values(
            id=uuid.uuid4(),
            cve_id=cve_pk,
            cwe_ref=ref,
            cwe_id=cwe_pk,
            is_primary=item.get("is_primary", False),
            assigner=item.get("assigner"),
            resolved_at=resolved_at,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_cve_weakness_pair",
            set_={
                # Primary is sticky: a later Secondary-only pass must not demote it.
                "is_primary": CVEWeakness.is_primary.op("OR")(stmt.excluded.is_primary),
                "cwe_id": func.coalesce(CVEWeakness.cwe_id_fk, stmt.excluded.cwe_id),
                "resolved_at": func.coalesce(CVEWeakness.resolved_at, stmt.excluded.resolved_at),
            },
        )
        await db.execute(stmt)
        count += 1
    return count


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def calculate_cve_priority(
    cvss_score: float | None,
    epss_score: float | None,
    exploit_status: str | None,
    is_kev: bool = False,
) -> str:
    """Calculate combined priority from CVSS + EPSS + KEV status.

    Returns: CRITICAL, HIGH, MEDIUM, or LOW.
    """
    is_kev = is_kev or (
        exploit_status is not None and ("kev" in exploit_status.lower() or exploit_status.lower() == "known_exploited")
    )
    if is_kev:
        return "CRITICAL"
    cvss = float(cvss_score) if cvss_score is not None else 0.0
    epss = float(epss_score) if epss_score is not None else 0.0
    if epss > 0.5 or cvss >= 9.0:
        return "HIGH"
    if epss > 0.1 or cvss >= 7.0:
        return "MEDIUM"
    return "LOW"


# --- Risk tier (exploitation-evidence weighted; feeds triage + opportunity badges) ---

RISK_TIER_RANKS = {"critical": 3, "high": 2, "medium": 1, "low": 0}
DEFAULT_EPSS_HIGH_RISK_THRESHOLD = 0.1


def get_epss_high_risk_threshold() -> float:
    """EPSS score at/above which a CVE is considered high risk (configurable)."""
    try:
        val = settings.get("cve_epss_high_risk_threshold")
        return float(val) if val is not None else DEFAULT_EPSS_HIGH_RISK_THRESHOLD
    except (TypeError, ValueError):
        return DEFAULT_EPSS_HIGH_RISK_THRESHOLD


def compute_risk_tier(
    *,
    is_kev: bool = False,
    epss_score: float | None = None,
    metasploit_module: str | None = None,
    github_poc_count: int | None = None,
    cvss_score: float | None = None,
    severity: str | None = None,
    epss_threshold: float | None = None,
) -> str:
    """Derive a simple risk tier weighted by exploitation evidence.

    critical: in CISA KEV (actively exploited)
    high:     EPSS >= threshold (default 0.1) or a Metasploit module exists
    medium:   public PoC on GitHub, or CVSS critical/high severity
    low:      everything else

    CVSS severity alone caps at medium — high/critical tiers are reserved for
    exploitation evidence, per the KEV > EPSS > CVSS prioritization model.
    """
    if is_kev:
        return "critical"
    threshold = epss_threshold if epss_threshold is not None else get_epss_high_risk_threshold()
    if (epss_score or 0.0) >= threshold or metasploit_module:
        return "high"
    cvss = float(cvss_score) if cvss_score is not None else 0.0
    if (github_poc_count or 0) > 0 or cvss >= 9.0:
        return "medium"
    if (severity or "").upper() in ("CRITICAL", "HIGH"):
        return "medium"
    return "low"


def risk_tier_for(cve: CVE, epss_threshold: float | None = None) -> str:
    """Compute the risk tier for a CVE ORM object."""
    return compute_risk_tier(
        is_kev=bool(cve.is_kev),
        epss_score=cve.epss_score,
        metasploit_module=cve.metasploit_module,
        github_poc_count=cve.github_poc_count,
        cvss_score=float(cve.cvss_score) if cve.cvss_score is not None else None,
        severity=cve.severity,
        epss_threshold=epss_threshold,
    )


def risk_tier_rank_expr(epss_threshold: float | None = None):
    """SQL expression ranking CVEs by risk tier (3=critical .. 0=low).

    Mirrors compute_risk_tier so server-side sorting and triage scoring agree
    with the tier shown in the UI.
    """
    from sqlalchemy import case, or_

    threshold = epss_threshold if epss_threshold is not None else get_epss_high_risk_threshold()
    return case(
        (CVE.is_kev.is_(True), 3),
        (or_(CVE.epss_score >= threshold, CVE.metasploit_module.isnot(None)), 2),
        (
            or_(
                CVE.github_poc_count > 0,
                CVE.cvss_score >= 9.0,
                func.upper(CVE.severity).in_(["CRITICAL", "HIGH"]),
            ),
            1,
        ),
        else_=0,
    )


async def extract_and_store_cves(
    db: AsyncSession,
    entry_id: uuid.UUID,
    text: str,
    enrich: bool = True,
) -> list[CVE]:
    """Extract CVE IDs from text, optionally enrich from NVD, and store."""
    cve_ids = extract_cve_ids(text)
    if not cve_ids:
        return []

    stored = []
    freshly_enriched: list[tuple[CVE, list[dict]]] = []
    for cve_id in cve_ids:
        result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
        existing = result.scalar_one_or_none()

        if existing:
            existing.updated_at = datetime.now(UTC)
            # Re-enrich from NVD if key data is still missing (e.g., prior NVD lookup failed)
            if enrich and not existing.cvss_score and not existing.description:
                nvd = await enrich_from_nvd(cve_id)
                if nvd:
                    existing.cvss_score = nvd.get("cvss_score")
                    existing.severity = nvd.get("severity")
                    existing.description = nvd.get("description")
                    existing.affected_products = nvd.get("affected_products", [])
                    existing.references_ = nvd.get("references", [])
                    existing.nvd_data = nvd.get("nvd_data", {})
                    freshly_enriched.append((existing, existing.affected_products))
            cve_obj = existing
        else:
            # An analyst deleted this CVE from the AI entities table — don't
            # mint it again (CVEs bypass resolve_entity_creation).
            from app.intelligence.entity_resolution import is_name_denied

            if await is_name_denied(db, "cve", cve_id):
                logger.info("Skipping CVE %s: on the analyst do-not-recreate list", cve_id)
                continue

            cve_obj = CVE(cve_id=cve_id, created_via="ai_extraction", created_from_entry_id=entry_id)

            # NVD enrichment
            if enrich:
                nvd = await enrich_from_nvd(cve_id)
                if nvd:
                    cve_obj.cvss_score = nvd.get("cvss_score")
                    cve_obj.severity = nvd.get("severity")
                    cve_obj.description = nvd.get("description")
                    cve_obj.affected_products = nvd.get("affected_products", [])
                    cve_obj.references_ = nvd.get("references", [])
                    cve_obj.nvd_data = nvd.get("nvd_data", {})
                    freshly_enriched.append((cve_obj, cve_obj.affected_products))

            db.add(cve_obj)
            await db.flush()

        # Link to entry (atomic upsert — prevents duplicates under concurrency)
        await db.execute(pg_insert(EntryCVE).values(entry_id=entry_id, cve_id=cve_obj.id).on_conflict_do_nothing())

        stored.append(cve_obj)

    await db.flush()

    # Authoritative affects-links from the parsed CPE data (cve_affected table)
    if any(products for _, products in freshly_enriched):
        try:
            index = await build_cpe_index(db)
            for cve_obj, products in freshly_enriched:
                if products:
                    await sync_cve_affected(db, cve_obj.id, products, index)
            await db.flush()
        except Exception:
            logger.exception("cve_affected sync failed")

    # Authoritative weakness links from the same NVD payload (cve_weaknesses).
    # Separate try block: a CPE-index failure must not cost us the CWE links.
    if freshly_enriched:
        try:
            cwe_index = await build_cwe_index(db)
            for cve_obj, _ in freshly_enriched:
                parsed_weaknesses = parse_nvd_weaknesses(cve_obj.nvd_data or {})
                if parsed_weaknesses:
                    await sync_cve_weaknesses(db, cve_obj.id, parsed_weaknesses, cwe_index)
            await db.flush()
        except Exception:
            logger.exception("cve_weaknesses sync failed")

    # Dispatch auto-enrichment for newly created CVEs
    try:
        from app.workers.enrichment_tasks import auto_enrich_entity

        for cve_obj in stored:
            if cve_obj.first_seen_at and (datetime.now(UTC) - cve_obj.first_seen_at).total_seconds() < 5:
                auto_enrich_entity.delay(
                    entity_type="cve",
                    entity_id=str(cve_obj.id),
                    entity_value=cve_obj.cve_id,
                )
    except Exception:
        pass  # Don't fail extraction if enrichment dispatch fails

    return stored
