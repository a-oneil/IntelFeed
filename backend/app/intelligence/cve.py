"""CVE extraction and NVD enrichment."""

import logging
import re
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import Integer, and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.enrichment.gateway import MAX_TOKEN_WAIT, GatewayError, SourceGateway
from app.intelligence.cpe_resolver import CPEIndex, build_cpe_index
from app.models.cve import CVE, EntryCVE
from app.models.cve_affected import CVEAffected
from app.models.cwe import CWE, CVEWeakness

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
# A CVE id with a decimal glued on: a table's CVSS column run into the id
# column by HTML stripping ("CVE-2026-103849" + "10.0" → "CVE-2026-10384910.0").
_CVE_GLUED_SCORE_RE = re.compile(r"CVE-(\d{4})-(\d{4,})(?=\.\d)")
# Real sequence numbers run to six digits, seven in the 1000000+ block the
# DWF and a few CNAs issue. Eight or more is two numbers glued together.
CVE_MAX_SEQUENCE_DIGITS = 7

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Seconds per request inside NVD's rolling window: 5 req/30s unkeyed, 50 req/30s
# with an API key. The NVD source's gateway enforces the window; these only
# size work (how many lookups fit in a run).
NVD_PACE_UNKEYED = 6.5
NVD_PACE_KEYED = 0.7

# NVD sweeps stop asking about an id after this many misses, spaced at least
# NVD_RETRY_DAYS apart. A miss is stamped into nvd_data, so a junk id pulled
# out of prose (a typo, a placeholder like CVE-2024-XXXXX's digits, a reserved
# id that never publishes) costs three lookups, not one a night forever.
NVD_MAX_ATTEMPTS = 3
NVD_RETRY_DAYS = 7


def nvd_retry_allowed(now: datetime):
    """SQL predicate: the CVE has NVD lookups left and none in the last week."""
    attempts = CVE.nvd_data["_enrich_attempts"].astext.cast(Integer)
    last_attempt = CVE.nvd_data["_enrich_last_attempt"].astext
    retry_cutoff = (now - timedelta(days=NVD_RETRY_DAYS)).isoformat()
    return or_(
        CVE.nvd_data.is_(None),
        ~CVE.nvd_data.has_key("_enrich_attempts"),
        and_(attempts < NVD_MAX_ATTEMPTS, last_attempt < retry_cutoff),
    )


def stamp_nvd_miss(cve: CVE, now: datetime) -> None:
    """Record that NVD had nothing for this CVE (counts against its retries)."""
    blob = dict(cve.nvd_data or {})
    blob["_enrich_attempts"] = int(blob.get("_enrich_attempts") or 0) + 1
    blob["_enrich_last_attempt"] = now.isoformat()
    cve.nvd_data = blob


def nvd_request_pace(api_key: str | None) -> float:
    """Seconds one NVD request takes of the rolling window, for sizing a run.
    Nothing sleeps on it: the gateway paces the requests."""
    return NVD_PACE_KEYED if api_key else NVD_PACE_UNKEYED


async def nvd_gateway(db: AsyncSession, max_wait: float = MAX_TOKEN_WAIT) -> tuple[SourceGateway, str | None]:
    """The NVD source's gateway and key (the source row's key, else the
    instance-wide ``nvd_api_key`` setting)."""
    from app.enrichment.pipeline import gateway_for

    return await gateway_for(db, "nvd", max_wait=max_wait)


def is_plausible_cve_id(cve_id: str) -> bool:
    """Whether a ``CVE-YYYY-N`` string can be a real id.

    Rejects sequences longer than seven digits and five-plus-digit sequences
    with a leading zero (the CVE syntax only zero-pads to four)."""
    m = re.fullmatch(r"CVE-(\d{4})-(\d{4,})", cve_id or "")
    if not m:
        return False
    seq = m.group(2)
    if len(seq) > CVE_MAX_SEQUENCE_DIGITS:
        return False
    return not (len(seq) > 4 and seq.startswith("0"))


def _strip_glued_score(seq: str, after_dot: str) -> str | None:
    """The real sequence when a CVSS score's integer part was glued onto it.

    ``after_dot`` is the digit after the decimal point. "10" + ".0" is the
    10.0 score; otherwise the last digit is the score's integer part. None
    when what's left can't be a sequence."""
    tail = 2 if seq.endswith("10") and after_dot == "0" else 1
    head = seq[:-tail]
    if len(head) < 4 or (len(head) > 4 and head.startswith("0")):
        return None
    return head


def extract_cve_ids(text: str) -> list[str]:
    """Extract CVE IDs from text using regex.

    An id followed by ``.<digit>`` is a CVSS score glued onto it (a table
    whose cells lost their separator): the score's integer part is dropped
    and the real id kept. Implausible ids are skipped, as is a seven-digit id
    whose six-digit prefix the same text names on its own (the prefix plus a
    glued score digit)."""
    if not text:
        return []
    ids: set[str] = set()
    glued_at: set[int] = set()
    for m in _CVE_GLUED_SCORE_RE.finditer(text):
        glued_at.add(m.start())
        head = _strip_glued_score(m.group(2), text[m.end() + 1])
        if head:
            ids.add(f"CVE-{m.group(1)}-{head}")
    for m in CVE_PATTERN.finditer(text):
        if m.start() not in glued_at:
            ids.add(m.group())
    out = {i for i in ids if is_plausible_cve_id(i)}
    return [i for i in out if not (set(glued_score_prefixes(i)) & out)]


def glued_score_prefixes(cve_id: str) -> list[str]:
    """The ids a seven-digit CVE id could be with a CVSS integer glued on.

    Empty for ids of six digits or fewer and for the real 1000000+ block.
    Used to drop the long form when its prefix is named in the same text or
    already stored."""
    year, seq = cve_id.split("-")[1:3]
    if len(seq) != CVE_MAX_SEQUENCE_DIGITS or seq.startswith("1000"):
        return []
    out = [f"CVE-{year}-{seq[:-1]}"]
    if seq.endswith("10"):
        out.append(f"CVE-{year}-{seq[:-2]}")
    return out


async def enrich_from_nvd(cve_id: str, gateway: SourceGateway, api_key: str | None = None) -> dict | None:
    """Fetch CVE details from NVD API 2.0 through the NVD source's gateway.

    Returns None when NVD has nothing for the id or the request failed. A
    gateway refusal (throttled, breaker open, budget spent) raises, so callers
    can tell "NVD has nothing" from "not now".
    """
    headers = {"apiKey": api_key} if api_key else {}
    try:
        async with gateway.client(timeout=15) as client:
            resp = await client.get(NVD_API_URL, params={"cveId": cve_id}, headers=headers)
        if resp.status_code != 200:
            logger.warning(f"NVD returned {resp.status_code} for {cve_id}")
            return None
        data = resp.json()
    except GatewayError:
        raise
    except Exception as e:
        logger.warning(f"NVD enrichment failed for {cve_id}: {e}")
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    return parse_nvd_record(vulns[0].get("cve", {}))


#: Records per page of a change window: the most NVD returns in one answer.
NVD_PAGE = 2000
#: The longest window one change query may cover (NVD's limit).
NVD_MAX_WINDOW = timedelta(days=120)


def _nvd_time(at: datetime) -> str:
    return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


async def fetch_nvd_changes(
    start: datetime, end: datetime, gateway: SourceGateway, api_key: str | None = None, start_index: int = 0
) -> tuple[list[dict], int]:
    """One page of the NVD records last modified between ``start`` and
    ``end`` (at most ``NVD_MAX_WINDOW`` apart), parsed as ``enrich_from_nvd``
    parses one, and how many the whole window holds. A failed request raises:
    a window read in part must not count as read."""
    headers = {"apiKey": api_key} if api_key else {}
    params = {
        "lastModStartDate": _nvd_time(start),
        "lastModEndDate": _nvd_time(end),
        "resultsPerPage": NVD_PAGE,
        "startIndex": start_index,
    }
    async with gateway.client(timeout=60) as client:
        resp = await client.get(NVD_API_URL, params=params, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    records = [parse_nvd_record(v["cve"]) for v in data.get("vulnerabilities", []) if v.get("cve", {}).get("id")]
    return records, int(data.get("totalResults") or 0)


def parse_nvd_record(cve_data: dict) -> dict:
    """One NVD CVE record (``vulnerabilities[].cve``) as the values IntelFeed
    keeps: score, severity, description, affected products, references, and
    the record itself as ``nvd_data``."""
    # Extract CVSS v3.1 score
    cvss_score = None
    severity = None
    vector = None
    metrics = cve_data.get("metrics", {})
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = (cvss_data.get("baseSeverity") or metric_list[0].get("baseSeverity") or "").upper()
            vector = cvss_data.get("vectorString")
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
        "cvss_vector": vector,
        "description": description,
        "affected_products": affected_products,
        "references": references,
        "nvd_data": cve_data,
    }


async def apply_nvd_record(db: AsyncSession, cve: CVE, nvd: dict, cache: dict | None = None) -> int:
    """Write what an NVD record carries beyond the field map's columns (score,
    severity and description go through the NVD source's outputs): the record
    itself, affected products and references, its cve_affected and
    cve_weaknesses links. ``cache`` holds the CPE and CWE indexes across the
    CVEs of one run. Returns the affected pairs written."""
    cache = {} if cache is None else cache
    blob = dict(nvd.get("nvd_data") or {})
    # Keep the sweeps' own stamps; a hit ends the miss count.
    for key in ("_refreshed_at", "_enrich_last_attempt"):
        if key in (cve.nvd_data or {}) and key not in blob:
            blob[key] = cve.nvd_data[key]
    cve.nvd_data = blob
    if nvd.get("references"):
        cve.references_ = nvd["references"]
    products = nvd.get("affected_products") or []
    pairs = 0
    if products:
        cve.affected_products = products
        if "cpe_index" not in cache:
            cache["cpe_index"] = await build_cpe_index(db)
        pairs = await sync_cve_affected(db, cve.id, products, cache["cpe_index"])
    weaknesses = parse_nvd_weaknesses(blob)
    if weaknesses:
        if "cwe_index" not in cache:
            cache["cwe_index"] = await build_cwe_index(db)
        await sync_cve_weaknesses(db, cve.id, weaknesses, cache["cwe_index"])
    db.add(cve)
    return pairs


async def adopt_nvd_values(db: AsyncSession, cve: CVE) -> None:
    """Claim for NVD the score, severity and description it wrote before
    claims were recorded: a value that matches the stored NVD record is NVD's,
    so the field map lets NVD update it."""
    from app.services.claim_provenance import record_claim

    if not (cve.nvd_data or {}).get("id"):
        return
    old = parse_nvd_record(cve.nvd_data)
    for field in ("cvss_score", "severity", "description"):
        current, was = getattr(cve, field), old.get(field)
        if current is None or was is None:
            continue
        same = float(current) == float(was) if field == "cvss_score" else str(current) == str(was)
        if same:
            await record_claim(
                db,
                entity_type="cve",
                entity_id=cve.id,
                field=field,
                value=current,
                source_kind="enrichment",
                source_ref="nvd",
            )


async def apply_nvd(db: AsyncSession, cve: CVE, nvd: dict, cache: dict | None = None, via: str = "job"):
    """An NVD answer from a sweep, applied as a lookup's would be: the record's
    extra writes (``apply_nvd_record``), then the NVD source's result stored,
    its context written and its columns applied through the field map.
    Returns the pipeline's ``Applied``."""
    from app.enrichment.adapters.nvd import nvd_result
    from app.enrichment.pipeline import apply_source_result

    await adopt_nvd_values(db, cve)
    await apply_nvd_record(db, cve, nvd, cache)
    return await apply_source_result(db, "cve", cve.id, "nvd", nvd_result(nvd, via=via), cache)


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
    source: str = "nvd",
) -> int:
    """Upsert cve_affected rows for a CVE from parsed CPE pairs.

    Idempotent on (cve_id, cpe_vendor, cpe_product). Existing rows get version
    ranges refreshed and null FKs filled when the pair now resolves — resolved
    FKs are never cleared by a later non-resolving pass. A pair keeps the
    source that first recorded it: another source's pass leaves its versions
    alone. A pair from a source other than NVD whose product (or, with no
    product, vendor) resolves to one the CVE already has a row for is skipped,
    so a CNA's "Palo Alto Networks / PAN-OS" doesn't repeat NVD's
    "paloaltonetworks / pan-os".
    """
    held: set = set()
    if source != "nvd":
        held = {
            pid or vid
            for pid, vid in (
                await db.execute(
                    select(CVEAffected.product_id, CVEAffected.vendor_id).where(CVEAffected.cve_id == cve_pk)
                )
            ).all()
            if pid or vid
        }
    count = 0
    seen: set[tuple[str, str]] = set()
    for item in affected_products:
        cpe_vendor = (item.get("vendor") or "").strip().lower()
        cpe_product = (item.get("product") or "").strip().lower()
        if not cpe_vendor or not cpe_product or (cpe_vendor, cpe_product) in seen:
            continue
        seen.add((cpe_vendor, cpe_product))
        vendor_id, product_id = index.resolve_pair(cpe_vendor, cpe_product)
        if source != "nvd" and (product_id or vendor_id) in held - {None}:
            continue
        held.add(product_id or vendor_id)
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
            source=source,
            resolved_at=resolved_at,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_cve_affected_pair",
            where=CVEAffected.source == stmt.excluded.source,
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
    source: str = "nvd",
) -> int:
    """Upsert cve_weaknesses rows for a CVE from parsed weakness records (NVD's,
    or the CNA's from its CVE record, ``source="cvelist"``).

    Idempotent on (cve_id, cwe_ref); a pair keeps the source that first
    recorded it. Mirrors sync_cve_affected: the raw ref is always stored, the
    FK is filled only when it resolves, and a resolved FK is never cleared by a
    later pass.
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
            source=source,
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


async def _lookup_pending(db: AsyncSession, cve_id: uuid.UUID) -> bool:
    """Whether a lookup of the CVE is already queued or running."""
    from app.models.enrichment import EnrichmentJob

    found = await db.scalar(
        select(EnrichmentJob.id)
        .where(
            EnrichmentJob.entity_type == "cve",
            EnrichmentJob.entity_id == cve_id,
            EnrichmentJob.status.in_(("queued", "running")),
        )
        .limit(1)
    )
    return found is not None


async def extract_and_store_cves(
    db: AsyncSession,
    entry_id: uuid.UUID,
    text: str,
    enrich: bool = True,
) -> list[CVE]:
    """Extract CVE IDs from text, store them and link them to the entry.

    Nothing here calls a source. A new CVE, or one whose score and
    description are both still missing, is queued for lookup (the ``new``
    lane), so the enrichment queue applies each source's switch, trigger mode,
    rate limit and budget; NVD's answer fills the CVE from there.
    """
    cve_ids = extract_cve_ids(text)
    if not cve_ids:
        return []

    from app.enrichment.queue import enqueue

    stored = []
    to_enqueue: list[CVE] = []
    for cve_id in cve_ids:
        result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
        existing = result.scalar_one_or_none()

        if existing:
            existing.updated_at = datetime.now(UTC)
            # Ask again while key data is still missing (a prior lookup was
            # refused, or the sources are off), unless a lookup is already waiting.
            if (
                enrich
                and not existing.cvss_score
                and not existing.description
                and not await _lookup_pending(db, existing.id)
            ):
                to_enqueue.append(existing)
            cve_obj = existing
        else:
            # An analyst deleted this CVE from the AI entities table — don't
            # mint it again (CVEs bypass resolve_entity_creation).
            from app.intelligence.entity_resolution import is_name_denied

            if await is_name_denied(db, "cve", cve_id):
                logger.info("Skipping CVE %s: on the analyst do-not-recreate list", cve_id)
                continue
            # A new seven-digit id whose six-digit prefix is a stored CVE is
            # that CVE with a glued CVSS digit, not a new one.
            prefixes = glued_score_prefixes(cve_id)
            if prefixes and await db.scalar(select(CVE.id).where(CVE.cve_id.in_(prefixes)).limit(1)):
                logger.info("Skipping CVE %s: a stored CVE plus a glued score digit", cve_id)
                continue

            cve_obj = CVE(cve_id=cve_id, created_via="ai_extraction", created_from_entry_id=entry_id)
            db.add(cve_obj)
            await db.flush()
            if enrich:
                to_enqueue.append(cve_obj)

        # Link to entry (atomic upsert — prevents duplicates under concurrency)
        await db.execute(pg_insert(EntryCVE).values(entry_id=entry_id, cve_id=cve_obj.id).on_conflict_do_nothing())

        stored.append(cve_obj)

    await db.flush()

    for cve_obj in to_enqueue:
        await enqueue(db, "cve", cve_obj.id, cve_obj.cve_id)

    return stored
