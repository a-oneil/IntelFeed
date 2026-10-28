"""External intelligence feed ingestion: CISA KEV and Cybergeist."""

import asyncio
import logging
from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.gateway import JOB_TOKEN_WAIT, SOURCE_REFUSALS, SourceGateway
from app.intelligence.entity_resolution import gate_aliases, resolve_entity_creation
from app.models.cve import CVE
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import ThreatActor
from app.services.redis_client import get_redis

logger = logging.getLogger(__name__)

KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_REDIS_KEY = "intelfeed:kev:version"

CYBERGEIST_ACTOR_URL = "https://pubbucket.cybergeist.io/cybergeist.io-threatActor-public-feed.json"
CYBERGEIST_MALWARE_URL = "https://pubbucket.cybergeist.io/cybergeist.io-malware-public-feed.json"
# Two files a day, with no enrichment_sources row to configure them.
CYBERGEIST_GATEWAY = SourceGateway(
    "cybergeist", rate_limit_config={"requests_per_period": 10, "period_seconds": 3600}, max_wait=JOB_TOKEN_WAIT
)

# New KEV CVEs enriched from NVD per sync, and the seconds that may take.
MAX_NVD_ENRICHMENT = 50
NVD_ENRICH_SECONDS = 180


def _parse_kev_date(value: str | None) -> date | None:
    """Parse a KEV catalog date string (YYYY-MM-DD) into a date, or None."""
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def coerce_exploit_sources(sources) -> list[dict]:
    """`cves.exploit_sources` as a list of `{"source": ...}` dicts.

    The column was written as dicts by the KEV sync and, for a while, as bare
    strings by the Metasploit sync — and `.get()` on a string took the KEV
    sync down with it for two weeks. Every writer and reader goes through
    this so one odd row can never break a whole catalog run again.
    """
    out: list[dict] = []
    for item in sources or []:
        if isinstance(item, dict):
            out.append(item)
        elif isinstance(item, str) and item.strip():
            out.append({"source": item.strip()})
    return out


def apply_kev_record(cve_obj: CVE, kev_data: dict) -> bool:
    """Apply a KEV catalog record to a CVE. Returns True if newly added to KEV.

    Sets the first-class KEV columns, appends to exploit_sources, and promotes
    exploit_availability to 'active_exploitation' — unless an analyst manually
    set the exploit status (exploit_status_source == 'manual'), which is never
    overwritten by automated enrichment.
    """
    was_kev = bool(cve_obj.is_kev) or cve_obj.exploit_status == "kev"

    cve_obj.is_kev = True
    cve_obj.kev_date_added = _parse_kev_date(kev_data.get("dateAdded"))
    cve_obj.kev_due_date = _parse_kev_date(kev_data.get("dueDate"))

    existing_sources = coerce_exploit_sources(cve_obj.exploit_sources)
    if not any(s.get("source") == "kev" for s in existing_sources):
        cve_obj.exploit_sources = [*existing_sources, {"source": "kev", **kev_data}]
    elif existing_sources != list(cve_obj.exploit_sources or []):
        cve_obj.exploit_sources = existing_sources

    if cve_obj.exploit_status_source != "manual":
        cve_obj.exploit_status = "kev"
        cve_obj.exploit_availability = "active_exploitation"

    return not was_kev


async def sync_kev_feed(db: AsyncSession) -> dict:
    """Sync CISA Known Exploited Vulnerabilities catalog.

    Returns stats dict with counts of new/updated CVEs.
    """
    from app.enrichment.pipeline import gateway_for

    stats = {"new": 0, "updated": 0, "skipped": 0, "errors": 0, "kev_additions": 0}

    gateway, _ = await gateway_for(db, "cisa_kev", max_wait=JOB_TOKEN_WAIT)
    try:
        async with gateway.client(timeout=30) as client:
            resp = await client.get(KEV_CATALOG_URL)
            resp.raise_for_status()
            catalog = resp.json()
    except SOURCE_REFUSALS as e:
        logger.warning("KEV sync skipped: %s", e)
        return {**stats, "stopped": e.status}

    catalog_version = catalog.get("catalogVersion", "")
    r = await get_redis()
    cached_version = await r.get(KEV_REDIS_KEY)
    if cached_version == catalog_version:
        logger.info("KEV catalog unchanged (version %s), skipping", catalog_version)
        stats["skipped"] = len(catalog.get("vulnerabilities", []))
        return stats

    vulnerabilities = catalog.get("vulnerabilities", [])
    logger.info("Processing %d KEV vulnerabilities (version %s)", len(vulnerabilities), catalog_version)

    # Batch-load existing CVEs for efficiency
    kev_cve_ids = [v.get("cveID") for v in vulnerabilities if v.get("cveID")]
    existing_result = await db.execute(select(CVE).where(CVE.cve_id.in_(kev_cve_ids)))
    existing_map = {cve.cve_id: cve for cve in existing_result.scalars().all()}

    new_cve_ids = []
    # Track CVEs newly added to KEV for correlation events
    kev_addition_cves: list[tuple[str, CVE]] = []  # (cve_id, cve_obj)

    for vuln in vulnerabilities:
        cve_id = vuln.get("cveID")
        if not cve_id:
            continue

        kev_data = {
            "dateAdded": vuln.get("dateAdded"),
            "requiredAction": vuln.get("requiredAction"),
            "dueDate": vuln.get("dueDate"),
            "knownRansomwareCampaignUse": vuln.get("knownRansomwareCampaignUse"),
            "vendorProject": vuln.get("vendorProject"),
            "product": vuln.get("product"),
            "vulnerabilityName": vuln.get("vulnerabilityName"),
            "shortDescription": vuln.get("shortDescription"),
        }

        cve_obj = existing_map.get(cve_id)
        if cve_obj:
            # Update existing CVE with KEV data (never overwrites manual exploit status)
            newly_added = apply_kev_record(cve_obj, kev_data)
            # Store description from KEV if CVE has none
            if not cve_obj.description and kev_data.get("shortDescription"):
                cve_obj.description = kev_data["shortDescription"]
            cve_obj.updated_at = datetime.now(UTC)
            if newly_added:
                kev_addition_cves.append((cve_id, cve_obj))
            stats["updated"] += 1
        else:
            # Create new CVE
            cve_obj = CVE(
                cve_id=cve_id,
                description=kev_data.get("shortDescription"),
                exploit_sources=[],
            )
            apply_kev_record(cve_obj, kev_data)
            db.add(cve_obj)
            existing_map[cve_id] = cve_obj
            new_cve_ids.append(cve_id)
            kev_addition_cves.append((cve_id, cve_obj))
            stats["new"] += 1

    await db.flush()

    # Generate correlation events for new KEV additions
    if kev_addition_cves:
        from app.intelligence.correlation_events import create_kev_addition_event

        for cve_id, cve_obj in kev_addition_cves:
            try:
                await create_kev_addition_event(db, cve_id, cve_obj.id)
                stats["kev_additions"] += 1
            except Exception:
                logger.debug("Failed to create KEV addition event for %s", cve_id, exc_info=True)

    await db.commit()

    # KEV addition changes severity signals on entries already covering the CVE
    if kev_addition_cves:
        from app.workers.signal_tasks import dispatch_cve_rescore

        for _, cve_obj in kev_addition_cves:
            dispatch_cve_rescore(cve_obj.id)

    # Enrich new CVEs from NVD at its pace (5 req/30s without an API key), at
    # most what fits in NVD_ENRICH_SECONDS of the task's 300s limit; the nightly
    # reenrich-cve-nvd job picks up the rest.
    if new_cve_ids:
        from app.intelligence.cve import enrich_from_nvd, nvd_gateway, nvd_request_pace

        nvd_gw, api_key = await nvd_gateway(db)
        pace = nvd_request_pace(api_key)
        enrich_batch = new_cve_ids[: min(MAX_NVD_ENRICHMENT, int(NVD_ENRICH_SECONDS / pace))]
        logger.info(
            "Enriching %d/%d new KEV CVEs from NVD",
            len(enrich_batch),
            len(new_cve_ids),
        )
        for i, cve_id in enumerate(enrich_batch):
            if i:
                await asyncio.sleep(pace)
            try:
                nvd = await enrich_from_nvd(cve_id, nvd_gw, api_key)
            except SOURCE_REFUSALS as e:
                logger.warning("KEV sync: NVD enrichment stopping at %d/%d: %s", i, len(enrich_batch), e)
                stats["stopped"] = e.status
                break
            if nvd:
                cve_obj = existing_map[cve_id]
                cve_obj.cvss_score = nvd.get("cvss_score")
                cve_obj.severity = nvd.get("severity")
                if nvd.get("description"):
                    cve_obj.description = nvd["description"]
                cve_obj.affected_products = nvd.get("affected_products", [])
                cve_obj.references_ = nvd.get("references", [])
                cve_obj.nvd_data = nvd.get("nvd_data", {})

        await db.commit()
    await r.set(KEV_REDIS_KEY, catalog_version)
    logger.info("KEV sync complete: %d new, %d updated", stats["new"], stats["updated"])
    return stats


async def sync_cybergeist_threat_actors(db: AsyncSession) -> dict:
    """Sync threat actors from Cybergeist public feed.

    Returns stats dict and list of newly created actor IDs.
    """
    stats = {"new": 0, "updated": 0, "skipped": 0, "errors": 0}
    new_entity_ids = []

    try:
        async with CYBERGEIST_GATEWAY.client(timeout=30) as client:
            resp = await client.get(CYBERGEIST_ACTOR_URL)
            resp.raise_for_status()
            actors_data = resp.json()
    except SOURCE_REFUSALS as e:
        logger.warning("Cybergeist actors sync skipped: %s", e)
        return {**stats, "stopped": e.status, "new_entity_ids": []}

    if not isinstance(actors_data, list):
        actors_data = actors_data.get("objects", actors_data.get("data", []))

    logger.info("Processing %d Cybergeist threat actors", len(actors_data))

    for actor_data in actors_data:
        # Cybergeist uses "value" (lowercase) and "preferred" (proper case)
        raw_name = actor_data.get("preferred") or actor_data.get("value") or actor_data.get("name", "")
        name = raw_name.strip()
        if not name:
            continue

        # Build alias set: include the lowercase "value" form if different from canonical name
        new_aliases: set[str] = set()
        value_form = actor_data.get("value", "").strip()
        if value_form and value_form.lower() != name.lower():
            new_aliases.add(value_form)

        # Description may be a dict with "text" key or a plain string
        raw_desc = actor_data.get("description")
        desc_text = raw_desc.get("text", "") if isinstance(raw_desc, dict) else (raw_desc or "")

        try:
            # Resolver: exact + normalized lookup, tombstones, creation gates
            # (planning/entity-creation-guardrails.md) — no override for syncs.
            decision = await resolve_entity_creation(db, "threat_actor", name, list(new_aliases), source="cybergeist")
            actor = decision.entity

            cybergeist_meta = {
                "publicUrl": actor_data.get("publicUrl"),
                "stixLink": actor_data.get("stixLink"),
                "description": desc_text[:1000] if desc_text else None,
                "cybergeist_id": actor_data.get("id"),
            }

            if actor:
                # Merge aliases as set union (gated: collisions/junk dropped)
                gated = await gate_aliases(db, "threat_actor", actor.name, sorted(new_aliases), entity_id=actor.id)
                existing_aliases = set(actor.aliases or [])
                merged = sorted(existing_aliases | set(gated))
                if merged != sorted(existing_aliases):
                    actor.aliases = merged
                # Store/update Cybergeist metadata
                meta = actor.metadata_ or {}
                meta["cybergeist"] = cybergeist_meta
                actor.metadata_ = meta

                # Fill in description if empty
                if not actor.description and desc_text:
                    actor.description = desc_text[:2000]

                stats["updated"] += 1
            elif decision.action != "create":
                # Tombstoned cross-type, gate-blocked, or held for adjudication —
                # don't resurrect the shadow the daily sync would otherwise recreate.
                stats["skipped"] += 1
            else:
                actor = ThreatActor(
                    name=name,
                    aliases=await gate_aliases(db, "threat_actor", name, sorted(new_aliases)),
                    description=desc_text[:2000] if desc_text else None,
                    metadata_={"cybergeist": cybergeist_meta},
                )
                db.add(actor)
                await db.flush()
                new_entity_ids.append(str(actor.id))
                stats["new"] += 1
        except Exception:
            logger.exception("Error processing Cybergeist actor: %s", name)
            stats["errors"] += 1

    await db.commit()
    logger.info(
        "Cybergeist actors sync: %d new, %d updated, %d skipped, %d errors",
        stats["new"],
        stats["updated"],
        stats["skipped"],
        stats["errors"],
    )
    return {**stats, "new_entity_ids": new_entity_ids}


async def sync_cybergeist_malware(db: AsyncSession) -> dict:
    """Sync malware families from Cybergeist public feed.

    Returns stats dict and list of newly created malware IDs.
    """
    stats = {"new": 0, "updated": 0, "skipped": 0, "errors": 0}
    new_entity_ids = []

    try:
        async with CYBERGEIST_GATEWAY.client(timeout=30) as client:
            resp = await client.get(CYBERGEIST_MALWARE_URL)
            resp.raise_for_status()
            malware_data = resp.json()
    except SOURCE_REFUSALS as e:
        logger.warning("Cybergeist malware sync skipped: %s", e)
        return {**stats, "stopped": e.status, "new_entity_ids": []}

    if not isinstance(malware_data, list):
        malware_data = malware_data.get("objects", malware_data.get("data", []))

    logger.info("Processing %d Cybergeist malware families", len(malware_data))

    for entry in malware_data:
        # Cybergeist uses "value" (lowercase) and "preferred" (proper case)
        raw_name = entry.get("preferred") or entry.get("value") or entry.get("name", "")
        name = raw_name.strip()
        if not name:
            continue

        # Build alias set: include the lowercase "value" form if different from canonical name
        new_aliases: set[str] = set()
        value_form = entry.get("value", "").strip()
        if value_form and value_form.lower() != name.lower():
            new_aliases.add(value_form)

        # Description may be a dict with "text" key or a plain string
        raw_desc = entry.get("description")
        desc_text = raw_desc.get("text", "") if isinstance(raw_desc, dict) else (raw_desc or "")

        try:
            # Resolver: exact + normalized lookup, tombstones, creation gates
            # (planning/entity-creation-guardrails.md) — no override for syncs.
            decision = await resolve_entity_creation(db, "malware", name, list(new_aliases), source="cybergeist")
            malware = decision.entity

            cybergeist_meta = {
                "publicUrl": entry.get("publicUrl"),
                "stixLink": entry.get("stixLink"),
                "description": desc_text[:1000] if desc_text else None,
                "cybergeist_id": entry.get("id"),
            }

            if malware:
                # Merge aliases as set union (gated: collisions/junk dropped)
                gated = await gate_aliases(db, "malware", malware.name, sorted(new_aliases), entity_id=malware.id)
                existing_aliases = set(malware.aliases or [])
                merged = sorted(existing_aliases | set(gated))
                if merged != sorted(existing_aliases):
                    malware.aliases = merged
                # Store/update Cybergeist metadata
                meta = malware.metadata_ or {}
                meta["cybergeist"] = cybergeist_meta
                malware.metadata_ = meta

                if not malware.description and desc_text:
                    malware.description = desc_text[:2000]

                stats["updated"] += 1
            elif decision.action != "create":
                # Tombstoned cross-type, gate-blocked, or held for adjudication —
                # don't let the daily sync recreate it.
                stats["skipped"] += 1
            else:
                malware = MalwareFamily(
                    name=name,
                    aliases=await gate_aliases(db, "malware", name, sorted(new_aliases)),
                    description=desc_text[:2000] if desc_text else None,
                    metadata_={"cybergeist": cybergeist_meta},
                )
                db.add(malware)
                await db.flush()
                new_entity_ids.append(str(malware.id))
                stats["new"] += 1
        except Exception:
            logger.exception("Error processing Cybergeist malware: %s", name)
            stats["errors"] += 1

    await db.commit()
    logger.info(
        "Cybergeist malware sync: %d new, %d updated, %d skipped, %d errors",
        stats["new"],
        stats["updated"],
        stats["skipped"],
        stats["errors"],
    )
    return {**stats, "new_entity_ids": new_entity_ids}
