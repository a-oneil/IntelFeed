"""Celery tasks for the enrichment sources' scheduled jobs — EPSS, MITRE ATT&CK,
MISP Galaxy, Malpedia, Metasploit, NVD, GitHub PoC, Wikipedia, cvelistV5."""

import csv
import io
import itertools
import logging
import re
import time
from collections.abc import Iterator
from datetime import UTC, datetime

from sqlalchemy import bindparam, select, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID

from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.enrichment.gateway import JOB_TOKEN_WAIT, SOURCE_REFUSALS, GatewayError, GatewayUnavailable, SourceGateway
from app.intelligence.autolinker import filter_aliases
from app.intelligence.entity_dedup import find_entity_by_name_or_alias
from app.workers.celery_app import celery_app
from app.workers.db import run_async, source_job, worker_session

logger = logging.getLogger(__name__)


def _get_worker_session():
    return worker_session()


async def _job_gateway(source_type: str) -> tuple[SourceGateway, str | None]:
    """A scheduled job's gateway and key: its source row's bucket, budget and
    breaker, the same ones its per-entity lookups use."""
    from app.enrichment.pipeline import gateway_for

    async with _get_worker_session() as db:
        return await gateway_for(db, source_type, max_wait=JOB_TOKEN_WAIT)


def iter_epss_csv(text: str) -> Iterator[tuple[str, float, float]]:
    """Yield (cve_id, epss_score, percentile) rows from the FIRST EPSS daily CSV.

    The CSV starts with one or more comment lines (#model_version...) before
    the "cve,epss,percentile" header; rows with malformed scores are skipped.
    """
    lines = io.StringIO(text)
    for line in lines:
        if line.startswith("cve,"):
            header = line.strip().split(",")
            break
    else:
        return

    for row in csv.DictReader(lines, fieldnames=header):
        cve_id = (row.get("cve") or "").strip()
        if not cve_id.startswith("CVE-"):
            continue
        try:
            yield cve_id, float(row.get("epss", 0)), float(row.get("percentile", 0))
        except (TypeError, ValueError):
            continue


def _cvss_tier_rank(score: float) -> int:
    """Rank CVSS v3 severity tiers: none=0, low=1, medium=2, high=3, critical=4."""
    if score >= 9.0:
        return 4
    if score >= 7.0:
        return 3
    if score >= 4.0:
        return 2
    if score > 0:
        return 1
    return 0


# --- Scheduled enrichment tasks ---


@celery_app.task(name="app.workers.enrichment_tasks.run_epss_bulk_sync", soft_time_limit=900, time_limit=960)
def run_epss_bulk_sync():
    """Daily: download EPSS CSV, update all CVEs."""
    start = time.monotonic()
    try:
        stats = run_async(_run_epss_bulk_sync())
        logger.info("EPSS bulk sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_epss_bulk_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_epss_bulk_sync", status="error").inc()
        logger.exception("EPSS bulk sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_epss_bulk_sync").observe(time.monotonic() - start)


EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

# CSV rows applied per UPDATE, each chunk its own transaction: no CVE ORM
# objects are loaded, and a run holds a bounded set of row locks.
_EPSS_CHUNK_SIZE = 5000


@source_job("epss")
async def _run_epss_bulk_sync():
    import gzip
    from datetime import timedelta

    from app.intelligence.correlation_events import create_cve_score_change_event
    from app.models.enrichment import EnrichmentSource
    from app.workers.signal_tasks import dispatch_cve_rescore

    stats = {"updated": 0, "total_scores": 0, "score_changes": 0}

    gateway, _ = await _job_gateway("epss")
    try:
        async with gateway.client(timeout=120.0, follow_redirects=True) as client:
            resp = await client.get(EPSS_CSV_URL)
            resp.raise_for_status()
    except SOURCE_REFUSALS as e:
        logger.warning("EPSS bulk sync skipped: %s", e)
        return {**stats, "stopped": e.status}
    csv_text = gzip.decompress(resp.content).decode("utf-8")

    now = datetime.now(UTC)
    sql_params = {
        "now": now,
        "expires": now + timedelta(hours=24),
        "date_str": now.strftime("%Y-%m-%d"),
    }

    # Significant change: the score jumped by >= 0.1 (absolute) or crossed the
    # 0.5 threshold (high exploitation probability). Columns read in SET are the
    # pre-update row, so c.epss_score is the score being replaced. The epss_jump
    # signal reads epss_previous_score/epss_changed_at; epss_updated_at can't
    # serve since every sync touches it, change or not.
    significant = (
        "c.epss_score IS NOT NULL AND (abs(i.score - c.epss_score) >= 0.1 OR (c.epss_score < 0.5 AND i.score >= 0.5))"
    )
    update_cves = text(
        f"""
        UPDATE cves c
        SET epss_score = i.score,
            epss_percentile = i.pct,
            epss_updated_at = :now,
            epss_previous_score = CASE WHEN {significant} THEN c.epss_score ELSE c.epss_previous_score END,
            epss_changed_at = CASE WHEN {significant} THEN :now ELSE c.epss_changed_at END,
            updated_at = now()
        FROM unnest(CAST(:cve_ids AS text[]), CAST(:scores AS float8[]), CAST(:pcts AS float8[]))
            AS i(cve_id, score, pct)
        WHERE c.cve_id = i.cve_id
        RETURNING c.id, c.cve_id, c.epss_previous_score, c.epss_score, c.epss_changed_at = :now AS changed
        """
    )
    # Upsert enrichment_results set-based: overwrite the existing EPSS row per
    # CVE, insert only for CVEs that don't have one yet. parsed_data has the
    # lookup adapter's keys (EPSSAdapter), so both read as one source. The old per-CVE append
    # grew this table to ~40 rows per CVE (pruned in migration m2a2b3c4d5g9).
    ids_param = bindparam("ids", type_=ARRAY(UUID(as_uuid=True)))
    update_results = text(
        """
        UPDATE enrichment_results er
        SET raw_response = jsonb_build_object(
                'epss_score', c.epss_score, 'percentile', c.epss_percentile),
            parsed_data = jsonb_build_object(
                'cve', c.cve_id, 'epss', c.epss_score,
                'percentile', c.epss_percentile, 'date', CAST(:date_str AS text)),
            enriched_at = :now, expires_at = :expires, status = 'success'
        FROM cves c
        WHERE c.id = er.entity_id
          AND er.entity_type = 'cve' AND er.source_type = 'epss'
          AND c.id = ANY(:ids)
        """
    ).bindparams(ids_param)
    insert_results = text(
        """
        INSERT INTO enrichment_results
            (id, entity_type, entity_id, source_type, raw_response,
             parsed_data, enriched_at, expires_at, status)
        SELECT gen_random_uuid(), 'cve', c.id, 'epss',
               jsonb_build_object(
                   'epss_score', c.epss_score, 'percentile', c.epss_percentile),
               jsonb_build_object(
                   'cve', c.cve_id, 'epss', c.epss_score,
                   'percentile', c.epss_percentile, 'date', CAST(:date_str AS text)),
               :now, :expires, 'success'
        FROM cves c
        WHERE c.id = ANY(:ids)
          AND NOT EXISTS (
              SELECT 1 FROM enrichment_results er
              WHERE er.entity_id = c.id
                AND er.entity_type = 'cve' AND er.source_type = 'epss')
        """
    ).bindparams(ids_param)

    async with _get_worker_session() as db:
        for chunk in itertools.batched(iter_epss_csv(csv_text), _EPSS_CHUNK_SIZE):
            stats["total_scores"] += len(chunk)
            cve_ids, scores, pcts = (list(col) for col in zip(*chunk, strict=True))
            rows = (
                await db.execute(update_cves, {"now": now, "cve_ids": cve_ids, "scores": scores, "pcts": pcts})
            ).all()
            if not rows:
                continue
            stats["updated"] += len(rows)

            matched_ids = [row.id for row in rows]
            await db.execute(update_results, {**sql_params, "ids": matched_ids})
            await db.execute(insert_results, {**sql_params, "ids": matched_ids})

            # Correlation events for significant changes; rescores go out after
            # the commit so the worker reads the new score.
            increased = []
            for cve_uuid, cve_id_str, old_score, new_score, changed in rows:
                if not changed:
                    continue
                try:
                    await create_cve_score_change_event(db, cve_id_str, cve_uuid, "epss_score", old_score, new_score)
                    stats["score_changes"] += 1
                except Exception:
                    logger.debug("Failed to create EPSS change event for %s", cve_id_str, exc_info=True)
                if new_score > old_score:
                    increased.append(cve_uuid)

            await db.commit()
            for cve_uuid in increased:
                dispatch_cve_rescore(cve_uuid)

        # Update source last_synced_at
        source_result = await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "epss"))
        source = source_result.scalar_one_or_none()
        if source:
            source.last_synced_at = now
            source.health_status = "healthy"
            db.add(source)

        await db.commit()

    return stats


@celery_app.task(name="app.workers.enrichment_tasks.run_mitre_attack_sync", soft_time_limit=900, time_limit=960)
def run_mitre_attack_sync():
    """Weekly: download the MITRE ATT&CK STIX bundles (Enterprise + Mobile + ICS),
    hydrate the technique/mitigation catalog, and map groups to threat actors."""
    start = time.monotonic()
    try:
        stats = run_async(_run_mitre_attack_sync())
        logger.info("MITRE ATT&CK sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_mitre_attack_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_mitre_attack_sync", status="error").inc()
        logger.exception("MITRE ATT&CK sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_mitre_attack_sync").observe(time.monotonic() - start)


@source_job("mitre_attack")
async def _run_mitre_attack_sync():
    from app.intelligence.attack_catalog import (
        fetch_attack_bundles,
        hydrate_attack_catalog,
        hydrate_attack_entity_attributes,
        parse_attack_bundle,
    )
    from app.models.enrichment import EnrichmentSource

    async with _get_worker_session() as db:
        try:
            bundles = await fetch_attack_bundles(db)
        except SOURCE_REFUSALS as e:
            logger.warning("MITRE ATT&CK sync skipped: %s", e)
            return {"stopped": e.status}
        parsed = [parse_attack_bundle(bundle, domain) for domain, bundle in bundles.items()]

        # Full catalog hydration (Enterprise + Mobile + ICS): techniques with
        # tactics/platforms/parents/deprecation flags, mitigations, and
        # TTP-mitigation links. Updates existing rows in place so stub rows
        # (technique_name == technique_id) get backfilled.
        stats: dict = await hydrate_attack_catalog(db, parsed)

        # Fill blank profile fields on existing actors / malware / tools from the
        # same bundle — mitre_id, description, aliases, platforms. Matches by
        # name OR alias (so a merged actor still resolves when MITRE names it by
        # an alias) and never creates an entity.
        stats["entity_attributes"] = await hydrate_attack_entity_attributes(db, parsed)

        alias_map_items: list[tuple[str, list[str]]] = []
        for parsed_bundle in parsed:
            for obj in parsed_bundle.intrusion_sets:
                name = obj.get("name", "")
                if name:
                    alias_map_items.append((name, [a for a in obj.get("aliases", []) if isinstance(a, str)]))

        # Refresh the reference alias knowledge (guardrails Phase 4) from the
        # same intrusion sets — the resolver uses these synonym clusters to
        # resolve vendor names to existing profiles without an AI call.
        from app.intelligence.entity_resolution import upsert_known_aliases

        stats["alias_map_rows"] = await upsert_known_aliases(db, "mitre_attack", alias_map_items)

        # Import MITRE's curated `uses` relationships (group→software/technique,
        # software→technique) as confirmed external_feed edges onto entities
        # that already exist — the authority layer of the trust ladder.
        from app.intelligence.attack_catalog import sync_attack_relationships

        stats["relationships"] = await sync_attack_relationships(db, parsed)

        # Update source
        source_result = await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "mitre_attack"))
        source = source_result.scalar_one_or_none()
        if source:
            source.last_synced_at = datetime.now(UTC)
            source.health_status = "healthy"
            db.add(source)

        await db.commit()

    return stats


MISP_GALAXY_THREAT_ACTOR_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"


def parse_misp_galaxy_clusters(data: dict) -> list[tuple[str, list[str]]]:
    """Extract (canonical_name, synonyms) pairs from a MISP Galaxy cluster file."""
    items: list[tuple[str, list[str]]] = []
    for value in data.get("values") or []:
        if not isinstance(value, dict):
            continue
        name = (value.get("value") or "").strip()
        if not name:
            continue
        synonyms = [s.strip() for s in (value.get("meta") or {}).get("synonyms") or [] if isinstance(s, str)]
        items.append((name, [s for s in synonyms if s]))
    return items


def parse_misp_galaxy_attributes(data: dict) -> dict[str, dict]:
    """Extract profile attributes MISP Galaxy publishes beyond the synonym list.

    The cluster file we already download weekly carries origin country on ~480
    clusters, target sectors on ~190, and a motive on the rest — the same three
    fields the actor profile leaves blank most of the time. Only `meta.synonyms`
    was ever read.

    Returns {canonical_name: {"country", "sectors", "motivation", "description"}}
    with only the keys that actually had a value.
    """
    out: dict[str, dict] = {}
    for value in data.get("values") or []:
        if not isinstance(value, dict):
            continue
        name = (value.get("value") or "").strip()
        if not name:
            continue
        meta = value.get("meta") or {}
        attrs: dict = {}

        if meta.get("country"):
            attrs["country"] = str(meta["country"]).strip()

        # cfr-target-category is the broader of the two sector fields; merge both.
        sectors: list[str] = []
        for key in ("cfr-target-category", "targeted-sector"):
            raw = meta.get(key)
            if isinstance(raw, str):
                sectors.append(raw)
            elif isinstance(raw, list):
                sectors.extend(s for s in raw if isinstance(s, str))
        if sectors:
            attrs["sectors"] = sectors

        # `motive` is sparse; cfr-type-of-incident ("Espionage") covers far more.
        motive = meta.get("motive") or meta.get("cfr-type-of-incident")
        if motive:
            attrs["motivation"] = str(motive) if isinstance(motive, str) else ", ".join(str(m) for m in motive)

        if value.get("description"):
            attrs["description"] = str(value["description"]).strip()

        if attrs:
            out[name] = attrs
    return out


@celery_app.task(name="app.workers.enrichment_tasks.run_misp_galaxy_sync", soft_time_limit=300, time_limit=360)
def run_misp_galaxy_sync():
    """Weekly: refresh the known_alias_map from the MISP Galaxy threat-actor cluster.

    Reference knowledge only (guardrails Phase 4) — routes entity resolution;
    never writes aliases onto profiles."""
    start = time.monotonic()
    try:
        stats = run_async(_run_misp_galaxy_sync())
        logger.info("MISP Galaxy sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_misp_galaxy_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_misp_galaxy_sync", status="error").inc()
        logger.exception("MISP Galaxy sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_misp_galaxy_sync").observe(time.monotonic() - start)


@source_job("misp_galaxy")
async def _run_misp_galaxy_sync():
    from app.intelligence.entity_resolution import upsert_known_aliases

    gateway, _ = await _job_gateway("misp_galaxy")
    try:
        async with gateway.client(timeout=60, follow_redirects=True) as client:
            resp = await client.get(MISP_GALAXY_THREAT_ACTOR_URL)
            resp.raise_for_status()
            data = resp.json()
    except SOURCE_REFUSALS as e:
        logger.warning("MISP Galaxy sync skipped: %s", e)
        return {"stopped": e.status}

    items = parse_misp_galaxy_clusters(data)
    if not items:
        # An empty/garbled feed must not wipe the existing knowledge.
        logger.warning("MISP Galaxy threat-actor cluster returned no values; keeping existing alias map")
        return {"clusters": 0, "alias_rows": 0, "skipped": True}

    attributes = parse_misp_galaxy_attributes(data)

    async with _get_worker_session() as db:
        rows = await upsert_known_aliases(db, "misp_galaxy", items)

        # The synonym clusters stay resolution-only knowledge (guardrails Phase
        # 4). The rest of the cluster metadata is ordinary profile data, so fill
        # the blanks on actors we already track — never overwrite a value an
        # analyst or an earlier source already set.
        from app import entity_types
        from app.intelligence.actor_attributes import coerce_motivation, resolve_country_name
        from app.intelligence.sectors import normalize_sectors, sector_uuid
        from app.models.threat_actor import ThreatActor
        from app.services.claim_provenance import record_claims
        from app.services.sector_links import add_target_sector, list_target_sectors, refresh_targeted_sectors_cache

        synonyms_by_name = dict(items)
        filled = {"country": 0, "sectors": 0, "motivation": 0, "description": 0, "matched": 0}
        for name, attrs in attributes.items():
            actor = await find_entity_by_name_or_alias(db, ThreatActor, name, synonyms_by_name.get(name) or [])
            if not actor:
                continue
            filled["matched"] += 1
            changed = False

            # Each fill is also recorded as a claim so the profile can name the
            # reference feed that asserted it rather than showing a bare value.
            asserted: dict = {}

            if not actor.country and attrs.get("country"):
                country = await resolve_country_name(db, attrs["country"])
                if country:
                    actor.country = country
                    asserted["country"] = country
                    filled["country"] += 1
                    changed = True

            if attrs.get("sectors") and not await list_target_sectors(db, "threat_actor", actor.id):
                # Fill-if-empty against the junction, not the cache column; the
                # rows land as `enrichment` claims the nightly rollup never prunes.
                slugs = normalize_sectors(attrs["sectors"])
                if slugs:
                    for slug in slugs:
                        await add_target_sector(db, "threat_actor", actor.id, sector_uuid(slug), "enrichment")
                    labels = await refresh_targeted_sectors_cache(db, "threat_actor", actor)
                    asserted["targeted_sectors"] = labels
                    filled["sectors"] += 1
                    changed = True

            if not actor.motivation and attrs.get("motivation"):
                motivation = coerce_motivation(attrs["motivation"])
                if motivation:
                    actor.motivation = motivation
                    asserted["motivation"] = motivation
                    filled["motivation"] += 1
                    changed = True

            if not actor.description and attrs.get("description"):
                actor.description = attrs["description"]
                asserted["description"] = attrs["description"]
                filled["description"] += 1
                changed = True

            if changed:
                db.add(actor)
                await record_claims(
                    db,
                    entity_type=entity_types.THREAT_ACTOR,
                    entity_id=actor.id,
                    values=asserted,
                    source_kind="external_feed",
                    source_ref="cybergeist",
                )

        await db.commit()
    return {"clusters": len(items), "alias_rows": rows, "attributes": filled}


@celery_app.task(name="app.workers.enrichment_tasks.run_cve_nvd_backfill", soft_time_limit=900, time_limit=960)
def run_cve_nvd_backfill():
    """Backfill NVD data for CVEs missing descriptions/CVSS scores."""
    start = time.monotonic()
    try:
        stats = run_async(_run_cve_nvd_backfill())
        logger.info("CVE NVD backfill stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_cve_nvd_backfill", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_cve_nvd_backfill", status="error").inc()
        logger.exception("CVE NVD backfill failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_cve_nvd_backfill").observe(time.monotonic() - start)


# Wall-clock seconds the backfill may spend starting lookups: 120s under the
# task's 900s soft limit, left for the final commit.
_NVD_BACKFILL_BUDGET_S = 780


@source_job("nvd")
async def _run_cve_nvd_backfill():
    import asyncio as _asyncio
    from datetime import UTC, datetime

    from app.intelligence.cve import (
        enrich_from_nvd,
        nvd_gateway,
        nvd_request_pace,
        nvd_retry_allowed,
        stamp_nvd_miss,
    )
    from app.models.cve import CVE

    stats = {
        "enriched": 0,
        "failed": 0,
        "skipped_invalid": 0,
        "stopped": None,
        "total": 0,
        "pending": 0,
    }
    now = datetime.now(UTC)
    deadline = time.monotonic() + _NVD_BACKFILL_BUDGET_S

    async with _get_worker_session() as db:
        gateway, api_key = await nvd_gateway(db, max_wait=JOB_TOKEN_WAIT)
        delay = nvd_request_pace(api_key)

        # Process valid-format CVEs first (4-5 digit suffix), skip obviously bogus ones
        from sqlalchemy import func as sa_func

        # Ids NVD has already missed on are retried on the shared budget (3
        # lookups, a week apart) — autolink and extraction mint a stub for any
        # CVE-shaped string, and without the budget every junk id was looked up
        # again every night.
        due = (
            CVE.description.is_(None),
            sa_func.length(sa_func.split_part(CVE.cve_id, "-", 3)) <= 5,
            nvd_retry_allowed(now),
        )
        stats["pending"] = (await db.execute(select(sa_func.count()).select_from(CVE).where(*due))).scalar() or 0
        # Load only what one run can look up at this pace; the rest waits for
        # tomorrow's run.
        result = await db.execute(
            select(CVE).where(*due).order_by(CVE.cve_id).limit(int(_NVD_BACKFILL_BUDGET_S / delay))
        )
        cves = result.scalars().all()
        stats["total"] = len(cves)

        # Count skipped invalid CVEs
        invalid_result = await db.execute(
            select(sa_func.count())
            .select_from(CVE)
            .where(
                CVE.description.is_(None),
                sa_func.length(sa_func.split_part(CVE.cve_id, "-", 3)) > 5,
            )
        )
        stats["skipped_invalid"] = invalid_result.scalar() or 0

        logger.info(
            "CVE NVD backfill: %d of %d valid CVEs this run, %d invalid skipped (delay=%.1fs)",
            stats["total"],
            stats["pending"],
            stats["skipped_invalid"],
            delay,
        )

        for i, cve_obj in enumerate(cves):
            if time.monotonic() >= deadline:
                # Out of budget: stop cleanly so the run commits and records its
                # stats instead of being killed at the soft limit.
                logger.info("CVE NVD backfill stopping at %d/%d: time budget spent", i, len(cves))
                stats["stopped"] = "out_of_time"
                break
            try:
                nvd = await enrich_from_nvd(cve_obj.cve_id, gateway, api_key)
            except SOURCE_REFUSALS as e:
                # Throttled, breaker open or budget spent: stop without charging
                # this CVE a retry; tomorrow's run picks it back up.
                logger.warning("CVE NVD backfill stopping at %d/%d: %s", i, len(cves), e)
                stats["stopped"] = e.status
                break
            if nvd:
                cve_obj.cvss_score = nvd.get("cvss_score")
                cve_obj.severity = nvd.get("severity")
                cve_obj.description = nvd.get("description")
                cve_obj.affected_products = nvd.get("affected_products", [])
                cve_obj.references_ = nvd.get("references", [])
                cve_obj.nvd_data = nvd.get("nvd_data", {})
                db.add(cve_obj)
                stats["enriched"] += 1
            else:
                stamp_nvd_miss(cve_obj, now)
                stats["failed"] += 1

            # Commit in batches of 50 to avoid losing progress
            if (i + 1) % 50 == 0:
                await db.commit()
                logger.info(
                    "CVE NVD backfill progress: %d/%d enriched, %d failed",
                    stats["enriched"],
                    stats["total"],
                    stats["failed"],
                )

            await _asyncio.sleep(delay)

        await db.commit()

    return stats


@celery_app.task(name="app.workers.enrichment_tasks.run_cve_nvd_refresh", soft_time_limit=900, time_limit=960)
def run_cve_nvd_refresh():
    """Periodic: re-check NVD for CVSS score changes on already-enriched CVEs."""
    start = time.monotonic()
    try:
        stats = run_async(_run_cve_nvd_refresh())
        logger.info("CVE NVD refresh stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_cve_nvd_refresh", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_cve_nvd_refresh", status="error").inc()
        logger.exception("CVE NVD refresh failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_cve_nvd_refresh").observe(time.monotonic() - start)


@source_job("nvd")
async def _run_cve_nvd_refresh():
    """Re-enrich CVEs that already have NVD data, detecting CVSS score changes."""
    import asyncio as _asyncio
    from datetime import timedelta

    from app.intelligence.cve import enrich_from_nvd, nvd_gateway, nvd_request_pace
    from app.models.cve import CVE

    stats = {"checked": 0, "score_changes": 0, "failed": 0, "total": 0, "stopped": None}

    async with _get_worker_session() as db:
        gateway, api_key = await nvd_gateway(db, max_wait=JOB_TOKEN_WAIT)
        delay = nvd_request_pace(api_key)

        # Select CVEs that hold an NVD record not re-checked in 7 days, oldest
        # first. Limit to 100 per run to stay within rate limits. Staleness uses
        # the blob-internal stamp, NOT CVE.updated_at: the daily EPSS sync and
        # article mentions touch updated_at on nearly every CVE, which left this
        # job with nothing to select.
        now = datetime.now(UTC)
        cutoff = (now - timedelta(days=7)).isoformat()
        refreshed_at = CVE.nvd_data["_refreshed_at"].astext
        from sqlalchemy import func as sa_func
        from sqlalchemy import or_

        result = await db.execute(
            select(CVE)
            .where(
                CVE.nvd_data.has_key("id"),
                or_(~CVE.nvd_data.has_key("_refreshed_at"), refreshed_at < cutoff),
                sa_func.length(sa_func.split_part(CVE.cve_id, "-", 3)) <= 5,
            )
            .order_by(refreshed_at.asc().nulls_first())
            .limit(100)
        )
        cves = result.scalars().all()
        stats["total"] = len(cves)

        if not cves:
            return stats

        logger.info("CVE NVD refresh: re-checking %d CVEs for score changes (delay=%.1fs)", len(cves), delay)

        from app.intelligence.correlation_events import create_cve_score_change_event

        for i, cve_obj in enumerate(cves):
            old_cvss = float(cve_obj.cvss_score) if cve_obj.cvss_score is not None else None
            try:
                nvd = await enrich_from_nvd(cve_obj.cve_id, gateway, api_key)
            except SOURCE_REFUSALS as e:
                # Left unstamped, so the next run starts with it.
                logger.warning("CVE NVD refresh stopping at %d/%d: %s", i, len(cves), e)
                stats["stopped"] = e.status
                break
            if nvd:
                new_cvss = nvd.get("cvss_score")
                new_cvss_float = float(new_cvss) if new_cvss is not None else None

                # Detect CVSS severity tier escalation into high (>=7.0) or critical (>=9.0).
                # Numeric changes within the same tier, or any downgrade, do not notify.
                if old_cvss is not None and new_cvss_float is not None:
                    old_rank = _cvss_tier_rank(old_cvss)
                    new_rank = _cvss_tier_rank(new_cvss_float)
                    if new_rank > old_rank and new_rank >= 3:
                        try:
                            await create_cve_score_change_event(
                                db, cve_obj.cve_id, cve_obj.id, "cvss_score", old_cvss, new_cvss_float
                            )
                            stats["score_changes"] += 1
                        except Exception:
                            logger.debug("Failed to create CVSS change event for %s", cve_obj.cve_id, exc_info=True)
                        from app.workers.signal_tasks import dispatch_cve_rescore

                        dispatch_cve_rescore(cve_obj.id)

                # Update the CVE with fresh NVD data
                cve_obj.cvss_score = new_cvss
                cve_obj.severity = nvd.get("severity") or cve_obj.severity
                if nvd.get("description"):
                    cve_obj.description = nvd["description"]
                cve_obj.affected_products = nvd.get("affected_products", cve_obj.affected_products)
                cve_obj.references_ = nvd.get("references", cve_obj.references_)
                cve_obj.nvd_data = nvd.get("nvd_data", cve_obj.nvd_data)
                stats["checked"] += 1
            else:
                stats["failed"] += 1
            # Stamp hits and misses alike so a CVE NVD can't answer for rotates
            # to the back instead of heading every run.
            cve_obj.nvd_data = {**(cve_obj.nvd_data or {}), "_refreshed_at": now.isoformat()}
            db.add(cve_obj)

            if (i + 1) % 50 == 0:
                await db.commit()
                logger.info(
                    "CVE NVD refresh progress: %d/%d checked, %d score changes",
                    stats["checked"],
                    stats["total"],
                    stats["score_changes"],
                )

            await _asyncio.sleep(delay)

        await db.commit()

    return stats


@celery_app.task(name="app.workers.enrichment_tasks.run_malpedia_sync", soft_time_limit=600, time_limit=660)
def run_malpedia_sync():
    """Weekly: sync malware families and actors from Malpedia."""
    start = time.monotonic()
    try:
        stats = run_async(_run_malpedia_sync())
        logger.info("Malpedia sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_malpedia_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_malpedia_sync", status="error").inc()
        logger.exception("Malpedia sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_malpedia_sync").observe(time.monotonic() - start)


# Entities updated per Malpedia transaction.
_MALPEDIA_COMMIT_EVERY = 200


async def _malpedia_get(client, kind: str) -> dict:
    """Malpedia's full ``get/<kind>`` payload, or {} when the fetch fails.
    Gateway refusals propagate."""
    try:
        resp = await client.get(f"https://malpedia.caad.fkie.fraunhofer.de/api/get/{kind}")
        resp.raise_for_status()
        data = resp.json()
    except GatewayError:
        raise
    except Exception as e:
        logger.warning("Malpedia %s fetch failed: %s", kind, e)
        return {}
    if not isinstance(data, dict):
        logger.warning("Malpedia %s response was %s, not a dict; skipping", kind, type(data).__name__)
        return {}
    return data


@source_job("malpedia")
async def _run_malpedia_sync():
    from app.intelligence.actor_attributes import resolve_country_name
    from app.models.enrichment import EnrichmentSource
    from app.models.malware_family import MalwareFamily
    from app.models.threat_actor import ThreatActor
    from app.models.tool import Tool

    stats = {"families_updated": 0, "tools_updated": 0, "actors_updated": 0, "families_seen": 0, "stopped": None}

    # `get/families` returns the full {family_key: {...}} payload. The
    # `list/families` endpoint this used to call returns a bare list of keys,
    # so the isinstance guard discarded every row and the sync had been a
    # silent no-op — which is why no malware profile carried a malpedia_url.
    families: dict = {}
    actors: dict = {}
    gateway, _ = await _job_gateway("malpedia")
    async with gateway.client(timeout=120.0) as client:
        try:
            families = await _malpedia_get(client, "families")
            actors = await _malpedia_get(client, "actors")
        except SOURCE_REFUSALS as e:
            # Apply whatever arrived before the refusal.
            logger.warning("Malpedia sync stopping: %s", e)
            stats["stopped"] = e.status

    stats["families_seen"] = len(families)
    stats["actors_seen"] = len(actors)

    async with _get_worker_session() as db:
        # Commit in batches: one transaction over thousands of malware, tool and
        # actor rows held locks long enough to deadlock with other catalog syncs.
        dirty = 0
        for family_key, family_data in families.items():
            if dirty >= _MALPEDIA_COMMIT_EVERY:
                await db.commit()
                dirty = 0
            if not isinstance(family_data, dict):
                continue
            common_name = family_data.get("common_name") or family_key
            alt_names = [a for a in family_data.get("alt_names") or [] if isinstance(a, str)]
            malpedia_url = f"https://malpedia.caad.fkie.fraunhofer.de/details/{family_key}"
            github_url = next((u for u in family_data.get("urls") or [] if "github.com/" in str(u)), None)

            # Malpedia files offensive tooling under the same family namespace as
            # malware, so a key can match either table. Try malware first — it's
            # the larger and more specific catalog — then tools.
            for model, stat_key in ((MalwareFamily, "families_updated"), (Tool, "tools_updated")):
                entity = await find_entity_by_name_or_alias(db, model, common_name, alt_names)
                if not entity:
                    continue
                entity.malpedia_url = malpedia_url
                if family_data.get("description") and not entity.description:
                    entity.description = family_data["description"]
                if github_url and hasattr(entity, "github_url") and not entity.github_url:
                    entity.github_url = github_url
                if alt_names and not entity.aliases:
                    cleaned = filter_aliases(alt_names, common_name)
                    if cleaned:
                        entity.aliases = cleaned
                db.add(entity)
                stats[stat_key] += 1
                dirty += 1
                break

        for actor_key, actor_data in actors.items():
            if dirty >= _MALPEDIA_COMMIT_EVERY:
                await db.commit()
                dirty = 0
            if not isinstance(actor_data, dict):
                continue
            meta = actor_data.get("meta") or {}
            synonyms = [s for s in meta.get("synonyms") or [] if isinstance(s, str)]
            actor = await find_entity_by_name_or_alias(db, ThreatActor, actor_key, synonyms)
            if not actor:
                continue
            if actor_data.get("description") and not actor.description:
                actor.description = actor_data["description"]
            if meta.get("country") and not actor.country:
                # Malpedia reports ISO alpha-2; the column stores full names.
                country = await resolve_country_name(db, meta["country"])
                if country:
                    actor.country = country
            if synonyms and not actor.aliases:
                cleaned = filter_aliases(synonyms, actor_key)
                if cleaned:
                    actor.aliases = cleaned
            db.add(actor)
            stats["actors_updated"] += 1
            dirty += 1

        # Update source
        source_result = await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "malpedia"))
        source = source_result.scalar_one_or_none()
        if source:
            source.last_synced_at = datetime.now(UTC)
            source.health_status = "healthy"
            db.add(source)

        await db.commit()

    return stats


@celery_app.task(name="app.workers.enrichment_tasks.run_github_poc_scan", soft_time_limit=600, time_limit=660)
def run_github_poc_scan():
    """Daily: search GitHub for PoC repos for recent CVEs."""
    start = time.monotonic()
    try:
        stats = run_async(_run_github_poc_scan())
        logger.info("GitHub PoC scan stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_github_poc_scan", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_github_poc_scan", status="error").inc()
        logger.exception("GitHub PoC scan failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_github_poc_scan").observe(time.monotonic() - start)


# Wall-clock seconds the scan may spend starting searches: the source's bucket
# paces them, so a big batch on a slow bucket stops here and commits instead of
# being killed at the 600s soft limit (120s left for a token wait + commit).
_GITHUB_POC_BUDGET_S = 480


@source_job("github_poc")
async def _run_github_poc_scan():
    from datetime import timedelta

    from sqlalchemy import case, or_

    from app.enrichment.pipeline import gateway_for
    from app.enrichment.results import upsert_enrichment_result
    from app.models.cve import CVE
    from app.models.enrichment import EnrichmentResult, EnrichmentSource

    stats = {"scanned": 0, "pocs_found": 0, "stopped": None}
    deadline = time.monotonic() + _GITHUB_POC_BUDGET_S

    async with _get_worker_session() as db:
        # Warm before the settings.get() reads below — batch limit, rescan
        # window and the fallback token are all DB-overridable.
        from app.services.system_settings import warm_settings_cache

        await warm_settings_cache(db)
        source_result = await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "github_poc"))
        source = source_result.scalar_one_or_none()
        # The source's key, else the instance-wide github_token, so the scan
        # isn't stuck on GitHub's 10 req/min unauthenticated search limit.
        gateway, api_key = await gateway_for(db, "github_poc", max_wait=JOB_TOKEN_WAIT)

        headers = {"Accept": "application/vnd.github.v3+json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # Authenticated search allows 30 req/min; unauthenticated only 10, and
        # it 403s partway through a run. Size the batch to the credential we
        # actually have; the source's bucket paces the requests.
        batch_limit = int(settings.get("github_poc_batch_limit") or (300 if api_key else 40))

        # Backfill-aware candidate selection. The old query took the 50 CVEs
        # first seen in the last 7 days, which meant the other 60k+ rows were
        # never eligible and the scan could never catch up. Rank instead by how
        # much a PoC answer matters — KEV first, then EPSS, then how many
        # articles reference it — and skip anything scanned recently.
        rescan_cutoff = datetime.now(UTC) - timedelta(days=int(settings.get("github_poc_rescan_days") or 30))
        # NOT EXISTS rather than NOT IN — a NULL entity_id in the subquery would
        # make NOT IN return nothing at all and silently starve the scan.
        recently_scanned = (
            select(EnrichmentResult.id)
            .where(
                EnrichmentResult.entity_type == "cve",
                EnrichmentResult.entity_id == CVE.id,
                EnrichmentResult.source_type == "github_poc",
                EnrichmentResult.enriched_at >= rescan_cutoff,
            )
            .correlate(CVE)
            .exists()
        )
        # CVE has no stored article_count — derive "does any entry cite this" from
        # the junction, the same way the API list endpoint does.
        from app.models.cve import EntryCVE

        is_linked = select(EntryCVE.cve_id).where(EntryCVE.cve_id == CVE.id).correlate(CVE).exists()
        priority = case(
            (CVE.is_kev.is_(True), 3),
            (CVE.epss_score >= 0.1, 2),
            (is_linked, 1),
            else_=0,
        )
        result = await db.execute(
            select(CVE)
            .where(
                ~recently_scanned,
                # Rows with no signal at all aren't worth a search call.
                or_(CVE.is_kev.is_(True), CVE.epss_score.is_not(None), is_linked),
            )
            .order_by(priority.desc(), CVE.epss_score.desc().nullslast(), CVE.first_seen_at.desc())
            .limit(batch_limit)
        )
        cves = result.scalars().all()

        async with gateway.client(timeout=30.0, headers=headers) as client:
            for cve in cves:
                if time.monotonic() >= deadline:
                    stats["stopped"] = "out_of_time"
                    break
                try:
                    # Bare "<cve> poc exploit" ANDs all three words across the
                    # searched fields, so a repo literally named CVE-2024-3400
                    # scored zero hits — the scan reported "no PoC" for 99% of
                    # CVEs. Match the CVE id as a phrase in name/description
                    # instead; PoC repos put the id in one or the other.
                    resp = await client.get(
                        "https://api.github.com/search/repositories",
                        params={"q": f'"{cve.cve_id}" in:name,description', "sort": "stars", "per_page": 5},
                    )
                    resp.raise_for_status()
                    data = resp.json()

                    poc_repos = []
                    for item in data.get("items", [])[:5]:
                        poc_repos.append(
                            {
                                "name": item["name"],
                                "url": item["html_url"],
                                "stars": item["stargazers_count"],
                                "language": item.get("language"),
                                "description": item.get("description", ""),
                            }
                        )

                    now = datetime.now(UTC)
                    parsed = {
                        "cve_id": cve.cve_id,
                        "has_public_poc": len(poc_repos) > 0,
                        "poc_count": len(poc_repos),
                        "poc_repos": poc_repos,
                    }

                    await upsert_enrichment_result(
                        db,
                        entity_type="cve",
                        entity_id=cve.id,
                        source_type="github_poc",
                        raw_response=data,
                        parsed_data=parsed,
                        enriched_at=now,
                        expires_at=now + timedelta(hours=24),
                        status="success",
                    )

                    # Update CVE model directly. Write the count even when the
                    # scan finds nothing, so "scanned, no PoC" reads as 0 rather
                    # than looking unscanned, and a rescan clears stale hits.
                    old_poc_count = cve.github_poc_count or 0
                    new_poc_urls = [r["url"] for r in poc_repos]
                    cve.github_poc_count = len(poc_repos)
                    cve.github_poc_urls = new_poc_urls
                    db.add(cve)
                    if poc_repos:
                        old_availability = cve.exploit_availability
                        # Determine exploit availability level using full escalation hierarchy:
                        # active_exploitation (KEV) > weaponized (metasploit or 100+ star PoC) > poc
                        # Never overwrite an analyst-set status (exploit_status_source='manual').
                        max_stars = max((r["stars"] for r in poc_repos), default=0)
                        if (
                            cve.exploit_status_source != "manual"
                            and not cve.is_kev
                            and cve.exploit_availability != "active_exploitation"
                        ):
                            if cve.metasploit_module or max_stars >= 100:
                                cve.exploit_availability = "weaponized"
                            else:
                                cve.exploit_availability = "poc"
                        db.add(cve)
                        # Create correlation event if status changed
                        new_availability = cve.exploit_availability
                        if new_availability != old_availability:
                            from app.intelligence.correlation_events import create_exploit_status_change_event

                            await create_exploit_status_change_event(
                                db, cve.cve_id, cve.id, old_availability, new_availability
                            )
                        # Create event when new PoCs are discovered
                        if len(poc_repos) > old_poc_count:
                            from app.intelligence.correlation_events import create_new_exploit_discovered_event

                            try:
                                await create_new_exploit_discovered_event(
                                    db, cve.cve_id, cve.id, len(poc_repos), new_poc_urls
                                )
                            except Exception:
                                logger.debug("Failed to create exploit event for %s", cve.cve_id, exc_info=True)
                        if new_availability != old_availability or len(poc_repos) > old_poc_count:
                            from app.workers.signal_tasks import dispatch_cve_rescore

                            dispatch_cve_rescore(cve.id)
                        stats["pocs_found"] += 1
                    stats["scanned"] += 1

                except SOURCE_REFUSALS as e:
                    logger.warning("GitHub PoC scan stopping after %d CVEs: %s", stats["scanned"], e)
                    stats["stopped"] = e.status
                    break
                except GatewayUnavailable:
                    raise
                except Exception as e:
                    logger.warning("GitHub PoC scan failed for %s: %s", cve.cve_id, e)

        if source:
            source.last_synced_at = datetime.now(UTC)
            source.health_status = "healthy"
            db.add(source)

        await db.commit()

    return stats


@celery_app.task(name="app.workers.enrichment_tasks.run_wikipedia_bulk_sync", soft_time_limit=3600, time_limit=3660)
def run_wikipedia_bulk_sync():
    """Weekly: enrich entities missing Wikipedia content (countries, vendors, products, actors, malware)."""
    start = time.monotonic()
    try:
        stats = run_async(_run_wikipedia_bulk_sync())
        logger.info("Wikipedia bulk sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_wikipedia_bulk_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_wikipedia_bulk_sync", status="error").inc()
        logger.exception("Wikipedia bulk sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_wikipedia_bulk_sync").observe(time.monotonic() - start)


# Wall-clock seconds the sync may spend fetching: the wikipedia bucket paces it,
# so it stops here and commits rather than run into the 3600s soft limit.
_WIKIPEDIA_BULK_BUDGET_S = 3300


@source_job("wikipedia")
async def _run_wikipedia_bulk_sync():
    from datetime import timedelta

    from app.enrichment.pipeline import gateway_for
    from app.enrichment.wikipedia_helper import extract_first_paragraph, fetch_wikipedia
    from app.models.country import Country
    from app.models.enrichment import EnrichmentResult, EnrichmentSource
    from app.models.malware_family import MalwareFamily
    from app.models.product import Product
    from app.models.threat_actor import ThreatActor
    from app.models.tool import Tool
    from app.models.vendor import Vendor

    BATCH_LIMIT = 100

    # Entity types to enrich, ordered by priority
    entity_configs = [
        ("country", Country, "name"),
        ("vendor", Vendor, "name"),
        ("product", Product, "name"),
        ("threat_actor", ThreatActor, "name"),
        ("malware", MalwareFamily, "name"),
        ("tool", Tool, "name"),
    ]

    stats = {
        "country": 0,
        "vendor": 0,
        "product": 0,
        "threat_actor": 0,
        "malware": 0,
        "tool": 0,
        "total": 0,
        "failed": 0,
        "skipped": 0,
        "stopped": None,
    }
    deadline = time.monotonic() + _WIKIPEDIA_BULK_BUDGET_S

    async with _get_worker_session() as db:
        now = datetime.now(UTC)
        batch_count = 0
        gateway, _ = await gateway_for(db, "wikipedia", max_wait=JOB_TOKEN_WAIT)

        for entity_type, model_cls, name_attr in entity_configs:
            if stats["stopped"]:
                break
            # Skip entities a user explicitly cleared ("None") — they carry a
            # long-lived user_cleared marker and must not be re-populated by name.
            cleared_marker = (
                select(EnrichmentResult.id)
                .where(
                    EnrichmentResult.entity_type == entity_type,
                    EnrichmentResult.entity_id == model_cls.id,
                    EnrichmentResult.source_type == "wikipedia",
                    EnrichmentResult.parsed_data["user_cleared"].astext == "true",
                )
                .exists()
            )
            result = await db.execute(
                select(model_cls)
                .where(model_cls.wikipedia_content.is_(None), ~cleared_marker)
                .order_by(model_cls.name)
                .limit(BATCH_LIMIT)
            )
            entities = result.scalars().all()

            for entity in entities:
                if time.monotonic() >= deadline:
                    stats["stopped"] = "out_of_time"
                    break
                entity_name = getattr(entity, name_attr)
                if not entity_name:
                    stats["skipped"] += 1
                    continue

                # The source's bucket paces the requests (several per entity).
                try:
                    wiki_result = await fetch_wikipedia(entity_name, entity_type, transport=gateway.transport())
                except SOURCE_REFUSALS as e:
                    logger.warning("Wikipedia bulk sync stopping: %s", e)
                    stats["stopped"] = e.status
                    break
                except GatewayUnavailable:
                    raise
                except Exception as e:
                    logger.warning("Wikipedia fetch failed for %s/%s: %s", entity_type, entity_name, e)
                    stats["failed"] += 1
                    continue

                if not wiki_result:
                    stats["skipped"] += 1
                    continue

                # Topical guard (F11): a wrong-subject article (calendar year,
                # disambiguation page, geography, unrelated bio) anchors every
                # later AI resolution to the wrong identity — reject and log
                # for the Hygiene tab instead of persisting.
                from app.intelligence.entity_resolution import enrichment_content_ok, log_enrichment_reject

                ok, reject_reason = enrichment_content_ok(entity_name, wiki_result["content"])
                if not ok:
                    log_enrichment_reject(
                        db, entity_type, entity.id, entity_name, reject_reason, detail=wiki_result.get("url")
                    )
                    stats["skipped"] += 1
                    continue

                # Update entity model directly
                entity.wikipedia_url = wiki_result["url"]
                entity.wikipedia_content = wiki_result["content"]
                entity.wikipedia_image_url = wiki_result.get("image_url")
                if hasattr(entity, "description") and not entity.description:
                    first_para = extract_first_paragraph(wiki_result["content"])
                    if first_para:
                        entity.description = first_para
                db.add(entity)

                # Store enrichment result
                db.add(
                    EnrichmentResult(
                        entity_type=entity_type,
                        entity_id=entity.id,
                        source_type="wikipedia",
                        raw_response={
                            "title": wiki_result["title"],
                            "url": wiki_result["url"],
                            "content": wiki_result["content"],
                            "image_url": wiki_result.get("image_url"),
                        },
                        parsed_data={
                            "found": True,
                            "wikipedia_url": wiki_result["url"],
                            "wikipedia_content": wiki_result["content"],
                            "wikipedia_image_url": wiki_result.get("image_url"),
                            "title": wiki_result["title"],
                            "first_paragraph": extract_first_paragraph(wiki_result["content"]),
                        },
                        enriched_at=now,
                        expires_at=now + timedelta(hours=720),
                        status="success",
                    )
                )

                stats[entity_type] += 1
                stats["total"] += 1
                batch_count += 1

                # Commit in batches of 25
                if batch_count % 25 == 0:
                    await db.commit()
                    logger.info("Wikipedia bulk sync progress: %s", stats)

        # Update source last_synced_at
        source_result = await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "wikipedia"))
        source = source_result.scalar_one_or_none()
        if source:
            source.last_synced_at = now
            source.health_status = "healthy"
            db.add(source)

        await db.commit()

    return stats


METASPLOIT_METADATA_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
)

_MSF_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def parse_metasploit_modules(metadata: dict) -> dict[str, list[str]]:
    """Map CVE id -> Metasploit module fullnames from the framework metadata dump.

    `modules_metadata_base.json` is the same index msfconsole builds its search
    cache from: one entry per module, with a `references` list that carries
    CVE-YYYY-NNNN strings alongside OSVDB/BID/URL refs. Exploit and auxiliary
    modules both count — an auxiliary scanner for a CVE is still working
    exploitation code.
    """
    by_cve: dict[str, list[str]] = {}
    for entry in metadata.values():
        if not isinstance(entry, dict):
            continue
        fullname = entry.get("fullname") or entry.get("ref_name")
        if not fullname:
            continue
        for ref in entry.get("references") or []:
            ref = str(ref).strip()
            if _MSF_CVE_RE.match(ref):
                by_cve.setdefault(ref.upper(), []).append(fullname)
    return {cve: sorted(set(mods)) for cve, mods in by_cve.items()}


@celery_app.task(name="app.workers.enrichment_tasks.run_metasploit_sync", soft_time_limit=900, time_limit=960)
def run_metasploit_sync():
    """Weekly: map CVEs to Metasploit modules from the framework's metadata dump."""
    start = time.monotonic()
    try:
        stats = run_async(_run_metasploit_sync())
        logger.info("Metasploit sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_metasploit_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_metasploit_sync", status="error").inc()
        logger.exception("Metasploit sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_metasploit_sync").observe(time.monotonic() - start)


@source_job("metasploit")
async def _run_metasploit_sync():
    """Populate CVE.metasploit_module and escalate exploit_availability.

    Nothing in the codebase had ever written `metasploit_module`, which left the
    column, the workbench MSF column, and the `weaponized` branch of the exploit
    escalation permanently inert. Rapid7 publishes the module index as a single
    JSON file, so this needs no API key and no per-CVE requests.
    """
    from app.intelligence.external_feeds import coerce_exploit_sources
    from app.models.cve import CVE

    stats = {"modules_seen": 0, "cves_matched": 0, "cves_updated": 0, "escalated": 0}

    gateway, _ = await _job_gateway("metasploit")
    try:
        async with gateway.client(timeout=180.0, follow_redirects=True) as client:
            resp = await client.get(METASPLOIT_METADATA_URL)
            resp.raise_for_status()
            metadata = resp.json()
    except SOURCE_REFUSALS as e:
        logger.warning("Metasploit sync skipped: %s", e)
        return {**stats, "stopped": e.status}

    if not isinstance(metadata, dict):
        logger.warning("Metasploit metadata was %s, not a dict; skipping", type(metadata).__name__)
        return stats

    stats["modules_seen"] = len(metadata)
    by_cve = parse_metasploit_modules(metadata)
    stats["cves_matched"] = len(by_cve)
    if not by_cve:
        return stats

    async with _get_worker_session() as db:
        # Only touch CVEs we actually track; the module index covers far more.
        rows = (await db.execute(select(CVE).where(CVE.cve_id.in_(list(by_cve))))).scalars().all()
        rescored: list = []
        for cve in rows:
            modules = by_cve.get(cve.cve_id.upper()) or []
            if not modules:
                continue
            # Store the primary module name; the full list lives in exploit_sources.
            primary = modules[0]
            changed = False
            if cve.metasploit_module != primary:
                cve.metasploit_module = primary
                changed = True

            sources = coerce_exploit_sources(cve.exploit_sources)
            if not any(s.get("source") == "metasploit" for s in sources):
                sources.append({"source": "metasploit", "module": primary})
                cve.exploit_sources = sources
                changed = True
            elif sources != list(cve.exploit_sources or []):
                # Rows this sync wrote as bare strings before it used dicts.
                cve.exploit_sources = sources
                changed = True

            # A shipped module is weaponized exploitation code. Never downgrade
            # active_exploitation (KEV), and never overwrite an analyst verdict.
            old = cve.exploit_availability
            if (
                cve.exploit_status_source != "manual"
                and not cve.is_kev
                and cve.exploit_availability != "active_exploitation"
                and cve.exploit_availability != "weaponized"
            ):
                cve.exploit_availability = "weaponized"
                changed = True

            if changed:
                db.add(cve)
                stats["cves_updated"] += 1
            if cve.exploit_availability != old:
                stats["escalated"] += 1
                rescored.append(cve.id)
                from app.intelligence.correlation_events import create_exploit_status_change_event

                await create_exploit_status_change_event(db, cve.cve_id, cve.id, old, cve.exploit_availability)

        await db.commit()

    if rescored:
        from app.workers.signal_tasks import dispatch_cve_rescore

        for cve_id in rescored:
            dispatch_cve_rescore(cve_id)

    return stats


# --- cvelistV5: the CVE Program's records, CNA and CISA-ADP containers ---


async def _apply_cvelist_record(db, cve_pk, data, cwe_index: dict) -> bool:
    """Store one CVE record as the cvelist source's result for the CVE: its
    context, its declared columns, and its CWE ids as cve_weaknesses links.
    Returns True when a column changed."""
    from app.enrichment.entity_updater import apply_enrichment_results_to_entity
    from app.enrichment.pipeline import get_cached_result, store_result
    from app.intelligence.cve import sync_cve_weaknesses

    existing = await get_cached_result(db, "cve", cve_pk, "cvelist")
    await store_result(db, "cve", cve_pk, "cvelist", data, existing)
    parsed = data.parsed_data
    changed = await apply_enrichment_results_to_entity(
        db, "cve", cve_pk, [{"source_type": "cvelist", "status": "success", "parsed_data": parsed}]
    )
    weaknesses = [
        {"cwe_ref": ref, "is_primary": False, "assigner": parsed.get("assigner")}
        for ref in dict.fromkeys(parsed.get("weaknesses") or [])
    ]
    if weaknesses:
        await sync_cve_weaknesses(db, cve_pk, weaknesses, cwe_index, source="cvelist")
    return changed


@celery_app.task(name="app.workers.enrichment_tasks.run_cvelist_backfill", soft_time_limit=900, time_limit=960)
def run_cvelist_backfill():
    """Hourly: fetch the CVE record for CVEs the cvelist source hasn't checked lately."""
    start = time.monotonic()
    try:
        stats = run_async(_run_cvelist_backfill())
        logger.info("cvelist backfill stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_cvelist_backfill", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_cvelist_backfill", status="error").inc()
        logger.exception("cvelist backfill failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_cvelist_backfill").observe(time.monotonic() - start)


# Wall-clock seconds a backfill run may spend fetching: 120s under the 900s
# soft limit, left for the last commit.
_CVELIST_BACKFILL_BUDGET_S = 780


@source_job("cvelist")
async def _run_cvelist_backfill():
    """Fetch the record of each CVE with no unexpired cvelist result: the CVEs
    missing a score or description first, then KEV entries, then the newest.

    Each record is one raw.githubusercontent.com request, paced by the source's
    bucket; a run fetches what its time budget allows and the next run goes on.
    The delta sync keeps a fetched record current, and it is checked again here
    once its result expires (RECORD_TTL_HOURS).
    """
    import httpx
    from sqlalchemy import exists, func, or_

    from app.enrichment.adapters.cvelist import CVEListAdapter
    from app.enrichment.pipeline import gateway_for
    from app.intelligence.cve import build_cwe_index
    from app.models.cve import CVE
    from app.models.enrichment import EnrichmentResult

    stats = {"fetched": 0, "updated": 0, "not_found": 0, "failed": 0, "pending": 0, "stopped": None}
    deadline = time.monotonic() + _CVELIST_BACKFILL_BUDGET_S
    async with _get_worker_session() as db:
        gateway, _ = await gateway_for(db, "cvelist", max_wait=JOB_TOKEN_WAIT)
        adapter = CVEListAdapter(gateway=gateway)
        checked = exists().where(
            EnrichmentResult.source_type == "cvelist",
            EnrichmentResult.entity_type == "cve",
            EnrichmentResult.entity_id == CVE.id,
            EnrichmentResult.expires_at > datetime.now(UTC),
        )
        stats["pending"] = (await db.execute(select(func.count()).select_from(CVE).where(~checked))).scalar_one()
        # Only as many as one run can fetch at the bucket's rate.
        per_run = int(_CVELIST_BACKFILL_BUDGET_S * gateway.capacity / gateway.period) + gateway.capacity
        rows = (
            await db.execute(
                select(CVE.id, CVE.cve_id)
                .where(~checked)
                .order_by(
                    or_(CVE.cvss_score.is_(None), CVE.description.is_(None)).desc(),
                    CVE.is_kev.desc(),
                    CVE.first_seen_at.desc(),
                )
                .limit(per_run)
            )
        ).all()
        cwe_index = await build_cwe_index(db)

        for i, (cve_pk, cve_id) in enumerate(rows):
            if time.monotonic() >= deadline:
                stats["stopped"] = "out_of_time"
                break
            try:
                data = await adapter.enrich("cve", cve_id)
            except SOURCE_REFUSALS as e:
                logger.warning("cvelist backfill stopping at %d/%d: %s", i, len(rows), e)
                stats["stopped"] = e.status
                break
            except (httpx.HTTPError, ValueError) as e:
                # A server error or an unreadable record: left unchecked, so
                # the next run tries it again.
                logger.warning("cvelist record for %s failed: %s", cve_id, e)
                stats["failed"] += 1
                continue
            stats["fetched"] += 1
            if not data.parsed_data.get("found"):
                stats["not_found"] += 1
            if await _apply_cvelist_record(db, cve_pk, data, cwe_index):
                stats["updated"] += 1
            if (i + 1) % 50 == 0:
                await db.commit()
        await db.commit()
    return stats


@celery_app.task(name="app.workers.enrichment_tasks.run_cvelist_delta_sync", soft_time_limit=600, time_limit=660)
def run_cvelist_delta_sync():
    """Hourly: apply the CVE records that changed, from cvelistV5's delta zips."""
    start = time.monotonic()
    try:
        stats = run_async(_run_cvelist_delta_sync())
        logger.info("cvelist delta sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_cvelist_delta_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_cvelist_delta_sync", status="error").inc()
        logger.exception("cvelist delta sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_cvelist_delta_sync").observe(time.monotonic() - start)


# Wall-clock seconds a delta sync may spend before starting another zip.
_CVELIST_DELTA_BUDGET_S = 480
# The largest delta zip the sync downloads. A whole day's is about 4 MB; the
# daily baseline of every record (about 650 MB) is never fetched.
_CVELIST_DELTA_MAX_BYTES = 64 * 1024 * 1024
# Releases listed per run: about four days of hourly releases.
_CVELIST_RELEASES_PAGE = 100


def pick_cvelist_deltas(releases: list[dict], since: datetime | None) -> tuple[list[tuple[datetime, str]], bool]:
    """The delta zips covering the records changed after ``since``, oldest day
    first, as ``(published_at, url)``; and whether the listing starts after
    ``since``, so changes in between are missed.

    cvelistV5 publishes a release every hour whose delta zip holds every record
    changed since midnight UTC, and after midnight an end-of-day delta for the
    whole day. Per day that leaves one zip to read: the end-of-day one once it
    is out, else the newest hourly one. Without ``since`` (the first run) only
    the newest zip is read; the backfill covers the rest.
    """
    by_day: dict[str, tuple[bool, datetime, str]] = {}
    oldest = None
    for release in releases:
        published = datetime.fromisoformat(release["published_at"])
        oldest = min(oldest or published, published)
        if since and published <= since:
            continue
        for asset in release.get("assets") or []:
            name = asset.get("name") or ""
            if "_delta_CVEs_at_" not in name or not name.endswith(".zip"):
                continue
            day, end_of_day = name[:10], name.endswith("_end_of_day.zip")
            best = by_day.get(day)
            if best is None or (end_of_day, published) > best[:2]:
                by_day[day] = (end_of_day, published, asset["browser_download_url"])
    picked = [(published, url) for _, (_, published, url) in sorted(by_day.items())]
    gap = bool(since and oldest and oldest > since)
    return (picked if since else picked[-1:]), gap


async def _download_to(client, url: str, fh, limit: int) -> None:
    """Stream ``url`` into the open file ``fh``, refusing more than ``limit`` bytes."""
    async with client.stream("GET", url) as resp:
        resp.raise_for_status()
        size = 0
        async for chunk in resp.aiter_bytes():
            size += len(chunk)
            if size > limit:
                raise ValueError(f"{url} is larger than {limit} bytes")
            fh.write(chunk)
    fh.seek(0)


async def _apply_cvelist_delta(db, fh, cwe_index: dict, stats: dict) -> None:
    """Apply the records in a delta zip whose CVE ids are in the cves table,
    reading only those members."""
    import json
    import zipfile

    from app.enrichment.adapters.cvelist import record_result
    from app.models.cve import CVE

    with zipfile.ZipFile(fh) as archive:
        members = {
            name.rsplit("/", 1)[-1].removesuffix(".json").upper(): name
            for name in archive.namelist()
            if name.endswith(".json")
        }
        stats["records"] += len(members)
        ids = list(members)
        for start in range(0, len(ids), 1000):
            ours = (await db.execute(select(CVE.id, CVE.cve_id).where(CVE.cve_id.in_(ids[start : start + 1000])))).all()
            for cve_pk, cve_id in ours:
                record = json.loads(archive.read(members[cve_id.upper()]))
                stats["ours"] += 1
                if await _apply_cvelist_record(db, cve_pk, record_result(record), cwe_index):
                    stats["updated"] += 1


@source_job("cvelist")
async def _run_cvelist_delta_sync():
    """Read the delta zips released since the last run (the source row's
    ``last_synced_at`` holds the newest one read) and apply the records of the
    CVEs we track. Each zip streams to a temporary file and only our records
    are read from it, so a run holds one record in memory at a time."""
    import tempfile

    from app.enrichment.adapters.cvelist import RELEASES_URL
    from app.enrichment.pipeline import gateway_for
    from app.intelligence.cve import build_cwe_index
    from app.models.enrichment import EnrichmentSource

    stats = {"deltas": 0, "records": 0, "ours": 0, "updated": 0, "gap": False, "stopped": None}
    deadline = time.monotonic() + _CVELIST_DELTA_BUDGET_S
    async with _get_worker_session() as db:
        gateway, _ = await gateway_for(db, "cvelist", max_wait=JOB_TOKEN_WAIT)
        source = (
            await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "cvelist"))
        ).scalar_one_or_none()
        cwe_index = await build_cwe_index(db)
        try:
            async with gateway.client(timeout=60, follow_redirects=True) as client:
                resp = await client.get(
                    RELEASES_URL,
                    params={"per_page": _CVELIST_RELEASES_PAGE},
                    headers={"Accept": "application/vnd.github+json"},
                )
                resp.raise_for_status()
                deltas, stats["gap"] = pick_cvelist_deltas(resp.json(), source.last_synced_at if source else None)
                if stats["gap"]:
                    logger.warning("cvelist delta sync: releases since %s are no longer listed", source.last_synced_at)
                for published, url in deltas:
                    if time.monotonic() >= deadline:
                        stats["stopped"] = "out_of_time"
                        break
                    with tempfile.TemporaryFile() as fh:
                        await _download_to(client, url, fh, _CVELIST_DELTA_MAX_BYTES)
                        await _apply_cvelist_delta(db, fh, cwe_index, stats)
                    if source:
                        source.last_synced_at = published
                    await db.commit()
                    stats["deltas"] += 1
        except SOURCE_REFUSALS as e:
            # Keeps the zips already applied; the next run starts after them.
            logger.warning("cvelist delta sync stopping: %s", e)
            stats["stopped"] = e.status
    return stats
