"""Celery tasks for scheduled and auto enrichment — EPSS, MITRE ATT&CK, Malpedia, GitHub PoC."""

import logging
import re
import time
from datetime import UTC, datetime

from sqlalchemy import bindparam, select, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID

from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.intelligence.autolinker import filter_aliases
from app.intelligence.entity_dedup import find_entity_by_name_or_alias
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)


def _get_worker_session():
    return worker_session()


def parse_epss_csv(text: str) -> dict[str, dict]:
    """Parse the FIRST EPSS daily CSV into {cve_id: {epss_score, percentile}}.

    The CSV starts with one or more comment lines (#model_version...) before
    the "cve,epss,percentile" header; rows with malformed scores are skipped.
    """
    import csv

    lines = text.strip().split("\n")
    csv_start = 0
    for i, line in enumerate(lines):
        if line.startswith("cve,"):
            csv_start = i
            break

    epss_data: dict[str, dict] = {}
    for row in csv.DictReader(lines[csv_start:]):
        cve_id = (row.get("cve") or "").strip()
        if not cve_id.startswith("CVE-"):
            continue
        try:
            epss_data[cve_id] = {
                "epss_score": float(row.get("epss", 0)),
                "percentile": float(row.get("percentile", 0)),
            }
        except (TypeError, ValueError):
            continue
    return epss_data


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


# --- Auto-enrichment task (fired after entity extraction) ---


@celery_app.task(name="app.workers.enrichment_tasks.auto_enrich_entity", soft_time_limit=120, time_limit=180)
def auto_enrich_entity(
    entity_type: str,
    entity_id: str,
    entity_value: str,
    adapter_entity_type: str | None = None,
    confidence: str | None = None,
    base_confidence: float | None = None,
):
    """Auto-enrich a newly extracted entity using sources with trigger_mode='auto'."""
    start = time.monotonic()
    try:
        results = run_async(
            _auto_enrich_entity(
                entity_type,
                entity_id,
                entity_value,
                adapter_entity_type,
                confidence,
                base_confidence,
            )
        )
        logger.info("Auto-enriched %s/%s: %d sources", entity_type, entity_value, len(results))
        CELERY_TASKS_TOTAL.labels(task_name="auto_enrich_entity", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="auto_enrich_entity", status="error").inc()
        logger.exception("Auto-enrichment failed for %s/%s", entity_type, entity_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="auto_enrich_entity").observe(time.monotonic() - start)


@celery_app.task(name="app.workers.enrichment_tasks.bulk_enrich_for_gap", soft_time_limit=180, time_limit=240)
def bulk_enrich_for_gap(
    entity_type: str,
    entity_id: str,
    entity_value: str,
    adapter_entity_type: str | None = None,
    source_types: list[str] | None = None,
):
    """Run enrichment against a fixed list of enabled sources, bypassing trigger_mode.

    Used by the Entity Hygiene "Enrich N" buttons — the user explicitly opted
    in, so we want every applicable enabled adapter to run regardless of
    whether it's normally auto / scheduled / manual.
    """
    start = time.monotonic()
    try:
        run_async(
            _bulk_enrich_for_gap(
                entity_type,
                entity_id,
                entity_value,
                adapter_entity_type,
                source_types,
            )
        )
        CELERY_TASKS_TOTAL.labels(task_name="bulk_enrich_for_gap", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="bulk_enrich_for_gap", status="error").inc()
        logger.exception("Bulk gap enrichment failed for %s/%s", entity_type, entity_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="bulk_enrich_for_gap").observe(time.monotonic() - start)


async def _bulk_enrich_for_gap(
    entity_type: str,
    entity_id: str,
    entity_value: str,
    adapter_entity_type: str | None,
    source_types: list[str] | None,
):
    import uuid

    from app.enrichment.pipeline import enrich_entity

    async with _get_worker_session() as db:
        eid = uuid.UUID(entity_id)
        # trigger="manual" + explicit source_types → pipeline skips the
        # trigger_mode filter, so scheduled/manual adapters fire too.
        results = await enrich_entity(
            entity_type=adapter_entity_type or entity_type,
            entity_id=eid,
            entity_value=entity_value,
            db=db,
            trigger="manual",
            source_types=source_types,
        )

        # Propagate enrichment data into the entity's own columns so the
        # gap actually closes. Handles wikipedia + mitre_attack + malpedia
        # for description, and mitre_attack for mitre_id.
        from app.enrichment.entity_updater import apply_enrichment_results_to_entity

        updated = await apply_enrichment_results_to_entity(db, entity_type, eid, results)

        await db.commit()
        logger.info(
            "Bulk-enriched %s/%s via %d source(s) (entity %s): %s",
            entity_type,
            entity_value,
            len(results),
            "updated" if updated else "unchanged",
            ", ".join(r.get("source_type", "?") + ":" + r.get("status", "?") for r in results),
        )
        return results


async def _auto_enrich_entity(
    entity_type: str,
    entity_id: str,
    entity_value: str,
    adapter_entity_type: str | None,
    confidence: str | None = None,
    base_confidence: float | None = None,
):
    import uuid

    from app.enrichment.pipeline import enrich_entity

    async with _get_worker_session() as db:
        eid = uuid.UUID(entity_id)
        results = await enrich_entity(
            entity_type=adapter_entity_type or entity_type,
            entity_id=eid,
            entity_value=entity_value,
            db=db,
            trigger="auto",
            entity_confidence=confidence,
            entity_base_confidence=base_confidence,
        )

        # Propagate enrichment data to entity model fields (wikipedia +
        # mitre_attack + malpedia handle different entity columns; see
        # apply_enrichment_results_to_entity for the precedence).
        from app.enrichment.entity_updater import apply_enrichment_results_to_entity

        await apply_enrichment_results_to_entity(db, entity_type, eid, results)

        await db.commit()
        return results


# --- Scheduled enrichment tasks ---


@celery_app.task(name="app.workers.enrichment_tasks.run_scheduled_enrichment", soft_time_limit=600, time_limit=660)
def run_scheduled_enrichment():
    """Periodic task: check for scheduled enrichment sources that are due and run them."""
    start = time.monotonic()
    try:
        stats = run_async(_run_scheduled_enrichment())
        if stats["sources_processed"] > 0:
            logger.info("Scheduled enrichment stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_scheduled_enrichment", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_scheduled_enrichment", status="error").inc()
        logger.exception("Scheduled enrichment failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_scheduled_enrichment").observe(time.monotonic() - start)


async def _run_scheduled_enrichment():
    from datetime import timedelta

    from sqlalchemy import or_

    from app.enrichment.registry import get_adapter
    from app.models.enrichment import EnrichmentSource

    stats = {"sources_processed": 0, "results": 0, "errors": 0}
    now = datetime.now(UTC)

    async with _get_worker_session() as db:
        # Find scheduled sources that are due: next_scheduled_at <= now, or never run (null)
        result = await db.execute(
            select(EnrichmentSource)
            .where(EnrichmentSource.is_enabled == True)  # noqa: E712
            .where(EnrichmentSource.trigger_mode == "scheduled")
            .where(
                or_(
                    EnrichmentSource.next_scheduled_at <= now,
                    EnrichmentSource.next_scheduled_at.is_(None),
                )
            )
        )
        sources = result.scalars().all()

        for source in sources:
            try:
                from app.core.encryption import decrypt_value

                api_key = decrypt_value(source.api_key_encrypted) if source.api_key_encrypted else None
                adapter = get_adapter(source.source_type, api_key=api_key, config=source.config)
                bulk_results = await adapter.bulk_sync()
                stats["results"] += len(bulk_results)
                source.last_synced_at = now
                source.health_status = "healthy"
                stats["sources_processed"] += 1
            except Exception as e:
                logger.warning("Scheduled enrichment failed for %s: %s", source.source_type, e)
                source.health_status = "degraded"
                stats["errors"] += 1

            # Always advance next_scheduled_at so we don't retry immediately on failure
            interval = source.schedule_interval_hours or 24
            source.next_scheduled_at = now + timedelta(hours=interval)
            db.add(source)

        await db.commit()

    return stats


@celery_app.task(name="app.workers.enrichment_tasks.run_epss_bulk_sync", soft_time_limit=900, time_limit=960)
def run_epss_bulk_sync():
    """Daily: download EPSS CSV, update all CVEs."""
    start = time.monotonic()
    try:
        stats = run_async(_run_epss_bulk_sync())
        logger.info("EPSS bulk sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_epss_bulk_sync", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_epss_bulk_sync", status="error").inc()
        logger.exception("EPSS bulk sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_epss_bulk_sync").observe(time.monotonic() - start)


async def _run_epss_bulk_sync():
    import gzip
    from datetime import timedelta

    import httpx

    from app.models.cve import CVE
    from app.models.enrichment import EnrichmentSource

    stats = {"updated": 0, "total_scores": 0}

    async with _get_worker_session() as db:
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
            resp = await client.get("https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")
            resp.raise_for_status()

        decompressed = gzip.decompress(resp.content)
        epss_data = parse_epss_csv(decompressed.decode("utf-8"))

        stats["total_scores"] = len(epss_data)
        stats["score_changes"] = 0
        # Update CVEs that exist in our database
        result = await db.execute(select(CVE))
        cves = result.scalars().all()
        now = datetime.now(UTC)

        # Collect significant EPSS changes for event generation
        epss_changes: list[tuple] = []  # (cve_id_str, cve_uuid, old_score, new_score)
        matched_ids: list = []

        for cve in cves:
            if cve.cve_id in epss_data:
                scores = epss_data[cve.cve_id]
                old_epss = cve.epss_score
                new_epss = scores["epss_score"]

                # Detect significant EPSS changes:
                # - Score jumped by >= 0.1 (absolute)
                # - Score crossed the 0.5 threshold (high exploitation probability)
                if old_epss is not None and new_epss != old_epss:
                    delta = abs(new_epss - old_epss)
                    crossed_threshold = old_epss < 0.5 <= new_epss
                    if delta >= 0.1 or crossed_threshold:
                        epss_changes.append((cve.cve_id, cve.id, old_epss, new_epss))
                        # epss_jump signal reads these; epss_updated_at can't
                        # serve since every sync touches it, change or not
                        cve.epss_previous_score = old_epss
                        cve.epss_changed_at = now

                # Update CVE model directly
                cve.epss_score = new_epss
                cve.epss_percentile = scores["percentile"]
                cve.epss_updated_at = now
                db.add(cve)
                matched_ids.append(cve.id)
                stats["updated"] += 1

        # Upsert enrichment_results set-based: overwrite the existing EPSS row per
        # CVE, insert only for CVEs that don't have one yet. The old per-CVE append
        # grew this table to ~40 rows per CVE (pruned in migration m2a2b3c4d5g9).
        if matched_ids:
            await db.flush()  # make the CVE column updates visible to the SQL below
            sql_params = {
                "ids": matched_ids,
                "now": now,
                "expires": now + timedelta(hours=24),
                "date_str": now.strftime("%Y-%m-%d"),
            }
            await db.execute(
                text(
                    """
                    UPDATE enrichment_results er
                    SET raw_response = jsonb_build_object(
                            'epss_score', c.epss_score, 'percentile', c.epss_percentile),
                        parsed_data = jsonb_build_object(
                            'cve_id', c.cve_id, 'epss_score', c.epss_score,
                            'epss_percentile', c.epss_percentile, 'date', CAST(:date_str AS text)),
                        enriched_at = :now, expires_at = :expires, status = 'success'
                    FROM cves c
                    WHERE c.id = er.entity_id
                      AND er.entity_type = 'cve' AND er.source_type = 'epss'
                      AND c.id = ANY(:ids)
                    """
                ).bindparams(bindparam("ids", type_=ARRAY(UUID(as_uuid=True)))),
                sql_params,
            )
            await db.execute(
                text(
                    """
                    INSERT INTO enrichment_results
                        (id, entity_type, entity_id, source_type, raw_response,
                         parsed_data, enriched_at, expires_at, status)
                    SELECT gen_random_uuid(), 'cve', c.id, 'epss',
                           jsonb_build_object(
                               'epss_score', c.epss_score, 'percentile', c.epss_percentile),
                           jsonb_build_object(
                               'cve_id', c.cve_id, 'epss_score', c.epss_score,
                               'epss_percentile', c.epss_percentile, 'date', CAST(:date_str AS text)),
                           :now, :expires, 'success'
                    FROM cves c
                    WHERE c.id = ANY(:ids)
                      AND NOT EXISTS (
                          SELECT 1 FROM enrichment_results er
                          WHERE er.entity_id = c.id
                            AND er.entity_type = 'cve' AND er.source_type = 'epss')
                    """
                ).bindparams(bindparam("ids", type_=ARRAY(UUID(as_uuid=True)))),
                sql_params,
            )

        # Generate correlation events for significant EPSS changes
        if epss_changes:
            from app.intelligence.correlation_events import create_cve_score_change_event
            from app.workers.signal_tasks import dispatch_cve_rescore

            for cve_id_str, cve_uuid, old_score, new_score in epss_changes:
                try:
                    await create_cve_score_change_event(db, cve_id_str, cve_uuid, "epss_score", old_score, new_score)
                    stats["score_changes"] += 1
                except Exception:
                    logger.debug("Failed to create EPSS change event for %s", cve_id_str, exc_info=True)
                if new_score > old_score:
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
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_mitre_attack_sync", status="error").inc()
        logger.exception("MITRE ATT&CK sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_mitre_attack_sync").observe(time.monotonic() - start)


async def _run_mitre_attack_sync():
    from app.intelligence.attack_catalog import (
        fetch_attack_bundles,
        hydrate_attack_catalog,
        hydrate_attack_entity_attributes,
        parse_attack_bundle,
    )
    from app.models.enrichment import EnrichmentSource

    bundles = await fetch_attack_bundles()
    parsed = [parse_attack_bundle(bundle, domain) for domain, bundle in bundles.items()]

    async with _get_worker_session() as db:
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
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_misp_galaxy_sync", status="error").inc()
        logger.exception("MISP Galaxy sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_misp_galaxy_sync").observe(time.monotonic() - start)


async def _run_misp_galaxy_sync():
    import httpx

    from app.intelligence.entity_resolution import upsert_known_aliases

    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
        resp = await client.get(MISP_GALAXY_THREAT_ACTOR_URL)
        resp.raise_for_status()
        data = resp.json()

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
        from app.intelligence.actor_attributes import coerce_motivation, coerce_sectors, resolve_country_name
        from app.models.threat_actor import ThreatActor
        from app.services.claim_provenance import record_claims

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

            if not actor.targeted_sectors and attrs.get("sectors"):
                sectors = coerce_sectors(attrs["sectors"])
                if sectors:
                    actor.targeted_sectors = sectors
                    asserted["targeted_sectors"] = sectors
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
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_cve_nvd_backfill", status="error").inc()
        logger.exception("CVE NVD backfill failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_cve_nvd_backfill").observe(time.monotonic() - start)


async def _run_cve_nvd_backfill():
    import asyncio as _asyncio

    from app.intelligence.cve import enrich_from_nvd
    from app.models.cve import CVE

    stats = {"enriched": 0, "failed": 0, "skipped_invalid": 0, "total": 0}

    async with _get_worker_session() as db:
        # Resolve API key from DB (secrets are encrypted, cache may not be warm)
        from app.services.system_settings import get_setting

        api_key = await get_setting("nvd_api_key", db)
        # With API key: 50 req/30s (~0.6s each); without: 5 req/30s (~6s each)
        delay = 0.7 if api_key else 6

        # Process valid-format CVEs first (4-5 digit suffix), skip obviously bogus ones
        from sqlalchemy import func as sa_func

        result = await db.execute(
            select(CVE)
            .where(
                CVE.description.is_(None),
                sa_func.length(sa_func.split_part(CVE.cve_id, "-", 3)) <= 5,
            )
            .order_by(CVE.cve_id)
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
            "CVE NVD backfill: %d valid CVEs to enrich, %d invalid skipped (delay=%.1fs)",
            stats["total"],
            stats["skipped_invalid"],
            delay,
        )

        for i, cve_obj in enumerate(cves):
            nvd = await enrich_from_nvd(cve_obj.cve_id)
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
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_cve_nvd_refresh", status="error").inc()
        logger.exception("CVE NVD refresh failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_cve_nvd_refresh").observe(time.monotonic() - start)


async def _run_cve_nvd_refresh():
    """Re-enrich CVEs that already have NVD data, detecting CVSS score changes."""
    import asyncio as _asyncio
    from datetime import timedelta

    from app.intelligence.cve import enrich_from_nvd
    from app.models.cve import CVE

    stats = {"checked": 0, "score_changes": 0, "failed": 0, "total": 0}

    async with _get_worker_session() as db:
        from app.services.system_settings import get_setting

        api_key = await get_setting("nvd_api_key", db)
        delay = 0.7 if api_key else 6

        # Select CVEs that have NVD data and were last updated more than 7 days ago.
        # Limit to 100 per run to stay within rate limits.
        cutoff = datetime.now(UTC) - timedelta(days=7)
        from sqlalchemy import func as sa_func

        result = await db.execute(
            select(CVE)
            .where(
                CVE.description.isnot(None),
                CVE.updated_at < cutoff,
                sa_func.length(sa_func.split_part(CVE.cve_id, "-", 3)) <= 5,
            )
            .order_by(CVE.updated_at.asc())
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
            nvd = await enrich_from_nvd(cve_obj.cve_id)
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
                db.add(cve_obj)
                stats["checked"] += 1
            else:
                stats["failed"] += 1

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
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_malpedia_sync", status="error").inc()
        logger.exception("Malpedia sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_malpedia_sync").observe(time.monotonic() - start)


async def _run_malpedia_sync():
    import httpx

    from app.intelligence.actor_attributes import resolve_country_name
    from app.models.enrichment import EnrichmentSource
    from app.models.malware_family import MalwareFamily
    from app.models.threat_actor import ThreatActor
    from app.models.tool import Tool

    stats = {"families_updated": 0, "tools_updated": 0, "actors_updated": 0, "families_seen": 0}

    async with httpx.AsyncClient(timeout=120.0) as client:
        # `get/families` returns the full {family_key: {...}} payload. The
        # `list/families` endpoint this used to call returns a bare list of keys,
        # so the isinstance guard below discarded every row and the sync had been
        # a silent no-op — which is why no malware profile carried a malpedia_url.
        try:
            resp = await client.get("https://malpedia.caad.fkie.fraunhofer.de/api/get/families")
            resp.raise_for_status()
            families = resp.json()
            if not isinstance(families, dict):
                logger.warning("Malpedia families response was %s, not a dict; skipping", type(families).__name__)
                families = {}
        except Exception as e:
            logger.warning("Malpedia families fetch failed: %s", e)
            families = {}

        try:
            resp = await client.get("https://malpedia.caad.fkie.fraunhofer.de/api/get/actors")
            resp.raise_for_status()
            actors = resp.json()
            if not isinstance(actors, dict):
                logger.warning("Malpedia actors response was %s, not a dict; skipping", type(actors).__name__)
                actors = {}
        except Exception as e:
            logger.warning("Malpedia actors fetch failed: %s", e)
            actors = {}

    stats["families_seen"] = len(families)
    stats["actors_seen"] = len(actors)

    async with _get_worker_session() as db:
        for family_key, family_data in families.items():
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
                break

        for actor_key, actor_data in actors.items():
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
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_github_poc_scan", status="error").inc()
        logger.exception("GitHub PoC scan failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_github_poc_scan").observe(time.monotonic() - start)


async def _run_github_poc_scan():
    from datetime import timedelta

    import httpx
    from sqlalchemy import case, or_

    from app.enrichment.results import upsert_enrichment_result
    from app.models.cve import CVE
    from app.models.enrichment import EnrichmentResult, EnrichmentSource

    stats = {"scanned": 0, "pocs_found": 0, "rate_limited": False}

    # Get source for API key
    async with _get_worker_session() as db:
        # Warm before the settings.get() reads below — batch limit, rescan
        # window and the fallback token are all DB-overridable.
        from app.services.system_settings import warm_settings_cache

        await warm_settings_cache(db)
        source_result = await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "github_poc"))
        source = source_result.scalar_one_or_none()
        api_key = None
        if source and source.api_key_encrypted:
            from app.core.encryption import decrypt_value

            api_key = decrypt_value(source.api_key_encrypted)
        # Fall back to a globally configured token so the scan isn't stuck on
        # GitHub's 10 req/min unauthenticated search limit just because nobody
        # pasted a key into the enrichment source form.
        api_key = api_key or (settings.get("github_token") or None)

        headers = {"Accept": "application/vnd.github.v3+json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # Authenticated search allows 30 req/min; unauthenticated only 10, and
        # it 403s partway through a run. Size the batch to the credential we
        # actually have.
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

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            for cve in cves:
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
                    if resp.status_code in (403, 429):
                        logger.warning("GitHub rate limited after %d CVEs, stopping scan", stats["scanned"])
                        stats["rate_limited"] = True
                        break
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
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_wikipedia_bulk_sync", status="error").inc()
        logger.exception("Wikipedia bulk sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_wikipedia_bulk_sync").observe(time.monotonic() - start)


async def _run_wikipedia_bulk_sync():
    import asyncio as _asyncio
    from datetime import timedelta

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
    }

    async with _get_worker_session() as db:
        now = datetime.now(UTC)
        batch_count = 0

        for entity_type, model_cls, name_attr in entity_configs:
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
                entity_name = getattr(entity, name_attr)
                if not entity_name:
                    stats["skipped"] += 1
                    continue

                try:
                    wiki_result = await fetch_wikipedia(entity_name, entity_type)
                except Exception as e:
                    logger.warning("Wikipedia fetch failed for %s/%s: %s", entity_type, entity_name, e)
                    stats["failed"] += 1
                    await _asyncio.sleep(6.0)
                    continue

                if not wiki_result:
                    stats["skipped"] += 1
                    await _asyncio.sleep(6.0)
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
                    await _asyncio.sleep(6.0)
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

                # Rate limit: ~10 requests/minute
                await _asyncio.sleep(6.0)

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


async def _run_metasploit_sync():
    """Populate CVE.metasploit_module and escalate exploit_availability.

    Nothing in the codebase had ever written `metasploit_module`, which left the
    column, the workbench MSF column, and the `weaponized` branch of the exploit
    escalation permanently inert. Rapid7 publishes the module index as a single
    JSON file, so this needs no API key and no per-CVE requests.
    """
    import httpx

    from app.models.cve import CVE

    stats = {"modules_seen": 0, "cves_matched": 0, "cves_updated": 0, "escalated": 0}

    async with httpx.AsyncClient(timeout=180.0, follow_redirects=True) as client:
        resp = await client.get(METASPLOIT_METADATA_URL)
        resp.raise_for_status()
        metadata = resp.json()

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

            sources = list(cve.exploit_sources or [])
            if "metasploit" not in sources:
                sources.append("metasploit")
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
