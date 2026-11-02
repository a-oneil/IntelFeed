"""Celery tasks for the enrichment sources' scheduled jobs — EPSS, MITRE ATT&CK,
MISP Galaxy, Malpedia, Metasploit, NVD, GitHub PoC, Wikipedia, cvelistV5, Wikidata, endoflife.date,
Tranco, CAPEC, CTID control mappings, D3FEND, abuse.ch ThreatFox and URLhaus."""

import asyncio
import csv
import io
import ipaddress
import itertools
import logging
import re
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

from sqlalchemy import bindparam, select, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID

from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.enrichment.gateway import (
    JOB_TOKEN_WAIT,
    SOURCE_REFUSALS,
    AuthFailed,
    GatewayError,
    GatewayUnavailable,
    SourceGateway,
)
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


#: How long a stored EPSS answer stands. A score that hasn't changed isn't
#: rewritten; its rows are renewed in bulk once they come within EPSS_RENEW
#: of expiring, so a day's sync touches only what changed plus a sliver.
EPSS_TTL = timedelta(days=30)
#: The percentile move that rewrites a CVE whose score didn't change: one point.
EPSS_PERCENTILE_STEP = 0.01
EPSS_RENEW = timedelta(days=2)


@source_job("epss")
async def _run_epss_bulk_sync():
    """Download FIRST's daily CSV and apply it set-based, a chunk per
    transaction. A CVE is written (the cves row, its EPSS result row and
    context) only when its score changed or its percentile moved by
    EPSS_PERCENTILE_STEP or more; a percentile ranks a CVE against all the
    others, so smaller moves happen to nearly every CVE every day and rewrite
    nothing. The columns are EPSSAdapter's Column outputs, which a single
    lookup writes through the field map; this job writes them set-based and
    records no claims: a claim per CVE per changed score would grow without
    bound."""
    import gzip

    from app.intelligence.correlation_events import create_cve_score_change_event
    from app.models.enrichment import EnrichmentSource
    from app.workers.signal_tasks import dispatch_cve_rescore

    stats = {"fetched": 0, "changed": 0, "written": 0, "updated": 0, "total_scores": 0, "score_changes": 0}

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
        "expires": now + EPSS_TTL,
        "date_str": now.strftime("%Y-%m-%d"),
    }

    # Significant change: the score jumped by >= 0.1 (absolute) or crossed the
    # 0.5 threshold (high exploitation probability). Columns read in SET are the
    # pre-update row, so c.epss_score is the score being replaced. The epss_jump
    # signal reads epss_previous_score/epss_changed_at; epss_updated_at is when
    # the score last changed.
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
          AND (
            c.epss_score IS DISTINCT FROM i.score
            OR c.epss_percentile IS NULL
            OR abs(c.epss_percentile - i.pct) >= :pct_step
          )
        RETURNING c.id, c.cve_id, c.epss_previous_score, c.epss_score, c.epss_changed_at = :now AS changed
        """
    )
    # Upsert enrichment_results set-based: overwrite the existing EPSS row per
    # CVE, insert only for CVEs that don't have one yet. parsed_data has the
    # lookup adapter's keys (EPSSAdapter), so both read as one source.
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
    # The source's Context outputs (EPSSAdapter: epss, percentile, date), as
    # store_context would write them, for the same CVEs.
    upsert_context = text(
        """
        INSERT INTO entity_context (entity_type, entity_id, source_type, key, value, observed_at, expires_at)
        SELECT 'cve', c.id, 'epss', k.key, k.value, :now, :expires
        FROM cves c
        CROSS JOIN LATERAL (VALUES
            ('epss', to_jsonb(c.epss_score)),
            ('percentile', to_jsonb(c.epss_percentile)),
            ('date', to_jsonb(CAST(:date_str AS text)))
        ) AS k(key, value)
        WHERE c.id = ANY(:ids) AND k.value IS NOT NULL
        ON CONFLICT (entity_type, entity_id, source_type, key)
        DO UPDATE SET value = EXCLUDED.value, observed_at = EXCLUDED.observed_at, expires_at = EXCLUDED.expires_at
        """
    ).bindparams(ids_param)
    renew = {"expires": now + EPSS_TTL, "renew_before": now + EPSS_RENEW}
    renew_results = text(
        """
        UPDATE enrichment_results SET expires_at = :expires
        WHERE entity_type = 'cve' AND source_type = 'epss' AND status = 'success' AND expires_at < :renew_before
        """
    )
    renew_context = text(
        """
        UPDATE entity_context SET expires_at = :expires
        WHERE entity_type = 'cve' AND source_type = 'epss' AND expires_at < :renew_before
        """
    )

    async with _get_worker_session() as db:
        for chunk in itertools.batched(iter_epss_csv(csv_text), _EPSS_CHUNK_SIZE):
            stats["total_scores"] += len(chunk)
            cve_ids, scores, pcts = (list(col) for col in zip(*chunk, strict=True))
            rows = (
                await db.execute(
                    update_cves,
                    {"now": now, "cve_ids": cve_ids, "scores": scores, "pcts": pcts, "pct_step": EPSS_PERCENTILE_STEP},
                )
            ).all()
            if not rows:
                continue
            stats["updated"] += len(rows)

            matched_ids = [row.id for row in rows]
            await db.execute(update_results, {**sql_params, "ids": matched_ids})
            await db.execute(insert_results, {**sql_params, "ids": matched_ids})
            await db.execute(upsert_context, {**sql_params, "ids": matched_ids})

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

        # Answers that didn't change stand: renew the rows about to expire.
        await db.execute(renew_results, renew)
        await db.execute(renew_context, renew)

        # Update source last_synced_at
        source_result = await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "epss"))
        source = source_result.scalar_one_or_none()
        if source:
            source.last_synced_at = now
            source.health_status = "healthy"
            db.add(source)

        await db.commit()

    stats["fetched"] = stats["total_scores"]
    stats["changed"] = stats["written"] = stats["updated"]
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
        return {"fetched": 0, "changed": 0, "written": 0, "stopped": e.status}

    items = parse_misp_galaxy_clusters(data)
    if not items:
        # An empty/garbled feed must not wipe the existing knowledge.
        logger.warning("MISP Galaxy threat-actor cluster returned no values; keeping existing alias map")
        return {"fetched": 0, "changed": 0, "written": 0, "clusters": 0, "alias_rows": 0, "skipped": True}

    attributes = parse_misp_galaxy_attributes(data)

    async with _get_worker_session() as db:
        rows = await upsert_known_aliases(db, "misp_galaxy", items)

        # The synonym clusters stay resolution-only knowledge (guardrails Phase
        # 4). The rest of the cluster metadata is ordinary profile data, applied
        # through the field map to actors we already track: it fills blanks
        # only (MISPGalaxySource's outputs), with a claim naming MISP Galaxy.
        from app import entity_types
        from app.enrichment.base import EnrichmentData
        from app.enrichment.pipeline import apply_source_result
        from app.intelligence.sectors import normalize_sectors
        from app.models.threat_actor import ThreatActor

        synonyms_by_name = dict(items)
        stats = {"fetched": len(items), "changed": 0, "written": 0, "matched": 0}
        cache: dict = {}
        for name, attrs in attributes.items():
            actor = await find_entity_by_name_or_alias(db, ThreatActor, name, synonyms_by_name.get(name) or [])
            if not actor:
                continue
            stats["matched"] += 1
            parsed = {"found": True, "name": name, **attrs}
            if attrs.get("sectors"):
                parsed["sectors"] = normalize_sectors(attrs["sectors"])
            data = EnrichmentData(raw_response={"cluster": name}, parsed_data=parsed, ttl_hours=24 * 8)
            applied = await apply_source_result(db, entity_types.THREAT_ACTOR, actor.id, "misp_galaxy", data, cache)
            stats["changed"] += applied.changed
            stats["written"] += applied.written

        await db.commit()
    return {**stats, "clusters": len(items), "alias_rows": rows}


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


def _bounded(gateway: SourceGateway, deadline: float) -> bool:
    """Let ``gateway`` wait for a token only as long as the run has left, so a
    token wait can't carry a job past its time budget. False once it's spent."""
    left = deadline - time.monotonic()
    gateway.max_wait = max(0.0, min(JOB_TOKEN_WAIT, left))
    return left > 0


def _per_run(gateway: SourceGateway, seconds: float) -> int:
    """How many requests fit in ``seconds`` at the gateway's rate."""
    return int(seconds * gateway.capacity / gateway.period) + gateway.capacity


@source_job("nvd", lane="backfill")
async def _run_cve_nvd_backfill():
    """Look up each CVE that has no NVD record yet, whatever else filled it
    (a CNA's record from cvelist fills the description first), within the
    retry budget for ids NVD keeps missing. The gateway paces the requests;
    each answer goes through the NVD source's field map (``apply_nvd``)."""
    from sqlalchemy import func as sa_func
    from sqlalchemy import or_

    from app.intelligence.cve import apply_nvd, enrich_from_nvd, nvd_gateway, nvd_retry_allowed, stamp_nvd_miss
    from app.models.cve import CVE

    stats = {
        "fetched": 0,
        "changed": 0,
        "written": 0,
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

        # No NVD record: never looked up, or only miss stamps so far. Ids NVD
        # has already missed on are retried on the shared budget (3 lookups, a
        # week apart), since autolink and extraction mint a stub for any
        # CVE-shaped string. Valid-format ids only (a 4-5 digit suffix).
        no_record = or_(CVE.nvd_data.is_(None), ~CVE.nvd_data.has_key("id"))
        valid = sa_func.length(sa_func.split_part(CVE.cve_id, "-", 3)) <= 5
        due = (no_record, valid, nvd_retry_allowed(now))
        stats["pending"] = (await db.execute(select(sa_func.count()).select_from(CVE).where(*due))).scalar() or 0
        # Load only what one run can look up at the source's rate; the rest
        # waits for tomorrow's run. CVEs nothing has filled go first.
        result = await db.execute(
            select(CVE)
            .where(*due)
            .order_by(
                or_(CVE.cvss_score.is_(None), CVE.description.is_(None)).desc(),
                CVE.is_kev.desc(),
                CVE.cve_id,
            )
            .limit(_per_run(gateway, _NVD_BACKFILL_BUDGET_S))
        )
        cves = result.scalars().all()
        stats["total"] = len(cves)
        stats["skipped_invalid"] = (
            await db.execute(select(sa_func.count()).select_from(CVE).where(no_record, ~valid))
        ).scalar() or 0

        logger.info(
            "CVE NVD backfill: %d of %d valid CVEs this run, %d invalid skipped",
            stats["total"],
            stats["pending"],
            stats["skipped_invalid"],
        )

        cache: dict = {}
        for i, cve_obj in enumerate(cves):
            if not _bounded(gateway, deadline):
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
                stats["fetched"] += 1
                applied = await apply_nvd(db, cve_obj, nvd, cache, via="cve-nvd-backfill")
                stats["changed"] += applied.changed
                stats["written"] += applied.written
                stats["enriched"] += 1
            else:
                stamp_nvd_miss(cve_obj, now)
                db.add(cve_obj)
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


_NVD_REFRESH_BUDGET_S = 780
#: How far back a first run (no window read yet) looks for changes.
_NVD_REFRESH_FIRST_WINDOW = timedelta(days=8)


@source_job("nvd")
async def _run_cve_nvd_refresh():
    """Apply every NVD record changed since the last run to the CVEs IntelFeed
    holds, detecting CVSS score changes. One request returns up to 2,000
    changed records, so a day of NVD's changes costs a few requests rather
    than one per CVE.

    The window starts where the last fully read one ended (the nvd row's
    ``last_synced_at``; a first run looks back 8 days) and covers at most
    NVD's 120 days. A run that stops part way keeps the window's start, and
    the next reads it again: records already applied change nothing.

    Each answer goes through the NVD source's field map, so a newer NVD score
    replaces NVD's own (or a lower-ranked source's) but never an analyst's."""
    from app.intelligence.correlation_events import create_cve_score_change_event
    from app.intelligence.cve import NVD_MAX_WINDOW, apply_nvd, fetch_nvd_changes, nvd_gateway
    from app.models.cve import CVE
    from app.models.enrichment import EnrichmentSource

    stats = {"fetched": 0, "changed": 0, "written": 0, "checked": 0, "score_changes": 0, "pages": 0, "total": 0}
    stats["stopped"] = None
    deadline = time.monotonic() + _NVD_REFRESH_BUDGET_S

    async with _get_worker_session() as db:
        gateway, api_key = await nvd_gateway(db, max_wait=JOB_TOKEN_WAIT)
        source = (
            await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "nvd"))
        ).scalar_one_or_none()
        now = datetime.now(UTC)
        since = source.last_synced_at if source and source.last_synced_at else now - _NVD_REFRESH_FIRST_WINDOW
        since = max(since, now - NVD_MAX_WINDOW)
        stats["since"] = since.isoformat()

        cache: dict = {}
        index = 0
        while True:
            if not _bounded(gateway, deadline):
                stats["stopped"] = "out_of_time"
                break
            try:
                records, stats["total"] = await fetch_nvd_changes(since, now, gateway, api_key, index)
            except SOURCE_REFUSALS as e:
                logger.warning("CVE NVD refresh stopping at %d/%d: %s", index, stats["total"], e)
                stats["stopped"] = e.status
                break
            stats["pages"] += 1
            ids = [r["nvd_data"]["id"] for r in records]
            held = {c.cve_id: c for c in (await db.execute(select(CVE).where(CVE.cve_id.in_(ids)))).scalars()}
            for nvd in records:
                cve_obj = held.get(nvd["nvd_data"]["id"])
                if cve_obj is None:
                    continue
                stats["fetched"] += 1
                old_cvss = float(cve_obj.cvss_score) if cve_obj.cvss_score is not None else None
                applied = await apply_nvd(db, cve_obj, nvd, cache, via="cve-nvd-refresh")
                stats["changed"] += applied.changed
                stats["written"] += applied.written
                new_cvss = float(cve_obj.cvss_score) if cve_obj.cvss_score is not None else None

                # Detect CVSS severity tier escalation into high (>=7.0) or critical (>=9.0).
                # Numeric changes within the same tier, or any downgrade, do not notify.
                if old_cvss is not None and new_cvss is not None:
                    old_rank = _cvss_tier_rank(old_cvss)
                    new_rank = _cvss_tier_rank(new_cvss)
                    if new_rank > old_rank and new_rank >= 3:
                        try:
                            await create_cve_score_change_event(
                                db, cve_obj.cve_id, cve_obj.id, "cvss_score", old_cvss, new_cvss
                            )
                            stats["score_changes"] += 1
                        except Exception:
                            logger.debug("Failed to create CVSS change event for %s", cve_obj.cve_id, exc_info=True)
                        from app.workers.signal_tasks import dispatch_cve_rescore

                        dispatch_cve_rescore(cve_obj.id)
                stats["checked"] += 1
                cve_obj.nvd_data = {**(cve_obj.nvd_data or {}), "_refreshed_at": now.isoformat()}
                db.add(cve_obj)
            await db.commit()
            index += len(records)
            if not records or index >= stats["total"]:
                break

        if stats["stopped"] is None and source is not None:
            source.last_synced_at = now
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
    from app.enrichment.base import EnrichmentData
    from app.enrichment.pipeline import apply_source_result
    from app.intelligence.actor_attributes import resolve_country_name
    from app.models.enrichment import EnrichmentSource
    from app.models.malware_family import MalwareFamily
    from app.models.threat_actor import ThreatActor
    from app.models.tool import Tool

    stats = {"fetched": 0, "changed": 0, "written": 0, "families_updated": 0, "tools_updated": 0}
    stats.update({"actors_updated": 0, "families_seen": 0, "stopped": None})

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
    stats["fetched"] = len(families) + len(actors)

    async with _get_worker_session() as db:
        # Commit in batches: one transaction over thousands of malware, tool and
        # actor rows held locks long enough to deadlock with other catalog syncs.
        # Each match is applied as a lookup's answer would be (the Malpedia
        # source's columns, claims and context, apply_source_result).
        dirty = 0
        cache: dict = {}
        for family_key, family_data in families.items():
            if dirty >= _MALPEDIA_COMMIT_EVERY:
                await db.commit()
                dirty = 0
            if not isinstance(family_data, dict):
                continue
            common_name = family_data.get("common_name") or family_key
            alt_names = [a for a in family_data.get("alt_names") or [] if isinstance(a, str)]
            data = _malpedia_family_result(family_key, family_data)

            # Malpedia files offensive tooling under the same family namespace as
            # malware, so a key can match either table. Try malware first — it's
            # the larger and more specific catalog — then tools.
            for model, entity_type, stat_key in (
                (MalwareFamily, "malware", "families_updated"),
                (Tool, "tool", "tools_updated"),
            ):
                entity = await find_entity_by_name_or_alias(db, model, common_name, alt_names)
                if not entity:
                    continue
                applied = await apply_source_result(db, entity_type, entity.id, "malpedia", data, cache)
                stats["changed"] += applied.changed
                stats["written"] += applied.written
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
            # Malpedia reports ISO alpha-2; the column stores full names.
            country = await resolve_country_name(db, meta["country"]) if meta.get("country") else None
            data = EnrichmentData(
                raw_response={"via": "malpedia-sync", "id": actor_key},
                parsed_data={
                    "found": True,
                    "actor_name": actor_data.get("value") or actor_key,
                    "description": (actor_data.get("description") or "")[:2000],
                    "alt_names": synonyms,
                    "country": country,
                    "refs": [r for r in meta.get("refs") or [] if isinstance(r, str)][:10],
                    "families": list(actor_data.get("families") or {})[:20],
                },
                ttl_hours=168,
            )
            applied = await apply_source_result(db, "threat_actor", actor.id, "malpedia", data, cache)
            stats["changed"] += applied.changed
            stats["written"] += applied.written
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


def _malpedia_family_result(family_key: str, family_data: dict):
    """A ``get/families`` entry as the Malpedia source's answer for a family
    (the lookup's keys). The family page is built from its key, and GitHub
    links go first, so the repository survives the reference list's cap."""
    from app.enrichment.base import EnrichmentData

    urls = [u for u in family_data.get("urls") or [] if isinstance(u, str)]
    urls = sorted(urls, key=lambda u: "github.com/" not in u)[:25]
    return EnrichmentData(
        raw_response={"via": "malpedia-sync", "id": family_key},
        parsed_data={
            "found": True,
            "family_name": family_data.get("common_name") or family_key,
            "description": (family_data.get("description") or "")[:2000],
            "alt_names": [a for a in family_data.get("alt_names") or [] if isinstance(a, str)],
            "attribution": [a for a in family_data.get("attribution") or [] if isinstance(a, str)],
            "urls": urls,
            "malpedia_url": f"https://malpedia.caad.fkie.fraunhofer.de/details/{family_key}",
        },
        ttl_hours=168,
    )


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

    from app.enrichment.adapters.github_poc import GitHubPoCAdapter, parse_search
    from app.enrichment.base import EnrichmentData
    from app.enrichment.pipeline import apply_source_result, gateway_for
    from app.models.cve import CVE
    from app.models.enrichment import EnrichmentResult, EnrichmentSource
    from app.services.claim_provenance import record_claim

    stats = {"fetched": 0, "changed": 0, "written": 0, "scanned": 0, "pocs_found": 0, "stopped": None}
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

        cache: dict = {}
        async with gateway.client(timeout=30.0, headers=headers) as client:
            for cve in cves:
                if not _bounded(gateway, deadline):
                    stats["stopped"] = "out_of_time"
                    break
                try:
                    resp = await client.get(
                        GitHubPoCAdapter._api_url,
                        params={"q": GitHubPoCAdapter.search_query(cve.cve_id), "sort": "stars", "per_page": 5},
                    )
                    resp.raise_for_status()
                    parsed = parse_search(cve.cve_id, resp.json())
                    stats["fetched"] += 1
                    # Stored, its context (the PoC badge, repos) written, as a
                    # lookup's answer is. The raw response is the search, kept
                    # small: parsed_data holds what is used.
                    applied = await apply_source_result(
                        db,
                        "cve",
                        cve.id,
                        "github_poc",
                        EnrichmentData(
                            raw_response={"via": "github-poc-scan", "total_count": parsed["poc_count"]},
                            parsed_data=parsed,
                            ttl_hours=24,
                        ),
                        cache,
                    )
                    stats["changed"] += applied.changed
                    poc_repos = parsed["poc_repos"]

                    # Update CVE model directly. Write the count even when the
                    # scan finds nothing, so "scanned, no PoC" reads as 0 rather
                    # than looking unscanned, and a rescan clears stale hits.
                    old_poc_count = cve.github_poc_count or 0
                    new_poc_urls = [r["url"] for r in poc_repos]
                    if (cve.github_poc_count, list(cve.github_poc_urls or [])) != (len(poc_repos), new_poc_urls):
                        cve.github_poc_count = len(poc_repos)
                        cve.github_poc_urls = new_poc_urls
                        db.add(cve)
                        stats["written"] += 1
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
                            await record_claim(
                                db,
                                entity_type="cve",
                                entity_id=cve.id,
                                field="exploit_availability",
                                value=new_availability,
                                source_kind="enrichment",
                                source_ref="github_poc",
                            )
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
                except (GatewayUnavailable, AuthFailed):
                    # A rejected key fails the job so Engine → Jobs shows why.
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
#: How long "no article" stands before the weekly sync asks again.
_WIKIPEDIA_NOT_FOUND_TTL_H = 30 * 24


async def _wikipedia_not_found(db, entity_type: str, entity_id, cache: dict, reason: str) -> None:
    """Store a "no article" answer, so the next runs move on to other names."""
    from app.enrichment.base import EnrichmentData
    from app.enrichment.pipeline import apply_source_result

    data = EnrichmentData(
        raw_response={"via": "wikipedia-bulk-sync", "status": reason},
        parsed_data={"found": False},
        ttl_hours=_WIKIPEDIA_NOT_FOUND_TTL_H,
    )
    await apply_source_result(db, entity_type, entity_id, "wikipedia", data, cache)


@source_job("wikipedia", lane="backfill")
async def _run_wikipedia_bulk_sync():

    from app.enrichment.base import EnrichmentData
    from app.enrichment.pipeline import apply_source_result, gateway_for
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
        "fetched": 0,
        "changed": 0,
        "written": 0,
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
        cache: dict = {}
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
            # An answer that still stands (a "no article" one included) isn't
            # asked again.
            fresh_answer = (
                select(EnrichmentResult.id)
                .where(
                    EnrichmentResult.entity_type == entity_type,
                    EnrichmentResult.entity_id == model_cls.id,
                    EnrichmentResult.source_type == "wikipedia",
                    EnrichmentResult.expires_at > now,
                )
                .exists()
            )
            result = await db.execute(
                select(model_cls)
                .where(model_cls.wikipedia_content.is_(None), ~cleared_marker, ~fresh_answer)
                .order_by(model_cls.name)
                .limit(BATCH_LIMIT)
            )
            entities = result.scalars().all()

            for entity in entities:
                if not _bounded(gateway, deadline):
                    stats["stopped"] = "out_of_time"
                    break
                entity_name = getattr(entity, name_attr)
                if not entity_name:
                    stats["skipped"] += 1
                    continue

                # The source's bucket paces the requests (several per entity).
                # One entity can make a dozen of them, each waiting for a slot,
                # so the run's time left bounds the whole fetch, not just the
                # first wait.
                try:
                    wiki_result = await asyncio.wait_for(
                        fetch_wikipedia(entity_name, entity_type, transport=gateway.transport()),
                        timeout=max(1.0, deadline - time.monotonic()),
                    )
                except TimeoutError:
                    stats["stopped"] = "out_of_time"
                    break
                except SOURCE_REFUSALS as e:
                    logger.warning("Wikipedia bulk sync stopping: %s", e)
                    stats["stopped"] = e.status
                    break
                except (GatewayUnavailable, AuthFailed):
                    # A rejected key fails the job so Engine → Jobs shows why.
                    raise
                except Exception as e:
                    logger.warning("Wikipedia fetch failed for %s/%s: %s", entity_type, entity_name, e)
                    stats["failed"] += 1
                    continue

                if not wiki_result:
                    await _wikipedia_not_found(db, entity_type, entity.id, cache, "no_article")
                    stats["skipped"] += 1
                    continue
                stats["fetched"] += 1

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
                    await _wikipedia_not_found(db, entity_type, entity.id, cache, "off_topic")
                    stats["skipped"] += 1
                    continue

                # Applied as a lookup's answer is: the article's columns move
                # together, the first paragraph takes the description by rank,
                # and each write is claimed for Wikipedia.
                applied = await apply_source_result(
                    db,
                    entity_type,
                    entity.id,
                    "wikipedia",
                    EnrichmentData(
                        raw_response={"via": "wikipedia-bulk-sync", "title": wiki_result["title"]},
                        parsed_data={
                            "found": True,
                            "wikipedia_url": wiki_result["url"],
                            "wikipedia_content": wiki_result["content"],
                            "wikipedia_image_url": wiki_result.get("image_url"),
                            "title": wiki_result["title"],
                            "first_paragraph": extract_first_paragraph(wiki_result["content"]),
                        },
                        ttl_hours=720,
                    ),
                    cache,
                )
                stats["changed"] += applied.changed
                stats["written"] += applied.written

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
    from app.models.cve import CVE

    stats = {"fetched": 0, "changed": 0, "written": 0, "modules_seen": 0, "cves_matched": 0, "cves_updated": 0}
    stats["escalated"] = 0

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

    stats["modules_seen"] = stats["fetched"] = len(metadata)
    by_cve = parse_metasploit_modules(metadata)
    stats["cves_matched"] = len(by_cve)
    if not by_cve:
        return stats

    from app.enrichment.base import EnrichmentData
    from app.enrichment.pipeline import apply_source_result
    from app.intelligence.correlation_events import create_exploit_status_change_event
    from app.services.claim_provenance import record_claim

    async with _get_worker_session() as db:
        # Only touch CVEs we actually track; the module index covers far more.
        rows = (await db.execute(select(CVE).where(CVE.cve_id.in_(list(by_cve))))).scalars().all()
        rescored: list = []
        cache: dict = {}
        for cve in rows:
            modules = by_cve.get(cve.cve_id.upper()) or []
            if not modules:
                continue
            # The primary module goes on the column (and exploit_sources, via
            # MetasploitSource.apply_record); the full list is profile context.
            data = EnrichmentData(
                raw_response={"via": "metasploit-sync"},
                parsed_data={"found": True, "module": modules[0], "modules": modules},
                ttl_hours=24 * 8,
            )
            sources_before = list(cve.exploit_sources or [])
            applied = await apply_source_result(db, "cve", cve.id, "metasploit", data, cache)
            stats["changed"] += applied.changed
            written = applied.written or list(cve.exploit_sources or []) != sources_before

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
                db.add(cve)
                written = True
                await record_claim(
                    db,
                    entity_type="cve",
                    entity_id=cve.id,
                    field="exploit_availability",
                    value="weaponized",
                    source_kind="enrichment",
                    source_ref="metasploit",
                )

            if written:
                stats["cves_updated"] += 1
                stats["written"] += 1
            if cve.exploit_availability != old:
                stats["escalated"] += 1
                rescored.append(cve.id)
                await create_exploit_status_change_event(db, cve.cve_id, cve.id, old, cve.exploit_availability)

        await db.commit()

    if rescored:
        from app.workers.signal_tasks import dispatch_cve_rescore

        for cve_id in rescored:
            dispatch_cve_rescore(cve_id)

    return stats


# --- cvelistV5: the CVE Program's records, CNA and CISA-ADP containers ---


async def _apply_cvelist_record(db, cve_pk, data, cache: dict, stats: dict) -> None:
    """Store one CVE record as the cvelist source's result for the CVE: its
    context, its declared columns, and (the source's ``apply_record``) its CWE
    ids as cve_weaknesses links and affected products as cve_affected rows."""
    from app.enrichment.pipeline import apply_source_result

    applied = await apply_source_result(db, "cve", cve_pk, "cvelist", data, cache)
    stats["changed"] += applied.changed
    stats["written"] += applied.written
    stats["updated"] += applied.written


@celery_app.task(name="app.workers.enrichment_tasks.run_cvelist_backfill", soft_time_limit=900, time_limit=960)
def run_cvelist_backfill():
    """Hourly: apply the cvelistV5 baseline to CVEs the cvelist source hasn't checked lately."""
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


# Wall-clock seconds a backfill run may spend: 120s under the 900s soft limit,
# left for the last commit.
_CVELIST_BACKFILL_BUDGET_S = 780
# The largest baseline zip downloaded (every record: about 650 MB).
_CVELIST_BASELINE_MAX_BYTES = 2 * 1024**3
# Where the baseline is kept between runs: a run that runs out of time leaves
# it for the next, which goes on without downloading it again.
_CVELIST_BASELINE_DIR = "intelfeed-cvelist"


async def _cvelist_baseline(client) -> str | None:
    """The newest baseline zip on local disk, downloaded through the source's
    gateway when it isn't there yet (older ones are deleted). None when the
    releases list no baseline."""
    import os
    import tempfile

    from app.enrichment.adapters.cvelist import RELEASES_URL, pick_baseline

    resp = await client.get(RELEASES_URL, params={"per_page": 5}, headers={"Accept": "application/vnd.github+json"})
    resp.raise_for_status()
    picked = pick_baseline(resp.json())
    if picked is None:
        return None
    name, url = picked
    folder = os.path.join(tempfile.gettempdir(), _CVELIST_BASELINE_DIR)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, os.path.basename(name))
    for old in os.listdir(folder):
        if os.path.join(folder, old) != path:
            os.remove(os.path.join(folder, old))
    if not os.path.exists(path):
        partial = path + ".part"
        try:
            with open(partial, "w+b") as fh:
                await _download_to(client, url, fh, _CVELIST_BASELINE_MAX_BYTES)
            os.replace(partial, path)
        finally:
            if os.path.exists(partial):
                os.remove(partial)
    return path


def _baseline_records(path: str, wanted) -> Iterator[tuple[str, dict]]:
    """(CVE id, record) for each record in the baseline at ``path`` whose id
    ``wanted`` accepts, streamed: the outer zip's ``cves.zip`` member is read
    front to back, one record in memory at a time."""
    import json
    import zipfile

    from app.enrichment.adapters.cvelist import iter_zip, member_cve_id

    with zipfile.ZipFile(path) as outer:
        inner = next((n for n in outer.namelist() if n.endswith(".zip")), None)
        if inner is None:
            raise ValueError(f"{path} holds no records zip")
        with outer.open(inner) as stream:
            for name, data in iter_zip(stream, lambda n: wanted(member_cve_id(n))):
                yield member_cve_id(name), json.loads(data)


async def _cvelist_records(db, gateway, due: dict, deadline: float, cache: dict, stats: dict) -> None:
    """Fetch and apply the due CVEs' records one request each, as a lookup does."""
    import httpx

    from app.enrichment.adapters.cvelist import CVEListAdapter

    adapter = CVEListAdapter(gateway=gateway)
    for i, (cve_id, cve_pk) in enumerate(due.items()):
        if not _bounded(gateway, deadline):
            stats["stopped"] = "out_of_time"
            break
        try:
            data = await adapter.enrich("cve", cve_id)
        except SOURCE_REFUSALS as e:
            logger.warning("cvelist backfill stopping at %d/%d: %s", i, len(due), e)
            stats["stopped"] = e.status
            break
        except (httpx.HTTPError, ValueError) as e:
            # A server error or an unreadable record: left unchecked, so the
            # next run tries it again.
            logger.warning("cvelist record for %s failed: %s", cve_id, e)
            continue
        stats["fetched"] += 1
        if not data.parsed_data.get("found"):
            stats["not_found"] += 1
        await _apply_cvelist_record(db, cve_pk, data, cache, stats)
        if (i + 1) % 50 == 0:
            await db.commit()


@source_job("cvelist", lane="backfill")
async def _run_cvelist_backfill():
    """Apply the record of each CVE with no unexpired cvelist result, read from
    the cvelistV5 baseline zip (every record as of midnight UTC, published with
    each release) instead of fetched one at a time.

    With only a few CVEs due (fewer than half a run's worth of requests at the
    source's rate), their records are fetched one at a time instead. The zip
    is downloaded once through the source's gateway and kept on local disk; a
    run reads it front to back for the CVEs due and stops at its time budget,
    and the next run goes on with what is still due. Once a run has read the
    whole zip, the due CVEs it doesn't hold are stored as not found (asked
    again in NOT_FOUND_TTL_HOURS). The delta sync keeps a record current after
    that, and it is checked here again once its result expires
    (RECORD_TTL_HOURS).
    """
    import asyncio

    import httpx
    from sqlalchemy import exists

    from app.enrichment.adapters.cvelist import NOT_FOUND_TTL_HOURS, record_result
    from app.enrichment.base import EnrichmentData
    from app.enrichment.pipeline import gateway_for
    from app.models.cve import CVE
    from app.models.enrichment import EnrichmentResult

    stats = {"fetched": 0, "changed": 0, "written": 0, "updated": 0, "not_found": 0, "pending": 0, "stopped": None}
    deadline = time.monotonic() + _CVELIST_BACKFILL_BUDGET_S
    async with _get_worker_session() as db:
        checked = exists().where(
            EnrichmentResult.source_type == "cvelist",
            EnrichmentResult.entity_type == "cve",
            EnrichmentResult.entity_id == CVE.id,
            EnrichmentResult.expires_at > datetime.now(UTC),
        )
        due = {
            cve_id.upper(): cve_pk
            for cve_pk, cve_id in (await db.execute(select(CVE.id, CVE.cve_id).where(~checked))).all()
        }
        stats["pending"] = len(due)
        if not due:
            return stats

        gateway, _ = await gateway_for(db, "cvelist", max_wait=JOB_TOKEN_WAIT)
        cache: dict = {}
        if len(due) <= _per_run(gateway, _CVELIST_BACKFILL_BUDGET_S) // 2:
            # A few new CVEs: their records one at a time beat a baseline download.
            await _cvelist_records(db, gateway, due, deadline, cache, stats)
            await db.commit()
            return stats
        _bounded(gateway, deadline)
        try:
            async with gateway.client(timeout=60, follow_redirects=True) as client:
                path = await _cvelist_baseline(client)
        except SOURCE_REFUSALS as e:
            logger.warning("cvelist backfill skipped: %s", e)
            return {**stats, "stopped": e.status}
        except (httpx.HTTPError, ValueError, OSError) as e:
            logger.warning("cvelist baseline download failed: %s", e)
            return {**stats, "stopped": "download_failed"}
        if path is None:
            return {**stats, "stopped": "no_baseline"}

        finished = True
        # Each record is found in a thread: skipping the zip's other records
        # inflates them, which would otherwise block the loop.
        records = _baseline_records(path, lambda c: c in due)
        i = 0
        while (found := await asyncio.to_thread(next, records, None)) is not None:
            if time.monotonic() >= deadline:
                stats["stopped"] = "out_of_time"
                finished = False
                break
            cve_id, record = found
            stats["fetched"] += 1
            await _apply_cvelist_record(db, due.pop(cve_id), record_result(record), cache, stats)
            i += 1
            if i % 50 == 0:
                await db.commit()
        if finished:
            # Read to the end: what's still due has no record (reserved, or junk).
            for cve_pk in due.values():
                if time.monotonic() >= deadline:
                    stats["stopped"] = "out_of_time"
                    break
                missing = EnrichmentData(
                    raw_response={"status": "not_in_baseline"},
                    parsed_data={"found": False},
                    ttl_hours=NOT_FOUND_TTL_HOURS,
                )
                await _apply_cvelist_record(db, cve_pk, missing, cache, stats)
                stats["not_found"] += 1
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
# baseline of every record is the backfill's.
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


async def _apply_cvelist_delta(db, fh, cache: dict, stats: dict) -> None:
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
                stats["fetched"] += 1
                await _apply_cvelist_record(db, cve_pk, record_result(record), cache, stats)


@source_job("cvelist")
async def _run_cvelist_delta_sync():
    """Read the delta zips released since the last run (the source row's
    ``last_synced_at`` holds the newest one read) and apply the records of the
    CVEs we track. Each zip streams to a temporary file and only our records
    are read from it, so a run holds one record in memory at a time."""
    import tempfile

    from app.enrichment.adapters.cvelist import RELEASES_URL
    from app.enrichment.pipeline import gateway_for
    from app.models.enrichment import EnrichmentSource

    stats = {"fetched": 0, "changed": 0, "written": 0, "deltas": 0, "records": 0, "ours": 0, "updated": 0}
    stats.update({"gap": False, "stopped": None})
    deadline = time.monotonic() + _CVELIST_DELTA_BUDGET_S
    async with _get_worker_session() as db:
        gateway, _ = await gateway_for(db, "cvelist", max_wait=JOB_TOKEN_WAIT)
        source = (
            await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "cvelist"))
        ).scalar_one_or_none()
        cache: dict = {}
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
                    if not _bounded(gateway, deadline):
                        stats["stopped"] = "out_of_time"
                        break
                    with tempfile.TemporaryFile() as fh:
                        await _download_to(client, url, fh, _CVELIST_DELTA_MAX_BYTES)
                        await _apply_cvelist_delta(db, fh, cache, stats)
                    if source:
                        source.last_synced_at = published
                    await db.commit()
                    stats["deltas"] += 1
        except SOURCE_REFUSALS as e:
            # Keeps the zips already applied; the next run starts after them.
            logger.warning("cvelist delta sync stopping: %s", e)
            stats["stopped"] = e.status
    return stats


@celery_app.task(name="app.workers.enrichment_tasks.run_wikidata_sync", soft_time_limit=900, time_limit=960)
def run_wikidata_sync():
    """Weekly: vendor websites, product vendors, country regions and vendor facts from Wikidata."""
    start = time.monotonic()
    try:
        stats = run_async(_run_wikidata_sync())
        logger.info("Wikidata sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_wikidata_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_wikidata_sync", status="error").inc()
        logger.exception("Wikidata sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_wikidata_sync").observe(time.monotonic() - start)


@source_job("wikidata")
async def _run_wikidata_sync():
    from app.enrichment.wikidata import sync_wikidata

    gateway, _ = await _job_gateway("wikidata")
    async with _get_worker_session() as db:
        return await sync_wikidata(db, gateway)


@celery_app.task(name="app.workers.enrichment_tasks.run_github_repo_sync", soft_time_limit=900, time_limit=960)
def run_github_repo_sync():
    """Weekly: stars, last push, archived state, license and topics of tools' GitHub repositories."""
    start = time.monotonic()
    try:
        stats = run_async(_run_github_repo_sync())
        logger.info("GitHub repo sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_github_repo_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_github_repo_sync", status="error").inc()
        logger.exception("GitHub repo sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_github_repo_sync").observe(time.monotonic() - start)


@source_job("github_repo")
async def _run_github_repo_sync():
    from app.enrichment.github_repo import sync_github_repos

    gateway, api_key = await _job_gateway("github_repo")
    async with _get_worker_session() as db:
        return await sync_github_repos(db, gateway, api_key)


@celery_app.task(name="app.workers.enrichment_tasks.run_endoflife_sync", soft_time_limit=900, time_limit=960)
def run_endoflife_sync():
    """Daily: product support lifecycles from endoflife.date."""
    start = time.monotonic()
    try:
        stats = run_async(_run_endoflife_sync())
        logger.info("endoflife.date sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_endoflife_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_endoflife_sync", status="error").inc()
        logger.exception("endoflife.date sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_endoflife_sync").observe(time.monotonic() - start)


@source_job("endoflife")
async def _run_endoflife_sync():
    from app.enrichment.endoflife import sync_endoflife

    gateway, _ = await _job_gateway("endoflife")
    async with _get_worker_session() as db:
        return await sync_endoflife(db, gateway)


@celery_app.task(name="app.workers.enrichment_tasks.run_capec_sync", soft_time_limit=900, time_limit=960)
def run_capec_sync():
    """Weekly: the MITRE CAPEC catalog and each technique's attack patterns."""
    start = time.monotonic()
    try:
        stats = run_async(_run_capec_sync())
        logger.info("CAPEC sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_capec_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_capec_sync", status="error").inc()
        logger.exception("CAPEC sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_capec_sync").observe(time.monotonic() - start)


@source_job("capec")
async def _run_capec_sync():
    from app.enrichment.capec import sync_capec

    gateway, _ = await _job_gateway("capec")
    async with _get_worker_session() as db:
        return await sync_capec(db, gateway)


@celery_app.task(name="app.workers.enrichment_tasks.run_ctid_sync", soft_time_limit=900, time_limit=960)
def run_ctid_sync():
    """Weekly: NIST 800-53 and CIS controls on techniques from CTID's mappings."""
    start = time.monotonic()
    try:
        stats = run_async(_run_ctid_sync())
        logger.info("CTID sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_ctid_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_ctid_sync", status="error").inc()
        logger.exception("CTID sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_ctid_sync").observe(time.monotonic() - start)


@source_job("ctid")
async def _run_ctid_sync():
    from app.enrichment.ctid import sync_ctid

    gateway, _ = await _job_gateway("ctid")
    async with _get_worker_session() as db:
        return await sync_ctid(db, gateway)


@celery_app.task(name="app.workers.enrichment_tasks.run_d3fend_sync", soft_time_limit=900, time_limit=960)
def run_d3fend_sync():
    """Weekly: D3FEND countermeasures for techniques."""
    start = time.monotonic()
    try:
        stats = run_async(_run_d3fend_sync())
        logger.info("D3FEND sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_d3fend_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_d3fend_sync", status="error").inc()
        logger.exception("D3FEND sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_d3fend_sync").observe(time.monotonic() - start)


@source_job("d3fend")
async def _run_d3fend_sync():
    from app.enrichment.d3fend import sync_d3fend

    gateway, _ = await _job_gateway("d3fend")
    async with _get_worker_session() as db:
        return await sync_d3fend(db, gateway)


@celery_app.task(name="app.workers.enrichment_tasks.run_etda_sync", soft_time_limit=1800, time_limit=1860)
def run_etda_sync():
    """Weekly: match ETDA Threat Group Cards to tracked threat actors."""
    start = time.monotonic()
    try:
        stats = run_async(_run_etda_sync())
        logger.info("ETDA sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_etda_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_etda_sync", status="error").inc()
        logger.exception("ETDA sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_etda_sync").observe(time.monotonic() - start)


@source_job("etda")
async def _run_etda_sync():
    from app.enrichment.etda import sync_etda

    gateway, _ = await _job_gateway("etda")
    async with _get_worker_session() as db:
        return await sync_etda(db, gateway)


@celery_app.task(name="app.workers.enrichment_tasks.run_ransomware_group_profiles", soft_time_limit=900, time_limit=960)
def run_ransomware_group_profiles():
    """Every four hours: a few tracked ransomware groups' profiles from ransomware.live."""
    start = time.monotonic()
    try:
        stats = run_async(_run_ransomware_group_profiles())
        logger.info("ransomware.live group profile stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_ransomware_group_profiles", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_ransomware_group_profiles", status="error").inc()
        logger.exception("ransomware.live group profiles failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_ransomware_group_profiles").observe(time.monotonic() - start)


@source_job("ransomware_live")
async def _run_ransomware_group_profiles():
    from app.enrichment.ransomware_groups import sync_group_profiles

    gateway, _ = await _job_gateway("ransomware_live")
    async with _get_worker_session() as db:
        return await sync_group_profiles(db, gateway)


TRANCO_LATEST_URL = "https://tranco-list.eu/api/lists/date/latest"
#: A domain ranked this high is a popular site: worth an analyst's look before
#: it is treated as an indicator.
TRANCO_REVIEW_RANK = 10_000
#: List rows matched against the ledger per query.
_TRANCO_CHUNK = 10_000
#: How long a rank stays fresh on the profile: one daily list plus slack.
_TRANCO_CONTEXT_TTL = timedelta(hours=48)
_TRANCO_COMMIT_EVERY = 500


def parse_tranco_line(line: str) -> tuple[int, str] | None:
    """``"1,google.com"`` → (1, "google.com"); None for anything else."""
    rank, _, domain = line.strip().partition(",")
    domain = domain.strip().lower()
    return (int(rank), domain) if rank.isdigit() and domain else None


@celery_app.task(name="app.workers.enrichment_tasks.run_tranco_sync", soft_time_limit=900, time_limit=960)
def run_tranco_sync():
    """Daily: rank the ledger's domains against the Tranco top-1M list."""
    start = time.monotonic()
    try:
        stats = run_async(_run_tranco_sync())
        logger.info("Tranco sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_tranco_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_tranco_sync", status="error").inc()
        logger.exception("Tranco sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_tranco_sync").observe(time.monotonic() - start)


def _uuids(ids):
    """A uuid[] parameter: one bind however many ids (an IN list would bind each)."""
    return bindparam(None, list(ids), type_=ARRAY(UUID(as_uuid=True)))


async def _tranco_match(db, batch: dict[str, int]) -> dict:
    """The ledger's domains among ``batch`` (domain → rank), as
    id → (rank, rank before, is_denied)."""
    from app.models.observable import Observable

    rows = await db.execute(
        select(Observable.id, Observable.value, Observable.popularity_rank, Observable.is_denied).where(
            Observable.kind == "domain", Observable.value.in_(list(batch))
        )
    )
    return {oid: (batch[value], old, denied) for oid, value, old, denied in rows}


@source_job("tranco")
async def _run_tranco_sync():
    """Apply today's rank to the ledger's domains in the list and a "not
    found" answer to those that dropped out, through the field map (the
    ``popularity_rank`` column, its claim and the profile's rank context), and
    set ``needs_review`` on a domain the first time it ranks in the top
    TRANCO_REVIEW_RANK. Nothing is deleted or denied.

    The ~22 MB CSV is streamed line by line and matched against the ledger a
    chunk at a time, so only the ledger's matches are held in memory.
    """
    from sqlalchemy import all_, any_, update

    from app.enrichment.base import EnrichmentData
    from app.enrichment.catalogs import tranco_victim_matches, write_tranco_victim_ranks
    from app.enrichment.pipeline import apply_source_result
    from app.models.enrichment import EnrichmentSource
    from app.models.observable import Observable

    stats = dict.fromkeys(("listed", "matched", "ranked", "dropped", "flagged", "victims", "changed", "written"), 0)
    matched: dict = {}
    victims: dict = {}

    gateway, _ = await _job_gateway("tranco")
    try:
        async with gateway.client(timeout=120.0, follow_redirects=True) as client:
            meta = await client.get(TRANCO_LATEST_URL)
            meta.raise_for_status()
            latest = meta.json()
            stats["list_id"] = latest.get("list_id")
            async with _get_worker_session() as db, client.stream("GET", latest["download"]) as resp:
                resp.raise_for_status()
                batch: dict[str, int] = {}
                async for line in resp.aiter_lines():
                    if (row := parse_tranco_line(line)) is None:
                        continue
                    stats["listed"] += 1
                    batch.setdefault(row[1], row[0])
                    if len(batch) >= _TRANCO_CHUNK:
                        matched.update(await _tranco_match(db, batch))
                        victims.update(await tranco_victim_matches(db, batch))
                        batch = {}
                if batch:
                    matched.update(await _tranco_match(db, batch))
                    victims.update(await tranco_victim_matches(db, batch))
    except SOURCE_REFUSALS as e:
        logger.warning("Tranco sync skipped: %s", e)
        return {**stats, "stopped": e.status}
    if not stats["listed"]:
        # An empty file would read as "every domain dropped out".
        raise RuntimeError(f"Tranco list {stats['list_id']} had no rows")

    now = datetime.now(UTC)
    ranked = sum(1 for rank, old, _ in matched.values() if rank != old)
    flagged = [
        oid
        for oid, (rank, old, denied) in matched.items()
        if rank <= TRANCO_REVIEW_RANK and (old is None or old > TRANCO_REVIEW_RANK) and not denied
    ]
    ttl = int(_TRANCO_CONTEXT_TTL.total_seconds() // 3600)
    raw = {"list_id": stats["list_id"]}
    cache: dict = {}
    async with _get_worker_session() as db:
        # A listed domain's answer, and a "not found" one for a domain that
        # dropped out, go through the field map as a lookup's would: the rank
        # column (and its claim) and the profile's rank context.
        dropped = (
            (
                await db.execute(
                    select(Observable.id).where(
                        Observable.kind == "domain",
                        Observable.popularity_rank.isnot(None),
                        Observable.id != all_(_uuids(matched)),
                    )
                )
            )
            .scalars()
            .all()
        )
        answers = [(oid, {"found": True, "rank": rank}) for oid, (rank, _, _) in matched.items()]
        answers += [(oid, {"found": False}) for oid in dropped]
        for n, (oid, parsed) in enumerate(answers, 1):
            data = EnrichmentData(raw_response=raw, parsed_data=parsed, ttl_hours=ttl)
            applied = await apply_source_result(db, "observable", oid, "tranco", data, cache)
            stats["changed"] += applied.changed
            stats["written"] += applied.written
            if n % _TRANCO_COMMIT_EVERY == 0:
                await db.commit()
        if flagged:
            await db.execute(update(Observable).where(Observable.id == any_(_uuids(flagged))).values(needs_review=True))
        # Ransomware victims are ranked by their domain too (context only).
        stats["victims"] = await write_tranco_victim_ranks(db, victims, now, _TRANCO_CONTEXT_TTL)
        source = (
            await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "tranco"))
        ).scalar_one_or_none()
        if source:
            source.last_synced_at = now
            source.health_status = "healthy"
        await db.commit()

    stats.update(matched=len(matched), ranked=ranked, dropped=len(dropped), flagged=len(flagged))
    stats["fetched"] = stats["listed"]
    return stats


#: Most IPs one bulk connection carries; the rest are due on the next run.
CYMRU_BULK_MAX = 10_000
_CYMRU_COMMIT_EVERY = 500


@celery_app.task(name="app.workers.enrichment_tasks.run_cymru_bulk_sync", soft_time_limit=900, time_limit=960)
def run_cymru_bulk_sync():
    """Every 6 hours: map the ledger's active IPs that are due to their AS."""
    start = time.monotonic()
    try:
        stats = run_async(_run_cymru_bulk_sync())
        logger.info("Team Cymru bulk sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_cymru_bulk_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_cymru_bulk_sync", status="error").inc()
        logger.exception("Team Cymru bulk sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_cymru_bulk_sync").observe(time.monotonic() - start)


def _ip_key(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


@source_job("cymru")
async def _run_cymru_bulk_sync():
    """Look up, over one bulk WHOIS connection, the active IPs with no fresh
    Team Cymru answer (none yet, or one past its TTL), newest sighting first,
    and apply each answer as a lookup's is: columns, claims, context."""
    from app.enrichment.base import EnrichmentData
    from app.enrichment.pipeline import apply_source_result
    from app.enrichment.registry import get_adapter
    from app.models.enrichment import EnrichmentResult
    from app.models.observable import Observable

    stats = {"due": 0, "fetched": 0, "changed": 0, "written": 0, "unannounced": 0}
    adapter = get_adapter("cymru", gateway=(await _job_gateway("cymru"))[0])
    fresh = (
        select(EnrichmentResult.id)
        .where(
            EnrichmentResult.entity_type == "observable",
            EnrichmentResult.entity_id == Observable.id,
            EnrichmentResult.source_type == "cymru",
            EnrichmentResult.status == "success",
            EnrichmentResult.expires_at > datetime.now(UTC),
        )
        .exists()
    )
    async with _get_worker_session() as db:
        due = (
            await db.execute(
                select(Observable.id, Observable.value)
                .where(adapter.scope_filter("observable", Observable), ~fresh)
                .order_by(Observable.last_seen_at.desc())
                .limit(CYMRU_BULK_MAX)
            )
        ).all()
    ips = {oid: key for oid, value in due if (key := _ip_key(value))}
    stats["due"] = len(ips)
    if not ips:
        return stats
    try:
        answers = await adapter.bulk_lookup(list(dict.fromkeys(ips.values())))
    except SOURCE_REFUSALS as e:
        logger.warning("Team Cymru bulk sync skipped: %s", e)
        return {**stats, "stopped": e.status}
    stats["fetched"] = len(answers)

    cache: dict = {}
    async with _get_worker_session() as db:
        for n, (oid, ip) in enumerate(ips.items(), 1):
            if (parsed := answers.get(ip)) is None:
                continue
            found = parsed.get("found", False)
            stats["unannounced"] += not found
            data = EnrichmentData(raw_response={"bulk": True}, parsed_data=parsed, ttl_hours=168 if found else 24)
            applied = await apply_source_result(db, "observable", oid, "cymru", data, cache)
            stats["changed"] += applied.changed
            stats["written"] += applied.written
            if n % _CYMRU_COMMIT_EVERY == 0:
                await db.commit()
        await db.commit()
    return stats


def _run_abusech(name: str, label: str, body):
    """Run an abuse.ch export sync with the task metrics."""
    start = time.monotonic()
    try:
        stats = run_async(body())
        logger.info("%s sync stats: %s", label, stats)
        CELERY_TASKS_TOTAL.labels(task_name=name, status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name=name, status="error").inc()
        logger.exception("%s sync failed", label)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name=name).observe(time.monotonic() - start)


async def _abusech_sync(source_type: str):
    from app.enrichment.adapters.abusech import sync_export
    from app.enrichment.registry import ADAPTER_REGISTRY

    gateway, api_key = await _job_gateway(source_type)
    async with _get_worker_session() as db:
        return await sync_export(db, gateway, api_key, ADAPTER_REGISTRY[source_type])


@celery_app.task(name="app.workers.enrichment_tasks.run_threatfox_sync", soft_time_limit=1800, time_limit=1860)
def run_threatfox_sync():
    """Daily: match the ledger against ThreatFox's IOC export."""
    return _run_abusech("run_threatfox_sync", "ThreatFox", _run_threatfox_sync)


@source_job("threatfox")
async def _run_threatfox_sync():
    return await _abusech_sync("threatfox")


@celery_app.task(name="app.workers.enrichment_tasks.run_urlhaus_sync", soft_time_limit=1800, time_limit=1860)
def run_urlhaus_sync():
    """Every six hours: match the ledger against the URLhaus dump."""
    return _run_abusech("run_urlhaus_sync", "URLhaus", _run_urlhaus_sync)


@source_job("urlhaus")
async def _run_urlhaus_sync():
    return await _abusech_sync("urlhaus")


# ── OSV: records changed since the last run ─────────────────────────

OSV_MODIFIED_URL = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
OSV_RECORD_URL = "https://osv-vulnerabilities.storage.googleapis.com/{path}.json"
#: How far back the first run reads.
OSV_FIRST_WINDOW = timedelta(days=2)
_OSV_COMMIT_EVERY = 200


@celery_app.task(name="app.workers.enrichment_tasks.run_osv_delta_sync", soft_time_limit=900, time_limit=960)
def run_osv_delta_sync():
    """Hourly: apply the OSV records of tracked CVEs that changed since the last run."""
    start = time.monotonic()
    try:
        stats = run_async(_run_osv_delta_sync())
        logger.info("OSV delta sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="run_osv_delta_sync", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="run_osv_delta_sync", status="error").inc()
        logger.exception("OSV delta sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_osv_delta_sync").observe(time.monotonic() - start)


def parse_osv_modified_line(line: str) -> tuple[datetime, str] | None:
    """``2026-11-01T02:50:35.48Z,GIT/CVE-2026-1`` → (when, ``GIT/CVE-2026-1``)."""
    stamp, _, path = line.strip().partition(",")
    if not path:
        return None
    # OSV writes nanoseconds; datetime holds microseconds.
    stamp = re.sub(r"(\.\d{6})\d+", r"\1", stamp).replace("Z", "+00:00")
    try:
        when = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    return (when if when.tzinfo else when.replace(tzinfo=UTC)), path


@source_job("osv")
async def _run_osv_delta_sync():
    """Read OSV's change list (newest first) back to the osv row's
    ``last_synced_at``, keep the CVE records ("CVE-…" ids, under GIT/ or
    Linux/) of CVEs IntelFeed tracks, then fetch and apply each, oldest first,
    through the field map as a lookup's answer. The cursor moves only past
    what was applied: a refusal stops the run there, and a record that failed
    holds it, so the next run fetches that record again."""
    import httpx

    from app.enrichment.adapters.osv import TTL_HOURS, parse_vuln
    from app.enrichment.base import EnrichmentData
    from app.enrichment.pipeline import apply_source_result
    from app.models.cve import CVE
    from app.models.enrichment import EnrichmentSource

    stats = {"fetched": 0, "changed": 0, "written": 0, "listed": 0, "tracked": 0, "failed": 0, "stopped": None}
    now = datetime.now(UTC)
    async with _get_worker_session() as db:
        row = (
            await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "osv"))
        ).scalar_one_or_none()
        # Before the startup seed writes the row the job still runs, from the first window.
        since = (row.last_synced_at if row else None) or now - OSV_FIRST_WINDOW

    # CVE id → (newest change, record path); the list repeats an id per change.
    changed: dict[str, tuple[datetime, str]] = {}
    gateway, _ = await _job_gateway("osv")
    async with gateway.client(timeout=120.0, follow_redirects=True) as client:
        try:
            async with client.stream("GET", OSV_MODIFIED_URL) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    parsed = parse_osv_modified_line(line)
                    if parsed is None:
                        continue
                    when, path = parsed
                    if when <= since:
                        break
                    stats["listed"] += 1
                    record_id = path.rsplit("/", 1)[-1]
                    if record_id.startswith("CVE-") and record_id not in changed:
                        changed[record_id] = (when, path)
        except SOURCE_REFUSALS as e:
            logger.warning("OSV delta sync skipped: %s", e)
            return {**stats, "stopped": e.status}

        async with _get_worker_session() as db:
            tracked = {}
            ids = list(changed)
            for i in range(0, len(ids), 5000):
                chunk = ids[i : i + 5000]
                for pk, cve_id in await db.execute(select(CVE.id, CVE.cve_id).where(CVE.cve_id.in_(chunk))):
                    tracked[cve_id] = pk
            stats["tracked"] = len(tracked)

            cursor = since
            cache: dict = {}
            due = sorted((changed[c][0], changed[c][1], c) for c in tracked)
            for n, (when, path, cve_id) in enumerate(due, 1):
                try:
                    resp = await client.get(OSV_RECORD_URL.format(path=path))
                    resp.raise_for_status()
                    vuln = resp.json()
                except SOURCE_REFUSALS as e:
                    logger.warning("OSV delta sync stopping: %s", e)
                    stats["stopped"] = e.status
                    break
                except (httpx.HTTPError, ValueError) as e:
                    logger.warning("OSV record %s failed: %s", path, e)
                    stats["failed"] += 1
                    continue
                stats["fetched"] += 1
                data = EnrichmentData(
                    raw_response={"via": "osv-delta-sync", "path": path},
                    parsed_data=parse_vuln(vuln),
                    ttl_hours=TTL_HOURS,
                )
                applied = await apply_source_result(db, "cve", tracked[cve_id], "osv", data, cache)
                stats["changed"] += applied.changed
                stats["written"] += applied.written
                if not stats["failed"]:
                    cursor = when
                if n % _OSV_COMMIT_EVERY == 0:
                    await db.commit()

            row = (
                await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "osv"))
            ).scalar_one_or_none()
            # A run that applied everything reads up to now next time; one that
            # stopped, or had a record fail, resumes after the last record it
            # applied before that.
            if row is not None:
                row.last_synced_at = now if not (stats["stopped"] or stats["failed"]) else cursor
            await db.commit()
    return stats
