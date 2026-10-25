"""Celery tasks for external intelligence feeds and entity auto-linker."""

import logging
import time

from sqlalchemy.exc import DBAPIError

from app.ai.caller import Caller
from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session
from app.workers.pipeline_logging import pipeline_stage

logger = logging.getLogger(__name__)


def _get_worker_session():
    return worker_session()


@celery_app.task(name="app.workers.intel_feed_tasks.sync_kev_feed", soft_time_limit=300, time_limit=360)
def sync_kev_feed():
    """Sync CISA KEV catalog."""
    start = time.monotonic()
    try:
        stats = run_async(_sync_kev_feed())
        logger.info("KEV sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="sync_kev_feed", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="sync_kev_feed", status="error").inc()
        logger.exception("KEV sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="sync_kev_feed").observe(time.monotonic() - start)


async def _sync_kev_feed():
    from app.intelligence.external_feeds import sync_kev_feed

    async with _get_worker_session() as db:
        return await sync_kev_feed(db)


@celery_app.task(name="app.workers.intel_feed_tasks.refresh_cwe_catalog", soft_time_limit=600, time_limit=660)
def refresh_cwe_catalog():
    """Re-pull the MITRE CWE catalog and re-resolve any unmatched NVD refs.

    MITRE ships a release every few months; between them this is a no-op that
    costs one 2 MB download. The re-resolve pass is why it is worth scheduling
    at all: a CVE tagged with a weakness MITRE had not yet published stays
    unresolved until the catalog catches up, and then fixes itself here.
    """
    start = time.monotonic()
    try:
        stats = run_async(_refresh_cwe_catalog())
        logger.info("CWE catalog refresh stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="refresh_cwe_catalog", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="refresh_cwe_catalog", status="error").inc()
        logger.exception("CWE catalog refresh failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="refresh_cwe_catalog").observe(time.monotonic() - start)


async def _refresh_cwe_catalog():
    from app.intelligence.cwe_catalog import refresh_cwe_catalog as _refresh

    async with _get_worker_session() as db:
        return await _refresh(db)


@celery_app.task(name="app.workers.intel_feed_tasks.sync_cybergeist_feeds", soft_time_limit=300, time_limit=360)
def sync_cybergeist_feeds():
    """Sync Cybergeist threat actor and malware feeds."""
    start = time.monotonic()
    try:
        stats = run_async(_sync_cybergeist_feeds())
        logger.info("Cybergeist sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="sync_cybergeist_feeds", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="sync_cybergeist_feeds", status="error").inc()
        logger.exception("Cybergeist sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="sync_cybergeist_feeds").observe(time.monotonic() - start)


async def _sync_cybergeist_feeds():
    from app.intelligence.external_feeds import sync_cybergeist_malware, sync_cybergeist_threat_actors

    has_new_entities = False

    async with _get_worker_session() as db:
        actor_stats = await sync_cybergeist_threat_actors(db)
        if actor_stats.get("new_entity_ids"):
            has_new_entities = True

        malware_stats = await sync_cybergeist_malware(db)
        if malware_stats.get("new_entity_ids"):
            has_new_entities = True

    # If new entities were created, refresh auto-linker vocabulary and re-scan recent entries
    if has_new_entities:
        refresh_autolinker_vocabulary.delay()
        rescan_recent_entries.apply_async(kwargs={"days": 7}, countdown=30)

    return {"actors": actor_stats, "malware": malware_stats}


@celery_app.task(name="app.workers.intel_feed_tasks.sync_ransomware_victims", soft_time_limit=300, time_limit=360)
def sync_ransomware_victims():
    """Collect ransomware leak-site victim postings into structured records."""
    start = time.monotonic()
    try:
        stats = run_async(_sync_ransomware_victims())
        logger.info("Ransomware victim sync stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="sync_ransomware_victims", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="sync_ransomware_victims", status="error").inc()
        logger.exception("Ransomware victim sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="sync_ransomware_victims").observe(time.monotonic() - start)


async def _sync_ransomware_victims():
    from app.intelligence.ransomware_sync import sync_ransomware_victims as _run_sync

    async with _get_worker_session() as db:
        stats = await _run_sync(db)

    # New ransomware groups are autolinkable ThreatActors — refresh the vocabulary.
    if stats.get("new_group_ids"):
        refresh_autolinker_vocabulary.delay()
    return stats


@celery_app.task(name="app.workers.intel_feed_tasks.refresh_autolinker_vocabulary", soft_time_limit=120, time_limit=180)
def refresh_autolinker_vocabulary():
    """Rebuild the auto-linker Aho-Corasick automaton from DB."""
    start = time.monotonic()
    try:
        run_async(_refresh_autolinker_vocabulary())
        CELERY_TASKS_TOTAL.labels(task_name="refresh_autolinker_vocabulary", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="refresh_autolinker_vocabulary", status="error").inc()
        logger.exception("Auto-linker vocabulary refresh failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="refresh_autolinker_vocabulary").observe(time.monotonic() - start)


async def _refresh_autolinker_vocabulary():
    from app.intelligence.autolinker import refresh_vocabulary

    async with _get_worker_session() as db:
        vocab_size = await refresh_vocabulary(db)
        logger.info("Auto-linker vocabulary refreshed: %d entries", vocab_size)


@celery_app.task(
    bind=True,
    name="app.workers.intel_feed_tasks.autolink_entry_task",
    soft_time_limit=120,
    time_limit=180,
    autoretry_for=(DBAPIError,),
    retry_backoff=True,
    retry_jitter=True,
    max_retries=3,
)
@pipeline_stage("autolink")
def autolink_entry_task(self, entry_id: str):
    """Auto-link entities for a single entry.

    Retries on transient database failures (serialization/deadlock). This task is
    a chord header: if it raises, Celery skips the chord callback outright, so the
    entry loses co-occurrence, correlation, requirements and scoring for good. A
    retry is far cheaper than that silent hole.
    """
    start = time.monotonic()
    try:
        result = run_async(_autolink_entry(entry_id))
        if result:
            logger.info("Auto-linked %d entities for entry %s", len(result), entry_id)
        CELERY_TASKS_TOTAL.labels(task_name="autolink_entry_task", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="autolink_entry_task", status="error").inc()
        logger.exception("Auto-link failed for entry %s", entry_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="autolink_entry_task").observe(time.monotonic() - start)


def _reliability_to_weight(rating: str | None) -> float:
    """Map A-F reliability rating to a confidence weight multiplier."""
    from app.intelligence.autolinker import reliability_to_weight

    return reliability_to_weight(rating)


async def _autolink_entry(entry_id: str):
    import uuid

    from sqlalchemy import select

    from app.intelligence.autolinker import autolink_entry
    from app.models.entry import Entry
    from app.models.feed import Feed

    async with _get_worker_session() as db:
        result = await db.execute(select(Entry).where(Entry.id == uuid.UUID(entry_id)))
        entry = result.scalar_one_or_none()
        if not entry:
            logger.warning("Entry %s not found for auto-linking", entry_id)
            return []

        # Check feed's intel extraction mode
        feed_result = await db.execute(
            select(Feed.intel_extraction_mode, Feed.reliability_rating).where(Feed.id == entry.feed_id)
        )
        feed_row = feed_result.one_or_none()
        if not feed_row:
            return []

        mode = feed_row.intel_extraction_mode
        reliability = feed_row.reliability_rating

        # none or manual: skip auto-linking entirely
        if mode in ("none", "manual"):
            logger.debug("Skipping autolink for entry %s (feed mode: %s)", entry_id, mode)
            return []

        # Foreign-language entries (e.g. Russian Telegram channels) carry their
        # entity mentions in non-Latin script, which the English-built autolink
        # vocabulary won't catch. When a translation exists (the pipeline's
        # translate prologue runs before this stage), scan the translated text
        # alongside the original so entities appearing in either form get matched.
        from app.services.sanitizer import entry_text_with_translation

        title, content_text = entry_text_with_translation(entry)

        # selective: run relevance pre-filter first
        if mode == "selective":
            from app.intelligence.relevance_filter import get_relevance_threshold, score_relevance

            threshold = await get_relevance_threshold(db)
            score = score_relevance(title, entry.summary, content_text)
            if score < threshold:
                logger.debug(
                    "Entry %s below relevance threshold (%.2f < %.2f), skipping autolink",
                    entry_id,
                    score,
                    threshold,
                )
                return []

        # full: run unconditionally; selective with passing score: also runs
        source_weight = _reliability_to_weight(reliability)

        stored = await autolink_entry(
            db=db,
            entry_id=entry.id,
            content_text=content_text,
            title=title,
            summary=entry.summary or "",
            source_confidence_weight=source_weight,
        )
        await db.commit()
        return stored


@celery_app.task(
    name="app.workers.intel_feed_tasks.observables_entry_task",
    soft_time_limit=120,
    time_limit=180,
    autoretry_for=(DBAPIError,),
    retry_backoff=True,
    retry_jitter=True,
    max_retries=3,
)
@pipeline_stage("observables")
def observables_entry_task(entry_id: str):
    """Observables stage: candidates onto the entry, sightings of known values.

    Never creates a ledger row from a regex hit. Creation happens only through
    the judgment doors — this stage's one creating path is the curated
    ``ioc_list`` feed body, where the whole file is indicators by definition.
    """
    start = time.monotonic()
    try:
        stats = run_async(_scan_entry_observables(entry_id))
        if stats and any(stats.values()):
            logger.info("Observables for entry %s: %s", entry_id, stats)
        CELERY_TASKS_TOTAL.labels(task_name="observables_entry_task", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="observables_entry_task", status="error").inc()
        logger.exception("Observables scan failed for entry %s", entry_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="observables_entry_task").observe(time.monotonic() - start)


async def _codeblock_scan_skipped(db, entry) -> bool:
    """Whether this entry's feed sits in a category that never nominates host
    kinds from <pre> blocks (``observables_codeblock_skip_categories``)."""
    from sqlalchemy import select

    from app.models.category import Category
    from app.models.feed import Feed
    from app.services.system_settings import get_setting

    raw = await get_setting("observables_codeblock_skip_categories", db) or ""
    skip = {c.strip().lower() for c in str(raw).split(",") if c.strip()}
    if not skip or not entry.feed_id:
        return False
    name = (
        await db.execute(
            select(Category.name).join(Feed, Feed.category_id == Category.id).where(Feed.id == entry.feed_id)
        )
    ).scalar_one_or_none()
    return bool(name) and name.strip().lower() in skip


async def _scan_entry_observables(entry_id: str):
    import uuid

    from sqlalchemy import select

    from app.intelligence.observables import (
        candidates_as_json,
        scan_candidates,
        scan_code_block_candidates,
        scan_sighting_probes,
        sight_known_values,
        store_ioc_list_observables,
    )
    from app.models.entry import Entry
    from app.models.feed import Feed
    from app.services.sanitizer import entry_text_with_translation

    async with _get_worker_session() as db:
        result = await db.execute(select(Entry).where(Entry.id == uuid.UUID(entry_id)))
        entry = result.scalar_one_or_none()
        if not entry:
            return {}

        # A feed set to "none" is out of the intel system entirely, and that has
        # to include the ledger: the curated ioc_list door below creates rows
        # from a body, so without this check a feed the operator switched off
        # could still mint observables. Checked here rather than at dispatch for
        # the same reason `_autolink_entry` does it — the legacy path dispatches
        # every parallel stage unconditionally — and with the same precedence: a
        # feed marked "do not analyse" outranks a plan that enables the stage.
        mode = (
            await db.execute(select(Feed.intel_extraction_mode).where(Feed.id == entry.feed_id))
        ).scalar_one_or_none()
        if mode == "none":
            logger.debug("Skipping observables for entry %s (feed mode: none)", entry_id)
            return {}

        stats = {"candidates": 0, "sighted": 0, "feed_iocs": 0}

        metadata = entry.metadata_ or {}
        if metadata.get("content_type") == "ioc_list":
            # Curated indicator list: parse the pristine file body directly at
            # feed trust; no candidates needed.
            body = metadata.get("raw_content") or entry.content_text or ""
            stats["feed_iocs"] = await store_ioc_list_observables(
                db, entry.id, body, file_path=metadata.get("file_path"), seen_at=entry.published_at
            )
        else:
            from app.services.system_settings import get_setting

            cap = int(await get_setting("observables_candidate_max", db) or 200)
            title, content_text = entry_text_with_translation(entry)
            # Scan the HTML-rendered text when there is HTML: nh3's plain
            # strip glues table cells together ("pobelstudio.comdomain"),
            # the analysis renderer keeps rows as "cell | cell".
            if entry.content_html:
                from app.services.analysis_window import html_to_analysis_text

                rendered = html_to_analysis_text(entry.content_html)
                if rendered.strip():
                    translated_tail = content_text[len(entry.content_text or "") :]
                    content_text = rendered + translated_tail
            # Advisory bulletins / NVD / rule and catalog repositories: a bare
            # hex string is a checksum or commit, a dotted quad is a version.
            # Only defanged tokens nominate there.
            advisory = bool(metadata.get("content_type")) or await _codeblock_scan_skipped(db, entry)
            if not advisory:
                from app.models.feed import Feed as _Feed

                feed_type = (
                    await db.execute(select(_Feed.feed_type).where(_Feed.id == entry.feed_id))
                ).scalar_one_or_none()
                advisory = feed_type == "nvd"
            candidates = scan_candidates(
                f"{title}\n\n{content_text}", max_candidates=cap, plain_hashes=not advisory, plain_ips=not advisory
            )
            # Host-kind nominations come from the article's code blocks — where
            # authors put commands — never from prose regex. Rule-repository
            # files (any GitHub content_type) and advisory-bulletin feeds are
            # preformatted text, not commands, so they never nominate.
            if not advisory:
                existing = {(c.kind, c.value) for c in candidates}
                for c in scan_code_block_candidates(entry.content_html):
                    if (c.kind, c.value) not in existing and len(candidates) < cap:
                        candidates.append(c)
            # Replace only scan-origin candidates: AI shadow stagings arrive
            # later and a stage re-run must not wipe them.
            scanned = candidates_as_json(candidates)
            scan_keys = {(c["kind"], c["value"]) for c in scanned}
            kept_ai = [
                c
                for c in (entry.observable_candidates or [])
                if c.get("origin") == "ai" and (c.get("kind"), c.get("value")) not in scan_keys
            ]
            entry.observable_candidates = scanned + kept_ai
            stats["candidates"] = len(candidates)
            # Sight known ledger values even when the article prints them
            # fanged: probes cover every domain/URL/email-shaped token but can
            # only exact-match rows a judgment door already created.
            probe_keys = {(c.kind, c.value) for c in candidates}
            probes = [
                p for p in scan_sighting_probes(f"{title}\n\n{content_text}") if (p.kind, p.value) not in probe_keys
            ]
            stats["sighted"] = await sight_known_values(db, entry.id, candidates + probes)
            # The publisher door: the indicator file the write-up links to
            # (Talos / Bitdefender / Datadog GitHub repos), sighted on the article.
            if await get_setting("observables_publisher_ioc_enabled", db):
                from app.intelligence.publisher_iocs import store_publisher_observables

                try:
                    cap = int(await get_setting("observables_publisher_ioc_max_values", db) or 2000)
                    stats["publisher_iocs"] = await store_publisher_observables(db, entry, max_values=cap)
                except Exception:
                    logger.warning("Publisher IOC door failed for entry %s", entry_id, exc_info=True)

        await db.commit()
        if stats.get("publisher_iocs"):
            from app.workers.automation_tasks import dispatch_observable_capture_automations

            dispatch_observable_capture_automations(entry_id)
        return stats


@celery_app.task(name="app.workers.intel_feed_tasks.extract_entry_intel_task", soft_time_limit=300, time_limit=360)
@pipeline_stage("extract")
def extract_entry_intel_task(entry_id: str):
    """Run regex-based TTP/CVE extraction for a single entry on ingest."""
    start = time.monotonic()
    try:
        stats = run_async(_extract_entry_intel(entry_id))
        if any(stats.values()):
            logger.info("Auto-extracted for entry %s: %s", entry_id, stats)
        CELERY_TASKS_TOTAL.labels(task_name="extract_entry_intel_task", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="extract_entry_intel_task", status="error").inc()
        logger.exception("Auto-extraction failed for entry %s", entry_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="extract_entry_intel_task").observe(time.monotonic() - start)


async def _extract_entry_intel(entry_id: str):
    import uuid

    from sqlalchemy import select

    from app.intelligence.cve import extract_and_store_cves
    from app.intelligence.mitigation import extract_mitigation_ids_regex, store_mitigations
    from app.intelligence.rule_extraction import extract_rules_from_content, store_extracted_rules
    from app.intelligence.ttp import extract_ttp_ids_regex, store_ttps
    from app.models.entry import Entry
    from app.models.feed import Feed
    from app.pipeline.plans import feed_analysis_off

    stats = {"ttps": 0, "cves": 0, "mitigations": 0, "detection_rules": 0}
    # Entity ids this entry touched, per type — linking bumps article_count and
    # last_seen_at, so their search docs need a refresh even when the row itself
    # already existed.
    touched: dict[str, list] = {}

    async with _get_worker_session() as db:
        result = await db.execute(select(Entry).where(Entry.id == uuid.UUID(entry_id)))
        entry = result.scalar_one_or_none()
        if not entry:
            logger.warning("Entry %s not found for auto-extraction", entry_id)
            return stats

        # This task is dispatched when EITHER flag is on
        # (`auto_extract_on_ingest or extract_detection_rules`), so each half
        # has to check its own. Without the regex check below, turning off
        # "look up CVEs in NVD" did nothing at all as long as detection-rule
        # extraction was on — the regex passes ran regardless, and the setting
        # was decorative.
        feed_row = (
            await db.execute(
                select(Feed.intel_extraction_mode, Feed.auto_extract_on_ingest, Feed.extract_detection_rules).where(
                    Feed.id == entry.feed_id
                )
            )
        ).one_or_none()
        # "Analyse this feed" off (mode none) outranks both flags and the
        # GitHub import: nothing is tagged or created. Dispatch already skips
        # the stage for these feeds; this catches plan overlays, forced
        # dispatches and the Engine's re-run button.
        if feed_row is not None and feed_analysis_off(feed_row):
            return stats
        run_regex = bool(feed_row and feed_row.auto_extract_on_ingest)
        extract_rules_flag = bool(feed_row and feed_row.extract_detection_rules)

        # GitHub repo entries with a known content_type use the dedicated import
        # pipeline which handles rule creation, TTP/CVE linking, and scoring.
        content_type = (entry.metadata_ or {}).get("content_type", "")
        if content_type:
            # Attribute auto-extracted rules to the system user
            from app.services.github_rule_import import process_github_entry
            from app.services.system_user import get_system_user_id

            user_row = await get_system_user_id(db)
            if user_row:
                import_result = await process_github_entry(db, entry, user_row)
                stats["ttps"] = import_result.get("ttps_linked", 0)
                stats["cves"] = import_result.get("cves_linked", 0)
                rc = import_result.get("rule_count", 1 if import_result.get("rule_id") else 0)
                stats["detection_rules"] = rc
                logger.info(
                    "GitHub rule import for entry %s: %s",
                    entry_id,
                    import_result,
                )
            await db.commit()
            return stats

        # Scan original + translated text together — TTP/CVE IDs survive
        # translation, and translated prose exposes keywords the regex layers
        # match on (the pipeline's translate prologue runs before this stage).
        from app.services.sanitizer import entry_text_with_translation

        title, text = entry_text_with_translation(entry)
        # Include title for extraction — many feeds (e.g. NVD) put CVE IDs in the title
        if title:
            text = title + "\n" + text
        has_raw_content = bool((entry.metadata_ or {}).get("raw_content"))
        if not text.strip() and not has_raw_content:
            return stats

        if run_regex:
            # Regex-based TTP extraction (MITRE ATT&CK technique IDs)
            ttp_results = extract_ttp_ids_regex(text)
            if ttp_results:
                stored = await store_ttps(db, entry.id, ttp_results)
                stats["ttps"] = len(stored)
                touched.setdefault("ttp", []).extend(t.id for t, _ in stored)

            # Regex-based CVE extraction + NVD enrichment
            cves = await extract_and_store_cves(db, entry.id, text)
            stats["cves"] = len(cves)
            if cves:
                touched.setdefault("cve", []).extend(c.id for c in cves)

            # Regex-based mitigation extraction (MITRE M-IDs)
            mit_results = extract_mitigation_ids_regex(text)
            if mit_results:
                stored = await store_mitigations(db, entry.id, mit_results)
                stats["mitigations"] = len(stored)
                touched.setdefault("mitigation", []).extend(m.id for m, _ in stored)

        if extract_rules_flag:
            # Prefer raw_content from metadata (github_repo entries store file content there)
            rule_text = (entry.metadata_ or {}).get("raw_content") or text
            extracted = extract_rules_from_content(
                rule_text, source_url=entry.url, html=entry.content_html, article_title=entry.title
            )
            if extracted:
                # Attribute auto-extracted rules to the system user
                from app.services.system_user import get_system_user_id

                user_row = await get_system_user_id(db)
                if user_row:
                    stored_rules = await store_extracted_rules(db, entry.id, user_row, extracted)
                    stats["detection_rules"] = len(stored_rules)

        await db.commit()

        # Refresh only the docs for the entities this entry touched. This used
        # to dispatch the full sync_entity_search_indexes, which re-pushed all
        # ~50k entity documents because one entry linked one CVE — it fired on
        # nearly every ingested entry and pinned Meilisearch at a core. The
        # scheduled 4-hourly full sweep still heals any drift. Detection rules
        # index themselves in store_extracted_rules / process_github_entry.
        if touched:
            from app.services.entity_indexer import index_entities

            await index_entities(db, touched)

    return stats


@celery_app.task(
    name="app.workers.intel_feed_tasks.create_cooccurrence_relationships_task", soft_time_limit=300, time_limit=360
)
@pipeline_stage("cooccurrence")
def create_cooccurrence_relationships_task(entry_id: str):
    """Create EntityRelationship records from entity co-occurrence in a single entry."""
    start = time.monotonic()
    try:
        count = run_async(_create_cooccurrence_relationships(entry_id))
        if count:
            logger.info(
                "Created/updated %d co-occurrence relationships for entry %s",
                count,
                entry_id,
            )
        CELERY_TASKS_TOTAL.labels(task_name="create_cooccurrence_relationships_task", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="create_cooccurrence_relationships_task", status="error").inc()
        logger.exception("Co-occurrence relationship creation failed for entry %s", entry_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="create_cooccurrence_relationships_task").observe(
            time.monotonic() - start
        )


async def _create_cooccurrence_relationships(entry_id: str):
    import uuid as _uuid

    from app.intelligence.correlation import create_cooccurrence_relationships

    async with _get_worker_session() as db:
        count = await create_cooccurrence_relationships(db, _uuid.UUID(entry_id))
        await db.commit()
        return count


@celery_app.task(name="app.workers.intel_feed_tasks.rescan_recent_entries", soft_time_limit=900, time_limit=960)
def rescan_recent_entries(days: int = 7):
    """Re-scan recent entries with the auto-linker after vocabulary changes."""
    start = time.monotonic()
    try:
        stats = run_async(_rescan_recent_entries(days))
        logger.info("Re-scan complete: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="rescan_recent_entries", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="rescan_recent_entries", status="error").inc()
        logger.exception("Re-scan recent entries failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="rescan_recent_entries").observe(time.monotonic() - start)


async def _rescan_recent_entries(days: int):
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from app.intelligence.autolinker import autolink_batch
    from app.models.entry import Entry
    from app.models.feed import Feed

    async with _get_worker_session() as db:
        cutoff = datetime.now(UTC) - timedelta(days=days)
        result = await db.execute(
            select(Entry.id)
            .join(Feed, Feed.id == Entry.feed_id)
            .where(
                Entry.created_at >= cutoff,
                Feed.intel_extraction_mode.in_(["full", "selective"]),
            )
            .order_by(Entry.created_at.desc())
        )
        entry_ids = [row[0] for row in result.all()]

        if not entry_ids:
            return {"scanned": 0, "linked": 0}

        logger.info("Re-scanning %d entries from the last %d days", len(entry_ids), days)
        stats = await autolink_batch(db, entry_ids, delete_first=True)
        return stats


@celery_app.task(name="app.workers.intel_feed_tasks.backfill_paragraph_indices", soft_time_limit=900, time_limit=960)
def backfill_paragraph_indices_task():
    """Backfill paragraph_indices on junction records that have NULL.

    Lighter than a full rescan — preserves existing metadata and just adds
    paragraph position data by re-scanning entry text.
    """
    start = time.monotonic()
    try:
        stats = run_async(_backfill_paragraph_indices())
        logger.info("Paragraph indices backfill complete: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="backfill_paragraph_indices", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="backfill_paragraph_indices", status="error").inc()
        logger.exception("Paragraph indices backfill failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="backfill_paragraph_indices").observe(time.monotonic() - start)


async def _backfill_paragraph_indices():
    from app.intelligence.autolinker import backfill_paragraph_indices

    async with _get_worker_session() as db:
        stats = await backfill_paragraph_indices(db)
        return stats


@celery_app.task(name="app.workers.intel_feed_tasks.link_new_entity_to_entries", soft_time_limit=120, time_limit=180)
def link_new_entity_to_entries(entity_type: str, entity_id: str):
    """Search existing entries for a newly created entity and create links.

    Also refreshes the autolinker vocabulary for dictionary-based entities
    so that future incoming entries will be matched automatically.
    """
    start = time.monotonic()
    task_name = "link_new_entity_to_entries"
    try:
        stats = run_async(_link_new_entity_to_entries(entity_type, entity_id))
        logger.info("Entity backlink stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name=task_name, status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name=task_name, status="error").inc()
        logger.exception("Entity backlink failed: %s/%s", entity_type, entity_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name=task_name).observe(time.monotonic() - start)


async def _link_new_entity_to_entries(entity_type: str, entity_id: str):
    import uuid

    from app.intelligence.autolinker import link_entity_to_existing_entries

    # Refresh autolinker vocabulary for dictionary-based entities so future
    # entries also get linked automatically
    if entity_type in ("threat_actor", "malware", "country", "vendor", "product"):
        await _refresh_autolinker_vocabulary()

    async with _get_worker_session() as db:
        stats = await link_entity_to_existing_entries(db, entity_type, uuid.UUID(entity_id))
        return stats


@celery_app.task(name="app.workers.intel_feed_tasks.revalidate_autolinks", soft_time_limit=600, time_limit=660)
def revalidate_autolinks():
    """Remove stale auto-link records that no longer pass the current matching rules.

    Re-scans every entry that has at least one auto-linked entity and deletes any
    junction records whose entity is not found by scan_text() under the current
    vocabulary and false-positive / ambiguity rules.  article_count is adjusted
    downward for each removed link.
    """
    start = time.monotonic()
    try:
        stats = run_async(_revalidate_autolinks())
        logger.info("Autolink revalidation complete: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="revalidate_autolinks", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="revalidate_autolinks", status="error").inc()
        logger.exception("Autolink revalidation failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="revalidate_autolinks").observe(time.monotonic() - start)


async def _revalidate_autolinks() -> dict:
    import uuid as _uuid

    from sqlalchemy import delete, select

    from app.intelligence.autolinker import refresh_vocabulary, scan_text, split_into_paragraphs
    from app.models.entry import Entry
    from app.models.malware_family import EntryMalware, MalwareFamily
    from app.models.threat_actor import EntryThreatActor, ThreatActor

    stats = {"entries_checked": 0, "actor_links_removed": 0, "malware_links_removed": 0}

    async with _get_worker_session() as db:
        # Rebuild vocabulary so the new rules are active in this worker process.
        await refresh_vocabulary(db)

        # --- Collect all entries that have at least one auto-linked record ---
        actor_entries_q = await db.execute(
            select(EntryThreatActor.entry_id).where(EntryThreatActor.source == "auto_link").distinct()
        )
        malware_entries_q = await db.execute(
            select(EntryMalware.entry_id).where(EntryMalware.source == "auto_link").distinct()
        )
        actor_entry_ids = {row[0] for row in actor_entries_q.all()}
        malware_entry_ids = {row[0] for row in malware_entries_q.all()}
        all_entry_ids = actor_entry_ids | malware_entry_ids

        logger.info(
            "Revalidating autolinks: %d entries with actor links, %d with malware links",
            len(actor_entry_ids),
            len(malware_entry_ids),
        )

        batch_size = 200
        entry_id_list = list(all_entry_ids)

        for batch_start in range(0, len(entry_id_list), batch_size):
            batch = entry_id_list[batch_start : batch_start + batch_size]

            rows = await db.execute(
                select(Entry.id, Entry.title, Entry.summary, Entry.content_text).where(Entry.id.in_(batch))
            )
            entries = {row.id: row for row in rows.all()}

            for entry_id in batch:
                stats["entries_checked"] += 1
                row = entries.get(entry_id)
                if not row:
                    continue

                paragraphs = split_into_paragraphs(row.title or "", row.summary or "", row.content_text or "")
                scan_results = scan_text(paragraphs)

                # Build sets of entity UUIDs that the scanner accepts for this entry.
                valid_actor_ids: set[_uuid.UUID] = set()
                valid_malware_ids: set[_uuid.UUID] = set()
                for match in scan_results:
                    if match["entity_type"] == "threat_actor":
                        valid_actor_ids.add(_uuid.UUID(match["entity_id"]))
                    elif match["entity_type"] == "malware":
                        valid_malware_ids.add(_uuid.UUID(match["entity_id"]))

                # --- Threat actor links ---
                if entry_id in actor_entry_ids:
                    existing_actors = await db.execute(
                        select(EntryThreatActor.threat_actor_id).where(
                            EntryThreatActor.entry_id == entry_id,
                            EntryThreatActor.source == "auto_link",
                        )
                    )
                    stale_actor_ids = [row[0] for row in existing_actors.all() if row[0] not in valid_actor_ids]
                    if stale_actor_ids:
                        await db.execute(
                            delete(EntryThreatActor).where(
                                EntryThreatActor.entry_id == entry_id,
                                EntryThreatActor.threat_actor_id.in_(stale_actor_ids),
                                EntryThreatActor.source == "auto_link",
                            )
                        )
                        # Decrement article_count — floor at 0.
                        for actor_id in stale_actor_ids:
                            actor_row = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))
                            actor = actor_row.scalar_one_or_none()
                            if actor and actor.article_count > 0:
                                actor.article_count -= 1
                        stats["actor_links_removed"] += len(stale_actor_ids)

                # --- Malware links ---
                if entry_id in malware_entry_ids:
                    existing_malware = await db.execute(
                        select(EntryMalware.malware_family_id).where(
                            EntryMalware.entry_id == entry_id,
                            EntryMalware.source == "auto_link",
                        )
                    )
                    stale_malware_ids = [row[0] for row in existing_malware.all() if row[0] not in valid_malware_ids]
                    if stale_malware_ids:
                        await db.execute(
                            delete(EntryMalware).where(
                                EntryMalware.entry_id == entry_id,
                                EntryMalware.malware_family_id.in_(stale_malware_ids),
                                EntryMalware.source == "auto_link",
                            )
                        )
                        for malware_id in stale_malware_ids:
                            mw_row = await db.execute(select(MalwareFamily).where(MalwareFamily.id == malware_id))
                            mw = mw_row.scalar_one_or_none()
                            if mw and mw.article_count > 0:
                                mw.article_count -= 1
                        stats["malware_links_removed"] += len(stale_malware_ids)

            await db.commit()
            logger.info(
                "Revalidation batch %d/%d done — removed %d actor / %d malware links so far",
                min(batch_start + batch_size, len(entry_id_list)),
                len(entry_id_list),
                stats["actor_links_removed"],
                stats["malware_links_removed"],
            )

    return stats


@celery_app.task(name="app.workers.intel_feed_tasks.bulk_extract_intelligence", soft_time_limit=1800, time_limit=1860)
def bulk_extract_intelligence(entry_ids: list[str], extract_types: list[str], user_id: str, use_ai: bool = False):
    """Process entries sequentially, running requested extractors on each."""
    start = time.monotonic()
    try:
        stats = run_async(_bulk_extract(entry_ids, extract_types, user_id, use_ai))
        logger.info("Bulk extraction stats: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="bulk_extract_intelligence", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="bulk_extract_intelligence", status="error").inc()
        logger.exception("Bulk extraction failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="bulk_extract_intelligence").observe(time.monotonic() - start)


async def _bulk_extract(entry_ids: list[str], extract_types: list[str], user_id: str, use_ai: bool):
    import uuid

    from sqlalchemy import select

    from app.api.events import publish_event
    from app.intelligence.cve import extract_and_store_cves
    from app.intelligence.mitigation import extract_mitigations, store_mitigations
    from app.intelligence.rule_extraction import extract_rules_from_content, store_extracted_rules
    from app.intelligence.ttp import extract_ttps, store_ttps
    from app.models.entry import Entry
    from app.models.feed import Feed

    stats = {
        "processed": 0,
        "ttps": 0,
        "cves": 0,
        "actors": 0,
        "malware": 0,
        "tools": 0,
        "sectors": 0,
        "article_metadata": 0,
        "mitigations": 0,
        "detection_rules": 0,
    }

    async with _get_worker_session() as db:
        for i, eid_str in enumerate(entry_ids):
            eid = uuid.UUID(eid_str)
            result = await db.execute(
                select(Entry, Feed.extract_detection_rules).join(Feed, Entry.feed_id == Feed.id).where(Entry.id == eid)
            )
            row = result.one_or_none()
            if not row:
                continue
            entry, feed_extract_rules = row

            entry_data = {
                "title": entry.title,
                "content_text": entry.content_text or "",
                "content_html": entry.content_html,
                "summary": entry.summary,
                "author": entry.author,
                "url": entry.url,
                "published_at": str(entry.published_at) if entry.published_at else "",
                "feed_title": "",
            }
            uid = uuid.UUID(user_id)

            # Include title for extraction — many feeds (e.g. NVD) put CVE IDs in the title
            extract_text = entry.content_text or ""
            if entry.title:
                extract_text = entry.title + "\n" + extract_text

            if "ttps" in extract_types:
                # Regex layer always; AI TTPs come from the one-pass analysis below
                ttp_results, _, _ = await extract_ttps(db, uid, eid, entry_data, use_ai=False)
                stored = await store_ttps(db, eid, ttp_results)
                stats["ttps"] += len(stored)

            if "cves" in extract_types:
                stored = await extract_and_store_cves(db, eid, extract_text)
                stats["cves"] += len(stored)

            if "mitigations" in extract_types:
                mit_results, _, _ = await extract_mitigations(db, uid, eid, entry_data, use_ai=False)
                stored = await store_mitigations(db, eid, mit_results)
                stats["mitigations"] += len(stored)

            if use_ai:
                # One consolidated entry_analysis call replaces the old per-task
                # AI extraction calls (threat_actor_id, malware_id, tool_extraction,
                # country_id, sector_id, article_metadata — now deprecated seeds).
                # A person clicked Extract, but the result is shared state and
                # the run is a batch: pipeline spend, with the clicker kept as
                # provenance. Derive first so a since-deleted account never
                # reaches the result's foreign key.
                from app.ai.engine import derive_caller
                from app.services.entry_analysis import analyze_entry

                caller = Caller.system((await derive_caller(db, uid)).user_id)
                _parsed, counts = await analyze_entry(db, uid, eid, entry_data, force=True, caller=caller)
                stats["ttps"] += counts.get("ttps", 0)
                stats["actors"] += counts.get("threat_actors", 0)
                stats["malware"] += counts.get("malware", 0)
                stats["tools"] += counts.get("tools", 0)
                stats["sectors"] += counts.get("sectors", 0)
                stats["mitigations"] += counts.get("mitigations", 0)

            if "detection_rules" in extract_types:
                # GitHub repo entries with a known content_type use the dedicated
                # import pipeline (handles Sigma, Elastic, Splunk, Sentinel, YARA)
                content_type = (entry.metadata_ or {}).get("content_type", "")
                if content_type:
                    from app.services.github_rule_import import process_github_entry

                    import_result = await process_github_entry(db, entry, uid)
                    rc = import_result.get("rule_count", 1 if import_result.get("rule_id") else 0)
                    stats["detection_rules"] += rc
                    stats["ttps"] += import_result.get("ttps_linked", 0)
                    stats["cves"] += import_result.get("cves_linked", 0)
                elif feed_extract_rules:
                    # Regex extraction for non-GitHub entries
                    rule_text = (entry.metadata_ or {}).get("raw_content") or extract_text
                    rules = extract_rules_from_content(
                        rule_text, source_url=entry.url, html=entry.content_html, article_title=entry.title
                    )
                    if rules:
                        stored = await store_extracted_rules(db, eid, uid, rules)
                        stats["detection_rules"] += len(stored)

            await db.commit()
            stats["processed"] += 1

            publish_event(
                user_id,
                "bulk_extract_progress",
                {
                    "current": i + 1,
                    "total": len(entry_ids),
                    "entry_id": eid_str,
                },
            )

    publish_event(user_id, "bulk_extract_complete", stats)
    return stats


# --- Requirement Matching Tasks ---


@celery_app.task(name="app.workers.intel_feed_tasks.match_requirements_task", soft_time_limit=120, time_limit=180)
@pipeline_stage("requirements")
def match_requirements_task(entry_id: str):
    """Match a new entry against active intelligence requirements."""
    start = time.monotonic()
    try:
        result = run_async(_match_requirements(entry_id))
        if result:
            logger.info("Matched entry %s against %d requirements", entry_id, len(result))
        CELERY_TASKS_TOTAL.labels(task_name="match_requirements_task", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="match_requirements_task", status="error").inc()
        logger.exception("Requirement matching failed for entry %s", entry_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="match_requirements_task").observe(time.monotonic() - start)


async def _match_requirements(entry_id: str):
    import uuid

    from app.intelligence.requirement_matching import match_entry_against_requirements

    async with _get_worker_session() as db:
        matches = await match_entry_against_requirements(db, uuid.UUID(entry_id))
        await db.commit()
        return matches


@celery_app.task(name="app.workers.intel_feed_tasks.check_requirement_expiry_task", soft_time_limit=120, time_limit=180)
def check_requirement_expiry_task():
    """Daily check for expired intelligence requirements."""
    start = time.monotonic()
    try:
        count = run_async(_check_requirement_expiry())
        logger.info("Expired %d requirements", count)
        CELERY_TASKS_TOTAL.labels(task_name="check_requirement_expiry_task", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="check_requirement_expiry_task", status="error").inc()
        logger.exception("Requirement expiry check failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="check_requirement_expiry_task").observe(time.monotonic() - start)


async def _check_requirement_expiry():
    from app.intelligence.requirement_matching import check_requirement_expiry

    async with _get_worker_session() as db:
        count = await check_requirement_expiry(db)
        await db.commit()
        return count


# --- Entity Profile Rebuild Tasks ---


@celery_app.task(name="app.workers.intel_feed_tasks.rebuild_entity_profiles", soft_time_limit=600, time_limit=660)
def rebuild_entity_profiles():
    """Daily rebuild of entity profile fields (associated_ttps, associated_actors, timelines)."""
    start = time.monotonic()
    try:
        stats = run_async(_rebuild_profiles())
        logger.info("Entity profile rebuild: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="rebuild_entity_profiles", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="rebuild_entity_profiles", status="error").inc()
        logger.exception("Entity profile rebuild failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="rebuild_entity_profiles").observe(time.monotonic() - start)


async def _rebuild_profiles():
    from app.intelligence.profile_builder import rebuild_all_profiles

    async with _get_worker_session() as db:
        stats = await rebuild_all_profiles(db)
        await db.commit()
        return stats


# --- Correlation Event Archival ---


@celery_app.task(name="app.workers.intel_feed_tasks.archive_correlation_events", soft_time_limit=120, time_limit=180)
def archive_correlation_events():
    """Archive read correlation events older than 90 days."""
    start = time.monotonic()
    try:
        count = run_async(_archive_events())
        logger.info("Archived %d correlation events", count)
        CELERY_TASKS_TOTAL.labels(task_name="archive_correlation_events", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="archive_correlation_events", status="error").inc()
        logger.exception("Correlation event archival failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="archive_correlation_events").observe(time.monotonic() - start)


async def _archive_events():
    from app.intelligence.correlation_events import archive_old_events

    async with _get_worker_session() as db:
        count = await archive_old_events(db, retention_days=90)
        await db.commit()
        return count


# --- Correlation Engine Reset ---


@celery_app.task(name="app.workers.intel_feed_tasks.reset_correlation_engine", soft_time_limit=120, time_limit=180)
def reset_correlation_engine():
    """Delete all entity-entry junction records and entity relationships to reset the correlation engine."""
    start = time.monotonic()
    try:
        stats = run_async(_reset_correlation_engine())
        logger.info("Correlation engine reset: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="reset_correlation_engine", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="reset_correlation_engine", status="error").inc()
        logger.exception("Correlation engine reset failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="reset_correlation_engine").observe(time.monotonic() - start)


async def _reset_correlation_engine():
    from sqlalchemy import delete, update

    from app.models.country import Country, EntryCountry
    from app.models.cve import CVE, EntryCVE
    from app.models.entity_relationship import EntityRelationship
    from app.models.malware_family import EntryMalware, MalwareFamily
    from app.models.mitigation import EntryMitigation
    from app.models.threat_actor import EntryThreatActor, ThreatActor
    from app.models.tool import EntryTool, Tool
    from app.models.ttp import TTP, EntryTTP
    from app.services.redis_client import get_redis

    stats = {}
    async with _get_worker_session() as db:
        # Delete all junction records
        for label, model in [
            ("ttp_links", EntryTTP),
            ("cve_links", EntryCVE),
            ("actor_links", EntryThreatActor),
            ("malware_links", EntryMalware),
            ("country_links", EntryCountry),
            ("mitigation_links", EntryMitigation),
            ("tool_links", EntryTool),
        ]:
            result = await db.execute(delete(model))
            stats[label] = result.rowcount

        # Delete entity-entity relationships
        result = await db.execute(delete(EntityRelationship))
        stats["entity_relationships"] = result.rowcount

        # Reset article_count on all entities
        for model in [TTP, CVE, ThreatActor, MalwareFamily, Country, Tool]:
            if hasattr(model, "article_count"):
                await db.execute(update(model).values(article_count=0))

        await db.commit()

    # Flush all correlation caches from Redis so stale pivot/graph data isn't served
    try:
        r = await get_redis()
        deleted = 0
        for prefix in ["intelfeed:corr:pivot:*", "intelfeed:corr:graph:*"]:
            keys = []
            async for key in r.scan_iter(match=prefix, count=500):
                keys.append(key)
            if keys:
                await r.delete(*keys)
                deleted += len(keys)
        stats["cache_keys_cleared"] = deleted
    except Exception as e:
        logger.warning("Failed to clear correlation cache during reset: %s", e)
        stats["cache_keys_cleared"] = 0

    return stats


# --- Rescan All Feeds (Regex Extraction) ---


@celery_app.task(name="app.workers.intel_feed_tasks.rescan_all_feeds_extraction", soft_time_limit=1800, time_limit=1860)
def rescan_all_feeds_extraction():
    """Re-run regex-based TTP/CVE/mitigation extraction on ALL entries."""
    start = time.monotonic()
    try:
        stats = run_async(_rescan_all_feeds_extraction())
        logger.info("Rescan all feeds extraction complete: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="rescan_all_feeds_extraction", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="rescan_all_feeds_extraction", status="error").inc()
        logger.exception("Rescan all feeds extraction failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="rescan_all_feeds_extraction").observe(time.monotonic() - start)


async def _rescan_all_feeds_extraction():
    import json

    import redis as _redis
    from sqlalchemy import select

    from app.intelligence.autolinker import autolink_entry
    from app.intelligence.cve import extract_and_store_cves
    from app.intelligence.mitigation import extract_mitigation_ids_regex, store_mitigations
    from app.intelligence.relevance_filter import get_relevance_threshold, score_relevance
    from app.intelligence.rule_extraction import extract_rules_from_content, store_extracted_rules
    from app.intelligence.ttp import extract_ttp_ids_regex, store_ttps
    from app.models.entry import Entry
    from app.models.feed import Feed

    stats = {
        "entries_processed": 0,
        "entries_skipped": 0,
        "ttps": 0,
        "cves": 0,
        "mitigations": 0,
        "detection_rules": 0,
        "autolinks": 0,
    }
    batch_size = 200
    checkpoint_key = "rescan_extraction:checkpoint"

    # Resume from last checkpoint if available
    r = _redis.from_url(settings.redis_url)
    try:
        checkpoint = r.get(checkpoint_key)
        if checkpoint:
            saved = json.loads(checkpoint)
            offset = saved.get("offset", 0)
            stats.update({k: v for k, v in saved.items() if k in stats})
            logger.info("Resuming rescan from offset %d (checkpoint found)", offset)
        else:
            offset = 0
    finally:
        r.close()

    async with _get_worker_session() as db:
        relevance_threshold = await get_relevance_threshold(db)
        while True:
            result = await db.execute(
                select(
                    Entry.id,
                    Entry.title,
                    Entry.summary,
                    Entry.content_text,
                    Entry.content_html,
                    Entry.url,
                    Entry.feed_id,
                    Entry.metadata_,
                    Feed.intel_extraction_mode,
                    Feed.auto_extract_on_ingest,
                    Feed.reliability_rating,
                    Feed.extract_detection_rules,
                )
                .join(Feed, Entry.feed_id == Feed.id)
                .order_by(Entry.published_at.desc())
                .offset(offset)
                .limit(batch_size)
            )
            rows = result.all()
            if not rows:
                break

            for (
                entry_id,
                title,
                summary,
                content_text,
                content_html,
                entry_url,
                feed_id,
                entry_metadata,
                extraction_mode,
                auto_extract,
                reliability,
                extract_rules,
            ) in rows:
                # Feeds with extraction_mode "none" skip everything
                if extraction_mode == "none":
                    stats["entries_skipped"] += 1
                    continue

                text = content_text or ""
                if title:
                    text = title + "\n" + text
                has_raw = bool((entry_metadata or {}).get("raw_content"))
                if not text.strip() and not has_raw:
                    continue

                # Regex TTP/CVE/mitigation extraction — only for feeds with auto_extract_on_ingest
                if auto_extract:
                    # TTP extraction
                    ttp_results = extract_ttp_ids_regex(text)
                    if ttp_results:
                        stored = await store_ttps(db, entry_id, ttp_results)
                        stats["ttps"] += len(stored)

                    # CVE extraction
                    cves = await extract_and_store_cves(db, entry_id, text)
                    stats["cves"] += len(cves)

                    # Mitigation extraction
                    mit_results = extract_mitigation_ids_regex(text)
                    if mit_results:
                        stored = await store_mitigations(db, entry_id, mit_results)
                        stats["mitigations"] += len(stored)

                # Detection rule import / extraction
                content_type = (entry_metadata or {}).get("content_type", "")
                if content_type:
                    # GitHub repo entries: use dedicated import pipeline
                    from app.services.github_rule_import import process_github_entry

                    # Attribute auto-extracted rules to the system user
                    from app.services.system_user import get_system_user_id

                    user_row = await get_system_user_id(db)
                    if user_row:
                        entry_obj = await db.get(Entry, entry_id)
                        if entry_obj:
                            import_result = await process_github_entry(db, entry_obj, user_row)
                            rc = import_result.get("rule_count", 1 if import_result.get("rule_id") else 0)
                            stats["detection_rules"] += rc
                            stats["ttps"] += import_result.get("ttps_linked", 0)
                            stats["cves"] += import_result.get("cves_linked", 0)
                elif extract_rules:
                    # Non-GitHub entries: regex extraction
                    rule_text = (entry_metadata or {}).get("raw_content") or text
                    extracted = extract_rules_from_content(
                        rule_text, source_url=entry_url, html=content_html, article_title=title
                    )
                    if extracted:
                        from app.services.system_user import get_system_user_id

                        user_row = await get_system_user_id(db)
                        if user_row:
                            stored_rules = await store_extracted_rules(db, entry_id, user_row, extracted)
                            stats["detection_rules"] += len(stored_rules)

                # Auto-linking — respects intel_extraction_mode
                # "manual" skips auto-linking; "selective" applies relevance filter
                if extraction_mode == "manual":
                    stats["entries_processed"] += 1
                    continue

                if extraction_mode == "selective":
                    score = score_relevance(title or "", summary, content_text)
                    if score < relevance_threshold:
                        stats["entries_processed"] += 1
                        continue

                # "full" or "selective" that passed the relevance filter
                source_weight = _reliability_to_weight(reliability)
                autolinked = await autolink_entry(
                    db,
                    entry_id=entry_id,
                    content_text=content_text or "",
                    title=title or "",
                    summary=summary or "",
                    source_confidence_weight=source_weight,
                )
                stats["autolinks"] += len(autolinked)

                stats["entries_processed"] += 1

            await db.commit()
            offset += batch_size
            logger.info("Rescan progress: %d entries processed so far", stats["entries_processed"])

            # Save checkpoint to Redis for resume on failure
            r = _redis.from_url(settings.redis_url)
            try:
                r.setex(checkpoint_key, 7200, json.dumps({"offset": offset, **stats}))
            finally:
                r.close()

    # Clear checkpoint on successful completion
    r = _redis.from_url(settings.redis_url)
    try:
        r.delete(checkpoint_key)
    finally:
        r.close()

    return stats


@celery_app.task(name="app.workers.intel_feed_tasks.sync_read_state_to_search", soft_time_limit=300, time_limit=360)
def sync_read_state_to_search(entry_ids: list[str], is_read: bool):
    """Batch-sync is_read for the given entries to Meilisearch, off the request path.

    Dispatched by mark_all_read so the API request commits and returns quickly
    instead of blocking on a large synchronous search sync (which previously
    exceeded the client timeout and rolled the read-state write back).
    """
    from app.services import meilisearch_client

    meilisearch_client.bulk_update_read_state(entry_ids, is_read)
    return {"synced": len(entry_ids)}


@celery_app.task(name="app.workers.intel_feed_tasks.sync_entity_indexes", soft_time_limit=900, time_limit=960)
def sync_entity_indexes():
    """Full sync of intelligence entities to Meilisearch."""
    start = time.monotonic()
    try:
        stats = run_async(_sync_entity_indexes())
        logger.info("Entity index sync complete: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="sync_entity_indexes", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="sync_entity_indexes", status="error").inc()
        logger.exception("Entity index sync failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="sync_entity_indexes").observe(time.monotonic() - start)


async def _sync_entity_indexes() -> dict:
    from app.services.entity_indexer import sync_all_entities

    async with _get_worker_session() as db:
        return await sync_all_entities(db)


@celery_app.task(name="app.workers.intel_feed_tasks.rebuild_search_index", soft_time_limit=1800, time_limit=1860)
def rebuild_search_index(user_id: str):
    """Rebuild the entries search index from the database.

    Scoped to user_id for the per-user fields (is_read/is_starred/is_bookmarked/has_notes)
    baked into each entry document.
    """
    start = time.monotonic()
    try:
        stats = run_async(_rebuild_search_index(user_id))
        logger.info("Search index rebuild complete: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="rebuild_search_index", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="rebuild_search_index", status="error").inc()
        logger.exception("Search index rebuild failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="rebuild_search_index").observe(time.monotonic() - start)


async def _rebuild_search_index(user_id: str) -> dict:
    import uuid as _uuid

    from sqlalchemy import func, select

    from app.models.entry import Entry
    from app.models.entry_media import EntryMedia
    from app.models.entry_state import UserEntryState
    from app.models.feed import Feed
    from app.models.note import Note
    from app.services import meilisearch_client
    from app.services.entry_tags import search_tag_fields

    user_uuid = _uuid.UUID(user_id)

    if not meilisearch_client.rebuild_index():
        return {"status": "error", "message": "Meilisearch unavailable"}

    batch_size = 500
    offset = 0
    total = 0

    async with _get_worker_session() as db:
        while True:
            result = await db.execute(
                select(
                    Entry,
                    Feed.feed_type,
                    func.coalesce(Feed.custom_title, Feed.title).label("feed_title"),
                    Feed.category_id,
                )
                .join(Feed, Entry.feed_id == Feed.id)
                .order_by(Entry.created_at)
                .offset(offset)
                .limit(batch_size)
            )
            rows = result.all()
            if not rows:
                break

            entry_ids = [row[0].id for row in rows]

            tag_fields = await search_tag_fields(db, entry_ids)

            states_map: dict = {}
            state_result = await db.execute(
                select(
                    UserEntryState.entry_id,
                    UserEntryState.is_read,
                    UserEntryState.is_starred,
                    UserEntryState.is_bookmarked,
                )
                .where(UserEntryState.entry_id.in_(entry_ids))
                .where(UserEntryState.user_id == user_uuid)
            )
            for eid, is_read, is_starred, is_bookmarked in state_result.all():
                states_map[eid] = {
                    "is_read": is_read,
                    "is_starred": is_starred,
                    "is_bookmarked": is_bookmarked,
                }

            notes_result = await db.execute(
                select(Note.entry_id).where(Note.entry_id.in_(entry_ids)).where(Note.created_by == user_uuid).distinct()
            )
            notes_set = {row[0] for row in notes_result.all()}

            media_map: dict = {}
            media_result = await db.execute(
                select(EntryMedia.entry_id, EntryMedia.media_type).where(EntryMedia.entry_id.in_(entry_ids))
            )
            for eid, mtype in media_result.all():
                if eid not in media_map:
                    media_map[eid] = mtype

            docs = []
            for entry, feed_type, feed_title, category_id in rows:
                state = states_map.get(entry.id, {})
                docs.append(
                    {
                        "id": str(entry.id),
                        "feed_id": str(entry.feed_id),
                        "title": entry.title,
                        "content_text": (entry.content_text or "")[:50000],
                        "summary": entry.summary or "",
                        "author": entry.author or "",
                        "published_at": int(entry.published_at.timestamp()) if entry.published_at else 0,
                        "feed_type": feed_type or "rss",
                        "category_id": str(category_id) if category_id else None,
                        "feed_title": feed_title or "",
                        "url": entry.url or "",
                        "media_type": media_map.get(entry.id),
                        "language": entry.language,
                        "tags": tag_fields[str(entry.id)]["tags"],
                        "user_tags": tag_fields[str(entry.id)]["user_tags"],
                        "is_read": state.get("is_read", False),
                        "is_starred": state.get("is_starred", False),
                        "is_bookmarked": state.get("is_bookmarked", False),
                        "has_notes": entry.id in notes_set,
                        "word_count": entry.word_count or 0,
                    }
                )

            meilisearch_client.bulk_index_entries(docs)
            total += len(docs)
            offset += batch_size

    return {"status": "ok", "total": total}


@celery_app.task(
    name="app.workers.intel_feed_tasks.build_telegram_forward_relationships",
    soft_time_limit=300,
    time_limit=360,
)
def build_telegram_forward_relationships():
    """Scan telegram entries' forwarded_from metadata to build actor-to-actor edges.

    When channel A (auto-attributed to actor X) forwards a message originally posted on
    channel B (auto-attributed to actor Y), that's evidence X consumes content from Y.
    We materialize this as an EntityRelationship of type 'communicates_with' between the
    two actors, with the source set to 'auto_extracted'.

    Idempotent — uses ON CONFLICT DO NOTHING against the (source, target, rel_type) unique
    constraint. Safe to re-run.
    """
    start = time.monotonic()
    try:
        stats = run_async(_build_telegram_forward_relationships())
        CELERY_TASKS_TOTAL.labels(task_name="build_telegram_forward_relationships", status="success").inc()
        logger.info("Telegram forward relationships: %s", stats)
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="build_telegram_forward_relationships", status="error").inc()
        logger.exception("build_telegram_forward_relationships failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="build_telegram_forward_relationships").observe(
            time.monotonic() - start
        )


async def _build_telegram_forward_relationships() -> dict:
    import re as _re
    import uuid as _uuid

    from sqlalchemy import select as _select
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.models.entity_relationship import EntityRelationship
    from app.models.entry import Entry
    from app.models.feed import Feed

    async with _get_worker_session() as db:
        # Build channel_id → threat_actor_id map from telegram feeds
        feed_rows = await db.execute(_select(Feed).where(Feed.feed_type == "telegram"))
        channel_to_actor: dict[int, _uuid.UUID] = {}
        for f in feed_rows.scalars().all():
            cfg = f.adapter_config or {}
            actor_id = cfg.get("threat_actor_id")
            channel_id = cfg.get("channel_id")
            if not actor_id or channel_id is None:
                continue
            try:
                channel_to_actor[int(channel_id)] = _uuid.UUID(str(actor_id))
            except (ValueError, TypeError):
                continue

        if not channel_to_actor:
            return {"actors": 0, "edges_created": 0}

        # Pull telegram entries with forwarded_from metadata
        entry_rows = await db.execute(
            _select(Entry, Feed.adapter_config)
            .join(Feed, Feed.id == Entry.feed_id)
            .where(Feed.feed_type == "telegram")
            .where(Entry.metadata_["forwarded_from"].isnot(None))
        )

        edges: dict[tuple[_uuid.UUID, _uuid.UUID], list[_uuid.UUID]] = {}
        channel_id_re = _re.compile(r"channel_id:(-?\d+)")

        for row in entry_rows.all():
            entry: Entry = row[0]
            forwarder_cfg = row[1] or {}
            forwarder_actor_raw = forwarder_cfg.get("threat_actor_id")
            if not forwarder_actor_raw:
                continue
            try:
                forwarder_actor = _uuid.UUID(str(forwarder_actor_raw))
            except (ValueError, TypeError):
                continue

            fwd = (entry.metadata_ or {}).get("forwarded_from") or {}
            from_id = fwd.get("from_id")
            if not isinstance(from_id, str):
                continue
            m = channel_id_re.search(from_id)
            if not m:
                continue
            try:
                source_channel_id = int(m.group(1))
            except ValueError:
                continue

            source_actor = channel_to_actor.get(source_channel_id)
            if source_actor is None or source_actor == forwarder_actor:
                continue

            key = (forwarder_actor, source_actor)
            edges.setdefault(key, []).append(entry.id)

        edges_created = 0
        for (src, tgt), evidence_ids in edges.items():
            stmt = (
                pg_insert(EntityRelationship.__table__)
                .values(
                    source_type="threat_actor",
                    source_id=src,
                    target_type="threat_actor",
                    target_id=tgt,
                    relationship_type="communicates_with",
                    confidence="probable",
                    source="auto_extracted",
                    description="Auto-derived from Telegram forward attribution",
                    evidence_entry_ids=evidence_ids[:50],
                )
                .on_conflict_do_nothing(
                    index_elements=[
                        "source_type",
                        "source_id",
                        "target_type",
                        "target_id",
                        "relationship_type",
                    ]
                )
            )
            result = await db.execute(stmt)
            if result.rowcount:
                edges_created += result.rowcount

        await db.commit()
        return {"actors": len(channel_to_actor), "edges_created": edges_created}
