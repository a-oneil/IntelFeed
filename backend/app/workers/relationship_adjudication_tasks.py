"""Nightly AI adjudicator for probable relationship edges.

The trust ladder's machine layer: co-occurrence and AI extraction leave edges
at `probable` ("reported"); this module reads the evidence behind each one and
either promotes it to `confirmed` (corroborated) or demotes it to `possible`
and blocks re-promotion (coincidental). Humans keep the veto (reject) but are
no longer the gate — the top tier fills without clicks.

  adjudicate_relationships       — kickoff. Gated on the
                                   relationship_adjudication_enabled setting;
                                   collects unadjudicated probable edges with
                                   enough evidence, fans out batches to the
                                   `ai` queue.

  adjudicate_relationship_batch  — judges one batch via the
                                   relationship_adjudication AI task and writes
                                   verdicts + confidence changes back.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime, timedelta

from celery.exceptions import Retry as CeleryRetry
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.engine import run_task
from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.user import User
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)

MACHINE_SOURCES = ("co_occurrence", "auto_extracted")
VALID_VERDICTS = {"corroborated", "coincidental", "unsure"}
_EVIDENCE_TITLES_PER_EDGE = 6
_MAX_EDGES_PER_RUN = 500

# Dossier context: each entity's AI assessment paragraph, handed to the judge
# alongside the headlines. Headlines are written for readers who already know
# who the actor is, so without this the honest verdict is usually `unsure` —
# and unsure edges come back every 14 days forever.
_DOSSIER_CHARS = 700
#: The assessment is written from the entity's N most recent linked articles
#: (see services/entity_summary.generate_entity_assessment). When an edge's
#: evidence is mostly those same articles, the dossier is the evidence restated
#: and the model would be corroborating itself — drop it past this overlap.
_ASSESSMENT_ARTICLE_WINDOW = 20
_DOSSIER_EVIDENCE_OVERLAP_MAX = 0.5


async def _resolve_system_user(db: AsyncSession) -> User | None:
    from app.services.system_user import get_system_user

    return await get_system_user(db)


async def _entity_names(db: AsyncSession, refs: set[tuple[str, uuid.UUID]]) -> dict[tuple[str, uuid.UUID], str]:
    """Resolve (entity_type, id) pairs to display names in bulk."""
    from app.models.campaign import Campaign
    from app.models.country import Country
    from app.models.cve import CVE
    from app.models.malware_family import MalwareFamily
    from app.models.product import Product
    from app.models.threat_actor import ThreatActor
    from app.models.tool import Tool
    from app.models.ttp import TTP
    from app.models.vendor import Vendor

    columns = {
        "threat_actor": (ThreatActor, ThreatActor.name),
        "malware": (MalwareFamily, MalwareFamily.name),
        "tool": (Tool, Tool.name),
        "country": (Country, Country.name),
        "campaign": (Campaign, Campaign.name),
        "vendor": (Vendor, Vendor.name),
        "product": (Product, Product.name),
        "cve": (CVE, CVE.cve_id),
    }
    out: dict[tuple[str, uuid.UUID], str] = {}
    by_type: dict[str, list[uuid.UUID]] = {}
    for etype, eid in refs:
        by_type.setdefault(etype, []).append(eid)
    for etype, ids in by_type.items():
        if etype == "ttp":
            rows = await db.execute(select(TTP.id, TTP.technique_id, TTP.technique_name).where(TTP.id.in_(ids)))
            for rid, tech_id, tech_name in rows.all():
                out[(etype, rid)] = f"{tech_id} {tech_name}" if tech_name else tech_id
            continue
        cfg = columns.get(etype)
        if not cfg:
            continue
        model, name_col = cfg
        rows = await db.execute(select(model.id, name_col).where(model.id.in_(ids)))
        for rid, name in rows.all():
            out[(etype, rid)] = name
    return out


def _refs_by_type(refs: set[tuple[str, uuid.UUID]]) -> dict[str, list[uuid.UUID]]:
    by_type: dict[str, list[uuid.UUID]] = {}
    for etype, eid in refs:
        by_type.setdefault(etype, []).append(eid)
    return by_type


def _description_column(model_cls):
    """The assessment column for a model: `description`, else `context`."""
    col = getattr(model_cls, "description", None)
    if col is None:
        col = getattr(model_cls, "context", None)
    return col


async def _entity_dossiers(db: AsyncSession, refs: set[tuple[str, uuid.UUID]]) -> dict[tuple[str, uuid.UUID], str]:
    """Assessment paragraph per entity ref, whitespace-collapsed and trimmed.

    Keyed off ENTITY_MODEL_MAP, so "has a dossier" means "is a type the
    assessment writer produces paragraphs for" — campaigns and anything else
    outside that map simply get no context line.
    """
    from app.services.entity_summary import ENTITY_MODEL_MAP

    out: dict[tuple[str, uuid.UUID], str] = {}
    for etype, ids in _refs_by_type(refs).items():
        cfg = ENTITY_MODEL_MAP.get(etype)
        if not cfg:
            continue
        col = _description_column(cfg[0])
        if col is None:
            continue
        rows = await db.execute(select(cfg[0].id, col).where(cfg[0].id.in_(ids)))
        for rid, text_val in rows.all():
            collapsed = " ".join((text_val or "").split())
            if collapsed:
                out[(etype, rid)] = collapsed[:_DOSSIER_CHARS]
    return out


async def _assessment_article_sets(
    db: AsyncSession, refs: set[tuple[str, uuid.UUID]]
) -> dict[tuple[str, uuid.UUID], set[uuid.UUID]]:
    """The entry ids each entity's assessment was written from.

    Mirrors the assessment's own window (N most recent linked articles, newest
    first) so the overlap check compares like with like.
    """
    from app.services.entity_summary import ENTITY_MODEL_MAP

    out: dict[tuple[str, uuid.UUID], set[uuid.UUID]] = {}
    for etype, ids in _refs_by_type(refs).items():
        cfg = ENTITY_MODEL_MAP.get(etype)
        if not cfg:
            continue
        _model_cls, junction_cls, fk_attr = cfg
        fk_col = getattr(junction_cls, fk_attr)
        ranked = (
            select(
                fk_col.label("eid"),
                junction_cls.entry_id.label("entry_id"),
                func.row_number().over(partition_by=fk_col, order_by=Entry.published_at.desc().nullslast()).label("rn"),
            )
            .join(Entry, Entry.id == junction_cls.entry_id)
            .where(fk_col.in_(ids))
            .subquery()
        )
        rows = await db.execute(
            select(ranked.c.eid, ranked.c.entry_id).where(ranked.c.rn <= _ASSESSMENT_ARTICLE_WINDOW)
        )
        for rid, entry_id in rows.all():
            out.setdefault((etype, rid), set()).add(entry_id)
    return out


def _dossier_line(
    ref: tuple[str, uuid.UUID],
    name: str,
    evidence_ids: set[uuid.UUID],
    dossiers: dict[tuple[str, uuid.UUID], str],
    article_sets: dict[tuple[str, uuid.UUID], set[uuid.UUID]],
) -> dict | None:
    """One {name, text} context line, or None when there is nothing safe to add."""
    text = dossiers.get(ref)
    if not text:
        return None
    articles = article_sets.get(ref)
    if articles and evidence_ids:
        overlap = len(articles & evidence_ids) / len(evidence_ids)
        if overlap > _DOSSIER_EVIDENCE_OVERLAP_MAX:
            return None
    return {"name": f"{name} ({ref[0]})", "text": text}


# --------------------------------------------------------------------------- kickoff


@celery_app.task(
    name="app.workers.relationship_adjudication_tasks.adjudicate_relationships",
    soft_time_limit=300,
    time_limit=360,
)
def adjudicate_relationships(limit: int | None = None) -> dict:
    """Kickoff: gather unadjudicated probable edges, fan out batches."""
    start = time.monotonic()
    try:
        stats = run_async(_kickoff_async(limit))
        CELERY_TASKS_TOTAL.labels(task_name="adjudicate_relationships", status="success").inc()
        logger.info("adjudicate_relationships kickoff: %s", stats)
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="adjudicate_relationships", status="error").inc()
        logger.exception("adjudicate_relationships kickoff failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="adjudicate_relationships").observe(time.monotonic() - start)


async def _kickoff_async(limit: int | None) -> dict:
    async with worker_session() as db:
        from app.services.system_settings import _ensure_cache

        await _ensure_cache(db)

        if not settings.get("relationship_adjudication_enabled"):
            return {"status": "disabled"}

        batch_size = max(1, int(settings.get("relationship_adjudication_batch_size") or 20))
        # Cap each nightly run so a large first-night backlog drains over days
        # instead of monopolizing the AI worker queue for hours.
        if limit is None:
            limit = _MAX_EDGES_PER_RUN
        items = await collect_adjudicable_edges(db, limit)

    if not items:
        return {"status": "no_pending_edges", "edges": 0, "batches": 0}

    batches = 0
    for i in range(0, len(items), batch_size):
        adjudicate_relationship_batch.apply_async(args=[items[i : i + batch_size]], queue="ai")
        batches += 1

    return {"status": "dispatched", "edges": len(items), "batches": batches, "batch_size": batch_size}


async def collect_adjudicable_edges(db: AsyncSession, limit: int | None = None) -> list[dict]:
    """Serialize unadjudicated probable machine edges into self-contained items.

    Item shape: {edge_id, claim, source_type, target_type, evidence: [titles]}.
    Evidence headlines are resolved here so batch workers don't re-query.
    """
    min_articles = max(1, int(settings.get("relationship_adjudication_min_articles") or 3))

    from sqlalchemy import or_ as sa_or

    # Unadjudicated edges, plus "unsure" verdicts after a 14-day cooldown —
    # evidence keeps accumulating, so unsure must not be a terminal state.
    unsure_cutoff = datetime.now(UTC) - timedelta(days=14)
    query = (
        select(EntityRelationship)
        .where(
            EntityRelationship.source.in_(MACHINE_SOURCES),
            EntityRelationship.confidence == "probable",
            sa_or(
                EntityRelationship.adjudication_verdict.is_(None),
                (EntityRelationship.adjudication_verdict == "unsure")
                & (EntityRelationship.adjudicated_at < unsure_cutoff),
            ),
            func.coalesce(func.array_length(EntityRelationship.evidence_entry_ids, 1), 0) >= min_articles,
        )
        .order_by(func.array_length(EntityRelationship.evidence_entry_ids, 1).desc())
    )
    if limit:
        query = query.limit(limit)
    edges = list((await db.execute(query)).scalars().all())
    if not edges:
        return []

    # Evidence-structure ordering: spend AI calls where they'll confirm
    # something valuable. Recurring edges (2+ story clusters) first, then
    # single-story, then unknown (no embeddings), then no-story roundup
    # scatter last — for those, the shape already is the verdict.
    from app.intelligence.evidence_structure import story_cluster_counts, structure_enabled

    if structure_enabled():
        counts = await story_cluster_counts(db, {e.id: (e.evidence_entry_ids or []) for e in edges})

        def _structure_rank(edge) -> int:
            n = counts.get(edge.id)
            if n is None:
                return 2
            if n >= 2:
                return 0
            return 1 if n == 1 else 3

        edges.sort(key=lambda e: (_structure_rank(e), -len(e.evidence_entry_ids or [])))

    refs = {(e.source_type, e.source_id) for e in edges} | {(e.target_type, e.target_id) for e in edges}
    names = await _entity_names(db, refs)

    # Profile paragraphs for both ends of each claim. Two extra queries per type
    # for the whole run, no extra AI call — the context rides in the batch that
    # already runs.
    dossiers: dict[tuple[str, uuid.UUID], str] = {}
    article_sets: dict[tuple[str, uuid.UUID], set[uuid.UUID]] = {}
    if settings.get("relationship_adjudication_dossier"):
        dossiers = await _entity_dossiers(db, refs)
        if dossiers:
            article_sets = await _assessment_article_sets(db, set(dossiers))

    # Bulk-fetch evidence headlines. evidence_entry_ids appends chronologically,
    # so the NEWEST evidence is at the tail — judge on recent reporting, not
    # the stale early co-mentions.
    all_entry_ids = {eid for e in edges for eid in (e.evidence_entry_ids or [])[-_EVIDENCE_TITLES_PER_EDGE * 2 :]}
    titles: dict[uuid.UUID, tuple[str, str | None]] = {}
    if all_entry_ids:
        rows = await db.execute(select(Entry.id, Entry.title, Entry.published_at).where(Entry.id.in_(all_entry_ids)))
        for rid, title, published in rows.all():
            titles[rid] = (title or "", published.date().isoformat() if published else None)

    items: list[dict] = []
    for edge in edges:
        src_name = names.get((edge.source_type, edge.source_id))
        tgt_name = names.get((edge.target_type, edge.target_id))
        if not src_name or not tgt_name:
            continue
        evidence = []
        seen_titles: set[str] = set()
        for eid in reversed((edge.evidence_entry_ids or [])[-_EVIDENCE_TITLES_PER_EDGE * 2 :]):
            t = titles.get(eid)
            if t and t[0] and t[0] not in seen_titles:  # syndicated copies repeat titles
                seen_titles.add(t[0])
                evidence.append(f"{t[0]} ({t[1]})" if t[1] else t[0])
            if len(evidence) >= _EVIDENCE_TITLES_PER_EDGE:
                break
        verb = edge.relationship_type.replace("_", " ")
        item = {
            "edge_id": str(edge.id),
            "claim": f"{src_name} ({edge.source_type}) {verb} {tgt_name} ({edge.target_type})",
            "evidence": evidence,
        }
        evidence_ids = set(edge.evidence_entry_ids or [])
        context = [
            line
            for line in (
                _dossier_line((edge.source_type, edge.source_id), src_name, evidence_ids, dossiers, article_sets),
                _dossier_line((edge.target_type, edge.target_id), tgt_name, evidence_ids, dossiers, article_sets),
            )
            if line
        ]
        if context:
            item["dossiers"] = context
        items.append(item)
    return items


# --------------------------------------------------------------------------- batch


@celery_app.task(
    name="app.workers.relationship_adjudication_tasks.adjudicate_relationship_batch",
    bind=True,
    soft_time_limit=420,
    time_limit=480,
    autoretry_for=(TimeoutError,),
    max_retries=2,
)
def adjudicate_relationship_batch(self, items: list[dict]) -> dict:
    """Judge one batch of edges. Runs on the ai queue."""
    start = time.monotonic()
    try:
        stats = run_async(_adjudicate_batch_async(items))
        status = stats.get("status", "unknown")
        if status == "provider_paused":
            pause_until_str = stats.get("pause_until")
            countdown = 3600
            if pause_until_str:
                try:
                    pause_until = datetime.fromisoformat(pause_until_str)
                    countdown = max(60, min(3600, int((pause_until - datetime.now(UTC)).total_seconds()) + 30))
                except ValueError:
                    pass
            CELERY_TASKS_TOTAL.labels(task_name="adjudicate_relationship_batch", status="provider_paused").inc()
            raise self.retry(countdown=countdown, max_retries=24)
        CELERY_TASKS_TOTAL.labels(
            task_name="adjudicate_relationship_batch",
            status="success" if status == "adjudicated" else "error",
        ).inc()
        return stats
    except self.MaxRetriesExceededError:
        CELERY_TASKS_TOTAL.labels(task_name="adjudicate_relationship_batch", status="error").inc()
        raise
    except CeleryRetry:
        # A routine provider-pause retry, not a failure — don't log/count it as one.
        raise
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="adjudicate_relationship_batch", status="error").inc()
        logger.exception("adjudicate_relationship_batch failed for %d edges", len(items))
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="adjudicate_relationship_batch").observe(time.monotonic() - start)


def _render_edges_block(items: list[dict]) -> str:
    """Render one prompt block per edge.

    The dossier lines go *inside* this block rather than into a new template
    variable on purpose: installs carry their own stored copy of the
    relationship_adjudication prompt, and a new `{{ variable }}` would render
    to nothing on every one of them. edges_block is already in every version of
    the template, so the context lands whatever the stored prompt looks like.
    """
    lines = []
    for item in items:
        evidence = "\n".join(f"    - {t}" for t in item.get("evidence") or []) or "    (no headlines available)"
        block = f"- edge_id={item['edge_id']}\n  claim: {item['claim']}\n  evidence headlines:\n{evidence}"
        for dossier in item.get("dossiers") or []:
            block += f"\n  profile of {dossier['name']}: {dossier['text']}"
        lines.append(block)
    return "\n".join(lines)


async def _adjudicate_batch_async(items: list[dict]) -> dict:
    from app.ai.providers.claude_code_provider import QuotaExhaustedError

    if not items:
        return {"status": "adjudicated", "adjudicated": 0}

    async with worker_session() as db:
        from app.services.system_settings import _ensure_cache, invalidate_cache

        invalidate_cache()
        await _ensure_cache(db)

        system_user = await _resolve_system_user(db)
        if not system_user:
            return {"status": "no_admin_user"}

        variables = {
            "edge_count": len(items),
            "edges_block": _render_edges_block(items),
        }
        try:
            result = await run_task(
                db=db,
                user_id=system_user.id,
                task_name="relationship_adjudication",
                variables=variables,
                target_type="rel_adjudication",  # ai_results.target_type is varchar(20)
                target_id=uuid.uuid4(),
                force=True,
            )
        except QuotaExhaustedError as e:
            pause_until = getattr(e, "reset_at", None) or getattr(e, "pause_until", None)
            return {
                "status": "provider_paused",
                "pause_until": pause_until.isoformat() if pause_until else None,
            }

        if not result:
            return {"status": "no_assignment"}
        if result.get("_extraction_status") == "provider_paused":
            return {"status": "provider_paused", "pause_until": result.get("_pause_until")}
        if result.get("_extraction_status") not in (None, "success"):
            logger.warning(
                "relationship adjudication batch: AI returned status=%r; no verdicts written",
                result.get("_extraction_status"),
            )
            return {"status": "ai_no_success", "ai_status": result.get("_extraction_status")}

        verdicts = result.get("verdicts")
        if not isinstance(verdicts, list):
            return {"status": "ai_bad_shape"}

        input_ids = {item["edge_id"] for item in items}
        now = datetime.now(UTC)
        counts = {"corroborated": 0, "coincidental": 0, "unsure": 0}
        unknown = 0
        touched_entities: set[tuple[str, str]] = set()
        for v in verdicts:
            if not isinstance(v, dict):
                continue
            edge_id = str(v.get("edge_id") or "")
            verdict = v.get("verdict")
            if edge_id not in input_ids or verdict not in VALID_VERDICTS:
                unknown += 1
                continue
            try:
                row_id = uuid.UUID(edge_id)
            except ValueError:
                unknown += 1
                continue
            edge = (
                await db.execute(select(EntityRelationship).where(EntityRelationship.id == row_id))
            ).scalar_one_or_none()
            if edge is None or edge.source == "analyst_rejected":
                continue
            edge.adjudication_verdict = verdict
            edge.adjudicated_at = now
            reason = (v.get("reason") or "")[:300]
            if verdict == "corroborated":
                edge.confidence = "confirmed"
                if reason and not edge.description:
                    edge.description = reason
            elif verdict == "coincidental":
                edge.confidence = "possible"
            counts[verdict] += 1
            touched_entities.add((edge.source_type, str(edge.source_id)))
            touched_entities.add((edge.target_type, str(edge.target_id)))
        await db.commit()

        # Confidence changes alter pivot/graph payloads — drop affected caches.
        from app.intelligence.correlation_cache import invalidate_entity_cache

        for etype, eid in touched_entities:
            await invalidate_entity_cache(etype, eid)

        return {"status": "adjudicated", "batch_size": len(items), **counts, "unknown_ids": unknown}
