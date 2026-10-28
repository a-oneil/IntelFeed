"""What the Enrichment console shows: each source's status, limits, queue,
fill rates and jobs, built from its manifest, its ``enrichment_sources`` row,
the gateway's Redis counters, ``enrichment_jobs`` and ``job_runs``.

Status, in order: ``failing`` when one of the source's jobs last ended in an
error or its circuit breaker is open; ``needs_key`` when it needs an API key it
doesn't have; ``off`` when it is switched off; else ``ok``. ``attention`` is the
reason a source needs a look (a failing job, an open breaker, a missing key on
a source that is on, lookups that gave up), or None.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import ARRAY, JSON, String, Text, and_, cast, exists, func, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.enrichment.base import Source
from app.enrichment.gateway import GatewayUnavailable, hourly_requests
from app.enrichment.manifest import Column, Context, Egress
from app.enrichment.pause import is_paused
from app.enrichment.queue import BACKFILL_SHARE, LANES
from app.enrichment.registry import ADAPTER_REGISTRY, SOURCE_REGISTRY, source_gateway
from app.models.enrichment import EnrichmentJob, EnrichmentSource, UserEnrichmentOverride
from app.models.job_run import JobRun

#: Queue outcomes that mean "waiting for the source", not "broken".
DEFERRALS = ("rate_limited", "breaker_open", "budget_exhausted", "backfill_share", "paused")

#: The value an entity is looked up by, where it isn't ``name``.
LOOKUP_COLUMN = {"cve": "cve_id", "cwe": "cwe_id", "ttp": "technique_id", "observable": "value"}

#: Backfill size when the request names none, and the most one request queues.
BACKFILL_DEFAULT = 1000
BACKFILL_MAX = 50000

_ACRONYMS = {"cvss", "cwe", "eol", "epss", "id", "iso", "kev", "mitre", "url", "github"}
_SPELLING = {"github": "GitHub", "mitre": "MITRE"}


def _model(entity_type: str):
    from app.enrichment.entity_updater import _get_model_map

    return _get_model_map().get(entity_type)


def _words(name: str) -> str:
    """``cvss_score`` → ``CVSS score``."""
    return " ".join(
        _SPELLING.get(w, w.upper()) if w in _ACRONYMS else w for w in name.replace(".", " ").split("_") if w
    )


def type_label(entity_type: str) -> str:
    label = entity_types.LABELS.get(entity_type, entity_type.replace("_", " "))
    return label[0].upper() + label[1:]


def fills(cls: type[Source]) -> str:
    """What a source writes, in a few words: its columns, then its profile
    context, else its first job's description."""
    items: list[str] = []
    for out in cls.outputs:
        if isinstance(out, Column):
            if out.follows:
                continue
            word = _words(out.path.split(".", 1)[0])
        else:
            # "Open ports" → "open ports"; an acronym ("EPSS score") stays.
            word = out.label if out.label[:2].isupper() else out.label[0].lower() + out.label[1:]
        if word.lower() not in (i.lower() for i in items):
            items.append(word)
    if not items:
        return cls.jobs[0].description if cls.jobs else ""
    shown = ", ".join(items[:4])
    return f"{shown} +{len(items) - 4} more" if len(items) > 4 else shown


def primary_column(cls: type[Source], entity_type: str | None = None) -> Column | None:
    """The column a backfill fills: the source's first column output (for
    ``entity_type``, when given) that isn't written along with another."""
    for out in cls.columns():
        if out.follows or out.entity_type not in cls.applies_to:
            continue
        if entity_type is None or out.entity_type == entity_type:
            return out
    return None


# ── Fill rates ───────────────────────────────────────────────────────


def _filled(model, path: str):
    """SQL: the entity's ``path`` (``column`` or ``column.key``) holds a value."""
    name, _, key = path.partition(".")
    col = getattr(model, name)
    if key:
        value = col[key].astext
        return and_(value.isnot(None), value.notin_(["", "null", "[]", "{}"]))
    kind = col.type
    if isinstance(kind, ARRAY):
        return func.coalesce(func.cardinality(col), 0) > 0
    if isinstance(kind, JSON):
        return and_(col.isnot(None), cast(col, Text).notin_(["null", "[]", "{}"]))
    if isinstance(kind, String | Text):
        return and_(col.isnot(None), func.btrim(col) != "")
    return col.isnot(None)


async def fill_rates(db: AsyncSession, cls: type[Source]) -> dict[str, float | None]:
    """Percent of in-scope entities whose column holds a value, per column
    target. One query per entity type."""
    by_type: dict[str, list[str]] = {}
    for out in cls.columns():
        if out.entity_type in cls.applies_to and out.target not in by_type.get(out.entity_type, []):
            by_type.setdefault(out.entity_type, []).append(out.target)
    rates: dict[str, float | None] = {}
    for entity_type, targets in by_type.items():
        model = _model(entity_type)
        if model is None:
            continue
        query = select(
            func.count(),
            *(func.count().filter(_filled(model, t.split(".", 1)[1])) for t in targets),
        ).select_from(model)
        scope = cls.scope_filter(entity_type, model)
        if scope is not None:
            query = query.where(scope)
        total, *filled = (await db.execute(query)).one()
        for target, n in zip(targets, filled, strict=True):
            rates[target] = round(100 * n / total, 1) if total else None
    return rates


def _missing(cls: type[Source], column: Column, source_type: str, *, in_scope: bool):
    """The entity model and the conditions for entities lacking ``column``;
    ``in_scope`` narrows them to those the source can look up and doesn't
    already have waiting in its queue."""
    model = _model(column.entity_type)
    where = [not_(_filled(model, column.path))]
    if in_scope:
        scope = cls.scope_filter(column.entity_type, model)
        if scope is not None:
            where.append(scope)
        waiting = exists().where(
            EnrichmentJob.entity_type == column.entity_type,
            EnrichmentJob.entity_id == model.id,
            EnrichmentJob.source_type == source_type,
            EnrichmentJob.status.in_(("queued", "running")),
        )
        where.append(~waiting)
    return model, where


# ── Shared reads ─────────────────────────────────────────────────────


async def _global_key(source: EnrichmentSource, db: AsyncSession) -> str | None:
    from app.enrichment.pipeline import resolve_api_key

    return await resolve_api_key(source, None, db)


async def _job_runs(db: AsyncSession, keys: list[str]) -> dict[str, dict]:
    """Per job key, its runs over 30 days and its last run."""
    if not keys:
        return {}
    since = datetime.now(UTC) - timedelta(days=30)
    counts = (
        await db.execute(
            select(
                JobRun.job_key,
                func.count(),
                func.count().filter(JobRun.status == "success"),
                func.count().filter(JobRun.status == "error"),
            )
            .where(JobRun.job_key.in_(keys), JobRun.finished_at >= since)
            .group_by(JobRun.job_key)
        )
    ).all()
    last = (
        (
            await db.execute(
                select(JobRun)
                .where(JobRun.job_key.in_(keys))
                .distinct(JobRun.job_key)
                .order_by(JobRun.job_key, JobRun.finished_at.desc().nulls_last())
            )
        )
        .scalars()
        .all()
    )
    runs = {k: {"runs": 0, "ok": 0, "errors": 0, "last": None} for k in keys}
    for key, n, ok, errors in counts:
        runs[key].update(runs=n, ok=ok, errors=errors)
    for run in last:
        runs[run.job_key]["last"] = run
    return runs


async def _source_rows(db: AsyncSession) -> dict[str, EnrichmentSource]:
    rows = (await db.execute(select(EnrichmentSource))).scalars().all()
    return {r.source_type: r for r in rows if r.source_type in SOURCE_REGISTRY}


# ── Console ──────────────────────────────────────────────────────────


async def console(db: AsyncSession, entity_type: str | None = None) -> dict:
    rows = await _source_rows(db)
    job_keys = [job.key for cls in SOURCE_REGISTRY.values() for job in cls.jobs]
    runs = await _job_runs(db, job_keys)
    failed_lookups = dict(
        (
            await db.execute(
                select(EnrichmentJob.source_type, func.count())
                .where(EnrichmentJob.status == "failed")
                .group_by(EnrichmentJob.source_type)
            )
        ).all()
    )

    redis_ok = True
    try:
        hourly = await hourly_requests(list(rows))
    except GatewayUnavailable:
        redis_ok, hourly = False, {}

    sources = []
    for source_type, row in rows.items():
        cls = SOURCE_REGISTRY[source_type]
        key = await _global_key(row, db)
        breaker = 0.0
        if redis_ok:
            try:
                breaker = await source_gateway(row, key).breaker_open_for()
            except GatewayUnavailable:
                redis_ok = False

        errored = [
            (runs[j.key]["errors"], runs[j.key]["runs"], j.key)
            for j in cls.jobs
            if runs[j.key]["last"] is not None and runs[j.key]["last"].status == "error"
        ]
        needs_key = "api_key" in cls.requires and not key
        if errored or breaker:
            status = "failing"
        elif needs_key:
            status = "needs_key"
        elif not row.is_enabled:
            status = "off"
        else:
            status = "ok"

        attention = None
        if errored:
            errors, total, job_key = max(errored)
            attention = f"{job_key} failed {errors} of {total} runs in 30 days"
        elif breaker:
            attention = f"the source asked to back off; retrying in {max(1, round(breaker / 60))} min"
        elif needs_key and row.is_enabled:
            attention = "needs an API key"
        elif failed_lookups.get(source_type) and row.is_enabled:
            n = failed_lookups[source_type]
            attention = f"{n} lookup{'s' if n != 1 else ''} gave up after repeated errors"

        sources.append(
            {
                "id": str(row.id),
                "source_type": source_type,
                "label": row.display_name or cls.display_name,
                "kind": cls.kind,
                "status": status,
                "enabled": row.is_enabled,
                "fills": fills(cls),
                "applies_to": list(cls.applies_to),
                "attention": attention,
            }
        )

    counts: dict[str, int] = {}
    for s in sources:
        for t in s["applies_to"]:
            counts[t] = counts.get(t, 0) + 1

    since = datetime.now(UTC) - timedelta(hours=24)
    queued, deferred = (
        await db.execute(
            select(
                func.count().filter(EnrichmentJob.created_at >= since),
                func.count().filter(EnrichmentJob.last_status.in_(DEFERRALS), EnrichmentJob.updated_at >= since),
            )
        )
    ).one()

    summary = {
        "sources_on": sum(1 for s in sources if s["enabled"]),
        "sources_total": len(sources),
        "needs_attention": sum(1 for s in sources if s["attention"]),
        "paused": await is_paused(db),
        "redis_ok": redis_ok,
        "activity_24h": {
            "requests": sum(sum(v) for v in hourly.values()),
            "queued": queued,
            "deferred": deferred,
            "iocs_sent_off_box": sum(
                sum(v) for st, v in hourly.items() if SOURCE_REGISTRY[st].egress == Egress.SHARES_IOC
            ),
        },
    }

    if entity_type:
        sources = [s for s in sources if entity_type in s["applies_to"]]
    sources.sort(key=lambda s: (s["attention"] is None, not s["enabled"], s["label"].lower()))
    return {
        "summary": summary,
        "entity_types": [
            {"entity_type": t, "label": type_label(t), "source_count": n}
            for t, n in sorted(counts.items(), key=lambda kv: (-kv[1], type_label(kv[0])))
        ],
        "sources": sources,
    }


# ── Source detail ────────────────────────────────────────────────────


async def detail(db: AsyncSession, source_type: str) -> dict | None:
    from app.api.job_schedules import _load_overrides
    from app.workers.job_registry import schedule_to_human

    cls = SOURCE_REGISTRY.get(source_type)
    row = (await _source_rows(db)).get(source_type)
    if cls is None or row is None:
        return None
    key = await _global_key(row, db)
    gateway = source_gateway(row, key)
    quota = cls.quota.keyed if key and cls.quota.keyed else cls.quota

    try:
        used_today = await gateway.used_today()
        trend = (await hourly_requests([source_type]))[source_type]
    except GatewayUnavailable:
        used_today, trend = 0, [0] * 24

    if key:
        key_text = "global"
    else:
        overrides = (
            await db.execute(
                select(func.count()).where(
                    UserEnrichmentOverride.source_id == row.id, UserEnrichmentOverride.api_key_encrypted.isnot(None)
                )
            )
        ).scalar_one()
        key_text = f"user_overrides:{overrides}" if overrides else "none"

    primary = primary_column(cls)
    lookup = source_type in ADAPTER_REGISTRY
    triggers = []
    if lookup:
        if row.trigger_mode == "auto":
            triggers.append("new")
        triggers.append("manual")
        if primary:
            triggers.append("backfill")
    if cls.jobs:
        triggers.append("schedule")

    scope = None
    if primary:
        kinds = cls.applies_to.get(primary.entity_type)
        scope = f"{entity_types.LABELS.get(primary.entity_type, primary.entity_type)}"
        if kinds:
            scope += f" ({', '.join(kinds)})"
        for col, values in cls.scope.items():
            scope += f", {_words(col)} {' or '.join(values)}"
        scope += f" with no {_words(primary.path)}"

    lanes = {lane: 0 for lane in LANES}
    waiting = retrying = failed = 0
    queue_rows = (
        await db.execute(
            select(
                EnrichmentJob.status,
                EnrichmentJob.lane,
                func.count(),
                func.count().filter(or_(EnrichmentJob.attempts > 0, EnrichmentJob.last_status.isnot(None))),
            )
            .where(EnrichmentJob.source_type == source_type)
            .group_by(EnrichmentJob.status, EnrichmentJob.lane)
        )
    ).all()
    for status, lane, n, tried in queue_rows:
        if status == "failed":
            failed += n
            continue
        waiting += n
        lanes[lane] = lanes.get(lane, 0) + n
        if status == "queued":
            retrying += tried

    rates = await fill_rates(db, cls)
    outputs = []
    for out in cls.outputs:
        if isinstance(out, Column):
            outputs.append(
                {
                    "field": out.key,
                    "target": out.target,
                    "kind": "column",
                    "policy": out.policy.value,
                    "rank": out.rank,
                    "filled_pct": rates.get(out.target),
                }
            )
        elif isinstance(out, Context):
            outputs.append(
                {
                    "field": out.key,
                    "target": f"profile: {out.label}",
                    "kind": "context",
                    "policy": None,
                    "rank": None,
                    "filled_pct": None,
                }
            )

    gap = None
    if primary and _model(primary.entity_type) is not None:
        model, where = _missing(cls, primary, source_type, in_scope=False)
        missing = (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()
        in_scope = 0
        if lookup:
            _, where = _missing(cls, primary, source_type, in_scope=True)
            in_scope = (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()
        per_day = gateway.capacity * 86400 / gateway.period
        if row.daily_budget:
            per_day = min(per_day, row.daily_budget * BACKFILL_SHARE)
        gap = {
            "entity_type": primary.entity_type,
            "field": primary.path,
            "missing": missing,
            "in_scope": in_scope,
            "eta_days": max(0.1, round(in_scope / per_day, 1)) if per_day and in_scope else None,
        }

    overrides = await _load_overrides(db)
    runs = await _job_runs(db, [j.key for j in cls.jobs])
    jobs = []
    for job in cls.jobs:
        schedule = (overrides.get(job.key) or {}).get("schedule") or job.schedule
        r = runs[job.key]
        last = r["last"]
        result = (last.detail or {}).get("result") if last else None
        jobs.append(
            {
                "key": job.key,
                "schedule": schedule_to_human(schedule),
                "runs_30d": r["runs"],
                "ok_30d": r["ok"],
                "last_status": last.status if last else None,
                "last_error": last.error if last else None,
                "last_detail": (result if isinstance(result, dict) else {"result": result})
                if result is not None
                else None,
            }
        )

    return {
        "limits": {
            "requests_per_period": gateway.capacity,
            "period_seconds": gateway.period,
            "ceiling_per_period": quota.ceiling_per_period,
            "daily_budget": row.daily_budget,
            "used_today": used_today,
            "backfill_share": BACKFILL_SHARE if row.daily_budget and lookup else None,
            "refresh_days": None,
            "key": key_text,
            "triggers": triggers,
            "scope": scope,
        },
        "trend_24h": trend,
        "queue": {"waiting": waiting, "by_lane": lanes, "retrying": retrying, "failed": failed},
        "outputs": outputs,
        "gap": gap,
        "jobs": jobs,
    }


# ── Backfill ─────────────────────────────────────────────────────────


class BackfillError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


async def backfill(db: AsyncSession, source_type: str, entity_type: str | None, limit: int | None) -> int:
    """Queue backfill-lane lookups at a lookup source for the in-scope entities
    missing its primary column, newest first, at most ``limit``. Returns the
    number queued."""
    from app.enrichment.queue import enqueue_many

    cls = ADAPTER_REGISTRY.get(source_type)
    if cls is None:
        raise BackfillError("not_lookup", f"{source_type} has no per-entity lookup to backfill with")
    if entity_type is not None and entity_type not in cls.applies_to:
        raise BackfillError("not_applicable", f"{cls.display_name} doesn't look up {entity_type}")
    column = primary_column(cls, entity_type)
    if column is None:
        raise BackfillError("no_column", f"{cls.display_name} fills no column to backfill")
    row = (await _source_rows(db)).get(source_type)
    if row is None or not row.is_enabled:
        raise BackfillError("source_disabled", f"{cls.display_name} is off")

    limit = min(max(1, limit or BACKFILL_DEFAULT), BACKFILL_MAX)
    model, where = _missing(cls, column, source_type, in_scope=True)
    value_col = getattr(model, LOOKUP_COLUMN.get(column.entity_type, "name"))
    order = model.created_at.desc() if hasattr(model, "created_at") else model.id
    picked = (
        await db.execute(select(model.id, value_col).where(*where, value_col.isnot(None)).order_by(order).limit(limit))
    ).all()
    return await enqueue_many(db, column.entity_type, source_type, [(eid, value) for eid, value in picked])
