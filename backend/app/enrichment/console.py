"""What the Enrichment console shows: each source's status, limits, queue,
fill rates and jobs, built from its manifest, its ``enrichment_sources`` row,
the gateway's Redis counters, ``enrichment_jobs`` and ``job_runs``.

Status, in order: ``key_rejected`` when the source is on and turned its key
down (a 401/403 the gateway recorded as an auth failure); ``failing`` when it is
on and one of its jobs last ended in an error or its circuit breaker is open;
``needs_key`` when it needs an API key it doesn't have; ``off`` when it is
switched off; else ``ok``. A source that is off never counts as failing: its
old errors aren't something to act on. ``attention`` is the reason a source
that is on needs a look (a rejected key, a failing job, an open breaker, a
missing key, lookups that gave up), or None.

``new`` marks a source whose row was added in the last ``NEW_DAYS`` days after
the instance's first sources, so the sources a release adds stand out without
every source on a fresh install reading as new.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import ARRAY, JSON, String, Text, and_, cast, exists, func, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.enrichment.base import Source
from app.enrichment.gateway import BACKFILL_SHARE, DEFAULT_RATE, GatewayUnavailable, hourly_requests, iocs_sent
from app.enrichment.manifest import Column, Context, Egress, Relation
from app.enrichment.pause import is_paused
from app.enrichment.queue import DEFERRALS, LANES
from app.enrichment.registry import ADAPTER_REGISTRY, SOURCE_REGISTRY, source_gateway
from app.enrichment.relations import claim_counts
from app.models.enrichment import EnrichmentJob, EnrichmentSource
from app.models.job_run import JobRun
from app.services.enrichment_gaps import ENRICH_GAP_SPECS

#: How long a source added after the first ones reads as new on the console.
NEW_DAYS = 14

#: Queue ``last_status`` values the console names, in the words it uses.
QUEUE_REASONS = (
    "rate_limited",
    "breaker_open",
    "budget_exhausted",
    "backfill_share",
    "paused",
    "auth_failed",
    "source_disabled",
)

#: Backfill size when the request names none, and the most one request queues.
BACKFILL_DEFAULT = 1000
BACKFILL_MAX = 50000

_ACRONYMS = {
    "asn",
    "capec",
    "cis",
    "cpe",
    "cvss",
    "cwe",
    "eol",
    "epss",
    "github",
    "id",
    "iso",
    "kev",
    "mitre",
    "nist",
    "ssvc",
    "ttp",
    "url",
}
_SPELLING = {"github": "GitHub", "mitre": "MITRE"}


def _model(entity_type: str):
    from app.enrichment.entity_updater import _get_model_map

    return _get_model_map().get(entity_type)


def _words(name: str) -> str:
    """``cvss_score`` → ``CVSS score``."""
    return " ".join(
        _SPELLING.get(w, w.upper()) if w in _ACRONYMS else w for w in name.replace(".", " ").split("_") if w
    )


def _rate_note(stored: dict, gateway, key: str | None) -> str | None:
    """Why the enforced rate differs from the stored one, if it does."""
    stored_per_s = stored["requests_per_period"] / stored["period_seconds"]
    effective_per_s = gateway.capacity / gateway.period
    if effective_per_s > stored_per_s and key:
        return "with key"
    if effective_per_s < stored_per_s:
        return "held to the source's limit"
    return None


def type_label(entity_type: str) -> str:
    label = entity_types.LABELS.get(entity_type, entity_type.replace("_", " "))
    return label[0].upper() + label[1:]


def _relation_words(out: Relation) -> str:
    """``uses tool``, ``communicates with malware family or tool``."""
    targets = " or ".join(entity_types.LABELS.get(t, t) for t in out.target_types)
    return f"{out.relation.replace('_', ' ')} {targets}"


def _context_words(label: str) -> str:
    """``Open ports`` → ``open ports``; a label that opens with an acronym or a
    mixed-case word (``EPSS score``, ``PoC``) keeps its case."""
    first = label.split(" ", 1)[0]
    return label if any(c.isupper() for c in first[1:]) else label[0].lower() + label[1:]


def fills(cls: type[Source]) -> str:
    """What a source writes, in a few words: its columns, then its profile
    context, else its first job's description."""
    items: list[str] = []
    for out in cls.outputs:
        if isinstance(out, Column):
            if out.follows:
                continue
            word = _words(out.path.split(".", 1)[0])
        elif isinstance(out, Relation):
            word = _relation_words(out)
        else:
            word = _context_words(out.label)
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
        # octet_length reads a long value's stored size without unpacking it,
        # which keeps a count over every CVE description fast.
        return func.coalesce(func.octet_length(col), 0) > 0
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


async def job_runs(db: AsyncSession, keys: list[str]) -> dict[str, dict]:
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


async def gateway_state(gateway) -> tuple[str, str | None, float]:
    """(state, message, seconds) for one source's credential: ``auth_failed``
    when the source rejected its key (the gateway's recorded auth failure),
    ``breaker_open`` while it backs off, else ``ok``. Raises
    GatewayUnavailable when Redis is down."""
    auth_failure = getattr(gateway, "auth_failure", None)
    if callable(auth_failure):
        auth = await auth_failure()
        if auth:
            return "auth_failed", auth.get("message"), float(auth.get("expires_in") or 0)
    seconds = await gateway.breaker_open_for()
    return ("breaker_open", None, seconds) if seconds else ("ok", None, 0.0)


def refresh_days(cls: type[Source], row: EnrichmentSource) -> float | None:
    """How often a stored answer is looked up again, in days: the row's own
    ``refresh_days`` setting, else the adapter module's ``TTL_HOURS``. None
    when nothing says."""
    import sys

    configured = (row.config or {}).get("refresh_days")
    if isinstance(configured, int | float) and configured > 0:
        return float(configured)
    hours = getattr(sys.modules.get(cls.__module__), "TTL_HOURS", None)
    if isinstance(hours, int | float) and hours > 0:
        return round(hours / 24, 2)
    return None


def is_new(row: EnrichmentSource, first_created: datetime | None, now: datetime | None = None) -> bool:
    """Added in the last NEW_DAYS days, and at least a day after the first
    source row (so a fresh install's seeded sources don't all read as new)."""
    created = row.created_at
    if created is None or first_created is None:
        return False
    now = now or datetime.now(UTC)
    return created >= now - timedelta(days=NEW_DAYS) and created - first_created >= timedelta(days=1)


async def _source_rows(db: AsyncSession) -> dict[str, EnrichmentSource]:
    rows = (await db.execute(select(EnrichmentSource))).scalars().all()
    return {r.source_type: r for r in rows if r.source_type in SOURCE_REGISTRY}


# ── Console ──────────────────────────────────────────────────────────


def _key_label(key_id: str) -> str:
    from app.enrichment.keys import credentials, label

    return label(credentials()[key_id])


async def console(db: AsyncSession, entity_type: str | None = None) -> dict:
    from app.enrichment.keys import credential_for

    rows = await _source_rows(db)
    job_keys = [job.key for cls in SOURCE_REGISTRY.values() for job in cls.jobs]
    runs = await job_runs(db, job_keys)
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

    first_created = min((r.created_at for r in rows.values() if r.created_at), default=None)
    sources = []
    attention: list[dict] = []
    for source_type, row in rows.items():
        cls = SOURCE_REGISTRY[source_type]
        label = row.display_name or cls.display_name
        key = await _global_key(row, db)
        state, state_message, breaker, used_today = "ok", None, 0.0, 0
        if redis_ok:
            gateway = source_gateway(row, key)
            try:
                used_today = await gateway.used_today()
                if row.is_enabled:
                    state, state_message, breaker = await gateway_state(gateway)
            except GatewayUnavailable:
                redis_ok = False

        errored = [
            (runs[j.key]["errors"], runs[j.key]["runs"], j.key)
            for j in cls.jobs
            if runs[j.key]["last"] is not None and runs[j.key]["last"].status == "error"
        ]
        missing_key = cls.requires_api_key and not key
        # What is missing, in words.
        needs = "key" if missing_key else None
        on = row.is_enabled
        credential = credential_for(source_type)
        # A source that is off is off: its old job errors and breaker aren't
        # something to act on, and they don't count toward "need attention".
        if on and state == "auth_failed":
            status = "key_rejected"
        elif on and (errored or breaker):
            status = "failing"
        elif missing_key:
            status = "needs_key"
        elif not on:
            status = "off"
        else:
            status = "ok"

        # Why the source needs a look, and the one action that fixes it.
        problem = None
        if not on:
            pass
        elif state == "auth_failed":
            problem = (
                state_message or "the source rejected the API key",
                {"kind": "key", "key": credential, "label": "Replace key"},
            )
        elif errored:
            errors, total, job_key = max(errored)
            problem = (
                f"{job_key} failed {errors} of {total} runs in 30 days",
                {"kind": "source", "source": source_type, "tab": "jobs", "label": "Open jobs"},
            )
        elif breaker:
            problem = (
                f"the source asked to back off; retrying in {max(1, round(breaker / 60))} min",
                {"kind": "source", "source": source_type, "tab": "overview", "label": "Open"},
            )
        elif missing_key:
            problem = (
                "needs an API key before it can run",
                {"kind": "key", "key": credential, "label": "Add key"},
            )
        elif failed_lookups.get(source_type):
            n = failed_lookups[source_type]
            problem = (
                f"{n} lookup{'s' if n != 1 else ''} gave up after repeated errors",
                {"kind": "retry", "source": source_type, "label": "Retry all"},
            )
        if problem:
            attention.append(
                {
                    "source_type": source_type,
                    "label": label,
                    "text": problem[0],
                    "severity": "bad" if status in ("key_rejected", "failing") else "warn",
                    "action": problem[1],
                }
            )

        if credential is None:
            key_status = None
        elif state == "auth_failed":
            key_status = "rejected"
        elif key:
            key_status = "set"
        else:
            key_status = "missing" if missing_key else "optional"

        sources.append(
            {
                "id": str(row.id),
                "source_type": source_type,
                "label": label,
                "about": cls.about,
                "kind": cls.kind,
                "status": status,
                "enabled": on,
                "new": is_new(row, first_created),
                "needs": needs,
                "fills": fills(cls),
                "applies_to": list(cls.applies_to),
                "attention": problem[0] if problem else None,
                # What a lookup sends out: none (the source is downloaded),
                # low (public ids), shares_ioc (the analyst's indicators).
                "egress": cls.egress.value,
                "license": cls.license.name,
                "commercial_ok": cls.license.commercial_ok,
                "key": credential,
                "key_status": key_status,
                # A catalog source has no lookups to run on their own.
                "trigger_mode": row.trigger_mode if cls.kind == "lookup" else None,
                "used_today": used_today,
                "daily_budget": row.daily_budget,
                "jobs": len(cls.jobs),
                # Settings that tune its jobs, so a settings search can open
                # the source they live in.
                "settings_keys": [k for job in cls.jobs for k in job.settings_keys],
                # Settings that configure the source itself, on its Limits tab.
                "source_settings": list(cls.settings_keys),
            }
        )

    # One rejected or missing key is one problem, however many sources share it.
    merged: list[dict] = []
    for item in attention:
        action = item["action"]
        twin = next(
            (m for m in merged if action["kind"] == "key" and m["action"] == action and m["text"] == item["text"]),
            None,
        )
        if twin:
            twin.setdefault("sources", [twin["label"]]).append(item["label"])
            twin["label"] = _key_label(action["key"])
        else:
            merged.append(dict(item))
    merged.sort(key=lambda a: (a["severity"] != "bad", a["label"].lower()))
    if not redis_ok:
        merged.insert(
            0,
            {
                "source_type": None,
                "label": "Redis",
                "text": "is unreachable: every request to an outside source is refused until it's back",
                "severity": "bad",
                "action": None,
            },
        )

    counts: dict[str, int] = {}
    for src in sources:
        for t in src["applies_to"]:
            counts[t] = counts.get(t, 0) + 1

    since = datetime.now(UTC) - timedelta(hours=24)
    waiting, backfill_waiting, deferred = (
        await db.execute(
            select(
                func.count().filter(EnrichmentJob.status.in_(("queued", "running"))),
                func.count().filter(EnrichmentJob.status.in_(("queued", "running")), EnrichmentJob.lane == "backfill"),
                func.count().filter(EnrichmentJob.last_status.in_(DEFERRALS), EnrichmentJob.updated_at >= since),
            )
        )
    ).one()
    try:
        sent = await iocs_sent() if redis_ok else None
    except GatewayUnavailable:
        sent = None
    ioc_sources = [src["label"] for src in sources if src["egress"] == Egress.SHARES_IOC.value and src["enabled"]]

    summary = {
        "sources_on": sum(1 for src in sources if src["enabled"]),
        "sources_total": len(sources),
        "paused": await is_paused(db),
        "redis_ok": redis_ok,
        "activity_24h": {
            "requests": sum(sum(v) for v in hourly.values()),
            # 24 hourly totals across every source, oldest first.
            "trend": [sum(col) for col in zip(*hourly.values(), strict=True)] if hourly else [0] * 24,
            "waiting": waiting,
            "waiting_backfill": backfill_waiting,
            "deferred": deferred,
            # Distinct indicators sent to sources that receive them; None
            # when Redis can't say.
            "iocs_sent": sent,
            "ioc_sources": ioc_sources,
        },
    }

    if entity_type:
        sources = [src for src in sources if entity_type in src["applies_to"]]
    sources.sort(key=lambda src: (src["attention"] is None, not src["enabled"], src["label"].lower()))
    return {
        "summary": summary,
        "attention": merged,
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
    # The console edits the row's own rate. What the gateway enforces can
    # differ: a keyed quota stands in for it when a key is in use, and a rate
    # above the source's ceiling is held to the ceiling.
    stored = {**DEFAULT_RATE, **(row.rate_limit_config or {})}
    quota = cls.quota.keyed if key and cls.quota.keyed else cls.quota

    try:
        used_today = await gateway.used_today()
        trend = (await hourly_requests([source_type]))[source_type]
    except GatewayUnavailable:
        used_today, trend = 0, [0] * 24

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
    reasons = {reason: 0 for reason in QUEUE_REASONS}
    waiting = retrying = failed = 0
    queue_rows = (
        await db.execute(
            select(
                EnrichmentJob.status,
                EnrichmentJob.lane,
                EnrichmentJob.last_status,
                func.count(),
                func.count().filter(or_(EnrichmentJob.attempts > 0, EnrichmentJob.last_status.isnot(None))),
            )
            .where(EnrichmentJob.source_type == source_type)
            .group_by(EnrichmentJob.status, EnrichmentJob.lane, EnrichmentJob.last_status)
        )
    ).all()
    for status, lane, last_status, n, tried in queue_rows:
        if status == "failed":
            failed += n
            continue
        waiting += n
        lanes[lane] = lanes.get(lane, 0) + n
        if status == "queued":
            retrying += tried
            if last_status in reasons:
                reasons[last_status] += n

    rates = await fill_rates(db, cls)
    claims = await claim_counts(db, source_type) if cls.relations() else {}
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
        elif isinstance(out, Relation):
            counts = claims.get(out.key, {})
            outputs.append(
                {
                    "field": out.key,
                    "target": f"relationship: {_relation_words(out)}",
                    "kind": "relationship",
                    "policy": None,
                    "rank": None,
                    "filled_pct": None,
                    "linked": counts.get("linked", 0),
                    "held": counts.get("held", 0),
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
    runs = await job_runs(db, [j.key for j in cls.jobs])
    jobs = []
    for job in cls.jobs:
        schedule = (overrides.get(job.key) or {}).get("schedule") or job.schedule
        r = runs[job.key]
        last = r["last"]
        result = (last.detail or {}).get("result") if last else None
        jobs.append(
            {
                "key": job.key,
                "description": job.description,
                # The settings that tune this job, edited beside it.
                "settings_keys": list(job.settings_keys),
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
            "rate": {"requests_per_period": stored["requests_per_period"], "period_seconds": stored["period_seconds"]},
            "effective_rate": {"requests_per_period": gateway.capacity, "period_seconds": gateway.period},
            "rate_note": _rate_note(stored, gateway, key),
            "ceiling_per_period": quota.ceiling_per_period,
            "daily_budget": row.daily_budget,
            "used_today": used_today,
            "backfill_share": BACKFILL_SHARE if row.daily_budget and lookup else None,
            "refresh_days": refresh_days(cls, row),
            # Requests in flight at once under one credential.
            "concurrency": gateway.concurrency,
            "triggers": triggers,
            "scope": scope,
        },
        "trend_24h": trend,
        "queue": {
            "waiting": waiting,
            "by_lane": lanes,
            "retrying": retrying,
            # Queued lookups by why they are waiting again: rate_limited is
            # a 429 (or the bucket), breaker_open a back-off, and so on.
            "by_reason": {k: v for k, v in reasons.items() if v},
            "failed": failed,
        },
        # What the limits form edits, so the console needs no second request.
        "settings": {
            "trigger_mode": row.trigger_mode,
            "rate_limit_config": row.rate_limit_config or {},
        },
        "outputs": outputs,
        "gap": gap,
        "jobs": jobs,
    }


# ── Coverage ─────────────────────────────────────────────────────────


def _ai_field(entity_type: str, column: str) -> str | None:
    """The AI gap-research field (``/admin/hygiene/enrichment-gaps/enrich``)
    that covers this column, if one does."""
    for spec_type, field in ENRICH_GAP_SPECS:
        if spec_type == entity_type and (column == field or column.startswith(f"{field}_")):
            return field
    return None


async def coverage(db: AsyncSession) -> list[dict]:
    """How full each column a source fills is, across every entity of its type,
    which sources fill it, and the one thing to do about the rest: a backfill
    through an enabled lookup source, else AI research where it covers the
    field, else nothing (the field's jobs fill it on their schedule)."""
    from app.workers.job_registry import schedule_to_human

    rows = await _source_rows(db)
    targets: dict[str, list[tuple[str, Column]]] = {}
    for source_type, cls in SOURCE_REGISTRY.items():
        if source_type not in rows:
            continue
        for column in cls.columns():
            if column.follows or column.entity_type not in cls.applies_to or "." in column.path:
                continue
            targets.setdefault(column.target, []).append((source_type, column))

    by_type: dict[str, list[str]] = {}
    for target in targets:
        by_type.setdefault(target.split(".", 1)[0], []).append(target)
    filled: dict[str, tuple[int, int]] = {}
    for entity_type, names in by_type.items():
        model = _model(entity_type)
        if model is None:
            continue
        counted = (func.count().filter(_filled(model, t.split(".", 1)[1])) for t in names)
        total, *counts = (await db.execute(select(func.count(), *counted).select_from(model))).one()
        for target, n in zip(names, counts, strict=True):
            filled[target] = (n, total)

    out = []
    for target, outputs in targets.items():
        if target not in filled:
            continue
        n, total = filled[target]
        entity_type, column = target.split(".", 1)
        outputs.sort(key=lambda o: (o[1].rank or 0, o[0]))
        on = [(st, col) for st, col in outputs if rows[st].is_enabled]
        action = None
        if total > n:
            # A backfill queues only the entities its source can look up and
            # doesn't already have waiting; the button names the most it could.
            # A backfill fills the source's first column, so it is offered
            # only where this field is that column.
            lookup = next(
                (
                    st
                    for st, col in on
                    if st in ADAPTER_REGISTRY
                    and (primary := primary_column(SOURCE_REGISTRY[st], entity_type)) is not None
                    and primary.target == col.target
                ),
                None,
            )
            if lookup:
                action = {"kind": "backfill", "source": lookup, "count": total - n}
            elif field := _ai_field(entity_type, column):
                action = {"kind": "ai", "field": field}
        cadence = None
        if action is None:
            jobs = [job for st, _ in on for job in SOURCE_REGISTRY[st].jobs]
            cadence = schedule_to_human(jobs[0].schedule) if jobs else None
        out.append(
            {
                "entity_type": entity_type,
                "entity_label": type_label(entity_type),
                "field": column,
                "label": _words(column),
                "filled": n,
                "total": total,
                "filled_pct": round(100 * n / total, 1) if total else None,
                "sources": [
                    {
                        "source_type": st,
                        "label": rows[st].display_name or SOURCE_REGISTRY[st].display_name,
                        "enabled": rows[st].is_enabled,
                    }
                    for st in dict.fromkeys(st for st, _ in outputs)
                ],
                "action": action,
                "cadence": cadence,
            }
        )
    out.sort(key=lambda r: (r["entity_label"], r["label"].lower()))
    return out


# ── Activity ─────────────────────────────────────────────────────────


async def activity(db: AsyncSession) -> dict:
    """The queue by lane (waiting and put off), the lookups that gave up by
    source, and each source's requests over the last 24 hours."""
    rows = await _source_rows(db)
    lanes = {lane: {"waiting": 0, "deferred": 0} for lane in LANES}
    for lane, waiting, deferred in (
        await db.execute(
            select(
                EnrichmentJob.lane,
                func.count().filter(EnrichmentJob.status.in_(("queued", "running"))),
                func.count().filter(EnrichmentJob.status == "queued", EnrichmentJob.last_status.in_(DEFERRALS)),
            ).group_by(EnrichmentJob.lane)
        )
    ).all():
        lanes.setdefault(lane, {"waiting": 0, "deferred": 0}).update(waiting=waiting, deferred=deferred)

    def label(st: str) -> str:
        row = rows.get(st)
        return (row.display_name if row else None) or SOURCE_REGISTRY[st].display_name

    failed = [
        {"source_type": st, "label": label(st), "count": n, "last_error": err}
        for st, n, err in (
            await db.execute(
                select(EnrichmentJob.source_type, func.count(), func.max(EnrichmentJob.last_error))
                .where(EnrichmentJob.status == "failed")
                .group_by(EnrichmentJob.source_type)
            )
        ).all()
        if st in SOURCE_REGISTRY
    ]
    try:
        hourly = await hourly_requests(list(rows))
    except GatewayUnavailable:
        hourly = None
    requests = (
        sorted(
            ({"source_type": st, "label": label(st), "requests": sum(v)} for st, v in hourly.items() if sum(v)),
            key=lambda r: -r["requests"],
        )
        if hourly is not None
        else None
    )
    return {
        "lanes": [{"lane": lane, **counts} for lane, counts in lanes.items()],
        "backfill_share": BACKFILL_SHARE,
        "failed": sorted(failed, key=lambda f: -f["count"]),
        "requests": requests,
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
    value_col = getattr(model, cls.lookup_column(column.entity_type))
    order = model.created_at.desc() if hasattr(model, "created_at") else model.id
    picked = (
        await db.execute(select(model.id, value_col).where(*where, value_col.isnot(None)).order_by(order).limit(limit))
    ).all()
    return await enqueue_many(db, column.entity_type, source_type, [(eid, value) for eid, value in picked])
