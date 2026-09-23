"""Signal engine — explainable per-entry signals and the IDF-weighted priority score.

Each signal is a rare-by-construction observation about an entry (first mention
of an entity, severe-but-under-covered CVE, near-duplicate echo, …) with a
human-readable explanation. The priority score is the weighted sum of raw
signal scores, where each signal type's weight self-tunes to its 30-day firing
rate (IDF-style): a signal firing on half the river contributes almost nothing,
one firing on 0.5% of entries contributes a lot. Family multipliers (global,
admin-set) sit on top for coarse steering.

Computed by score_entry_task after post-processing (co-occurrence edges,
correlation events, requirement matches all exist by then). All queries are
index-backed; the feed_echo overlap probe is the only one that fans out, and it
excludes mega-entities to stay bounded.
"""

import json
import logging
import math
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

from sqlalchemy import func, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.correlation_event import CorrelationEventRecord
from app.models.country import EntryCountry
from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.story_thread import StoryThread, StoryThreadEntry
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import EntryTTP
from app.services.redis_client import get_redis

logger = logging.getLogger(__name__)

RATES_REDIS_KEY = "intelfeed:signal_engine:rates"
MULTIPLIERS_REDIS_KEY = "intelfeed:signal_engine:multipliers"
THRESHOLD_REDIS_KEY = "intelfeed:signal_engine:threshold"  # auto (p95), written by rates job
THRESHOLD_OVERRIDE_REDIS_KEY = "intelfeed:signal_engine:threshold_override"  # manual
FEEDBACK_NUDGE_REDIS_KEY = "intelfeed:signal_engine:feedback_nudge"  # bounded ±10%, from Radar thumbs
DEFAULT_RADAR_THRESHOLD = 1.5

SIGNAL_FAMILIES: dict[str, str] = {
    "novel_entity": "novelty",
    "entity_resurgence": "novelty",
    "new_pairing": "novelty",
    "scoop": "novelty",
    "source_convergence": "coverage",
    "under_reported": "coverage",
    "feed_echo": "coverage",
    "kev_added": "severity",
    "epss_jump": "severity",
    "epss_high": "severity",
    "weaponized_poc": "severity",
    "critical_cvss": "severity",
    "pir_match": "interest",
    "correlation_event": "interest",
    "detection_content": "content",
    "research_depth": "content",
}

DEFAULT_FAMILY_MULTIPLIERS: dict[str, float] = {
    "novelty": 1.0,
    "coverage": 1.0,
    "severity": 1.0,
    "interest": 1.0,
    "content": 1.0,
}

# Cold-start firing-rate estimates, replaced nightly by recompute_signal_rates
# from actual 30-day data. Deliberately conservative: frequent signals start
# down-weighted (pir_match fires on ~43% of prod entries today).
DEFAULT_FIRING_RATES: dict[str, float] = {
    "novel_entity": 0.02,
    "entity_resurgence": 0.005,
    "new_pairing": 0.01,
    "scoop": 0.005,
    "source_convergence": 0.05,
    "under_reported": 0.005,
    "feed_echo": 0.15,
    "kev_added": 0.01,
    "epss_jump": 0.005,
    "epss_high": 0.01,
    "weaponized_poc": 0.02,
    "critical_cvss": 0.05,
    "pir_match": 0.43,
    "correlation_event": 0.25,
    "detection_content": 0.02,
    "research_depth": 0.05,
}

# feed_echo contributes negatively with a fixed weight — its job is to sink
# re-reported stories, not to participate in IDF weighting.
ECHO_WEIGHT = -0.5

# Entities linked to more articles than this are excluded from the echo/
# convergence overlap probes (shared "Microsoft"-scale entities would make
# everything look like an echo — and make the probe scan wide).
MEGA_ENTITY_ARTICLE_COUNT = 500

NOVEL_ARTICLE_COUNT = 3
NOVEL_FIRST_SEEN_DAYS = 14
RESURGENCE_DAYS = 90
ECHO_WINDOW_HOURS = 72
ECHO_MIN_ENTITIES = 3
ECHO_MIN_RATIO = 0.7
CONVERGENCE_WINDOW_HOURS = 24
CONVERGENCE_MIN_FEEDS = 3
# Longest thread title shown inside an echo explanation.
ECHO_TITLE_CHARS = 60
UNDER_REPORTED_MAX_FEEDS = 2
EPSS_JUMP_WINDOW_DAYS = 7
CRITICAL_CVSS_MAX_AGE_DAYS = 90
RESEARCH_MIN_WORDS = 1500


@dataclass
class SignalHit:
    signal_type: str
    score: float  # raw strength 0..1
    explanation: str
    payload: dict = field(default_factory=dict)


def idf_weight(rate: float) -> float:
    """Weight a signal by rarity: 5% firing rate → 1.0; clamped to [0.1, 3.0]."""
    return max(0.1, min(3.0, math.log(1.0 / max(rate, 0.001)) / math.log(1.0 / 0.05)))


def compute_priority_score(
    hits: list[SignalHit],
    rates: dict[str, float] | None = None,
    multipliers: dict[str, float] | None = None,
) -> float:
    rates = {**DEFAULT_FIRING_RATES, **(rates or {})}
    multipliers = {**DEFAULT_FAMILY_MULTIPLIERS, **(multipliers or {})}
    total = 0.0
    for hit in hits:
        family = SIGNAL_FAMILIES.get(hit.signal_type, "interest")
        mult = multipliers.get(family, 1.0)
        if hit.signal_type == "feed_echo":
            total += hit.score * ECHO_WEIGHT * mult
        else:
            total += hit.score * idf_weight(rates.get(hit.signal_type, 0.05)) * mult
    return round(total, 4)


def attribute_feedback_votes(
    feedback_rows: list[tuple],
    rates: dict[str, float],
) -> dict[str, list[int]]:
    """Attribute each Radar thumb to the family of the entry's top-contributing signal.

    feedback_rows: (feedback_id, verdict, signal_type, score) — one row per
    signal on the voted entry. A vote counts only toward the signal that
    contributed most to the score (score × IDF weight, echo excluded):
    smearing it across every family present let one noisy signal poison the
    families it happened to co-fire with.
    """
    merged = {**DEFAULT_FIRING_RATES, **rates}
    best: dict = {}  # feedback_id -> (contribution, signal_type, verdict)
    for fb_id, verdict, signal_type, score in feedback_rows:
        if signal_type == "feed_echo":
            continue
        contribution = (score or 0) * idf_weight(merged.get(signal_type, 0.05))
        cur = best.get(fb_id)
        if cur is None or contribution > cur[0]:
            best[fb_id] = (contribution, signal_type, verdict)
    family_votes: dict[str, list[int]] = {}
    for _, signal_type, verdict in best.values():
        family = SIGNAL_FAMILIES.get(signal_type)
        if family:
            family_votes.setdefault(family, []).append(verdict)
    return family_votes


# ── Per-user learned weights (Radar personalisation) ───────────────
#
# The global feedback nudge above pools every analyst's thumbs into one set of
# multipliers that is baked into the stored Entry.priority_score. These helpers
# are the per-analyst counterpart: a weight fitted from one user's own verdicts,
# applied as a read-time lift on the Radar ordering (see
# app/services/radar_personalization.py). Nothing here touches stored scores.

# Full-confidence swing of a personal weight. Wider than the global ±10% nudge
# because it only reorders one analyst's queue and is reversible with one click.
PERSONAL_WEIGHT_SPAN = 0.35
PERSONAL_WEIGHT_MIN = 1.0 - PERSONAL_WEIGHT_SPAN
PERSONAL_WEIGHT_MAX = 1.0 + PERSONAL_WEIGHT_SPAN
# Shrinkage constant: a family reaches half its full swing at K votes. Keeps
# three enthusiastic thumbs from moving a family as far as thirty do.
PERSONAL_SHRINKAGE_K = 8


def fit_personal_weight(votes: list[int], shrinkage_k: int = PERSONAL_SHRINKAGE_K) -> float:
    """Fit one family's personal multiplier from a user's ±1 verdicts.

    weight = 1 + SPAN x mean(votes) x n/(n+k) — the shrinkage term pulls small
    samples back toward neutral instead of letting them saturate the bound.
    """
    if not votes:
        return 1.0
    n = len(votes)
    mean = sum(votes) / n
    raw = 1.0 + PERSONAL_WEIGHT_SPAN * mean * (n / (n + shrinkage_k))
    return round(max(PERSONAL_WEIGHT_MIN, min(PERSONAL_WEIGHT_MAX, raw)), 4)


def personal_signal_coefficients(
    weights: dict[str, float],
    rates: dict[str, float] | None = None,
) -> dict[str, float]:
    """signal_type -> per-unit-score delta for a user's non-neutral families.

    Mirrors compute_priority_score exactly: a stored signal contributes
    ``score x idf_weight x multiplier`` to the global score, so re-weighting it
    for one user is ``score x idf_weight x (w - 1)``. Summing that over an
    entry's signals reproduces the score the engine would have produced with
    this user's multipliers, without re-scoring anything. Families sitting at
    1.0 are omitted so the SQL CASE stays as small as the user's actual
    divergence from the global weights.
    """
    merged = {**DEFAULT_FIRING_RATES, **(rates or {})}
    coeffs: dict[str, float] = {}
    for signal_type, family in SIGNAL_FAMILIES.items():
        delta = weights.get(family, 1.0) - 1.0
        if abs(delta) < 1e-6:
            continue
        base = ECHO_WEIGHT if signal_type == "feed_echo" else idf_weight(merged.get(signal_type, 0.05))
        coeffs[signal_type] = round(base * delta, 6)
    return coeffs


async def _thread_signals_enabled(db: AsyncSession) -> bool:
    """Whether story-thread membership may answer the coverage signals.

    DB-override-aware rather than ``settings.get`` — scoring runs in a worker
    that does not warm the settings cache, and an unwarmed read silently
    returns the env default.
    """
    from app.services.system_settings import get_setting

    try:
        return bool(await get_setting("thread_signals_enabled", db))
    except Exception:
        logger.warning("thread_signals_enabled lookup failed; using entity probes", exc_info=True)
        return False


async def get_signal_rates() -> dict[str, float]:
    try:
        r = await get_redis()
        raw = await r.get(RATES_REDIS_KEY)
        if raw:
            return {**DEFAULT_FIRING_RATES, **json.loads(raw)}
    except Exception:
        logger.debug("Failed to read signal rates from redis, using defaults", exc_info=True)
    return dict(DEFAULT_FIRING_RATES)


async def get_family_multipliers() -> dict[str, float]:
    try:
        r = await get_redis()
        raw = await r.get(MULTIPLIERS_REDIS_KEY)
        if raw:
            return {**DEFAULT_FAMILY_MULTIPLIERS, **json.loads(raw)}
    except Exception:
        logger.debug("Failed to read family multipliers from redis, using defaults", exc_info=True)
    return dict(DEFAULT_FAMILY_MULTIPLIERS)


async def get_feedback_nudges() -> dict[str, float]:
    """Per-family multiplier nudge from Radar feedback (0.9–1.1); applied on top of user multipliers."""
    try:
        r = await get_redis()
        raw = await r.get(FEEDBACK_NUDGE_REDIS_KEY)
        if raw:
            return {k: max(0.9, min(1.1, float(v))) for k, v in json.loads(raw).items()}
    except Exception:
        logger.debug("Failed to read feedback nudges from redis", exc_info=True)
    return {}


async def get_radar_threshold() -> tuple[float, bool]:
    """(threshold, is_auto) — manual override beats the auto p95 from the rates job."""
    try:
        r = await get_redis()
        override = await r.get(THRESHOLD_OVERRIDE_REDIS_KEY)
        if override is not None:
            return float(override), False
        auto = await r.get(THRESHOLD_REDIS_KEY)
        if auto is not None:
            return float(auto), True
    except Exception:
        logger.debug("Failed to read radar threshold from redis, using default", exc_info=True)
    return DEFAULT_RADAR_THRESHOLD, True


# ── Entity link collection ─────────────────────────────────────────


@dataclass
class _EntityLinks:
    actors: list  # ThreatActor rows
    malware: list  # MalwareFamily rows
    tools: list  # Tool rows
    cves: list  # CVE rows
    ttp_count: int
    country_count: int


async def _collect_links(db: AsyncSession, entry_id: uuid.UUID) -> _EntityLinks:
    actor_ids = (
        (await db.execute(select(EntryThreatActor.threat_actor_id).where(EntryThreatActor.entry_id == entry_id)))
        .scalars()
        .all()
    )
    malware_ids = (
        (await db.execute(select(EntryMalware.malware_family_id).where(EntryMalware.entry_id == entry_id)))
        .scalars()
        .all()
    )
    tool_ids = (await db.execute(select(EntryTool.tool_id).where(EntryTool.entry_id == entry_id))).scalars().all()
    cve_ids = (await db.execute(select(EntryCVE.cve_id).where(EntryCVE.entry_id == entry_id))).scalars().all()
    ttp_count = (
        await db.execute(select(func.count()).select_from(EntryTTP).where(EntryTTP.entry_id == entry_id))
    ).scalar_one()
    country_count = (
        await db.execute(select(func.count()).select_from(EntryCountry).where(EntryCountry.entry_id == entry_id))
    ).scalar_one()

    actors = (
        (await db.execute(select(ThreatActor).where(ThreatActor.id.in_(actor_ids)))).scalars().all()
        if actor_ids
        else []
    )
    malware = (
        (await db.execute(select(MalwareFamily).where(MalwareFamily.id.in_(malware_ids)))).scalars().all()
        if malware_ids
        else []
    )
    tools = (await db.execute(select(Tool).where(Tool.id.in_(tool_ids)))).scalars().all() if tool_ids else []
    cves = (await db.execute(select(CVE).where(CVE.id.in_(cve_ids)).limit(100))).scalars().all() if cve_ids else []
    return _EntityLinks(
        actors=actors,
        malware=malware,
        tools=tools,
        cves=cves,
        ttp_count=ttp_count,
        country_count=country_count,
    )


# ── Individual signals ─────────────────────────────────────────────


async def _novel_entity(db: AsyncSession, entry: Entry, links: _EntityLinks, anchor: datetime) -> SignalHit | None:
    """First/early coverage, measured against articles published before this entry.

    Deliberately NOT the entity's current article_count: that grows after
    scoring, so a re-score (or backfill) would strip the badge from the
    genuinely-first entry once the entity becomes established. Prior-count
    queries are anchored on this entry's publish time and never change.
    """
    recent_cutoff = anchor - timedelta(days=NOVEL_FIRST_SEEN_DAYS)
    prior_counts: dict = {}
    for junction, id_col, rows in (
        (EntryThreatActor, EntryThreatActor.threat_actor_id, links.actors),
        (EntryMalware, EntryMalware.malware_family_id, links.malware),
        (EntryTool, EntryTool.tool_id, links.tools),
    ):
        ids = [r.id for r in rows]
        if not ids:
            continue
        counted = (
            await db.execute(
                select(id_col, func.count())
                .select_from(junction)
                .join(Entry, Entry.id == junction.entry_id)
                .where(id_col.in_(ids), junction.entry_id != entry.id, Entry.published_at < anchor)
                .group_by(id_col)
            )
        ).all()
        prior_counts.update(dict(counted))
    novel: list[tuple[str, str, int]] = []  # (type_label, name, prior_articles)
    for label, rows in (("threat actor", links.actors), ("malware", links.malware), ("tool", links.tools)):
        for row in rows:
            prior = prior_counts.get(row.id, 0)
            first_seen = row.first_seen_at
            if prior < NOVEL_ARTICLE_COUNT or (first_seen and first_seen >= recent_cutoff):
                novel.append((label, row.name, prior))
    for row in links.cves:
        # CVEs have no article_count — first_seen recency is the only novelty criterion
        if row.first_seen_at and row.first_seen_at >= recent_cutoff:
            novel.append(("CVE", row.cve_id, 0))
    if not novel:
        return None
    novel.sort(key=lambda n: n[2])
    label, name, prior = novel[0]
    score = 1.0 if prior == 0 else 0.7
    if prior == 0:
        explanation = f"First mention of {label} '{name}'"
    else:
        explanation = f"Early coverage of {label} '{name}' ({prior} prior article{'s' if prior != 1 else ''})"
    if len(novel) > 1:
        explanation += f" (+{len(novel) - 1} more new entities)"
    return SignalHit(
        "novel_entity",
        score,
        explanation,
        {"entities": [{"type": t, "name": n, "prior_articles": p} for t, n, p in novel[:5]]},
    )


async def _entity_resurgence(db: AsyncSession, entry: Entry, links: _EntityLinks, anchor: datetime) -> SignalHit | None:
    cutoff = anchor - timedelta(days=RESURGENCE_DAYS)
    candidates = [
        ("threat actor", EntryThreatActor, EntryThreatActor.threat_actor_id, links.actors),
        ("malware", EntryMalware, EntryMalware.malware_family_id, links.malware),
        ("tool", EntryTool, EntryTool.tool_id, links.tools),
    ]
    checked = 0
    for label, junction, id_col, rows in candidates:
        for row in rows:
            if (row.article_count or 0) <= NOVEL_ARTICLE_COUNT:
                continue  # novelty covers these
            if checked >= 10:
                return None
            checked += 1
            prior_max = (
                await db.execute(
                    select(func.max(Entry.published_at))
                    .select_from(junction)
                    .join(Entry, Entry.id == junction.entry_id)
                    .where(
                        id_col == row.id,
                        junction.entry_id != entry.id,
                        Entry.published_at < anchor,
                    )
                )
            ).scalar_one_or_none()
            if prior_max and prior_max < cutoff:
                gap_days = (anchor - prior_max).days
                return SignalHit(
                    "entity_resurgence",
                    min(1.0, gap_days / 365),
                    f"{label.capitalize()} '{row.name}' resurfaced after {gap_days} days of silence",
                    {"entity_type": label, "name": row.name, "gap_days": gap_days},
                )
    return None


async def _new_pairing(db: AsyncSession, entry_id: uuid.UUID) -> SignalHit | None:
    interesting_pairs = {
        frozenset({"threat_actor", "malware"}),
        frozenset({"threat_actor", "country"}),
        frozenset({"malware", "cve"}),
        frozenset({"threat_actor", "tool"}),
    }
    # Evidence is append-ordered, so first element == founding entry. Stable
    # under re-score/backfill, unlike the old created-within-the-hour check,
    # which erased the signal on every rescore sweep.
    #
    # Trust gate: only surface a pairing once it has climbed the relationship
    # trust ladder to probable/confirmed. A brand-new edge is born "possible"
    # (a single co-mention) — surfacing those made the signal fire on every
    # coincidental co-mention (e.g. an actor and a bystander country named in
    # the same grab-bag paragraph). Requiring probable+ means the pairing was
    # corroborated by evidence volume/feeds or promoted by the adjudicator;
    # `is_distinct_from("coincidental")` also excludes edges the adjudicator
    # explicitly ruled noise (defensive — those are demoted to possible too).
    rows = (
        (
            await db.execute(
                select(EntityRelationship).where(
                    EntityRelationship.source == "co_occurrence",
                    EntityRelationship.evidence_entry_ids[1] == entry_id,
                    EntityRelationship.confidence.in_(("probable", "confirmed")),
                    EntityRelationship.adjudication_verdict.is_distinct_from("coincidental"),
                )
            )
        )
        .scalars()
        .all()
    )
    pairings = [r for r in rows if frozenset({r.source_type, r.target_type}) in interesting_pairs]
    if not pairings:
        return None
    rel = pairings[0]
    source_name = await _pairing_endpoint_name(db, rel.source_type, rel.source_id)
    target_name = await _pairing_endpoint_name(db, rel.target_type, rel.target_id)
    return SignalHit(
        "new_pairing",
        min(1.0, 0.6 + 0.2 * (len(pairings) - 1)),
        f"First-ever observed pairing: {source_name} ↔ {target_name} ({rel.relationship_type.replace('_', ' ')})",
        {
            "pairings": [
                {
                    "source_type": r.source_type,
                    "source_id": str(r.source_id),
                    "source_name": await _pairing_endpoint_name(db, r.source_type, r.source_id),
                    "target_type": r.target_type,
                    "target_id": str(r.target_id),
                    "target_name": await _pairing_endpoint_name(db, r.target_type, r.target_id),
                    "relationship_type": r.relationship_type,
                }
                for r in pairings[:5]
            ]
        },
    )


async def _pairing_endpoint_name(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> str:
    """Human-readable label for a relationship endpoint, falling back to the
    bare type name if the entity can't be resolved."""
    from app.intelligence.correlation import _entity_label, get_entity

    try:
        entity = await get_entity(db, entity_type, entity_id)
    except KeyError:
        entity = None
    if entity is None:
        return entity_type.replace("_", " ")
    return _entity_label(entity_type, entity)


def _probe_entity_ids(links: _EntityLinks) -> tuple[list, list, list, list]:
    """Entity ids for the echo/convergence probes, excluding mega-entities.

    Name-twins are collapsed across type (actor wins over malware over tool):
    the Qilin RaaS *group* and the Qilin ransomware *payload* model one real
    subject, so counting both would let a single subject satisfy the
    >=2-shared-entities convergence bar on its own. Dropping the twin from the
    probe union also caps the candidate-side shared count, not just the anchor's.
    """
    seen_names: set[str] = set()
    actor_ids, malware_ids, tool_ids = [], [], []
    for entities, out in ((links.actors, actor_ids), (links.malware, malware_ids), (links.tools, tool_ids)):
        for e in entities:
            if (e.article_count or 0) > MEGA_ENTITY_ARTICLE_COUNT:
                continue
            name = (getattr(e, "name", None) or "").strip().lower()
            if name and name in seen_names:
                continue  # twin of a higher-priority-type entity already counted
            if name:
                seen_names.add(name)
            out.append(e.id)
    cve_ids = [c.id for c in links.cves]
    return actor_ids, malware_ids, tool_ids, cve_ids


def _source_key(url: str | None, feed_id) -> str:
    """Host of the article URL (feed id fallback) as the independent-source unit.

    Counting feed_ids let multi-feed outlets and aggregator rebroadcasts of the
    same site inflate "independent sources".
    """
    if url:
        try:
            host = urlparse(url).netloc.lower().split(":")[0].removeprefix("www.")
            if host:
                return host
        except ValueError:
            pass
    return f"feed:{feed_id}"


def _overlap_union_select(actor_ids: list, malware_ids: list, tool_ids: list, cve_ids: list):
    parts = []
    if actor_ids:
        parts.append(
            select(EntryThreatActor.entry_id.label("entry_id")).where(EntryThreatActor.threat_actor_id.in_(actor_ids))
        )
    if malware_ids:
        parts.append(
            select(EntryMalware.entry_id.label("entry_id")).where(EntryMalware.malware_family_id.in_(malware_ids))
        )
    if tool_ids:
        parts.append(select(EntryTool.entry_id.label("entry_id")).where(EntryTool.tool_id.in_(tool_ids)))
    if cve_ids:
        parts.append(select(EntryCVE.entry_id.label("entry_id")).where(EntryCVE.cve_id.in_(cve_ids)))
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0].subquery()
    return union_all(*parts).subquery()


async def _feed_echo(
    db: AsyncSession, entry: Entry, links: _EntityLinks, anchor: datetime
) -> tuple[SignalHit | None, int]:
    """Returns (echo hit or None, distinct source-domain count sharing >=2 entities in 24h).

    Both echo and source_convergence read the same junction-union probe, so
    they're computed together.
    """
    actor_ids, malware_ids, tool_ids, cve_ids = _probe_entity_ids(links)
    n_entities = len(actor_ids) + len(malware_ids) + len(tool_ids) + len(cve_ids)
    if n_entities == 0:
        return None, 0

    union_sq = _overlap_union_select(actor_ids, malware_ids, tool_ids, cve_ids)
    echo_cutoff = anchor - timedelta(hours=ECHO_WINDOW_HOURS)

    overlaps = (
        await db.execute(
            select(Entry.id, Entry.feed_id, Entry.url, Entry.published_at, func.count().label("shared"))
            .select_from(union_sq)
            .join(Entry, Entry.id == union_sq.c.entry_id)
            .where(Entry.id != entry.id, Entry.published_at >= echo_cutoff)
            .group_by(Entry.id, Entry.feed_id, Entry.url, Entry.published_at)
            .having(func.count() >= 2)
            .order_by(func.count().desc())
            .limit(50)
        )
    ).all()

    convergence_cutoff_lo = anchor - timedelta(hours=CONVERGENCE_WINDOW_HOURS)
    convergence_sources = {
        _source_key(row.url, row.feed_id)
        for row in overlaps
        if row.published_at and row.published_at >= convergence_cutoff_lo
    }
    convergence_sources.add(_source_key(entry.url, entry.feed_id))

    echo_hit = None
    if n_entities >= ECHO_MIN_ENTITIES:
        earlier = [
            row
            for row in overlaps
            if row.published_at and row.published_at < anchor and row.shared / n_entities >= ECHO_MIN_RATIO
        ]
        if earlier:
            best = earlier[0]
            ratio = round(best.shared / n_entities, 2)
            echo_hit = SignalHit(
                "feed_echo",
                min(1.0, ratio),
                f"Echoes earlier coverage ({best.shared}/{n_entities} shared entities)",
                {"duplicate_of": str(best.id), "shared": best.shared, "total": n_entities, "ratio": ratio},
            )
    return echo_hit, len(convergence_sources)


async def _thread_coverage(db: AsyncSession, entry_id: uuid.UUID) -> dict | None:
    """The story thread this entry belongs to, if the sweeper has placed it.

    ``feed_echo`` and ``source_convergence`` are both approximations of a
    question story threads answer directly: is this the same story as something
    we already have, and how many outlets carried it? The entity-overlap probe
    below had to infer it from shared extracted entities inside a 72-hour
    window — which misses every re-report of a story with nothing extractable
    in it, and fires on two genuinely different stories that happen to share an
    actor and a CVE. A thread membership is a decision made against the whole
    story, with the article's own vector, so where one exists it wins.

    Empty at ingest, always: threading runs up to 30 minutes behind scoring.
    The verdict lands on the rescore that ``rescore_entries_for_threads``
    dispatches once the sweeper has placed the article.
    """
    row = (
        (
            await db.execute(
                select(
                    StoryThreadEntry.role,
                    StoryThreadEntry.duplicate_of_entry_id,
                    StoryThread.id.label("thread_id"),
                    StoryThread.slug,
                    StoryThread.title,
                    StoryThread.source_count,
                    StoryThread.entry_count,
                )
                .join(StoryThread, StoryThread.id == StoryThreadEntry.thread_id)
                .where(StoryThreadEntry.entry_id == entry_id)
            )
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def _thread_echo_hit(thread: dict) -> SignalHit:
    """This article re-reports a story the platform already holds."""
    outlets = int(thread.get("source_count") or 0)
    title = (thread.get("title") or "").strip()
    if len(title) > ECHO_TITLE_CHARS:
        title = title[: ECHO_TITLE_CHARS - 1].rstrip() + "…"
    dup = thread.get("duplicate_of_entry_id")
    return SignalHit(
        "feed_echo",
        1.0,
        f'Re-reports "{title}" — {outlets} outlets on that story',
        {
            "duplicate_of": str(dup) if dup else None,
            "thread_id": str(thread["thread_id"]),
            "thread_slug": thread.get("slug"),
            "source": "story_thread",
        },
    )


def _thread_convergence_hit(thread: dict) -> SignalHit:
    """Independent outlets carrying the story this article belongs to."""
    outlets = int(thread.get("source_count") or 0)
    return SignalHit(
        "source_convergence",
        min(1.0, outlets / 6),
        f"{outlets} independent outlets are covering this story",
        {
            "source_count": outlets,
            "thread_id": str(thread["thread_id"]),
            "thread_slug": thread.get("slug"),
            "article_count": int(thread.get("entry_count") or 0),
            "source": "story_thread",
        },
    )


def _severity_signals(links: _EntityLinks, anchor: datetime) -> list[SignalHit]:
    hits: list[SignalHit] = []
    if not links.cves:
        return hits
    # Anchored to the entry, not wall-clock: KEV addition within a week either
    # side of publication (rescores triggered by a later KEV add still fire).
    kev_recent = [
        c for c in links.cves if c.is_kev and c.kev_date_added and abs((anchor.date() - c.kev_date_added).days) <= 7
    ]
    if kev_recent:
        hits.append(
            SignalHit(
                "kev_added",
                1.0,
                f"{kev_recent[0].cve_id} added to CISA KEV this week",
                {"cve_ids": [c.cve_id for c in kev_recent[:5]]},
            )
        )
    poc = [c for c in links.cves if (c.github_poc_count or 0) > 0 and c.exploit_availability in ("weaponized", "poc")]
    if poc:
        worst = max(poc, key=lambda c: c.github_poc_count or 0)
        hits.append(
            SignalHit(
                "weaponized_poc",
                0.8,
                f"Public exploit code available for {worst.cve_id} ({worst.github_poc_count} repos)",
                {"cve_ids": [c.cve_id for c in poc[:5]]},
            )
        )
    jumped = [
        c
        for c in links.cves
        if c.epss_previous_score is not None
        and (c.epss_score or 0) > c.epss_previous_score
        and c.epss_changed_at
        and abs((anchor - c.epss_changed_at).total_seconds()) <= EPSS_JUMP_WINDOW_DAYS * 86400
    ]
    if jumped:
        worst = max(jumped, key=lambda c: (c.epss_score or 0) - (c.epss_previous_score or 0))
        hits.append(
            SignalHit(
                "epss_jump",
                0.9,
                f"{worst.cve_id} EPSS exploitation probability jumped from "
                f"{round((worst.epss_previous_score or 0) * 100)}% to {round((worst.epss_score or 0) * 100)}%",
                {
                    "cve_ids": [c.cve_id for c in jumped[:5]],
                    "from_score": worst.epss_previous_score,
                    "to_score": worst.epss_score,
                },
            )
        )
    high_pct = [c for c in links.cves if (c.epss_percentile or 0) >= 0.95]
    if high_pct:
        worst = max(high_pct, key=lambda c: c.epss_percentile or 0)
        hits.append(
            SignalHit(
                "epss_high",
                0.8,
                f"{worst.cve_id} in the top {max(1, round((1 - (worst.epss_percentile or 0)) * 100))}% "
                "of EPSS exploitation probability",
                {"cve_ids": [c.cve_id for c in high_pct[:5]]},
            )
        )
    # Recency-gated: a passing mention of an old critical CVE (Log4Shell in a
    # retrospective) shouldn't carry a severity boost forever.
    critical = [
        c
        for c in links.cves
        if (c.cvss_score or 0) >= 9
        and c.first_seen_at
        and (anchor - c.first_seen_at).days <= CRITICAL_CVSS_MAX_AGE_DAYS
    ]
    if critical:
        worst = max(critical, key=lambda c: float(c.cvss_score or 0))
        hits.append(
            SignalHit(
                "critical_cvss",
                0.6,
                f"{worst.cve_id} is CVSS {worst.cvss_score}",
                {"cve_ids": [c.cve_id for c in critical[:5]]},
            )
        )
    return hits


async def _under_reported(db: AsyncSession, links: _EntityLinks) -> SignalHit | None:
    """Severe CVE that few sources have ever covered.

    Counted per CVE via the EntryCVE junction — NOT via the entry-overlap
    convergence probe, which requires >=2 shared entities and so misses
    articles that cover only the CVE. All-time count: a CVE heavily covered
    last month isn't under-reported just because this week is quiet.
    """
    severe = [
        c
        for c in links.cves
        if c.is_kev
        or (c.cvss_score or 0) >= 9
        or (c.epss_score or 0) >= 0.5
        or c.exploit_availability in ("weaponized", "active_exploitation")
    ]
    if not severe:
        return None
    counts = dict(
        (
            await db.execute(
                select(EntryCVE.cve_id, func.count(func.distinct(Entry.feed_id)))
                .join(Entry, Entry.id == EntryCVE.entry_id)
                .where(EntryCVE.cve_id.in_([c.id for c in severe]))
                .group_by(EntryCVE.cve_id)
            )
        ).all()
    )
    # The scored entry's own EntryCVE rows exist by now, so every severe CVE
    # has at least this entry's feed counted.
    worst = min(severe, key=lambda c: counts.get(c.id, 1))
    feeds_covering = counts.get(worst.id, 1)
    if feeds_covering > UNDER_REPORTED_MAX_FEEDS:
        return None
    marker = (
        "KEV-listed"
        if worst.is_kev
        else (f"CVSS {worst.cvss_score}" if (worst.cvss_score or 0) >= 9 else "high exploitation probability")
    )
    source_word = "source" if feeds_covering == 1 else "sources"
    return SignalHit(
        "under_reported",
        1.0,
        f"{worst.cve_id} is {marker} but only {feeds_covering} {source_word} covering it",
        {"cve_ids": [c.cve_id for c in severe[:5]], "feeds_covering": feeds_covering},
    )


async def _interest_signals(db: AsyncSession, entry_id: uuid.UUID) -> list[SignalHit]:
    hits: list[SignalHit] = []
    pir_titles = (
        (
            await db.execute(
                select(IntelligenceRequirement.title)
                .join(RequirementMatch, RequirementMatch.requirement_id == IntelligenceRequirement.id)
                .where(RequirementMatch.entry_id == entry_id)
                .order_by(IntelligenceRequirement.title)
            )
        )
        .scalars()
        .all()
    )
    pir_count = len(pir_titles)
    if pir_count:
        shown = ", ".join(f"'{t}'" for t in pir_titles[:2])
        if pir_count > 2:
            shown += f" (+{pir_count - 2} more)"
        hits.append(
            SignalHit(
                "pir_match",
                min(1.0, pir_count / 3),
                f"Matches intelligence requirement{'s' if pir_count != 1 else ''}: {shown}",
                {"count": pir_count, "titles": list(pir_titles[:5])},
            )
        )
    events = (
        await db.execute(
            select(
                CorrelationEventRecord.severity,
                CorrelationEventRecord.source_entity_label,
                CorrelationEventRecord.related_entity_label,
            ).where(CorrelationEventRecord.entry_id == entry_id)
        )
    ).all()
    if events:
        total = len(events)
        severities = {e.severity for e in events}
        top = "high" if "high" in severities else ("medium" if "medium" in severities else "low")
        score = {"high": 1.0, "medium": 0.6, "low": 0.3}[top]
        # Name a representative pairing, preferring one at the top severity.
        rep = next((e for e in events if e.severity == top), events[0])
        detail = f"{rep.source_entity_label} ↔ {rep.related_entity_label}"
        if total > 1:
            explanation = f"Correlation: {detail} (+{total - 1} more, max severity {top})"
        else:
            explanation = f"Correlation: {detail} (severity {top})"
        hits.append(
            SignalHit(
                "correlation_event",
                score,
                explanation,
                {"count": total, "max_severity": top},
            )
        )
    return hits


async def _content_signals(db: AsyncSession, entry: Entry, links: _EntityLinks) -> list[SignalHit]:
    hits: list[SignalHit] = []
    rule_count = (
        await db.execute(select(func.count()).select_from(DetectionRule).where(DetectionRule.entry_id == entry.id))
    ).scalar_one()
    if rule_count:
        hits.append(
            SignalHit(
                "detection_content",
                0.8,
                f"Contains {rule_count} detection rule{'s' if rule_count != 1 else ''}",
                {"rule_count": rule_count},
            )
        )
    if (entry.word_count or 0) >= RESEARCH_MIN_WORDS and (links.ttp_count >= 3 or rule_count):
        hits.append(
            SignalHit(
                "research_depth",
                0.6,
                f"Long-form analysis ({entry.word_count} words, {links.ttp_count} techniques)",
                {"word_count": entry.word_count, "ttp_count": links.ttp_count},
            )
        )
    return hits


# ── Orchestration ──────────────────────────────────────────────────


async def _guarded(probe_name: str, entry_id, coro, fallback):
    """Run one signal probe; on failure log + count and return `fallback`.

    A failing probe omits its signal from the score instead of failing the
    whole scoring task — the metric makes that omission visible.
    """
    from app.core.metrics import SIGNAL_PROBE_FAILURES_TOTAL

    try:
        return await coro
    except Exception:
        logger.warning("Signal probe %s failed for entry %s", probe_name, entry_id, exc_info=True)
        SIGNAL_PROBE_FAILURES_TOTAL.labels(probe=probe_name).inc()
        return fallback


async def compute_entry_signals(db: AsyncSession, entry: Entry) -> list[SignalHit]:
    """Compute all signals for an entry. Entry must have feed relationship loadable."""
    now = datetime.now(UTC)
    # Time-window signals anchor on the entry's own timeline (published, else
    # fetched) so re-scores and backfills reproduce the same facts.
    anchor = entry.published_at or entry.fetched_at or now
    # _collect_links stays unguarded: every probe depends on it, so a partial
    # score without links would be misleading — let the task retry instead.
    links = await _collect_links(db, entry.id)
    hits: list[SignalHit] = []

    novel = await _guarded("novel_entity", entry.id, _novel_entity(db, entry, links, anchor), None)
    if novel:
        hits.append(novel)
    else:
        resurgence = await _guarded("entity_resurgence", entry.id, _entity_resurgence(db, entry, links, anchor), None)
        if resurgence:
            hits.append(resurgence)

    pairing = await _guarded("new_pairing", entry.id, _new_pairing(db, entry.id), None)
    if pairing:
        hits.append(pairing)

    # Coverage signals: the thread verdict where there is one, the entity-overlap
    # probe everywhere else. Both answer the same two questions, and a thread
    # answers them with the whole story rather than a 72-hour entity window.
    thread = None
    if await _thread_signals_enabled(db):
        thread = await _guarded("thread_coverage", entry.id, _thread_coverage(db, entry.id), None)

    echo = None
    if thread:
        if thread["role"] == "echo":
            echo = _thread_echo_hit(thread)
            hits.append(echo)
        elif int(thread["source_count"] or 0) >= CONVERGENCE_MIN_FEEDS:
            hits.append(_thread_convergence_hit(thread))
        # A beat in a thread is not an echo of it — the sweeper compared this
        # article against every member and decided it carried something new.
        # Running the entity probe anyway would overrule that with a worse
        # instrument.
    else:
        echo, convergence_sources = await _guarded(
            "feed_echo", entry.id, _feed_echo(db, entry, links, anchor), (None, 0)
        )
        if echo:
            hits.append(echo)
        elif convergence_sources >= CONVERGENCE_MIN_FEEDS:
            hits.append(
                SignalHit(
                    "source_convergence",
                    min(1.0, convergence_sources / 6),
                    f"Covered by {convergence_sources} independent sources within 24h",
                    {"source_count": convergence_sources},
                )
            )

    hits.extend(_severity_signals(links, anchor))

    under = await _guarded("under_reported", entry.id, _under_reported(db, links), None)
    if under:
        hits.append(under)

    if novel and not echo:
        reliability = getattr(getattr(entry, "feed", None), "reliability_rating", None)
        if reliability in ("A", "B"):
            hits.append(
                SignalHit(
                    "scoop",
                    0.8,
                    f"Original reporting from a reliability-{reliability} source on new entities",
                    {"reliability": reliability},
                )
            )

    hits.extend(await _guarded("interest_signals", entry.id, _interest_signals(db, entry.id), []))
    hits.extend(await _guarded("content_signals", entry.id, _content_signals(db, entry, links), []))

    from app.core.metrics import ENTRY_SIGNALS_FIRED_TOTAL

    for hit in hits:
        ENTRY_SIGNALS_FIRED_TOTAL.labels(signal_type=hit.signal_type).inc()
    return hits
