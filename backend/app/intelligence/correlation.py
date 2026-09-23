"""Intelligence correlation engine — pivot queries, graph building, cross-entity search, timeline."""

import logging
import math
import re
import uuid
from datetime import UTC, datetime, timedelta
from itertools import combinations

from sqlalchemy import String, cast, func, or_, select, type_coerce
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.cve import risk_tier_for
from app.intelligence.relationship_matrix import hidden_relationship_confidences, is_allowed_relationship
from app.models.campaign import Campaign
from app.models.country import Country, EntryCountry
from app.models.cve import CVE, EntryCVE
from app.models.cwe import CWE, EntryCWE
from app.models.detection_rule import DetectionRule
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.intel_report import IntelReport
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.mitigation import EntryMitigation, Mitigation
from app.models.observable import EntryObservable, Observable
from app.models.product import EntryProduct, Product
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.models.vendor import EntryVendor, Vendor
from app.search.note_results import fetch_notes, text_conditions

logger = logging.getLogger(__name__)


def _aliases_match_bounded(model, query: str):
    """Word-boundary-aware SQL match against an entity's aliases array.

    Prevents short aliases like 'fox' from matching mid-word inside another
    alias such as 'firefox'. Uses Postgres POSIX regex with \\y boundaries.
    """
    pattern = rf"\y{re.escape(query)}\y"
    return func.array_to_string(model.aliases, " ").op("~*")(pattern)


def _alias_contains_bounded(aliases: list[str] | None, query_lower: str) -> bool:
    """Python-side word-boundary alias match used for match_field labeling."""
    if not aliases:
        return False
    pattern = re.compile(rf"\b{re.escape(query_lower)}\b", re.IGNORECASE)
    return any(pattern.search(a or "") for a in aliases)


# Maps entity_type string to (Model, JunctionModel, junction_fk_column)
ENTITY_CONFIG = {
    "ttp": (TTP, EntryTTP, EntryTTP.ttp_id),
    "cve": (CVE, EntryCVE, EntryCVE.cve_id),
    "cwe": (CWE, EntryCWE, EntryCWE.cwe_id),
    "threat_actor": (ThreatActor, EntryThreatActor, EntryThreatActor.threat_actor_id),
    "malware": (MalwareFamily, EntryMalware, EntryMalware.malware_family_id),
    "country": (Country, EntryCountry, EntryCountry.country_id),
    "mitigation": (Mitigation, EntryMitigation, EntryMitigation.mitigation_id),
    "tool": (Tool, EntryTool, EntryTool.tool_id),
    "vendor": (Vendor, EntryVendor, EntryVendor.vendor_id),
    "product": (Product, EntryProduct, EntryProduct.product_id),
    "observable": (Observable, EntryObservable, EntryObservable.observable_id),
}

VALID_ENTITY_TYPES = set(ENTITY_CONFIG.keys())

# A campaign can be pivoted FROM but never appears as a related type: it is a
# curated membership list, not something extracted from an article. Everything
# a pivot needs from its source is the entity row and a seed set of entries,
# and a campaign has both — its entries are simply chosen rather than matched.
# Kept out of VALID_ENTITY_TYPES because that set also gates false-positive
# reporting and entity export, neither of which means anything for a campaign.
PIVOT_SOURCE_TYPES = VALID_ENTITY_TYPES | {"campaign"}


def entry_scope_junction(entity_type: str) -> tuple[type, object] | None:
    """(junction model, entity-id column) answering "which entries are this entity's".

    One place to ask, because every surface that scopes articles to an entity —
    the pulse line, the whats-new strip, the atlas buckets — needs the same
    answer, and a campaign's is its membership table rather than an extraction
    junction. Returns None for a type that owns no entries at all.
    """
    if entity_type == "campaign":
        from app.models.campaign import CampaignEntry

        return CampaignEntry, CampaignEntry.campaign_id
    config = ENTITY_CONFIG.get(entity_type)
    if not config:
        return None
    _, junction, fk_col = config
    return junction, fk_col


def _entity_label(entity_type: str, entity) -> str:
    """Return a human-readable label for an entity."""
    if entity_type == "ttp":
        return f"{entity.technique_id} {entity.technique_name}"
    if entity_type == "cve":
        return entity.cve_id
    if entity_type == "cwe":
        return f"{entity.cwe_id} {entity.name}"
    if entity_type == "observable":
        return entity.label or entity.value
    if entity_type == "campaign":
        return entity.name
    if entity_type == "threat_actor":
        return entity.name
    if entity_type == "malware":
        return entity.name
    if entity_type == "country":
        return entity.name
    if entity_type == "mitigation":
        return f"{entity.mitre_id} {entity.name}" if entity.mitre_id else entity.name
    if entity_type == "tool":
        return entity.name
    if entity_type == "vendor":
        return entity.name
    if entity_type == "product":
        return entity.name
    return str(entity.id)


async def get_entity(db: AsyncSession, entity_type: str, entity_id: uuid.UUID):
    """Fetch a single entity by type and ID."""
    from sqlalchemy.orm import selectinload

    if entity_type == "campaign":
        from app.models.campaign import Campaign

        result = await db.execute(select(Campaign).where(Campaign.id == entity_id))
        return result.scalar_one_or_none()

    model = ENTITY_CONFIG[entity_type][0]
    q = select(model).where(model.id == entity_id)
    # Eagerly load vendor relationship for products
    if entity_type == "product":
        q = q.options(selectinload(Product.vendor))
    result = await db.execute(q)
    return result.scalar_one_or_none()


async def _get_entry_ids_for_entity(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> list[uuid.UUID]:
    """Get all entry IDs linked to an entity via its junction table."""
    if entity_type == "campaign":
        from app.models.campaign import CampaignEntry

        result = await db.execute(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == entity_id))
        return [row[0] for row in result.all()]

    _, junction, fk_col = ENTITY_CONFIG[entity_type]
    result = await db.execute(select(junction.entry_id).where(fk_col == entity_id))
    return [row[0] for row in result.all()]


def _compute_proximity_score(
    source_indices: list[int] | None,
    target_indices: list[int] | None,
) -> float:
    """Compute proximity score between two entities based on paragraph distances.

    Formula: 1.0 / (1 + decay_rate × min_distance).
    Parameters read from system settings (DB override > env default).
    """
    from app.config import settings as env_settings

    default_score = float(env_settings.get("proximity_default_score") or 0.3)
    decay_rate = float(env_settings.get("proximity_decay_rate") or 1.0)

    if source_indices is None or target_indices is None:
        return default_score
    if not source_indices or not target_indices:
        return default_score
    min_dist = min(abs(a - b) for a in source_indices for b in target_indices)
    return 1.0 / (1 + decay_rate * min_dist)


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _reliability_multiplier(rating: str | None) -> float:
    """Evidence weight for a feed's admiralty source-reliability rating.

    A/B feeds count slightly more, D/E slightly less; C, F ("cannot be
    judged") and unrated feeds are neutral. Multipliers are tunable via
    settings — set both to 1.0 to disable reliability weighting.
    """
    from app.config import settings as env_settings

    if rating in ("A", "B"):
        return float(env_settings.get("relationship_reliability_high_multiplier") or 1.15)
    if rating in ("D", "E"):
        return float(env_settings.get("relationship_reliability_low_multiplier") or 0.85)
    return 1.0


def _compute_relationship_strength(
    per_entry_scores: list[float],
    distinct_articles: float,
    last_seen: datetime | None,
) -> tuple[float, float]:
    """Composite relationship strength in [0, 1], plus its closeness component.

    Three separable signals instead of the old unbounded proximity sum:
    - corroboration — log-scaled distinct evidence articles, saturating at
      `relationship_corroboration_saturation` (volume of independent reporting)
    - closeness — mean of the top-3 per-article proximity scores, stays 0–1
      (were they actually discussed together, or both in a roundup?)
    - recency — exponential decay on the newest evidence with
      `relationship_recency_half_life_days` (relationships go stale)

    `distinct_articles` may be a reliability-weighted (fractional) article
    count — evidence from A/B-rated feeds counts slightly more than D/E.
    """
    from app.config import settings as env_settings

    saturation = float(env_settings.get("relationship_corroboration_saturation") or 8)
    half_life = float(env_settings.get("relationship_recency_half_life_days") or 90)
    w_corr = float(env_settings.get("relationship_weight_corroboration") or 0.45)
    w_close = float(env_settings.get("relationship_weight_closeness") or 0.40)
    w_rec = float(env_settings.get("relationship_weight_recency") or 0.15)

    corroboration = 0.0
    if distinct_articles > 0 and saturation > 0:
        corroboration = min(1.0, math.log2(1 + distinct_articles) / math.log2(1 + saturation))

    top = sorted(per_entry_scores, reverse=True)[:3]
    closeness = sum(top) / len(top) if top else 0.0

    recency = 0.0
    if last_seen is not None and half_life > 0:
        age_days = max(0.0, (datetime.now(UTC) - _as_utc(last_seen)).total_seconds() / 86400)
        recency = math.exp(-age_days / half_life)

    return w_corr * corroboration + w_close * closeness + w_rec * recency, closeness


_corpus_count_cache: tuple[float, int] = (0.0, 0)


async def _corpus_entry_count(db: AsyncSession) -> int:
    """Total entries, memoized for 5 minutes per process.

    Feeds the specificity denominator, which barely moves as the corpus
    drifts — an uncached count(*) per pivot would run ~900× per pre-warm
    cycle for the same slowly-changing number.
    """
    import time as _time

    global _corpus_count_cache
    ts, cached = _corpus_count_cache
    now = _time.monotonic()
    if cached and now - ts < 300:
        return cached
    total = (await db.execute(select(func.count(Entry.id)))).scalar() or 0
    _corpus_count_cache = (now, total)
    return total


def _specificity(article_count: int, total_entries: int | None) -> float | None:
    """How special is this entity as a counterpart, in [0, 1]?

    IDF-style: an entity mentioned in a handful of articles scores ~1.0; one
    mentioned across the whole corpus (CrowdStrike, Linux) approaches 0. Used
    to damp relationship strength so ubiquitous entities stop dominating —
    evidence volume with a promiscuous counterpart is reporting noise, not a
    relationship.
    """
    if not total_entries or total_entries < 2:
        return None
    ac = max(1, article_count or 1)
    return max(0.0, min(1.0, math.log(total_entries / ac) / math.log(total_entries)))


def _strength_tier(score: float) -> str:
    """Tier a strength score using the same settings the UI badges read."""
    from app.config import settings as env_settings

    strong = float(env_settings.get("proximity_strong_threshold") or 0.7)
    moderate = float(env_settings.get("proximity_moderate_threshold") or 0.3)
    if score >= strong:
        return "strong"
    if score >= moderate:
        return "moderate"
    return "weak"


def _monthly_trend(dates: list[datetime], buckets: int = 12) -> list[int]:
    """Bucket evidence dates into trailing calendar months (oldest → newest)."""
    counts = [0] * buckets
    now = datetime.now(UTC)
    for d in dates:
        d = _as_utc(d)
        months_ago = (now.year - d.year) * 12 + (now.month - d.month)
        if 0 <= months_ago < buckets:
            counts[buckets - 1 - months_ago] += 1
    return counts


async def _attach_evidence_titles(db: AsyncSession, items: list[dict]) -> None:
    """Bulk-fetch entry titles for the proximity/evidence breakdowns."""
    all_eids: set[str] = set()
    for item in items:
        for pe in item.get("proximity_entries") or []:
            all_eids.add(pe["entry_id"])
    if not all_eids:
        return
    title_result = await db.execute(
        select(Entry.id, Entry.title).where(Entry.id.in_([uuid.UUID(eid) for eid in all_eids]))
    )
    title_map = {str(row[0]): row[1] for row in title_result.all()}
    for item in items:
        for pe in item.get("proximity_entries") or []:
            pe["title"] = title_map.get(pe["entry_id"], "")


async def _get_related_entities(
    db: AsyncSession,
    related_type: str,
    entry_ids: list[uuid.UUID],
    exclude_id: uuid.UUID | None = None,
    source_type: str | None = None,
    source_id: uuid.UUID | None = None,
    entry_meta: dict[uuid.UUID, tuple] | None = None,
    enrich_titles: bool = True,
    feed_reliability: dict[uuid.UUID, str | None] | None = None,
    total_entries: int | None = None,
) -> list[dict]:
    """Get entities of a given type linked to any of the given entry IDs.

    When source_type/source_id are provided, computes a component-based
    relationship strength (corroboration / closeness / recency) between the
    source entity and each related entity; `proximity_score` carries the
    composite so existing badge thresholds stay meaningful. Otherwise falls
    back to co-occurrence count only.

    `entry_meta` maps entry_id → (published_at, feed_id, content_hash); the
    pivot prefetches it once and passes it in (this function runs 9×/pivot).
    `enrich_titles=False` skips evidence-title hydration so callers can
    truncate first and hydrate only survivors.
    `feed_reliability` maps feed_id → admiralty source-reliability rating;
    the pivot prefetches it, otherwise it's fetched here. Evidence is
    weighted by `_reliability_multiplier` so A/B sources count slightly more.
    """
    model, junction, fk_col = ENTITY_CONFIG[related_type]

    # Base query: co-occurrence count
    query = (
        select(model, func.count(junction.entry_id).label("co_occurrence_count"))
        .join(junction, fk_col == model.id)
        .where(junction.entry_id.in_(entry_ids))
        .group_by(model.id)
        .order_by(func.count(junction.entry_id).desc())
    )

    if exclude_id is not None:
        query = query.where(model.id != exclude_id)

    result = await db.execute(query)
    items = []

    # If source info provided, fetch paragraph_indices for proximity scoring
    source_para_map: dict[uuid.UUID, list[int] | None] | None = None
    # A campaign has no paragraph position in an article — its bond to a related
    # entity is membership, not closeness — so it takes the co-occurrence-only
    # path rather than KeyError-ing on a junction it has no row in.
    if source_type in ENTITY_CONFIG and source_id:
        _, src_junction, src_fk_col = ENTITY_CONFIG[source_type]
        src_result = await db.execute(
            select(src_junction.entry_id, src_junction.paragraph_indices)
            .where(src_fk_col == source_id)
            .where(src_junction.entry_id.in_(entry_ids))
        )
        source_para_map = {row[0]: row[1] for row in src_result.all()}

    all_entities = result.all()

    # Batch-fetch all target entities' paragraph_indices in one query (avoids N+1)
    target_para_map: dict[uuid.UUID, list[tuple[uuid.UUID, list[int] | None]]] = {}
    if source_para_map is not None and all_entities:
        all_entity_ids = [entity.id for entity, _count in all_entities]
        tgt_result = await db.execute(
            select(fk_col, junction.entry_id, junction.paragraph_indices)
            .where(fk_col.in_(all_entity_ids))
            .where(junction.entry_id.in_(entry_ids))
        )
        for entity_id_val, tgt_entry_id, tgt_indices in tgt_result.all():
            target_para_map.setdefault(entity_id_val, []).append((tgt_entry_id, tgt_indices))

    # Entry metadata (published_at, feed_id, content_hash) powers the strength
    # components; fetch it here only when the caller didn't prefetch.
    if source_para_map is not None and entry_meta is None and entry_ids:
        meta_result = await db.execute(
            select(Entry.id, Entry.published_at, Entry.feed_id, Entry.content_hash).where(Entry.id.in_(entry_ids))
        )
        entry_meta = {row[0]: (row[1], row[2], row[3]) for row in meta_result.all()}

    # Feed reliability ratings weight the evidence; fetch only when the
    # caller didn't prefetch (the pivot passes it in).
    if source_para_map is not None and feed_reliability is None and entry_meta:
        rel_feed_ids = {meta[1] for meta in entry_meta.values() if meta[1]}
        if rel_feed_ids:
            rel_result = await db.execute(select(Feed.id, Feed.reliability_rating).where(Feed.id.in_(rel_feed_ids)))
            feed_reliability = {row[0]: row[1] for row in rel_result.all()}
    feed_reliability = feed_reliability or {}

    # CVE rows have no article_count column — bulk-count their global entry
    # links so they get real specificity instead of a free 1.0 (which would
    # exempt ubiquitous CVEs from damping and float them above damped types).
    cve_article_counts: dict[uuid.UUID, int] = {}
    if related_type == "cve" and source_para_map is not None and all_entities and total_entries:
        cnt_rows = await db.execute(
            select(EntryCVE.cve_id, func.count(EntryCVE.entry_id))
            .where(EntryCVE.cve_id.in_([e.id for e, _ in all_entities]))
            .group_by(EntryCVE.cve_id)
        )
        cve_article_counts = {row[0]: row[1] for row in cnt_rows.all()}

    for entity, count in all_entities:
        item = _serialize_entity(related_type, entity)
        item["co_occurrence_count"] = count

        if source_para_map is not None:
            per_entry_scores: list[float] = []
            prox_entries = []
            article_weights: dict[str, float] = {}
            feed_ids: set[uuid.UUID] = set()
            dates: list[datetime] = []
            for tgt_entry_id, tgt_indices in target_para_map.get(entity.id, []):
                src_indices = source_para_map.get(tgt_entry_id)
                entry_score = _compute_proximity_score(src_indices, tgt_indices)
                published_at = feed_id = content_hash = None
                meta = (entry_meta or {}).get(tgt_entry_id)
                if meta:
                    published_at, feed_id, content_hash = meta
                # Reliability weighting: closeness sees the weighted per-entry
                # score; corroboration sees a weighted article count (dedup by
                # article, keeping the most reliable copy's weight).
                rel_mult = _reliability_multiplier(feed_reliability.get(feed_id)) if feed_id else 1.0
                per_entry_scores.append(min(1.0, entry_score * rel_mult))
                article_key = content_hash or str(tgt_entry_id)
                article_weights[article_key] = max(article_weights.get(article_key, 0.0), rel_mult)
                if feed_id:
                    feed_ids.add(feed_id)
                if published_at:
                    dates.append(published_at)
                prox_entries.append(
                    {
                        "entry_id": str(tgt_entry_id),
                        "score": round(entry_score, 3),
                        "published_at": _as_utc(published_at).isoformat() if published_at else None,
                    }
                )
            # Sort by score descending and keep top contributors
            prox_entries.sort(key=lambda x: x["score"], reverse=True)

            first_seen = min(dates) if dates else None
            last_seen = max(dates) if dates else None
            score, closeness = _compute_relationship_strength(
                per_entry_scores, sum(article_weights.values()), last_seen
            )
            # Specificity damping: blend the IDF term in by the configured
            # weight so ubiquitous counterparts (reporting vendors, OS names)
            # sink instead of headlining every profile. Explicit None checks —
            # 0 is a valid "off" value that `or` would clobber.
            from app.config import settings as env_settings

            raw_weight = env_settings.get("relationship_specificity_weight")
            spec_weight = 0.5 if raw_weight is None else float(raw_weight)
            article_count = (
                cve_article_counts.get(entity.id, 0)
                if related_type == "cve"
                else getattr(entity, "article_count", 0) or 0
            )
            specificity = _specificity(article_count, total_entries) if spec_weight > 0 else None
            if specificity is not None:
                score *= (1 - spec_weight) + spec_weight * specificity
                # Ubiquitous vendors/products are reporters, not relationships —
                # the UI folds these into a collapsed "reporting sources" group.
                raw_fold = env_settings.get("relationship_reporting_source_specificity")
                fold_threshold = 0.45 if raw_fold is None else float(raw_fold)
                if related_type in ("vendor", "product") and specificity < fold_threshold:
                    item["context_role"] = "reporting_source"
            item["proximity_score"] = round(score, 3)
            item["proximity_entries"] = prox_entries[:20]
            item["strength"] = {
                "score": round(score, 3),
                "tier": _strength_tier(score),
                "closeness": round(closeness, 3),
                "specificity": round(specificity, 3) if specificity is not None else None,
                "articles": len(article_weights),
                "sources": len(feed_ids),
                "first_seen": _as_utc(first_seen).isoformat() if first_seen else None,
                "last_seen": _as_utc(last_seen).isoformat() if last_seen else None,
                "trend": _monthly_trend(dates),
            }
        else:
            item["proximity_score"] = None
            item["proximity_entries"] = None

        items.append(item)

    # Sort by strength when available, fall back to co_occurrence_count order.
    # Tier filtering is the caller's job (pivot applies min_tier + limits; the
    # graph builder applies its own proximity threshold).
    if source_para_map is not None:
        items.sort(key=lambda x: x.get("proximity_score") or 0, reverse=True)

        if enrich_titles:
            await _attach_evidence_titles(db, items)

    return items


def _serialize_entity(entity_type: str, entity) -> dict:
    """Serialize an entity to a dict for API responses."""
    base = {"id": str(entity.id), "type": entity_type}
    if entity_type == "campaign":
        # The profile shell reads first_seen_at/last_seen_at on every type; for a
        # campaign those are the dates the analyst declared, and the article
        # dates it actually holds ride along separately as last_activity_at.
        base.update(
            {
                "name": getattr(entity, "name", None),
                "description": getattr(entity, "description", None),
                "status": getattr(entity, "status", None),
                "tlp_marking": getattr(entity, "tlp_marking", None),
                "tags": getattr(entity, "tags", None) or [],
                "start_date": str(entity.start_date) if getattr(entity, "start_date", None) else None,
                "end_date": str(entity.end_date) if getattr(entity, "end_date", None) else None,
                "first_seen_at": _dt(getattr(entity, "created_at", None)),
                "last_seen_at": _dt(getattr(entity, "updated_at", None)),
                "created_at": _dt(getattr(entity, "created_at", None)),
            }
        )
        return base
    if entity_type == "ttp":
        base.update(
            {
                "technique_id": getattr(entity, "technique_id", None),
                "technique_name": getattr(entity, "technique_name", None),
                "tactic": getattr(entity, "tactic", None),
                "tactics": getattr(entity, "tactics", None) or [],
                "description": getattr(entity, "description", None),
                "platforms": getattr(entity, "platforms", None) or [],
                "data_sources": getattr(entity, "data_sources", None) or [],
                "mitre_url": getattr(entity, "mitre_url", None),
                "detection": getattr(entity, "detection", None),
                "is_subtechnique": getattr(entity, "is_subtechnique", False) or False,
                "parent_technique_id": getattr(entity, "parent_technique_id", None),
                "is_deprecated": getattr(entity, "is_deprecated", False) or False,
                "superseded_by": getattr(entity, "superseded_by", None),
                "matrix_domain": getattr(entity, "matrix_domain", None),
                "article_count": getattr(entity, "article_count", 0),
                "first_seen_at": _dt(getattr(entity, "first_seen_at", None)),
                "last_seen_at": _dt(getattr(entity, "last_seen_at", None)),
                "wikipedia_url": getattr(entity, "wikipedia_url", None),
                "wikipedia_content": getattr(entity, "wikipedia_content", None),
                "wikipedia_image_url": getattr(entity, "wikipedia_image_url", None),
            }
        )
    elif entity_type == "cwe":
        base.update(
            {
                "cwe_id": getattr(entity, "cwe_id", None),
                "name": getattr(entity, "name", None),
                "kind": getattr(entity, "kind", None),
                "abstraction": getattr(entity, "abstraction", None),
                "status": getattr(entity, "status", None),
                "mapping_usage": getattr(entity, "mapping_usage", None),
                "description": getattr(entity, "description", None),
                "parent_cwe_id": getattr(entity, "parent_cwe_id", None),
                "likelihood_of_exploit": getattr(entity, "likelihood_of_exploit", None),
                "alternate_terms": getattr(entity, "alternate_terms", None) or [],
                "capec_ids": getattr(entity, "capec_ids", None) or [],
                "consequences": getattr(entity, "consequences", None) or [],
                "mitigations": getattr(entity, "mitigations", None) or [],
                "detection_methods": getattr(entity, "detection_methods", None) or [],
                "cwe_url": getattr(entity, "cwe_url", None),
                "is_deprecated": getattr(entity, "is_deprecated", False) or False,
                "superseded_by": getattr(entity, "superseded_by", None),
                "article_count": getattr(entity, "article_count", 0),
                "first_seen_at": _dt(getattr(entity, "first_seen_at", None)),
                "last_seen_at": _dt(getattr(entity, "last_seen_at", None)),
                "wikipedia_url": getattr(entity, "wikipedia_url", None),
                "wikipedia_content": getattr(entity, "wikipedia_content", None),
                "wikipedia_image_url": getattr(entity, "wikipedia_image_url", None),
            }
        )
    elif entity_type == "observable":
        base.update(
            {
                "kind": getattr(entity, "kind", None),
                "value": getattr(entity, "value", None),
                "label": getattr(entity, "label", None),
                # The hero renders mono value + name; a label ("AMSI bypass
                # loader") is the only name an observable has.
                "name": getattr(entity, "label", None),
                "role": getattr(entity, "role", None),
                "status": getattr(entity, "status", None),
                "current_confidence": getattr(entity, "current_confidence", None),
                "evidence": getattr(entity, "evidence", None),
                "description": getattr(entity, "description", None),
                "created_via": getattr(entity, "created_via", None),
                "sighting_count": getattr(entity, "sighting_count", 0),
                "article_count": getattr(entity, "article_count", 0),
                "first_seen_at": _dt(getattr(entity, "first_seen_at", None)),
                "last_seen_at": _dt(getattr(entity, "last_seen_at", None)),
            }
        )
    elif entity_type == "cve":
        base.update(
            {
                "cve_id": getattr(entity, "cve_id", None),
                "cvss_score": float(entity.cvss_score) if getattr(entity, "cvss_score", None) else None,
                "severity": getattr(entity, "severity", None),
                "description": getattr(entity, "description", None),
                "epss_score": float(entity.epss_score) if getattr(entity, "epss_score", None) else None,
                "epss_percentile": float(entity.epss_percentile) if getattr(entity, "epss_percentile", None) else None,
                "exploit_availability": getattr(entity, "exploit_availability", None),
                "exploit_status": getattr(entity, "exploit_status", None),
                "exploit_status_source": getattr(entity, "exploit_status_source", None),
                "affected_products": getattr(entity, "affected_products", []) or [],
                "github_poc_count": getattr(entity, "github_poc_count", None),
                "github_poc_urls": getattr(entity, "github_poc_urls", None) or [],
                "metasploit_module": getattr(entity, "metasploit_module", None),
                "is_kev": bool(getattr(entity, "is_kev", False)),
                "kev_date_added": _dt(getattr(entity, "kev_date_added", None)),
                "kev_due_date": _dt(getattr(entity, "kev_due_date", None)),
                "risk_tier": risk_tier_for(entity),
                "first_seen_at": _dt(getattr(entity, "first_seen_at", None)),
                "wikipedia_url": getattr(entity, "wikipedia_url", None),
                "wikipedia_content": getattr(entity, "wikipedia_content", None),
                "wikipedia_image_url": getattr(entity, "wikipedia_image_url", None),
            }
        )
    elif entity_type == "threat_actor":
        base.update(
            {
                "name": getattr(entity, "name", None),
                "aliases": getattr(entity, "aliases", None) or [],
                "country": getattr(entity, "country", None),
                "origin_country_id": str(entity.origin_country_id)
                if getattr(entity, "origin_country_id", None)
                else None,
                "motivation": getattr(entity, "motivation", None),
                "actor_type": getattr(entity, "actor_type", None),
                "mitre_id": getattr(entity, "mitre_id", None),
                "targeted_sectors": getattr(entity, "targeted_sectors", None) or [],
                "description": getattr(entity, "description", None),
                "article_count": getattr(entity, "article_count", 0),
                "first_seen_at": _dt(getattr(entity, "first_seen_at", None)),
                "last_seen_at": _dt(getattr(entity, "last_seen_at", None)),
                "wikipedia_url": getattr(entity, "wikipedia_url", None),
                "wikipedia_content": getattr(entity, "wikipedia_content", None),
                "wikipedia_image_url": getattr(entity, "wikipedia_image_url", None),
            }
        )
    elif entity_type == "malware":
        base.update(
            {
                "name": getattr(entity, "name", None),
                "aliases": getattr(entity, "aliases", None) or [],
                "malware_type": getattr(entity, "malware_type", None),
                "mitre_id": getattr(entity, "mitre_id", None),
                "targeted_sectors": getattr(entity, "targeted_sectors", None) or [],
                "malpedia_url": getattr(entity, "malpedia_url", None),
                "description": getattr(entity, "description", None),
                "article_count": getattr(entity, "article_count", 0),
                "first_seen_at": _dt(getattr(entity, "first_seen_at", None)),
                "last_seen_at": _dt(getattr(entity, "last_seen_at", None)),
                "wikipedia_url": getattr(entity, "wikipedia_url", None),
                "wikipedia_content": getattr(entity, "wikipedia_content", None),
                "wikipedia_image_url": getattr(entity, "wikipedia_image_url", None),
            }
        )
    elif entity_type == "country":
        base.update(
            {
                "name": getattr(entity, "name", None),
                "aliases": getattr(entity, "aliases", None) or [],
                "iso_code": getattr(entity, "iso_code", None),
                "region": getattr(entity, "region", None),
                "description": getattr(entity, "description", None),
                "article_count": getattr(entity, "article_count", 0),
                "first_seen_at": _dt(getattr(entity, "first_seen_at", None)),
                "last_seen_at": _dt(getattr(entity, "last_seen_at", None)),
                "wikipedia_url": getattr(entity, "wikipedia_url", None),
                "wikipedia_content": getattr(entity, "wikipedia_content", None),
                "wikipedia_image_url": getattr(entity, "wikipedia_image_url", None),
            }
        )
    elif entity_type == "tool":
        base.update(
            {
                "name": getattr(entity, "name", None),
                "aliases": getattr(entity, "aliases", None) or [],
                "tool_type": getattr(entity, "tool_type", None),
                "description": getattr(entity, "description", None),
                "platforms": getattr(entity, "platforms", None) or [],
                "malpedia_url": getattr(entity, "malpedia_url", None),
                "github_url": getattr(entity, "github_url", None),
                "article_count": getattr(entity, "article_count", 0),
                "first_seen_at": _dt(getattr(entity, "first_seen_at", None)),
                "last_seen_at": _dt(getattr(entity, "last_seen_at", None)),
                "wikipedia_url": getattr(entity, "wikipedia_url", None),
                "wikipedia_content": getattr(entity, "wikipedia_content", None),
                "wikipedia_image_url": getattr(entity, "wikipedia_image_url", None),
            }
        )
    elif entity_type == "mitigation":
        base.update(
            {
                "name": getattr(entity, "name", None),
                "mitre_id": getattr(entity, "mitre_id", None),
                "mitre_url": getattr(entity, "mitre_url", None),
                "cis_controls": getattr(entity, "cis_controls", None) or [],
                "nist_controls": getattr(entity, "nist_controls", None) or [],
                "description": getattr(entity, "description", None),
                "article_count": getattr(entity, "article_count", 0),
                "wikipedia_url": getattr(entity, "wikipedia_url", None),
                "wikipedia_content": getattr(entity, "wikipedia_content", None),
                "wikipedia_image_url": getattr(entity, "wikipedia_image_url", None),
            }
        )
    elif entity_type == "vendor":
        base.update(
            {
                "name": getattr(entity, "name", None),
                "aliases": getattr(entity, "aliases", None) or [],
                "vendor_type": getattr(entity, "vendor_type", None),
                "website": getattr(entity, "website", None),
                "description": getattr(entity, "description", None),
                "wikipedia_url": getattr(entity, "wikipedia_url", None),
                "wikipedia_content": getattr(entity, "wikipedia_content", None),
                "wikipedia_image_url": getattr(entity, "wikipedia_image_url", None),
                "article_count": getattr(entity, "article_count", 0),
                "first_seen_at": _dt(getattr(entity, "first_seen_at", None)),
                "last_seen_at": _dt(getattr(entity, "last_seen_at", None)),
            }
        )
    elif entity_type == "product":
        vendor_name = None
        try:
            if getattr(entity, "vendor", None):
                vendor_name = entity.vendor.name
        except Exception:
            pass
        base.update(
            {
                "name": getattr(entity, "name", None),
                "aliases": getattr(entity, "aliases", None) or [],
                "vendor_id": str(entity.vendor_id) if getattr(entity, "vendor_id", None) else None,
                "vendor_name": vendor_name,
                "product_type": getattr(entity, "product_type", None),
                "website": getattr(entity, "website", None),
                "description": getattr(entity, "description", None),
                "wikipedia_url": getattr(entity, "wikipedia_url", None),
                "wikipedia_content": getattr(entity, "wikipedia_content", None),
                "wikipedia_image_url": getattr(entity, "wikipedia_image_url", None),
                "article_count": getattr(entity, "article_count", 0),
                "first_seen_at": _dt(getattr(entity, "first_seen_at", None)),
                "last_seen_at": _dt(getattr(entity, "last_seen_at", None)),
            }
        )
    return base


def _dt(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


async def _get_manual_relationships(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> list[dict]:
    """Get manually created/confirmed EntityRelationship records for an entity."""
    query = select(EntityRelationship).where(
        or_(
            (EntityRelationship.source_type == entity_type) & (EntityRelationship.source_id == entity_id),
            (EntityRelationship.target_type == entity_type) & (EntityRelationship.target_id == entity_id),
        ),
        EntityRelationship.source != "analyst_rejected",
    )
    hidden = hidden_relationship_confidences()
    if hidden:
        query = query.where(EntityRelationship.confidence.notin_(hidden))
    result = await db.execute(query)
    relationships = []
    for rel in result.scalars().all():
        # Determine the "other" side of the relationship
        is_outbound = rel.source_type == entity_type and rel.source_id == entity_id
        if is_outbound:
            other_type, other_id = rel.target_type, rel.target_id
        else:
            other_type, other_id = rel.source_type, rel.source_id
        relationships.append(
            {
                "relationship_id": str(rel.id),
                "entity_type": other_type,
                "entity_id": other_id,
                "relationship_type": rel.relationship_type,
                "confidence": rel.confidence,
                "source": rel.source,
                "description": rel.description,
                "adjudication_verdict": rel.adjudication_verdict,
                "evidence_count": len(rel.evidence_entry_ids or []),
                # outbound: this entity <verb> other; inbound: other <verb> this entity
                "direction": "outbound" if is_outbound else "inbound",
            }
        )
    return relationships


async def pivot_from_entity(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    *,
    limit_per_type: int = 50,
    min_tier: str | None = None,
    window_days: int | None = None,
    offset: int = 0,
    sort: str = "strength",
) -> dict:
    """Pivot from one entity to all related entities via shared entries.

    Related lists are ranked (`sort`: strength | recent | articles), optionally
    filtered to a minimum tier and a trailing evidence window, then sliced to
    `offset:offset+limit_per_type`; `related_counts` carries pre-slice totals.
    """
    from app.intelligence.correlation_cache import (
        get_cached_pivot,
        pivot_cache_variant,
        set_cached_pivot,
    )

    # Persistent tier floor: when the caller didn't ask for a tier, apply the
    # platform-wide default (resolved before the cache key so variants stay
    # correct when the setting changes).
    if min_tier is None:
        from app.config import settings as _settings

        default_tier = str(_settings.get("relationship_min_tier_default") or "").lower()
        if default_tier in ("moderate", "strong"):
            min_tier = default_tier

    variant = pivot_cache_variant(
        limit_per_type=limit_per_type,
        min_tier=min_tier,
        window_days=window_days,
        offset=offset,
        sort=sort,
    )
    cached = await get_cached_pivot(entity_type, str(entity_id), variant=variant)
    if cached is not None:
        return cached

    entity = await get_entity(db, entity_type, entity_id)
    if not entity:
        return {}

    entry_ids = await _get_entry_ids_for_entity(db, entity_type, entity_id)

    # Prefetch entry metadata once — it powers the strength components in each
    # of the 9 per-type related queries plus the evidence window filter.
    entry_meta: dict[uuid.UUID, tuple] = {}
    if entry_ids:
        meta_result = await db.execute(
            select(Entry.id, Entry.published_at, Entry.feed_id, Entry.content_hash).where(Entry.id.in_(entry_ids))
        )
        entry_meta = {row[0]: (row[1], row[2], row[3]) for row in meta_result.all()}

    # Prefetch feed reliability ratings once — they weight the evidence in
    # each per-type related query.
    feed_reliability: dict[uuid.UUID, str | None] = {}
    pivot_feed_ids = {meta[1] for meta in entry_meta.values() if meta[1]}
    if pivot_feed_ids:
        rel_result = await db.execute(select(Feed.id, Feed.reliability_rating).where(Feed.id.in_(pivot_feed_ids)))
        feed_reliability = {row[0]: row[1] for row in rel_result.all()}

    if window_days and entry_ids:
        cutoff = datetime.now(UTC) - timedelta(days=window_days)
        entry_ids = [
            eid for eid in entry_ids if (meta := entry_meta.get(eid)) and meta[0] and _as_utc(meta[0]) >= cutoff
        ]

    entries: list[dict] = []
    related: dict[str, list] = {}
    related_counts: dict[str, int] = {}

    if entry_ids:
        # Get related entries, deduped by content_hash (one per unique article)
        canonical_subq = (
            select(Entry.id.label("entry_id"))
            .where(Entry.id.in_(entry_ids))
            .where(Entry.content_hash.isnot(None))
            .distinct(Entry.content_hash)
            .order_by(Entry.content_hash, Entry.created_at.asc())
        ).subquery()
        entry_result = await db.execute(
            select(Entry)
            .where(
                or_(
                    Entry.content_hash.is_(None),
                    Entry.id.in_(select(canonical_subq.c.entry_id)),
                )
            )
            .where(Entry.id.in_(entry_ids))
            .order_by(Entry.published_at.desc().nullslast())
        )
        entries = [
            {
                "id": str(e.id),
                "title": e.title,
                "url": e.url,
                "published_at": _dt(e.published_at),
                "created_at": _dt(e.created_at),
                "feed_id": str(e.feed_id),
            }
            for e in entry_result.scalars().all()
        ]

        # Corpus size for the specificity (IDF) damping — memoized per process.
        total_entries = await _corpus_entry_count(db)

        # Get related entities of each type (excluding the source entity itself)
        for related_type in ENTITY_CONFIG:
            # Co-mention observables would flood every profile that shares one
            # ioc_list entry (and render as raw UUIDs). Claim-backed edges still
            # arrive via the typed relationships; the ledger's own profile
            # pivots normally.
            if related_type == "observable" and entity_type != "observable":
                related["observables"] = []
                continue
            exclude = entity_id if related_type == entity_type else None
            related[related_type + "s"] = await _get_related_entities(
                db,
                related_type,
                entry_ids,
                exclude_id=exclude,
                source_type=entity_type,
                source_id=entity_id,
                entry_meta=entry_meta,
                enrich_titles=False,
                feed_reliability=feed_reliability,
                total_entries=total_entries,
            )

        # Get related detection rules (via shared entry + direct entity references)
        from sqlalchemy.dialects.postgresql import JSONB as _JSONB

        rule_filters = [DetectionRule.entry_id.in_(entry_ids)]

        # Also find rules that directly reference this entity
        if entity_type == "ttp":
            technique_id = getattr(entity, "technique_id", None)
            if technique_id:
                rule_filters.append(DetectionRule.source_ttps.op("@>")(type_coerce([technique_id], _JSONB)))
        elif entity_type == "cve":
            cve_id_str = getattr(entity, "cve_id", None)
            if cve_id_str:
                rule_filters.append(DetectionRule.source_cves.op("@>")(type_coerce([cve_id_str], _JSONB)))
        elif entity_type == "threat_actor":
            rule_filters.append(DetectionRule.source_actors.any(entity_id))

        # Column select, not select(DetectionRule): the entity form triggers the
        # model's lazy="joined" Entry load, duplicating each entry's full article
        # content once per rule (1.8GB / OOM on heavily-linked entities).
        rule_result = await db.execute(
            select(
                DetectionRule.id,
                DetectionRule.title,
                DetectionRule.rule_type,
                DetectionRule.severity,
                DetectionRule.created_at,
                DetectionRule.source_ttps,
                DetectionRule.source_cves,
            )
            .where(or_(*rule_filters))
            .order_by(DetectionRule.created_at.desc())
        )
        related["detection_rules"] = [
            {
                "id": str(r.id),
                "title": r.title,
                "rule_type": r.rule_type,
                "severity": r.severity,
                "created_at": _dt(r.created_at),
                # What the rule detects — powers the graph's coverage badges.
                "source_ttps": r.source_ttps or [],
                "source_cves": r.source_cves or [],
            }
            for r in rule_result.all()
        ]

    # Join the typed relationship layer (verb / confidence / provenance) onto
    # the co-occurrence rows by pair — previously this data was dropped for any
    # co-occurring pair.
    manual_rels = await _get_manual_relationships(db, entity_type, entity_id)
    rel_by_pair = {(m["entity_type"], str(m["entity_id"])): m for m in manual_rels}
    seen_ids = {item["id"] for items in related.values() for item in items if isinstance(item, dict) and "id" in item}
    for key, items in related.items():
        rtype = key[:-1]
        for item in items:
            if not isinstance(item, dict):
                continue
            m = rel_by_pair.get((rtype, item.get("id", "")))
            if m:
                item["relationship_id"] = m["relationship_id"]
                item["relationship_type"] = m["relationship_type"]
                item["relationship_confidence"] = m["confidence"]
                item["relationship_source"] = m["source"]
                item["relationship_direction"] = m["direction"]
                item["relationship_description"] = m["description"]
                item["relationship_adjudication"] = m["adjudication_verdict"]
                item["relationship_evidence_count"] = m["evidence_count"]

    # Tier filter + per-type truncation. Counts reflect pre-truncation totals so
    # the UI can show "870 CVEs · top 50". Confirmed relationships always pass
    # the tier filter; detection rules have no strength and are never filtered.
    tier_rank = {"weak": 0, "moderate": 1, "strong": 2}
    min_rank = tier_rank.get(min_tier or "", 0)

    def _sort_key(i: dict):
        s = i.get("strength") or {}
        if sort == "recent":
            return s.get("last_seen") or ""
        if sort == "articles":
            return s.get("articles") or 0
        return i.get("proximity_score") or 0

    # Detection coverage is computed against the whole rules library (at the
    # end of this function) over every related technique/CVE — collected here
    # so rows the truncation below drops still count.
    coverage_tech_ids = {t.get("technique_id") for t in related.get("ttps", []) if t.get("technique_id")}
    coverage_cve_ids = {c.get("cve_id") for c in related.get("cves", []) if c.get("cve_id")}

    for key in list(related.keys()):
        items = related[key]
        if key != "detection_rules":
            if min_rank > 0:
                items = [
                    i
                    for i in items
                    if tier_rank.get(((i.get("strength") or {}).get("tier") or "weak"), 0) >= min_rank
                    or i.get("relationship_confidence") == "confirmed"
                ]
            if sort != "strength":
                items = sorted(items, key=_sort_key, reverse=True)
        related_counts[key] = len(items)
        related[key] = items[offset : offset + limit_per_type]

    # Hydrate evidence titles only for rows that survived truncation.
    survivors = [i for items in related.values() for i in items if isinstance(i, dict)]
    await _attach_evidence_titles(db, survivors)

    # Evidence structure (story clustering) for the same survivors — gated on
    # relationship_evidence_structure inside, degrades to absent without
    # embeddings coverage.
    from app.intelligence.evidence_structure import attach_evidence_structure

    await attach_evidence_structure(db, survivors)

    # Append typed relationships to entities that never co-occur (pure manual /
    # external links) so they aren't invisible. Bulk-fetch the counterparts per
    # type — the MITRE import gives prominent actors 100+ such edges, and one
    # get_entity round-trip each would dominate uncached pivot latency.
    orphan_ids_by_type: dict[str, list[uuid.UUID]] = {}
    for mrel in manual_rels:
        if mrel["entity_type"] in ENTITY_CONFIG and str(mrel["entity_id"]) not in seen_ids:
            orphan_ids_by_type.setdefault(mrel["entity_type"], []).append(mrel["entity_id"])
    orphan_entities: dict[tuple[str, str], object] = {}
    for otype, oids in orphan_ids_by_type.items():
        model = ENTITY_CONFIG[otype][0]
        rows = await db.execute(select(model).where(model.id.in_(oids)))
        for ent in rows.scalars().all():
            orphan_entities[(otype, str(ent.id))] = ent

    for mrel in manual_rels:
        other_type = mrel["entity_type"]
        if other_type not in ENTITY_CONFIG:
            continue
        other_id = mrel["entity_id"]
        if str(other_id) in seen_ids:
            continue
        other_entity = orphan_entities.get((other_type, str(other_id)))
        if not other_entity:
            continue
        item = _serialize_entity(other_type, other_entity)
        item["co_occurrence_count"] = 0
        item["relationship_id"] = mrel["relationship_id"]
        item["relationship_type"] = mrel["relationship_type"]
        item["relationship_confidence"] = mrel["confidence"]
        item["relationship_source"] = mrel["source"]
        item["relationship_direction"] = mrel["direction"]
        item["relationship_description"] = mrel["description"]
        item["relationship_adjudication"] = mrel["adjudication_verdict"]
        item["relationship_evidence_count"] = mrel["evidence_count"]
        key = other_type + "s"
        if key not in related:
            related[key] = []
        related[key].append(item)
        related_counts[key] = related_counts.get(key, 0) + 1
        seen_ids.add(str(other_id))

    # ATT&CK catalog claims: technique↔mitigation mappings live in
    # ttp_mitigations, not entity_relationships — synthesize them as claim
    # rows so mitigations appear in the list, not just on the graph. The
    # synthetic relationship_id marks them catalog-derived; confirmed +
    # external_feed reads as "corroborated · MITRE" and blocks moderation.
    if entity_type in ("ttp", "mitigation"):
        from app.models.mitigation import TTPMitigation

        if entity_type == "ttp":
            cat_result = await db.execute(
                select(Mitigation)
                .join(TTPMitigation, TTPMitigation.mitigation_id == Mitigation.id)
                .where(TTPMitigation.ttp_id == entity_id)
            )
            cat_key, cat_type, cat_verb = "mitigations", "mitigation", "mitigated_by"
        else:
            cat_result = await db.execute(
                select(TTP)
                .join(TTPMitigation, TTPMitigation.ttp_id == TTP.id)
                .where(TTPMitigation.mitigation_id == entity_id)
            )
            cat_key, cat_type, cat_verb = "ttps", "ttp", "mitigates"

        for cat_ent in cat_result.scalars().all():
            annotation = {
                "relationship_id": f"catalog-ttp-mitigation-{cat_ent.id}",
                "relationship_type": cat_verb,
                "relationship_confidence": "confirmed",
                "relationship_source": "external_feed",
                "relationship_direction": "outbound",
                "relationship_description": None,
                "relationship_adjudication": None,
                "relationship_evidence_count": 0,
            }
            if str(cat_ent.id) in seen_ids:
                existing = next(
                    (i for i in related.get(cat_key, []) if isinstance(i, dict) and i.get("id") == str(cat_ent.id)),
                    None,
                )
                # Annotate a co-occurring row only when no real typed
                # relationship already claims it.
                if existing is not None and not existing.get("relationship_id"):
                    existing.update(annotation)
                continue
            item = _serialize_entity(cat_type, cat_ent)
            item["co_occurrence_count"] = 0
            item.update(annotation)
            if cat_key not in related:
                related[cat_key] = []
            related[cat_key].append(item)
            related_counts[cat_key] = related_counts.get(cat_key, 0) + 1
            seen_ids.add(str(cat_ent.id))

    # Country pivots: annotate actors with their semantic verb so the UI can
    # group "targeting {country}" / "operating from {country}" /
    # "infrastructure in {country}".
    if entity_type == "country" and related.get("threat_actors"):
        from app.models.country_junction import ThreatActorTargetCountry

        targeting_q = await db.execute(
            select(ThreatActorTargetCountry.threat_actor_id).where(ThreatActorTargetCountry.country_id == entity_id)
        )
        targeting = {str(r) for r in targeting_q.scalars().all()}
        origin_q = await db.execute(select(ThreatActor.id).where(ThreatActor.origin_country_id == entity_id))
        origin = {str(r) for r in origin_q.scalars().all()}
        # Actors co-occurring in entries where this country's role was
        # "infrastructure" (C2 hosting, staging, relays).
        infra_q = await db.execute(
            select(EntryThreatActor.threat_actor_id)
            .join(EntryCountry, EntryCountry.entry_id == EntryThreatActor.entry_id)
            .where(EntryCountry.country_id == entity_id, EntryCountry.role == "infrastructure")
        )
        infra = {str(r) for r in infra_q.scalars().all()}
        for item in related["threat_actors"]:
            if item.get("id") in targeting:
                item["country_relationship"] = "targets"
            elif item.get("id") in origin:
                item["country_relationship"] = "operates_from"
            elif item.get("id") in infra:
                item["country_relationship"] = "infrastructure"

    # Library-wide detection coverage: which of the related techniques/CVEs
    # does ANY rule in the library cover — not just rules extracted from this
    # entity's own articles (that scoping made every technique read as a
    # coverage gap on entities whose entries yielded no rules). Counts feed
    # the graph's inspector; presence/absence feeds the ticks and gap rings.
    for t in related.get("ttps", []):
        if isinstance(t, dict) and t.get("technique_id"):
            coverage_tech_ids.add(t["technique_id"])
    for c in related.get("cves", []):
        if isinstance(c, dict) and c.get("cve_id"):
            coverage_cve_ids.add(c["cve_id"])
    if entity_type == "ttp" and getattr(entity, "technique_id", None):
        coverage_tech_ids.add(entity.technique_id)
    elif entity_type == "cve" and getattr(entity, "cve_id", None):
        coverage_cve_ids.add(entity.cve_id)

    rule_coverage: dict[str, dict[str, int]] = {"ttps": {}, "cves": {}}
    if coverage_tech_ids:
        cov_sub = (
            select(func.jsonb_array_elements_text(DetectionRule.source_ttps).label("ref"))
            .where(DetectionRule.source_ttps.isnot(None))
            .subquery()
        )
        cov_rows = await db.execute(
            select(cov_sub.c.ref, func.count()).where(cov_sub.c.ref.in_(coverage_tech_ids)).group_by(cov_sub.c.ref)
        )
        rule_coverage["ttps"] = {ref: int(n) for ref, n in cov_rows.all()}
    if coverage_cve_ids:
        cov_sub = (
            select(func.jsonb_array_elements_text(DetectionRule.source_cves).label("ref"))
            .where(DetectionRule.source_cves.isnot(None))
            .subquery()
        )
        cov_rows = await db.execute(
            select(cov_sub.c.ref, func.count()).where(cov_sub.c.ref.in_(coverage_cve_ids)).group_by(cov_sub.c.ref)
        )
        rule_coverage["cves"] = {ref: int(n) for ref, n in cov_rows.all()}

    serialized_entity = _serialize_entity(entity_type, entity)
    if entity_type == "campaign":
        # A campaign's newest article is the first entry — entries are already
        # ordered published_at desc. This is what "gone quiet" measures from,
        # and it is a different fact from updated_at, which any edit bumps.
        serialized_entity["last_activity_at"] = entries[0]["published_at"] if entries else None

    result = {
        "entity": serialized_entity,
        "related": related,
        "related_counts": related_counts,
        "rule_coverage": rule_coverage,
        "entries": entries,
    }

    await set_cached_pivot(entity_type, str(entity_id), result, variant=variant)
    return result


async def build_entity_graph(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    depth: int = 1,
    window_days: int | None = None,
    include_observables: bool = False,
) -> dict:
    """Build a node/edge graph for visualization. depth=1 means direct co-occurrence.

    Each node contributes its N strongest neighbors (not everything above the
    threshold); edges carry the typed verb / confidence / provenance where a
    relationship record exists, oriented semantically. `window_days` restricts
    the evidence window per node.
    """
    from app.config import settings as env_settings
    from app.intelligence.correlation_cache import confidence_cache_variant, get_cached_graph, set_cached_graph

    variant = (f":w{window_days}" if window_days else "") + confidence_cache_variant()
    cached = await get_cached_graph(entity_type, str(entity_id), depth, variant=variant)
    if cached is not None:
        return cached

    entity = await get_entity(db, entity_type, entity_id)
    if not entity:
        return {"nodes": [], "edges": []}

    # Corpus size for specificity damping — memoized per process.
    graph_total_entries = await _corpus_entry_count(db)

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    edge_pair_seen: set[tuple[str, str]] = set()
    visited: set[tuple[str, str]] = set()

    async def _expand(etype: str, eid: uuid.UUID, current_depth: int):
        key = (etype, str(eid))
        if key in visited:
            return
        visited.add(key)

        ent = await get_entity(db, etype, eid)
        if not ent:
            return

        node_id = f"{etype}-{eid}"
        if node_id not in nodes:
            article_count = getattr(ent, "article_count", 1) or 1
            nodes[node_id] = {
                "id": node_id,
                "type": etype,
                "label": _entity_label(etype, ent),
                "size": min(article_count * 10, 100),
                "data": _serialize_entity(etype, ent),
            }

        if current_depth <= 0:
            return

        entry_ids = await _get_entry_ids_for_entity(db, etype, eid)
        if window_days and entry_ids:
            cutoff = datetime.now(UTC) - timedelta(days=window_days)
            win_result = await db.execute(select(Entry.id).where(Entry.id.in_(entry_ids), Entry.published_at >= cutoff))
            entry_ids = [row[0] for row in win_result.all()]
        if not entry_ids:
            return

        # Keep only the N strongest neighbors per node — the cap replaces the
        # old minimum-strength filter: sparse entities keep their few (weak)
        # edges instead of an empty graph, dense ones stay readable.
        max_neighbors = int(env_settings.get("graph_max_neighbors_per_node") or 30)

        candidates: list[tuple[str, dict]] = []
        for related_type in ENTITY_CONFIG:
            # Observables stay off the map unless asked for (or the map is
            # centered on one) — hundreds of ledger atoms as nodes is the
            # graph bloat the ledger design exists to prevent.
            if related_type == "observable" and not include_observables and etype != "observable":
                continue
            related_entities = await _get_related_entities(
                db,
                related_type,
                entry_ids,
                exclude_id=eid if related_type == etype else None,
                source_type=etype,
                source_id=eid,
                total_entries=graph_total_entries,
            )
            for rel in related_entities:
                # Ubiquitous reporting vendors/products are background, not
                # relationships — keep them off the map entirely.
                if rel.get("context_role") == "reporting_source":
                    continue
                candidates.append((related_type, rel))
        # A campaign's claim is its membership. Nothing writes entity_relationship
        # rows for a campaign — it is not in the relationship matrix — so the
        # claims-only rule below left its map a single unconnected node. But
        # everything a campaign contains is there because an analyst put the
        # articles in, which is as asserted as a relationship gets; the curated
        # CampaignEntity roles (primary / secondary / related) are the verb.
        campaign_roles: dict[str, str] = {}
        if etype == "campaign":
            from app.models.campaign import CampaignEntity

            role_rows = await db.execute(
                select(CampaignEntity.entity_type, CampaignEntity.entity_id, CampaignEntity.role).where(
                    CampaignEntity.campaign_id == eid
                )
            )
            campaign_roles = {f"{rtype}-{rid}": role for rtype, rid, role in role_rows.all()}

        # Curation outranks volume. A campaign's proximity is co-occurrence only,
        # and CVEs co-occur far more than the actor the campaign is named after —
        # so a plain score sort spent the whole neighbour budget on CVEs and cut
        # the one entity the analyst explicitly called primary.
        role_rank = {"primary": 2, "secondary": 1}

        def _candidate_rank(c: tuple[str, dict]) -> tuple[int, float]:
            related_type, rel = c
            role = campaign_roles.get(f"{related_type}-{rel['id']}")
            return (role_rank.get(role or "", 0), rel.get("proximity_score") or 0)

        candidates.sort(key=_candidate_rank, reverse=True)
        candidates = candidates[:max_neighbors]

        # Typed relationship records give edges their verb, direction,
        # confidence and provenance — one verb language with the browser rows.
        manual_rels = await _get_manual_relationships(db, etype, eid)
        rel_by_pair = {(m["entity_type"], str(m["entity_id"])): m for m in manual_rels}

        for related_type, rel in candidates:
            # The map shows CLAIMS only: a candidate without a typed
            # relationship (pure co-mention) stays in the tab's context
            # shelf — co-occurrence data here just enriches typed edges
            # (all tiers, signal included) with proximity and evidence.
            mrel = rel_by_pair.get((related_type, rel["id"]))
            if not mrel and etype == "campaign":
                role = campaign_roles.get(f"{related_type}-{rel['id']}", "related")
                mrel = {
                    "relationship_id": f"campaign-member-{rel['id']}",
                    "relationship_type": role,
                    "confidence": "confirmed" if role != "related" else "likely",
                    "source": "analyst",
                    "direction": "outbound",
                    "description": None,
                    "adjudication_verdict": None,
                    "evidence_count": rel.get("co_occurrence_count", 0),
                }
            if not mrel:
                continue

            prox = rel.get("proximity_score")
            co_count = rel.get("co_occurrence_count", 1)
            rel_node_id = f"{related_type}-{rel['id']}"
            edge_key = tuple(sorted([node_id, rel_node_id]))

            if rel_node_id not in nodes:
                nodes[rel_node_id] = {
                    "id": rel_node_id,
                    "type": related_type,
                    "label": _get_label_from_serialized(related_type, rel),
                    "size": min(co_count * 10, 80),
                    "data": rel,
                }

            if edge_key not in edge_pair_seen:
                edge_pair_seen.add(edge_key)
                weight = prox if prox is not None else co_count
                # Include linking articles so the graph can show evidence
                edge_entries = rel.get("proximity_entries") or []
                edge_source, edge_target = node_id, rel_node_id
                if mrel["direction"] == "inbound":
                    edge_source, edge_target = rel_node_id, node_id
                edges.append(
                    {
                        "source": edge_source,
                        "target": edge_target,
                        "weight": weight,
                        "label": mrel["relationship_type"],
                        "proximity_score": prox,
                        "confidence": mrel["confidence"],
                        "provenance": mrel["source"],
                        "relationship_id": mrel["relationship_id"],
                        "entries": [
                            {"entry_id": pe["entry_id"], "title": pe.get("title", ""), "score": pe.get("score", 0)}
                            for pe in edge_entries
                        ],
                    }
                )

            if current_depth > 1 and mrel["confidence"] != "possible":
                await _expand(related_type, uuid.UUID(rel["id"]), current_depth - 1)

        # Include origin country for threat actors as a direct relationship
        if etype == "threat_actor":
            origin_country_id = getattr(ent, "origin_country_id", None)
            if origin_country_id:
                country_ent = await get_entity(db, "country", origin_country_id)
                if country_ent:
                    rel_node_id = f"country-{origin_country_id}"
                    edge_key = tuple(sorted([node_id, rel_node_id]))
                    if rel_node_id not in nodes:
                        article_count = getattr(country_ent, "article_count", 1) or 1
                        nodes[rel_node_id] = {
                            "id": rel_node_id,
                            "type": "country",
                            "label": _entity_label("country", country_ent),
                            "size": min(article_count * 10, 80),
                            "data": _serialize_entity("country", country_ent),
                        }
                    if edge_key not in edge_pair_seen:
                        edge_pair_seen.add(edge_key)
                        edges.append(
                            {
                                "source": node_id,
                                "target": rel_node_id,
                                "weight": 2,
                                "label": "origin country",
                            }
                        )

        # Also expand manual EntityRelationship edges — every claim tier the
        # tab shows, trust-ranked. The frontend folds story-less nodes into
        # per-type ghost pills, so the graph can carry all of an entity's
        # claims; the cap only exists for degenerate hubs (a targeted country
        # can hold 2,800+ typed edges) and keeps the strongest ones.
        conf_rank = {"confirmed": 3, "probable": 2, "possible": 1}
        max_claim_edges = int(env_settings.get("graph_max_claim_edges") or 300)
        ranked_manual = sorted(
            (m for m in manual_rels if m["confidence"] in conf_rank and m["entity_type"] in ENTITY_CONFIG),
            key=lambda m: (conf_rank[m["confidence"]], m["evidence_count"]),
            reverse=True,
        )[:max_claim_edges]

        # Bulk-fetch counterparts per type instead of one query per edge.
        manual_ids_by_type: dict[str, list[uuid.UUID]] = {}
        for m in ranked_manual:
            manual_ids_by_type.setdefault(m["entity_type"], []).append(m["entity_id"])
        manual_ents: dict[tuple[str, str], object] = {}
        for otype, oids in manual_ids_by_type.items():
            model = ENTITY_CONFIG[otype][0]
            ent_rows = await db.execute(select(model).where(model.id.in_(oids)))
            for e_row in ent_rows.scalars().all():
                manual_ents[(otype, str(e_row.id))] = e_row

        for rank_idx, mrel in enumerate(ranked_manual):
            other_type = mrel["entity_type"]
            other_id = mrel["entity_id"]
            other_ent = manual_ents.get((other_type, str(other_id)))
            if not other_ent:
                continue
            rel_node_id = f"{other_type}-{other_id}"
            edge_key = tuple(sorted([node_id, rel_node_id]))

            if rel_node_id not in nodes:
                article_count = getattr(other_ent, "article_count", 1) or 1
                nodes[rel_node_id] = {
                    "id": rel_node_id,
                    "type": other_type,
                    "label": _entity_label(other_type, other_ent),
                    "size": min(article_count * 10, 80),
                    "data": _serialize_entity(other_type, other_ent),
                }

            if edge_key not in edge_pair_seen:
                edge_pair_seen.add(edge_key)
                edge_source, edge_target = node_id, rel_node_id
                if mrel["direction"] == "inbound":
                    edge_source, edge_target = rel_node_id, node_id
                edges.append(
                    {
                        "source": edge_source,
                        "target": edge_target,
                        "weight": 1,
                        "label": mrel["relationship_type"],
                        "confidence": mrel["confidence"],
                        "provenance": mrel["source"],
                        "relationship_id": mrel["relationship_id"],
                    }
                )

            # Multi-hop expansion stays selective: only the strongest
            # corroborated/reported edges recurse, matching the old cap —
            # signal-tier and long-tail edges appear but don't fan out.
            if current_depth > 1 and rank_idx < max_neighbors and conf_rank[mrel["confidence"]] >= 2:
                await _expand(other_type, other_id, current_depth - 1)

    await _expand(entity_type, entity_id, depth)

    # Weakness layer: every CVE node pulls its catalog CWEs (cve_weaknesses).
    # These are NVD/MITRE catalog claims that the relationship matrix
    # deliberately keeps out of entity_relationships — the graph is where
    # their convergence is worth seeing (three exploited CVEs → one CWE says
    # what tradecraft the actor lives on).
    cve_node_by_uuid = {uuid.UUID(n["id"][4:]): n["id"] for n in nodes.values() if n["type"] == "cve"}
    if cve_node_by_uuid:
        from app.models.cwe import CWE, CVEWeakness

        cwe_rows = await db.execute(
            select(CVEWeakness.cve_id, CWE)
            .join(CWE, CWE.id == CVEWeakness.cwe_id_fk)
            .where(CVEWeakness.cve_id.in_(cve_node_by_uuid.keys()))
        )
        for cve_uuid, cwe in cwe_rows.all():
            cwe_node_id = f"cwe-{cwe.id}"
            if cwe_node_id not in nodes:
                nodes[cwe_node_id] = {
                    "id": cwe_node_id,
                    "type": "cwe",
                    "label": _entity_label("cwe", cwe),
                    "size": 16,
                    "data": _serialize_entity("cwe", cwe),
                }
            edges.append(
                {
                    "source": cve_node_by_uuid[cve_uuid],
                    "target": cwe_node_id,
                    "weight": 1,
                    "label": "weakness",
                    "confidence": "confirmed",
                    "provenance": "external_feed",
                }
            )

    # Mitigation layer (catalog): ATT&CK's technique↔mitigation mappings, on
    # every graph — a mitigation-seed graph shows the techniques it counters,
    # and any graph's TTP nodes pull their mitigations. The frontend folds
    # story-less nodes into one pill per type, so an actor's 40 techniques
    # don't turn into 120 mitigation spokes on the canvas.
    from app.models.mitigation import TTPMitigation

    edge_pairs = set(edge_pair_seen)

    if entity_type == "mitigation":
        ttp_rows = await db.execute(
            select(TTP)
            .join(TTPMitigation, TTPMitigation.ttp_id == TTP.id)
            .where(TTPMitigation.mitigation_id == entity_id)
        )
        seed_node = f"mitigation-{entity_id}"
        for tech in ttp_rows.scalars().all():
            tid = f"ttp-{tech.id}"
            if tid not in nodes:
                nodes[tid] = {
                    "id": tid,
                    "type": "ttp",
                    "label": _entity_label("ttp", tech),
                    "size": 16,
                    "data": _serialize_entity("ttp", tech),
                }
            pair = tuple(sorted([seed_node, tid]))
            if pair not in edge_pairs:
                edge_pairs.add(pair)
                edges.append(
                    {
                        "source": seed_node,
                        "target": tid,
                        "weight": 1,
                        "label": "mitigates",
                        "confidence": "confirmed",
                        "provenance": "external_feed",
                    }
                )

    ttp_node_by_uuid = {uuid.UUID(n["id"][4:]): n["id"] for n in nodes.values() if n["type"] == "ttp"}
    if ttp_node_by_uuid:
        mit_rows = await db.execute(
            select(TTPMitigation.ttp_id, Mitigation)
            .join(Mitigation, Mitigation.id == TTPMitigation.mitigation_id)
            .where(TTPMitigation.ttp_id.in_(ttp_node_by_uuid.keys()))
        )
        for ttp_uuid, mit in mit_rows.all():
            mid = f"mitigation-{mit.id}"
            if entity_type == "mitigation" and mid == f"mitigation-{entity_id}":
                continue
            if mid not in nodes:
                nodes[mid] = {
                    "id": mid,
                    "type": "mitigation",
                    "label": _entity_label("mitigation", mit),
                    "size": 16,
                    "data": _serialize_entity("mitigation", mit),
                }
            pair = tuple(sorted([ttp_node_by_uuid[ttp_uuid], mid]))
            if pair not in edge_pairs:
                edge_pairs.add(pair)
                edges.append(
                    {
                        "source": ttp_node_by_uuid[ttp_uuid],
                        "target": mid,
                        "weight": 1,
                        "label": "mitigated by",
                        "confidence": "confirmed",
                        "provenance": "external_feed",
                    }
                )

    result = {"nodes": list(nodes.values()), "edges": edges}
    await set_cached_graph(entity_type, str(entity_id), depth, result, variant=variant)
    return result


async def build_entry_graph(db: AsyncSession, entry_id: uuid.UUID, include_observables: bool = False) -> dict:
    """Build a graph of all entities linked to a specific entry and their inter-relationships."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    # Collect all entities linked to this entry
    for etype, (model, junction, fk_col) in ENTITY_CONFIG.items():
        if etype == "observable" and not include_observables:
            continue
        result = await db.execute(select(model).join(junction, fk_col == model.id).where(junction.entry_id == entry_id))
        for entity in result.scalars().all():
            node_id = f"{etype}-{entity.id}"
            article_count = getattr(entity, "article_count", 1) or 1
            nodes[node_id] = {
                "id": node_id,
                "type": etype,
                "label": _entity_label(etype, entity),
                "size": min(article_count * 10, 100),
                "data": _serialize_entity(etype, entity),
            }

    if not nodes:
        return {"nodes": [], "edges": []}

    # Fetch entry title for edge evidence
    entry_result = await db.execute(select(Entry.title).where(Entry.id == entry_id))
    entry_title = entry_result.scalar() or ""
    entry_evidence = [{"entry_id": str(entry_id), "title": entry_title, "score": 1.0}]

    # Build edges: entities that co-occur in this entry are connected
    # Cap at 500 edges to avoid O(n²) blowup with many entities
    MAX_ENTRY_GRAPH_EDGES = 500
    node_list = list(nodes.values())
    for a, b in combinations(node_list, 2):
        if len(edges) >= MAX_ENTRY_GRAPH_EDGES:
            break
        edge_label = "co-mentioned"
        edges.append(
            {
                "source": a["id"],
                "target": b["id"],
                "weight": 1,
                "label": edge_label,
                "entries": entry_evidence,
            }
        )

    # Also include manual EntityRelationship edges between these entities
    node_ids_by_type: dict[str, list[uuid.UUID]] = {}
    for n in node_list:
        raw_id = uuid.UUID(n["id"].split("-", 1)[1])
        node_ids_by_type.setdefault(n["type"], []).append(raw_id)

    for etype, eids in node_ids_by_type.items():
        for eid in eids:
            manual_rels = await _get_manual_relationships(db, etype, eid)
            for mrel in manual_rels:
                other_node_id = f"{mrel['entity_type']}-{mrel['entity_id']}"
                if other_node_id in nodes:
                    edge_key = tuple(sorted([f"{etype}-{eid}", other_node_id]))
                    existing = next(
                        (e for e in edges if tuple(sorted([e["source"], e["target"]])) == edge_key),
                        None,
                    )
                    if existing:
                        existing["label"] = mrel["relationship_type"]
                    else:
                        edges.append(
                            {
                                "source": f"{etype}-{eid}",
                                "target": other_node_id,
                                "weight": 1,
                                "label": mrel["relationship_type"],
                            }
                        )

    return {"nodes": node_list, "edges": edges}


def _get_label_from_serialized(entity_type: str, data: dict) -> str:
    if entity_type == "ttp":
        return f"{data.get('technique_id', '')} {data.get('technique_name', '')}"
    if entity_type == "cve":
        return data.get("cve_id", "")
    if entity_type in ("threat_actor", "malware", "country", "tool", "vendor", "product"):
        return data.get("name", "")
    if entity_type == "mitigation":
        mid = data.get("mitre_id", "")
        name = data.get("name", "")
        return f"{mid} {name}" if mid else name
    if entity_type == "observable":
        return data.get("label") or data.get("value", "")
    return data.get("id", "")


# `match_field` values that mean "the query matched this entity's own identity"
# — its name, an alias, or the identifier it is catalogued under. Every other
# value (description, tags, tactic, rule body, ...) means the entity merely
# mentions the query, which is a categorically weaker result and is grouped
# separately in the UI.
DIRECT_MATCH_FIELDS = frozenset({"name", "alias", "technique", "cve_id", "mitre_id", "value"})

# `title` is judged separately. A detection rule or report title is a sentence
# describing what the thing does, not a name: "Detects a backdoor DLL used by
# LockBit 3.0 affiliates" contains "lockbit" but the rule is not LockBit. Left
# in DIRECT_MATCH_FIELDS it put sixteen YARA rules ahead of the LockBit entity
# they describe. A title only counts as identity when the query is what the
# title opens with, which is how someone searching a rule *by name* types it.
TITLE_MATCH_FIELDS = frozenset({"title"})


def _classify_match(item: dict, query_lower: str) -> str:
    """ "direct" if the query hit this entity's identity, else "mention"."""
    field = item.get("match_field")
    if field in DIRECT_MATCH_FIELDS:
        return "direct"
    if field in TITLE_MATCH_FIELDS:
        title = (item.get("title") or "").lower().strip()
        return "direct" if title == query_lower or title.startswith(query_lower) else "mention"
    return "mention"


async def search_all_entities(
    db: AsyncSession, query: str, limit: int = 50, entity_types: list[str] | None = None
) -> list[dict]:
    """Search across all entity types. Returns results sorted by relevance (exact match first).

    If entity_types is provided, only those types are searched and each gets the full limit.
    """
    results: list[dict] = []
    q = f"%{query}%"
    ql = query.lower()
    # When filtering by type, give each type the full limit; otherwise cap per-type
    if entity_types:
        per_type_limit = limit
        _search_type = set(entity_types)
    else:
        per_type_limit = max(limit // 3, 20)
        _search_type = None

    def _should_search(type_name: str) -> bool:
        return _search_type is None or type_name in _search_type

    def _match_field(entity, entity_type: str, name_field: str = "name") -> str:
        """Determine which field matched the query for display hints."""
        name_val = getattr(entity, name_field, None)
        if name_val and ql in name_val.lower():
            return name_field
        if _alias_contains_bounded(getattr(entity, "aliases", None), ql):
            return "alias"
        return name_field

    # TTPs — search technique_id, technique_name, tactic, and description
    ttp_result = await db.execute(
        select(TTP)
        .where(
            or_(
                TTP.technique_id.ilike(q),
                TTP.technique_name.ilike(q),
                TTP.tactic.ilike(q),
                TTP.description.ilike(q),
            )
        )
        .limit(per_type_limit)
    )
    for ttp in ttp_result.scalars().all():
        item = _serialize_entity("ttp", ttp)
        if ql in (ttp.technique_id or "").lower() or ql in (ttp.technique_name or "").lower():
            item["match_field"] = "technique"
        elif ql in (ttp.tactic or "").lower():
            item["match_field"] = "tactic"
        else:
            item["match_field"] = "description"
        results.append(item)

    # CVEs — search cve_id and description
    cve_result = await db.execute(
        select(CVE).where(or_(CVE.cve_id.ilike(q), CVE.description.ilike(q))).limit(per_type_limit)
    )
    for cve in cve_result.scalars().all():
        item = _serialize_entity("cve", cve)
        item["match_field"] = "cve_id" if ql in (cve.cve_id or "").lower() else "description"
        results.append(item)

    # Weaknesses — search catalog id, name, alternate terms and description.
    # Alternate terms are searchable here on purpose: a human typing "use after
    # free" should find CWE-416. That is the opposite of the autolinker, which
    # matches the id alone — a human query is an explicit request, a dictionary
    # scan over article prose is not.
    if _should_search("cwe"):
        cwe_result = await db.execute(
            select(CWE)
            .where(
                or_(
                    CWE.cwe_id.ilike(q),
                    CWE.name.ilike(q),
                    func.array_to_string(CWE.alternate_terms, " ").ilike(q),
                    CWE.description.ilike(q),
                )
            )
            .limit(per_type_limit)
        )
        for cwe in cwe_result.scalars().all():
            item = _serialize_entity("cwe", cwe)
            if ql in (cwe.cwe_id or "").lower():
                item["match_field"] = "cwe_id"
            elif ql in (cwe.name or "").lower():
                item["match_field"] = "name"
            elif _alias_contains_bounded(cwe.alternate_terms, ql):
                item["match_field"] = "alias"
            else:
                item["match_field"] = "description"
            results.append(item)

    # Threat Actors — search name, aliases, description
    actor_result = await db.execute(
        select(ThreatActor)
        .where(
            or_(
                ThreatActor.name.ilike(q),
                _aliases_match_bounded(ThreatActor, query),
                ThreatActor.description.ilike(q),
            )
        )
        .limit(per_type_limit)
    )
    for actor in actor_result.scalars().all():
        item = _serialize_entity("threat_actor", actor)
        mf = _match_field(actor, "threat_actor")
        item["match_field"] = (
            mf
            if mf != "name"
            else (
                "description"
                if ql not in (actor.name or "").lower() and not _alias_contains_bounded(actor.aliases, ql)
                else mf
            )
        )
        results.append(item)

    # Malware — search name, aliases, malware_type
    malware_result = await db.execute(
        select(MalwareFamily)
        .where(
            or_(
                MalwareFamily.name.ilike(q),
                _aliases_match_bounded(MalwareFamily, query),
                MalwareFamily.malware_type.ilike(q),
            )
        )
        .limit(per_type_limit)
    )
    for malware in malware_result.scalars().all():
        item = _serialize_entity("malware", malware)
        mf = _match_field(malware, "malware")
        if mf == "name" and ql not in (malware.name or "").lower() and not _alias_contains_bounded(malware.aliases, ql):
            mf = "malware_type"
        item["match_field"] = mf
        results.append(item)

    # Detection Rules — search title, description, tags, notes, rule_content,
    # source_ttps, source_cves, mitre_tactics
    rule_result = await db.execute(
        select(DetectionRule)
        .where(
            or_(
                DetectionRule.title.ilike(q),
                DetectionRule.description.ilike(q),
                DetectionRule.notes.ilike(q),
                DetectionRule.rule_content.ilike(q),
                func.array_to_string(DetectionRule.tags, ",").ilike(q),
                func.array_to_string(DetectionRule.mitre_tactics, ",").ilike(q),
                cast(DetectionRule.source_ttps, String).ilike(q),
                cast(DetectionRule.source_cves, String).ilike(q),
            )
        )
        .limit(per_type_limit)
    )
    for rule in rule_result.scalars().all():
        # Determine which field matched
        rl = ql
        if rl in (rule.title or "").lower():
            mf = "title"
        elif rl in (rule.description or "").lower():
            mf = "description"
        elif any(rl in t.lower() for t in (rule.source_ttps or [])):
            mf = "source_ttps"
        elif any(rl in c.lower() for c in (rule.source_cves or [])):
            mf = "source_cves"
        elif any(rl in t.lower() for t in (rule.tags or [])):
            mf = "tags"
        elif any(rl in t.lower() for t in (rule.mitre_tactics or [])):
            mf = "mitre_tactics"
        elif rl in (rule.notes or "").lower():
            mf = "notes"
        else:
            mf = "rule_content"
        results.append(
            {
                "id": str(rule.id),
                "type": "detection_rule",
                "title": rule.title,
                "rule_type": rule.rule_type,
                "severity": rule.severity,
                "match_field": mf,
            }
        )

    # Offensive Tools — search name, aliases, tool_type
    tool_result = await db.execute(
        select(Tool)
        .where(
            or_(
                Tool.name.ilike(q),
                _aliases_match_bounded(Tool, query),
                Tool.tool_type.ilike(q),
            )
        )
        .limit(per_type_limit)
    )
    for tool in tool_result.scalars().all():
        item = _serialize_entity("tool", tool)
        mf = _match_field(tool, "tool")
        if mf == "name" and ql not in (tool.name or "").lower() and not _alias_contains_bounded(tool.aliases, ql):
            mf = "tool_type"
        item["match_field"] = mf
        results.append(item)

    # Vendors — search name, aliases, vendor_type
    if _should_search("vendor"):
        vendor_result = await db.execute(
            select(Vendor)
            .where(
                or_(
                    Vendor.name.ilike(q),
                    _aliases_match_bounded(Vendor, query),
                    Vendor.vendor_type.ilike(q),
                )
            )
            .limit(per_type_limit)
        )
        for vendor in vendor_result.scalars().all():
            item = _serialize_entity("vendor", vendor)
            mf = _match_field(vendor, "vendor")
            if (
                mf == "name"
                and ql not in (vendor.name or "").lower()
                and not _alias_contains_bounded(vendor.aliases, ql)
            ):
                mf = "vendor_type"
            item["match_field"] = mf
            results.append(item)

    # Products — search name, aliases, product_type
    if _should_search("product"):
        product_result = await db.execute(
            select(Product)
            .where(
                or_(
                    Product.name.ilike(q),
                    _aliases_match_bounded(Product, query),
                    Product.product_type.ilike(q),
                )
            )
            .limit(per_type_limit)
        )
        for product in product_result.scalars().all():
            item = _serialize_entity("product", product)
            mf = _match_field(product, "product")
            if (
                mf == "name"
                and ql not in (product.name or "").lower()
                and not _alias_contains_bounded(product.aliases, ql)
            ):
                mf = "product_type"
            item["match_field"] = mf
            results.append(item)

    # Countries — search name and aliases
    country_result = await db.execute(
        select(Country)
        .where(
            or_(
                Country.name.ilike(q),
                _aliases_match_bounded(Country, query),
            )
        )
        .limit(per_type_limit)
    )
    for country in country_result.scalars().all():
        item = _serialize_entity("country", country)
        item["match_field"] = _match_field(country, "country")
        results.append(item)

    # Mitigations — search name and mitre_id
    mitigation_result = await db.execute(
        select(Mitigation)
        .where(
            or_(
                Mitigation.name.ilike(q),
                Mitigation.mitre_id.ilike(q),
                Mitigation.description.ilike(q),
            )
        )
        .limit(per_type_limit)
    )
    for mit in mitigation_result.scalars().all():
        item = _serialize_entity("mitigation", mit)
        if ql in (mit.mitre_id or "").lower():
            item["match_field"] = "mitre_id"
        elif ql in (mit.name or "").lower():
            item["match_field"] = "name"
        else:
            item["match_field"] = "description"
        results.append(item)

    # Campaigns — search name and description
    campaign_result = await db.execute(
        select(Campaign)
        .where(
            or_(
                Campaign.name.ilike(q),
                Campaign.description.ilike(q),
            )
        )
        .limit(per_type_limit)
    )
    for campaign in campaign_result.scalars().all():
        results.append(
            {
                "id": str(campaign.id),
                "type": "campaign",
                "name": campaign.name,
                "description": campaign.description,
                "status": campaign.status,
                "tlp_marking": campaign.tlp_marking,
                "tags": campaign.tags or [],
                "match_field": "name",
            }
        )

    # Intel Reports — search title and summary
    report_result = await db.execute(
        select(IntelReport)
        .where(
            or_(
                IntelReport.title.ilike(q),
                IntelReport.summary.ilike(q),
            )
        )
        .limit(per_type_limit)
    )
    for report in report_result.scalars().all():
        results.append(
            {
                "id": str(report.id),
                "type": "intel_report",
                "title": report.title,
                "summary": report.summary,
                "template_type": report.template_type,
                "status": report.status,
                "tlp_marking": report.tlp_marking,
                "tags": report.tags or [],
                "match_field": "title",
            }
        )

    # Notes — analyst writing, from the two tables that hold it. The `note:`
    # query-language field runs the same fetch with its own WHERE clauses, so
    # both paths return identically shaped rows.
    if _should_search("note"):
        note_where, entity_note_where = text_conditions(query)
        note_results, _ = await fetch_notes(db, note_where, entity_note_where, per_type_limit, ql)
        results.extend(note_results)

    # Sort: exact name match first, then alias match, then by type priority
    type_priority = {
        "threat_actor": 0,
        "malware": 1,
        "detection_rule": 2,
        "tool": 3,
        "cve": 4,
        "ttp": 5,
        "vendor": 6,
        "product": 7,
        "country": 8,
        "mitigation": 9,
        "campaign": 10,
        "intel_report": 11,
        "note": 12,
    }

    def sort_key(item):
        label = (item.get("name") or item.get("value") or item.get("cve_id") or item.get("title") or "").lower()
        aliases = [a.lower() for a in (item.get("aliases") or []) if a]
        # 0 = exact name match, 1 = exact alias match, 2 = partial match
        if label == ql:
            exact_rank = 0
        elif ql in aliases:
            exact_rank = 1
        else:
            exact_rank = 2
        is_alias = 1 if item.get("match_field") == "alias" else 0
        return (exact_rank, is_alias, type_priority.get(item["type"], 99))

    # When type filter is active, only keep matching types
    if _search_type:
        results = [r for r in results if r["type"] in _search_type]

    results.sort(key=sort_key)

    # Split identity matches from incidental ones. `match_field` already says
    # WHICH column matched; this says what that means to a reader. Searching
    # "lockbit" returns the LockBit actor (its name) alongside 31 actors whose
    # prose merely cites LockBit — the same list until you separate them.
    for item in results:
        item["match_kind"] = _classify_match(item, ql)

    return results[:limit]


async def entity_timeline(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> list[dict]:
    """Get temporal activity for an entity: linked articles, correlation events, and enrichments."""
    # A campaign's articles come from its membership table rather than an
    # extraction junction; everything downstream is the same.
    if entity_type == "campaign":
        from app.models.campaign import CampaignEntry

        linked_ids_subq = (select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == entity_id)).subquery()
    else:
        _, junction, fk_col = ENTITY_CONFIG[entity_type]
        linked_ids_subq = (select(junction.entry_id).where(fk_col == entity_id)).subquery()

    # 1. Linked articles, deduped by content_hash
    canonical_subq = (
        select(Entry.id.label("entry_id"))
        .where(Entry.id.in_(select(linked_ids_subq.c.entry_id)))
        .where(Entry.content_hash.isnot(None))
        .distinct(Entry.content_hash)
        .order_by(Entry.content_hash, Entry.created_at.asc())
    ).subquery()
    result = await db.execute(
        select(Entry.id, Entry.title, Entry.published_at, Entry.url)
        .where(Entry.id.in_(select(linked_ids_subq.c.entry_id)))
        .where(
            or_(
                Entry.content_hash.is_(None),
                Entry.id.in_(select(canonical_subq.c.entry_id)),
            )
        )
        .order_by(Entry.published_at.desc().nullslast())
    )

    events = []
    for eid, title, published_at, url in result.all():
        events.append(
            {
                "entry_id": str(eid),
                "title": title,
                "url": url,
                "date": _dt(published_at),
                "event_type": "article",
            }
        )

    # 2. Correlation events referencing this entity
    from app.models.correlation_event import CorrelationEventRecord

    corr_result = await db.execute(
        select(
            CorrelationEventRecord.id,
            CorrelationEventRecord.event_type,
            CorrelationEventRecord.context,
            CorrelationEventRecord.severity,
            CorrelationEventRecord.created_at,
            CorrelationEventRecord.entry_id,
            CorrelationEventRecord.source_entity_type,
            CorrelationEventRecord.source_entity_id,
            CorrelationEventRecord.related_entity_type,
            CorrelationEventRecord.related_entity_id,
        )
        .where(
            (
                (CorrelationEventRecord.source_entity_type == entity_type)
                & (CorrelationEventRecord.source_entity_id == entity_id)
            )
            | (
                (CorrelationEventRecord.related_entity_type == entity_type)
                & (CorrelationEventRecord.related_entity_id == entity_id)
            )
        )
        .order_by(CorrelationEventRecord.created_at.desc())
    )
    for (
        cid,
        etype,
        context,
        severity,
        created_at,
        c_entry_id,
        src_etype,
        src_eid,
        rel_etype,
        rel_eid,
    ) in corr_result.all():
        # Navigate to the "other" entity (the one that isn't the current entity)
        if str(src_eid) == str(entity_id) and src_etype == entity_type:
            nav_etype, nav_eid = rel_etype, rel_eid
        else:
            nav_etype, nav_eid = src_etype, src_eid
        events.append(
            {
                "entry_id": str(c_entry_id) if c_entry_id else None,
                "title": context,
                "url": None,
                "date": _dt(created_at),
                "event_type": "correlation",
                "severity": severity,
                "event_subtype": etype,
                "nav_context": {"entity_type": nav_etype, "entity_id": str(nav_eid)},
            }
        )

    # 3. Enrichment results for this entity
    from app.models.enrichment import EnrichmentResult

    enrich_result = await db.execute(
        select(
            EnrichmentResult.id,
            EnrichmentResult.source_type,
            EnrichmentResult.status,
            EnrichmentResult.enriched_at,
        )
        .where(
            EnrichmentResult.entity_type == entity_type,
            EnrichmentResult.entity_id == entity_id,
        )
        .order_by(EnrichmentResult.enriched_at.desc())
    )
    for eid, source_type, status, enriched_at in enrich_result.all():
        events.append(
            {
                "entry_id": None,
                "title": f"Enriched via {source_type} ({status})",
                "url": None,
                "date": _dt(enriched_at),
                "event_type": "enrichment",
                "event_subtype": source_type,
            }
        )

    # 4. Fetch entity object (used by later sections)
    entity_obj = await get_entity(db, entity_type, entity_id)

    # 5. Detection rules referencing this entity
    # Detection rules can reference entities via source_ttps,
    # source_cves (JSONB arrays), or source_actors, source_campaigns (UUID arrays)
    from sqlalchemy.dialects.postgresql import JSONB

    rule_filters = []
    if entity_type == "ttp":
        # source_ttps stores technique_id strings (e.g. "T1059"), not UUIDs
        technique_id = getattr(entity_obj, "technique_id", None)
        if technique_id:
            rule_filters.append(DetectionRule.source_ttps.op("@>")(type_coerce([technique_id], JSONB)))
    elif entity_type == "cve":
        # source_cves stores CVE ID strings (e.g. "CVE-2024-2961")
        cve_id_str = getattr(entity_obj, "cve_id", None)
        if cve_id_str:
            rule_filters.append(DetectionRule.source_cves.op("@>")(type_coerce([cve_id_str], JSONB)))
    elif entity_type == "campaign":
        # DetectionRule has carried source_campaigns since the model was
        # written; nothing read it until a campaign could own a timeline.
        rule_filters.append(DetectionRule.source_campaigns.any(entity_id))
    elif entity_type == "threat_actor":
        rule_filters.append(DetectionRule.source_actors.any(entity_id))
    elif entity_type == "malware":
        # Malware may be referenced via tags
        pass

    if rule_filters:
        rule_result = await db.execute(
            select(
                DetectionRule.id,
                DetectionRule.title,
                DetectionRule.rule_type,
                DetectionRule.severity,
                DetectionRule.created_at,
            )
            .where(or_(*rule_filters))
            .order_by(DetectionRule.created_at.desc())
        )
        for rid, title, rule_type, severity, created_at in rule_result.all():
            events.append(
                {
                    "entry_id": None,
                    "title": f"Detection rule created: {title} ({rule_type})",
                    "url": None,
                    "date": _dt(created_at),
                    "event_type": "detection_rule",
                    "severity": severity,
                    "event_subtype": rule_type,
                    "nav_context": {"url": f"/workbench/rule/{rid}"},
                }
            )

    # 6. Manual relationships involving this entity
    rel_query = (
        select(
            EntityRelationship.id,
            EntityRelationship.source_type,
            EntityRelationship.source_id,
            EntityRelationship.target_type,
            EntityRelationship.target_id,
            EntityRelationship.relationship_type,
            EntityRelationship.confidence,
            EntityRelationship.source,
            EntityRelationship.created_at,
        )
        .where(
            or_(
                (EntityRelationship.source_type == entity_type) & (EntityRelationship.source_id == entity_id),
                (EntityRelationship.target_type == entity_type) & (EntityRelationship.target_id == entity_id),
            )
        )
        .order_by(EntityRelationship.created_at.desc())
    )
    hidden_conf = hidden_relationship_confidences()
    if hidden_conf:
        rel_query = rel_query.where(EntityRelationship.confidence.notin_(hidden_conf))
    rel_result = await db.execute(rel_query)
    # Collect rows and resolve other-entity display names. Track whether the
    # viewed entity is the SOURCE (outbound: viewed <verb> other) so titles can
    # render the passive form when it's the object (inbound: other <verb> viewed).
    rel_rows = []
    other_ids_by_type: dict[str, set[uuid.UUID]] = {}
    for rid, src_type, src_id, tgt_type, tgt_id, rel_type, confidence, source, created_at in rel_result.all():
        is_outbound = str(src_id) == str(entity_id) and src_type == entity_type
        if is_outbound:
            other_type, other_id = tgt_type, tgt_id
        else:
            other_type, other_id = src_type, src_id
        rel_rows.append((other_type, other_id, rel_type, confidence, created_at, is_outbound))
        other_ids_by_type.setdefault(other_type, set()).add(other_id)

    # Batch-fetch display names keyed by (type, id)
    _NAME_ATTR = {
        "cve": "cve_id",
        "ttp": "technique_name",
    }
    _TYPE_LABEL = {
        "threat_actor": "actor",
        "malware": "malware",
        "ttp": "TTP",
        "cve": "CVE",
        "country": "country",
        "mitigation": "mitigation",
        "tool": "tool",
    }
    entity_name_map: dict[tuple[str, uuid.UUID], str] = {}
    for otype, oids in other_ids_by_type.items():
        if otype not in ENTITY_CONFIG:
            continue
        omodel = ENTITY_CONFIG[otype][0]
        name_attr = _NAME_ATTR.get(otype, "name")
        name_col = getattr(omodel, name_attr, None)
        if name_col is None:
            continue
        name_result = await db.execute(select(omodel.id, name_col).where(omodel.id.in_(list(oids))))
        for eid, ename in name_result.all():
            entity_name_map[(otype, eid)] = ename

    # (active, passive) verb forms, viewed entity as implicit subject:
    # outbound → "Uses malware “Pegasus”"; inbound → "Used by actor “NSO Group”".
    # Symmetric verbs read the same in both directions.
    _VERB_FORMS = {
        "uses": ("Uses", "Used by"),
        "exploits": ("Exploits", "Exploited by"),
        "targets": ("Targets", "Targeted by"),
        "attributed_to": ("Attributed to", "Attribution of"),
        "variant_of": ("Variant of", "Has variant"),
        "communicates_with": ("Communicates with", "Communicates with"),
        "delivers": ("Delivers", "Delivered by"),
        "drops": ("Drops", "Dropped by"),
        "hosts": ("Hosts", "Hosted by"),
        "related_to": ("Related to", "Related to"),
    }

    for other_type, other_id, rel_type, confidence, created_at, is_outbound in rel_rows:
        other_name = entity_name_map.get((other_type, other_id))
        type_label = _TYPE_LABEL.get(other_type, other_type.replace("_", " "))
        fallback = rel_type.replace("_", " ").capitalize()
        forms = _VERB_FORMS.get(rel_type, (fallback, fallback))
        verb = forms[0] if is_outbound else forms[1]
        if other_name:
            title = f"{verb} {type_label} \u201c{other_name}\u201d"
        else:
            title = f"{verb} ({type_label})"
        events.append(
            {
                "entry_id": None,
                "title": title,
                "url": None,
                "date": _dt(created_at),
                "event_type": "relationship",
                "event_subtype": rel_type,
                "nav_context": {"entity_type": other_type, "entity_id": str(other_id)},
            }
        )

    # 7. Campaign associations
    from app.models.campaign import Campaign, CampaignEntity

    camp_result = await db.execute(
        select(
            CampaignEntity.id,
            CampaignEntity.campaign_id,
            CampaignEntity.role,
            CampaignEntity.added_at,
            Campaign.name,
        )
        .join(Campaign, Campaign.id == CampaignEntity.campaign_id)
        .where(
            CampaignEntity.entity_type == entity_type,
            CampaignEntity.entity_id == entity_id,
        )
        .order_by(CampaignEntity.added_at.desc())
    )
    for ceid, camp_id, role, added_at, camp_name in camp_result.all():
        events.append(
            {
                "entry_id": None,
                "title": f"Added to campaign: {camp_name} (role: {role})",
                "url": None,
                "date": _dt(added_at),
                "event_type": "campaign",
                "event_subtype": role,
                "nav_context": {"url": f"/workbench/campaign/{camp_id}"},
            }
        )

    # Sort all events by date descending
    events.sort(key=lambda e: e.get("date") or "", reverse=True)
    return events


# ---------------------------------------------------------------------------
# Co-occurrence → EntityRelationship persistence
# ---------------------------------------------------------------------------

# Entity types valid for EntityRelationship records (must match model constraints)
_RELATABLE_TYPES = {"threat_actor", "malware", "ttp", "cve", "tool", "country"}

# Maps (source_type, target_type) → relationship_type for co-occurrence.
# Uses only values from EntityRelationship.relationship_type enum.
COOCCURRENCE_RELATIONSHIP_MAP: dict[tuple[str, str], str] = {
    ("threat_actor", "malware"): "uses",
    ("threat_actor", "ttp"): "uses",
    ("threat_actor", "cve"): "exploits",
    ("threat_actor", "country"): "targets",
    ("threat_actor", "tool"): "uses",
    ("malware", "ttp"): "uses",
    ("malware", "cve"): "exploits",
    ("malware", "country"): "targets",
    ("malware", "tool"): "related_to",
    ("cve", "ttp"): "related_to",
}

# Max entities per entry before we skip co-occurrence generation (avoid N^2 explosion)
_MAX_ENTITIES_PER_ENTRY = 50

# Speculative verbs that ride on the weakest evidence: a country "targets"
# edge or a generic "related_to" is asserted from a bare co-mention, and
# countries in particular show up as bystanders (victims, researcher locale,
# an actor's disguise). Hold these to the same strong-proximity bar as
# unmapped pairs so a loose cross-paragraph co-mention can't manufacture them.
_SOFT_COOCCURRENCE_VERBS = {"targets", "related_to"}


def _canonical_pair(
    type_a: str, id_a: uuid.UUID, type_b: str, id_b: uuid.UUID
) -> tuple[str, uuid.UUID, str, uuid.UUID]:
    """Return (source_type, source_id, target_type, target_id) in deterministic order.

    Ensures the same entity pair always maps to the same row regardless of
    which side we encounter first.
    """
    if (type_a, str(id_a)) <= (type_b, str(id_b)):
        return type_a, id_a, type_b, id_b
    return type_b, id_b, type_a, id_a


def _directed_pair(
    type_a: str, id_a: uuid.UUID, type_b: str, id_b: uuid.UUID
) -> tuple[str, uuid.UUID, str, uuid.UUID, str, bool]:
    """Orient an entity pair semantically and pick its relationship type.

    Returns (source_type, source_id, target_type, target_id, relationship_type,
    mapped). Direction comes from COOCCURRENCE_RELATIONSHIP_MAP — the map key is
    (source_type, target_type) read as "source <verb> target" (e.g. threat_actor
    -uses-> malware), so the stored row keeps that semantic direction regardless
    of encounter order. Unmapped pairs fall back to canonical (order-stable)
    direction with the symmetric "related_to" and mapped=False.
    """
    if (type_a, type_b) in COOCCURRENCE_RELATIONSHIP_MAP:
        return type_a, id_a, type_b, id_b, COOCCURRENCE_RELATIONSHIP_MAP[(type_a, type_b)], True
    if (type_b, type_a) in COOCCURRENCE_RELATIONSHIP_MAP:
        return type_b, id_b, type_a, id_a, COOCCURRENCE_RELATIONSHIP_MAP[(type_b, type_a)], True
    src_type, src_id, tgt_type, tgt_id = _canonical_pair(type_a, id_a, type_b, id_b)
    return src_type, src_id, tgt_type, tgt_id, "related_to", False


def _proximity_to_confidence(score: float) -> str | None:
    """Map a proximity score to a confidence level, or None to skip.

    Thresholds come from the same proximity settings the UI badges use, so
    tuning them in Settings moves confidence assignment and display together.
    """
    from app.config import settings as env_settings

    strong = float(env_settings.get("proximity_strong_threshold") or 0.7)
    moderate = float(env_settings.get("proximity_moderate_threshold") or 0.3)
    if score >= strong:
        return "probable"
    if score >= moderate:
        return "possible"
    return None  # too far apart — skip


async def _passes_story_floor(db: AsyncSession, evidence_entry_ids: list[uuid.UUID]) -> bool:
    """Story floor for possible→probable promotion.

    Digest articles satisfy the count+feeds rule by coincidence; requiring at
    least one similarity cluster of 2+ evidence entries means some story
    actually asserted the pair more than once. Passes when the feature is off
    or the evidence has too few embeddings to judge (degrade, don't block).
    """
    from app.intelligence.evidence_structure import has_story_cluster, structure_enabled

    if not structure_enabled():
        return True
    verdict = await has_story_cluster(db, evidence_entry_ids)
    return verdict is not False


async def _passes_theme_floor(db: AsyncSession, evidence_entry_ids: list[uuid.UUID]) -> bool:
    """Narrative floor for possible→probable promotion.

    The day briefing already grouped each day's articles under headings. If
    every one of this pair's placed evidence articles sits under a single
    heading, the pair was asserted by one reporting wave told several ways —
    the count+feeds rule can't tell that apart from independent corroboration,
    and this can.

    Same degradation contract as the story floor: passes when the gate is off,
    and passes when too little of the evidence was ever placed to judge.
    """
    from app.intelligence.narrative_themes import spans_multiple_themes, theme_gating_enabled

    if not theme_gating_enabled():
        return True
    verdict = await spans_multiple_themes(db, evidence_entry_ids)
    return verdict is not False


async def create_cooccurrence_relationships(
    db: AsyncSession,
    entry_id: uuid.UUID,
) -> int:
    """Create EntityRelationship records for entity pairs co-occurring in an entry.

    Queries all junction tables for the given entry, computes pairwise proximity
    scores, and upserts EntityRelationship rows with source='co_occurrence'.

    Returns the count of new or updated relationships.
    """
    # 1. Gather all entities linked to this entry with their paragraph_indices
    entity_refs: list[tuple[str, uuid.UUID, list[int] | None]] = []

    for etype, (_, junction, fk_col) in ENTITY_CONFIG.items():
        if etype not in _RELATABLE_TYPES:
            continue
        result = await db.execute(select(fk_col, junction.paragraph_indices).where(junction.entry_id == entry_id))
        for eid, para_indices in result.all():
            entity_refs.append((etype, eid, para_indices))

    if len(entity_refs) < 2:
        return 0

    # Cap to avoid N^2 explosion on entity-dense entries
    if len(entity_refs) > _MAX_ENTITIES_PER_ENTRY:
        logger.info(
            "Entry %s has %d entities, exceeding cap of %d — skipping co-occurrence",
            entry_id,
            len(entity_refs),
            _MAX_ENTITIES_PER_ENTRY,
        )
        return 0

    # 2. Generate pairwise relationships
    from app.config import settings as env_settings

    strong_threshold = float(env_settings.get("proximity_strong_threshold") or 0.7)
    promote_count = int(env_settings.get("relationship_evidence_promote_count") or 3)
    upsert_count = 0

    for (type_a, id_a, para_a), (type_b, id_b, para_b) in combinations(entity_refs, 2):
        # Skip same-type pairs (e.g. two TTPs co-occurring isn't meaningful)
        if type_a == type_b:
            continue

        score = _compute_proximity_score(para_a, para_b)
        confidence = _proximity_to_confidence(score)
        if confidence is None:
            continue

        src_type, src_id, tgt_type, tgt_id, rel_type, mapped = _directed_pair(type_a, id_a, type_b, id_b)
        # Unmapped pairs (e.g. cve+country) have no semantic verb; a generic
        # related_to edge is only worth keeping when the co-mention is
        # exceptionally close — otherwise it's noise.
        if not mapped and score < strong_threshold:
            continue
        # Speculative mapped verbs (country "targets", "related_to") get the
        # same strong-proximity bar — a moderate co-mention isn't enough
        # evidence to assert the claim.
        if rel_type in _SOFT_COOCCURRENCE_VERBS and score < strong_threshold:
            continue
        # Pairs outside the semantic allowlist (country↔cve, country↔tool, …)
        # are never stored, no matter how close the co-mention.
        if not is_allowed_relationship(src_type, rel_type, tgt_type):
            continue

        # Check if relationship already exists
        existing = await db.execute(
            select(EntityRelationship).where(
                EntityRelationship.source_type == src_type,
                EntityRelationship.source_id == src_id,
                EntityRelationship.target_type == tgt_type,
                EntityRelationship.target_id == tgt_id,
                EntityRelationship.relationship_type == rel_type,
            )
        )
        rel = existing.scalar_one_or_none()

        if rel is not None:
            # Analyst rejected this relationship — never resurrect or accumulate
            # evidence on it from co-occurrence.
            if rel.source == "analyst_rejected":
                continue
            # Update existing: append evidence, potentially upgrade confidence
            if entry_id not in (rel.evidence_entry_ids or []):
                rel.evidence_entry_ids = (rel.evidence_entry_ids or []) + [entry_id]
            # Upgrade confidence only for co_occurrence-sourced relationships:
            # one exceptionally close co-mention or `promote_count` distinct
            # evidence entries — AND corroboration across ≥2 distinct feeds, so
            # a single chatty source can't self-promote. Two narrative floors
            # then ask whether the evidence is really independent: one story
            # cluster (embeddings) and one day-briefing heading spread. Edges
            # the adjudicator ruled coincidental stay at possible regardless.
            if (
                rel.source == "co_occurrence"
                and rel.confidence == "possible"
                and rel.adjudication_verdict != "coincidental"
                and (confidence == "probable" or len(rel.evidence_entry_ids or []) >= promote_count)
            ):
                feed_count = (
                    await db.execute(
                        select(func.count(func.distinct(Entry.feed_id))).where(
                            Entry.id.in_(rel.evidence_entry_ids or [])
                        )
                    )
                ).scalar() or 0
                if (
                    feed_count >= 2
                    and await _passes_story_floor(db, rel.evidence_entry_ids or [])
                    and await _passes_theme_floor(db, rel.evidence_entry_ids or [])
                ):
                    rel.confidence = "probable"
        else:
            # New edges always start at "possible" — probable is earned by
            # corroboration, never granted on first sight.
            db.add(
                EntityRelationship(
                    source_type=src_type,
                    source_id=src_id,
                    target_type=tgt_type,
                    target_id=tgt_id,
                    relationship_type=rel_type,
                    confidence="possible",
                    source="co_occurrence",
                    evidence_entry_ids=[entry_id],
                )
            )

        upsert_count += 1

    if upsert_count:
        await db.flush()

    return upsert_count


# Type preference when collapsing name-twins: an actor and a malware family that
# share a display name (the Qilin RaaS *group* vs. the Qilin ransomware *payload*)
# model one real-world subject. Keep the higher-signal type as the representative.
_TWIN_TYPE_PRIORITY = {"threat_actor": 0, "malware": 1, "tool": 2, "ttp": 3, "cve": 4, "country": 5}


def _collapse_name_twins(
    entities: set[tuple[str, uuid.UUID]],
    labels: dict[tuple[str, uuid.UUID], str],
) -> list[tuple[str, uuid.UUID]]:
    """Collapse entities sharing a normalized display name to one representative.

    Without this an actor/malware twin (e.g. Qilin) counts as two shared
    entities, letting a single subject satisfy the >=2-shared-entities
    convergence bar on its own and rendering as "Qilin, Qilin".
    """
    best: dict[str, tuple[str, uuid.UUID]] = {}
    for etype, eid in entities:
        key = (labels.get((etype, eid)) or str(eid)).strip().lower()
        cur = best.get(key)
        if cur is None or _TWIN_TYPE_PRIORITY.get(etype, 99) < _TWIN_TYPE_PRIORITY.get(cur[0], 99):
            best[key] = (etype, eid)
    return list(best.values())


async def temporal_clusters(
    db: AsyncSession,
    days: int = 7,
    window_hours: int = 24,
    min_shared_entities: int = 2,
    limit: int = 20,
    user_id: uuid.UUID | None = None,
) -> list[dict]:
    """Find temporal clusters: entries within N-hour windows sharing 2+ entities.

    Returns clusters sorted by strength (shared entity count * entry count).
    Each cluster has entries, shared entities, and time range.
    """
    from collections import defaultdict
    from datetime import timedelta

    from app.models.entry_state import UserEntryState
    from app.models.feed import Feed

    cutoff = datetime.now(UTC) - timedelta(days=days)

    # Gather all entry-entity pairs within the time window
    # We query each junction table and collect (entry_id, entity_type, entity_id, entity_label)
    entry_entities: dict[uuid.UUID, list[tuple[str, uuid.UUID, str]]] = defaultdict(list)
    entry_meta: dict[uuid.UUID, dict] = {}

    # Fetch entries with published_at in range, excluding user's read entries
    q = (
        select(
            Entry.id,
            Entry.title,
            Entry.published_at,
            Entry.url,
            Entry.feed_id,
            Entry.priority_score,
            Feed.title.label("feed_title"),
        )
        .join(Feed, Feed.id == Entry.feed_id)
        .where(Entry.published_at >= cutoff)
        .where(Entry.published_at.isnot(None))
    )
    if user_id is not None:
        read_entry_ids = (
            select(UserEntryState.entry_id)
            .where(UserEntryState.user_id == user_id)
            .where(UserEntryState.is_read == True)  # noqa: E712
        )
        q = q.where(Entry.id.notin_(read_entry_ids))
    q = q.order_by(Entry.published_at.desc()).limit(5000)

    entries_result = await db.execute(q)
    for eid, title, pub_at, url, feed_id, priority_score, feed_title in entries_result.all():
        entry_meta[eid] = {
            "id": str(eid),
            "title": title,
            "published_at": _dt(pub_at),
            "url": url,
            "feed_id": str(feed_id),
            "priority_score": float(priority_score) if priority_score is not None else 0.0,
            "feed_title": feed_title,
        }

    if not entry_meta:
        return []

    entry_ids = list(entry_meta.keys())

    # Load entity links for these entries (top 4 entity types)
    entity_configs = [
        ("ttp", EntryTTP, EntryTTP.ttp_id, EntryTTP.entry_id, TTP, "technique_id"),
        (
            "threat_actor",
            EntryThreatActor,
            EntryThreatActor.threat_actor_id,
            EntryThreatActor.entry_id,
            ThreatActor,
            "name",
        ),
        ("malware", EntryMalware, EntryMalware.malware_family_id, EntryMalware.entry_id, MalwareFamily, "name"),
    ]

    entity_labels: dict[tuple[str, uuid.UUID], str] = {}

    for etype, junction, entity_fk, entry_fk, model, label_attr in entity_configs:
        result = await db.execute(select(entry_fk, entity_fk).where(entry_fk.in_(entry_ids)))
        entity_ids_needed = set()
        pairs = []
        for e_id, ent_id in result.all():
            pairs.append((e_id, ent_id))
            entity_ids_needed.add(ent_id)

        if entity_ids_needed:
            label_result = await db.execute(
                select(model.id, getattr(model, label_attr)).where(model.id.in_(entity_ids_needed))
            )
            for model_id, label in label_result.all():
                entity_labels[(etype, model_id)] = label

        for e_id, ent_id in pairs:
            label = entity_labels.get((etype, ent_id), str(ent_id))
            entry_entities[e_id].append((etype, ent_id, label))

    # Build entity-to-entries index
    entity_to_entries: dict[tuple[str, uuid.UUID], list[uuid.UUID]] = defaultdict(list)
    for e_id, entities in entry_entities.items():
        for etype, ent_id, _ in entities:
            entity_to_entries[(etype, ent_id)].append(e_id)

    # Find entry pairs that share entities AND are within the time window
    from itertools import combinations

    cluster_map: dict[frozenset[uuid.UUID], set[tuple[str, uuid.UUID]]] = defaultdict(set)

    for (etype, ent_id), linked_entries in entity_to_entries.items():
        if len(linked_entries) < 2:
            continue

        # Check temporal proximity between entry pairs
        for a, b in combinations(linked_entries, 2):
            meta_a = entry_meta.get(a)
            meta_b = entry_meta.get(b)
            if not meta_a or not meta_b:
                continue
            # Different feeds only (same-feed co-occurrence is expected)
            if meta_a["feed_id"] == meta_b["feed_id"]:
                continue

            dt_a = meta_a["published_at"]
            dt_b = meta_b["published_at"]
            if not dt_a or not dt_b:
                continue

            try:
                ta = datetime.fromisoformat(dt_a)
                tb = datetime.fromisoformat(dt_b)
            except (ValueError, TypeError):
                continue

            if abs((ta - tb).total_seconds()) <= window_hours * 3600:
                pair = frozenset([a, b])
                cluster_map[pair].add((etype, ent_id))

    # Merge overlapping pairs into clusters
    # Simple approach: group pairs sharing entries
    clusters: list[dict] = []
    seen_pairs: set[frozenset[uuid.UUID]] = set()

    # Sort pairs by shared entity count descending
    sorted_pairs = sorted(cluster_map.items(), key=lambda x: len(x[1]), reverse=True)

    for pair, shared_entities in sorted_pairs:
        if len(_collapse_name_twins(shared_entities, entity_labels)) < min_shared_entities:
            continue
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        # Expand cluster: find other pairs that share entries with this pair
        cluster_entries = set(pair)
        cluster_shared = set(shared_entities)

        for other_pair, other_shared in sorted_pairs:
            if other_pair in seen_pairs:
                continue
            if cluster_entries & other_pair:  # overlap
                cluster_entries |= other_pair
                cluster_shared &= other_shared  # intersection of shared entities
                seen_pairs.add(other_pair)

        # Collapse actor/malware name-twins so one subject counts once — for the
        # threshold, the displayed chips, and the strength score alike.
        collapsed_shared = _collapse_name_twins(cluster_shared, entity_labels)
        if len(collapsed_shared) < min_shared_entities:
            continue

        entries_in_cluster = []
        for e_id in cluster_entries:
            meta = entry_meta.get(e_id)
            if meta:
                entries_in_cluster.append(meta)

        entries_in_cluster.sort(key=lambda e: e.get("published_at") or "", reverse=True)

        shared_list = [
            {"entity_type": etype, "entity_id": str(eid), "label": entity_labels.get((etype, eid), str(eid))}
            for etype, eid in collapsed_shared
        ]

        dates = [e["published_at"] for e in entries_in_cluster if e.get("published_at")]
        strength = len(collapsed_shared) * len(entries_in_cluster)

        clusters.append(
            {
                "entries": entries_in_cluster,
                "shared_entities": shared_list,
                "time_range": {"start": min(dates) if dates else None, "end": max(dates) if dates else None},
                "strength": strength,
                "entry_count": len(entries_in_cluster),
                "shared_entity_count": len(collapsed_shared),
            }
        )

    clusters.sort(key=lambda c: c["strength"], reverse=True)
    return clusters[:limit]
