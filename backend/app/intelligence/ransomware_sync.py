"""Ransomware leak-site sync: fetch postings, resolve entities, upsert victims +
disclosures (planning/ransomware-victim-tracker.md §5.2, Option A).

Kept self-contained (separate from external_feeds.py) so the tracker owns its dedup
and never leaks into the article stream. The Celery wrapper + JOB_REGISTRY entry live
in app/workers/intel_feed_tasks.py; this module is the pure async orchestrator.

Resolution rules:
  - group   → ThreatActor via resolve_entity_creation (tombstones/gates/aliases),
              stamped actor_type='ransomware' when it has none yet.
  - country → Country by ISO code (ransomware.live sends alpha-2), else name/alias.
  - sector  → sectors.normalize_sector(activity).
  - victim  → dedup on domain first, else name/alias; one org, many disclosures.
Disclosures dedup on (source, guid); an org re-listed by a second group stays one
victim row with two disclosures.
"""

import logging
import re
from collections import defaultdict
from datetime import UTC, datetime

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.adapters.base import ParsedEntry
from app.adapters.ransomware_live import RansomwareLiveAdapter, _parse_dt
from app.api.events import publish_event
from app.enrichment.gateway import JOB_TOKEN_WAIT, SOURCE_REFUSALS, GatewayUnavailable, SourceGateway
from app.intelligence.entity_dedup import find_entity_by_name_or_alias
from app.intelligence.entity_resolution import gate_aliases, resolve_entity_creation
from app.intelligence.sectors import normalize_sector, sector_label, sector_uuid
from app.models.country import Country
from app.models.ransomware import RansomwareVictim, VictimDisclosure
from app.models.threat_actor import ThreatActor
from app.models.user_entity_watch import UserEntityWatch
from app.services.claim_provenance import record_claim

logger = logging.getLogger(__name__)

RANSOMWARE_LIVE_GROUPS_URL = "https://api.ransomware.live/v2/groups"

# Trailing version token on a leak-site group slug (lockbit2, lockbit3, lockbit3_fs,
# lockbit5) — stripped to produce a base-name ALIAS CANDIDATE so the existing resolver
# can fold versions into the base group (e.g. 'lockbit' → your LockBit actor). This
# only generates a candidate key; resolve_entity_creation still decides the match.
_VERSION_SUFFIX = re.compile(r"[\s_-]*v?\d+(?:[\s_-]?fs|[\s_-]?v\d+)?$", re.IGNORECASE)


def _deversion(name: str) -> str | None:
    """A base-name candidate with any trailing version token removed, or None if
    unchanged / too short to be a distinct signal."""
    base = _VERSION_SUFFIX.sub("", name.strip()).strip()
    return base if base and base.lower() != name.strip().lower() and len(base) >= 4 else None


async def fetch_group_catalog(gateway: SourceGateway) -> dict[str, dict]:
    """Slug → {'name', 'altname'} from ransomware.live /v2/groups. Provides the
    proper display name and 'also known as' alias the resolver dedups on. Rate-limited
    (1/min) so it's fetched once per sync; on any failure returns {} and resolution
    falls back to the slug (still de-versioned + alias-unioned)."""
    catalog: dict[str, dict] = {}
    try:
        async with gateway.client(timeout=60.0) as client:
            resp = await client.get(RANSOMWARE_LIVE_GROUPS_URL)
        if resp.status_code != 200:
            logger.warning("ransomware.live /v2/groups returned %s — resolving on slugs only", resp.status_code)
            return {}
        rows = resp.json()
    except (httpx.HTTPError, ValueError):
        logger.warning("ransomware.live /v2/groups fetch failed — resolving on slugs only", exc_info=True)
        return {}
    if not isinstance(rows, list):
        return {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        slug = (row.get("url") or "").rstrip("/").split("/")[-1].strip().lower()
        if not slug:
            continue
        catalog[slug] = {
            "name": (row.get("name") or "").strip() or slug,
            "altname": (row.get("altname") or "").strip() or None,
        }
    logger.info("ransomware.live group catalog: %d groups", len(catalog))
    return catalog


def _default_adapters(gateway: SourceGateway) -> list:
    """Enabled leak-site source adapters. Add sibling adapters here as sources are
    confirmed (eCrime.ch, broker channels) — the sync loop is source-agnostic."""
    return [RansomwareLiveAdapter(gateway)]


async def _last_posted_at(db: AsyncSession, source: str) -> datetime | None:
    """High-water mark for incremental polling: newest disclosure we already hold for
    this source. Stateless (no Redis/setting) — the (source, guid) unique constraint
    is the real dedup; this only trims re-fetched work."""
    return await db.scalar(select(func.max(VictimDisclosure.posted_at)).where(VictimDisclosure.source == source))


async def _resolve_group(
    db: AsyncSession,
    group_slug: str,
    source: str,
    stats: dict,
    new_group_ids: list[str],
    catalog: dict[str, dict],
) -> ThreatActor | None:
    """Resolve a leak-site group slug to a ThreatActor through the app's canonical
    resolver (app/intelligence/entity_resolution.resolve_entity_creation), feeding it
    the group's proper name + aliases so its existing exact/normalized/known-alias
    matchers reuse tracked actors instead of spawning duplicates.

    Enrichment: ransomware.live's slug (e.g. 'alphv', 'lockbit3') is mapped via the
    /v2/groups catalog to a proper name + altname ('blackcat'), and a de-versioned
    candidate ('lockbit') is added — so 'alphv'→BlackCat and 'lockbit3'→LockBit fold
    into existing actors. On a match we union those aliases (gate_aliases) so the actor
    learns the slug for next time. Returns None (disclosure keeps group_name_raw only)
    for junk names or when the resolver blocks/holds/tombstones.
    """
    slug = (group_slug or "").strip()
    if len(slug) < 2:
        # Junk feed value (e.g. 'J'); keep the raw name on the disclosure, no actor.
        return None

    meta = catalog.get(slug.lower(), {})
    proper = meta.get("name") or slug
    # Alias candidates the resolver matches on (and that a matched actor then learns):
    # the raw slug, ransomware.live's altname, and a de-versioned base name. Deduped;
    # gate_aliases drops any that collide with the matched actor's own name.
    candidates: list[str] = []
    for cand in (slug, meta.get("altname"), _deversion(slug)):
        c = (cand or "").strip()
        if c and c.lower() not in {x.lower() for x in candidates}:
            candidates.append(c)

    decision = await resolve_entity_creation(db, "threat_actor", proper, candidates, source=source)
    actor = decision.entity
    if actor is not None:
        if actor.actor_type is None:
            actor.actor_type = "ransomware"
            await record_claim(
                db,
                entity_type=entity_types.THREAT_ACTOR,
                entity_id=actor.id,
                field="actor_type",
                value="ransomware",
                source_kind="external_feed",
                source_ref=source,
            )
        # Teach the matched actor the slug/altname so future runs match by alias.
        gated = await gate_aliases(db, "threat_actor", actor.name, candidates, entity_id=actor.id, source=source)
        merged = sorted(set(actor.aliases or []) | set(gated))
        if merged != sorted(set(actor.aliases or [])):
            actor.aliases = merged
        return actor
    if decision.action != "create":
        # blocked / held / tombstone — record the raw name on the disclosure, no link.
        return None
    actor = ThreatActor(
        name=proper,
        aliases=await gate_aliases(db, "threat_actor", proper, candidates, source=source),
        actor_type="ransomware",
        metadata_={"actor_class": "ransomware", "source": source},
    )
    db.add(actor)
    await db.flush()
    await record_claim(
        db,
        entity_type=entity_types.THREAT_ACTOR,
        entity_id=actor.id,
        field="actor_type",
        value="ransomware",
        source_kind="external_feed",
        source_ref=source,
    )
    new_group_ids.append(str(actor.id))
    stats["new_groups"] += 1
    return actor


async def _resolve_country_id(db: AsyncSession, code: str | None):
    """ransomware.live sends an ISO alpha-2 code (e.g. 'SE'). Match iso_code first,
    then fall back to name/alias (some records carry a full country name)."""
    if not code:
        return None
    code = code.strip()
    if not code:
        return None
    cid = await db.scalar(select(Country.id).where(func.lower(Country.iso_code) == code.lower()))
    if cid is not None:
        return cid
    hit = await find_entity_by_name_or_alias(db, Country, code)
    return hit.id if hit is not None else None


async def _resolve_victim(
    db: AsyncSession,
    md: dict,
    country_id,
    sector: str | None,
    posted_at: datetime,
    stats: dict,
    new_victim_ids: list[str],
) -> RansomwareVictim:
    """Dedup target: match an existing org on domain first (strongest signal), then
    name/alias; otherwise create. Backfills missing domain/country/sector on match."""
    name = md["victim"]
    domain = md.get("domain")

    victim = None
    if domain:
        victim = await db.scalar(select(RansomwareVictim).where(func.lower(RansomwareVictim.domain) == domain.lower()))
    if victim is None:
        victim = await find_entity_by_name_or_alias(db, RansomwareVictim, name)

    if victim is None:
        victim = RansomwareVictim(
            name=name,
            domain=domain,
            country_id=country_id,
            sector=sector,
            first_seen_at=posted_at,
            last_seen_at=posted_at,
            disclosure_count=0,
            metadata_={},
        )
        db.add(victim)
        await db.flush()
        new_victim_ids.append(str(victim.id))
        stats["new_victims"] += 1
    else:
        if not victim.domain and domain:
            victim.domain = domain
        if not victim.country_id and country_id:
            victim.country_id = country_id
        if not victim.sector and sector:
            victim.sector = sector
        stats["updated_victims"] += 1
    return victim


async def _ingest_posting(
    db: AsyncSession,
    entry: ParsedEntry,
    stats: dict,
    new_group_ids: list[str],
    new_victim_ids: list[str],
    new_disclosures: list[dict],
    catalog: dict[str, dict],
) -> None:
    md = entry.metadata
    source = md["source"]
    guid = entry.guid

    # Dedup: one posting event per (source, guid).
    existing = await db.scalar(
        select(VictimDisclosure.id).where(VictimDisclosure.source == source, VictimDisclosure.guid == guid)
    )
    if existing is not None:
        stats["skipped_existing"] += 1
        return

    group_name = md.get("group")
    group = await _resolve_group(db, group_name, source, stats, new_group_ids, catalog) if group_name else None
    country_id = await _resolve_country_id(db, md.get("country"))
    sector = normalize_sector(md.get("activity"))
    posted_at = entry.published_at or datetime.now(UTC)

    victim = await _resolve_victim(db, md, country_id, sector, posted_at, stats, new_victim_ids)

    disclosure = VictimDisclosure(
        victim_id=victim.id,
        group_id=group.id if group is not None else None,
        group_name_raw=group_name,
        leak_site_url=md.get("claim_url"),
        posted_at=posted_at,
        published_at=_parse_dt(md.get("published")),
        country_id=country_id,
        sector=sector,
        claimed_data=md.get("claimed_data"),
        source=source,
        guid=guid,
        metadata_={"attackdate": md.get("attackdate"), "activity": md.get("activity")},
    )
    db.add(disclosure)
    await db.flush()

    # Denormalized aggregates on the org.
    victim.disclosure_count = (victim.disclosure_count or 0) + 1
    if posted_at > victim.last_seen_at:
        victim.last_seen_at = posted_at
    if posted_at < victim.first_seen_at:
        victim.first_seen_at = posted_at
    stats["new_disclosures"] += 1

    # Capture the fields watchlist alerting needs (JSON-serializable, no post-commit
    # lazy loads). Emitted after the source commits.
    new_disclosures.append(
        {
            "disclosure_id": str(disclosure.id),
            "victim_id": str(victim.id),
            "victim_name": victim.name,
            "group_id": str(group.id) if group is not None else None,
            "group_name": group.name if group is not None else group_name,
            "sector": sector,
            "sector_label": sector_label(sector) if sector else None,
            "country_id": str(country_id) if country_id else None,
            "posted_at": posted_at.isoformat(),
            "leak_site_url": md.get("claim_url"),
            "source": source,
        }
    )


async def emit_watchlist_alerts(db: AsyncSession, new_disclosures: list[dict]) -> int:
    """Push a real-time SSE alert for each fresh disclosure that hits a watched org,
    watched ransomware group, or a watched sector (my_sectors).

    This is the disclosure-level counterpart to the entry-pipeline `entity_watchlisted`
    automation condition — the automation engine is Entry-typed and can't see
    VictimDisclosure rows, so a watch here IS the subscription (no rule to configure).
    Org, group and sector watches are all per-user (UserEntityWatch → publish_event(user)).
    Delivered via the same Redis/SSE bus as keyword_match and correlation_event alerts.
    Never raises — alerting must not fail a sync.
    """
    if not new_disclosures:
        return 0

    victim_ids = {d["victim_id"] for d in new_disclosures}
    group_ids = {d["group_id"] for d in new_disclosures if d["group_id"]}

    sector_ids = {sector_uuid(d["sector"]): d["sector"] for d in new_disclosures if d.get("sector")}

    watchers_by_victim: dict[str, set[str]] = defaultdict(set)
    watchers_by_group: dict[str, set[str]] = defaultdict(set)
    watchers_by_sector: dict[str, set[str]] = defaultdict(set)
    try:
        rows = (
            await db.execute(
                select(UserEntityWatch.created_by, UserEntityWatch.entity_type, UserEntityWatch.entity_id).where(
                    UserEntityWatch.mode == "watch",
                    UserEntityWatch.entity_type.in_(["ransomware_victim", "threat_actor", "sector"]),
                )
            )
        ).all()
    except Exception:
        logger.exception("ransomware alerts: failed to load watches")
        return 0
    for created_by, etype, eid in rows:
        sid = str(eid)
        if etype == "ransomware_victim" and sid in victim_ids:
            watchers_by_victim[sid].add(str(created_by))
        elif etype == "threat_actor" and sid in group_ids:
            watchers_by_group[sid].add(str(created_by))
        elif etype == "sector" and eid in sector_ids:
            watchers_by_sector[sector_ids[eid]].add(str(created_by))

    sent = 0
    for d in new_disclosures:
        # Per-user hits, one event per user: org beats group beats sector as the reason.
        reason_by_user: dict[str, str] = {}
        for uid in watchers_by_sector.get(d.get("sector") or "", ()):
            reason_by_user[uid] = "watched sector"
        for uid in watchers_by_group.get(d["group_id"] or "", ()):
            reason_by_user[uid] = "watched group"
        for uid in watchers_by_victim.get(d["victim_id"], ()):
            reason_by_user[uid] = "watched org"
        for uid, reason in reason_by_user.items():
            publish_event(uid, "ransomware_disclosure", {**d, "reason": reason})
            sent += 1
    if sent:
        logger.info("ransomware alerts: emitted %d watchlist SSE events", sent)
    return sent


async def sync_ransomware_victims(
    db: AsyncSession,
    since: datetime | None = None,
    adapters: list | None = None,
    catalog: dict[str, dict] | None = None,
) -> dict:
    """Fetch recent leak-site postings from every enabled source and upsert
    victims + disclosures. Commits per source. Returns a stats dict; ``new_group_ids``
    lets the caller refresh the autolinker vocabulary. ``catalog`` (slug→name/altname)
    is fetched from /v2/groups when omitted; pass ``{}`` to resolve on slugs only."""
    stats = {
        "new_disclosures": 0,
        "new_victims": 0,
        "updated_victims": 0,
        "new_groups": 0,
        "skipped_existing": 0,
        "errors": 0,
        "watchlist_alerts": 0,
        "stopped": None,
    }
    new_group_ids: list[str] = []
    new_victim_ids: list[str] = []
    new_disclosures: list[dict] = []

    from app.enrichment.pipeline import gateway_for

    gateway, _ = await gateway_for(db, "ransomware_live", max_wait=JOB_TOKEN_WAIT)

    # Group name/alias catalog (fetched once — the endpoint is rate-limited 1/min) so
    # the resolver can fold slugs into tracked actors by alias.
    if catalog is None:
        try:
            catalog = await fetch_group_catalog(gateway)
        except SOURCE_REFUSALS as e:
            logger.warning("ransomware sync skipped: %s", e)
            return {**stats, "stopped": e.status, "new_group_ids": [], "new_victim_ids": []}

    for adapter in adapters or _default_adapters(gateway):
        source = getattr(adapter, "SOURCE", adapter.__class__.__name__)
        cutoff = since if since is not None else await _last_posted_at(db, source)
        try:
            _meta, entries = await adapter.fetch_entries({}, cutoff)
        except SOURCE_REFUSALS as e:
            logger.warning("ransomware sync: %s refused, skipping it this run: %s", source, e)
            stats["stopped"] = e.status
            continue
        except GatewayUnavailable:
            raise
        except Exception:
            logger.exception("ransomware sync: fetch failed for source=%s", source)
            stats["errors"] += 1
            continue

        for entry in entries:
            try:
                await _ingest_posting(db, entry, stats, new_group_ids, new_victim_ids, new_disclosures, catalog)
            except Exception:
                logger.exception("ransomware sync: failed to ingest posting from source=%s", source)
                stats["errors"] += 1
        await db.commit()

    # Real-time watchlist alerts for the freshly-committed disclosures.
    stats["watchlist_alerts"] = await emit_watchlist_alerts(db, new_disclosures)

    logger.info(
        "ransomware sync: %d disclosures, %d new victims, %d updated, %d new groups, %d skipped, %d errors",
        stats["new_disclosures"],
        stats["new_victims"],
        stats["updated_victims"],
        stats["new_groups"],
        stats["skipped_existing"],
        stats["errors"],
    )
    return {**stats, "new_group_ids": new_group_ids, "new_victim_ids": new_victim_ids}
