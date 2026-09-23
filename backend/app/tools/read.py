"""Read Operations tools."""

import uuid
from datetime import UTC

from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters import _ADAPTERS, _EXTENDED_ADAPTERS
from app.intelligence.correlation import ENTITY_CONFIG
from app.models.campaign import Campaign
from app.models.correlation_event import CorrelationEventRecord as CorrelationEvent
from app.models.cve import CVE
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.intelligence_requirement import IntelligenceRequirement
from app.models.malware_family import MalwareFamily
from app.models.telemetry_source import TelemetrySource
from app.models.threat_actor import ThreatActor
from app.models.ttp import TTP
from app.schemas.intelligence import RULE_TYPE_PATTERN
from app.tools import _tool

# Rule formats derived from the canonical validation pattern so they can't drift.
_RULE_TYPES = sorted(RULE_TYPE_PATTERN.strip("^$()").split("|"))

# All registered feed adapter types, derived from the adapter registry.
_FEED_TYPES = sorted({*_ADAPTERS, *_EXTENDED_ADAPTERS})

# Response key per entity type for entry-level intelligence payloads
# (ENTITY_CONFIG in app.intelligence.correlation is the canonical junction map).
_ENTITY_RESULT_KEYS = {
    "ttp": "ttps",
    "cve": "cves",
    "threat_actor": "threat_actors",
    "malware": "malware",
    "country": "countries",
    "tool": "tools",
    "vendor": "vendors",
    "product": "products",
    "mitigation": "mitigations",
    "cwe": "cwes",
}


def _entity_result_key(entity_type: str) -> str:
    return _ENTITY_RESULT_KEYS.get(entity_type, f"{entity_type}s")


def _brief_entity(entity_type: str, ent) -> dict:
    """Compact serialization of a linked entity for entry/campaign payloads."""
    if entity_type == "ttp":
        return {"id": str(ent.id), "technique_id": ent.technique_id, "name": ent.technique_name, "tactic": ent.tactic}
    if entity_type == "cve":
        return {"id": str(ent.id), "cve_id": ent.cve_id, "cvss": ent.cvss_score, "severity": ent.severity}
    if entity_type == "cwe":
        return {"id": str(ent.id), "cwe_id": ent.cwe_id, "name": ent.name, "abstraction": ent.abstraction}
    if entity_type == "observable":
        return {"id": str(ent.id), "kind": ent.kind, "value": ent.value, "name": ent.label or ent.value}
    return {"id": str(ent.id), "name": getattr(ent, "name", None)}


@_tool(
    name="get_entry",
    description=(
        "Fetch a single RSS entry by ID with full content and all extracted intelligence: "
        "TTPs, CVEs, CWEs, threat actors, malware, tools, vendors, products, countries, and mitigations."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID"},
        },
        "required": ["entry_id"],
    },
)
async def _get_entry(db: AsyncSession, user_id: uuid.UUID, entry_id: str) -> dict:
    eid = uuid.UUID(entry_id)
    result = await db.execute(select(Entry).where(Entry.id == eid))
    entry = result.scalar_one_or_none()
    if not entry:
        return {"error": "Entry not found"}

    content = entry.content_text or entry.content_html or ""
    if len(content) > 8000:
        content = content[:8000] + "\n...[truncated]"

    payload = {
        "id": str(entry.id),
        "title": entry.title,
        "url": entry.url,
        "author": entry.author,
        "published_at": str(entry.published_at) if entry.published_at else None,
        "content": content,
        "summary": entry.summary,
    }
    # Every entity junction from the canonical map (correlation.ENTITY_CONFIG).
    for etype, (model, junction, entity_fk) in ENTITY_CONFIG.items():
        q = await db.execute(select(model).join(junction, entity_fk == model.id).where(junction.entry_id == eid))
        payload[_entity_result_key(etype)] = [_brief_entity(etype, ent) for ent in q.scalars()]
    return payload


@_tool(
    name="get_feed_entries",
    description="List recent entries from a specific feed.",
    input_schema={
        "properties": {
            "feed_id": {"type": "string", "description": "Feed UUID"},
            "limit": {"type": "integer", "default": 20},
        },
        "required": ["feed_id"],
    },
)
async def _get_feed_entries(db: AsyncSession, user_id: uuid.UUID, feed_id: str, limit: int = 20) -> dict:
    fid = uuid.UUID(feed_id)
    result = await db.execute(
        select(Entry).where(Entry.feed_id == fid).order_by(Entry.published_at.desc()).limit(min(limit, 50))
    )
    entries = result.scalars().all()
    return {
        "entries": [
            {"id": str(e.id), "title": e.title, "published_at": str(e.published_at), "url": e.url} for e in entries
        ]
    }


@_tool(
    name="get_threat_actor",
    description=(
        "Get a threat actor profile including aliases, actor type, motivation, origin country, "
        "targeted sectors, associated TTPs, and the count of linked articles (article_count)."
    ),
    input_schema={
        "properties": {
            "actor_id": {"type": "string", "description": "Threat actor UUID"},
        },
        "required": ["actor_id"],
    },
)
async def _get_threat_actor(db: AsyncSession, user_id: uuid.UUID, actor_id: str) -> dict:
    from sqlalchemy.orm import selectinload

    aid = uuid.UUID(actor_id)
    result = await db.execute(
        select(ThreatActor).options(selectinload(ThreatActor.origin_country)).where(ThreatActor.id == aid)
    )
    actor = result.scalar_one_or_none()
    if not actor:
        return {"error": "Threat actor not found"}
    return {
        "id": str(actor.id),
        "name": actor.name,
        "aliases": actor.aliases,
        "description": actor.description,
        "actor_type": actor.actor_type,
        "country": actor.country,
        "origin_country": actor.origin_country.name if actor.origin_country else None,
        "motivation": actor.motivation,
        "targeted_sectors": actor.targeted_sectors,
        "mitre_id": actor.mitre_id,
        "associated_ttps": actor.associated_ttps,
        "first_seen_at": str(actor.first_seen_at),
        "last_seen_at": str(actor.last_seen_at),
        "article_count": actor.article_count,
    }


@_tool(
    name="get_malware",
    description=(
        "Get malware family profile with aliases, type, targeted sectors, associated actors, "
        "and the count of linked articles (article_count)."
    ),
    input_schema={
        "properties": {
            "malware_id": {"type": "string", "description": "Malware family UUID"},
        },
        "required": ["malware_id"],
    },
)
async def _get_malware(db: AsyncSession, user_id: uuid.UUID, malware_id: str) -> dict:
    mid = uuid.UUID(malware_id)
    result = await db.execute(select(MalwareFamily).where(MalwareFamily.id == mid))
    mw = result.scalar_one_or_none()
    if not mw:
        return {"error": "Malware family not found"}
    return {
        "id": str(mw.id),
        "name": mw.name,
        "aliases": mw.aliases,
        "description": mw.description,
        "malware_type": mw.malware_type,
        "targeted_sectors": mw.targeted_sectors,
        "malpedia_url": mw.malpedia_url,
        "associated_actors": mw.associated_actors,
        "first_seen_at": str(mw.first_seen_at),
        "last_seen_at": str(mw.last_seen_at),
        "article_count": mw.article_count,
    }


@_tool(
    name="get_cve",
    description=(
        "Get CVE details including CVSS/EPSS scores, severity, CISA KEV status, GitHub PoC and "
        "Metasploit availability, structured NVD affected vendor/product links, NVD weakness (CWE) "
        "assignments, and linked article count."
    ),
    input_schema={
        "properties": {
            "cve_id": {"type": "string", "description": "CVE UUID or CVE ID string (e.g. CVE-2024-1234)"},
        },
        "required": ["cve_id"],
    },
)
async def _get_cve(db: AsyncSession, user_id: uuid.UUID, cve_id: str) -> dict:
    from app.models.cve import EntryCVE
    from app.models.cve_affected import CVEAffected
    from app.models.cwe import CWE, CVEWeakness

    try:
        cid = uuid.UUID(cve_id)
        result = await db.execute(select(CVE).where(CVE.id == cid))
    except ValueError:
        result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
    cve = result.scalar_one_or_none()
    if not cve:
        return {"error": "CVE not found"}
    # Compute article_count via junction count since the CVE model doesn't store it
    count_result = await db.execute(select(func.count(EntryCVE.entry_id)).where(EntryCVE.cve_id == cve.id))
    article_count = count_result.scalar_one()
    # Structured affects-links parsed from NVD CPE data (cve_affected table)
    affected_q = await db.execute(select(CVEAffected).where(CVEAffected.cve_id == cve.id))
    affected = [
        {
            "vendor": a.cpe_vendor,
            "product": a.cpe_product,
            "version_start": a.version_start,
            "version_end": a.version_end,
            "vendor_id": str(a.vendor_id) if a.vendor_id else None,
            "product_id": str(a.product_id) if a.product_id else None,
        }
        for a in affected_q.scalars()
    ]
    # NVD weakness assignments. The NVD-CWE-noinfo sentinel is kept rather than
    # filtered: "NVD declined to classify this" is a real answer.
    weakness_rows = (
        await db.execute(
            select(CVEWeakness, CWE)
            .outerjoin(CWE, CWE.id == CVEWeakness.cwe_id_fk)
            .where(CVEWeakness.cve_id == cve.id)
            .order_by(CVEWeakness.is_primary.desc(), CVEWeakness.cwe_ref)
        )
    ).all()
    weaknesses = [
        {
            "cwe_ref": link.cwe_ref,
            "name": cwe.name if cwe else None,
            "abstraction": cwe.abstraction if cwe else None,
            "mapping_usage": cwe.mapping_usage if cwe else None,
            "is_primary": link.is_primary,
        }
        for link, cwe in weakness_rows
    ]
    return {
        "id": str(cve.id),
        "cve_id": cve.cve_id,
        "description": cve.description,
        "cvss_score": cve.cvss_score,
        "severity": cve.severity,
        "epss_score": cve.epss_score,
        "affected_products": cve.affected_products,  # legacy JSONB list
        "affected": affected,
        "exploit_status": cve.exploit_status,
        "exploit_availability": cve.exploit_availability,
        "is_kev": cve.is_kev,
        "kev_date_added": str(cve.kev_date_added) if cve.kev_date_added else None,
        "kev_due_date": str(cve.kev_due_date) if cve.kev_due_date else None,
        "github_poc_count": cve.github_poc_count,
        "github_poc_urls": cve.github_poc_urls,
        "metasploit_module": cve.metasploit_module,
        "first_seen_at": str(cve.first_seen_at),
        "article_count": article_count,
        "weaknesses": weaknesses,
    }


@_tool(
    name="get_observable",
    description=(
        "Look up an observable (IOC ledger row) by UUID or by its value (IP, domain, URL, hash, cmdline, "
        "registry key, ...). Returns kind, role, current/base confidence with decay state, sighting count, "
        "capture provenance (which judgment door created it) with the evidence sentence, first/last seen, "
        "and the most recent sighting articles. Defanged input (evil[.]com, hxxps://) is normalized."
    ),
    input_schema={
        "properties": {
            "observable": {"type": "string", "description": "Observable UUID or the value itself (defanged ok)"},
            "kind": {
                "type": "string",
                "description": "Optional kind to disambiguate a value lookup (ipv4, domain, sha256, cmdline, ...)",
            },
        },
        "required": ["observable"],
    },
)
async def _get_observable(db: AsyncSession, user_id: uuid.UUID, observable: str, kind: str | None = None) -> dict:
    from app.intelligence.observables import classify_value, normalize_value, refang
    from app.models.entry import Entry
    from app.models.observable import EntryObservable, Observable

    obs = None
    try:
        oid = uuid.UUID(observable)
        obs = (await db.execute(select(Observable).where(Observable.id == oid))).scalar_one_or_none()
    except ValueError:
        if kind:
            canonical = normalize_value(kind, observable)
            obs = (
                await db.execute(select(Observable).where(Observable.kind == kind, Observable.value == canonical))
            ).scalar_one_or_none()
        else:
            classified = classify_value(observable)
            if classified:
                obs = (
                    await db.execute(
                        select(Observable).where(Observable.kind == classified[0], Observable.value == classified[1])
                    )
                ).scalar_one_or_none()
            if obs is None:
                obs = (
                    await db.execute(
                        select(Observable)
                        .where(Observable.value == refang(observable.strip()))
                        .order_by(Observable.sighting_count.desc())
                        .limit(1)
                    )
                ).scalar_one_or_none()
    if not obs:
        return {"error": "Observable not found — the ledger only holds values a judgment door confirmed"}

    sightings = (
        await db.execute(
            select(Entry.id, Entry.title, Entry.published_at, EntryObservable.source, EntryObservable.surface_form)
            .join(EntryObservable, EntryObservable.entry_id == Entry.id)
            .where(EntryObservable.observable_id == obs.id)
            .order_by(Entry.published_at.desc().nulls_last())
            .limit(10)
        )
    ).all()

    return {
        "id": str(obs.id),
        "kind": obs.kind,
        "value": obs.value,
        "label": obs.label,
        "language": obs.language,
        "role": obs.role,
        "status": obs.status,
        "is_denied": obs.is_denied,
        "base_confidence": obs.base_confidence,
        "current_confidence": obs.current_confidence,
        "confidence_pinned": obs.confidence_pinned,
        "captured_by": obs.created_via,
        "evidence": obs.evidence,
        "description": obs.description,
        "sighting_count": obs.sighting_count,
        "first_seen_at": str(obs.first_seen_at),
        "last_seen_at": str(obs.last_seen_at),
        "recent_sightings": [
            {
                "entry_id": str(r.id),
                "title": r.title,
                "published_at": str(r.published_at) if r.published_at else None,
                "source": r.source,
                "surface_form": r.surface_form,
            }
            for r in sightings
        ],
        "script_content": obs.content[:2000] if obs.kind == "script" and obs.content else None,
    }


@_tool(
    name="search_observables",
    description=(
        "Search the observables ledger (IOCs captured with judgment: AI-confirmed indicators, curated feed "
        "entries, TTP host artifacts, analyst promotions). Filter by substring, kind, role, lifecycle "
        "status, or capture door. Sorted by last sighting."
    ),
    input_schema={
        "properties": {
            "query": {"type": "string", "description": "Substring of the value or label (optional)"},
            "kind": {"type": "string", "description": "ipv4, ipv6, domain, url, md5, sha256, cmdline, script, ..."},
            "role": {"type": "string", "description": "c2, delivery, payload, phishing, exfil, exploit, scanning"},
            "status": {"type": "string", "description": "active, aging, or expired"},
            "limit": {"type": "integer", "description": "Max rows (default 20, cap 100)"},
        },
        "required": [],
    },
)
async def _search_observables(
    db: AsyncSession,
    user_id: uuid.UUID,
    query: str | None = None,
    kind: str | None = None,
    role: str | None = None,
    status: str | None = None,
    limit: int = 20,
) -> dict:
    from app.models.observable import Observable

    q = select(Observable).where(Observable.is_denied.is_(False))
    if query:
        pattern = f"%{query}%"
        q = q.where(or_(Observable.value.ilike(pattern), Observable.label.ilike(pattern)))
    if kind:
        q = q.where(Observable.kind == kind)
    if role:
        q = q.where(Observable.role == role)
    if status:
        q = q.where(Observable.status == status)
    rows = (await db.execute(q.order_by(Observable.last_seen_at.desc()).limit(min(max(limit, 1), 100)))).scalars().all()
    return {
        "count": len(rows),
        "observables": [
            {
                "id": str(o.id),
                "kind": o.kind,
                "value": o.value,
                "label": o.label,
                "role": o.role,
                "status": o.status,
                "current_confidence": o.current_confidence,
                "sighting_count": o.sighting_count,
                "captured_by": o.created_via,
                "last_seen_at": str(o.last_seen_at),
            }
            for o in rows
        ],
    }


@_tool(
    name="get_cwe",
    description=(
        "Get a MITRE CWE weakness by ID, including its position on the abstraction ladder "
        "(Pillar/Class/Base/Variant), parent and lineage, MITRE mapping guidance, catalog mitigations "
        "and detection methods, how many CVEs carry it directly and across its whole subtree, how many "
        "of those are in CISA KEV, and linked article count."
    ),
    input_schema={
        "properties": {
            "cwe_id": {"type": "string", "description": "CWE UUID or catalog ID string (e.g. CWE-416)"},
        },
        "required": ["cwe_id"],
    },
)
async def _get_cwe(db: AsyncSession, user_id: uuid.UUID, cwe_id: str) -> dict:
    from app.api.intelligence import _cwe_rolled_counts
    from app.models.cwe import CWE, CVEWeakness

    try:
        cid = uuid.UUID(cwe_id)
        result = await db.execute(select(CWE).where(CWE.id == cid))
    except ValueError:
        key = cwe_id if cwe_id.upper().startswith("CWE-") else f"CWE-{cwe_id}"
        result = await db.execute(select(CWE).where(func.upper(CWE.cwe_id) == key.upper()))
    cwe = result.scalar_one_or_none()
    if not cwe:
        return {"error": "CWE not found"}

    counts = (
        await db.execute(
            select(func.count(CVEWeakness.id), func.count(CVEWeakness.id).filter(CVE.is_kev.is_(True)))
            .select_from(CVEWeakness)
            .join(CVE, CVE.id == CVEWeakness.cve_id)
            .where(CVEWeakness.cwe_id_fk == cwe.id)
        )
    ).one()
    rolled = (await _cwe_rolled_counts(db)).get(cwe.id, (0, 0))

    # Root-first path to the pillar. A Class or Pillar's direct count is close to
    # meaningless on its own — NVD tags a CVE wherever the analyst chose — so the
    # rolled figure and the lineage are what make the number interpretable.
    by_id = {row.cwe_id: row for row in (await db.execute(select(CWE))).scalars()}
    lineage, cursor, seen = [], cwe.parent_cwe_id, set()
    while cursor and cursor not in seen and len(lineage) < 12:
        seen.add(cursor)
        parent = by_id.get(cursor)
        if parent is None:
            break
        lineage.append({"cwe_id": parent.cwe_id, "name": parent.name, "abstraction": parent.abstraction})
        cursor = parent.parent_cwe_id
    lineage.reverse()

    return {
        "id": str(cwe.id),
        "cwe_id": cwe.cwe_id,
        "name": cwe.name,
        "kind": cwe.kind,
        "abstraction": cwe.abstraction,
        "status": cwe.status,
        "mapping_usage": cwe.mapping_usage,
        "description": cwe.description,
        "parent_cwe_id": cwe.parent_cwe_id,
        "lineage": lineage,
        "likelihood_of_exploit": cwe.likelihood_of_exploit,
        "alternate_terms": cwe.alternate_terms,
        "capec_ids": cwe.capec_ids,
        "consequences": cwe.consequences,
        "mitigations": cwe.mitigations,
        "detection_methods": cwe.detection_methods,
        "cwe_url": cwe.cwe_url,
        "is_deprecated": cwe.is_deprecated,
        "superseded_by": cwe.superseded_by,
        "cve_count": int(counts[0] or 0),
        "cve_count_rolled": rolled[0],
        "kev_count": int(counts[1] or 0),
        "kev_count_rolled": rolled[1],
        "article_count": cwe.article_count,
        "first_seen_at": str(cwe.first_seen_at),
        "last_seen_at": str(cwe.last_seen_at),
    }


@_tool(
    name="get_ttp",
    description=(
        "Get a MITRE ATT&CK technique (TTP) by ID, including tactic, platforms, data sources, and linked articles."
    ),
    input_schema={
        "properties": {
            "ttp_id": {"type": "string", "description": "TTP UUID or technique ID string (e.g. T1059.001)"},
        },
        "required": ["ttp_id"],
    },
)
async def _get_ttp(db: AsyncSession, user_id: uuid.UUID, ttp_id: str) -> dict:
    try:
        tid = uuid.UUID(ttp_id)
        result = await db.execute(select(TTP).where(TTP.id == tid))
    except ValueError:
        result = await db.execute(select(TTP).where(TTP.technique_id == ttp_id))
    ttp = result.scalar_one_or_none()
    if not ttp:
        return {"error": "TTP not found"}
    return {
        "id": str(ttp.id),
        "technique_id": ttp.technique_id,
        "technique_name": ttp.technique_name,
        "tactic": ttp.tactic,
        "description": ttp.description,
        "platforms": ttp.platforms,
        "data_sources": ttp.data_sources,
        "mitre_url": ttp.mitre_url,
        "detection": ttp.detection,
        "is_subtechnique": ttp.is_subtechnique,
        "first_seen_at": str(ttp.first_seen_at),
        "last_seen_at": str(ttp.last_seen_at),
        "article_count": ttp.article_count,
    }


@_tool(
    name="get_campaign",
    description="Get campaign details with timeline, linked entries, linked entities, and detection gaps.",
    input_schema={
        "properties": {
            "campaign_id": {"type": "string", "description": "Campaign UUID"},
        },
        "required": ["campaign_id"],
    },
)
async def _get_campaign(db: AsyncSession, user_id: uuid.UUID, campaign_id: str) -> dict:
    from app.models.campaign import CampaignEntity, CampaignEntry

    cid = uuid.UUID(campaign_id)
    result = await db.execute(select(Campaign).where(Campaign.id == cid))
    campaign = result.scalar_one_or_none()
    if not campaign:
        return {"error": "Campaign not found"}

    entries_q = await db.execute(
        select(Entry.id, Entry.title, Entry.published_at)
        .join(CampaignEntry, CampaignEntry.entry_id == Entry.id)
        .where(CampaignEntry.campaign_id == cid)
        .order_by(Entry.published_at.desc())
    )
    entities_q = await db.execute(select(CampaignEntity).where(CampaignEntity.campaign_id == cid))

    return {
        "id": str(campaign.id),
        "name": campaign.name,
        "description": campaign.description,
        "status": campaign.status,
        "tlp_marking": campaign.tlp_marking,
        "start_date": str(campaign.start_date) if campaign.start_date else None,
        "end_date": str(campaign.end_date) if campaign.end_date else None,
        "tags": campaign.tags,
        "entries": [{"id": str(e.id), "title": e.title, "published_at": str(e.published_at)} for e in entries_q],
        "entities": [
            {"entity_type": e.entity_type, "entity_id": str(e.entity_id), "role": e.role} for e in entities_q.scalars()
        ],
    }


@_tool(
    name="get_feeds",
    description=f"List configured feeds of any registered adapter type ({', '.join(_FEED_TYPES)}) with health status.",
    input_schema={"properties": {"limit": {"type": "integer", "default": 50}}},
)
async def _get_feeds(db: AsyncSession, user_id: uuid.UUID, limit: int = 50) -> dict:
    result = await db.execute(select(Feed).order_by(Feed.title).limit(min(limit, 100)))
    feeds = result.scalars().all()
    return {
        "feeds": [
            {
                "id": str(f.id),
                "title": f.title,
                "url": f.url,
                "feed_type": f.feed_type,
                "is_active": f.is_active,
                "last_fetched_at": str(f.last_fetched_at) if f.last_fetched_at else None,
                "error_count": f.error_count,
            }
            for f in feeds
        ]
    }


@_tool(
    name="discover_telegram_channels",
    description=(
        "List every Telegram channel the IntelFeed bootstrap account is joined to, with "
        "is_subscribed = whether IntelFeed already ingests it. Use this to see which channels "
        "you've joined in your Telegram client app but haven't yet wired up as IntelFeed feeds."
    ),
    input_schema={
        "properties": {
            "session_name": {"type": "string", "description": "Optional named session"},
            "only_unsubscribed": {"type": "boolean", "default": False},
        }
    },
)
async def _discover_telegram_channels(
    db: AsyncSession,
    user_id: uuid.UUID,
    session_name: str = "",
    only_unsubscribed: bool = False,
) -> dict:
    from app.config import settings as _settings

    if not _settings.telegram_api_id or not _settings.telegram_api_hash:
        return {"error": "Telegram is not configured on this server"}

    from app.adapters.telegram import TelegramAdapter

    adapter = TelegramAdapter()
    try:
        dialogs = await adapter.list_my_dialogs(session_name=session_name)
    except RuntimeError as exc:
        return {"error": str(exc)}

    feed_rows = await db.execute(select(Feed).where(Feed.feed_type == "telegram"))
    subscribed_ids: set[int] = set()
    subscribed_unames: set[str] = set()
    feed_by_channel: dict[int, str] = {}
    for f in feed_rows.scalars().all():
        cfg = f.adapter_config or {}
        cid = cfg.get("channel_id")
        if cid is not None:
            try:
                subscribed_ids.add(int(cid))
                feed_by_channel[int(cid)] = str(f.id)
            except (TypeError, ValueError):
                pass
        uname = (cfg.get("channel_username") or cfg.get("channel") or "").lstrip("@").lower()
        if uname:
            subscribed_unames.add(uname)

    items = []
    for d in dialogs:
        is_sub = d["channel_id"] in subscribed_ids or (d.get("username") and d["username"].lower() in subscribed_unames)
        if only_unsubscribed and is_sub:
            continue
        items.append(
            {
                **d,
                "is_subscribed": is_sub,
                "feed_id": feed_by_channel.get(d["channel_id"]),
            }
        )

    items.sort(key=lambda x: (x["is_subscribed"], -1 * (x.get("subscribers") or 0)))
    return {
        "channels": items,
        "total": len(items),
        "subscribed_count": sum(1 for it in items if it["is_subscribed"]),
        "unsubscribed_count": sum(1 for it in items if not it["is_subscribed"]),
    }


@_tool(
    name="list_telegram_feeds",
    description=(
        "List Telegram channel feeds with their adapter config — channel, last_seen_id, "
        "attribution, session, error state."
    ),
    input_schema={"properties": {"limit": {"type": "integer", "default": 50}}},
)
async def _list_telegram_feeds(db: AsyncSession, user_id: uuid.UUID, limit: int = 50) -> dict:
    result = await db.execute(
        select(Feed).where(Feed.feed_type == "telegram").order_by(Feed.title).limit(min(limit, 200))
    )
    feeds = result.scalars().all()
    return {
        "feeds": [
            {
                "id": str(f.id),
                "title": f.title,
                "url": f.url,
                "is_active": f.is_active,
                "last_fetched_at": str(f.last_fetched_at) if f.last_fetched_at else None,
                "error_count": f.error_count,
                "last_error": f.last_error,
                "fetch_interval_minutes": f.fetch_interval_minutes,
                "adapter_config": {
                    k: v
                    for k, v in (f.adapter_config or {}).items()
                    # Don't leak campaign/actor UUIDs to display; truncate
                    if k
                    in (
                        "channel",
                        "channel_id",
                        "channel_username",
                        "include_media",
                        "extract_forwards",
                        "max_message_age_days",
                        "last_seen_id",
                        "session_name",
                        "threat_actor_id",
                        "campaign_id",
                    )
                },
            }
            for f in feeds
        ]
    }


@_tool(
    name="get_detection_rules",
    description=f"List detection rules. Optionally filter by rule type ({', '.join(_RULE_TYPES)}).",
    input_schema={
        "properties": {
            "rule_type": {
                "type": "string",
                "description": "Filter by rule type",
                "enum": _RULE_TYPES,
            },
            "limit": {"type": "integer", "default": 30},
        },
    },
)
async def _get_detection_rules(
    db: AsyncSession, user_id: uuid.UUID, rule_type: str | None = None, limit: int = 30
) -> dict:
    q = select(DetectionRule).order_by(DetectionRule.created_at.desc()).limit(min(limit, 50))
    if rule_type:
        q = q.where(DetectionRule.rule_type == rule_type)
    result = await db.execute(q)
    rules = result.scalars().all()
    return {
        "rules": [
            {
                "id": str(r.id),
                "title": r.title,
                "rule_type": r.rule_type,
                "severity": r.severity,
                "rule_content": r.rule_content[:500] if r.rule_content else None,
                "created_at": str(r.created_at),
            }
            for r in rules
        ]
    }


@_tool(
    name="get_requirements",
    description="Get intelligence requirements and their coverage status.",
    input_schema={
        "properties": {
            "status": {
                "type": "string",
                "enum": ["active", "fulfilled", "expired", "draft"],
                "description": "Filter by status",
            },
        },
    },
)
async def _get_requirements(db: AsyncSession, user_id: uuid.UUID, status: str | None = None) -> dict:
    # Order by priority semantically (critical > high > medium > low), not alphabetically.
    priority_rank = case(
        (IntelligenceRequirement.priority == "critical", 0),
        (IntelligenceRequirement.priority == "high", 1),
        (IntelligenceRequirement.priority == "medium", 2),
        (IntelligenceRequirement.priority == "low", 3),
        else_=4,
    )
    q = select(IntelligenceRequirement).order_by(priority_rank)
    if status:
        q = q.where(IntelligenceRequirement.status == status)
    result = await db.execute(q.limit(50))
    reqs = result.scalars().all()
    return {
        "requirements": [
            {
                "id": str(r.id),
                "title": r.title,
                "description": r.description,
                "priority": r.priority,
                "status": r.status,
                "category": r.category,
                "keywords": r.keywords,
                "auto_match": r.auto_match,
                "match_count": r.match_count,
                "last_matched_at": str(r.last_matched_at) if r.last_matched_at else None,
            }
            for r in reqs
        ]
    }


@_tool(
    name="get_correlation_events",
    description=(
        "Get recent correlation events — coverage gaps, trending entities, campaign and "
        "requirement matches, new TTPs/malware for known actors or malware, actor-malware "
        "co-occurrence, feed staleness/errors, exploit and CVE score changes, and KEV additions."
    ),
    input_schema={
        "properties": {
            "limit": {"type": "integer", "default": 30},
            "unread_only": {"type": "boolean", "default": False},
        },
    },
)
async def _get_correlation_events(
    db: AsyncSession, user_id: uuid.UUID, limit: int = 30, unread_only: bool = False
) -> dict:
    q = select(CorrelationEvent).order_by(CorrelationEvent.created_at.desc()).limit(min(limit, 100))
    if unread_only:
        q = q.where(CorrelationEvent.is_read == False)  # noqa: E712
    result = await db.execute(q)
    events = result.scalars().all()
    return {
        "events": [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "severity": e.severity,
                "source_entity_type": e.source_entity_type,
                "source_entity_label": e.source_entity_label,
                "related_entity_type": e.related_entity_type,
                "related_entity_label": e.related_entity_label,
                "context": e.context,
                "is_read": e.is_read,
                "created_at": str(e.created_at),
            }
            for e in events
        ],
        "count": len(events),
    }


@_tool(
    name="get_analytics",
    description=(
        "Get platform analytics: trending entities, intelligence velocity, detection coverage gaps, and overview stats."
    ),
    input_schema={
        "properties": {
            "metric": {
                "type": "string",
                "enum": ["overview", "trending", "detection_coverage", "velocity"],
                "description": "Which analytics metric to retrieve",
            },
            "entity_type": {"type": "string", "description": "For trending: threat_actor, malware, cve, ttp"},
            "days": {"type": "integer", "default": 30},
        },
        "required": ["metric"],
    },
)
async def _get_analytics(
    db: AsyncSession, user_id: uuid.UUID, metric: str, entity_type: str | None = None, days: int = 30
) -> dict:
    from app.intelligence.analytics import (
        analytics_overview,
        detection_coverage,
        entity_trending,
        intelligence_velocity,
    )

    if metric == "overview":
        return await analytics_overview(db)
    elif metric == "trending":
        if not entity_type:
            return {"error": "entity_type required for trending metric"}
        return {"trending": await entity_trending(db, entity_type, days=days)}
    elif metric == "detection_coverage":
        return await detection_coverage(db, include_gaps=True)
    elif metric == "velocity":
        return await intelligence_velocity(db, days=days)
    return {"error": f"Unknown metric: {metric}"}


@_tool(
    name="get_dashboard_stats",
    description=(
        "Get system-wide statistics: total entries, feeds, detection rules, counts for every "
        "entity type (ttp = observed techniques with linked articles; full catalog size in "
        "ttp_catalog_size), and recent activity (entries in the last 24h/7d)."
    ),
    input_schema={"properties": {}},
)
async def _get_dashboard_stats(db: AsyncSession, user_id: uuid.UUID) -> dict:
    from datetime import datetime, timedelta

    from app.models.ransomware import RansomwareVictim
    from app.models.ttp import EntryTTP

    entries_count = (await db.execute(select(func.count(Entry.id)))).scalar() or 0
    feeds_count = (await db.execute(select(func.count(Feed.id)))).scalar() or 0
    rules_count = (await db.execute(select(func.count(DetectionRule.id)))).scalar() or 0

    # Every entity type from the canonical junction map, plus ransomware victims
    # (leak-site sourced, no entry junction so not in ENTITY_CONFIG).
    entities: dict[str, int] = {}
    for etype, (model, _junction, _fk) in ENTITY_CONFIG.items():
        entities[etype] = (await db.execute(select(func.count(model.id)))).scalar() or 0
    entities["ransomware_victim"] = (await db.execute(select(func.count(RansomwareVictim.id)))).scalar() or 0

    # TTP count as *observed* techniques (linked to at least one entry); the full
    # MITRE catalog size is reported separately.
    ttp_catalog_size = entities["ttp"]
    entities["ttp"] = (await db.execute(select(func.count(func.distinct(EntryTTP.ttp_id))))).scalar() or 0

    now = datetime.now(UTC)
    entries_24h = (
        await db.execute(select(func.count(Entry.id)).where(Entry.published_at >= now - timedelta(hours=24)))
    ).scalar() or 0
    entries_7d = (
        await db.execute(select(func.count(Entry.id)).where(Entry.published_at >= now - timedelta(days=7)))
    ).scalar() or 0

    return {
        "entries": entries_count,
        "feeds": feeds_count,
        "detection_rules": rules_count,
        "entities": entities,
        "ttp_catalog_size": ttp_catalog_size,
        "recent_activity": {"entries_last_24h": entries_24h, "entries_last_7d": entries_7d},
    }


@_tool(
    name="get_enrichment_data",
    description=(
        "Get enrichment results stored on an entity: CVE (EPSS, KEV, GitHub PoCs, Metasploit, "
        "NVD data), malware (Malpedia, Wikipedia), threat actor (Wikipedia), or TTP (Wikipedia)."
    ),
    input_schema={
        "properties": {
            "entity_type": {
                "type": "string",
                "enum": ["cve", "malware", "threat_actor", "ttp"],
                "description": "Entity type",
            },
            "entity_id": {"type": "string", "description": "Entity UUID"},
        },
        "required": ["entity_type", "entity_id"],
    },
)
async def _get_enrichment_data(db: AsyncSession, user_id: uuid.UUID, entity_type: str, entity_id: str) -> dict:
    def _wiki(entity) -> dict:
        content = entity.wikipedia_content or ""
        if len(content) > 2000:
            content = content[:2000] + "\n...[truncated]"
        return {
            "wikipedia_url": entity.wikipedia_url,
            "wikipedia_content": content or None,
            "wikipedia_image_url": entity.wikipedia_image_url,
        }

    eid = uuid.UUID(entity_id)
    if entity_type == "cve":
        result = await db.execute(select(CVE).where(CVE.id == eid))
        cve = result.scalar_one_or_none()
        if not cve:
            return {"error": "CVE not found"}
        return {
            "entity_type": "cve",
            "cve_id": cve.cve_id,
            "cvss_score": cve.cvss_score,
            "epss_score": cve.epss_score,
            "epss_percentile": cve.epss_percentile,
            "exploit_availability": cve.exploit_availability,
            "exploit_status": cve.exploit_status,
            "is_kev": cve.is_kev,
            "kev_date_added": str(cve.kev_date_added) if cve.kev_date_added else None,
            "kev_due_date": str(cve.kev_due_date) if cve.kev_due_date else None,
            "github_poc_count": cve.github_poc_count,
            "github_poc_urls": cve.github_poc_urls,
            "metasploit_module": cve.metasploit_module,
            "nvd_data": cve.nvd_data or {},
            "references": cve.references_,
        }
    elif entity_type == "malware":
        result = await db.execute(select(MalwareFamily).where(MalwareFamily.id == eid))
        mw = result.scalar_one_or_none()
        if not mw:
            return {"error": "Malware not found"}
        return {
            "entity_type": "malware",
            "name": mw.name,
            "malpedia_url": mw.malpedia_url,
            "malware_type": mw.malware_type,
            "associated_actors": mw.associated_actors,
            **_wiki(mw),
        }
    elif entity_type == "threat_actor":
        result = await db.execute(select(ThreatActor).where(ThreatActor.id == eid))
        actor = result.scalar_one_or_none()
        if not actor:
            return {"error": "Threat actor not found"}
        return {
            "entity_type": "threat_actor",
            "name": actor.name,
            "actor_type": actor.actor_type,
            "country": actor.country,
            "motivation": actor.motivation,
            **_wiki(actor),
        }
    elif entity_type == "ttp":
        result = await db.execute(select(TTP).where(TTP.id == eid))
        ttp = result.scalar_one_or_none()
        if not ttp:
            return {"error": "TTP not found"}
        return {
            "entity_type": "ttp",
            "technique_id": ttp.technique_id,
            "technique_name": ttp.technique_name,
            "mitre_url": ttp.mitre_url,
            **_wiki(ttp),
        }
    return {"error": f"Unsupported entity type: {entity_type}"}


@_tool(
    name="get_attack_layer",
    description=(
        "Get MITRE ATT&CK Navigator layer JSON for a specific entry's TTPs, or (without "
        "entry_id) for all observed techniques — those linked to at least one entry, "
        "excluding deprecated catalog techniques."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Optional: scope to TTPs from a specific entry"},
            "title": {"type": "string", "default": "IntelFeed ATT&CK Coverage"},
        },
    },
)
async def _get_attack_layer(
    db: AsyncSession, user_id: uuid.UUID, entry_id: str | None = None, title: str = "IntelFeed ATT&CK Coverage"
) -> dict:
    from app.intelligence.ttp import generate_navigator_layer
    from app.models.ttp import EntryTTP

    if entry_id:
        result = await db.execute(select(TTP).join(EntryTTP).where(EntryTTP.entry_id == uuid.UUID(entry_id)))
    else:
        # Observed techniques only: linked to at least one entry, not deprecated.
        result = await db.execute(
            select(TTP).join(EntryTTP, EntryTTP.ttp_id == TTP.id).where(TTP.is_deprecated.is_(False)).distinct()
        )

    ttps = [
        {"technique_id": t.technique_id, "technique_name": t.technique_name, "confidence": "medium"}
        for t in result.scalars()
    ]
    return generate_navigator_layer(ttps, title=title)


@_tool(
    name="get_telemetry_sources",
    description="List configured telemetry/log sources and their coverage. Useful for assessing detection feasibility.",
    input_schema={"properties": {}},
)
async def _get_telemetry_sources(db: AsyncSession, user_id: uuid.UUID) -> dict:
    result = await db.execute(select(TelemetrySource).order_by(TelemetrySource.category))
    sources = result.scalars().all()
    return {
        "sources": [
            {
                "id": str(s.id),
                "name": s.name,
                "category": s.category,
                "vendor": s.vendor,
                "product": s.product,
                "log_types": s.log_types,
                "ingested_into": s.ingested_into,
                "enabled": s.enabled,
                "notes": s.notes,
            }
            for s in sources
        ],
        "count": len(sources),
    }


# --- New tools (post-March 2026) ---


@_tool(
    name="get_campaigns",
    description="List campaigns with optional status filter.",
    input_schema={
        "properties": {
            "status": {
                "type": "string",
                "enum": ["active", "monitoring", "closed", "historical"],
                "description": "Filter by status",
            },
            "limit": {"type": "integer", "default": 30},
        },
    },
)
async def _get_campaigns(db: AsyncSession, user_id: uuid.UUID, status: str | None = None, limit: int = 30) -> dict:
    from app.models.campaign import CampaignEntity, CampaignEntry

    q = select(Campaign).order_by(Campaign.created_at.desc()).limit(min(limit, 50))
    if status:
        q = q.where(Campaign.status == status)
    result = await db.execute(q)
    campaigns = result.scalars().all()

    campaign_list = []
    for c in campaigns:
        entry_count = (
            await db.execute(select(func.count()).select_from(CampaignEntry).where(CampaignEntry.campaign_id == c.id))
        ).scalar() or 0
        entity_count = (
            await db.execute(select(func.count(CampaignEntity.id)).where(CampaignEntity.campaign_id == c.id))
        ).scalar() or 0
        campaign_list.append(
            {
                "id": str(c.id),
                "name": c.name,
                "status": c.status,
                "tlp_marking": c.tlp_marking,
                "description": c.description,
                "entry_count": entry_count,
                "entity_count": entity_count,
                "created_at": str(c.created_at),
            }
        )
    return {"campaigns": campaign_list}


@_tool(
    name="get_campaign_timeline",
    description="Get chronological entries in a campaign, sorted by publication date.",
    input_schema={
        "properties": {
            "campaign_id": {"type": "string", "description": "Campaign UUID"},
        },
        "required": ["campaign_id"],
    },
)
async def _get_campaign_timeline(db: AsyncSession, user_id: uuid.UUID, campaign_id: str) -> dict:
    from app.models.campaign import CampaignEntry

    cid = uuid.UUID(campaign_id)
    result = await db.execute(
        select(Entry.id, Entry.title, Entry.url, Entry.published_at, CampaignEntry.notes)
        .join(CampaignEntry, CampaignEntry.entry_id == Entry.id)
        .where(CampaignEntry.campaign_id == cid)
        .order_by(Entry.published_at.desc().nullslast())
    )
    entries = list(result)
    return {
        "campaign_id": campaign_id,
        "entries": [
            {
                "id": str(e.id),
                "title": e.title,
                "url": e.url,
                "published_at": str(e.published_at) if e.published_at else None,
                "notes": e.notes,
            }
            for e in entries
        ],
    }


@_tool(
    name="get_campaign_attack_layer",
    description="Get MITRE ATT&CK Navigator layer JSON for all TTPs linked to a campaign.",
    input_schema={
        "properties": {
            "campaign_id": {"type": "string", "description": "Campaign UUID"},
        },
        "required": ["campaign_id"],
    },
)
async def _get_campaign_attack_layer(db: AsyncSession, user_id: uuid.UUID, campaign_id: str) -> dict:
    from app.intelligence.ttp import generate_navigator_layer
    from app.models.campaign import CampaignEntry
    from app.models.ttp import EntryTTP

    cid = uuid.UUID(campaign_id)
    campaign_q = await db.execute(select(Campaign).where(Campaign.id == cid))
    campaign = campaign_q.scalar_one_or_none()
    if not campaign:
        return {"error": "Campaign not found"}

    result = await db.execute(
        select(TTP.technique_id, TTP.technique_name, TTP.tactic)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .join(CampaignEntry, CampaignEntry.entry_id == EntryTTP.entry_id)
        .where(CampaignEntry.campaign_id == cid)
        .distinct()
    )
    ttps = [
        {"technique_id": t.technique_id, "technique_name": t.technique_name, "confidence": "medium"} for t in result
    ]
    layer = generate_navigator_layer(ttps, title=campaign.name)
    return {"layer": layer, "technique_count": len(ttps)}


@_tool(
    name="get_campaign_detection_gaps",
    description=(
        "Telemetry-aware detection coverage for a campaign's TTPs: covered, "
        "library_only (rules blocked by missing telemetry), and gaps (no rule)."
    ),
    input_schema={
        "properties": {
            "campaign_id": {"type": "string", "description": "Campaign UUID"},
        },
        "required": ["campaign_id"],
    },
)
async def _get_campaign_detection_gaps(db: AsyncSession, user_id: uuid.UUID, campaign_id: str) -> dict:
    from app.models.campaign import CampaignEntry
    from app.models.ttp import EntryTTP
    from app.services.detection_coverage import (
        STATUS_COVERED,
        STATUS_LIBRARY_ONLY,
        classify_techniques,
    )

    cid = uuid.UUID(campaign_id)
    result = await db.execute(
        select(TTP)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .join(CampaignEntry, CampaignEntry.entry_id == EntryTTP.entry_id)
        .where(CampaignEntry.campaign_id == cid)
        .distinct()
    )
    ttps = result.scalars().all()

    classification = await classify_techniques(db, [t.technique_id for t in ttps])

    gaps = []
    library_only = []
    covered = []
    for ttp in ttps:
        info = classification.get(ttp.technique_id) or {}
        entry = {"technique_id": ttp.technique_id, "name": ttp.technique_name, "tactic": ttp.tactic}
        status = info.get("status")
        if status == STATUS_COVERED:
            entry["rule_count"] = info["rule_count"]
            covered.append(entry)
        elif status == STATUS_LIBRARY_ONLY:
            entry["rule_count"] = info["rule_count"]
            entry["missing_data_sources"] = info["missing_data_sources"]
            library_only.append(entry)
        else:
            gaps.append(entry)

    total = len(gaps) + len(library_only) + len(covered)
    return {
        "campaign_id": campaign_id,
        "gaps": gaps,
        "library_only": library_only,
        "covered": covered,
        "coverage_percentage": round(len(covered) / total * 100, 1) if total else 0,
    }


@_tool(
    name="suggest_campaign_entries",
    description="Suggest entries that share entities with a campaign but aren't yet linked to it.",
    input_schema={
        "properties": {
            "campaign_id": {"type": "string", "description": "Campaign UUID"},
            "limit": {"type": "integer", "default": 10},
        },
        "required": ["campaign_id"],
    },
)
async def _suggest_campaign_entries(db: AsyncSession, user_id: uuid.UUID, campaign_id: str, limit: int = 10) -> dict:
    from collections import Counter

    from app.models.campaign import CampaignEntry

    cid = uuid.UUID(campaign_id)
    # Get existing campaign entry IDs
    existing_q = await db.execute(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == cid))
    existing_ids = {row[0] for row in existing_q}
    if not existing_ids:
        return {"suggestions": [], "message": "Campaign has no entries yet"}

    # Collect entity IDs per type from campaign entries, across every junction in
    # the canonical map (correlation.ENTITY_CONFIG). Kept per-type so overlap
    # lookups never mix UUIDs across junction tables.
    junctions = [(junction, fk) for _model, junction, fk in ENTITY_CONFIG.values()]
    entity_ids_by_junction: list[tuple[object, object, set]] = []
    for junction, fk in junctions:
        q = await db.execute(select(fk).where(junction.entry_id.in_(existing_ids)))
        ids = {row[0] for row in q}
        if ids:
            entity_ids_by_junction.append((junction, fk, ids))

    if not entity_ids_by_junction:
        return {"suggestions": [], "message": "Campaign entries have no linked entities"}

    # Find other entries sharing those entities
    overlap = Counter()
    for junction, fk, ids in entity_ids_by_junction:
        q = await db.execute(
            select(junction.entry_id).where(
                fk.in_(ids),
                junction.entry_id.notin_(existing_ids),
            )
        )
        for row in q:
            overlap[row[0]] += 1

    # Get top candidates
    top = overlap.most_common(min(limit, 20))
    if not top:
        return {"suggestions": []}

    entry_ids = [eid for eid, _ in top]
    entries_q = await db.execute(select(Entry).where(Entry.id.in_(entry_ids)))
    entry_map = {e.id: e for e in entries_q.scalars()}

    suggestions = []
    for eid, count in top:
        e = entry_map.get(eid)
        if e:
            suggestions.append(
                {
                    "entry_id": str(eid),
                    "title": e.title,
                    "url": e.url,
                    "published_at": str(e.published_at) if e.published_at else None,
                    "shared_entity_count": count,
                }
            )
    return {"suggestions": suggestions}


@_tool(
    name="export_campaign",
    description=(
        "Export a complete campaign intel package: linked entries, every entity type extracted "
        "from those entries (TTPs, CVEs, actors, malware, tools, vendors, products, countries, "
        "mitigations), explicitly linked entities, and detection rules sourced from the campaign."
    ),
    input_schema={
        "properties": {
            "campaign_id": {"type": "string", "description": "Campaign UUID"},
        },
        "required": ["campaign_id"],
    },
)
async def _export_campaign(db: AsyncSession, user_id: uuid.UUID, campaign_id: str) -> dict:
    from app.models.campaign import CampaignEntity, CampaignEntry

    cid = uuid.UUID(campaign_id)
    campaign_q = await db.execute(select(Campaign).where(Campaign.id == cid))
    campaign = campaign_q.scalar_one_or_none()
    if not campaign:
        return {"error": "Campaign not found"}

    # Entries
    entries_q = await db.execute(
        select(Entry).join(CampaignEntry, CampaignEntry.entry_id == Entry.id).where(CampaignEntry.campaign_id == cid)
    )
    entries = entries_q.scalars().all()
    entry_ids = [e.id for e in entries]

    # Entities from entries — every junction type in the canonical map.
    entities_by_type: dict[str, list[dict]] = {}
    for etype, (model, junction, entity_fk) in ENTITY_CONFIG.items():
        items: list[dict] = []
        if entry_ids:
            q = await db.execute(
                select(model).join(junction, entity_fk == model.id).where(junction.entry_id.in_(entry_ids)).distinct()
            )
            items = [_brief_entity(etype, ent) for ent in q.scalars()]
        entities_by_type[_entity_result_key(etype)] = items

    # Linked entities
    linked_q = await db.execute(select(CampaignEntity).where(CampaignEntity.campaign_id == cid))
    linked = [{"entity_type": e.entity_type, "entity_id": str(e.entity_id), "role": e.role} for e in linked_q.scalars()]

    # Detection rules explicitly sourced from this campaign
    rules_q = await db.execute(select(DetectionRule).where(DetectionRule.source_campaigns.contains([cid])))
    rules = [
        {"id": str(r.id), "title": r.title, "rule_type": r.rule_type, "severity": r.severity} for r in rules_q.scalars()
    ]

    return {
        "campaign": {
            "id": str(campaign.id),
            "name": campaign.name,
            "status": campaign.status,
            "tlp_marking": campaign.tlp_marking,
            "description": campaign.description,
        },
        "entries": [
            {"id": str(e.id), "title": e.title, "url": e.url, "published_at": str(e.published_at)} for e in entries
        ],
        **entities_by_type,
        "linked_entities": linked,
        "detection_rules": rules,
        "stats": {
            "entries": len(entries),
            "detection_rules": len(rules),
            **{key: len(items) for key, items in entities_by_type.items()},
        },
    }


@_tool(
    name="get_automation_rules",
    description="List automation rules with optional label filter.",
    input_schema={
        "properties": {
            "label": {"type": "string", "description": "Filter by label"},
            "limit": {"type": "integer", "default": 30},
        },
    },
)
async def _get_automation_rules(
    db: AsyncSession, user_id: uuid.UUID, label: str | None = None, limit: int = 30
) -> dict:
    from app.models.automation_rule import AutomationRule

    q = select(AutomationRule).order_by(AutomationRule.created_at.desc()).limit(min(limit, 50))
    if label:
        q = q.where(AutomationRule.labels.contains([label]))
    result = await db.execute(q)
    rules = result.scalars().all()
    return {
        "rules": [
            {
                "id": str(r.id),
                "name": r.name,
                "trigger_type": r.trigger_type,
                "is_enabled": r.is_enabled,
                "labels": r.labels,
                "run_count": r.run_count,
                "last_triggered_at": str(r.last_triggered_at) if r.last_triggered_at else None,
            }
            for r in rules
        ]
    }


@_tool(
    name="get_automation_templates",
    description="List pre-built automation rule templates with categories.",
    input_schema={"properties": {}},
)
async def _get_automation_templates(db: AsyncSession, user_id: uuid.UUID) -> dict:
    from app.automation.templates import AUTOMATION_TEMPLATES, TEMPLATE_CATEGORIES

    return {"templates": AUTOMATION_TEMPLATES, "categories": TEMPLATE_CATEGORIES}


@_tool(
    name="get_automation_logs",
    description="Get recent automation execution logs.",
    input_schema={
        "properties": {
            "rule_id": {"type": "string", "description": "Optional: filter by specific rule"},
            "limit": {"type": "integer", "default": 30},
        },
    },
)
async def _get_automation_logs(
    db: AsyncSession, user_id: uuid.UUID, rule_id: str | None = None, limit: int = 30
) -> dict:
    from app.models.automation_log import AutomationLog
    from app.models.automation_rule import AutomationRule

    q = (
        select(AutomationLog)
        .join(AutomationRule, AutomationLog.rule_id == AutomationRule.id)
        .order_by(AutomationLog.executed_at.desc())
        .limit(min(limit, 50))
    )
    if rule_id:
        q = q.where(AutomationLog.rule_id == uuid.UUID(rule_id))
    result = await db.execute(q)
    logs = result.scalars().all()
    return {
        "logs": [
            {
                "id": str(lg.id),
                "rule_id": str(lg.rule_id),
                "entry_id": str(lg.entry_id) if lg.entry_id else None,
                "trigger_type": lg.trigger_type,
                "status": lg.status,
                "actions_executed": lg.actions_executed,
                "error_message": lg.error_message,
                "executed_at": str(lg.executed_at),
            }
            for lg in logs
        ]
    }


@_tool(
    name="get_trending_entities",
    description="Get top entities by mention count over a time window.",
    input_schema={
        "properties": {
            "entity_type": {
                "type": "string",
                "enum": ["threat_actor", "malware", "cve", "ttp"],
                "description": "Entity type to trend",
            },
            "days": {"type": "integer", "default": 30},
            "limit": {"type": "integer", "default": 10},
        },
        "required": ["entity_type"],
    },
)
async def _get_trending_entities(
    db: AsyncSession, user_id: uuid.UUID, entity_type: str, days: int = 30, limit: int = 10
) -> dict:
    from app.intelligence.analytics import entity_trending

    return {
        "entity_type": entity_type,
        "days": days,
        "trending": await entity_trending(db, entity_type, days=days, limit=limit),
    }


@_tool(
    name="get_feed_value",
    description="Get feed value scores — composite 0-100 intelligence contribution metric per feed.",
    input_schema={
        "properties": {
            "days": {"type": "integer", "default": 30},
        },
    },
)
async def _get_feed_value(db: AsyncSession, user_id: uuid.UUID, days: int = 30) -> dict:
    from app.intelligence.source_analytics import compute_feed_value_scores

    return await compute_feed_value_scores(db, days=days)


@_tool(
    name="get_source_reliability",
    description=(
        "Get feeds ranked by intelligence contribution: entity extractions across every entity "
        "junction type, plus detection rules generated from each feed's entries."
    ),
    input_schema={
        "properties": {
            "limit": {"type": "integer", "default": 20},
        },
    },
)
async def _get_source_reliability(db: AsyncSession, user_id: uuid.UUID, limit: int = 20) -> dict:
    from collections import Counter

    feeds_q = await db.execute(select(Feed).order_by(Feed.title).limit(100))
    feeds = feeds_q.scalars().all()

    entry_counts: dict[uuid.UUID, int] = {}
    q = await db.execute(select(Entry.feed_id, func.count(Entry.id)).group_by(Entry.feed_id))
    for feed_id, count in q:
        entry_counts[feed_id] = count

    # Entity links per feed, across every junction in the canonical map.
    entity_counts: Counter = Counter()
    for _etype, (_model, junction, _fk) in ENTITY_CONFIG.items():
        q = await db.execute(
            select(Entry.feed_id, func.count())
            .select_from(junction)
            .join(Entry, junction.entry_id == Entry.id)
            .group_by(Entry.feed_id)
        )
        for feed_id, count in q:
            entity_counts[feed_id] += count

    # Detection rules generated from each feed's entries.
    rule_counts: dict[uuid.UUID, int] = {}
    q = await db.execute(
        select(Entry.feed_id, func.count(DetectionRule.id))
        .select_from(DetectionRule)
        .join(Entry, DetectionRule.entry_id == Entry.id)
        .group_by(Entry.feed_id)
    )
    for feed_id, count in q:
        rule_counts[feed_id] = count

    results = []
    for f in feeds:
        entry_count = entry_counts.get(f.id, 0)
        if entry_count == 0:
            continue
        entity_count = entity_counts.get(f.id, 0)
        results.append(
            {
                "feed_id": str(f.id),
                "title": f.title,
                "feed_type": f.feed_type,
                "entry_count": entry_count,
                "entity_count": entity_count,
                "detection_rule_count": rule_counts.get(f.id, 0),
                "entities_per_article": round(entity_count / entry_count, 2) if entry_count else 0,
            }
        )

    results.sort(key=lambda x: x["entity_count"], reverse=True)
    return {"feeds": results[:limit]}


@_tool(
    name="get_entry_insights",
    description="Get actionable intelligence insights for a specific entry's entities.",
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID"},
        },
        "required": ["entry_id"],
    },
)
async def _get_entry_insights(db: AsyncSession, user_id: uuid.UUID, entry_id: str) -> dict:
    from app.intelligence.insights import generate_entry_insights

    return await generate_entry_insights(db, uuid.UUID(entry_id))


@_tool(
    name="get_triage_queue",
    description=(
        "Get priority-scored entry queue for analyst review. Uses the signal-engine "
        "ranking when signal_engine_surface is enabled, otherwise the legacy composite "
        "heuristic — mirroring GET /api/entries/triage."
    ),
    input_schema={
        "properties": {
            "days": {"type": "integer", "default": 7, "description": "Lookback window in days"},
            "limit": {"type": "integer", "default": 20},
        },
    },
)
async def _get_triage_queue(db: AsyncSession, user_id: uuid.UUID, days: int = 7, limit: int = 20) -> dict:
    from app.services.system_settings import get_setting
    from app.services.triage import get_triage_entries, get_triage_entries_signals

    if bool(await get_setting("signal_engine_surface", db)):
        return await get_triage_entries_signals(
            db, user_id, days=days, limit=min(limit, 50), offset=0, user_id_for_watches=user_id
        )
    return await get_triage_entries(db, user_id, days=days, limit=min(limit, 50), offset=0)


@_tool(
    name="get_priority_queue",
    description=(
        "The analyst's reading queue, exactly as the Priority Queue page shows it: unread entries "
        "that clear the radar threshold, ranked by signal score, with story threads folded in as "
        "single rows so a story eleven outlets covered is one item and not eleven. Ask this for "
        "'what should I read next' / 'what's important right now'. Prefer it over get_triage_queue, "
        "which is the older heuristic and does not fold stories."
    ),
    input_schema={
        "properties": {
            "limit": {"type": "integer", "description": "Entries per page (1-200, default 25); thread rows are extra"},
            "unread_only": {"type": "boolean", "description": "false also returns entries already read (default true)"},
            "with_threads": {"type": "boolean", "description": "false skips story folding (default true)"},
            "cursor": {"type": "string", "description": "next_cursor from a previous call, for the next page"},
        },
    },
    mutating=False,
)
async def _get_priority_queue(
    db: AsyncSession,
    user_id: uuid.UUID,
    limit: int = 25,
    unread_only: bool = True,
    with_threads: bool = True,
    cursor: str | None = None,
) -> dict:
    from app.api.entries import build_priority_queue
    from app.models.user import User

    if not 1 <= limit <= 200:
        return {"error": "limit must be between 1 and 200"}
    user = await db.get(User, user_id)
    if user is None:
        return {"error": "user not found"}

    page = await build_priority_queue(
        db,
        user,
        unread_only=unread_only,
        with_threads=with_threads,
        limit=limit,
        cursor=cursor,
    )

    items = []
    for row in page.items:
        if row.kind == "thread":
            th = row.thread
            items.append(
                {
                    "kind": "thread",
                    "score": round(row.score, 3),
                    "slug": th.slug,
                    "title": th.title,
                    "summary": th.summary,
                    "outlets": th.source_count,
                    "articles": th.entry_count,
                    "unread": th.unread_count,
                    "new_since_opened": th.new_since_opened,
                    "folded_articles": len(row.absorbed_entry_ids),
                    "url": f"/priority-queue?thread={th.slug}",
                }
            )
            continue
        e = row.entry
        items.append(
            {
                "kind": "entry",
                "score": round(row.score, 3),
                "entry_id": str(e.id),
                "title": e.title,
                "url": e.url,
                "feed": e.feed_title,
                "published_at": e.published_at,
                "summary": (e.summary or "")[:400] or None,
                "signals": [s.get("type") for s in (e.top_signals or [])],
            }
        )

    return {
        "items": items,
        "count": len(items),
        "has_more": page.has_more,
        "next_cursor": page.next_cursor,
        "radar_threshold": page.radar_threshold,
    }


@_tool(
    name="get_requirement_coverage",
    description="Get intelligence requirements coverage summary — counts by status, priority, category, and staleness.",
    input_schema={"properties": {}},
)
async def _get_requirement_coverage(db: AsyncSession, user_id: uuid.UUID) -> dict:
    from datetime import timedelta

    q = await db.execute(select(IntelligenceRequirement))
    reqs = q.scalars().all()

    from datetime import datetime

    now = datetime.now(UTC)
    stale_threshold = now - timedelta(days=30)

    by_status = {}
    by_priority = {}
    by_category = {}
    stale = 0
    for r in reqs:
        by_status[r.status] = by_status.get(r.status, 0) + 1
        if r.priority:
            by_priority[r.priority] = by_priority.get(r.priority, 0) + 1
        if r.category:
            by_category[r.category] = by_category.get(r.category, 0) + 1
        if r.status == "active" and (not r.last_matched_at or r.last_matched_at < stale_threshold):
            stale += 1

    return {
        "total": len(reqs),
        "by_status": by_status,
        "by_priority": by_priority,
        "by_category": by_category,
        "stale": stale,
        "requirements": [
            {
                "id": str(r.id),
                "title": r.title,
                "status": r.status,
                "priority": r.priority,
                "category": r.category,
                "match_count": r.match_count,
                "last_matched_at": str(r.last_matched_at) if r.last_matched_at else None,
            }
            for r in reqs
        ],
    }
