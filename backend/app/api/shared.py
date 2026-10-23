"""Public sharing API — create share links (authenticated) and view shared entries (public)."""

import html
import logging
import re
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Body, Depends, Path, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.intelligence.cve import calculate_cve_priority, risk_tier_for
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.country import Country, EntryCountry
from app.models.cve import CVE, EntryCVE
from app.models.cwe import CWE, EntryCWE
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.entry_media import EntryMedia
from app.models.feed import Feed
from app.models.glossary_term import GlossaryTerm
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.mitigation import EntryMitigation, Mitigation
from app.models.note import Note
from app.models.product import EntryProduct, Product
from app.models.shared_entry import SharedEntry
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.models.user import User
from app.models.vendor import EntryVendor, Vendor
from app.schemas.entry import EntryMediaBrief
from app.schemas.glossary import GlossaryMatchResponse, GlossaryTermResponse
from app.schemas.intelligence import (
    CVEResponse,
    CWEResponse,
    DetectionRuleResponse,
    EntryCountryResponse,
    MalwareFamilyResponse,
    MitigationResponse,
    ProductResponse,
    ThreatActorResponse,
    ToolResponse,
    TTPResponse,
    VendorResponse,
)
from app.schemas.note import NoteResponse

router = APIRouter()

logger = logging.getLogger(__name__)


def _entry_tts_text(entry: Entry) -> str:
    """Read-aloud speech text for an entry (same derivation the authed reader uses)."""
    from app.services.tts_text import normalize_plain_text, text_from_html

    if entry.content_html:
        return text_from_html(entry.content_html, entry.title)
    body = entry.content_text or entry.summary or ""
    return normalize_plain_text(f"{entry.title}\n\n{body}" if entry.title else body)


# --- Schemas ---


class ShareLinkResponse(BaseModel):
    token: str
    url: str
    created_at: datetime
    expires_at: datetime | None


class SharedEntryResponse(BaseModel):
    """Full entry with intelligence data for public viewing."""

    # Entry fields
    id: uuid.UUID
    title: str
    author: str | None
    url: str | None
    content_html: str | None
    content_text: str | None
    summary: str | None
    published_at: datetime | None
    fetched_at: datetime
    word_count: int | None
    image_url: str | None
    feed_title: str | None
    feed_type: str | None
    metadata: dict | None
    media: list[EntryMediaBrief] = []
    # Intelligence
    ttps: list[TTPResponse] = []
    cves: list[CVEResponse] = []
    cwes: list[CWEResponse] = []
    threat_actors: list[ThreatActorResponse] = []
    malware: list[MalwareFamilyResponse] = []
    countries: list[EntryCountryResponse] = []
    mitigations: list[MitigationResponse] = []
    tools: list[ToolResponse] = []
    vendors: list[VendorResponse] = []
    products: list[ProductResponse] = []
    detection_rules: list[DetectionRuleResponse] = []
    notes: list[NoteResponse] = []
    glossary_matches: list[GlossaryMatchResponse] = []
    referenced_urls: list[dict] = []
    ai_results: list[dict] = []
    ai_tasks: list[dict] = []
    # Share metadata
    shared_at: datetime


# --- Authenticated endpoints (manage share links) ---


@router.post("/entries/{entry_id}/share", response_model=ShareLinkResponse)
async def create_share_link(
    entry_id: uuid.UUID = Path(..., description="ID of the entry to share"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a public share link for an entry, or return the caller's existing active one.
    When server-side TTS is enabled, also pre-generates read-aloud audio (best-effort,
    24h eviction TTL) so it is ready when the share is first opened."""
    # Verify entry exists
    result = await db.execute(select(Entry).where(Entry.id == entry_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    # Check for the caller's existing active share
    existing = await db.execute(
        select(SharedEntry).where(
            SharedEntry.entry_id == entry_id,
            SharedEntry.created_by == user.id,
            SharedEntry.is_active.is_(True),
        )
    )
    share = existing.scalar_one_or_none()

    if not share:
        share = SharedEntry(entry_id=entry_id, created_by=user.id)
        db.add(share)
        await db.flush()

    # Pre-generate read-aloud audio so it's ready the moment the share is opened,
    # instead of waiting for the first viewer to click Listen. ttl_days=1 keeps this
    # share-scoped: the audio lapses after ~24h of no plays, then regenerates on
    # demand. Best-effort — a synthesis-enqueue hiccup must not fail the share.
    if settings.tts_enabled:
        try:
            from app.services import tts

            await tts.get_or_enqueue(
                db, source="entry", ref_id=str(entry.id), text=_entry_tts_text(entry), ttl_days=1.0
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Share TTS pre-generation failed for entry %s: %s", entry.id, exc)

    return ShareLinkResponse(
        token=share.token,
        url=f"/shared/{share.token}",
        created_at=share.created_at,
        expires_at=share.expires_at,
    )


@router.delete("/entries/{entry_id}/share")
async def revoke_share_link(
    entry_id: uuid.UUID = Path(..., description="ID of the entry whose share link to revoke"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate the caller's active share link for this entry so the public URL stops resolving.

    Admins deactivate every active share for the entry."""
    query = select(SharedEntry).where(
        SharedEntry.entry_id == entry_id,
        SharedEntry.is_active.is_(True),
    )
    if user.role != "admin":
        query = query.where(SharedEntry.created_by == user.id)
    result = await db.execute(query)
    shares = result.scalars().all()
    if not shares:
        raise AppError(code="not_found", message="No active share link", status_code=404)

    for share in shares:
        share.is_active = False
    return {"message": "Share link revoked"}


@router.get("/entries/{entry_id}/share", response_model=ShareLinkResponse | None)
async def get_share_link(
    entry_id: uuid.UUID = Path(..., description="ID of the entry to look up"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the caller's active share link for this entry, or null if they have not shared it."""
    result = await db.execute(
        select(SharedEntry).where(
            SharedEntry.entry_id == entry_id,
            SharedEntry.created_by == user.id,
            SharedEntry.is_active.is_(True),
        )
    )
    share = result.scalar_one_or_none()
    if not share:
        return None
    return ShareLinkResponse(
        token=share.token,
        url=f"/shared/{share.token}",
        created_at=share.created_at,
        expires_at=share.expires_at,
    )


# --- Public endpoint (no auth required) ---


@router.get("/shared/{token}", response_model=SharedEntryResponse)
async def get_shared_entry(
    token: str = Path(..., description="Share link token"),
    db: AsyncSession = Depends(get_db),
):
    """Public, unauthenticated view of a shared entry: the article plus its linked
    intelligence (TTPs, CVEs, actors, malware, notes, media, etc.).
    Returns 410 if the share link has expired."""
    # Look up share link
    result = await db.execute(select(SharedEntry).where(SharedEntry.token == token, SharedEntry.is_active.is_(True)))
    share = result.scalar_one_or_none()
    if not share:
        raise AppError(code="not_found", message="Share link not found or expired", status_code=404)

    # Check expiry
    if share.expires_at and share.expires_at < datetime.now(UTC):
        raise AppError(code="expired", message="Share link has expired", status_code=410)

    entry_id = share.entry_id

    # Fetch entry
    entry_result = await db.execute(select(Entry).where(Entry.id == entry_id))
    entry = entry_result.scalar_one_or_none()
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    # Feed info
    feed_result = await db.execute(select(Feed.title, Feed.feed_type).where(Feed.id == entry.feed_id))
    feed_row = feed_result.one_or_none()
    feed_title = feed_row[0] if feed_row else None
    feed_type = feed_row[1] if feed_row else None

    # Media
    media_result = await db.execute(select(EntryMedia).where(EntryMedia.entry_id == entry_id))
    media_items = [
        EntryMediaBrief(
            id=m.id,
            media_type=m.media_type,
            url=m.url,
            thumbnail_url=m.thumbnail_url,
            duration_seconds=m.duration_seconds,
        )
        for m in media_result.scalars().all()
    ]

    # TTPs
    ttp_result = await db.execute(
        select(TTP, EntryTTP.confidence, EntryTTP.source_text)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .where(EntryTTP.entry_id == entry_id)
        .order_by(TTP.tactic, TTP.technique_id)
    )
    ttps = []
    for ttp, confidence, source_text in ttp_result.all():
        resp = TTPResponse(
            id=ttp.id,
            technique_id=ttp.technique_id,
            technique_name=ttp.technique_name,
            tactic=ttp.tactic,
            description=ttp.description,
            platforms=ttp.platforms or [],
            data_sources=ttp.data_sources or [],
            mitre_url=ttp.mitre_url,
            detection=ttp.detection,
            is_subtechnique=ttp.is_subtechnique or False,
            first_seen_at=ttp.first_seen_at,
            last_seen_at=ttp.last_seen_at,
            article_count=ttp.article_count,
            confidence=confidence,
            source_text=source_text,
        )
        ttps.append(resp)

    # CVEs
    article_count_sq = (
        select(func.count(EntryCVE.entry_id))
        .where(EntryCVE.cve_id == CVE.id)
        .correlate(CVE)
        .scalar_subquery()
        .label("article_count")
    )
    cve_result = await db.execute(
        select(CVE, article_count_sq)
        .join(EntryCVE, EntryCVE.cve_id == CVE.id)
        .where(EntryCVE.entry_id == entry_id)
        .order_by(CVE.cvss_score.desc().nullslast())
    )
    cves = [
        CVEResponse(
            id=c.id,
            cve_id=c.cve_id,
            cvss_score=c.cvss_score,
            severity=c.severity,
            description=c.description,
            affected_products=c.affected_products,
            exploit_status=c.exploit_status,
            exploit_sources=c.exploit_sources,
            references_=c.references_ or [],
            nvd_data=c.nvd_data,
            timeline=c.timeline,
            first_seen_at=c.first_seen_at,
            updated_at=c.updated_at,
            article_count=ac or 0,
            epss_score=c.epss_score,
            epss_percentile=c.epss_percentile,
            epss_updated_at=c.epss_updated_at,
            exploit_availability=c.exploit_availability,
            exploit_status_source=c.exploit_status_source,
            github_poc_count=c.github_poc_count,
            github_poc_urls=c.github_poc_urls or [],
            metasploit_module=c.metasploit_module,
            is_kev=bool(c.is_kev),
            kev_date_added=c.kev_date_added,
            kev_due_date=c.kev_due_date,
            priority=calculate_cve_priority(c.cvss_score, c.epss_score, c.exploit_status, is_kev=bool(c.is_kev)),
            risk_tier=risk_tier_for(c),
        )
        for c, ac in cve_result.all()
    ]

    # Threat actors
    actor_result = await db.execute(
        select(ThreatActor)
        .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
        .where(EntryThreatActor.entry_id == entry_id)
        .order_by(ThreatActor.name)
    )
    threat_actors = [ThreatActorResponse.model_validate(a) for a in actor_result.scalars().all()]

    # Malware
    malware_result = await db.execute(
        select(MalwareFamily)
        .join(EntryMalware, EntryMalware.malware_family_id == MalwareFamily.id)
        .where(EntryMalware.entry_id == entry_id)
        .order_by(MalwareFamily.name)
    )
    malware_list = [MalwareFamilyResponse.model_validate(m) for m in malware_result.scalars().all()]

    # Countries
    country_result = await db.execute(
        select(Country, EntryCountry.role, EntryCountry.confidence, EntryCountry.source)
        .join(EntryCountry, EntryCountry.country_id == Country.id)
        .where(EntryCountry.entry_id == entry_id)
        .order_by(Country.name)
    )
    countries = [
        EntryCountryResponse(
            id=c.id,
            name=c.name,
            iso_code=c.iso_code,
            aliases=c.aliases or [],
            region=c.region,
            description=c.description,
            first_seen_at=c.first_seen_at,
            last_seen_at=c.last_seen_at,
            article_count=c.article_count,
            role=role,
            confidence=confidence,
            source=source,
        )
        for c, role, confidence, source in country_result.all()
    ]

    # Weaknesses
    cwe_result = await db.execute(
        select(CWE, EntryCWE)
        .join(EntryCWE, EntryCWE.cwe_id == CWE.id)
        .where(EntryCWE.entry_id == entry_id)
        .order_by(CWE.cwe_id)
    )
    cwes = [
        CWEResponse(
            id=c.id,
            cwe_id=c.cwe_id,
            name=c.name,
            kind=c.kind,
            abstraction=c.abstraction,
            status=c.status,
            mapping_usage=c.mapping_usage,
            description=c.description,
            parent_cwe_id=c.parent_cwe_id,
            alternate_terms=c.alternate_terms or [],
            capec_ids=c.capec_ids or [],
            cwe_url=c.cwe_url,
            is_deprecated=c.is_deprecated,
            superseded_by=c.superseded_by,
            article_count=c.article_count,
            first_seen_at=c.first_seen_at,
            last_seen_at=c.last_seen_at,
            confidence=link.confidence,
            source=link.source,
        )
        for c, link in cwe_result.all()
    ]

    # Mitigations
    mit_result = await db.execute(
        select(Mitigation, EntryMitigation)
        .join(EntryMitigation, EntryMitigation.mitigation_id == Mitigation.id)
        .where(EntryMitigation.entry_id == entry_id)
        .order_by(Mitigation.name)
    )
    mitigations = [
        MitigationResponse(
            id=m.id,
            mitre_id=m.mitre_id,
            name=m.name,
            description=m.description,
            mitre_url=m.mitre_url,
            cis_controls=m.cis_controls or [],
            nist_controls=m.nist_controls or [],
            article_count=m.article_count,
            first_seen_at=m.first_seen_at,
            last_seen_at=m.last_seen_at,
            confidence=link.confidence,
            source=link.source,
        )
        for m, link in mit_result.all()
    ]

    # Offensive tools
    tool_result = await db.execute(
        select(Tool, EntryTool)
        .join(EntryTool, EntryTool.tool_id == Tool.id)
        .where(EntryTool.entry_id == entry_id)
        .order_by(Tool.name)
    )
    tools = [
        ToolResponse(
            id=t.id,
            name=t.name,
            aliases=t.aliases or [],
            description=t.description,
            tool_type=t.tool_type,
            platforms=t.platforms or [],
            malpedia_url=t.malpedia_url,
            github_url=t.github_url,
            detection_artifacts=t.detection_artifacts or {},
            article_count=t.article_count,
            first_seen_at=t.first_seen_at,
            last_seen_at=t.last_seen_at,
            confidence=link.confidence,
        )
        for t, link in tool_result.all()
    ]

    # Notes
    note_result = await db.execute(
        select(Note).where(Note.entry_id == entry_id).order_by(Note.is_pinned.desc(), Note.created_at.desc())
    )
    notes = [NoteResponse.model_validate(n) for n in note_result.scalars().all()]

    # Detection rules
    rule_result = await db.execute(
        select(DetectionRule).where(DetectionRule.entry_id == entry_id).order_by(DetectionRule.created_at)
    )
    detection_rules = [
        DetectionRuleResponse(
            id=r.id,
            entry_id=r.entry_id,
            created_by=r.created_by,
            rule_type=r.rule_type,
            title=r.title,
            description=r.description,
            rule_content=r.rule_content,
            severity=r.severity,
            tags=r.tags or [],
            source_ttps=r.source_ttps or [],
            source_cves=r.source_cves or [],
            is_draft=r.is_draft,
            log_sources=r.log_sources,
            mitre_tactics=r.mitre_tactics or [],
            data_sources=r.data_sources or [],
            notes=r.notes,
            metadata_=r.metadata_,
            source_entries=r.source_entries or [],
            source_actors=r.source_actors or [],
            source_campaigns=r.source_campaigns or [],
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rule_result.scalars().all()
    ]

    # Vendors
    vendor_result = await db.execute(
        select(Vendor, EntryVendor)
        .join(EntryVendor, EntryVendor.vendor_id == Vendor.id)
        .where(EntryVendor.entry_id == entry_id)
        .order_by(Vendor.name)
    )
    vendors_list = [
        VendorResponse(
            id=v.id,
            name=v.name,
            aliases=v.aliases or [],
            description=v.description,
            website=v.website,
            vendor_type=v.vendor_type,
            article_count=v.article_count,
            first_seen_at=v.first_seen_at,
            last_seen_at=v.last_seen_at,
            confidence=link.confidence,
        )
        for v, link in vendor_result.all()
    ]

    # Products
    product_result = await db.execute(
        select(Product, EntryProduct)
        .join(EntryProduct, EntryProduct.product_id == Product.id)
        .where(EntryProduct.entry_id == entry_id)
        .order_by(Product.name)
    )
    products_list = [
        ProductResponse(
            id=p.id,
            vendor_id=p.vendor_id,
            vendor_name=None,
            name=p.name,
            aliases=p.aliases or [],
            description=p.description,
            product_type=p.product_type,
            website=p.website,
            article_count=p.article_count,
            first_seen_at=p.first_seen_at,
            last_seen_at=p.last_seen_at,
            confidence=link.confidence,
        )
        for p, link in product_result.all()
    ]

    # Referenced URLs
    referenced_urls_list: list[dict] = []
    html = entry.content_html or entry.summary or ""
    if html:
        from html import unescape
        from urllib.parse import urlparse

        link_pattern = re.compile(r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
        seen_urls: set[str] = set()
        for match in link_pattern.finditer(html):
            href = unescape(match.group(1)).strip()
            context_html = match.group(2).strip()
            context = re.sub(r"<[^>]+>", "", context_html).strip()
            parsed = urlparse(href)
            if parsed.scheme not in ("http", "https"):
                continue
            if "/api/image-proxy" in href:
                continue
            if href in seen_urls:
                continue
            seen_urls.add(href)
            referenced_urls_list.append({"url": href, "context": context or href})

    # AI Results (persisted)
    ai_results_query = await db.execute(
        select(AIResult)
        .where(
            AIResult.target_type == "entry",
            AIResult.target_id == entry_id,
            AIResult.is_current.is_(True),
        )
        .order_by(AIResult.created_at.desc())
    )
    ai_results_list = []
    for ar in ai_results_query.scalars().all():
        # Get task name
        task_result = await db.execute(select(AITask.name, AITask.display_name).where(AITask.id == ar.task_id))
        task_row = task_result.one_or_none()
        ai_results_list.append(
            {
                "id": str(ar.id),
                "target_type": ar.target_type,
                "target_id": str(ar.target_id) if ar.target_id else None,
                "is_current": ar.is_current,
                "task_id": str(ar.task_id),
                "task_name": task_row[0] if task_row else None,
                "model_name": ar.model_name,
                "parsed_result": ar.parsed_result,
                "cost_estimate": str(ar.cost_estimate) if ar.cost_estimate else None,
                "created_at": ar.created_at.isoformat() if ar.created_at else None,
            }
        )

    # AI Tasks (available analysis/generation tasks). Honors the per-task
    # "show in article actions" setting, mirroring the authenticated reader.
    EXCLUDED_SHARED_TASKS = {"detection_engineering_summary", "report_section", "detection_rules"}
    ai_tasks_query = await db.execute(
        select(AITask)
        .where(
            AITask.category.in_(["analysis", "generation"]),
            AITask.show_in_entry_actions.is_(True),
        )
        .order_by(AITask.name)
    )
    ai_tasks_list = [
        {
            "id": str(t.id),
            "name": t.name,
            "display_name": t.display_name,
            "description": t.description,
            "category": t.category,
            "variables": t.variables or [],
            "is_system": t.is_system,
            "show_in_entry_actions": t.show_in_entry_actions,
            "entry_action_order": t.entry_action_order,
            "show_in_entity_actions": t.show_in_entity_actions,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        }
        for t in ai_tasks_query.scalars().all()
        if t.name not in EXCLUDED_SHARED_TASKS
    ]

    # Glossary matches
    glossary_matches: list[GlossaryMatchResponse] = []
    text = entry.content_text or entry.summary or ""
    if text:
        glossary_result = await db.execute(select(GlossaryTerm))
        glossary_terms = glossary_result.scalars().all()
        for term in sorted(glossary_terms, key=lambda t: len(t.name), reverse=True):
            all_names = [term.name] + (term.search_terms or [])
            pattern = re.compile(
                "|".join(r"\b" + re.escape(n) + r"\b" for n in all_names),
                re.IGNORECASE,
            )
            found = pattern.findall(text)
            if found:
                glossary_matches.append(
                    GlossaryMatchResponse(
                        term=GlossaryTermResponse(
                            id=term.id,
                            name=term.name,
                            category=term.category,
                            maturity=term.maturity,
                            description=term.description,
                            long_description=term.long_description,
                            technologies=term.technologies or [],
                            search_terms=term.search_terms or [],
                            is_system=term.is_system,
                            created_by=term.created_by,
                            created_at=term.created_at,
                            updated_at=term.updated_at,
                        ),
                        match_count=len(found),
                    )
                )
        glossary_matches.sort(key=lambda m: m.match_count, reverse=True)

    return SharedEntryResponse(
        id=entry.id,
        title=entry.title,
        author=entry.author,
        url=entry.url,
        content_html=entry.content_html,
        content_text=entry.content_text,
        summary=entry.summary,
        published_at=entry.published_at,
        fetched_at=entry.fetched_at,
        word_count=entry.word_count,
        image_url=entry.image_url,
        feed_title=feed_title,
        feed_type=feed_type,
        metadata=entry.metadata_,
        media=media_items,
        ttps=ttps,
        cves=cves,
        threat_actors=threat_actors,
        malware=malware_list,
        countries=countries,
        cwes=cwes,
        mitigations=mitigations,
        tools=tools,
        vendors=vendors_list,
        products=products_list,
        detection_rules=detection_rules,
        notes=notes,
        glossary_matches=glossary_matches,
        referenced_urls=referenced_urls_list,
        ai_results=ai_results_list,
        ai_tasks=ai_tasks_list,
        shared_at=share.created_at,
    )


async def _resolve_active_share_entry(token: str, db: AsyncSession) -> Entry:
    """Validate a public share token and return its entry (same checks as the reader)."""
    result = await db.execute(select(SharedEntry).where(SharedEntry.token == token, SharedEntry.is_active.is_(True)))
    share = result.scalar_one_or_none()
    if not share:
        raise AppError(code="not_found", message="Share link not found or expired", status_code=404)
    if share.expires_at and share.expires_at < datetime.now(UTC):
        raise AppError(code="expired", message="Share link has expired", status_code=410)
    entry = (await db.execute(select(Entry).where(Entry.id == share.entry_id))).scalar_one_or_none()
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)
    return entry


@router.post("/shared/{token}/tts/prepare")
async def prepare_shared_tts(
    token: str = Path(..., description="Share link token"),
    db: AsyncSession = Depends(get_db),
):
    """Public read-aloud prepare — authorized by the share token, not a JWT."""
    from app.services import tts as _tts

    if not settings.tts_enabled:
        raise AppError(code="tts_disabled", message="Server-side read-aloud is disabled.", status_code=503)

    entry = await _resolve_active_share_entry(token, db)
    # Same cache key as the authed reader (source="entry"), so audio is shared.
    result = await _tts.get_or_enqueue(db, source="entry", ref_id=str(entry.id), text=_entry_tts_text(entry))
    return result


@router.get("/shared/{token}/tts/file/{cache_key}.mp3")
async def get_shared_tts_file(
    token: str = Path(..., description="Share link token"),
    cache_key: str = Path(..., description="Audio cache key returned by the prepare endpoint"),
    db: AsyncSession = Depends(get_db),
):
    """Public read-aloud file — authorized by the share token, not a JWT."""
    from app.api.tts import _serve_audio_file
    from app.services import tts as _tts

    # Token must be a valid, active share for the file to be served.
    await _resolve_active_share_entry(token, db)
    response = _serve_audio_file(cache_key)
    await _tts.touch(db, cache_key)
    return response


class RunSharedTaskRequest(BaseModel):
    task_name: str

    model_config = ConfigDict(json_schema_extra={"example": {"task_name": "threat_assessment"}})


@router.post("/shared/{token}/run-ai-task")
async def run_shared_ai_task(
    token: str = Path(..., description="Share link token"),
    body: RunSharedTaskRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """Run an AI task on a shared entry. Each task can only be executed once per article."""
    from app.ai.caller import Caller
    from app.ai.engine import run_task

    # Validate share token
    result = await db.execute(select(SharedEntry).where(SharedEntry.token == token, SharedEntry.is_active.is_(True)))
    share = result.scalar_one_or_none()
    if not share:
        raise AppError(code="not_found", message="Share link not found or expired", status_code=404)

    if share.expires_at and share.expires_at < datetime.now(UTC):
        raise AppError(code="expired", message="Share link has expired", status_code=410)

    entry_id = share.entry_id

    # Only allow analysis/generation tasks (no detection_rules, extraction, etc.)
    EXCLUDED_SHARED_TASKS = {"detection_engineering_summary", "report_section", "detection_rules"}
    task_result = await db.execute(select(AITask).where(AITask.name == body.task_name))
    task = task_result.scalar_one_or_none()
    if not task:
        raise AppError(code="not_found", message=f"Task '{body.task_name}' not found", status_code=404)
    if task.category not in ("analysis", "generation") or task.name in EXCLUDED_SHARED_TASKS:
        raise AppError(code="forbidden", message="This task cannot be run on shared articles", status_code=403)

    # One-time enforcement: check if already run. limit(1) keeps this an
    # existence check — a target carrying duplicate current rows should still
    # get a clean 409, not a MultipleResultsFound 500.
    existing = await db.execute(
        select(AIResult)
        .where(
            AIResult.target_type == "entry",
            AIResult.target_id == entry_id,
            AIResult.is_current.is_(True),
            AIResult.task_id == task.id,
        )
        .limit(1)
    )
    existing_result = existing.scalar_one_or_none()
    if existing_result:
        raise AppError(
            code="already_executed",
            message="This AI analysis has already been run on this article",
            status_code=409,
        )

    # Fetch entry for task input
    entry_result = await db.execute(select(Entry).where(Entry.id == entry_id))
    entry = entry_result.scalar_one_or_none()
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    # Build entry data dict
    entry_data = {
        "title": entry.title or "",
        "author": entry.author or "",
        "url": entry.url or "",
        "content": entry.content_text or entry.summary or "",
        "summary": entry.summary or "",
        "published_at": entry.published_at.isoformat() if entry.published_at else "",
    }

    # The sharer is recorded as the attributed user, but the caller is the
    # anonymous link: share traffic is pipeline spend, never a person's.
    parsed = await run_task(
        db=db,
        user_id=share.created_by,
        task_name=body.task_name,
        variables={"entry": entry_data},
        entry_id=entry_id,
        target_type="entry",
        target_id=entry_id,
        caller=Caller.share(share.created_by),
    )
    if parsed is None:
        raise AppError(
            code="not_configured",
            message=f"AI task '{body.task_name}' is not configured",
            status_code=422,
        )

    # Fetch the saved result for metadata
    latest = (
        await db.execute(
            select(AIResult)
            .where(
                AIResult.target_type == "entry",
                AIResult.target_id == entry_id,
                AIResult.is_current.is_(True),
                AIResult.task_id == task.id,
            )
            .order_by(AIResult.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    return {
        "task_name": body.task_name,
        "entry_id": str(entry_id),
        "result": parsed,
        "model_name": latest.model_name if latest else None,
        "cost_estimate": str(latest.cost_estimate) if latest and latest.cost_estimate else None,
    }


class SharedAskAgentMessage(BaseModel):
    role: str
    content: str


class SharedAskAgentRequest(BaseModel):
    question: str
    history: list[SharedAskAgentMessage] = []

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "question": "Which initial access technique does this article describe?",
                "history": [
                    {"role": "user", "content": "Summarize this article."},
                    {"role": "assistant", "content": "The article covers a LockBit intrusion..."},
                ],
            }
        }
    )


@router.post("/shared/{token}/ask-agent")
async def shared_ask_agent(
    token: str = Path(..., description="Share link token"),
    body: SharedAskAgentRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """Ask the AI agent a question about a shared entry."""
    from app.ai.caller import Caller
    from app.ai.engine import (
        _get_provider_instance,
        get_active_prompt,
        get_task_assignment,
        record_direct_result,
        render_prompt,
    )

    # Validate share token
    result = await db.execute(select(SharedEntry).where(SharedEntry.token == token, SharedEntry.is_active.is_(True)))
    share = result.scalar_one_or_none()
    if not share:
        raise AppError(code="not_found", message="Share link not found or expired", status_code=404)
    if share.expires_at and share.expires_at < datetime.now(UTC):
        raise AppError(code="expired", message="Share link has expired", status_code=410)

    entry = await db.get(Entry, share.entry_id)
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    if not body.question.strip():
        raise AppError(code="bad_request", message="Question is required", status_code=400)

    assignment_data = await get_task_assignment(db, share.created_by, "entry_qa")
    if not assignment_data:
        raise AppError(code="not_configured", message="Ask Agent is not configured", status_code=422)

    assignment, task, provider_model = assignment_data
    system_template, user_template = await get_active_prompt(db, task.id)

    entry_dict = {
        "title": entry.title,
        "content_text": entry.content_text or "",
        "content_html": entry.content_html,
        "summary": entry.summary,
        "author": entry.author,
        "url": entry.url,
        "published_at": str(entry.published_at) if entry.published_at else "",
        "feed_title": "",
    }
    variables = {
        "entry": entry_dict,
        "question": body.question,
        "conversation_history": [{"role": m.role, "content": m.content} for m in body.history],
    }
    rendered_system = render_prompt(system_template, variables) if system_template else None
    rendered_user = render_prompt(user_template, variables)

    provider = _get_provider_instance(provider_model)
    config = {**provider_model.config, **assignment.config}
    temperature = config.get("temperature", 0.3)
    max_tokens = config.get("max_tokens", 2048)

    caller = Caller.share(share.created_by)
    ledger = dict(
        caller=caller,
        task=task,
        provider_model=provider_model,
        model_name=assignment.model_name,
        prompt_used=rendered_user,
        target_type="share_qa",
        target_id=share.id,
    )
    try:
        response = await provider.complete(
            prompt=rendered_user,
            system=rendered_system,
            temperature=temperature,
            max_tokens=max_tokens,
            model=assignment.model_name,
        )
    except Exception as e:
        # Commit before raising: the session dependency rolls back on any
        # exception, and a failed call still has to count as a request.
        await record_direct_result(db, response=None, error=str(e), **ledger)
        await db.commit()
        raise AppError(code="ai_error", message=f"AI provider error: {e}", status_code=502)

    await record_direct_result(db, response=response, **ledger)
    return {"answer": response.content, "model": response.model}


# --- OpenGraph preview endpoint ---
# Crawlers (Discord, Slack, Twitter, …) are routed to this by the frontend nginx
# config based on User-Agent. Returns a minimal HTML page whose only purpose is to
# carry per-article OG/Twitter meta tags so link previews show the article — not
# the generic site card.

_OG_DESCRIPTION_LIMIT = 280


def _truncate(text: str | None, limit: int) -> str:
    if not text:
        return ""
    no_tags = re.sub(r"<[^>]+>", " ", text)
    cleaned = re.sub(r"\s+", " ", html.unescape(no_tags)).strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1].rstrip() + "…"


@router.get("/shared/{token}/og", response_class=HTMLResponse, include_in_schema=False)
async def get_shared_entry_og(
    token: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    result = await db.execute(select(SharedEntry).where(SharedEntry.token == token, SharedEntry.is_active.is_(True)))
    share = result.scalar_one_or_none()
    if not share or (share.expires_at and share.expires_at < datetime.now(UTC)):
        # Crawlers handle 404 gracefully; humans still get the SPA via the normal
        # /shared/{token} path so they see the in-app expired/not-found state.
        return HTMLResponse(status_code=404, content="<!doctype html><title>Not found</title>")

    entry_result = await db.execute(select(Entry).where(Entry.id == share.entry_id))
    entry = entry_result.scalar_one_or_none()
    if not entry:
        return HTMLResponse(status_code=404, content="<!doctype html><title>Not found</title>")

    feed_result = await db.execute(select(Feed.title).where(Feed.id == entry.feed_id))
    feed_title = feed_result.scalar_one_or_none() or "IntelFeed"

    title = entry.title or "Shared article"
    description = _truncate(entry.summary or entry.content_text, _OG_DESCRIPTION_LIMIT) or feed_title
    image = entry.image_url or ""
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.hostname or ""
    canonical_url = f"{proto}://{host}/shared/{token}"

    e = html.escape
    image_tag = (
        f'<meta property="og:image" content="{e(image)}" /><meta name="twitter:image" content="{e(image)}" />'
        if image
        else ""
    )
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{e(title)}</title>
<link rel="canonical" href="{e(canonical_url)}" />
<meta name="description" content="{e(description)}" />
<meta property="og:type" content="article" />
<meta property="og:site_name" content="IntelFeed" />
<meta property="og:title" content="{e(title)}" />
<meta property="og:description" content="{e(description)}" />
<meta property="og:url" content="{e(canonical_url)}" />
<meta property="article:section" content="{e(feed_title)}" />
<meta name="twitter:card" content="{"summary_large_image" if image else "summary"}" />
<meta name="twitter:title" content="{e(title)}" />
<meta name="twitter:description" content="{e(description)}" />
{image_tag}
</head>
<body>
<h1>{e(title)}</h1>
<p>{e(description)}</p>
<p><a href="{e(canonical_url)}">Open in IntelFeed</a></p>
</body>
</html>
"""
    return HTMLResponse(content=body, headers={"Cache-Control": "public, max-age=300"})


@router.get("/shared/copilot/{token}")
async def get_shared_conversation(
    token: str = Path(..., description="Conversation share token"),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Public, read-only view of a shared copilot conversation (no auth)."""
    from app.models.ai_conversation import AIConversation

    conv = (await db.execute(select(AIConversation).where(AIConversation.share_token == token))).scalar_one_or_none()
    if not conv or not conv.share_token:
        raise AppError(code="not_found", message="Shared conversation not found", status_code=404)
    return {
        "title": conv.title,
        "scope_type": conv.scope_type,
        "messages": conv.messages or [],
    }
