"""BE-16: Entity profile editing API.

Allows updating editable fields on threat actors, malware families, CVEs, and TTPs.
Includes entity merge and duplicate detection.
"""

import logging
import re
import uuid
from datetime import UTC

from fastapi import APIRouter, Body, Depends, Path, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.core.exceptions import AppError
from app.core.security import get_admin_user, get_current_user, get_viewer
from app.database import get_db
from app.intelligence.correlation_cache import invalidate_entity_cache
from app.intelligence.entity_dedup import find_entity_by_name_or_alias
from app.intelligence.entity_resolution import (
    DENIABLE_TYPES,
    deniable_names,
    deny_entity_names,
    resolve_entity_creation,
)
from app.models.campaign import Campaign, CampaignEntity, CampaignEntry
from app.models.country import Country, EntryCountry
from app.models.cve import CVE, EntryCVE
from app.models.entity_note import EntityNote
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.mitigation import EntryMitigation, Mitigation, TTPMitigation
from app.models.product import EntryProduct, Product
from app.models.sector import Sector
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.models.user import User
from app.models.vendor import EntryVendor, Vendor
from app.services.entity_backlink import dispatch_backlink_for_added_aliases, dispatch_entity_backlink
from app.services.entity_indexer import delete_entity_document
from app.services.entity_summary import ENTITY_MODEL_MAP, generate_entity_assessment

logger = logging.getLogger(__name__)

router = APIRouter()


# --- Merge config: entity_type -> (Model, JunctionModel, junction_fk_attr) ---
MERGE_CONFIG = {
    "threat_actor": (ThreatActor, EntryThreatActor, "threat_actor_id"),
    "malware": (MalwareFamily, EntryMalware, "malware_family_id"),
    "country": (Country, EntryCountry, "country_id"),
    "tool": (Tool, EntryTool, "tool_id"),
    "vendor": (Vendor, EntryVendor, "vendor_id"),
    "product": (Product, EntryProduct, "product_id"),
}


async def _unlink_entries_for_removed_aliases(
    db: AsyncSession,
    old_aliases: list[str],
    new_aliases: list[str],
    junction_table,
    entity_id_col,
    entity_id: uuid.UUID,
) -> int:
    """When aliases are removed from an entity, unlink entries that were linked only via those aliases.

    Compares old and new alias lists (case-insensitive). A junction row is deleted
    iff every value in its matched_names array is a removed alias — i.e. no remaining
    matched form would still trigger the link.
    """
    old_set = {a.lower() for a in (old_aliases or [])}
    new_set = {a.lower() for a in (new_aliases or [])}
    removed = old_set - new_set
    if not removed:
        return 0

    result = await db.execute(select(junction_table).where(entity_id_col == entity_id))
    deleted_ids: list[uuid.UUID] = []
    for row in result.scalars().all():
        names = row.matched_names or []
        if not names:
            continue
        if all((n or "").lower() in removed for n in names):
            await db.delete(row)
            deleted_ids.append(row.entry_id)

    if deleted_ids:
        logger.info(
            "Unlinked %d entries from entity %s due to removed aliases: %s",
            len(deleted_ids),
            entity_id,
            removed,
        )
    return len(deleted_ids)


# --- Schemas ---


class ThreatActorCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    aliases: list[str] | None = None
    description: str | None = None
    country: str | None = None
    motivation: str | None = None
    entry_id: uuid.UUID | None = None
    # Logged "create anyway" override for creation-gate rejections (manual UI only).
    force: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "APT29",
                "aliases": ["Cozy Bear", "Midnight Blizzard", "Nobelium"],
                "description": "Russian state-sponsored espionage group targeting governments and think tanks.",
                "country": "Russia",
                "motivation": "espionage",
            }
        }
    )


class MalwareFamilyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    aliases: list[str] | None = None
    description: str | None = None
    malware_type: str | None = None
    entry_id: uuid.UUID | None = None
    force: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "LockBit",
                "aliases": ["LockBit 3.0", "LockBit Black"],
                "description": "Ransomware-as-a-service family used in double-extortion attacks.",
                "malware_type": "ransomware",
            }
        }
    )


class CVECreate(BaseModel):
    cve_id: str = Field(..., min_length=1, max_length=20, pattern=r"^CVE-\d{4}-\d{4,}$")
    description: str | None = None
    severity: str | None = Field(default=None, pattern=r"^(CRITICAL|HIGH|MEDIUM|LOW|NONE)$")
    cvss_score: float | None = None
    affected_products: list | None = None
    exploit_status: str | None = None
    exploit_availability: str | None = Field(default=None, pattern=r"^(none|poc|weaponized|active_exploitation)$")
    entry_id: uuid.UUID | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "cve_id": "CVE-2024-3400",
                "description": "Command injection in PAN-OS GlobalProtect allowing unauthenticated RCE.",
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "affected_products": ["PAN-OS 10.2", "PAN-OS 11.0"],
                "exploit_availability": "active_exploitation",
            }
        }
    )


class TTPCreate(BaseModel):
    technique_id: str = Field(..., min_length=1, max_length=20)
    technique_name: str = Field(..., min_length=1, max_length=255)
    tactic: str | None = None
    description: str | None = None
    platforms: list[str] | None = None
    data_sources: list[str] | None = None
    is_subtechnique: bool = False
    entry_id: uuid.UUID | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "technique_id": "T1566.001",
                "technique_name": "Spearphishing Attachment",
                "tactic": "initial-access",
                "platforms": ["Windows", "macOS", "Linux"],
                "is_subtechnique": True,
            }
        }
    )


class CountryCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    iso_code: str | None = None
    aliases: list[str] | None = None
    region: str | None = None
    description: str | None = None
    entry_id: uuid.UUID | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "North Korea",
                "iso_code": "KP",
                "aliases": ["DPRK"],
                "region": "Asia",
            }
        }
    )


class MitigationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    mitre_id: str | None = None
    description: str | None = None
    mitre_url: str | None = None
    entry_id: uuid.UUID | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "User Training",
                "mitre_id": "M1017",
                "mitre_url": "https://attack.mitre.org/mitigations/M1017/",
            }
        }
    )


class ToolCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    aliases: list[str] | None = None
    description: str | None = None
    tool_type: str | None = None
    github_url: str | None = None
    entry_id: uuid.UUID | None = None
    force: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Cobalt Strike",
                "aliases": ["CS", "Beacon"],
                "description": "Commercial adversary-simulation framework widely abused for post-exploitation C2.",
                "tool_type": "c2_framework",
            }
        }
    )


class VendorCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    aliases: list[str] | None = None
    description: str | None = None
    website: str | None = None
    vendor_type: str | None = None
    entry_id: uuid.UUID | None = None
    force: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Palo Alto Networks",
                "aliases": ["PAN"],
                "website": "https://www.paloaltonetworks.com",
                "vendor_type": "security",
            }
        }
    )


class ProductCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    aliases: list[str] | None = None
    description: str | None = None
    product_type: str | None = None
    website: str | None = None
    vendor_id: uuid.UUID | None = None
    entry_id: uuid.UUID | None = None
    force: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "PAN-OS",
                "description": "Operating system for Palo Alto Networks next-generation firewalls.",
                "product_type": "firewall",
                "vendor_id": "b7e3d1f5-2a4c-4d8e-9f0a-1b2c3d4e5f6a",
            }
        }
    )


class ThreatActorUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    aliases: list[str] | None = None
    description: str | None = None
    mitre_id: str | None = None
    country: str | None = None
    motivation: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "aliases": ["Cozy Bear", "Midnight Blizzard", "Nobelium"],
                "motivation": "espionage",
            }
        }
    )


class MalwareFamilyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    aliases: list[str] | None = None
    description: str | None = None
    malpedia_url: str | None = None
    malware_type: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "malware_type": "ransomware",
                "malpedia_url": "https://malpedia.caad.fkie.fraunhofer.de/details/win.lockbit",
            }
        }
    )


class CVEUpdate(BaseModel):
    description: str | None = None
    severity: str | None = None
    exploit_status: str | None = None
    affected_products: list | None = None
    exploit_availability: str | None = Field(default=None, pattern=r"^(none|poc|weaponized|active_exploitation)$")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "severity": "CRITICAL",
                "exploit_availability": "active_exploitation",
            }
        }
    )


class CountryUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    iso_code: str | None = None
    aliases: list[str] | None = None
    region: str | None = None
    description: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "aliases": ["DPRK"],
                "region": "Asia",
            }
        }
    )


class SectorUpdate(BaseModel):
    """A sector's name and slug are the vocabulary itself and never change here."""

    aliases: list[str] | None = None
    description: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "aliases": ["hospitals", "health systems", "pharma"],
                "description": "Hospitals, health systems, clinics, insurers and medical-device makers.",
            }
        }
    )


class ToolUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    aliases: list[str] | None = None
    description: str | None = None
    tool_type: str | None = None
    malpedia_url: str | None = None
    github_url: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "tool_type": "credential_theft",
                "github_url": "https://github.com/gentilkiwi/mimikatz",
            }
        }
    )


class VendorUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    aliases: list[str] | None = None
    description: str | None = None
    website: str | None = None
    vendor_type: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "website": "https://www.paloaltonetworks.com",
                "vendor_type": "security",
            }
        }
    )


class ProductUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    aliases: list[str] | None = None
    description: str | None = None
    product_type: str | None = None
    website: str | None = None
    vendor_id: uuid.UUID | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "product_type": "firewall",
                "vendor_id": "b7e3d1f5-2a4c-4d8e-9f0a-1b2c3d4e5f6a",
            }
        }
    )


class TTPUpdate(BaseModel):
    technique_name: str | None = None
    tactic: str | None = None
    description: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "technique_name": "Spearphishing Attachment",
                "tactic": "initial-access",
            }
        }
    )


# --- Create endpoints ---


async def _resolve_manual(db: AsyncSession, entity_type: str, name: str, aliases: list[str] | None, force: bool):
    """Run the creation resolver for a manual-UI create.

    Returns the matched entity (upsert path) or None (clear to create). Gate
    rejections surface as 409 with the reason so the UI can show a warning and
    offer the logged "create anyway" retry (``force=true``); ``force`` bypasses
    gates but never the matchers or tombstones.
    """
    decision = await resolve_entity_creation(db, entity_type, name, aliases, source="manual", override=force)
    if decision.action in ("blocked", "held", "tombstone"):
        raise AppError(
            code="entity_creation_gated",
            message=(
                f"Creation of {entity_type} '{name}' was rejected by the entity guardrails "
                f"({decision.reason or decision.action}). Retry with force=true to create anyway."
            ),
            status_code=409,
            details=[{"reason": decision.reason or decision.action, **decision.detail}],
        )
    return decision.entity


async def _apply_fields(db: AsyncSession, entity_type: str, entity, body, fields: list[str], user) -> None:
    """Copy the supplied body fields onto the entity, recording each real change
    as an analyst claim.

    Only fields whose value actually moves are recorded: a profile save that
    re-submits unchanged values must not re-stamp every field as freshly
    asserted by whoever hit save, or genuine provenance drowns in no-ops.
    """
    from app.services.claim_provenance import record_claims, render_value

    changed: dict = {}
    for field in fields:
        value = getattr(body, field, None)
        if value is None:
            continue
        if render_value(value) != render_value(getattr(entity, field, None)):
            changed[field] = value
        setattr(entity, field, value)
    if changed:
        await record_claims(
            db,
            entity_type=entity_type,
            entity_id=entity.id,
            values=changed,
            source_kind="analyst",
            created_by=getattr(user, "id", None),
        )


async def _assert_name_available(db: AsyncSession, model, new_name: str, exclude_id: uuid.UUID) -> None:
    """Raise 409 if another row of ``model`` already uses ``new_name`` (case-insensitive).

    The name-owning entity tables carry a unique(name) constraint; without this
    pre-check a rename to a taken name surfaces as a raw 500 IntegrityError.
    """
    clash = (
        await db.execute(
            select(model.id).where(
                func.lower(model.name) == new_name.strip().lower(),
                model.id != exclude_id,
            )
        )
    ).scalar_one_or_none()
    if clash is not None:
        raise AppError(
            code="conflict",
            message=f"An entity named '{new_name}' already exists in this type.",
            status_code=409,
        )


@router.post("/threat-actors", status_code=201)
async def create_threat_actor_manual(
    body: ThreatActorCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually create a threat actor and optionally link it to an entry."""
    # Resolver: case/normalized-insensitive upsert against name + aliases, plus
    # the creation gates (manual keeps a logged "create anyway" override).
    actor = await _resolve_manual(db, "threat_actor", body.name, body.aliases, body.force)
    is_new = actor is None

    if is_new:
        actor = ThreatActor(
            name=body.name,
            aliases=body.aliases or [],
            description=body.description,
            country=body.country,
            motivation=body.motivation,
        )
        db.add(actor)
        await db.flush()
        await db.refresh(actor)
    else:
        if body.aliases:
            actor.aliases = body.aliases
        if body.description:
            actor.description = body.description
        if body.country:
            actor.country = body.country
        if body.motivation:
            actor.motivation = body.motivation

    if body.entry_id:
        # Atomic upsert: the resolver may have matched an existing actor that is
        # already linked to this entry (alias hit), and a bare insert would raise
        # the duplicate-PK IntegrityError as an unhandled 500.
        await db.execute(
            pg_insert(EntryThreatActor)
            .values(entry_id=body.entry_id, threat_actor_id=actor.id)
            .on_conflict_do_nothing()
        )
        await db.flush()

    if is_new:
        dispatch_entity_backlink("threat_actor", str(actor.id))

    return {
        "id": str(actor.id),
        "name": actor.name,
        "aliases": actor.aliases,
        "description": actor.description,
        "country": actor.country,
        "motivation": actor.motivation,
    }


@router.post("/malware", status_code=201)
async def create_malware_manual(
    body: MalwareFamilyCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually create a malware family and optionally link it to an entry."""
    # Resolver: case/normalized-insensitive upsert against name + aliases, plus
    # the creation gates (manual keeps a logged "create anyway" override).
    malware = await _resolve_manual(db, "malware", body.name, body.aliases, body.force)
    is_new = malware is None

    if is_new:
        malware = MalwareFamily(
            name=body.name,
            aliases=body.aliases or [],
            description=body.description,
            malware_type=body.malware_type,
        )
        db.add(malware)
        await db.flush()
        await db.refresh(malware)
    else:
        if body.aliases:
            malware.aliases = body.aliases
        if body.description:
            malware.description = body.description
        if body.malware_type:
            malware.malware_type = body.malware_type

    if body.entry_id:
        # Atomic upsert — see create_threat_actor_manual.
        await db.execute(
            pg_insert(EntryMalware)
            .values(entry_id=body.entry_id, malware_family_id=malware.id, source="manual")
            .on_conflict_do_nothing()
        )
        await db.flush()

    if is_new:
        dispatch_entity_backlink("malware", str(malware.id))

    return {
        "id": str(malware.id),
        "name": malware.name,
        "aliases": malware.aliases,
        "description": malware.description,
        "malware_type": malware.malware_type,
    }


@router.post("/cves", status_code=201)
async def create_cve_manual(
    body: CVECreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually create a CVE and optionally link it to an entry."""
    result = await db.execute(select(CVE).where(func.upper(CVE.cve_id) == body.cve_id.upper()))
    cve = result.scalar_one_or_none()
    is_new = cve is None

    if is_new:
        cve = CVE(
            cve_id=body.cve_id.upper(),
            description=body.description,
            severity=body.severity,
            cvss_score=body.cvss_score,
            affected_products=body.affected_products or [],
            exploit_status=body.exploit_status,
            exploit_availability=body.exploit_availability,
            exploit_status_source=("manual" if (body.exploit_status or body.exploit_availability) else None),
        )
        db.add(cve)
        await db.flush()
        await db.refresh(cve)
    else:
        if body.description:
            cve.description = body.description
        if body.severity:
            cve.severity = body.severity
        if body.cvss_score is not None:
            cve.cvss_score = body.cvss_score
        if body.exploit_status:
            cve.exploit_status = body.exploit_status
        if body.exploit_availability:
            cve.exploit_availability = body.exploit_availability
        if body.exploit_status or body.exploit_availability:
            cve.exploit_status_source = "manual"

    if body.entry_id:
        existing_link = await db.execute(
            select(EntryCVE).where(EntryCVE.entry_id == body.entry_id, EntryCVE.cve_id == cve.id)
        )
        if not existing_link.scalar_one_or_none():
            db.add(EntryCVE(entry_id=body.entry_id, cve_id=cve.id))

    await db.flush()
    await db.refresh(cve)

    if is_new:
        dispatch_entity_backlink("cve", str(cve.id))

    return {
        "id": str(cve.id),
        "cve_id": cve.cve_id,
        "description": cve.description,
        "severity": cve.severity,
        "cvss_score": float(cve.cvss_score) if cve.cvss_score else None,
    }


@router.post("/ttps", status_code=201)
async def create_ttp_manual(
    body: TTPCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually create a TTP and optionally link it to an entry."""
    result = await db.execute(select(TTP).where(func.upper(TTP.technique_id) == body.technique_id.upper()))
    ttp = result.scalar_one_or_none()
    is_new = ttp is None

    if is_new:
        ttp = TTP(
            technique_id=body.technique_id.upper(),
            technique_name=body.technique_name,
            tactic=body.tactic,
            description=body.description,
            platforms=body.platforms or [],
            data_sources=body.data_sources or [],
            is_subtechnique=body.is_subtechnique,
        )
        db.add(ttp)
        await db.flush()
        await db.refresh(ttp)
    else:
        if body.technique_name:
            ttp.technique_name = body.technique_name
        if body.tactic:
            ttp.tactic = body.tactic
        if body.description:
            ttp.description = body.description

    if body.entry_id:
        existing_link = await db.execute(
            select(EntryTTP).where(EntryTTP.entry_id == body.entry_id, EntryTTP.ttp_id == ttp.id)
        )
        if not existing_link.scalar_one_or_none():
            db.add(EntryTTP(entry_id=body.entry_id, ttp_id=ttp.id))

    await db.flush()
    await db.refresh(ttp)

    if is_new:
        dispatch_entity_backlink("ttp", str(ttp.id))

    return {
        "id": str(ttp.id),
        "technique_id": ttp.technique_id,
        "technique_name": ttp.technique_name,
        "tactic": ttp.tactic,
        "description": ttp.description,
    }


@router.post("/countries", status_code=201)
async def create_country_manual(
    body: CountryCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually create a country and optionally link it to an entry."""
    country = await find_entity_by_name_or_alias(db, Country, body.name, body.aliases)
    is_new = country is None

    if is_new:
        country = Country(
            name=body.name,
            iso_code=body.iso_code,
            aliases=body.aliases or [],
            region=body.region,
            description=body.description,
        )
        db.add(country)
        await db.flush()
        await db.refresh(country)
    else:
        if body.iso_code:
            country.iso_code = body.iso_code
        if body.aliases:
            country.aliases = body.aliases
        if body.region:
            country.region = body.region
        if body.description:
            country.description = body.description

    if body.entry_id:
        existing_link = await db.execute(
            select(EntryCountry).where(EntryCountry.entry_id == body.entry_id, EntryCountry.country_id == country.id)
        )
        if not existing_link.scalar_one_or_none():
            db.add(EntryCountry(entry_id=body.entry_id, country_id=country.id))

    await db.flush()
    await db.refresh(country)

    if is_new:
        dispatch_entity_backlink("country", str(country.id))

    return {
        "id": str(country.id),
        "name": country.name,
        "iso_code": country.iso_code,
        "aliases": country.aliases,
        "region": country.region,
        "description": country.description,
    }


@router.post("/mitigations", status_code=201)
async def create_mitigation_manual(
    body: MitigationCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually create a mitigation and optionally link it to an entry."""
    if body.mitre_id:
        result = await db.execute(select(Mitigation).where(func.upper(Mitigation.mitre_id) == body.mitre_id.upper()))
    else:
        result = await db.execute(select(Mitigation).where(func.lower(Mitigation.name) == body.name.lower()))
    mitigation = result.scalar_one_or_none()
    is_new = mitigation is None

    if is_new:
        mitigation = Mitigation(
            name=body.name,
            mitre_id=body.mitre_id,
            description=body.description,
            mitre_url=body.mitre_url,
        )
        db.add(mitigation)
        await db.flush()
        await db.refresh(mitigation)
    else:
        if body.description:
            mitigation.description = body.description
        if body.mitre_url:
            mitigation.mitre_url = body.mitre_url

    if body.entry_id:
        existing_link = await db.execute(
            select(EntryMitigation).where(
                EntryMitigation.entry_id == body.entry_id,
                EntryMitigation.mitigation_id == mitigation.id,
            )
        )
        if not existing_link.scalar_one_or_none():
            db.add(EntryMitigation(entry_id=body.entry_id, mitigation_id=mitigation.id))

    await db.flush()
    await db.refresh(mitigation)

    if is_new:
        dispatch_entity_backlink("mitigation", str(mitigation.id))

    return {
        "id": str(mitigation.id),
        "name": mitigation.name,
        "mitre_id": mitigation.mitre_id,
        "description": mitigation.description,
    }


@router.post("/tools", status_code=201)
async def create_tool_manual(
    body: ToolCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually create a tool and optionally link it to an entry."""
    tool = await _resolve_manual(db, "tool", body.name, body.aliases, body.force)
    is_new = tool is None

    if is_new:
        tool = Tool(
            name=body.name,
            aliases=body.aliases or [],
            description=body.description,
            tool_type=body.tool_type,
            github_url=body.github_url,
        )
        db.add(tool)
        await db.flush()
        await db.refresh(tool)
    else:
        if body.aliases:
            tool.aliases = body.aliases
        if body.description:
            tool.description = body.description
        if body.tool_type:
            tool.tool_type = body.tool_type
        if body.github_url:
            tool.github_url = body.github_url

    if body.entry_id:
        existing_link = await db.execute(
            select(EntryTool).where(EntryTool.entry_id == body.entry_id, EntryTool.tool_id == tool.id)
        )
        if not existing_link.scalar_one_or_none():
            db.add(EntryTool(entry_id=body.entry_id, tool_id=tool.id))

    await db.flush()
    await db.refresh(tool)

    if is_new:
        dispatch_entity_backlink("tool", str(tool.id))

    return {
        "id": str(tool.id),
        "name": tool.name,
        "aliases": tool.aliases,
        "description": tool.description,
        "tool_type": tool.tool_type,
        "github_url": tool.github_url,
    }


# --- Update endpoints ---


@router.put("/threat-actors/{actor_id}")
async def update_threat_actor(
    actor_id: uuid.UUID = Path(..., description="UUID of the threat actor."),
    body: ThreatActorUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update editable fields on a threat actor. Removing aliases unlinks entries matched only
    via those aliases; newly added aliases queue a background re-scan of existing entries."""
    result = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))
    actor = result.scalar_one_or_none()
    if not actor:
        raise AppError(code="not_found", message="Threat actor not found", status_code=404)

    if body.name is not None and body.name.strip().lower() != (actor.name or "").lower():
        await _assert_name_available(db, ThreatActor, body.name, actor_id)

    # Unlink entries that were linked via removed aliases
    old_aliases = list(actor.aliases or [])
    if body.aliases is not None:
        await _unlink_entries_for_removed_aliases(
            db,
            actor.aliases,
            body.aliases,
            EntryThreatActor,
            EntryThreatActor.threat_actor_id,
            actor_id,
        )

    await _apply_fields(
        db,
        entity_types.THREAT_ACTOR,
        actor,
        body,
        ["name", "aliases", "description", "mitre_id", "country", "motivation"],
        user,
    )

    db.add(actor)
    await db.flush()
    await db.refresh(actor)
    await invalidate_entity_cache("threat_actor", str(actor_id))

    # Newly added aliases widen the match surface — retro-scan existing entries
    dispatch_backlink_for_added_aliases("threat_actor", actor_id, old_aliases, actor.aliases)

    return {
        "id": str(actor.id),
        "name": actor.name,
        "aliases": actor.aliases,
        "description": actor.description,
        "mitre_id": actor.mitre_id,
        "country": actor.country,
        "motivation": actor.motivation,
    }


@router.put("/malware/{malware_id}")
async def update_malware_family(
    malware_id: uuid.UUID = Path(..., description="UUID of the malware family."),
    body: MalwareFamilyUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update editable fields on a malware family. Removing aliases unlinks entries matched only
    via those aliases; newly added aliases queue a background re-scan of existing entries."""
    result = await db.execute(select(MalwareFamily).where(MalwareFamily.id == malware_id))
    malware = result.scalar_one_or_none()
    if not malware:
        raise AppError(code="not_found", message="Malware family not found", status_code=404)

    if body.name is not None and body.name.strip().lower() != (malware.name or "").lower():
        await _assert_name_available(db, MalwareFamily, body.name, malware_id)

    # Unlink entries that were linked via removed aliases
    old_aliases = list(malware.aliases or [])
    if body.aliases is not None:
        await _unlink_entries_for_removed_aliases(
            db,
            malware.aliases,
            body.aliases,
            EntryMalware,
            EntryMalware.malware_family_id,
            malware_id,
        )

    await _apply_fields(
        db,
        entity_types.MALWARE,
        malware,
        body,
        ["name", "aliases", "description", "malpedia_url", "malware_type"],
        user,
    )

    db.add(malware)
    await db.flush()
    await db.refresh(malware)
    await invalidate_entity_cache("malware", str(malware_id))

    # Newly added aliases widen the match surface — retro-scan existing entries
    dispatch_backlink_for_added_aliases("malware", malware_id, old_aliases, malware.aliases)

    return {
        "id": str(malware.id),
        "name": malware.name,
        "aliases": malware.aliases,
        "description": malware.description,
        "malpedia_url": malware.malpedia_url,
        "malware_type": malware.malware_type,
    }


@router.put("/cves/{cve_uuid}")
async def update_cve(
    cve_uuid: uuid.UUID = Path(..., description="Internal UUID of the CVE row (not the CVE-YYYY-NNNN identifier)."),
    body: CVEUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update editable fields on a CVE. Analyst-set exploit status is marked as manual so
    automated enrichment (KEV sync, PoC scan) won't overwrite it."""
    result = await db.execute(select(CVE).where(CVE.id == cve_uuid))
    cve = result.scalar_one_or_none()
    if not cve:
        raise AppError(code="not_found", message="CVE not found", status_code=404)

    await _apply_fields(
        db,
        entity_types.CVE,
        cve,
        body,
        ["description", "severity", "exploit_status", "affected_products", "exploit_availability"],
        user,
    )

    # Track provenance: analyst-set exploit status is never overwritten by
    # automated enrichment (KEV sync, GitHub PoC scan).
    if body.exploit_status is not None or body.exploit_availability is not None:
        cve.exploit_status_source = "manual"

    db.add(cve)
    await db.flush()
    await db.refresh(cve)
    await invalidate_entity_cache("cve", str(cve_uuid))
    return {
        "id": str(cve.id),
        "cve_id": cve.cve_id,
        "description": cve.description,
        "severity": cve.severity,
        "exploit_status": cve.exploit_status,
        "exploit_availability": cve.exploit_availability,
        "exploit_status_source": cve.exploit_status_source,
    }


@router.put("/ttps/{ttp_id}")
async def update_ttp(
    ttp_id: uuid.UUID = Path(..., description="Internal UUID of the TTP row (not the ATT&CK technique id)."),
    body: TTPUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update the technique name, tactic, or description of a TTP."""
    result = await db.execute(select(TTP).where(TTP.id == ttp_id))
    ttp = result.scalar_one_or_none()
    if not ttp:
        raise AppError(code="not_found", message="TTP not found", status_code=404)

    await _apply_fields(db, entity_types.TTP, ttp, body, ["technique_name", "tactic", "description"], user)

    db.add(ttp)
    await db.flush()
    await db.refresh(ttp)
    await invalidate_entity_cache("ttp", str(ttp_id))
    return {
        "id": str(ttp.id),
        "technique_id": ttp.technique_id,
        "technique_name": ttp.technique_name,
        "tactic": ttp.tactic,
        "description": ttp.description,
    }


@router.put("/countries/{country_id}")
async def update_country(
    country_id: uuid.UUID = Path(..., description="UUID of the country."),
    body: CountryUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update editable fields on a country. Removing aliases unlinks entries matched only via
    those aliases; newly added aliases queue a background re-scan of existing entries."""
    result = await db.execute(select(Country).where(Country.id == country_id))
    country = result.scalar_one_or_none()
    if not country:
        raise AppError(code="not_found", message="Country not found", status_code=404)

    if body.name is not None and body.name.strip().lower() != (country.name or "").lower():
        await _assert_name_available(db, Country, body.name, country_id)

    # Unlink entries that were linked via removed aliases
    old_aliases = list(country.aliases or [])
    if body.aliases is not None:
        await _unlink_entries_for_removed_aliases(
            db,
            country.aliases,
            body.aliases,
            EntryCountry,
            EntryCountry.country_id,
            country_id,
        )

    await _apply_fields(
        db, entity_types.COUNTRY, country, body, ["name", "iso_code", "aliases", "region", "description"], user
    )

    db.add(country)
    await db.flush()
    await db.refresh(country)
    await invalidate_entity_cache("country", str(country_id))

    # Newly added aliases widen the match surface — retro-scan existing entries
    dispatch_backlink_for_added_aliases("country", country_id, old_aliases, country.aliases)

    return {
        "id": str(country.id),
        "name": country.name,
        "iso_code": country.iso_code,
        "aliases": country.aliases,
        "region": country.region,
        "description": country.description,
    }


@router.put("/sectors/{sector_id}")
async def update_sector(
    sector_id: uuid.UUID = Path(..., description="UUID of the sector."),
    body: SectorUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a sector's aliases or description.

    Sectors are a closed vocabulary: the name and slug are fixed, there is no
    create, delete, merge or convert, and because sectors are never autolinked
    an alias change does not retro-scan or unlink anything — aliases only widen
    what ``sector:`` search resolves.
    """
    result = await db.execute(select(Sector).where(Sector.id == sector_id))
    sector = result.scalar_one_or_none()
    if not sector:
        raise AppError(code="not_found", message="Sector not found", status_code=404)

    await _apply_fields(db, entity_types.SECTOR, sector, body, ["aliases", "description"], user)

    db.add(sector)
    await db.flush()
    await db.refresh(sector)
    await invalidate_entity_cache("sector", str(sector_id))

    return {
        "id": str(sector.id),
        "slug": sector.slug,
        "name": sector.name,
        "aliases": sector.aliases,
        "description": sector.description,
    }


# --- Target sectors (actors and malware) ---


class TargetSectorBody(BaseModel):
    """A sector by UUID, canonical slug or display name."""

    sector: str = Field(min_length=1, max_length=100)

    model_config = ConfigDict(json_schema_extra={"example": {"sector": "healthcare"}})


def _require_target_sector_type(entity_type: str) -> None:
    from app.services.sector_links import TARGET_SECTOR_ENTITY_TYPES

    if entity_type not in TARGET_SECTOR_ENTITY_TYPES:
        raise AppError(
            code="bad_request",
            message=f"{entity_type} cannot target sectors; expected one of {sorted(TARGET_SECTOR_ENTITY_TYPES)}",
            status_code=400,
        )


async def _load_target_entity(db: AsyncSession, entity_type: str, entity_id: uuid.UUID):
    from app.services.sector_links import junction_for

    model, _, _ = junction_for(entity_type)
    entity = (await db.execute(select(model).where(model.id == entity_id))).scalar_one_or_none()
    if entity is None:
        raise AppError(code="not_found", message=f"{entity_type} not found", status_code=404)
    return entity


@router.get("/{entity_type}/{entity_id}/target-sectors")
async def list_entity_target_sectors(
    entity_type: str = Path(..., description="threat_actor or malware."),
    entity_id: uuid.UUID = Path(..., description="Entity UUID."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """The sectors this actor or family is asserted to target, with the source of each claim
    (rollup from its own articles, reference-feed enrichment, the seed backfill, or an analyst)
    and the article evidence behind it."""
    from app.services.sector_links import list_target_sectors

    _require_target_sector_type(entity_type)
    await _load_target_entity(db, entity_type, entity_id)
    return await list_target_sectors(db, entity_type, entity_id)


@router.post("/{entity_type}/{entity_id}/target-sectors", status_code=201)
async def add_entity_target_sector(
    entity_type: str = Path(..., description="threat_actor or malware."),
    entity_id: uuid.UUID = Path(..., description="Entity UUID."),
    body: TargetSectorBody = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Assert that the actor or family targets a sector. Recorded as an analyst claim; an existing
    rolled-up or enriched row is upgraded to the analyst's, never duplicated."""
    from app.api.intelligence import _load_sector
    from app.services.claim_provenance import record_claim
    from app.services.sector_links import add_target_sector, list_target_sectors, refresh_targeted_sectors_cache

    _require_target_sector_type(entity_type)
    entity = await _load_target_entity(db, entity_type, entity_id)
    sector = await _load_sector(db, body.sector)
    changed = await add_target_sector(db, entity_type, entity_id, sector.id, "analyst")
    labels = await refresh_targeted_sectors_cache(db, entity_type, entity)
    if changed:
        await record_claim(
            db,
            entity_type=entity_type,
            entity_id=entity_id,
            field="targeted_sectors",
            value=labels,
            source_kind="analyst",
            created_by=user.id,
        )
        await invalidate_entity_cache(entity_type, str(entity_id))
        await invalidate_entity_cache("sector", str(sector.id))
    return {
        "sector_id": str(sector.id),
        "slug": sector.slug,
        "name": sector.name,
        "changed": changed,
        "target_sectors": await list_target_sectors(db, entity_type, entity_id),
    }


@router.delete("/{entity_type}/{entity_id}/target-sectors/{sector_ref}", status_code=204)
async def remove_entity_target_sector(
    entity_type: str = Path(..., description="threat_actor or malware."),
    entity_id: uuid.UUID = Path(..., description="Entity UUID."),
    sector_ref: str = Path(..., description="Sector UUID, slug or name."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Withdraw a targets-sector claim. The nightly rollup will re-assert it if the entity's own
    articles still carry the evidence; remove the entry links to make that stick."""
    from app.api.intelligence import _load_sector
    from app.services.claim_provenance import record_claim
    from app.services.sector_links import refresh_targeted_sectors_cache, remove_target_sector

    _require_target_sector_type(entity_type)
    entity = await _load_target_entity(db, entity_type, entity_id)
    sector = await _load_sector(db, sector_ref)
    if not await remove_target_sector(db, entity_type, entity_id, sector.id):
        raise AppError(code="not_found", message="Target-sector claim not found", status_code=404)
    labels = await refresh_targeted_sectors_cache(db, entity_type, entity)
    await record_claim(
        db,
        entity_type=entity_type,
        entity_id=entity_id,
        field="targeted_sectors",
        value=labels,
        source_kind="analyst",
        created_by=user.id,
    )
    await invalidate_entity_cache(entity_type, str(entity_id))
    await invalidate_entity_cache("sector", str(sector.id))
    return Response(status_code=204)


# --- Unlink all entries from entity ---


@router.delete("/{entity_type}/{entity_id}/unlink-all")
async def unlink_all_entries(
    entity_type: str = Path(
        ..., description="Entity type slug (threat_actor, malware, cve, ttp, country, tool, vendor, product)."
    ),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity to unlink from every entry."),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove all entry-entity junction records for a given entity, unlinking every article. Admin only."""
    from app.intelligence.correlation import ENTITY_CONFIG

    if entity_type not in ENTITY_CONFIG:
        raise AppError(code="invalid_type", message=f"Unknown entity type: {entity_type}", status_code=400)

    _, junction, fk_col = ENTITY_CONFIG[entity_type]
    result = await db.execute(delete(junction).where(fk_col == entity_id).returning(junction.entry_id))
    deleted_ids = result.scalars().all()

    # Reset article_count if the entity has one
    model = ENTITY_CONFIG[entity_type][0]
    entity = await db.scalar(select(model).where(model.id == entity_id))
    if entity and hasattr(entity, "article_count"):
        entity.article_count = 0
    if entity and hasattr(entity, "sighting_count"):
        entity.sighting_count = 0

    await db.flush()
    await invalidate_entity_cache(entity_type, str(entity_id))
    # Invalidate caches for entities that co-occurred on the unlinked entries
    from app.intelligence.correlation_cache import invalidate_entry_caches

    for eid in deleted_ids:
        await invalidate_entry_caches(db, str(eid))

    return {"unlinked": len(deleted_ids)}


# --- Delete helpers ---


async def _delete_entity_relationships(db: AsyncSession, entity_type: str, entity_id: uuid.UUID):
    """Remove all EntityRelationship records where this entity is source or target."""
    await db.execute(
        delete(EntityRelationship).where(
            or_(
                (EntityRelationship.source_type == entity_type) & (EntityRelationship.source_id == entity_id),
                (EntityRelationship.target_type == entity_type) & (EntityRelationship.target_id == entity_id),
            )
        )
    )


class DenyNameResponse(BaseModel):
    denied: int
    names: list[str]


@router.post("/{entity_type}/{entity_id}/deny-name", response_model=DenyNameResponse)
async def deny_entity_name(
    entity_type: str = Path(
        ..., description="Canonical entity type slug ('threat_actor', 'malware', 'tool', 'cve', 'ttp')."
    ),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity whose names should be banned."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add this entity's name (and aliases) to the analyst do-not-recreate list.

    Deleting an entity alone doesn't stick — the next article mentioning it mints
    it again. Call this just before the delete to stop the one-pass extractor and
    the autolinker from re-creating it. Only the types whose creation paths
    consult the list are accepted.
    """
    if entity_type not in DENIABLE_TYPES:
        raise AppError(
            code="bad_request",
            message=f"entity_type must be one of {sorted(DENIABLE_TYPES)}",
            status_code=422,
        )
    from app.intelligence.correlation import ENTITY_CONFIG

    model = ENTITY_CONFIG[entity_type][0]
    entity = await db.scalar(select(model).where(model.id == entity_id))
    if not entity:
        raise AppError(code="not_found", message="Entity not found", status_code=404)

    names = deniable_names(entity_type, entity)
    denied = await deny_entity_names(db, entity_type, names, reason="Deleted from the entity profile")
    await db.commit()
    # The names now sit in the autolinker's false-positive list — rebuild so the
    # vocabulary drops them immediately rather than at the next sync.
    from app.intelligence.autolinker import refresh_vocabulary

    await refresh_vocabulary(db)
    return DenyNameResponse(denied=denied, names=names)


# --- Delete endpoints ---


@router.delete("/threat-actors/{actor_id}", status_code=204)
async def delete_threat_actor(
    actor_id: uuid.UUID = Path(..., description="UUID of the threat actor."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete the threat actor along with its entry links and entity relationships, and remove
    its search-index document."""
    result = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))
    actor = result.scalar_one_or_none()
    if not actor:
        raise AppError(code="not_found", message="Threat actor not found", status_code=404)

    await db.execute(delete(EntryThreatActor).where(EntryThreatActor.threat_actor_id == actor_id))
    await _delete_entity_relationships(db, "threat_actor", actor_id)
    await db.delete(actor)
    await db.flush()
    delete_entity_document("threat_actor", actor_id)


@router.delete("/malware/{malware_id}", status_code=204)
async def delete_malware_family(
    malware_id: uuid.UUID = Path(..., description="UUID of the malware family."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete the malware family along with its entry links and entity relationships, and remove
    its search-index document."""
    result = await db.execute(select(MalwareFamily).where(MalwareFamily.id == malware_id))
    malware = result.scalar_one_or_none()
    if not malware:
        raise AppError(code="not_found", message="Malware family not found", status_code=404)

    await db.execute(delete(EntryMalware).where(EntryMalware.malware_family_id == malware_id))
    await _delete_entity_relationships(db, "malware", malware_id)
    await db.delete(malware)
    await db.flush()
    delete_entity_document("malware", malware_id)


@router.delete("/cves/{cve_uuid}", status_code=204)
async def delete_cve(
    cve_uuid: uuid.UUID = Path(..., description="Internal UUID of the CVE row (not the CVE-YYYY-NNNN identifier)."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete the CVE along with its entry links and entity relationships, and remove
    its search-index document."""
    result = await db.execute(select(CVE).where(CVE.id == cve_uuid))
    cve = result.scalar_one_or_none()
    if not cve:
        raise AppError(code="not_found", message="CVE not found", status_code=404)

    await db.execute(delete(EntryCVE).where(EntryCVE.cve_id == cve_uuid))
    await _delete_entity_relationships(db, "cve", cve_uuid)
    await db.delete(cve)
    await db.flush()
    delete_entity_document("cve", cve_uuid)


@router.delete("/ttps/{ttp_id}", status_code=204)
async def delete_ttp(
    ttp_id: uuid.UUID = Path(..., description="Internal UUID of the TTP row (not the ATT&CK technique id)."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete the TTP along with its entry links and entity relationships, and remove
    its search-index document."""
    result = await db.execute(select(TTP).where(TTP.id == ttp_id))
    ttp = result.scalar_one_or_none()
    if not ttp:
        raise AppError(code="not_found", message="TTP not found", status_code=404)

    await db.execute(delete(EntryTTP).where(EntryTTP.ttp_id == ttp_id))
    await _delete_entity_relationships(db, "ttp", ttp_id)
    await db.delete(ttp)
    await db.flush()
    delete_entity_document("ttp", ttp_id)


@router.delete("/countries/{country_id}", status_code=204)
async def delete_country(
    country_id: uuid.UUID = Path(..., description="UUID of the country."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete the country along with its entry links and entity relationships, and remove
    its search-index document."""
    result = await db.execute(select(Country).where(Country.id == country_id))
    country = result.scalar_one_or_none()
    if not country:
        raise AppError(code="not_found", message="Country not found", status_code=404)

    await db.execute(delete(EntryCountry).where(EntryCountry.country_id == country_id))
    await _delete_entity_relationships(db, "country", country_id)
    await db.delete(country)
    await db.flush()
    delete_entity_document("country", country_id)


@router.put("/tools/{tool_id}")
async def update_tool(
    tool_id: uuid.UUID = Path(..., description="UUID of the tool."),
    body: ToolUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update editable fields on a tool. Removing aliases unlinks entries matched only via
    those aliases; newly added aliases queue a background re-scan of existing entries."""
    result = await db.execute(select(Tool).where(Tool.id == tool_id))
    tool = result.scalar_one_or_none()
    if not tool:
        raise AppError(code="not_found", message="Tool not found", status_code=404)

    if body.name is not None and body.name.strip().lower() != (tool.name or "").lower():
        await _assert_name_available(db, Tool, body.name, tool_id)

    # Unlink entries that were linked via removed aliases
    old_aliases = list(tool.aliases or [])
    if body.aliases is not None:
        await _unlink_entries_for_removed_aliases(
            db,
            tool.aliases,
            body.aliases,
            EntryTool,
            EntryTool.tool_id,
            tool_id,
        )

    await _apply_fields(
        db,
        entity_types.TOOL,
        tool,
        body,
        ["name", "aliases", "description", "tool_type", "malpedia_url", "github_url"],
        user,
    )

    db.add(tool)
    await db.flush()
    await db.refresh(tool)
    await invalidate_entity_cache("tool", str(tool_id))

    # Newly added aliases widen the match surface — retro-scan existing entries
    dispatch_backlink_for_added_aliases("tool", tool_id, old_aliases, tool.aliases)

    return {
        "id": str(tool.id),
        "name": tool.name,
        "aliases": tool.aliases,
        "description": tool.description,
        "tool_type": tool.tool_type,
        "malpedia_url": tool.malpedia_url,
        "github_url": tool.github_url,
    }


@router.delete("/tools/{tool_id}", status_code=204)
async def delete_tool(
    tool_id: uuid.UUID = Path(..., description="UUID of the tool."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete the tool along with its entry links and entity relationships, and remove
    its search-index document."""
    result = await db.execute(select(Tool).where(Tool.id == tool_id))
    tool = result.scalar_one_or_none()
    if not tool:
        raise AppError(code="not_found", message="Tool not found", status_code=404)

    await db.execute(delete(EntryTool).where(EntryTool.tool_id == tool_id))
    await _delete_entity_relationships(db, "tool", tool_id)
    await db.delete(tool)
    await db.flush()
    delete_entity_document("tool", tool_id)
    await invalidate_entity_cache("tool", str(tool_id))


@router.post("/vendors", status_code=201)
async def create_vendor_manual(
    body: VendorCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually create a vendor and optionally link it to an entry."""
    vendor = await _resolve_manual(db, "vendor", body.name, body.aliases, body.force)
    is_new = vendor is None

    if is_new:
        vendor = Vendor(
            name=body.name,
            aliases=body.aliases or [],
            description=body.description,
            website=body.website,
            vendor_type=body.vendor_type,
        )
        db.add(vendor)
        await db.flush()
        await db.refresh(vendor)
    else:
        if body.aliases:
            vendor.aliases = body.aliases
        if body.description:
            vendor.description = body.description
        if body.website:
            vendor.website = body.website
        if body.vendor_type:
            vendor.vendor_type = body.vendor_type

    if body.entry_id:
        existing_link = await db.execute(
            select(EntryVendor).where(EntryVendor.entry_id == body.entry_id, EntryVendor.vendor_id == vendor.id)
        )
        if not existing_link.scalar_one_or_none():
            db.add(EntryVendor(entry_id=body.entry_id, vendor_id=vendor.id, source="manual"))

    await db.flush()
    await db.refresh(vendor)

    if is_new:
        dispatch_entity_backlink("vendor", str(vendor.id))

    return {
        "id": str(vendor.id),
        "name": vendor.name,
        "aliases": vendor.aliases,
        "description": vendor.description,
        "website": vendor.website,
        "vendor_type": vendor.vendor_type,
    }


@router.post("/products", status_code=201)
async def create_product_manual(
    body: ProductCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually create a product and optionally link it to an entry."""
    product = await _resolve_manual(db, "product", body.name, body.aliases, body.force)
    is_new = product is None

    if is_new:
        product = Product(
            name=body.name,
            aliases=body.aliases or [],
            description=body.description,
            product_type=body.product_type,
            website=body.website,
            vendor_id=body.vendor_id,
        )
        db.add(product)
        await db.flush()
        await db.refresh(product)
    else:
        if body.aliases:
            product.aliases = body.aliases
        if body.description:
            product.description = body.description
        if body.product_type:
            product.product_type = body.product_type
        if body.website:
            product.website = body.website
        if body.vendor_id:
            product.vendor_id = body.vendor_id

    if body.entry_id:
        existing_link = await db.execute(
            select(EntryProduct).where(EntryProduct.entry_id == body.entry_id, EntryProduct.product_id == product.id)
        )
        if not existing_link.scalar_one_or_none():
            db.add(EntryProduct(entry_id=body.entry_id, product_id=product.id, source="manual"))

    await db.flush()
    await db.refresh(product)

    if is_new:
        dispatch_entity_backlink("product", str(product.id))

    return {
        "id": str(product.id),
        "name": product.name,
        "aliases": product.aliases,
        "description": product.description,
        "product_type": product.product_type,
        "website": product.website,
        "vendor_id": str(product.vendor_id) if product.vendor_id else None,
    }


@router.put("/vendors/{vendor_id}")
async def update_vendor(
    vendor_id: uuid.UUID = Path(..., description="UUID of the vendor."),
    body: VendorUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update editable fields on a vendor. Removing aliases unlinks entries matched only via
    those aliases; newly added aliases queue a background re-scan of existing entries."""
    result = await db.execute(select(Vendor).where(Vendor.id == vendor_id))
    vendor = result.scalar_one_or_none()
    if not vendor:
        raise AppError(code="not_found", message="Vendor not found", status_code=404)

    if body.name is not None and body.name.strip().lower() != (vendor.name or "").lower():
        await _assert_name_available(db, Vendor, body.name, vendor_id)

    old_aliases = list(vendor.aliases or [])
    if body.aliases is not None:
        await _unlink_entries_for_removed_aliases(
            db,
            vendor.aliases,
            body.aliases,
            EntryVendor,
            EntryVendor.vendor_id,
            vendor_id,
        )

    await _apply_fields(
        db, entity_types.VENDOR, vendor, body, ["name", "aliases", "description", "website", "vendor_type"], user
    )

    db.add(vendor)
    await db.flush()
    await db.refresh(vendor)
    await invalidate_entity_cache("vendor", str(vendor_id))

    # Newly added aliases widen the match surface — retro-scan existing entries
    dispatch_backlink_for_added_aliases("vendor", vendor_id, old_aliases, vendor.aliases)

    return {
        "id": str(vendor.id),
        "name": vendor.name,
        "aliases": vendor.aliases,
        "description": vendor.description,
        "website": vendor.website,
        "vendor_type": vendor.vendor_type,
    }


@router.put("/products/{product_id}")
async def update_product(
    product_id: uuid.UUID = Path(..., description="UUID of the product."),
    body: ProductUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update editable fields on a product (including its owning vendor). Removing aliases
    unlinks entries matched only via those aliases; new aliases queue a background re-scan."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise AppError(code="not_found", message="Product not found", status_code=404)

    if body.name is not None and body.name.strip().lower() != (product.name or "").lower():
        await _assert_name_available(db, Product, body.name, product_id)

    old_aliases = list(product.aliases or [])
    if body.aliases is not None:
        await _unlink_entries_for_removed_aliases(
            db,
            product.aliases,
            body.aliases,
            EntryProduct,
            EntryProduct.product_id,
            product_id,
        )

    await _apply_fields(
        db, entity_types.PRODUCT, product, body, ["name", "aliases", "description", "product_type", "website"], user
    )

    if body.vendor_id is not None:
        product.vendor_id = body.vendor_id

    db.add(product)
    await db.flush()
    await db.refresh(product)
    await invalidate_entity_cache("product", str(product_id))

    # Newly added aliases widen the match surface — retro-scan existing entries
    dispatch_backlink_for_added_aliases("product", product_id, old_aliases, product.aliases)

    return {
        "id": str(product.id),
        "name": product.name,
        "aliases": product.aliases,
        "description": product.description,
        "product_type": product.product_type,
        "website": product.website,
        "vendor_id": str(product.vendor_id) if product.vendor_id else None,
    }


@router.delete("/vendors/{vendor_id}", status_code=204)
async def delete_vendor(
    vendor_id: uuid.UUID = Path(..., description="UUID of the vendor."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete the vendor along with its entry links and entity relationships, and remove
    its search-index document."""
    result = await db.execute(select(Vendor).where(Vendor.id == vendor_id))
    vendor = result.scalar_one_or_none()
    if not vendor:
        raise AppError(code="not_found", message="Vendor not found", status_code=404)

    await db.execute(delete(EntryVendor).where(EntryVendor.vendor_id == vendor_id))
    await _delete_entity_relationships(db, "vendor", vendor_id)
    await db.delete(vendor)
    await db.flush()
    await invalidate_entity_cache("vendor", str(vendor_id))


@router.delete("/products/{product_id}", status_code=204)
async def delete_product(
    product_id: uuid.UUID = Path(..., description="UUID of the product."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete the product along with its entry links and entity relationships, and remove
    its search-index document."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise AppError(code="not_found", message="Product not found", status_code=404)

    await db.execute(delete(EntryProduct).where(EntryProduct.product_id == product_id))
    await _delete_entity_relationships(db, "product", product_id)
    await db.delete(product)
    await db.flush()
    await invalidate_entity_cache("product", str(product_id))


class EntityMergeRequest(BaseModel):
    keeper_id: uuid.UUID = Field(..., description="ID of the entity to keep")
    merge_ids: list[uuid.UUID] = Field(..., min_length=1, description="IDs of entities to merge into the keeper")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "keeper_id": "d5b2c8f0-3e4a-4b6c-9d1e-7f8a9b0c1d2e",
                "merge_ids": ["3f9d2a1b-8c7e-4f6a-b5d4-0e1c2a3b4d5f"],
            }
        }
    )


@router.post("/{entity_type}/merge")
async def merge_entities(
    entity_type: str = Path(
        ..., description="Entity type to merge within (threat_actor, malware, country, tool, vendor, product)."
    ),
    body: EntityMergeRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Merge duplicate entities into a single keeper entity. Admin only.

    Reassigns all entry links and entity relationships from merge targets to the keeper,
    merges aliases (adding each target's name as an alias), sums article counts,
    and deletes the merged entities.
    """
    if entity_type not in MERGE_CONFIG:
        raise AppError(
            code="bad_request", message=f"Merge not supported for entity type: {entity_type}", status_code=400
        )

    if body.keeper_id in body.merge_ids:
        raise AppError(code="bad_request", message="keeper_id must not appear in merge_ids", status_code=400)

    model_cls, junction_cls, fk_attr = MERGE_CONFIG[entity_type]
    fk_col = getattr(junction_cls, fk_attr)

    # Load keeper
    result = await db.execute(select(model_cls).where(model_cls.id == body.keeper_id))
    keeper = result.scalar_one_or_none()
    if not keeper:
        raise AppError(code="not_found", message="Keeper entity not found", status_code=404)

    # Load targets
    result = await db.execute(select(model_cls).where(model_cls.id.in_(body.merge_ids)))
    targets = result.scalars().all()
    if len(targets) != len(body.merge_ids):
        found = {t.id for t in targets}
        missing = [str(mid) for mid in body.merge_ids if mid not in found]
        raise AppError(code="not_found", message=f"Entities not found: {', '.join(missing)}", status_code=404)

    merged_count = 0
    original_aliases = list(keeper.aliases or [])
    keeper_aliases = set(a.lower() for a in (keeper.aliases or []))
    new_aliases = list(keeper.aliases or [])

    for target in targets:
        # 1. Reassign entry links: update FK, skip conflicts (entry already linked to keeper)
        # Get entries linked to target but not to keeper
        target_entries = await db.execute(select(junction_cls.entry_id).where(fk_col == target.id))
        target_entry_ids = set(target_entries.scalars().all())

        keeper_entries = await db.execute(select(junction_cls.entry_id).where(fk_col == body.keeper_id))
        keeper_entry_ids = set(keeper_entries.scalars().all())

        # Move non-conflicting links
        moveable = target_entry_ids - keeper_entry_ids
        if moveable:
            await db.execute(
                update(junction_cls)
                .where(fk_col == target.id, junction_cls.entry_id.in_(moveable))
                .values({fk_attr: body.keeper_id})
            )

        # Delete remaining (conflicting) links
        await db.execute(delete(junction_cls).where(fk_col == target.id))

        # 2. Reassign entity relationships
        # Simply delete all of the target's relationships — the keeper already
        # has its own set and duplicating relationship rows adds little value
        # vs. risking unique-constraint violations during reassignment.
        await db.execute(
            delete(EntityRelationship).where(
                or_(
                    (EntityRelationship.source_type == entity_type) & (EntityRelationship.source_id == target.id),
                    (EntityRelationship.target_type == entity_type) & (EntityRelationship.target_id == target.id),
                )
            )
        )

        # 3. Merge aliases: add target name + target aliases to keeper
        target_name = getattr(target, "name", None)
        if target_name and target_name.lower() not in keeper_aliases and target_name.lower() != keeper.name.lower():
            new_aliases.append(target_name)
            keeper_aliases.add(target_name.lower())

        for alias in target.aliases or []:
            if alias.lower() not in keeper_aliases and alias.lower() != keeper.name.lower():
                new_aliases.append(alias)
                keeper_aliases.add(alias.lower())

        # 4. Merge stats
        if hasattr(keeper, "article_count") and hasattr(target, "article_count"):
            keeper.article_count = (keeper.article_count or 0) + (target.article_count or 0)

        if hasattr(keeper, "first_seen_at") and hasattr(target, "first_seen_at"):
            if target.first_seen_at and (not keeper.first_seen_at or target.first_seen_at < keeper.first_seen_at):
                keeper.first_seen_at = target.first_seen_at

        if hasattr(keeper, "last_seen_at") and hasattr(target, "last_seen_at"):
            if target.last_seen_at and (not keeper.last_seen_at or target.last_seen_at > keeper.last_seen_at):
                keeper.last_seen_at = target.last_seen_at

        # 5. Merge description if keeper has none
        if hasattr(keeper, "description") and not keeper.description and getattr(target, "description", None):
            keeper.description = target.description

        # 6. Merge MITRE ID if keeper has none
        if hasattr(keeper, "mitre_id") and not keeper.mitre_id and getattr(target, "mitre_id", None):
            keeper.mitre_id = target.mitre_id

        # Delete target (search doc too, or it lingers until the next full reindex)
        await db.delete(target)
        delete_entity_document(entity_type, target.id)
        merged_count += 1

    # Update keeper aliases
    keeper.aliases = new_aliases
    db.add(keeper)
    await db.flush()

    # Recount actual article links
    actual_count = await db.scalar(select(func.count()).select_from(junction_cls).where(fk_col == body.keeper_id))
    if hasattr(keeper, "article_count"):
        keeper.article_count = actual_count or 0

    await db.flush()
    await db.refresh(keeper)
    await invalidate_entity_cache(entity_type, str(body.keeper_id))
    for target in targets:
        await invalidate_entity_cache(entity_type, str(target.id))

    # Refresh autolinker vocabulary
    try:
        from app.workers.tasks import refresh_autolinker_vocabulary

        refresh_autolinker_vocabulary.delay()
    except Exception:
        pass

    # The keeper absorbed the targets' names/aliases — retro-scan for articles that
    # mention those forms but were linked to neither entity.
    dispatch_backlink_for_added_aliases(entity_type, body.keeper_id, original_aliases, keeper.aliases)

    logger.info("Merged %d %s entities into %s (%s)", merged_count, entity_type, keeper.name, body.keeper_id)

    return {
        "keeper": {
            "id": str(keeper.id),
            "name": keeper.name,
            "aliases": keeper.aliases,
            "article_count": getattr(keeper, "article_count", None),
        },
        "merged_count": merged_count,
    }


@router.get("/{entity_type}/duplicates")
async def find_duplicate_entities(
    entity_type: str = Path(
        ..., description="Entity type to scan (threat_actor, malware, country, tool, vendor, product)."
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Find potential duplicate entities using substring and alias matching.

    Returns groups of entities that may be duplicates based on:
    - One entity's name being a substring of another's name
    - One entity's name appearing in another's aliases
    - Shared aliases between entities
    """
    if entity_type not in MERGE_CONFIG:
        raise AppError(
            code="bad_request", message=f"Duplicate detection not supported for: {entity_type}", status_code=400
        )

    model_cls, _, _ = MERGE_CONFIG[entity_type]

    # Load all entities of this type
    result = await db.execute(select(model_cls).order_by(model_cls.name))
    entities = result.scalars().all()

    if len(entities) < 2:
        return {"groups": []}

    # Build lookup structures
    entity_list = []
    for e in entities:
        entity_list.append(
            {
                "id": str(e.id),
                "name": e.name,
                "name_lower": e.name.lower(),
                "aliases": [a.lower() for a in (e.aliases or [])],
                "aliases_original": e.aliases or [],
                "mitre_id": getattr(e, "mitre_id", None),
                "article_count": getattr(e, "article_count", 0) or 0,
                "description": getattr(e, "description", None),
            }
        )

    # Find duplicate groups
    # Track which entities are already grouped
    grouped = set()
    groups = []

    for i, a in enumerate(entity_list):
        if a["id"] in grouped:
            continue

        group_members = [a]
        reasons = {}

        for j, b in enumerate(entity_list):
            if i == j or b["id"] in grouped:
                continue

            match_reasons = []

            # Check substring: one name contains the other
            if len(a["name_lower"]) >= 3 and len(b["name_lower"]) >= 3:
                if a["name_lower"] in b["name_lower"] or b["name_lower"] in a["name_lower"]:
                    match_reasons.append("name_substring")

            # Check if a's name is in b's aliases or vice versa
            if a["name_lower"] in b["aliases"]:
                match_reasons.append("name_in_aliases")
            if b["name_lower"] in a["aliases"]:
                match_reasons.append("name_in_aliases")

            # Check shared aliases
            shared = set(a["aliases"]) & set(b["aliases"])
            if shared:
                match_reasons.append(f"shared_aliases: {', '.join(shared)}")

            # Check name after stripping common suffixes
            stripped_a = _strip_entity_suffixes(a["name_lower"])
            stripped_b = _strip_entity_suffixes(b["name_lower"])
            if stripped_a and stripped_b and stripped_a == stripped_b and a["name_lower"] != b["name_lower"]:
                match_reasons.append("name_after_normalization")

            if match_reasons:
                group_members.append(b)
                reasons[b["id"]] = match_reasons

        if len(group_members) > 1:
            for m in group_members:
                grouped.add(m["id"])
            groups.append(
                {
                    "entities": [
                        {
                            "id": m["id"],
                            "name": m["name"],
                            "aliases": m["aliases_original"],
                            "mitre_id": m.get("mitre_id"),
                            "article_count": m["article_count"],
                            "description": (m["description"] or "")[:200] if m.get("description") else None,
                            "match_reasons": reasons.get(m["id"], ["primary"]),
                        }
                        for m in group_members
                    ],
                }
            )

    # Sort groups by total article count (most important first)
    groups.sort(key=lambda g: sum(e["article_count"] for e in g["entities"]), reverse=True)

    return {"groups": groups, "total_groups": len(groups)}


def _strip_entity_suffixes(name: str) -> str:
    """Strip common suffixes from entity names for normalization comparison."""
    suffixes = [
        " ransomware gang",
        " ransomware group",
        " ransomware",
        " apt group",
        " apt",
        " group",
        " gang",
        " team",
        " threat group",
        " threat actor",
    ]
    result = name.strip()
    for suffix in suffixes:
        if result.endswith(suffix):
            result = result[: -len(suffix)].strip()
    # Strip leading/trailing special chars
    result = result.strip("$!@#")
    return result


# --- Ranked merge suggestions (scored pairs + persisted dismissals) ---


@router.get("/{entity_type}/merge-suggestions")
async def get_merge_suggestions(
    entity_type: str = Path(..., description="Entity type to score suggestions for."),
    limit: int = Query(50, description="Maximum suggestions to return (clamped to 1-200)."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Ranked duplicate-pair suggestions for one entity type.

    Combines normalized-name similarity (containment, token overlap,
    generic-suffix stripping), alias overlap, shared relationships, and
    co-mention frequency into a score with human-readable reasons. Includes
    cross-type tool-vs-malware name collisions flagged as ``cross_type``
    (informational — resolve those via convert/reclassify, not merge).
    Previously dismissed pairs are excluded.
    """
    from app.intelligence.merge_suggestions import SUGGESTION_CONFIG, suggest_merges

    if entity_type not in SUGGESTION_CONFIG:
        raise AppError(
            code="bad_request",
            message=f"Merge suggestions not supported for: {entity_type}",
            status_code=400,
        )
    limit = max(1, min(limit, 200))
    return await suggest_merges(db, entity_type, limit=limit)


class MergeSuggestionDismissRequest(BaseModel):
    entity_type_a: str = Field(..., max_length=30)
    entity_id_a: uuid.UUID
    entity_type_b: str = Field(..., max_length=30)
    entity_id_b: uuid.UUID

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type_a": "threat_actor",
                "entity_id_a": "d5b2c8f0-3e4a-4b6c-9d1e-7f8a9b0c1d2e",
                "entity_type_b": "threat_actor",
                "entity_id_b": "3f9d2a1b-8c7e-4f6a-b5d4-0e1c2a3b4d5f",
            }
        }
    )


@router.post("/merge-suggestions/dismiss")
async def dismiss_merge_suggestion(
    body: MergeSuggestionDismissRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Persistently dismiss a merge suggestion pair so it is never re-suggested."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.intelligence.merge_suggestions import SUGGESTION_CONFIG, pair_key
    from app.models.entity_maintenance import EntityMergeSuggestionDismissal

    for etype in (body.entity_type_a, body.entity_type_b):
        if etype not in SUGGESTION_CONFIG:
            raise AppError(
                code="bad_request",
                message=f"Unsupported entity type: {etype}",
                status_code=400,
            )
    if body.entity_id_a == body.entity_id_b and body.entity_type_a == body.entity_type_b:
        raise AppError(code="bad_request", message="Cannot dismiss a self-pair", status_code=400)

    (type_a, id_a), (type_b, id_b) = pair_key(
        body.entity_type_a, body.entity_id_a, body.entity_type_b, body.entity_id_b
    )
    await db.execute(
        pg_insert(EntityMergeSuggestionDismissal)
        .values(
            entity_type_a=type_a,
            entity_id_a=uuid.UUID(id_a),
            entity_type_b=type_b,
            entity_id_b=uuid.UUID(id_b),
            dismissed_by=user.id,
        )
        .on_conflict_do_nothing(constraint="uq_merge_suggestion_dismissal_pair")
    )
    await db.flush()
    return {"dismissed": True}


@router.delete("/mitigations/{mitigation_id}", status_code=204)
async def delete_mitigation(
    mitigation_id: uuid.UUID = Path(..., description="UUID of the mitigation."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete the mitigation along with its entry links and entity relationships, and remove
    its search-index document."""
    result = await db.execute(select(Mitigation).where(Mitigation.id == mitigation_id))
    mitigation = result.scalar_one_or_none()
    if not mitigation:
        raise AppError(code="not_found", message="Mitigation not found", status_code=404)

    await db.execute(delete(EntryMitigation).where(EntryMitigation.mitigation_id == mitigation_id))
    await db.execute(delete(TTPMitigation).where(TTPMitigation.mitigation_id == mitigation_id))
    await _delete_entity_relationships(db, "mitigation", mitigation_id)
    await db.delete(mitigation)
    await db.flush()
    delete_entity_document("mitigation", mitigation_id)
    await invalidate_entity_cache("mitigation", str(mitigation_id))


# --- AI Summary ---


@router.get("/{entity_type}/{entity_id}/provenance")
async def get_entity_field_provenance(
    entity_type: str = Path(..., description="Entity type slug, e.g. threat_actor."),
    entity_id: uuid.UUID = Path(..., description="Entity UUID."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Who asserted each fact on this profile, and whether they still agree with it.

    One call per profile: every tracked field's claims, each carrying the source
    that made it, the article and feed it came from (with the feed's A-F
    reliability grade), and the sentence behind it where one was captured.
    Fields that hold a value but carry no claim come back in
    ``unsourced_fields`` — an unattributable fact is reported as such rather
    than presented as established.
    """
    from app.services.claim_provenance import get_entity_claims

    # Nothing writes field claims for a campaign — every field on it was typed
    # by the analyst who owns it — so there is no provenance to report and no
    # error to raise either.
    if entity_type == "campaign":
        return {"entity_type": entity_type, "entity_id": str(entity_id), "fields": {}}

    if entity_type not in ENTITY_MODEL_MAP:
        raise AppError(
            code="bad_request",
            message=f"Unsupported entity type: {entity_type}",
            status_code=400,
        )
    model_cls = ENTITY_MODEL_MAP[entity_type][0]
    entity = (await db.execute(select(model_cls).where(model_cls.id == entity_id))).scalar_one_or_none()
    if entity is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)

    return await get_entity_claims(db, entity_type, entity_id, entity_row=entity)


# ENTITY_MODEL_MAP lives in app/services/entity_summary.py so the
# assessment-backfill worker can share it without importing the API layer.

# link_entity_to_existing_entries() also supports "mitigation" (name+alias
# search) — ENTITY_MODEL_MAP above omits it because it's scoped to
# Wikipedia-relevant types, not because rescan doesn't apply.
# Sectors are summarizable (ENTITY_MODEL_MAP) but never autolinked, so there is
# nothing to rescan for one — the gate below returns 400 rather than handing the
# autolinker a type it has no match surface for.
RESCAN_MODEL_MAP = {
    **{k: v[0] for k, v in ENTITY_MODEL_MAP.items() if k != "sector"},
    "mitigation": Mitigation,
}


@router.post("/{entity_type}/{entity_id}/rescan")
async def rescan_entity_articles(
    entity_type: str = Path(
        ...,
        description="Entity type slug (threat_actor, malware, cve, ttp, country, tool, vendor, product, mitigation).",
    ),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity to re-scan existing entries for."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Queue a re-scan of all existing entries for mentions of this entity.

    Reuses the same backlink task fired when an entity is manually created —
    useful after adding aliases, or when the analyst suspects the autolinker
    missed older articles. Runs in the background (Celery); a Redis lock in
    link_entity_to_existing_entries() prevents overlapping runs for the same
    entity, so re-clicking while one is in flight is a no-op.
    """
    if entity_type not in RESCAN_MODEL_MAP:
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)

    model_cls = RESCAN_MODEL_MAP[entity_type]
    exists = (await db.execute(select(model_cls.id).where(model_cls.id == entity_id))).scalar_one_or_none()
    if exists is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)

    dispatch_entity_backlink(entity_type, str(entity_id))
    return {"queued": True, "entity_type": entity_type, "entity_id": str(entity_id)}


# entity_type -> junction model joined on entry_id, filtered by this fk column == entity_id
# Types whose articles carry techniques, and the table that says which articles
# are theirs. A campaign's is its membership list rather than an extraction
# junction, which is the only difference — the technique join downstream is
# identical, so ATT&CK coverage, the ranked technique table and the gap
# classification all work off it unchanged.
DETECTION_GAPS_JUNCTION_MAP = {
    "threat_actor": (EntryThreatActor, EntryThreatActor.threat_actor_id),
    "malware": (EntryMalware, EntryMalware.malware_family_id),
    "campaign": (CampaignEntry, CampaignEntry.campaign_id),
}


@router.get("/{entity_type}/{entity_id}/detection-gaps")
async def get_entity_detection_gaps(
    entity_type: str = Path(..., description="threat_actor or malware — the only types with TTP-bearing entries."),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity whose technique coverage to classify."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Telemetry-aware detection coverage for this entity's referenced techniques.

    Same classification as the campaign detection-gaps endpoint (covered /
    library_only / no rule), scoped to TTPs from entries linked to this entity
    instead of a campaign's entries.
    """
    from app.services.detection_coverage import STATUS_COVERED, STATUS_LIBRARY_ONLY, classify_techniques

    if entity_type not in DETECTION_GAPS_JUNCTION_MAP:
        raise AppError(code="bad_request", message=f"detection-gaps not supported for {entity_type}", status_code=400)

    junction, fk_col = DETECTION_GAPS_JUNCTION_MAP[entity_type]
    result = await db.execute(
        select(TTP.id, TTP.technique_id, TTP.technique_name, TTP.tactic)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .join(junction, junction.entry_id == EntryTTP.entry_id)
        .where(fk_col == entity_id)
        .distinct()
    )
    entity_ttps = result.all()

    classification = await classify_techniques(db, [row.technique_id for row in entity_ttps])

    gaps, library_only, covered = [], [], []
    for ttp_row in entity_ttps:
        info = classification.get(ttp_row.technique_id) or {}
        entry = {
            "ttp_id": str(ttp_row.id),
            "technique_id": ttp_row.technique_id,
            "technique_name": ttp_row.technique_name,
            "tactic": ttp_row.tactic,
            "rule_count": info.get("rule_count", 0),
        }
        status = info.get("status")
        if status == STATUS_COVERED:
            entry["rules"] = info["rules"]
            covered.append(entry)
        elif status == STATUS_LIBRARY_ONLY:
            entry["rules"] = info["rules"]
            entry["missing_data_sources"] = info["missing_data_sources"]
            library_only.append(entry)
        else:
            gaps.append(entry)

    total = len(entity_ttps)
    return {
        "total_ttps": total,
        "covered_count": len(covered),
        "library_only_count": len(library_only),
        "no_rule_count": len(gaps),
        "gap_count": len(gaps),
        "coverage_percentage": round(len(covered) / total * 100, 1) if total > 0 else 0,
        "gaps": gaps,
        "library_only": library_only,
        "covered": covered,
    }


@router.get("/{entity_type}/{entity_id}/story-threads")
async def get_entity_story_threads(
    entity_type: str = Path(..., description="Entity type slug (threat_actor, malware, cve, ttp, …)."),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity."),
    limit: int = Query(2, ge=1, le=10, description="Maximum threads returned."),
    status: str = Query(
        "open", description="Thread status filter: open, dormant, closed, any, or past (dormant + closed)."
    ),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Story threads whose member articles link to this entity, most recently
    active first, each with its latest beat — powers the profile's Active
    Story card (status=open) and the expanded timeline's story markers
    (status=any)."""
    from app.intelligence.correlation import ENTITY_CONFIG
    from app.models.story_thread import StoryThread, StoryThreadBeat, StoryThreadEntry

    # A campaign reaches its stories through membership rather than extraction;
    # the join column is the only thing that differs.
    if entity_type == "campaign":
        if user.is_anonymous:
            return {"items": []}
        junction, fk_col = CampaignEntry, CampaignEntry.campaign_id
    elif entity_type in ENTITY_CONFIG:
        _, junction, fk_col = ENTITY_CONFIG[entity_type]
    else:
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)

    from app.services.public_view import visible_entries_only

    rows = (
        await db.execute(
            visible_entries_only(
                select(StoryThread, func.count(func.distinct(StoryThreadEntry.entry_id)).label("entity_entries"))
                .join(StoryThreadEntry, StoryThreadEntry.thread_id == StoryThread.id)
                .join(junction, junction.entry_id == StoryThreadEntry.entry_id),
                StoryThreadEntry.entry_id,
            )
            .where(
                fk_col == entity_id,
                *(
                    []
                    if status == "any"
                    else [StoryThread.status != "open"]
                    if status == "past"
                    else [StoryThread.status == status]
                ),
            )
            .group_by(StoryThread.id)
            .order_by(StoryThread.last_seen.desc().nulls_last())
            .limit(limit)
        )
    ).all()

    thread_ids = [row[0].id for row in rows]
    if user.is_anonymous:
        return {"items": await _visitor_story_cards(db, rows)}
    latest_beats: dict[uuid.UUID, StoryThreadBeat] = {}
    if thread_ids:
        beat_rows = (
            await db.execute(
                select(StoryThreadBeat)
                .where(StoryThreadBeat.thread_id.in_(thread_ids))
                .order_by(StoryThreadBeat.thread_id, StoryThreadBeat.position.desc())
            )
        ).scalars()
        for beat in beat_rows:
            latest_beats.setdefault(beat.thread_id, beat)

    return {
        "items": [
            {
                "slug": t.slug,
                "title": t.title,
                "summary": t.summary,
                "status": t.status,
                "entry_count": t.entry_count,
                "source_count": t.source_count,
                "first_seen": t.first_seen.isoformat() if t.first_seen else None,
                "last_seen": t.last_seen.isoformat() if t.last_seen else None,
                "entity_entry_count": entity_entries,
                "latest_beat": (
                    {
                        "headline": latest_beats[t.id].headline,
                        "occurred_at": (
                            latest_beats[t.id].occurred_at.isoformat() if latest_beats[t.id].occurred_at else None
                        ),
                    }
                    if t.id in latest_beats
                    else None
                ),
            }
            for t, entity_entries in rows
        ]
    }


async def _visitor_story_cards(db: AsyncSession, rows) -> list[dict]:
    """The Active Story cards a visitor sees: each thread rebuilt from its
    visible members (story_threads.visitor_thread_rows), its latest beat the
    last day-grouped one over them. Stored titles, AI summaries and beats can
    come from hidden articles."""
    from app.intelligence.story_threads import thread_title, visitor_slug
    from app.services.public_view import visitor_thread_view
    from app.services.thread_narrative import collect_members, heuristic_beats

    view = await visitor_thread_view(db, [t.id for t, _ in rows])
    cards = []
    for t, entity_entries in rows:
        seen = view.get(t.id)
        if seen is None:
            continue
        shown = set(seen["entry_ids"])
        beats = heuristic_beats([m for m in await collect_members(db, t.id) if m["entry_id"] in shown])
        latest = beats[-1] if beats else None
        cards.append(
            {
                "slug": visitor_slug(t.id),
                "title": thread_title(seen["first_title"]),
                "summary": None,
                "status": t.status,
                "entry_count": len(shown),
                "source_count": seen["source_count"],
                "first_seen": seen["first_seen"].isoformat() if seen["first_seen"] else None,
                "last_seen": seen["last_seen"].isoformat() if seen["last_seen"] else None,
                "entity_entry_count": entity_entries,
                "latest_beat": (
                    {
                        "headline": latest["headline"],
                        "occurred_at": latest["occurred_at"].isoformat() if latest["occurred_at"] else None,
                    }
                    if latest
                    else None
                ),
            }
        )
    return cards


@router.get("/{entity_type}/{entity_id}/attack-techniques")
async def get_entity_attack_techniques(
    entity_type: str = Path(..., description="threat_actor or malware — the only types with TTP-bearing entries."),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Techniques referenced by this entity's articles, ranked by evidence —
    per-technique article count and last-seen date. Powers the ATT&CK tab's
    evidence-ranked table (the Navigator layer endpoint stays flat)."""
    if entity_type not in DETECTION_GAPS_JUNCTION_MAP:
        raise AppError(
            code="bad_request", message=f"attack-techniques not supported for {entity_type}", status_code=400
        )
    junction, fk_col = DETECTION_GAPS_JUNCTION_MAP[entity_type]
    rows = (
        await db.execute(
            select(
                TTP.id,
                TTP.technique_id,
                TTP.technique_name,
                TTP.tactic,
                func.count(func.distinct(EntryTTP.entry_id)).label("articles"),
                func.max(Entry.published_at).label("last_seen"),
            )
            .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
            .join(junction, junction.entry_id == EntryTTP.entry_id)
            .join(Entry, Entry.id == EntryTTP.entry_id)
            .where(fk_col == entity_id)
            .group_by(TTP.id, TTP.technique_id, TTP.technique_name, TTP.tactic)
            .order_by(func.count(func.distinct(EntryTTP.entry_id)).desc(), func.max(Entry.published_at).desc())
        )
    ).all()
    return {
        "items": [
            {
                "id": str(row.id),
                "technique_id": row.technique_id,
                "technique_name": row.technique_name,
                "tactic": row.tactic,
                "articles": row.articles,
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            }
            for row in rows
        ]
    }


@router.get("/{entity_type}/{entity_id}/attack-layer")
async def get_entity_attack_layer(
    entity_type: str = Path(..., description="threat_actor or malware — the only types with TTP-bearing entries."),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity to build the Navigator layer for."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Generate ATT&CK Navigator JSON for this entity's referenced techniques."""
    from app.intelligence.ttp import generate_navigator_layer

    if entity_type not in DETECTION_GAPS_JUNCTION_MAP:
        raise AppError(code="bad_request", message=f"attack-layer not supported for {entity_type}", status_code=400)

    model_cls = Campaign if entity_type == "campaign" else RESCAN_MODEL_MAP[entity_type]
    entity = await db.get(model_cls, entity_id)
    if not entity:
        raise AppError(code="not_found", message="Entity not found", status_code=404)

    junction, fk_col = DETECTION_GAPS_JUNCTION_MAP[entity_type]
    result = await db.execute(
        select(TTP.technique_id, TTP.technique_name, TTP.tactic, EntryTTP.confidence)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .join(junction, junction.entry_id == EntryTTP.entry_id)
        .where(fk_col == entity_id)
        .distinct()
    )

    # The same technique can appear across multiple entries with different
    # confidence values — dedupe by technique_id, keeping the highest confidence.
    confidence_rank = {"low": 0, "medium": 1, "high": 2}
    by_technique: dict[str, dict] = {}
    for row in result.all():
        candidate = {
            "technique_id": row.technique_id,
            "technique_name": row.technique_name,
            "tactic": row.tactic,
            "confidence": row.confidence,
        }
        existing = by_technique.get(row.technique_id)
        if existing is None or (
            confidence_rank.get(row.confidence or "medium", 1)
            > confidence_rank.get(existing["confidence"] or "medium", 1)
        ):
            by_technique[row.technique_id] = candidate

    return generate_navigator_layer(list(by_technique.values()), title=getattr(entity, "name", str(entity_id)))


# window → (bucket count, bucket unit). Bucket size adapts so every window
# renders a readable series: hourly for a day, daily for bounded windows (so
# scrubbing resolves specific days), weekly only for the unbounded "all".
MENTIONS_WINDOWS: dict[str, tuple[int | None, str]] = {
    "24h": (24, "hour"),
    "7d": (7, "day"),
    "30d": (30, "day"),
    "60d": (60, "day"),
    "90d": (90, "day"),
    "all": (None, "week"),
}


@router.get("/{entity_type}/{entity_id}/mentions-timeseries")
async def get_entity_mentions_timeseries(
    entity_type: str = Path(
        ..., description="Entity type slug (threat_actor, malware, cve, ttp, country, tool, vendor, product)."
    ),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity to count mentions for."),
    window: str = Query(
        "90d", description="Time window: 24h (hourly buckets), 7d/30d/60d/90d (daily), or all (weekly)."
    ),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Mention counts for this entity, bucketed to fit the requested window —
    powers the profile timeline chart and header sparkline."""
    from datetime import UTC, datetime, timedelta

    from app.intelligence.correlation import entry_scope_junction

    scope = entry_scope_junction(entity_type)
    if scope is None:
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)
    if window not in MENTIONS_WINDOWS:
        raise AppError(
            code="bad_request",
            message=f"Unsupported window: {window} (expected one of {', '.join(MENTIONS_WINDOWS)})",
            status_code=400,
        )

    junction, fk_col = scope
    amount, bucket = MENTIONS_WINDOWS[window]
    now = datetime.now(UTC)

    # Derive the fill grid first and cut off at its start, so a partial first
    # bucket is included rather than silently dropped.
    start: datetime | None
    if bucket == "hour":
        start = (now - timedelta(hours=amount - 1)).replace(minute=0, second=0, microsecond=0)
        step, n = timedelta(hours=1), amount
    elif bucket == "day":
        start = (now - timedelta(days=amount - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        step, n = timedelta(days=1), amount
    else:  # week buckets — Monday-aligned to match date_trunc('week')
        monday = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        step = timedelta(weeks=1)
        if window == "all":
            start, n = None, 0  # derived from the data below
        else:
            start, n = monday - timedelta(weeks=amount - 1), amount

    bucket_col = func.date_trunc(bucket, Entry.published_at)
    query = (
        select(
            bucket_col.label("bucket"),
            func.count(func.distinct(Entry.id)).label("count"),
            func.count(func.distinct(Entry.feed_id)).label("feeds"),
        )
        .select_from(junction)
        .join(Entry, Entry.id == junction.entry_id)
        .where(fk_col == entity_id, Entry.published_at.isnot(None))
        .group_by(bucket_col)
        .order_by(bucket_col)
    )
    feeds_query = (
        select(func.count(func.distinct(Entry.feed_id)))
        .select_from(junction)
        .join(Entry, Entry.id == junction.entry_id)
        .where(fk_col == entity_id, Entry.published_at.isnot(None))
    )
    if start is not None:
        query = query.where(Entry.published_at >= start)
        feeds_query = feeds_query.where(Entry.published_at >= start)
    rows = (await db.execute(query)).all()
    total_feeds = (await db.execute(feeds_query)).scalar() or 0

    # Trend context for the header pulse line: total mentions in the window
    # immediately before this one (None for the unbounded "all" window), and
    # the busiest feed's share of the window — a newsletter-echo proxy.
    previous_total: int | None = None
    top_feed_share: float | None = None
    if start is not None:
        prev_start = start - step * n
        previous_total = (
            await db.execute(
                select(func.count(func.distinct(Entry.id)))
                .select_from(junction)
                .join(Entry, Entry.id == junction.entry_id)
                .where(
                    fk_col == entity_id,
                    Entry.published_at.isnot(None),
                    Entry.published_at >= prev_start,
                    Entry.published_at < start,
                )
            )
        ).scalar() or 0
        window_total = sum(row.count for row in rows)
        if window_total > 0:
            top_feed = (
                await db.execute(
                    select(func.count(func.distinct(Entry.id)).label("c"))
                    .select_from(junction)
                    .join(Entry, Entry.id == junction.entry_id)
                    .where(fk_col == entity_id, Entry.published_at >= start)
                    .group_by(Entry.feed_id)
                    .order_by(func.count(func.distinct(Entry.id)).desc())
                    .limit(1)
                )
            ).scalar()
            if top_feed:
                top_feed_share = round(top_feed / window_total, 3)

    if start is None:  # "all" — weekly from the first mention (min 2 buckets)
        monday = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        first = rows[0].bucket if rows else monday
        first_monday = (first - timedelta(days=first.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        n = max(int((monday - first_monday).days / 7) + 1, 2)
        start = monday - timedelta(weeks=n - 1)

    def key(dt: datetime) -> str:
        return dt.isoformat() if bucket == "hour" else dt.date().isoformat()

    counts = {key(row.bucket): (row.count, row.feeds) for row in rows}
    points = [
        {
            "date": key(start + step * i),
            "count": counts.get(key(start + step * i), (0, 0))[0],
            "feeds": counts.get(key(start + step * i), (0, 0))[1],
        }
        for i in range(n)
    ]

    return {
        "entity_type": entity_type,
        "entity_id": str(entity_id),
        "window": window,
        "bucket": bucket,
        "total_feeds": total_feeds,
        "previous_total": previous_total,
        "top_feed_share": top_feed_share,
        "points": points,
    }


@router.get("/{entity_type}/{entity_id}/entries-window")
async def get_entity_entries_window(
    entity_type: str = Path(
        ..., description="Entity type slug (threat_actor, malware, cve, ttp, country, tool, vendor, product)."
    ),
    entity_id: uuid.UUID = Path(..., description="UUID of the mentioned entity."),
    start: str = Query(..., description="Bucket start as an ISO datetime (inclusive)."),
    end: str = Query(..., description="Bucket end as an ISO datetime (exclusive)."),
    limit: int = Query(50, description="Maximum entries to return (clamped to 1-100)."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Articles mentioning this entity inside one timeline bucket — powers
    click-through from the mentions chart to the underlying reading."""
    from datetime import datetime

    from app.intelligence.correlation import entry_scope_junction
    from app.models.feed import Feed

    scope = entry_scope_junction(entity_type)
    if scope is None:
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)
    try:
        start_dt = datetime.fromisoformat(start)
        end_dt = datetime.fromisoformat(end)
    except ValueError:
        raise AppError(code="bad_request", message="start/end must be ISO datetimes", status_code=400)

    junction, fk_col = scope
    rows = (
        await db.execute(
            select(Entry.id, Entry.title, Entry.published_at, Feed.title.label("feed_title"))
            .select_from(junction)
            .join(Entry, Entry.id == junction.entry_id)
            .join(Feed, Feed.id == Entry.feed_id)
            .where(fk_col == entity_id, Entry.published_at >= start_dt, Entry.published_at < end_dt)
            .order_by(Entry.published_at.desc())
            .limit(min(max(limit, 1), 100))
        )
    ).all()

    return {
        "items": [
            {
                "entry_id": str(r.id),
                "title": r.title,
                "published_at": r.published_at.isoformat() if r.published_at else None,
                "feed_title": r.feed_title,
            }
            for r in rows
        ]
    }


@router.get("/{entity_type}/{entity_id}/top-entries")
async def get_entity_top_entries(
    entity_type: str = Path(
        ..., description="Entity type slug (threat_actor, malware, cve, ttp, country, tool, vendor, product)."
    ),
    entity_id: uuid.UUID = Path(..., description="UUID of the mentioned entity."),
    days: int = Query(30, description="Look-back window in days (clamped to 1-365)."),
    limit: int = Query(3, description="Maximum entries to return (clamped to 1-10)."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Highest-signal articles mentioning this entity in the window — the
    profile's "essential reading". Falls back to most recent when no entry has
    a signal score."""
    from datetime import datetime, timedelta

    from app.intelligence.correlation import entry_scope_junction
    from app.models.entry_signal import EntrySignal
    from app.models.feed import Feed

    scope = entry_scope_junction(entity_type)
    if scope is None:
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)

    junction, fk_col = scope
    cutoff = datetime.now(UTC) - timedelta(days=min(max(days, 1), 365))
    limit = min(max(limit, 1), 10)

    rows = (
        await db.execute(
            select(
                Entry.id,
                Entry.title,
                Entry.published_at,
                Feed.title.label("feed_title"),
                func.max(EntrySignal.score).label("signal"),
            )
            .select_from(junction)
            .join(Entry, Entry.id == junction.entry_id)
            .join(Feed, Feed.id == Entry.feed_id)
            .outerjoin(EntrySignal, EntrySignal.entry_id == Entry.id)
            .where(fk_col == entity_id, Entry.published_at >= cutoff)
            .group_by(Entry.id, Feed.title)
            .order_by(func.max(EntrySignal.score).desc().nulls_last(), Entry.published_at.desc())
            .limit(limit)
        )
    ).all()

    return {
        "entity_type": entity_type,
        "entity_id": str(entity_id),
        "days": days,
        "items": [
            {
                "entry_id": str(r.id),
                "title": r.title,
                "published_at": r.published_at.isoformat() if r.published_at else None,
                "feed_title": r.feed_title,
                "signal": round(float(r.signal), 3) if r.signal is not None else None,
            }
            for r in rows
        ],
    }


@router.post("/{entity_type}/{entity_id}/ai-summary")
async def generate_entity_ai_summary(
    entity_type: str = Path(
        ..., description="Entity type slug (threat_actor, malware, cve, ttp, country, tool, vendor, product)."
    ),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity to summarize."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate an AI summary for an entity based on linked articles and relationships, then save to description."""
    outcome = await generate_entity_assessment(db, user.id, entity_type, entity_id)
    status = outcome["status"]
    if status == "unsupported_type":
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)
    if status == "not_found":
        raise AppError(code="not_found", message="Entity not found", status_code=404)
    if status == "no_description_field":
        raise AppError(code="bad_request", message="Entity type does not have a description field", status_code=400)
    if status == "provider_paused":
        raise AppError(
            code="ai_unavailable",
            message="AI provider is rate-limited or paused — try again later.",
            status_code=503,
        )
    if status == "ai_error":
        raise AppError(
            code="ai_error",
            message=f"AI generation failed ({outcome.get('ai_status')}) — the model returned unusable output.",
            status_code=502,
        )
    if status != "updated":
        raise AppError(
            code="ai_unavailable",
            message="No AI task assignment configured. Assign a model to the 'article_summary' task in Settings > AI.",
            status_code=400,
        )

    return {"summary": outcome["summary"], "entity_id": str(entity_id), "entity_type": entity_type}


# --- Wikipedia Content ---


class WikipediaFetchRequest(BaseModel):
    title: str | None = None  # explicit article title chosen by the user

    model_config = ConfigDict(json_schema_extra={"example": {"title": "Cozy Bear"}})


def _wikipedia_refused(e) -> AppError:
    """The wikipedia source's gateway refused the request: 503 when it can't
    check its limits, else 429."""
    if e.status == "gateway_unavailable":
        return AppError(code=e.status, message="Wikipedia lookups are unavailable right now", status_code=503)
    return AppError(code=e.status, message="Wikipedia is rate limited; try again later", status_code=429)


@router.get("/{entity_type}/{entity_id}/wikipedia/search")
async def search_wikipedia_titles(
    entity_type: str = Path(
        ..., description="Entity type slug (threat_actor, malware, cve, ttp, country, tool, vendor, product)."
    ),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity being enriched."),
    q: str = Query(..., description="Search phrase for candidate Wikipedia article titles."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Search Wikipedia for candidate articles so the user can pick the right one."""
    if entity_type not in ENTITY_MODEL_MAP:
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)
    if not q.strip():
        return {"results": []}

    from app.enrichment.gateway import GatewayError
    from app.enrichment.pipeline import gateway_for
    from app.enrichment.wikipedia_helper import search_wikipedia

    gateway, _ = await gateway_for(db, "wikipedia")
    try:
        results = await search_wikipedia(q.strip(), gateway, limit=8)
    except GatewayError as e:
        raise _wikipedia_refused(e)
    except Exception:
        logger.exception("Wikipedia search failed for %r", q)
        raise AppError(code="upstream_error", message="Wikipedia search failed", status_code=502)

    return {"results": results}


@router.post("/{entity_type}/{entity_id}/wikipedia")
async def fetch_wikipedia_content(
    entity_type: str = Path(
        ..., description="Entity type slug (threat_actor, malware, cve, ttp, country, tool, vendor, product)."
    ),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity to enrich."),
    payload: WikipediaFetchRequest | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch Wikipedia content for an entity and save to wikipedia_content/wikipedia_url fields.

    With a `title` in the body, fetches that exact article (user-selected override);
    otherwise resolves by entity name with a title-match guardrail.
    """
    if entity_type not in ENTITY_MODEL_MAP:
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)

    model_cls = ENTITY_MODEL_MAP[entity_type][0]
    result = await db.execute(select(model_cls).where(model_cls.id == entity_id))
    entity = result.scalar_one_or_none()
    if not entity:
        raise AppError(code="not_found", message="Entity not found", status_code=404)

    # Get entity name for search
    entity_name = (
        getattr(entity, "name", None) or getattr(entity, "cve_id", None) or getattr(entity, "technique_id", None)
    )
    if not entity_name:
        raise AppError(code="bad_request", message="Entity has no searchable name", status_code=400)

    from app.enrichment.gateway import GatewayError
    from app.enrichment.pipeline import gateway_for
    from app.enrichment.wikipedia_helper import extract_first_paragraph, fetch_wikipedia, fetch_wikipedia_by_title

    gateway, _ = await gateway_for(db, "wikipedia")
    chosen_title = (payload.title or "").strip() if payload else ""
    try:
        if chosen_title:
            wiki_result = await fetch_wikipedia_by_title(chosen_title, transport=gateway.transport())
        else:
            wiki_result = await fetch_wikipedia(
                entity_name, entity_type, aliases=getattr(entity, "aliases", None), transport=gateway.transport()
            )
    except GatewayError as e:
        raise _wikipedia_refused(e)

    if not wiki_result:
        raise AppError(
            code="not_found",
            message=f"No Wikipedia article found for '{chosen_title or entity_name}'",
            status_code=404,
        )

    # Topical guard (F11) for name-resolved fetches — an explicitly chosen
    # title is a deliberate human pick and bypasses it.
    if not chosen_title:
        from app.intelligence.entity_resolution import enrichment_content_ok, log_enrichment_reject

        ok, reject_reason = enrichment_content_ok(entity_name, wiki_result["content"])
        if not ok:
            log_enrichment_reject(db, entity_type, entity_id, entity_name, reject_reason, detail=wiki_result.get("url"))
            raise AppError(
                code="enrichment_rejected",
                message=(
                    f"The Wikipedia article for '{entity_name}' looks like the wrong subject "
                    f"({reject_reason}). Use the search picker to select the right article."
                ),
                status_code=422,
            )

    entity.wikipedia_content = wiki_result["content"]
    entity.wikipedia_url = wiki_result["url"]
    entity.wikipedia_image_url = wiki_result.get("image_url")

    # Auto-set description from first paragraph if empty
    if hasattr(entity, "description") and not entity.description:
        first_para = extract_first_paragraph(wiki_result["content"])
        if first_para:
            entity.description = first_para

    if chosen_title:
        # Drop cached wikipedia enrichment so auto-enrichment can't overwrite the user's pick
        from app.models.enrichment import EnrichmentResult

        await db.execute(
            delete(EnrichmentResult).where(
                EnrichmentResult.entity_type == entity_type,
                EnrichmentResult.entity_id == entity_id,
                EnrichmentResult.source_type == "wikipedia",
            )
        )

    db.add(entity)
    await db.flush()
    await db.refresh(entity)
    await invalidate_entity_cache(entity_type, str(entity_id))
    await db.commit()

    return {
        "wikipedia_url": wiki_result["url"],
        "wikipedia_title": wiki_result["title"],
        "wikipedia_content": wiki_result["content"],
        "wikipedia_image_url": wiki_result.get("image_url"),
        "entity_id": str(entity_id),
        "entity_type": entity_type,
    }


@router.delete("/{entity_type}/{entity_id}/wikipedia")
async def clear_wikipedia_content(
    entity_type: str = Path(
        ..., description="Entity type slug (threat_actor, malware, cve, ttp, country, tool, vendor, product)."
    ),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity whose Wikipedia data to clear."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Clear an entity's Wikipedia link and suppress future auto-enrichment.

    Used when no Wikipedia article matches the entity ("None"). Writes a
    long-lived ``user_cleared`` marker so neither the enrichment pipeline (via
    cached-result check) nor the weekly bulk sync re-populates the fields.
    """
    if entity_type not in ENTITY_MODEL_MAP:
        raise AppError(code="bad_request", message=f"Unsupported entity type: {entity_type}", status_code=400)

    model_cls = ENTITY_MODEL_MAP[entity_type][0]
    result = await db.execute(select(model_cls).where(model_cls.id == entity_id))
    entity = result.scalar_one_or_none()
    if not entity:
        raise AppError(code="not_found", message="Entity not found", status_code=404)

    entity.wikipedia_content = None
    entity.wikipedia_url = None
    entity.wikipedia_image_url = None

    from datetime import datetime, timedelta

    from app.models.enrichment import EnrichmentResult

    # Replace any cached wikipedia enrichment with a long-lived suppression marker.
    await db.execute(
        delete(EnrichmentResult).where(
            EnrichmentResult.entity_type == entity_type,
            EnrichmentResult.entity_id == entity_id,
            EnrichmentResult.source_type == "wikipedia",
        )
    )
    now = datetime.now(UTC)
    db.add(
        EnrichmentResult(
            entity_type=entity_type,
            entity_id=entity_id,
            source_type="wikipedia",
            raw_response={"user_cleared": True},
            # status="success" + found=False → the pipeline treats it as a cache hit and
            # never re-fetches; user_cleared flag lets the bulk sync skip it too.
            parsed_data={"found": False, "user_cleared": True},
            enriched_at=now,
            expires_at=now + timedelta(days=36500),  # ~100 years — effectively permanent
            status="success",
        )
    )

    db.add(entity)
    await db.flush()
    await invalidate_entity_cache(entity_type, str(entity_id))
    await db.commit()

    return {"entity_id": str(entity_id), "entity_type": entity_type, "wikipedia_cleared": True}


# --- Entity Type Conversion ---

# One adapter per convertible type, keyed by the frontend slug (the vocabulary
# the profile UI, EntityRelationship, EntityNote and CampaignEntity all use).
# `canonical` is the slug the reclassify-tombstone + creation resolver use — only
# malware differs (`malware_families`). cve/ttp carry an external-id identity
# (cve_id / technique_id) instead of a free-text name and have no aliases.
CONVERT_ADAPTERS: dict[str, dict] = {
    "threat_actor": {
        "model": ThreatActor,
        "junction": EntryThreatActor,
        "junction_fk": "threat_actor_id",
        "has_name": True,
        "has_aliases": True,
        "identity_field": None,
    },
    "malware": {
        "model": MalwareFamily,
        "junction": EntryMalware,
        "junction_fk": "malware_family_id",
        "has_name": True,
        "has_aliases": True,
        "identity_field": None,
    },
    "tool": {
        "model": Tool,
        "junction": EntryTool,
        "junction_fk": "tool_id",
        "has_name": True,
        "has_aliases": True,
        "identity_field": None,
    },
    "vendor": {
        "model": Vendor,
        "junction": EntryVendor,
        "junction_fk": "vendor_id",
        "has_name": True,
        "has_aliases": True,
        "identity_field": None,
    },
    "product": {
        "model": Product,
        "junction": EntryProduct,
        "junction_fk": "product_id",
        "has_name": True,
        "has_aliases": True,
        "identity_field": None,
    },
    "country": {
        "model": Country,
        "junction": EntryCountry,
        "junction_fk": "country_id",
        "has_name": True,
        "has_aliases": True,
        "identity_field": None,
    },
    "cve": {
        "model": CVE,
        "junction": EntryCVE,
        "junction_fk": "cve_id",
        "has_name": False,
        "has_aliases": False,
        "identity_field": "cve_id",
    },
    "ttp": {
        "model": TTP,
        "junction": EntryTTP,
        "junction_fk": "ttp_id",
        "has_name": False,
        "has_aliases": False,
        "identity_field": "technique_id",
    },
}

# Attributes copied across when both models carry them. Type-specific fields
# (motivation, malware_type, vendor_id, cvss_score, tactic, …) are intentionally
# dropped — fix them via the profile editors after converting.
_CONVERT_COMMON_ATTRS = ("description", "article_count", "first_seen_at", "last_seen_at", "malpedia_url", "metadata_")

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def _convert_display_name(slug: str, entity) -> str:
    """Human-facing identity of an entity, regardless of type."""
    if slug == "cve":
        return entity.cve_id
    if slug == "ttp":
        return entity.technique_name or entity.technique_id
    return entity.name


def _normalize_target_identifier(target_type: str, raw: str | None) -> str:
    """Validate/normalize the external id required to convert *into* cve/ttp."""
    ident = (raw or "").strip().upper()
    if target_type == "cve":
        if not _CVE_ID_RE.match(ident):
            raise AppError(
                code="bad_request",
                message="Converting to a CVE needs a valid CVE ID (e.g. CVE-2024-1234).",
                status_code=400,
            )
    elif not _TECHNIQUE_ID_RE.match(ident):  # ttp
        raise AppError(
            code="bad_request",
            message="Converting to a TTP needs a valid ATT&CK technique ID (e.g. T1059 or T1059.001).",
            status_code=400,
        )
    return ident


class EntityConvertRequest(BaseModel):
    entity_id: uuid.UUID = Field(..., description="ID of the entity to convert")
    target_type: str = Field(..., description="Entity type to convert to")
    target_identifier: str | None = Field(
        default=None,
        description="Required when target_type is cve (a CVE ID) or ttp (an ATT&CK technique ID); ignored otherwise.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_id": "3f9d2a1b-8c7e-4f6a-b5d4-0e1c2a3b4d5f",
                "target_type": "tool",
            }
        }
    )


@router.post("/convert")
async def convert_entity_type(
    body: EntityConvertRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Convert an entity to any other type (e.g. malware → tool, vendor → product, tool → cve).

    Creates a new entity of the target type, migrates entry links, entity
    relationships, notes and campaign memberships, writes a reclassify tombstone
    so automated pipelines don't recreate the source, then deletes the source.
    Type-specific fields don't cross over — only common identity/description
    fields survive.
    """
    from app.api.entity_merge import _repoint_entity_relationships, _write_reclassify_tombstones

    tgt_slug = body.target_type
    tgt = CONVERT_ADAPTERS.get(tgt_slug)
    if tgt is None:
        raise AppError(code="bad_request", message=f"Unsupported target type: {tgt_slug}", status_code=400)

    # Determine source type by probing every convertible table for the id.
    src_slug = None
    source_entity = None
    for slug, adapter in CONVERT_ADAPTERS.items():
        found = (
            await db.execute(select(adapter["model"]).where(adapter["model"].id == body.entity_id))
        ).scalar_one_or_none()
        if found is not None:
            src_slug = slug
            source_entity = found
            break

    if source_entity is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)
    if src_slug == tgt_slug:
        raise AppError(code="bad_request", message="Entity is already that type", status_code=400)

    src = CONVERT_ADAPTERS[src_slug]
    tgt_model = tgt["model"]
    disp = _convert_display_name(src_slug, source_entity)

    # Resolve/validate the target identity and reject collisions up front.
    target_identifier = None
    if tgt["identity_field"] == "cve_id":
        target_identifier = _normalize_target_identifier("cve", body.target_identifier)
        clash = (await db.execute(select(CVE.id).where(CVE.cve_id == target_identifier))).scalar_one_or_none()
        if clash is not None:
            raise AppError(code="conflict", message=f"{target_identifier} already exists.", status_code=409)
    elif tgt["identity_field"] == "technique_id":
        target_identifier = _normalize_target_identifier("ttp", body.target_identifier)
        clash = (await db.execute(select(TTP.id).where(TTP.technique_id == target_identifier))).scalar_one_or_none()
        if clash is not None:
            raise AppError(code="conflict", message=f"{target_identifier} already exists.", status_code=409)
    else:
        clash = (
            await db.execute(select(tgt_model.id).where(func.lower(tgt_model.name) == disp.lower()))
        ).scalar_one_or_none()
        if clash is not None:
            raise AppError(
                code="conflict",
                message=f"An entity named '{disp}' already exists in {tgt_slug}.",
                status_code=409,
            )

    # Build the target from the common fields both types share.
    kwargs: dict = {}
    for attr in _CONVERT_COMMON_ATTRS:
        if hasattr(tgt_model, attr):
            value = getattr(source_entity, attr, None)
            if value is not None:
                kwargs[attr] = value
    if tgt["has_aliases"] and hasattr(tgt_model, "aliases"):
        kwargs["aliases"] = list(getattr(source_entity, "aliases", []) or [])
    if tgt["identity_field"] == "cve_id":
        kwargs["cve_id"] = target_identifier
    elif tgt["identity_field"] == "technique_id":
        kwargs["technique_id"] = target_identifier
        if hasattr(tgt_model, "technique_name"):
            kwargs["technique_name"] = disp
    elif tgt["has_name"]:
        kwargs["name"] = disp

    new_entity = tgt_model(**kwargs)
    db.add(new_entity)
    await db.flush()
    await db.refresh(new_entity)
    new_id = new_entity.id

    # 1. Migrate entry-junction rows. Junctions carry different metadata columns
    # (ttp uses source_text, cve has no matched_names) — copy only the shared set.
    src_j, tgt_j = src["junction"], tgt["junction"]
    src_fk, tgt_fk = src["junction_fk"], tgt["junction_fk"]
    src_fk_col, tgt_fk_col = getattr(src_j, src_fk), getattr(tgt_j, tgt_fk)
    shared_cols = ({c.key for c in src_j.__table__.columns} & {c.key for c in tgt_j.__table__.columns}) - {
        src_fk,
        tgt_fk,
        "entry_id",
    }

    already_linked = set((await db.execute(select(tgt_j.entry_id).where(tgt_fk_col == new_id))).scalars().all())
    old_links = (await db.execute(select(src_j).where(src_fk_col == body.entity_id))).scalars().all()
    migrated = 0
    for link in old_links:
        if link.entry_id in already_linked:
            continue
        row = {"entry_id": link.entry_id, tgt_fk: new_id}
        for col in shared_cols:
            row[col] = getattr(link, col)
        db.add(tgt_j(**row))
        already_linked.add(link.entry_id)
        migrated += 1
    await db.execute(delete(src_j).where(src_fk_col == body.entity_id))
    await db.flush()

    # 2. Repoint relationships (dedup + self-edge safe), notes and campaigns —
    # all keyed by frontend slug.
    await _repoint_entity_relationships(db, src_slug, body.entity_id, tgt_slug, new_id)
    await db.execute(
        update(EntityNote)
        .where(EntityNote.entity_type == src_slug, EntityNote.entity_id == body.entity_id)
        .values(entity_type=tgt_slug, entity_id=new_id)
    )
    await db.execute(
        update(CampaignEntity)
        .where(CampaignEntity.entity_type == src_slug, CampaignEntity.entity_id == body.entity_id)
        .values(entity_type=tgt_slug, entity_id=new_id)
    )

    # 3. Tombstone the source name + aliases so the autolinker /
    # AI extraction don't recreate the folded entity. cve/ttp sources have no
    # name/aliases and no resolver consumer, so skip them.
    if src["has_name"]:
        names = [disp, *(getattr(source_entity, "aliases", []) or [])]
        await _write_reclassify_tombstones(db, src_slug, names, tgt_slug, new_id)

    # 4. Delete the source (+ its search doc), invalidate caches, refresh vocab.
    await db.delete(source_entity)
    await db.flush()
    delete_entity_document(src_slug, body.entity_id)
    await invalidate_entity_cache(src_slug, str(body.entity_id))
    await invalidate_entity_cache(tgt_slug, str(new_id))

    try:
        from app.workers.tasks import refresh_autolinker_vocabulary

        refresh_autolinker_vocabulary.delay()
    except Exception:
        pass

    await db.commit()

    logger.info("Converted entity %s from %s to %s (new id: %s)", disp, src_slug, tgt_slug, new_id)

    return {
        "id": str(new_id),
        "name": _convert_display_name(tgt_slug, new_entity),
        "source_type": src_slug,
        "target_type": tgt_slug,
        "migrated_entry_links": migrated,
    }
