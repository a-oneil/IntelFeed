"""Simple intelligence API feed for external consumers."""

import hashlib
import hmac
from datetime import datetime

from fastapi import APIRouter, Depends, Header, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.core.exceptions import AppError
from app.database import get_db
from app.models.user import User

router = APIRouter()

_optional_bearer = HTTPBearer(auto_error=False)


async def _get_feed_user(
    x_api_key: str | None = Header(
        default=None, alias="X-API-Key", description="API key for external consumers (alternative to a JWT)"
    ),
    credentials: HTTPAuthorizationCredentials | None = Depends(_optional_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Authenticate via JWT (Authorization header) or X-API-Key header.

    Internal UI uses JWT; external consumers use X-API-Key.
    API keys are stored as SHA-256 hashes in user.settings["api_key_hash"].
    """
    # Try JWT first if Authorization header present
    if credentials:
        from fastapi import HTTPException

        from app.core.security import user_from_access_token

        try:
            return await user_from_access_token(credentials.credentials, db)
        except HTTPException:
            pass  # Fall through to API key auth

    # Fall back to API key — query by hash directly instead of iterating all users
    if x_api_key:
        key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()

        result = await db.execute(
            select(User).where(
                User.is_active.is_(True),
                User.settings["api_key_hash"].astext == key_hash,
            )
        )
        user = result.scalar_one_or_none()
        if user:
            stored_hash = (user.settings or {}).get("api_key_hash", "")
            if hmac.compare_digest(stored_hash, key_hash):
                return user

    raise AppError(
        code="unauthorized",
        message="Provide an Authorization header (JWT) or X-API-Key header",
        status_code=401,
    )


@router.get("/feed")
async def get_intelligence_feed(
    format: str = Query("json", pattern=r"^(json)$", description="Output format (only 'json' is supported)"),
    entity_type: str | None = Query(
        None, description="Comma-separated entity types to include: cve,ttp,actor,malware (default: all)"
    ),
    since: str | None = Query(None, description="Only entities first seen at or after this ISO 8601 timestamp"),
    tlp: str | None = Query(None, description="Comma-separated TLP labels (e.g. TLP:GREEN,TLP:CLEAR); not yet applied"),
    limit: int = Query(100, ge=1, le=500, description="Page size (also caps rows fetched per entity type)"),
    offset: int = Query(0, ge=0, description="Number of items to skip after cross-type sorting"),
    user: User = Depends(_get_feed_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Paginated feed of published intelligence data.
    Returns CVEs, TTPs, threat actors, malware from the system.

    Authentication: JWT (Authorization header) or API key (X-API-Key header).
    """
    from app.models.cve import CVE
    from app.models.malware_family import MalwareFamily
    from app.models.threat_actor import ThreatActor
    from app.models.ttp import TTP

    requested_types = set()
    if entity_type:
        # Retired spellings ('actor') are still accepted from existing API callers.
        requested_types = {entity_types.normalize_entity_type(t.strip()) for t in entity_type.split(",")}
    else:
        requested_types = {"cve", "ttp", "threat_actor", "malware"}

    since_dt = None
    if since:
        try:
            # URL-decode may turn '+' into space; restore timezone offset
            since_clean = since.strip().replace(" 00:00", "+00:00")
            since_dt = datetime.fromisoformat(since_clean)
        except ValueError:
            raise AppError(
                code="invalid_param",
                message="Invalid 'since' date format. Use ISO 8601.",
                status_code=400,
            )

    items = []

    # Collect entities
    if "cve" in requested_types:
        q = select(CVE)
        if since_dt:
            q = q.where(CVE.first_seen_at >= since_dt)
        result = await db.execute(q.order_by(CVE.first_seen_at.desc()).limit(limit))
        for cve in result.scalars().all():
            items.append(
                {
                    "entity_type": "vulnerability",
                    "cve_id": cve.cve_id,
                    "cvss_score": float(cve.cvss_score) if cve.cvss_score is not None else None,
                    "severity": cve.severity,
                    "description": cve.description,
                    "epss_score": cve.epss_score,
                    "exploit_availability": cve.exploit_availability,
                    "first_seen": cve.first_seen_at.isoformat() if cve.first_seen_at else None,
                    "id": str(cve.id),
                }
            )

    if "ttp" in requested_types:
        q = select(TTP)
        if since_dt:
            q = q.where(TTP.first_seen_at >= since_dt)
        result = await db.execute(q.order_by(TTP.first_seen_at.desc()).limit(limit))
        for ttp in result.scalars().all():
            items.append(
                {
                    "entity_type": "attack-pattern",
                    "technique_id": ttp.technique_id,
                    "technique_name": ttp.technique_name,
                    "tactic": ttp.tactic,
                    "first_seen": ttp.first_seen_at.isoformat() if ttp.first_seen_at else None,
                    "id": str(ttp.id),
                }
            )

    if "threat_actor" in requested_types:
        q = select(ThreatActor)
        if since_dt:
            q = q.where(ThreatActor.first_seen_at >= since_dt)
        result = await db.execute(q.order_by(ThreatActor.first_seen_at.desc()).limit(limit))
        for actor in result.scalars().all():
            items.append(
                {
                    "entity_type": "threat-actor",
                    "name": actor.name,
                    "aliases": actor.aliases,
                    "description": actor.description,
                    "country": actor.country,
                    "motivation": actor.motivation,
                    "first_seen": actor.first_seen_at.isoformat() if actor.first_seen_at else None,
                    "id": str(actor.id),
                }
            )

    if "malware" in requested_types:
        q = select(MalwareFamily)
        if since_dt:
            q = q.where(MalwareFamily.first_seen_at >= since_dt)
        result = await db.execute(q.order_by(MalwareFamily.first_seen_at.desc()).limit(limit))
        for mw in result.scalars().all():
            items.append(
                {
                    "entity_type": "malware",
                    "name": mw.name,
                    "aliases": mw.aliases,
                    "description": mw.description,
                    "malware_type": mw.malware_type,
                    "first_seen": mw.first_seen_at.isoformat() if mw.first_seen_at else None,
                    "id": str(mw.id),
                }
            )

    # Sort by first_seen descending
    items.sort(key=lambda x: x.get("first_seen") or "", reverse=True)

    # Apply overall pagination
    total = len(items)
    items = items[offset : offset + limit]

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": (offset + limit) < total,
    }
