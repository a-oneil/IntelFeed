import ipaddress
import time

import httpx
from fastapi import APIRouter, Request
from sqlalchemy import text

from app.config import settings
from app.core.build_info import build_stamp
from app.database import async_session
from app.services.redis_client import get_redis

router = APIRouter()


async def _check_database() -> dict:
    start = time.monotonic()
    try:
        async with async_session() as db:
            await db.execute(text("SELECT 1"))
        latency = round((time.monotonic() - start) * 1000, 1)
        return {"status": "ok", "latency_ms": latency}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def _check_redis() -> dict:
    start = time.monotonic()
    try:
        r = await get_redis()
        await r.ping()
        latency = round((time.monotonic() - start) * 1000, 1)
        return {"status": "ok", "latency_ms": latency}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def _check_meilisearch() -> dict:
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.meili_url}/health")
            latency = round((time.monotonic() - start) * 1000, 1)
            if resp.status_code == 200:
                return {"status": "ok", "latency_ms": latency}
            return {"status": "error", "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@router.get("/api/version")
async def version():
    """Build stamp of the running API: version, commit SHA and build timestamp.

    Touches nothing — no database, Redis or Meilisearch call — so unlike
    /api/health it is cheap enough to poll. Unauthenticated.

    `version` is `git describe --tags --always --dirty --match='v*'` at image
    build time, so it reads as a bare short SHA until the repo carries a `v*`
    tag and as a tag (or `v1.2.3-4-gabc1234`) after. The `--match` matters: CI
    also tags APK releases `android-v<version>`, and without it this reported
    the Android app's version. An unstamped build reports "dev".
    """
    return build_stamp()


def _is_local(request: Request) -> bool:
    """A caller on this host (the container healthcheck, an operator's exec curl):
    loopback peer and nothing forwarded it. Every proxied request carries
    X-Forwarded-For, so traffic from outside never counts."""
    if request.headers.get("x-forwarded-for"):
        return False
    host = request.client.host if request.client else ""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@router.get("/api/health")
async def health(request: Request):
    """Aggregate health check pinging PostgreSQL, Redis, and Meilisearch.

    Overall status is "healthy" when every component is ok, "degraded" when only the
    database is ok, and "unhealthy" when the database check fails. Unauthenticated.
    Latency and error text per component are shown only to a caller on this host;
    anyone else gets each component's status alone.
    """
    components = {
        "database": await _check_database(),
        "redis": await _check_redis(),
        "meilisearch": await _check_meilisearch(),
    }

    # Database is critical; others are non-critical
    db_ok = components["database"]["status"] == "ok"
    all_ok = all(c["status"] == "ok" for c in components.values())

    if all_ok:
        status = "healthy"
    elif db_ok:
        status = "degraded"
    else:
        status = "unhealthy"

    if not _is_local(request):
        components = {name: {"status": c["status"]} for name, c in components.items()}
    return {
        "status": status,
        **build_stamp(),
        "components": components,
    }
