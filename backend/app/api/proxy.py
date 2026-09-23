import hashlib
import logging
import socket
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from app.config import settings
from app.core.security import get_current_user
from app.models.user import User

_BLOCKED_NETWORKS = [
    ip_network("0.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("100.64.0.0/10"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("172.16.0.0/12"),
    ip_network("192.0.0.0/24"),
    ip_network("192.168.0.0/16"),
    ip_network("198.18.0.0/15"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]

logger = logging.getLogger(__name__)
router = APIRouter()

ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"}


def _cache_path(url: str) -> Path:
    """Content-addressed cache path: {cache_dir}/{hash[:2]}/{hash}"""
    h = hashlib.sha256(url.encode()).hexdigest()
    return Path(settings.image_proxy_cache_dir) / h[:2] / h


def _read_cache(url: str) -> tuple[bytes, str] | None:
    """Read cached image + content type from disk."""
    path = _cache_path(url)
    meta_path = path.with_suffix(".meta")
    if path.exists() and meta_path.exists():
        try:
            content_type = meta_path.read_text().strip()
            return path.read_bytes(), content_type
        except Exception:
            return None
    return None


def _write_cache(url: str, content: bytes, content_type: str) -> None:
    """Write image + content type to disk cache."""
    try:
        path = _cache_path(url)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.with_suffix(".meta").write_text(content_type)
    except Exception:
        logger.debug("Failed to write image cache for %s", url, exc_info=True)


@router.get("/image")
async def proxy_image(
    url: str = Query(..., description="Absolute http(s) URL of the external image to fetch"),
    w: int | None = Query(None, ge=1, le=2000, description="Target width in pixels; larger images are downscaled"),
    user: User = Depends(get_current_user),
):
    """Proxy and optionally resize an external image."""
    if not settings.image_proxy_enabled:
        return Response(status_code=404)

    # Validate URL scheme and block private/reserved IPs (SSRF protection)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return Response(status_code=400)

    try:
        hostname = parsed.hostname or ""
        resolved_ips = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, addr in resolved_ips:
            ip = ip_address(addr[0])
            if any(ip in net for net in _BLOCKED_NETWORKS):
                return Response(status_code=400)
    except (socket.gaierror, ValueError):
        return Response(status_code=400)

    # Build a cache key that includes the resize width
    cache_url = f"{url}?w={w}" if w else url

    # Check disk cache
    cached = _read_cache(cache_url)
    if cached:
        content, content_type = cached
        return Response(
            content=content,
            media_type=content_type,
            headers={
                "Cache-Control": f"public, max-age={settings.image_proxy_cache_ttl_days * 86400}",
                "X-Content-Type-Options": "nosniff",
            },
        )

    referer = f"{parsed.scheme}://{parsed.netloc}/"

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=10.0,
        headers={"User-Agent": settings.user_agent, "Referer": referer},
    ) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            content = response.content
            content_type = response.headers.get("content-type", "").split(";")[0].strip()
        except httpx.HTTPError as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status not in (403, 429, 503):
                return Response(status_code=502)
            # Likely a bot challenge — retry with curl_cffi browser impersonation.
            try:
                import asyncio

                from curl_cffi import requests as cffi_requests

                def _fetch():
                    return cffi_requests.get(
                        url,
                        impersonate="chrome",
                        timeout=15,
                        headers={"Referer": referer},
                    )

                cffi_resp = await asyncio.to_thread(_fetch)
                if cffi_resp.status_code != 200:
                    return Response(status_code=502)
                content = cffi_resp.content
                content_type = cffi_resp.headers.get("content-type", "").split(";")[0].strip()
            except Exception:
                logger.debug("curl_cffi fallback failed for %s", url, exc_info=True)
                return Response(status_code=502)

        if content_type not in ALLOWED_CONTENT_TYPES:
            return Response(status_code=415)

        if len(content) > settings.image_proxy_max_size_bytes:
            return Response(status_code=413)

        # Detect and block tracking pixels (1x1 images)
        if len(content) < 100:
            try:
                from io import BytesIO

                from PIL import Image

                img = Image.open(BytesIO(content))
                if img.size[0] <= 1 and img.size[1] <= 1:
                    return Response(status_code=204)
            except Exception:
                pass

        # Resize if requested
        if w and content_type != "image/svg+xml":
            try:
                from io import BytesIO

                from PIL import Image

                img = Image.open(BytesIO(content))
                if img.width > w:
                    ratio = w / img.width
                    new_height = int(img.height * ratio)
                    img = img.resize((w, new_height), Image.LANCZOS)
                    buf = BytesIO()
                    fmt = "JPEG" if content_type == "image/jpeg" else "PNG"
                    img.save(buf, format=fmt)
                    content = buf.getvalue()
            except Exception:
                pass

        # Write to disk cache
        _write_cache(cache_url, content, content_type)

        return Response(
            content=content,
            media_type=content_type,
            headers={
                "Cache-Control": f"public, max-age={settings.image_proxy_cache_ttl_days * 86400}",
                "X-Content-Type-Options": "nosniff",
            },
        )
