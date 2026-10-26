import hashlib
import logging
import uuid
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.safe_http import OutboundBlocked, safe_async_client, safe_curl_get
from app.core.security import get_viewer
from app.database import get_db
from app.models.entry import Entry
from app.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter()

ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"}

# Every proxied image is served from the app's own origin. As an <img> nothing
# in it runs, but opened directly an SVG is a document; this keeps it inert.
_IMAGE_HEADERS = {"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox; default-src 'none'"}


class _FetchFailed(Exception):
    def __init__(self, status: int):
        super().__init__(status)
        self.status = status


async def _fetch_image(url: str, referer: str, max_bytes: int) -> tuple[bytes, str]:
    """The image at ``url`` and its content type, or _FetchFailed(status).

    Both clients are the SSRF-guarded ones: every connection, redirects
    included, goes to a vetted public address (400 when one is refused). The
    body is streamed and abandoned past ``max_bytes`` (413), and anything that
    is not an allowed image type is refused (415) before it is read.
    """
    headers = {"User-Agent": str(settings.get("user_agent") or settings.user_agent), "Referer": referer}
    try:
        async with safe_async_client(follow_redirects=True, timeout=10.0, headers=headers) as client:
            async with client.stream("GET", url) as response:
                if response.status_code == 200:
                    content_type = response.headers.get("content-type", "").split(";")[0].strip()
                    if content_type not in ALLOWED_CONTENT_TYPES:
                        raise _FetchFailed(415)
                    declared = response.headers.get("content-length", "")
                    if declared.isdigit() and int(declared) > max_bytes:
                        raise _FetchFailed(413)
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body += chunk
                        if len(body) > max_bytes:
                            raise _FetchFailed(413)
                    return bytes(body), content_type
                if response.status_code not in (403, 429, 503):
                    raise _FetchFailed(502)
    except OutboundBlocked:
        raise _FetchFailed(400) from None
    except httpx.HTTPError:
        raise _FetchFailed(502) from None

    # 403/429/503: likely a bot challenge. Retry with browser impersonation.
    try:
        cffi_resp = await safe_curl_get(url, impersonate="chrome", timeout=15, headers={"Referer": referer})
    except OutboundBlocked:
        raise _FetchFailed(400) from None
    except Exception:
        logger.debug("curl_cffi fallback failed for %s", url, exc_info=True)
        raise _FetchFailed(502) from None
    if cffi_resp.status_code != 200:
        raise _FetchFailed(502)
    content_type = cffi_resp.headers.get("content-type", "").split(";")[0].strip()
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise _FetchFailed(415)
    if len(cffi_resp.content) > max_bytes:
        raise _FetchFailed(413)
    return cffi_resp.content, content_type


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


async def _entry_shows_image(db: AsyncSession, entry_id: uuid.UUID | None, url: str) -> bool:
    """Whether ``url`` is the entry's lead image or appears in its stored content."""
    if entry_id is None:
        return False
    row = (await db.execute(select(Entry.image_url, Entry.content).where(Entry.id == entry_id))).one_or_none()
    if row is None:
        return False
    image_url, content = row
    return url == image_url or (bool(content) and url in content)


@router.get("/image")
async def proxy_image(
    url: str = Query(..., description="Absolute http(s) URL of the external image to fetch"),
    w: int | None = Query(None, ge=1, le=2000, description="Target width in pixels; larger images are downscaled"),
    entry: uuid.UUID | None = Query(
        None, description="The entry whose article shows this image; lets a visitor load it before it is cached"
    ),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Proxy and optionally resize an external image."""
    if not settings.get("image_proxy_enabled"):
        return Response(status_code=404)

    # Scheme here; the address check runs on every connection in _fetch_image.
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
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
                "Cache-Control": f"public, max-age={int(settings.get('image_proxy_cache_ttl_days') or 0) * 86400}",
                **_IMAGE_HEADERS,
            },
        )

    # A visitor may only make the server fetch an image that a stored article
    # actually shows; anything else would make this an anonymous download relay.
    if user.is_anonymous and not await _entry_shows_image(db, entry, url):
        return Response(status_code=404)

    referer = f"{parsed.scheme}://{parsed.netloc}/"

    max_bytes = int(settings.get("image_proxy_max_size_bytes") or settings.image_proxy_max_size_bytes)
    try:
        content, content_type = await _fetch_image(url, referer, max_bytes)
    except _FetchFailed as e:
        return Response(status_code=e.status)

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
            "Cache-Control": f"public, max-age={int(settings.get('image_proxy_cache_ttl_days') or 0) * 86400}",
            **_IMAGE_HEADERS,
        },
    )
