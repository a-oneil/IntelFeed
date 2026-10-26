from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    # A self-hosted intel console is never something to index, and with public
    # read-only mode on, a crawler could otherwise walk every article.
    "X-Robots-Tag": "noindex, nofollow",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob: https:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "media-src 'self' https:; "
        "worker-src 'self' blob:; "
        "frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com; "
        "frame-ancestors 'none'; "
        "upgrade-insecure-requests"
    ),
}

# Relaxed CSP for Swagger UI docs (loads JS/CSS from CDN)
_SWAGGER_CDN = "https://cdn.jsdelivr.net https://unpkg.com"
DOCS_SECURITY_HEADERS = {
    **SECURITY_HEADERS,
    "Content-Security-Policy": (
        "default-src 'self'; "
        f"script-src 'self' 'unsafe-inline' {_SWAGGER_CDN}; "
        f"style-src 'self' 'unsafe-inline' {_SWAGGER_CDN}; "
        f"img-src 'self' data: blob: https:; "
        f"connect-src 'self' {_SWAGGER_CDN}; "
        "font-src 'self'; "
        "media-src 'self' https:; "
        "frame-ancestors 'none'"
    ),
}

_DOCS_PATHS = {"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}

# API responses differ per caller (a visitor's feed list is not an admin's),
# so no shared cache — Cloudflare, a corporate proxy — may ever serve one
# person's response to another. Routes that serve the same bytes to everyone
# (the image proxy, audio files) set their own Cache-Control and keep it.
API_CACHE_CONTROL = "private, no-store"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        path = request.url.path
        headers = DOCS_SECURITY_HEADERS if path in _DOCS_PATHS else SECURITY_HEADERS
        for header, value in headers.items():
            response.headers.setdefault(header, value)
        if path.startswith("/api/") or path == "/openapi.json":
            response.headers.setdefault("Cache-Control", API_CACHE_CONTROL)
        return response
