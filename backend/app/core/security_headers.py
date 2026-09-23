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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        headers = DOCS_SECURITY_HEADERS if request.url.path in _DOCS_PATHS else SECURITY_HEADERS
        for header, value in headers.items():
            response.headers.setdefault(header, value)
        return response
