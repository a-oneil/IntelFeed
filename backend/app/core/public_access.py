"""The write lock for public read-only mode.

Routes a visitor may read take ``get_viewer`` (core/security.py). This
middleware is the second lock: a request with no bearer token may not
change anything, whatever the route behind it says — so a route switched to
``get_viewer`` by mistake, or a new unauthenticated one, still cannot write.

The only anonymous non-GET requests allowed are the ones that exist today
(login, register, refresh, logout, the share page's own calls) and a short
reviewed list of read-only POSTs the visitor UI needs: name lookups and
intel counts that are POSTs only because their id lists don't fit a query
string. Those are size-limited here and still gated by the switch in the
route's ``get_viewer``.
"""

import re
from contextlib import contextmanager
from contextvars import ContextVar
from urllib.parse import parse_qsl, urlencode

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Whether the request being served is a visitor's. Set by get_viewer /
# get_current_user (core/security.py) once the caller is known, reset here at
# the start of every request, and read by the data layer (services/public_view.py)
# to hide what a visitor must never see even in routes that never look at the
# user. Request-scoped: middleware runs the app in its own task, so a value set
# inside a request never outlives it.
_viewer_is_anonymous: ContextVar[bool] = ContextVar("viewer_is_anonymous", default=False)


def viewer_is_anonymous() -> bool:
    return _viewer_is_anonymous.get()


def set_viewer_anonymous(flag: bool) -> None:
    _viewer_is_anonymous.set(flag)


@contextmanager
def instance_view():
    """Lift the visitor filter for work that builds shared state.

    A visitor's request can trigger a rebuild of something every user shares
    (the autolinker vocabulary). Built under the visitor filter it would leave
    out hidden-feed entities for everyone; inside this block it sees the whole
    instance, and nothing built here may be returned to the visitor as is.
    """
    token = _viewer_is_anonymous.set(False)
    try:
        yield
    finally:
        _viewer_is_anonymous.reset(token)


# Anonymous non-GET routes that exist regardless of public mode.
ANONYMOUS_WRITE_PATHS = frozenset(
    {
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/refresh",
        "/api/auth/logout",
    }
)
_SHARED_POST = re.compile(r"^/api/shared/[^/]+/(ask-agent|run-ai-task|tts/prepare)$")

# Read-only POSTs the visitor UI uses. Each takes a list of ids or names and
# returns counts or matches — nothing is stored. Keep this list short, and
# add to it only after reading the route.
ANONYMOUS_READ_POSTS = frozenset(
    {
        "/api/entries/intel-counts",
        "/api/entries/resolve-names",
        "/api/intelligence/resolve-names",
        "/api/glossary/detect",
        # Entity links in an assessment's text: Aho-Corasick over the posted
        # text, CPU only (rate-limited as a heavy read in core/rate_limit.py).
        "/api/autolink/scan",
    }
)
# A visitor's read-only POST body: enough for a page of ids, not a document.
ANONYMOUS_READ_POST_MAX_BYTES = 16 * 1024

# Read-only POSTs with a path parameter, by route template, with their body
# cap. Relationship signals: the entity tables post every loaded row's id
# (up to 1000 UUIDs, ~40 KB) and get counts and top relationships back, the
# same relationships a visitor sees on a profile.
ANONYMOUS_READ_POST_TEMPLATES: dict[str, int] = {
    "/api/entity-relationships/signals/{entity_type}": 48 * 1024,
}
_READ_POST_PATTERNS = tuple(
    (re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", template) + "$"), limit)
    for template, limit in ANONYMOUS_READ_POST_TEMPLATES.items()
)


def read_post_limit(path: str) -> int | None:
    """The body cap of a reviewed read-only POST, or None if ``path`` isn't one."""
    if path in ANONYMOUS_READ_POSTS:
        return ANONYMOUS_READ_POST_MAX_BYTES
    return next((limit for pattern, limit in _READ_POST_PATTERNS if pattern.match(path)), None)


def bearer_credential(authorization: str | None) -> str | None:
    """The token in an ``Authorization`` header, parsed as FastAPI's HTTPBearer
    parses it: scheme in any case, credential stripped. None unless both are
    there, so ``Bearer`` with nothing after it is no token at all."""
    scheme, _, credential = (authorization or "").strip().partition(" ")
    credential = credential.strip()
    return credential if scheme.lower() == "bearer" and credential else None


def anonymous_write_allowed(method: str, path: str) -> bool:
    """Whether an anonymous ``method`` request to ``path`` may reach its route."""
    if method in SAFE_METHODS or not path.startswith("/api/"):
        return True
    if path in ANONYMOUS_WRITE_PATHS or read_post_limit(path) is not None:
        return True
    return bool(_SHARED_POST.match(path))


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": {"code": code, "message": message, "details": []}})


class AnonymousWriteLockMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        set_viewer_anonymous(False)
        if bearer_credential(request.headers.get("authorization")):
            # Signed in (or claiming to be): the route's own dependency judges
            # the token. Anything less than a parseable token is treated as
            # anonymous here, and get_viewer refuses a malformed header.
            return await call_next(request)
        method, path = request.method, request.url.path
        if not anonymous_write_allowed(method, path):
            return _error(401, "unauthorized", "Sign in to make changes")
        if method not in SAFE_METHODS and (limit := read_post_limit(path)) is not None:
            length = request.headers.get("content-length", "")
            if not length.isdigit() or int(length) > limit:
                return _error(413, "payload_too_large", "Request body too large")
        if method == "GET":
            _cap_page_size(request, path)
        response = await call_next(request)
        if _scrubbed_path(path) and response.headers.get("content-type", "").startswith("application/json"):
            from app.core.security import public_read_only_enabled

            if public_read_only_enabled():
                return await _scrubbed(response)
        return response


# Lists that carry article text (summaries, often the whole article for RSS)
# or bulk links: a visitor's page is at most what the app itself asks for, so
# the per-minute request budget also bounds how much one can pull.
_PAGE_CAPPED = (
    re.compile(r"^/api/entries$"),
    re.compile(r"^/api/entries/priority-queue$"),
    re.compile(r"^/api/feeds/[^/]+/entries$"),
    re.compile(r"^/api/glossary/[^/]+/entries$"),
    re.compile(r"^/api/entity-links$"),
)
VISITOR_PAGE_CAP = 50


def _cap_page_size(request: Request, path: str) -> None:
    """Clamp ``limit`` on a page-capped list for an anonymous caller, by
    rewriting the query string the route will parse."""
    if not any(p.match(path) for p in _PAGE_CAPPED):
        return
    params = parse_qsl(request.scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True)
    capped, changed = [], False
    for key, value in params:
        if key == "limit" and (not value.isdigit() or int(value) > VISITOR_PAGE_CAP):
            value, changed = str(VISITOR_PAGE_CAP), True
        capped.append((key, value))
    if changed:
        request.scope["query_string"] = urlencode(capped).encode("latin-1")


# Anonymous routes that have their own audience and must reach it unchanged.
_UNSCRUBBED_PREFIXES = ("/api/auth/", "/api/shared/", "/api/public/", "/api/taxii2", "/api/publish/", "/api/health")


def _scrubbed_path(path: str) -> bool:
    return path.startswith("/api/") and not path.startswith(_UNSCRUBBED_PREFIXES)


async def _scrubbed(response: Response) -> Response:
    """The visitor's copy of a JSON response (services/public_view.scrub_for_visitor)."""
    import json

    from app.services.public_view import scrub_for_visitor

    body = b"".join([chunk async for chunk in response.body_iterator])
    try:
        payload = json.loads(body)
    except ValueError:
        return Response(body, status_code=response.status_code, headers=dict(response.headers))
    headers = {k: v for k, v in response.headers.items() if k.lower() != "content-length"}
    return JSONResponse(scrub_for_visitor(payload), status_code=response.status_code, headers=headers)
