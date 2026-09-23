import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

LOG_DIR = os.environ.get("LOG_DIR", "logs")

# 10 MB per file, keep 5 rotated backups
MAX_BYTES = 10 * 1024 * 1024
BACKUP_COUNT = 5


# Processors applied to non-structlog (foreign) log records so they get
# timestamps, levels, and logger names just like structlog-originated records.
_FOREIGN_PRE_CHAIN: list[structlog.types.Processor] = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.UnicodeDecoder(),
]


def _json_formatter() -> structlog.stdlib.ProcessorFormatter:
    """Structlog formatter that outputs JSON lines (used for all file handlers)."""
    return structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=_FOREIGN_PRE_CHAIN,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
    )


def _make_file_handler(filename: str, level: int = logging.INFO) -> RotatingFileHandler:
    """Create a rotating file handler writing JSON to LOG_DIR/filename."""
    path = os.path.join(LOG_DIR, filename)
    handler = RotatingFileHandler(path, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT)
    handler.setFormatter(_json_formatter())
    handler.setLevel(level)
    return handler


class _TaskLogFilter(logging.Filter):
    """Accept only records from celery and app.workers loggers."""

    def filter(self, record: logging.LogRecord) -> bool:
        return record.name.startswith(("celery", "app.workers"))


class _NotTaskLogFilter(logging.Filter):
    """Exclude celery/worker records — they belong to tasks.log, and keeping
    them out of app.log makes 'Application' vs 'Tasks' a real distinction."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not record.name.startswith(("celery", "app.workers"))


_logging_configured = False


def setup_logging() -> None:
    """Configure structlog with console + file handlers.

    File layout under LOG_DIR:
        app.log    — all INFO+ logs (catch-all)
        error.log  — ERROR+ only
        http.log   — HTTP request logs (app.request logger)
        tasks.log  — Celery worker/beat logs (app.workers.* and celery.* loggers)
        audit.log  — Mutating API action audit trail (app.audit logger)
    """
    global _logging_configured
    if _logging_configured:
        return
    _logging_configured = True

    is_prod = os.getenv("ENV", "development") == "production"

    # --- structlog pipeline ---------------------------------------------------
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if is_prod:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    console_formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=_FOREIGN_PRE_CHAIN,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    # --- stdlib root logger ---------------------------------------------------
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(console_handler)
    root.setLevel(logging.INFO)

    # --- file handlers (skip if dir can't be created — e.g. in tests) ---------
    try:
        os.makedirs(LOG_DIR, exist_ok=True)

        # Application log — everything except celery/worker records (those go
        # to tasks.log below; error.log still catches errors from both).
        app_handler = _make_file_handler("app.log")
        app_handler.addFilter(_NotTaskLogFilter())
        root.addHandler(app_handler)

        # Errors only
        root.addHandler(_make_file_handler("error.log", level=logging.ERROR))

        # HTTP request log — handler on the named logger; propagation still
        # sends records to root (→ app.log) as well.
        http_logger = logging.getLogger("app.request")
        http_logger.addHandler(_make_file_handler("http.log"))

        # Celery / worker task log — uses a filter on root so records from
        # celery.* and app.workers.* loggers go to tasks.log regardless of
        # whether Celery clears named-logger handlers during its own setup.
        task_handler = _make_file_handler("tasks.log")
        task_handler.addFilter(_TaskLogFilter())
        root.addHandler(task_handler)

        # Audit log
        audit_logger = logging.getLogger("app.audit")
        audit_logger.addHandler(_make_file_handler("audit.log"))

    except OSError:
        # Running in an environment where we can't write logs (CI, tests, etc.)
        pass

    # Quiet noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    # Dev-reload file watcher: logs "N changes detected" for every file event
    # (including log writes) — pure noise below WARNING.
    logging.getLogger("watchfiles").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every HTTP request with method, path, status, and duration."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in {"/api/health", "/metrics"} or request.url.path.startswith("/api/logs"):
            return await call_next(request)

        logger = structlog.get_logger("app.request")
        start = time.monotonic()

        response = await call_next(request)

        duration_ms = round((time.monotonic() - start) * 1000, 1)
        logger.info(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=duration_ms,
            client=request.client.host if request.client else None,
        )

        return response


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """Log all mutating API requests to the audit log.

    Captures method, path, response status, client IP, and (if available)
    the user ID from the JWT bearer token.
    """

    SKIP_PATHS = {"/api/health", "/metrics"}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        if request.url.path in self.SKIP_PATHS:
            return await call_next(request)

        response = await call_next(request)

        user_info = self._extract_user(request)
        logger = structlog.get_logger("app.audit")
        logger.info(
            "audit",
            action=request.method,
            path=request.url.path,
            status=response.status_code,
            user=user_info.get("username") or user_info.get("sub"),
            client=request.client.host if request.client else None,
        )

        return response

    @staticmethod
    def _extract_user(request: Request) -> dict:
        """Best-effort JWT decode to get user info."""
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return {}
        try:
            from jose import jwt as jose_jwt

            from app.config import settings

            return jose_jwt.decode(auth[7:], settings.secret_key, algorithms=["HS256"])
        except Exception:
            return {}
