"""Prometheus metrics for IntelFeed.

All metrics are defined here as module-level singletons.
Import the specific metric you need from this module.
"""

import time

from prometheus_client import Counter, Gauge, Histogram
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

# --- HTTP metrics ---

HTTP_REQUESTS_TOTAL = Counter(
    "intelfeed_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "intelfeed_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# --- Feed metrics ---

FEEDS_ACTIVE = Gauge(
    "intelfeed_feeds_active",
    "Number of active feeds",
)

FEED_FETCH_TOTAL = Counter(
    "intelfeed_feed_fetch_total",
    "Total feed fetches",
    ["status"],  # success, error, not_modified, rate_limited
)

FEED_FETCH_DURATION_SECONDS = Histogram(
    "intelfeed_feed_fetch_duration_seconds",
    "Feed fetch latency in seconds",
    ["feed_type"],
    buckets=(0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)

ENTRIES_INGESTED_TOTAL = Counter(
    "intelfeed_entries_ingested_total",
    "Total entries ingested",
    ["feed_type"],
)

# --- AI metrics ---

AI_REQUESTS_TOTAL = Counter(
    "intelfeed_ai_requests_total",
    "Total AI API calls",
    ["provider", "task"],
)

AI_TOKENS_TOTAL = Counter(
    "intelfeed_ai_tokens_total",
    "Total AI tokens used",
    ["provider", "direction"],  # direction: input, output
)

AI_COST_TOTAL = Counter(
    "intelfeed_ai_cost_total",
    "Estimated AI cost in USD",
    ["provider"],
)

AI_REQUEST_DURATION_SECONDS = Histogram(
    "intelfeed_ai_request_duration_seconds",
    "AI request latency in seconds",
    ["provider", "task"],
    buckets=(0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0),
)

# --- Signal engine metrics ---

SIGNAL_PROBE_FAILURES_TOTAL = Counter(
    "intelfeed_signal_probe_failures_total",
    "Signal probes that raised during entry scoring (signal omitted from score)",
    ["probe"],
)

ENTRY_SIGNALS_FIRED_TOTAL = Counter(
    "intelfeed_entry_signals_fired_total",
    "Signals fired during entry scoring, by type",
    ["signal_type"],
)

# --- Automation metrics ---

AUTOMATION_RUNS_TOTAL = Counter(
    "intelfeed_automation_runs_total",
    "Total automation rule executions",
    ["trigger_type", "status"],  # status: success, error, skipped
)

CORRELATION_EVENTS_TOTAL = Counter(
    "intelfeed_correlation_events_total",
    "Total correlation events detected",
    ["event_type"],
)

# --- Search metrics ---

SEARCH_QUERIES_TOTAL = Counter(
    "intelfeed_search_queries_total",
    "Total search queries",
)

# --- Celery task metrics ---

CELERY_TASKS_TOTAL = Counter(
    "intelfeed_celery_tasks_total",
    "Total Celery tasks executed",
    ["task_name", "status"],  # status: success, error, retry
)

CELERY_TASK_DURATION_SECONDS = Histogram(
    "intelfeed_celery_task_duration_seconds",
    "Celery task execution duration in seconds",
    ["task_name"],
    buckets=(0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0),
)

# --- Maintenance metrics ---

ENTRIES_CLEANED_TOTAL = Counter(
    "intelfeed_entries_cleaned_total",
    "Total expired entries cleaned up",
)

IMAGES_EVICTED_TOTAL = Counter(
    "intelfeed_images_evicted_total",
    "Total cached images evicted",
)

TELEGRAM_MEDIA_EVICTED_TOTAL = Counter(
    "intelfeed_telegram_media_evicted_total",
    "Total Telegram media files evicted past TTL",
)

# Paths to skip in HTTP metrics (high-cardinality or noisy)
_SKIP_PATHS = {"/api/health", "/metrics"}


def _normalize_path(path: str) -> str:
    """Normalize path for metric labels to avoid high cardinality.

    Replaces UUID-like segments with {id}.
    """
    parts = path.rstrip("/").split("/")
    normalized = []
    for part in parts:
        # UUID pattern: 8-4-4-4-12 hex chars or 32 hex chars
        if len(part) == 36 and part.count("-") == 4:
            normalized.append("{id}")
        elif len(part) == 32 and all(c in "0123456789abcdef" for c in part.lower()):
            normalized.append("{id}")
        else:
            normalized.append(part)
    return "/".join(normalized)


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Record HTTP request metrics for Prometheus."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        if path in _SKIP_PATHS:
            return await call_next(request)

        method = request.method
        normalized = _normalize_path(path)
        start = time.monotonic()

        response = await call_next(request)

        duration = time.monotonic() - start
        status = str(response.status_code)

        HTTP_REQUESTS_TOTAL.labels(method=method, path=normalized, status=status).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(method=method, path=normalized).observe(duration)

        return response
