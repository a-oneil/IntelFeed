"""Small cross-cutting helpers shared across routers and services."""

from datetime import UTC, datetime


def now_iso() -> str:
    """Current UTC time as an ISO-8601 string (used for message timestamps)."""
    return datetime.now(UTC).isoformat()
