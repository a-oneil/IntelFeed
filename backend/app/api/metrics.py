"""Prometheus metrics endpoint."""

import ipaddress
import logging

from fastapi import APIRouter, Request
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

router = APIRouter()
logger = logging.getLogger(__name__)

# Default allowed networks for metrics scraping (loopback + RFC 1918)
_ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_allowed(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _ALLOWED_NETWORKS)
    except ValueError:
        return False


@router.get("/metrics")
async def metrics(request: Request):
    """Expose Prometheus metrics for scraping."""
    # The direct peer only: X-Real-IP is whatever the caller sent unless a proxy
    # overwrote it, so it can't vouch for anyone. Scrapers reach api:8000 from
    # inside the compose network; nginx never proxies /metrics.
    client_ip = request.client.host if request.client else None
    if not client_ip or not _is_allowed(client_ip):
        logger.warning("Metrics access denied from %s", client_ip)
        return Response(status_code=403, content="Forbidden")
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
