"""Is this somewhere the server may call?

Anything that makes the API server fetch a URL a user typed — a webhook, a
personal AI provider's base URL — is a server-side request forgery waiting
for a hostname that resolves to the LAN. Checking the literal address is
not enough: ``evil.example`` can point at 10.0.0.5. The check here resolves
the name and refuses if any address it maps to is not public.

Resolve again on every call, not just when the URL is saved: DNS answers
change, and that is the whole trick. What this does not close is a name
that answers differently to the check and to the HTTP client moments
later (a zero-TTL rebinding attack). Closing that means connecting to the
vetted address, which the provider SDKs the base URLs feed don't allow,
so the operator's private-network switch and the audit trail are the
backstop.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from urllib.parse import urlparse

Address = ipaddress.IPv4Address | ipaddress.IPv6Address

_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}

#: A batch action validates the same webhook once per entry; resolving a name
#: it saw seconds ago again is wasted round-trips, not safety. Short enough
#: that a legitimately moved host is picked up within the minute.
RESOLVE_CACHE_SECONDS = 60.0
_resolved: dict[str, tuple[float, list[Address]]] = {}


def is_public(addr: Address) -> bool:
    """False for every range the server must not be pointed at.

    ``is_global`` carries the IANA special-purpose registry, which covers
    the private ranges and also shared address space (100.64.0.0/10 —
    CGNAT, Tailscale, most overlay networks) that ``is_private`` does not.
    Multicast is "global" by that registry and is still not a host.
    """
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


async def resolve_host(hostname: str) -> list[Address]:
    """Every address ``hostname`` currently maps to. Empty when it resolves to nothing."""
    now = time.monotonic()
    cached = _resolved.get(hostname)
    if cached and now - cached[0] < RESOLVE_CACHE_SECONDS:
        return cached[1]
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    seen: dict[str, Address] = {}
    for _family, _type, _proto, _canon, sockaddr in infos:
        raw = sockaddr[0]
        if raw not in seen:
            seen[raw] = ipaddress.ip_address(raw)
    addresses = list(seen.values())
    if addresses:
        _resolved[hostname] = (now, addresses)
    return addresses


async def check_outbound_url(url: str, *, allow_private: bool = False) -> str | None:
    """Why the server must not call ``url``, or None when it may.

    ``allow_private`` is the operator's choice for a trusted network (a
    homelab pointing at its own Ollama box); it skips the address check but
    not the scheme and hostname checks.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return "Invalid URL"
    if parsed.scheme not in ("http", "https"):
        return f"Unsupported URL scheme: {parsed.scheme or '(none)'}"
    hostname = parsed.hostname
    if not hostname:
        return "No hostname in URL"
    if allow_private:
        return None
    if hostname.lower().rstrip(".") in _LOCAL_NAMES:
        return "URL points to localhost"

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if not is_public(literal):
            return f"URL points to a private address ({hostname})"
        return None

    addresses = await resolve_host(hostname)
    if not addresses:
        return f"Could not resolve host {hostname}"
    for addr in addresses:
        if not is_public(addr):
            return f"{hostname} resolves to a private address ({addr})"
    return None
