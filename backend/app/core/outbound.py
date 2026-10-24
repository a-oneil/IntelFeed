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
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

Address = ipaddress.IPv4Address | ipaddress.IPv6Address

_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}

#: A batch action validates the same webhook once per entry; resolving a name
#: it saw seconds ago again is wasted round-trips, not safety. Short enough
#: that a legitimately moved host is picked up within the minute. A name that
#: resolved to nothing is cached for the same minute: a personal key whose
#: host is down would otherwise cost a failed lookup on every call.
RESOLVE_CACHE_SECONDS = 60.0
#: Hostnames come from users (webhook URLs, personal keys), so the cache is
#: bounded: stale entries go on every miss, and past this many the oldest go.
RESOLVE_CACHE_MAX = 512
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


#: The AWS IPv6 instance-metadata endpoint. It sits in fc00::/7 (unique local),
#: so it is "private" rather than link-local and needs naming here.
_AWS_IMDS_V6 = ipaddress.IPv6Address("fd00:ec2::254")


def is_never_reachable(addr: Address) -> bool:
    """Addresses no switch opens: this host itself (loopback, 0.0.0.0) and the
    link-local block, which is where cloud metadata services answer
    (169.254.169.254 hands out instance credentials). A trusted-network setting
    exists for LAN services such as a homelab's Ollama or n8n box; none of
    them live here."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr == _AWS_IMDS_V6


async def resolve_host(hostname: str) -> list[Address]:
    """Every address ``hostname`` currently maps to. Empty when it resolves to nothing."""
    now = time.monotonic()
    cached = _resolved.get(hostname)
    if cached and now - cached[0] < RESOLVE_CACHE_SECONDS:
        return cached[1]
    _evict(now)
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        # No such name; or a label the IDNA codec refuses (over 63 chars),
        # which getaddrinfo raises as UnicodeError rather than gaierror. Either
        # way the name resolves to nothing the server may call.
        infos = []
    seen: dict[str, Address] = {}
    for _family, _type, _proto, _canon, sockaddr in infos:
        raw = sockaddr[0]
        if raw not in seen:
            seen[raw] = ipaddress.ip_address(raw)
    addresses = list(seen.values())
    _resolved[hostname] = (now, addresses)
    return addresses


def _evict(now: float) -> None:
    """Drop expired entries; past the size bound, drop the oldest as well."""
    for name in [name for name, (at, _) in _resolved.items() if now - at >= RESOLVE_CACHE_SECONDS]:
        del _resolved[name]
    if len(_resolved) >= RESOLVE_CACHE_MAX:
        for name in sorted(_resolved, key=lambda n: _resolved[n][0])[: len(_resolved) - RESOLVE_CACHE_MAX + 1]:
            del _resolved[name]


OutboundProblemCode = Literal["invalid", "scheme", "no_host", "private", "reserved", "unresolved"]


@dataclass(frozen=True, slots=True)
class OutboundProblem:
    """Why the server must not call a URL. ``code`` is what callers branch on
    ("private" is the one an operator's trusted-network switch would allow);
    ``message`` is what they show."""

    code: OutboundProblemCode
    message: str


async def outbound_problem(url: str, *, allow_private: bool = False) -> OutboundProblem | None:
    """Why the server must not call ``url``, or None when it may.

    ``allow_private`` is the operator's choice for a trusted network (a
    homelab pointing at its own Ollama box); it opens private ranges but not
    the scheme and hostname checks, and never the addresses
    ``is_never_reachable`` names (code "reserved").
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return OutboundProblem("invalid", "Invalid URL")
    if parsed.scheme not in ("http", "https"):
        return OutboundProblem("scheme", f"Unsupported URL scheme: {parsed.scheme or '(none)'}")
    hostname = parsed.hostname
    if not hostname:
        return OutboundProblem("no_host", "No hostname in URL")
    if hostname.lower().rstrip(".") in _LOCAL_NAMES:
        return OutboundProblem("reserved" if allow_private else "private", "URL points to localhost")
    if allow_private:
        try:
            addresses = [ipaddress.ip_address(hostname)]
        except ValueError:
            # Unresolvable stays the HTTP client's error to report, as it was
            # before this mode resolved anything.
            addresses = await resolve_host(hostname)
        for addr in addresses:
            if is_never_reachable(addr):
                return OutboundProblem("reserved", f"{hostname} points to a loopback or link-local address ({addr})")
        return None

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if not is_public(literal):
            return OutboundProblem("private", f"URL points to a private address ({hostname})")
        return None

    addresses = await resolve_host(hostname)
    if not addresses:
        return OutboundProblem("unresolved", f"Could not resolve host {hostname}")
    for addr in addresses:
        if not is_public(addr):
            return OutboundProblem("private", f"{hostname} resolves to a private address ({addr})")
    return None


async def check_outbound_url(url: str, *, allow_private: bool = False) -> str | None:
    """``outbound_problem`` as a sentence, for callers that only report it."""
    problem = await outbound_problem(url, allow_private=allow_private)
    return problem.message if problem else None
