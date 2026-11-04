"""HTTP clients for URLs someone outside the server chose.

A feed URL, a link inside a feed, a podcast's transcript URL, a manual-ingest
URL, an image to proxy, a Mastodon instance: any of them can name, or redirect
to, the cloud metadata service, the api's own /metrics, Redis's neighbours on
the compose network, or a LAN admin page. ``outbound.outbound_problem`` checks a
URL before a call; this module enforces the same rule *at connect time*, for
every connection a client opens, including each redirect hop.

How: ``safe_async_client()`` is an ``httpx.AsyncClient`` whose transport's
network backend resolves the hostname itself, refuses unless every address it
maps to is allowed, and then connects to the vetted address. The URL, the Host
header and TLS (SNI and certificate checks against the hostname) are untouched,
so redirects and relative links behave as before, and a name that answers
differently a moment later (DNS rebinding) cannot move the connection.

``safe_curl_get()`` does the same for curl_cffi, which the feed worker and the
image proxy use to get past bot walls: redirects are followed one hop at a time
and each hop's connection is pinned with CURLOPT_RESOLVE.

Private ranges are refused unless ``outbound_allow_private_networks`` is on
(an install that reads feeds from its own LAN). Loopback, 0.0.0.0 and
link-local are refused regardless; see ``outbound.is_never_reachable``.
"""

from __future__ import annotations

import ipaddress
import typing
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

from app.core.outbound import Address, is_never_reachable, is_public, resolve_host

#: Redirect hops safe_curl_get follows, matching httpx's default.
MAX_REDIRECTS = 20


class OutboundBlocked(httpx.ConnectError):
    """The server refused to connect: the host is not somewhere it may call.

    A ConnectError, so existing ``except httpx.HTTPError`` / ``RequestError``
    handling treats it as the fetch failing, which is what it is.
    """


def _allow_private_default() -> bool:
    from app.config import settings

    return bool(settings.outbound_allow_private_networks)


def _refusal(host: str, addr: Address, allow_private: bool) -> str | None:
    if is_never_reachable(addr):
        return f"{host} points to a loopback or link-local address ({addr})"
    if not allow_private and not is_public(addr):
        return f"{host} points to a private address ({addr})"
    return None


async def vetted_address(host: str, *, allow_private: bool | None = None) -> Address:
    """The address to connect to for ``host``, or OutboundBlocked.

    Every address the name maps to must pass: a name that answers with one
    public and one private address is refused, because the HTTP stack may
    pick either.
    """
    if allow_private is None:
        allow_private = _allow_private_default()
    bare = host.strip("[]").rstrip(".")
    if not bare:
        raise OutboundBlocked("No hostname in URL")
    try:
        addresses: list[Address] = [ipaddress.ip_address(bare)]
    except ValueError:
        if bare.lower() in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
            raise OutboundBlocked(f"{host} is this host") from None
        addresses = await resolve_host(bare)
    if not addresses:
        raise OutboundBlocked(f"Could not resolve host {host}")
    for addr in addresses:
        problem = _refusal(host, addr, allow_private)
        if problem:
            raise OutboundBlocked(problem)
    return addresses[0]


class _PinningBackend(httpcore.AsyncNetworkBackend):
    """Resolves and vets in connect_tcp, then connects to the vetted address."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend, allow_private: bool | None):
        self._inner = inner
        self._allow_private = allow_private

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[typing.Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        addr = await vetted_address(host, allow_private=self._allow_private)
        return await self._inner.connect_tcp(
            str(addr), port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def connect_unix_socket(self, *args, **kwargs):  # pragma: no cover - never used for URLs
        raise OutboundBlocked("Unix sockets are not reachable from user-supplied URLs")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class SafeTransport(httpx.AsyncHTTPTransport):
    """An AsyncHTTPTransport whose every new connection goes to a vetted address."""

    def __init__(self, *, allow_private: bool | None = None, **kwargs):
        super().__init__(**kwargs)
        pool = self._pool
        pool._network_backend = _PinningBackend(pool._network_backend, allow_private)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.scheme not in ("http", "https"):
            raise OutboundBlocked(f"Unsupported URL scheme: {request.url.scheme}", request=request)
        try:
            return await super().handle_async_request(request)
        except OutboundBlocked as e:
            raise OutboundBlocked(str(e), request=request) from None


def safe_async_client(*, allow_private: bool | None = None, http2: bool = False, **kwargs) -> httpx.AsyncClient:
    """httpx.AsyncClient for a user-supplied URL. Same keyword arguments as
    AsyncClient (timeout, headers, follow_redirects, ...), minus transport.

    Environment proxies are not used: a proxy would make the connection, and
    the address check would be checking the proxy.
    """
    transport = SafeTransport(allow_private=allow_private, http2=http2)
    return httpx.AsyncClient(transport=transport, **kwargs)


async def safe_curl_get(url: str, *, allow_private: bool | None = None, **kwargs):
    """curl_cffi GET for a user-supplied URL, redirects re-vetted per hop.

    ``kwargs`` go to ``AsyncSession.get`` (impersonate, headers, timeout, ...);
    ``allow_redirects`` is handled here. Raises OutboundBlocked when any hop is
    refused. Returns the final curl_cffi response.
    """
    from curl_cffi import CurlOpt
    from curl_cffi import requests as cffi_requests

    follow = kwargs.pop("allow_redirects", True)
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        parts = urlsplit(current)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise OutboundBlocked(f"Unsupported URL: {current[:200]}")
        addr = await vetted_address(parts.hostname, allow_private=allow_private)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        pinned = f"[{addr}]" if addr.version == 6 else str(addr)
        resolve = [f"{parts.hostname}:{port}:{pinned}"]
        async with cffi_requests.AsyncSession(curl_options={CurlOpt.RESOLVE: resolve}) as session:
            response = await session.get(current, allow_redirects=False, **kwargs)
        location = response.headers.get("location")
        if not follow or response.status_code not in (301, 302, 303, 307, 308) or not location:
            return response
        current = urljoin(current, location)
    raise OutboundBlocked(f"Too many redirects fetching {url[:200]}")
