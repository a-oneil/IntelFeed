import logging
from urllib.parse import quote, unquote, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# In-memory cache of parsed robots.txt files: domain -> (parser, expiry_timestamp)
_cache: dict[str, tuple[RobotFileParser, float]] = {}
_CACHE_TTL = 3600  # 1 hour


def _select_entry(parser: RobotFileParser, useragent: str):
    """Pick the robots.txt group that governs ``useragent``.

    This does its own user-agent matching rather than calling
    ``Entry.applies_to``, because where the catch-all ``*`` group lives, and
    whether it matches at all, changed in Python 3.13:

    ======================  ===================  =======================
    .                       3.12                 3.13+
    ======================  ===================  =======================
    catch-all ``*`` group   ``default_entry``    inside ``entries``
    ``applies_to(real UA)``  True                False (``*`` only
    on a ``*`` group                              matches ``useragent=None``)
    ======================  ===================  =======================

    So on 3.13+ the old ``applies_to`` scan matched nothing, ``default_entry``
    was ``None``, and every site's Disallow rules were silently ignored —
    ``can_fetch`` failed open. Matching on ``entry.useragents`` directly
    behaves identically on every version.

    A group naming our agent wins over the catch-all (RFC 9309 §2.2.1).
    """
    # Same token rule the stdlib uses: compare against the product token only.
    token = useragent.split("/")[0].lower()
    catch_all = parser.default_entry  # 3.12 keeps the '*' group here
    for entry in parser.entries:
        for agent in entry.useragents:
            if agent == "*":
                if catch_all is None:  # 3.13+ keeps it here instead
                    catch_all = entry
            elif agent.lower() in token:
                return entry
    return catch_all


def _rule_allows(parser: RobotFileParser, useragent: str, url: str) -> bool:
    """Evaluate robots.txt rules with most-specific-match precedence.

    ``RobotFileParser.can_fetch`` returns the *first* matching rule, so a file
    written as ``Allow: /`` followed by ``Disallow: /admin/`` — an extremely
    common shape — reads as "everything is permitted" and we would happily
    crawl the disallowed paths. RFC 9309 §2.2.2 says the longest matching path
    wins, with ties going to Allow, which is what this implements.
    """
    if parser.disallow_all:
        return False
    if parser.allow_all:
        return True

    entry = _select_entry(parser, useragent)
    if entry is None:
        return True

    parsed = urlparse(unquote(url))
    path = urlunparse(("", "", parsed.path, parsed.params, parsed.query, "")) or "/"
    path = quote(path)

    best_length = -1
    best_allowance = True
    for line in entry.rulelines:
        if not line.applies_to(path):
            continue
        length = 0 if line.path == "*" else len(line.path)
        # On a tie the permissive rule wins, per the RFC.
        if length > best_length or (length == best_length and line.allowance):
            best_length = length
            best_allowance = line.allowance

    return best_allowance


async def can_fetch(url: str) -> bool:
    """Check if robots.txt allows fetching the given URL.

    Returns True if allowed or if robots.txt cannot be fetched.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    robots_url = f"{parsed.scheme}://{domain}/robots.txt"

    # Check cache
    import time

    if domain in _cache:
        parser, expiry = _cache[domain]
        if time.time() < expiry:
            return _rule_allows(parser, str(settings.get("user_agent") or settings.user_agent), url)

    # Fetch robots.txt
    parser = RobotFileParser()
    try:
        user_agent = str(settings.get("user_agent") or settings.user_agent)
        async with httpx.AsyncClient(timeout=10.0, headers={"User-Agent": user_agent}) as client:
            response = await client.get(robots_url)
            if response.status_code == 200:
                parser.parse(response.text.splitlines())
            else:
                # If robots.txt doesn't exist or errors, allow all
                parser.allow_all = True
    except httpx.HTTPError:
        # If we can't fetch robots.txt, default to allowing
        parser.allow_all = True

    _cache[domain] = (parser, time.time() + _CACHE_TTL)
    return _rule_allows(parser, str(settings.get("user_agent") or settings.user_agent), url)


async def get_crawl_delay(url: str) -> float | None:
    """Get the Crawl-delay directive for our user agent, if any."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Ensure robots.txt is cached
    await can_fetch(url)

    if domain in _cache:
        parser, _ = _cache[domain]
        delay = parser.crawl_delay(str(settings.get("user_agent") or settings.user_agent))
        if delay is not None:
            return float(delay)

    return None
