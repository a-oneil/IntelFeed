"""The publisher IOC-file door: the indicator list a write-up links to.

Talos, Bitdefender Labs and Datadog Security Labs keep their authoritative
indicator lists in GitHub repositories and link them from the article ("IOCs
for this research can also be found at our GitHub repository"). Those files
are cleaner than the article body — Talos's ``.json`` is a STIX 2.0 bundle
whose MISP labels carry the role — and the body is where the *behavioural*
observables live. This door fetches the linked file, parses it with the
publisher's own format, and writes the atoms through ``get_or_create_observable``
with ``via="publisher_ioc"``, sighted on the **article's** entry so the
attribution and evidence story stays attached to the write-up.

It is a judgment door (a publisher curated the list), not regex over prose:
only allow-listed repositories are ever fetched, every value still passes
``validate_kind_value``, and files are capped in size and value count.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.observables import (
    classify_value,
    get_or_create_observable,
    is_defanged,
    record_sighting,
    validate_kind_value,
)

logger = logging.getLogger(__name__)

VIA_PUBLISHER = "publisher_ioc"
_FETCH_TIMEOUT = 20.0
_MAX_BYTES = 2 * 1024 * 1024
_CACHE_TTL = 24 * 3600
_USER_AGENT = "IntelFeed/1.0 (+observables publisher door)"


@dataclass
class PublisherIndicator:
    kind: str
    value: str
    role: str | None = None
    label: str | None = None
    was_defanged: bool = False


#: Allow-listed publisher repositories: (hostname, path-prefix regex, parser).
#: Anything else linked from an article is never fetched.
PUBLISHER_IOC_SOURCES: tuple[tuple[str, str, str], ...] = (
    ("github.com", r"^/Cisco-Talos/IOCs/blob/", "talos"),
    ("raw.githubusercontent.com", r"^/Cisco-Talos/IOCs/", "talos"),
    ("github.com", r"^/bitdefender/malware-ioc/blob/", "bitdefender_csv"),
    ("raw.githubusercontent.com", r"^/bitdefender/malware-ioc/", "bitdefender_csv"),
    ("github.com", r"^/DataDog/indicators-of-compromise/(?:blob|tree)/", "datadog_csv"),
    ("raw.githubusercontent.com", r"^/DataDog/indicators-of-compromise/", "datadog_csv"),
)

_HREF_RE = re.compile(r'href="(https?://[^"]+)"', re.IGNORECASE)

#: MISP category → ledger role (Talos STIX labels).
_MISP_ROLE = {
    "network activity": "c2",
    "payload delivery": "delivery",
    "payload installation": "payload",
    "artifacts dropped": "payload",
    "external analysis": None,
    "social engineering": "phishing",
}
_SECTION_ROLE = {
    "hash": "payload",
    "hashes": "payload",
    "sha256": "payload",
    "md5": "payload",
    "ip": "c2",
    "ips": "c2",
    "ip addresses": "c2",
    "domain": "c2",
    "domains": "c2",
    "url": "delivery",
    "urls": "delivery",
}
#: Role hints from a description cell (Bitdefender / Datadog CSVs).
_DESC_ROLE_HINTS = (
    ("c2", r"\b(c2|command[- ]and[- ]control|beacon|controller|dead[- ]drop)\b"),
    ("exfil", r"\b(exfil|exfiltration)\b"),
    ("phishing", r"\b(phish|lure|decoy)\b"),
    ("delivery", r"\b(deliver|delivery|staging|stager|download|dropper|loader|distribution|cdn)\b"),
    ("payload", r"\b(payload|backdoor|implant|agent|binary|sample|archive|dll|module|script|stealer|rat)\b"),
    ("scanning", r"\b(scan|scanner)\b"),
)


def _role_from_text(text: str | None) -> str | None:
    low = (text or "").lower()
    for role, pat in _DESC_ROLE_HINTS:
        if re.search(pat, low):
            return role
    return None


# ---------------------------------------------------------------------------
# Link detection
# ---------------------------------------------------------------------------


def publisher_ioc_links(content_html: str | None) -> list[tuple[str, str]]:
    """``(url, parser)`` for every allow-listed publisher IOC file the article links to."""
    if not content_html:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in _HREF_RE.finditer(content_html):
        url = m.group(1).strip()
        try:
            host, path = re.match(r"https?://([^/]+)(/.*)?$", url).groups()  # type: ignore[union-attr]
        except AttributeError:
            continue
        path = path or "/"
        for src_host, prefix_re, parser in PUBLISHER_IOC_SOURCES:
            if host.lower() == src_host and re.match(prefix_re, path):
                clean = url.split("#", 1)[0]
                if clean not in seen:
                    seen.add(clean)
                    out.append((clean, parser))
                break
    return out


def raw_urls_for(url: str, parser: str) -> list[str]:
    """Raw-content URLs to fetch for a linked page. A Talos ``.txt`` link also
    yields its sibling ``.json`` (the STIX bundle carries roles)."""
    raw = url
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/(?:blob|tree)/([^/]+)/(.+)$", url)
    if m:
        owner, repo, ref, path = m.groups()
        raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    urls = [raw]
    if parser == "talos":
        if raw.endswith(".txt"):
            urls.insert(0, raw[: -len(".txt")] + ".json")
        elif raw.endswith(".json"):
            urls.append(raw[: -len(".json")] + ".txt")
    return urls


# ---------------------------------------------------------------------------
# Parsers (pure functions over file text)
# ---------------------------------------------------------------------------


def parse_talos_txt(text: str) -> list[PublisherIndicator]:
    """Talos ``.txt``: section headings (``Hashes``, ``IP Addresses``,
    ``Domains``, ``URLs``) then one value per line."""
    out: list[PublisherIndicator] = []
    role: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip().strip("-=*#:").strip()
        if not line:
            continue
        key = line.lower().rstrip("s") if line.lower().endswith("es") is False else line.lower()
        if line.lower() in _SECTION_ROLE or key in _SECTION_ROLE:
            role = _SECTION_ROLE.get(line.lower()) or _SECTION_ROLE.get(key)
            continue
        if line.lower().startswith(("sha256", "md5", "sha1", "ip address", "domain", "url")) and len(line) < 24:
            role = _SECTION_ROLE.get(line.lower().rstrip(":"), role)
            continue
        token = line.split()[0]
        classified = classify_value(token)
        if classified:
            label = line[len(token) :].strip(" ()-–—") or None
            out.append(
                PublisherIndicator(
                    classified[0], classified[1], role or _role_from_text(label), label, is_defanged(token)
                )
            )
    return out


_STIX_PATTERN_RE = re.compile(r"\[([a-z0-9_.:'-]+)\s*=\s*'([^']+)'\]", re.IGNORECASE)
_STIX_KIND = {
    "file:hashes.'sha-256'": "sha256",
    "file:hashes.sha-256": "sha256",
    "file:hashes.'md5'": "md5",
    "file:hashes.md5": "md5",
    "file:hashes.'sha-1'": "sha1",
    "file:hashes.sha-1": "sha1",
    "ipv4-addr:value": "ipv4",
    "ipv6-addr:value": "ipv6",
    "domain-name:value": "domain",
    "url:value": "url",
    "email-addr:value": "email",
}


def parse_stix_bundle(text: str) -> list[PublisherIndicator]:
    """STIX 2.x indicator bundle (Talos ``.json``) — pattern + MISP labels."""
    try:
        bundle = json.loads(text)
    except json.JSONDecodeError:
        return []
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        return []
    out: list[PublisherIndicator] = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern") or ""
        m = _STIX_PATTERN_RE.search(pattern)
        if not m:
            continue
        kind = _STIX_KIND.get(m.group(1).lower())
        value = m.group(2)
        if kind is None:
            classified = classify_value(value)
            if not classified:
                continue
            kind, value = classified
        role = None
        for label in obj.get("labels") or []:
            if isinstance(label, str) and label.lower().startswith("misp:category="):
                role = _MISP_ROLE.get(label.split("=", 1)[1].strip('"').lower())
        if kind in ("md5", "sha1", "sha256") and role in (None, "delivery"):
            # "Payload delivery" on a file hash names the file delivered — the
            # payload — while on a URL/domain/IP it names the delivery channel.
            role = "payload"
        out.append(PublisherIndicator(kind, value, role, (obj.get("name") or None)))
    return out


def parse_bitdefender_csv(text: str) -> list[PublisherIndicator]:
    """``indicator_type,data,additional_data,description``; ``source`` and
    ``threat_id`` rows are metadata, not indicators."""
    out: list[PublisherIndicator] = []
    for row in csv.DictReader(io.StringIO(text)):
        itype = (row.get("indicator_type") or "").strip().lower()
        data = (row.get("data") or "").strip()
        if not data or itype in ("source", "threat_id", "threat", "campaign", ""):
            continue
        classified = classify_value(data)
        if not classified:
            continue
        desc = (row.get("description") or row.get("additional_data") or "").strip() or None
        role = _role_from_text(desc) or ("payload" if classified[0] in ("md5", "sha1", "sha256") else None)
        out.append(PublisherIndicator(classified[0], classified[1], role, desc, is_defanged(data)))
    return out


def parse_generic_csv(text: str) -> list[PublisherIndicator]:
    """Datadog-style per-campaign CSVs with varying headers: the first cell
    that classifies as an atom is the value; a context/description/type cell
    gives the role. Package/version inventories (``pypi package`` rows) are
    not atoms and are skipped."""
    out: list[PublisherIndicator] = []
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return out
    fields = [f.strip().lower() for f in reader.fieldnames]
    value_cols = [
        f for f in fields if f in ("indicator", "ioc", "value", "data", "domain", "url", "ip", "hash", "sha256", "name")
    ]
    desc_cols = [
        f for f in fields if f in ("context", "description", "notes", "comment", "type", "artifact_type", "role")
    ]
    for raw in reader:
        row = {k.strip().lower(): (v or "").strip() for k, v in raw.items() if k}
        atype = (row.get("artifact_type") or row.get("type") or "").lower()
        if any(t in atype for t in ("package", "docker image", "github action", "extension")):
            continue
        classified = None
        for col in value_cols or fields:
            classified = classify_value(row.get(col, ""))
            if classified:
                break
        if not classified:
            continue
        desc = " ".join(row.get(c, "") for c in desc_cols).strip() or None
        role = _role_from_text(desc) or ("payload" if classified[0] in ("md5", "sha1", "sha256") else None)
        out.append(PublisherIndicator(classified[0], classified[1], role, desc, False))
    return out


def parse_publisher_file(parser: str, url: str, text: str) -> list[PublisherIndicator]:
    if parser == "talos":
        return parse_stix_bundle(text) if url.endswith(".json") else parse_talos_txt(text)
    if parser == "bitdefender_csv":
        return parse_bitdefender_csv(text)
    if parser == "datadog_csv":
        return parse_generic_csv(text) if url.endswith(".csv") else []
    return []


# ---------------------------------------------------------------------------
# Fetch + store
# ---------------------------------------------------------------------------


async def fetch_publisher_file(url: str) -> str | None:
    """Raw file text, Redis-cached for a day; None on any failure or oversize."""
    cache_key = f"intelfeed:publisher_ioc:{url}"
    try:
        from app.services.redis_client import get_redis

        redis = await get_redis()
        cached = await redis.get(cache_key)
        if cached is not None:
            return cached
    except Exception:
        redis = None
    try:
        async with httpx.AsyncClient(
            timeout=_FETCH_TIMEOUT, headers={"User-Agent": _USER_AGENT}, follow_redirects=True
        ) as client:
            resp = await client.get(url)
        if resp.status_code != 200 or len(resp.content) > _MAX_BYTES:
            return None
        text = resp.text
    except Exception:
        logger.info("publisher IOC fetch failed for %s", url, exc_info=True)
        return None
    if redis is not None:
        try:
            await redis.setex(cache_key, _CACHE_TTL, text)
        except Exception:
            pass
    return text


async def store_publisher_observables(
    db: AsyncSession,
    entry,
    *,
    max_values: int = 2000,
    fetcher=fetch_publisher_file,
    seen_at: datetime | None = None,
) -> int:
    """The publisher door for one article: fetch each allow-listed IOC file it
    links, parse, and write the atoms sighted on the article. Returns rows
    sighted. ``fetcher`` is injectable for tests."""
    links = publisher_ioc_links(getattr(entry, "content_html", None))
    if not links:
        return 0
    stored = 0
    seen: set[tuple[str, str]] = set()
    for url, parser in links:
        indicators: list[PublisherIndicator] = []
        for raw_url in raw_urls_for(url, parser):
            text = await fetcher(raw_url)
            if text:
                indicators = parse_publisher_file(parser, raw_url, text)
                if indicators:
                    break
        for ind in indicators[:max_values]:
            canonical = validate_kind_value(ind.kind, ind.value)
            if canonical is None or (ind.kind, canonical) in seen:
                continue
            seen.add((ind.kind, canonical))
            obs = await get_or_create_observable(
                db,
                ind.kind,
                canonical,
                via=VIA_PUBLISHER,
                entry_id=entry.id,
                role=ind.role,
                label=(ind.label or None) and ind.label[:200],
                evidence=f"Listed in the article's IOC table: {url}",
                was_defanged=ind.was_defanged,
            )
            if obs is None:
                continue
            await record_sighting(
                db,
                entry.id,
                obs,
                source="publisher",
                surface_form=ind.value,
                was_defanged=ind.was_defanged,
                seen_at=seen_at or getattr(entry, "published_at", None),
            )
            stored += 1
    return stored
