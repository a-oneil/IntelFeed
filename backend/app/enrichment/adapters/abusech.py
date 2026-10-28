"""abuse.ch: ThreatFox, URLhaus and MalwareBazaar, on one free Auth-Key.

abuse.ch requires an Auth-Key (https://auth.abuse.ch/) for every API call and
every export: an API call sends it in the ``Auth-Key`` header, an export
carries it in its URL path. The three sources share one key (``shared_key_group
= "abuse_ch"``): a key saved on any of them serves all three, and their
requests draw on one gateway bucket for it. Without a key their gateway sends
nothing (``NeedsKey``), and the Enrichment console shows them as needing one.

Two ways in:

- **Exports, matched here** (send nothing about the ledger). ThreatFox's full
  export (every IOC not yet expired; IOCs expire after six months, generated
  hourly: https://threatfox.abuse.ch/export/) and URLhaus's full dump (URLs
  online now or added in the past 90 days, generated every 5 minutes:
  https://urlhaus.abuse.ch/api/) are downloaded as zipped CSV, streamed to a
  temporary file and read a line at a time, and matched exactly against the
  ledger's ``(kind, value)``: ThreatFox IOCs by their own kind (an ``ip:port``
  by its IP), URLhaus URLs as URLs and by their host as a domain or IP. Only
  active observables (the sources' ``scope``) are written; an observable that
  had an answer and has left the export is withdrawn: its context and claims go.
- **Lookups** (``search_ioc``, URLhaus ``url``/``host``, Bazaar ``get_info``)
  send the observable to abuse.ch, so they are ``Egress.SHARES_IOC`` and run
  only when someone asks (``default_trigger_mode = "manual"``). MalwareBazaar
  is lookup-only: its only export small enough to fetch is the last 48 hours
  of samples (https://bazaar.abuse.ch/export/), and the hashes write-ups name
  are mostly older than that.

What an answer writes: a ``role`` the observable has none of (ThreatFox
``botnet_cc`` → ``c2``, ``payload_delivery`` → ``delivery``, ``payload`` →
``payload``; a URLhaus URL → ``delivery``; a Bazaar sample → ``payload``), the
malware families behind it as claims (``app/enrichment/relations.py``: only
families IntelFeed already tracks are linked, the connection is the family's —
``malware communicates_with`` a C2, ``malware uses`` the rest), and profile
context.

Terms (https://abuse.ch/terms-of-use/): free to authenticated users for
not-for-profit purposes, within "volumes reasonably expected for non-commercial
or non-profit purposes"; commercial use may need a Spamhaus subscription. No
numeric query limit is published; exports ask not to be fetched more often
than they are generated (hourly for full dumps).
"""

from __future__ import annotations

import csv
import io
import ipaddress
import logging
import tempfile
import uuid
import zipfile
from collections.abc import Iterator
from urllib.parse import quote, urlsplit

from sqlalchemy import select, union
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.gateway import SOURCE_REFUSALS, NeedsKey, SourceGateway
from app.enrichment.manifest import Column, Context, Display, Egress, Job, License, Quota, Relation

logger = logging.getLogger(__name__)

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"
BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
#: The key is part of an export's path, so its URL is never logged or raised.
THREATFOX_EXPORT = "https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip"
URLHAUS_EXPORT = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/full.csv.zip"

#: Lookup answers stay fresh this long.
LOOKUP_TTL_HOURS = 72
#: Export rows matched against the ledger per query.
CHUNK = 5000
#: Observables applied per commit.
BATCH = 50

#: ThreatFox threat_type → the ledger's role vocabulary (``NETWORK_ROLES``).
THREATFOX_ROLES = {"botnet_cc": "c2", "payload_delivery": "delivery", "payload": "payload"}
_THREAT_LABELS = {"botnet_cc": "botnet C2", "payload_delivery": "payload delivery", "payload": "payload"}
#: ThreatFox ioc_type → the ledger's kind.
_THREATFOX_KINDS = {
    "ip:port": "ipv4",
    "domain": "domain",
    "url": "url",
    "md5_hash": "md5",
    "sha1_hash": "sha1",
    "sha256_hash": "sha256",
}
_DELIVERY = {
    "email_attachment": "e-mail attachment",
    "email_link": "e-mail link",
    "web_download": "web download",
    "web_drive-by": "drive-by",
    "multiple": "multiple",
    "other": "other",
}
_BLACKLISTS = {"spamhaus_dbl": "Spamhaus DBL", "surbl": "SURBL"}


class ExportError(RuntimeError):
    """An export answered with an error. Says so without its URL, which holds the key."""


def _text(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "None", "null", "n/a") else text


def _day(value) -> str | None:
    """``"2020-12-06 09:10:23 UTC"`` → ``"2020-12-06"``."""
    text = _text(value)
    return text[:10] if text else None


def _tags(value) -> list[str]:
    """Tags as a list: the API sends one, the exports a comma- (or pipe-) separated string."""
    if isinstance(value, list):
        parts = value
    else:
        parts = (_text(value) or "").replace("|", ",").split(",")
    return list(dict.fromkeys(t for t in (_text(p) for p in parts) if t))


def _host_kind(host: str) -> str:
    try:
        return "ipv6" if ipaddress.ip_address(host).version == 6 else "ipv4"
    except ValueError:
        return "domain"


def _identity(kind: str, value: str) -> tuple[str, str]:
    from app.intelligence.observables import normalize_value

    return kind, normalize_value(kind, value)


def _kind_of(value: str) -> str | None:
    from app.intelligence.observables import classify_value

    found = classify_value(value)
    return found[0] if found else None


def _compact(facts: dict) -> dict:
    return {k: v for k, v in facts.items() if v not in (None, [], "")}


def _not_found(note: str | None = None) -> EnrichmentData:
    parsed = {"found": False, "note": note} if note else {"found": False}
    return EnrichmentData(raw_response={"status": "not_found"}, parsed_data=parsed, ttl_hours=LOOKUP_TTL_HOURS)


# ── Exports ──────────────────────────────────────────────────────────


def read_export(lines) -> Iterator[dict]:
    """Rows of an abuse.ch CSV export as dicts. The column names are the last
    ``#`` comment line before the data (``# "first_seen_utc","ioc_id",…`` or
    ``# id,dateadded,url,…``); values are quoted, ThreatFox's after ", "."""
    header: list[str] | None = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            fields = next(csv.reader([line.lstrip("#").strip()], skipinitialspace=True), [])
            if len(fields) >= 4:
                header = [f.strip().lower() for f in fields]
            continue
        if header is None:
            continue
        values = next(csv.reader([line], skipinitialspace=True), [])
        if len(values) == len(header):
            yield dict(zip(header, values, strict=True))


async def _download(gateway: SourceGateway, url: str, label: str):
    """The export, streamed to a temporary file (workers are memory-capped)."""
    tmp = tempfile.TemporaryFile()
    try:
        async with gateway.client(timeout=300.0, follow_redirects=True) as client:
            async with client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    raise ExportError(f"{label} export answered HTTP {resp.status_code}")
                async for chunk in resp.aiter_bytes():
                    tmp.write(chunk)
    except BaseException:
        tmp.close()
        raise
    tmp.seek(0)
    return tmp


def _export_rows(fileobj) -> Iterator[dict]:
    """The CSV inside a zipped export, a line at a time."""
    with zipfile.ZipFile(fileobj) as archive:
        member = next((n for n in archive.namelist() if n.lower().endswith(".csv")), None)
        if member is None:
            raise ExportError("the export holds no CSV")
        with archive.open(member) as raw:
            yield from read_export(io.TextIOWrapper(raw, encoding="utf-8", errors="replace"))


# ── The sources ──────────────────────────────────────────────────────


class _AbuseCh(EnrichmentAdapter):
    """What the three abuse.ch sources share: the key, the terms, the bucket."""

    requires = ("api_key",)
    shared_key_group = "abuse_ch"
    # abuse.ch publishes no numeric query limit, only "volumes reasonably
    # expected for non-commercial or non-profit purposes"
    # (https://abuse.ch/terms-of-use/, 3.2). Lookups are manual; a job makes
    # one request a run.
    quota = Quota(10, 60, daily_budget=500)
    # Every lookup sends the observable to abuse.ch. (The export jobs send
    # nothing about it; the source is marked by what its lookups reveal.)
    egress = Egress.SHARES_IOC
    # "Authenticated Users may access the Platforms for not-for-profit purposes";
    # commercial use "may require a paid subscription" (https://abuse.ch/terms-of-use/).
    license = License(
        "abuse.ch Terms of Use: not-for-profit use, commercial use by subscription",
        attribution="abuse.ch",
        commercial_ok=False,
    )
    scope = {"status": ("active",)}
    default_trigger_mode = "manual"

    def _auth(self) -> dict:
        if not self.api_key:
            raise NeedsKey(f"{self.source_type} needs an abuse.ch Auth-Key")
        return {"Auth-Key": self.api_key}

    async def _post(self, url: str, **kwargs) -> dict:
        async with self.http(timeout=15) as client:
            resp = await client.post(url, headers=self._auth(), **kwargs)
            resp.raise_for_status()
            return resp.json()


def _family(name: str | None, evidence: str) -> dict | None:
    return {"name": name, "evidence": evidence} if name else None


# ThreatFox ───────────────────────────────────────────────────────────


def threatfox_row(raw: dict) -> dict | None:
    """One IOC from the API (``ioc``, ``first_seen``…) or the export
    (``ioc_value``, ``first_seen_utc``…), with the ledger identity it is."""
    ioc = _text(raw.get("ioc") or raw.get("ioc_value"))
    kind = _THREATFOX_KINDS.get(_text(raw.get("ioc_type")) or "")
    if not ioc or not kind:
        return None
    if kind == "ipv4":
        ioc = ioc.rsplit(":", 1)[0].strip("[]")
        kind = _host_kind(ioc)
    try:
        confidence = int(_text(raw.get("confidence_level")) or 0)
    except ValueError:
        confidence = 0
    printable = _text(raw.get("malware_printable"))
    reference = _text(raw.get("reference"))
    return {
        "identity": _identity(kind, ioc),
        "id": _text(raw.get("id") or raw.get("ioc_id")),
        "threat_type": _text(raw.get("threat_type")),
        "malware": None if not printable or printable.lower().startswith("unknown") else printable,
        "confidence": confidence,
        "first_seen": _day(raw.get("first_seen") or raw.get("first_seen_utc")),
        "last_seen": _day(raw.get("last_seen") or raw.get("last_seen_utc")),
        "reference": reference if reference and reference.startswith(("https://", "http://")) else None,
        "tags": _tags(raw.get("tags")),
    }


def threatfox_facts(rows: list[dict]) -> dict:
    """What ThreatFox says about one indicator, over all its IOC entries
    (an IP can be listed once per port and family), best-confidence first."""
    rows = sorted(rows, key=lambda r: (r["confidence"], r["first_seen"] or ""), reverse=True)
    top = rows[0]
    c2, used = [], []
    for row in rows:
        threat = _THREAT_LABELS.get(row["threat_type"], row["threat_type"] or "indicator")
        evidence = f"ThreatFox: {threat}, {row['confidence']}% confidence, first seen {row['first_seen']}"
        if row["reference"]:
            evidence += f" ({row['reference']})"
        if family := _family(row["malware"], evidence):
            (c2 if row["threat_type"] == "botnet_cc" else used).append(family)
    seen_last = [r["last_seen"] for r in rows if r["last_seen"]]
    return _compact(
        {
            "found": True,
            "threat_type": ", ".join(
                dict.fromkeys(_THREAT_LABELS.get(r["threat_type"], r["threat_type"]) for r in rows if r["threat_type"])
            ),
            "role": THREATFOX_ROLES.get(top["threat_type"]),
            "confidence": top["confidence"],
            "first_seen": min((r["first_seen"] for r in rows if r["first_seen"]), default=None),
            "last_seen": max(seen_last, default=None),
            "malware": list(dict.fromkeys(r["malware"] for r in rows if r["malware"])),
            "tags": list(dict.fromkeys(t for r in rows for t in r["tags"])),
            "c2_families": c2,
            "families": used,
            "reference": next((r["reference"] for r in rows if r["reference"]), None),
            "link": {"url": f"https://threatfox.abuse.ch/ioc/{top['id']}/", "label": "ThreatFox"}
            if top["id"]
            else None,
        }
    )


_FAMILY_ITEM = {"name": "name", "evidence": "evidence"}


class ThreatFoxAdapter(_AbuseCh):
    source_type = "threatfox"
    display_name = "abuse.ch ThreatFox"
    applies_to = {"observable": ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256")}
    #: The export (``{key}`` in its path) the job matches, and how long its answer stays fresh.
    export_url = THREATFOX_EXPORT
    export_ttl_hours = 48  # a daily run, plus slack
    jobs = (
        Job(
            "threatfox-sync",
            "app.workers.enrichment_tasks.run_threatfox_sync",
            {"type": "crontab", "minute": "35", "hour": "4"},
            "Match the ledger's active observables against ThreatFox's IOC export: families, role and context",
        ),
    )
    outputs = (
        Column("role", "observable.role"),
        Relation("c2_families", "communicates_with", (entity_types.MALWARE, entity_types.TOOL), item=_FAMILY_ITEM),
        Relation("families", "uses", (entity_types.MALWARE,), item=_FAMILY_ITEM),
        Context("threat_type", "Threat", Display.FACT),
        Context("malware", "Malware", Display.CHIPS),
        Context("confidence", "Confidence (%)", Display.FACT),
        Context("first_seen", "First seen", Display.FACT),
        Context("last_seen", "Last seen", Display.FACT),
        Context("tags", "Tags", Display.CHIPS),
        Context("reference", "Reference", Display.LINK),
        Context("link", "ThreatFox", Display.LINK),
    )

    @staticmethod
    def export_keys(row: dict) -> list[tuple[str, str]]:
        """The ledger identities an export row speaks for."""
        parsed = threatfox_row(row)
        return [parsed["identity"]] if parsed else []

    @staticmethod
    def export_facts(kind: str, value: str, rows: list[dict]) -> dict:
        """parsed_data for one observable from its export rows."""
        return threatfox_facts([r for r in map(threatfox_row, rows) if r])

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        kind = _kind_of(entity_value)
        if kind not in self.applies_to["observable"]:
            return EnrichmentData(
                raw_response={"status": "unsupported_kind"},
                parsed_data={"found": False, "note": "ThreatFox lists IPs, domains, URLs and hashes"},
                ttl_hours=168,
            )
        identity = _identity(kind, entity_value)
        # ThreatFox lists an IP with its port, so an IP is searched by prefix.
        body = {"query": "search_ioc", "search_term": identity[1], "exact_match": kind not in ("ipv4", "ipv6")}
        data = await self._post(THREATFOX_API, json=body)
        if data.get("query_status") == "no_result":
            return _not_found()
        if data.get("query_status") != "ok":
            raise RuntimeError(f"ThreatFox answered {data.get('query_status')!r}")
        rows = [r for r in map(threatfox_row, data.get("data") or []) if r and r["identity"] == identity]
        if not rows:
            return _not_found()
        return EnrichmentData(
            raw_response={"ids": [r["id"] for r in rows]}, parsed_data=threatfox_facts(rows), ttl_hours=LOOKUP_TTL_HOURS
        )

    async def check_health(self) -> bool:
        # ThreatFox's own documented example IOC: nothing from the ledger.
        body = {"query": "search_ioc", "search_term": "139.180.203.104", "exact_match": True}
        try:
            return (await self._post(THREATFOX_API, json=body)).get("query_status") in ("ok", "no_result")
        except Exception:
            return False


# URLhaus ─────────────────────────────────────────────────────────────


def urlhaus_row(raw: dict) -> dict | None:
    """One malware URL from the API (``date_added``, ``urlhaus_reference``) or
    the dump (``dateadded``, ``urlhaus_link``)."""
    url = _text(raw.get("url"))
    if not url:
        return None
    return {
        "url": url,
        "host": (urlsplit(url).hostname or "").lower() or None,
        "status": _text(raw.get("url_status")) or "unknown",
        "threat": _text(raw.get("threat")),
        "tags": _tags(raw.get("tags")),
        "date_added": _day(raw.get("date_added") or raw.get("dateadded")),
        "last_online": _day(raw.get("last_online")),
        "link": _text(raw.get("urlhaus_reference") or raw.get("urlhaus_link")),
    }


def _blacklists(value) -> list[dict]:
    if not isinstance(value, dict):
        return []
    return [{"list": _BLACKLISTS.get(k, k), "status": v} for k, v in value.items() if _text(v)]


def urlhaus_facts(kind: str, value: str, rows: list[dict], blacklists=None, url_count=None) -> dict:
    """What URLhaus says about a URL (its one entry) or a host (the malware
    URLs on it). An offline URL is history, not a current threat."""
    if kind == "url":
        row = rows[0]
        tags = row["tags"]
        families = [{"name": t, "evidence": "URLhaus: malware distribution URL tagged " + t} for t in tags]
        return _compact(
            {
                "found": True,
                "url_status": row["status"],
                "threat": "malware distribution" if row["threat"] == "malware_download" else row["threat"],
                "role": "delivery" if row["threat"] == "malware_download" else None,
                "tags": tags,
                "first_seen": row["date_added"],
                "last_online": row["last_online"],
                "blacklists": _blacklists(blacklists),
                "families": families,
                "link": {"url": row["link"], "label": "URLhaus"} if row["link"] else None,
            }
        )
    statuses = {r["status"] for r in rows}
    online = sum(r["status"] == "online" for r in rows)
    tags = list(dict.fromkeys(t for r in rows for t in r["tags"]))
    n = int(url_count) if str(url_count or "").isdigit() else len(rows)
    return _compact(
        {
            "found": True,
            "url_status": "online" if online else "offline" if statuses == {"offline"} else "unknown",
            "urls": n,
            "online_urls": online,
            "tags": tags,
            "first_seen": min((r["date_added"] for r in rows if r["date_added"]), default=None),
            "blacklists": _blacklists(blacklists),
            "families": [{"name": t, "evidence": f"URLhaus: malware URLs on this host tagged {t}"} for t in tags],
            "link": {"url": f"https://urlhaus.abuse.ch/host/{quote(value)}/", "label": "URLhaus"},
        }
    )


class URLhausAdapter(_AbuseCh):
    source_type = "urlhaus"
    display_name = "abuse.ch URLhaus"
    applies_to = {"observable": ("url", "domain", "ipv4")}
    export_url = URLHAUS_EXPORT
    export_ttl_hours = 24  # four runs a day; a URL's status moves fast
    jobs = (
        Job(
            "urlhaus-sync",
            "app.workers.enrichment_tasks.run_urlhaus_sync",
            {"type": "crontab", "minute": "50", "hour": "*/6"},
            "Match the ledger's active URLs, domains and IPs against the URLhaus dump: status, tags and families",
        ),
    )
    outputs = (
        Column("role", "observable.role"),
        # URLhaus tags mix families with file types and architectures ("exe",
        # "32-bit"): a tag that names no tracked family is dropped, not held.
        Relation("families", "uses", (entity_types.MALWARE,), item=_FAMILY_ITEM, hold=False),
        Context(
            "url_status",
            "URLhaus",
            Display.BADGE,
            tones={"online": "danger", "offline": "neutral", "unknown": "neutral"},
        ),
        Context("threat", "Threat", Display.FACT),
        Context("urls", "Malware URLs", Display.FACT),
        Context("online_urls", "Online now", Display.FACT),
        Context("tags", "Tags", Display.CHIPS),
        Context("first_seen", "First seen", Display.FACT),
        Context("last_online", "Last online", Display.FACT),
        Context("blacklists", "Blocklists", Display.TABLE, item={"List": "list", "Status": "status"}),
        Context("link", "URLhaus", Display.LINK),
    )

    @staticmethod
    def export_keys(row: dict) -> list[tuple[str, str]]:
        parsed = urlhaus_row(row)
        if parsed is None:
            return []
        keys = [_identity("url", parsed["url"])]
        if parsed["host"]:
            keys.append(_identity(_host_kind(parsed["host"]), parsed["host"]))
        return keys

    @staticmethod
    def export_facts(kind: str, value: str, rows: list[dict]) -> dict:
        parsed = [r for r in map(urlhaus_row, rows) if r]
        if kind == "url":
            parsed = [r for r in parsed if _identity("url", r["url"]) == (kind, value)]
        return urlhaus_facts(kind, value, parsed)

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        kind = _kind_of(entity_value)
        if kind not in self.applies_to["observable"]:
            return EnrichmentData(
                raw_response={"status": "unsupported_kind"},
                parsed_data={"found": False, "note": "URLhaus lists URLs and the hosts serving them"},
                ttl_hours=168,
            )
        if kind == "url":
            data = await self._post(URLHAUS_API + "url/", data={"url": entity_value})
            rows = [r for r in [urlhaus_row(data)] if r]
        else:
            data = await self._post(URLHAUS_API + "host/", data={"host": entity_value})
            rows = [r for r in map(urlhaus_row, data.get("urls") or []) if r]
        # URLhaus's own host example spells it "query_staus".
        status = data.get("query_status", data.get("query_staus"))
        if status == "no_results":
            return _not_found()
        if status != "ok":
            raise RuntimeError(f"URLhaus answered {status!r}")
        if not rows:
            return _not_found()
        facts = urlhaus_facts(kind, entity_value, rows, data.get("blacklists"), data.get("url_count"))
        return EnrichmentData(raw_response={"id": data.get("id")}, parsed_data=facts, ttl_hours=LOOKUP_TTL_HOURS)

    async def check_health(self) -> bool:
        # URLhaus's own documented example host: nothing from the ledger.
        try:
            data = await self._post(URLHAUS_API + "host/", data={"host": "vektorex.com"})
        except Exception:
            return False
        return data.get("query_status", data.get("query_staus")) in ("ok", "no_results")


# MalwareBazaar ───────────────────────────────────────────────────────


#: The keys a vendor's intel names the sample by, best first (vendors differ).
_VENDOR_LABEL_KEYS = ("verdict", "malware_family", "threat_name", "detection", "status")


def _vendor_intel(value) -> list[dict]:
    """``{"ANY.RUN": [{"verdict": …}], "Triage": {"malware_family": …}}`` →
    one row per vendor that labelled the sample."""
    rows = []
    for vendor, intel in (value or {}).items() if isinstance(value, dict) else ():
        first = intel[0] if isinstance(intel, list) and intel else intel
        if not isinstance(first, dict):
            continue
        label = next((_text(first.get(k)) for k in _VENDOR_LABEL_KEYS if _text(first.get(k))), None)
        if label:
            rows.append({"vendor": vendor, "label": label})
    return rows


def bazaar_facts(sample: dict) -> dict:
    sha256 = _text(sample.get("sha256_hash"))
    signature = _text(sample.get("signature"))
    method = _text(sample.get("delivery_method"))
    return _compact(
        {
            "found": True,
            "role": "payload",
            "file_type": _text(sample.get("file_type")),
            "file_name": _text(sample.get("file_name")),
            "signature": signature,
            "first_seen": _day(sample.get("first_seen")),
            "last_seen": _day(sample.get("last_seen")),
            "delivery_method": _DELIVERY.get(method, method),
            "tags": _tags(sample.get("tags")),
            "vendor_intel": _vendor_intel(sample.get("vendor_intel")),
            "families": [f] if (f := _family(signature, "MalwareBazaar: sample signature")) else [],
            "link": {"url": f"https://bazaar.abuse.ch/sample/{sha256}/", "label": "MalwareBazaar"} if sha256 else None,
        }
    )


class MalwareBazaarAdapter(_AbuseCh):
    source_type = "malwarebazaar"
    display_name = "abuse.ch MalwareBazaar"
    applies_to = {"observable": ("md5", "sha1", "sha256")}
    outputs = (
        Column("role", "observable.role"),
        Relation("families", "uses", (entity_types.MALWARE,), item=_FAMILY_ITEM),
        Context("signature", "Signature", Display.FACT),
        Context("file_type", "File type", Display.FACT),
        Context("file_name", "File name", Display.FACT),
        Context("first_seen", "First seen", Display.FACT),
        Context("last_seen", "Last seen", Display.FACT),
        Context("delivery_method", "Delivery", Display.FACT),
        Context("tags", "Tags", Display.CHIPS),
        Context("vendor_intel", "Vendor intel", Display.TABLE, item={"Vendor": "vendor", "Label": "label"}),
        Context("link", "MalwareBazaar", Display.LINK),
    )

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        if _kind_of(entity_value) not in self.applies_to["observable"]:
            return EnrichmentData(
                raw_response={"status": "unsupported_kind"},
                parsed_data={"found": False, "note": "MalwareBazaar looks up file hashes"},
                ttl_hours=168,
            )
        data = await self._post(BAZAAR_API, data={"query": "get_info", "hash": entity_value.lower()})
        status = data.get("query_status")
        if status == "hash_not_found":
            return _not_found()
        if status != "ok" or not data.get("data"):
            raise RuntimeError(f"MalwareBazaar answered {status!r}")
        sample = data["data"][0]
        return EnrichmentData(
            raw_response={"sha256_hash": sample.get("sha256_hash")},
            parsed_data=bazaar_facts(sample),
            ttl_hours=LOOKUP_TTL_HOURS,
        )

    async def check_health(self) -> bool:
        # MalwareBazaar's own documented example hash: nothing from the ledger.
        body = {"query": "get_info", "hash": "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"}
        try:
            return (await self._post(BAZAAR_API, data=body)).get("query_status") in ("ok", "hash_not_found")
        except Exception:
            return False


# ── The export jobs ──────────────────────────────────────────────────


#: The sources with an export job.
ExportSource = type[ThreatFoxAdapter] | type[URLhausAdapter]


async def _match(db: AsyncSession, cls: ExportSource, batch: dict) -> dict:
    """The ledger's observables among ``batch`` ((kind, value) → export rows),
    as id → (kind, value, in scope, rows)."""
    from app.models.observable import Observable

    in_scope = cls.scope_filter(entity_types.OBSERVABLE, Observable)
    rows = await db.execute(
        select(Observable.id, Observable.kind, Observable.value, in_scope.label("in_scope")).where(
            Observable.kind.in_(cls.applies_to[entity_types.OBSERVABLE]),
            Observable.value.in_({value for _, value in batch}),
        )
    )
    return {
        oid: (kind, value, bool(ok), batch[(kind, value)]) for oid, kind, value, ok in rows if (kind, value) in batch
    }


async def _previously_matched(db: AsyncSession, source_type: str) -> set[uuid.UUID]:
    """Observables holding this source's context or relation claims."""
    from app.models.enrichment import EntityContext, EntityRelationClaim

    rows = await db.execute(
        union(
            select(EntityContext.entity_id).where(
                EntityContext.source_type == source_type, EntityContext.entity_type == entity_types.OBSERVABLE
            ),
            select(EntityRelationClaim.entity_id).where(
                EntityRelationClaim.source_type == source_type,
                EntityRelationClaim.entity_type == entity_types.OBSERVABLE,
            ),
        )
    )
    return set(rows.scalars())


async def sync_export(db: AsyncSession, gateway: SourceGateway, api_key: str | None, cls: ExportSource) -> dict:
    """Download the source's export, match it against the ledger and apply
    each active match; withdraw what an observable no longer in the export was
    given. Without a key nothing is sent; a refusal or an empty export stops
    the run before anything changes; an error status raises."""
    from app.enrichment.pipeline import apply_catalog_result

    stats = {"rows": 0, "matched": 0, "updated": 0, "withdrawn": 0, "stopped": None}
    if not api_key:
        stats["stopped"] = "needs_key"
        return stats
    try:
        export = await _download(gateway, cls.export_url.format(key=quote(api_key, safe="")), cls.display_name)
    except SOURCE_REFUSALS as e:
        logger.warning("%s export sync stopping: %s", cls.source_type, e)
        stats["stopped"] = e.status
        return stats

    found: dict = {}
    with export:
        batch: dict[tuple[str, str], list[dict]] = {}
        for row in _export_rows(export):
            stats["rows"] += 1
            for key in cls.export_keys(row):
                batch.setdefault(key, []).append(row)
            if len(batch) >= CHUNK:
                for oid, (kind, value, ok, rows) in (await _match(db, cls, batch)).items():
                    found.setdefault(oid, (kind, value, ok, []))[3].extend(rows)
                batch = {}
        if batch:
            for oid, (kind, value, ok, rows) in (await _match(db, cls, batch)).items():
                found.setdefault(oid, (kind, value, ok, []))[3].extend(rows)
    if not stats["rows"]:
        # An export with no rows is a broken download, not abuse.ch dropping everything.
        stats["stopped"] = "empty_export"
        return stats

    ttl = cls.export_ttl_hours
    applied = [(oid, kind, value, rows) for oid, (kind, value, ok, rows) in found.items() if ok]
    stats["matched"] = len(applied)
    for n, (oid, kind, value, rows) in enumerate(sorted(applied, key=lambda a: str(a[0]))):
        facts = cls.export_facts(kind, value, rows)
        data = EnrichmentData(raw_response={"rows": len(rows)}, parsed_data=facts, ttl_hours=ttl)
        if await apply_catalog_result(db, entity_types.OBSERVABLE, oid, cls.source_type, data):
            stats["updated"] += 1
        if n % BATCH == BATCH - 1:
            await db.commit()

    for oid in await _previously_matched(db, cls.source_type) - set(found):
        data = EnrichmentData(raw_response={}, parsed_data={"found": False}, ttl_hours=ttl)
        await apply_catalog_result(db, entity_types.OBSERVABLE, oid, cls.source_type, data)
        stats["withdrawn"] += 1
    await db.commit()
    return stats
