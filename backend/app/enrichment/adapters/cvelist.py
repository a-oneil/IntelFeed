"""cvelistV5 adapter — the CVE Program's own records, free, no API key.

A CVE record (CVE JSON 5) carries the assigning CNA's container — description,
CVSS, CWE and CAPEC ids, affected version ranges, solutions, references — and,
for most CVEs published since 2024 and every KEV entry, a CISA-ADP container
with CISA's SSVC decision points and a CVSS score for CVEs the CNA left
unscored. A lookup fetches one record from the cvelistV5 repository on
raw.githubusercontent.com; a 404 means the id has no published record.

The scheduled jobs (``app/workers/enrichment_tasks.py``) keep the records
current: ``cvelist-backfill`` reads the repository's baseline zip (every
record, published daily with each release) for the CVEs never checked (or
not checked in ``RECORD_TTL_HOURS``), and ``cvelist-delta-sync`` reads the
hourly delta zips for the records that changed.
"""

import re
import struct
import zlib
from collections.abc import Callable, Iterator
from typing import BinaryIO

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Column, Context, Display, Egress, Job, License, Policy, Quota
from app.intelligence.cve import _severity_from_score

RAW_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
RELEASES_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases"

# The delta sync rewrites any record that changes, so a stored record is
# current until the backfill re-checks it, a quarter later.
RECORD_TTL_HOURS = 90 * 24
# An id with no published record (reserved, or junk pulled from prose) is
# asked about again monthly; the delta sync picks it up sooner if it publishes.
NOT_FOUND_TTL_HOURS = 30 * 24

_CVE_ID = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
# CVSS versions in preference order: the 3.x score is the one NVD and the
# cves.cvss_score column carry; a 4.0-only CNA still beats no score.
_CVSS_VERSIONS = (("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV4_0", "4.0"))
_SSVC_POINTS = {
    "Exploitation": "ssvc_exploitation",
    "Automatable": "ssvc_automatable",
    "Technical Impact": "ssvc_technical_impact",
}
_TEXT_CAP = 1500
_ROWS_CAP = 25


#: The release asset holding every record: a zip whose one member is
#: ``cves.zip``, the repository's ``cves/`` tree as of midnight UTC.
BASELINE_MARKER = "_all_CVEs_at_midnight"


def pick_baseline(releases: list[dict]) -> tuple[str, str] | None:
    """The newest baseline asset in a releases listing, as (name, url)."""
    for release in releases:
        for asset in release.get("assets") or []:
            name = asset.get("name") or ""
            if BASELINE_MARKER in name and name.endswith(".zip"):
                return name, asset["browser_download_url"]
    return None


class _Reader:
    """A forward-only stream with push-back, for reading zip members in order."""

    def __init__(self, raw: BinaryIO):
        self.raw, self.buffer = raw, b""

    def read(self, n: int) -> bytes:
        while len(self.buffer) < n:
            chunk = self.raw.read(max(n - len(self.buffer), 1 << 16))
            if not chunk:
                break
            self.buffer += chunk
        out, self.buffer = self.buffer[:n], self.buffer[n:]
        return out

    def skip(self, n: int) -> None:
        while n > 0:
            got = len(self.read(min(n, 1 << 20)))
            if not got:
                raise ValueError("zip member ends early")
            n -= got

    def unread(self, data: bytes) -> None:
        self.buffer = data + self.buffer


def _inflate(reader: _Reader, keep: bool) -> tuple[bytes, int]:
    """A deflate stream of unknown length: (its bytes when ``keep``, the
    compressed length read)."""
    inflater, out, used = zlib.decompressobj(-15), [], 0
    while not inflater.eof:
        chunk = reader.read(1 << 16)
        if not chunk:
            raise ValueError("zip member ends early")
        data = inflater.decompress(chunk)
        if keep:
            out.append(data)
        used += len(chunk) - len(inflater.unused_data)
    reader.unread(inflater.unused_data)
    return b"".join(out), used


def iter_zip(stream: BinaryIO, wanted: Callable[[str], bool]) -> Iterator[tuple[str, bytes]]:
    """Each member of a zip read front to back from ``stream`` whose name
    ``wanted`` accepts, as (name, bytes); the rest are skipped. Reads local
    headers instead of the central directory, so nothing but the current
    member is held in memory and the stream needn't seek: the baseline's
    ``cves.zip`` is read straight out of the outer zip."""
    reader = _Reader(stream)
    while reader.read(4) == b"PK\x03\x04":
        _, flags, method, _, _, _, csize, usize, name_len, extra_len = struct.unpack("<HHHHHIIIHH", reader.read(26))
        name = reader.read(name_len).decode("utf-8", "replace")
        extra = reader.read(extra_len)
        while len(extra) >= 4:
            tag, size = struct.unpack("<HH", extra[:4])
            if tag == 0x0001 and size >= 16 and usize == 0xFFFFFFFF:
                usize, csize = struct.unpack("<QQ", extra[4:20])
            extra = extra[4 + size :]
        keep = not name.endswith("/") and wanted(name)
        if flags & 0x08:
            # Sizes follow the data in a descriptor: only a deflated member
            # can be read without them.
            if method != 8:
                raise ValueError(f"{name}: stored member with a data descriptor")
            data, _ = _inflate(reader, keep)
            head = reader.read(4)
            if head != b"PK\x07\x08":
                reader.unread(head)
            reader.read(12)  # crc and 4-byte sizes
            after = reader.read(4)
            if after[:2] != b"PK":
                reader.read(4)  # zip64: the sizes are 8 bytes each
            else:
                reader.unread(after)
        elif not keep:
            reader.skip(csize)
            continue
        elif method == 8:
            data = zlib.decompress(reader.read(csize), -15)
        elif method == 0:
            data = reader.read(csize)
        else:
            raise ValueError(f"{name}: compression method {method}")
        if keep:
            yield name, data


def member_cve_id(name: str) -> str | None:
    """The CVE id a record's path names (``cves/2024/3xxx/CVE-2024-3400.json``)."""
    if not name.endswith(".json"):
        return None
    stem = name.rsplit("/", 1)[-1][:-5].upper()
    return stem if _CVE_ID.match(stem) else None


def record_url(cve_id: str) -> str | None:
    """The record's raw URL (``cves/2024/3xxx/CVE-2024-3400.json``), or None
    for a malformed id."""
    match = _CVE_ID.match(cve_id or "")
    if not match:
        return None
    year, number = match.groups()
    return f"{RAW_URL}/{year}/{int(number) // 1000}xxx/{cve_id}.json"


def _english(entries, cap: int | None = None) -> str | None:
    """The English value of a CVE JSON 5 ``{lang, value}`` list, else the first."""
    entries = [e for e in entries or [] if isinstance(e, dict) and (e.get("value") or "").strip()]
    entry = next(
        (e for e in entries if (e.get("lang") or "").lower().startswith("en")), entries[0] if entries else None
    )
    return entry["value"].strip()[:cap] if entry else None


def _cvss(metrics) -> dict | None:
    """The preferred CVSS metric of a container: score, severity, vector, version."""
    for key, version in _CVSS_VERSIONS:
        for metric in metrics or []:
            cvss = metric.get(key) if isinstance(metric, dict) else None
            if isinstance(cvss, dict) and isinstance(cvss.get("baseScore"), (int, float)):
                score = float(cvss["baseScore"])
                return {
                    "score": score,
                    "severity": (cvss.get("baseSeverity") or "").upper() or _severity_from_score(score),
                    "vector": cvss.get("vectorString"),
                    "version": version,
                }
    return None


def _ssvc(metrics) -> dict:
    """CISA's SSVC decision points, lowercased, and when it assessed them."""
    for metric in metrics or []:
        other = metric.get("other") if isinstance(metric, dict) else None
        if not isinstance(other, dict) or other.get("type") != "ssvc":
            continue
        content = other.get("content") or {}
        points = {}
        for option in content.get("options") or []:
            for name, value in (option or {}).items():
                if name in _SSVC_POINTS and isinstance(value, str):
                    points[_SSVC_POINTS[name]] = value.strip().lower()
        return {**points, "ssvc_timestamp": content.get("timestamp")}
    return {}


def _kev_date(metrics) -> str | None:
    """The date CISA's ADP container says the CVE joined KEV."""
    for metric in metrics or []:
        other = metric.get("other") if isinstance(metric, dict) else None
        if isinstance(other, dict) and other.get("type") == "kev":
            added = (other.get("content") or {}).get("dateAdded")
            return added[:10] if isinstance(added, str) else None
    return None


def _known(value) -> str | None:
    """A CNA field, or None for the "n/a" CNAs write when they don't know."""
    return value if isinstance(value, str) and value.strip() and value.strip().lower() != "n/a" else None


def _affected(entries) -> list[dict]:
    """The CNA's affected version ranges, one row per affected range."""
    rows = []
    for entry in entries or []:
        vendor, product = _known(entry.get("vendor")), _known(entry.get("product"))
        versions = [v for v in entry.get("versions") or [] if v.get("status") == "affected"]
        if not versions and entry.get("defaultStatus") == "affected":
            versions = [{}]
        for v in versions:
            version = _known(v.get("version"))
            at_most = _known(v.get("lessThanOrEqual"))
            below = _known(v.get("lessThan")) or (f"≤ {at_most}" if at_most else None)
            if product or version or below:
                rows.append({"vendor": vendor, "product": product, "version": version, "fixed": below})
    return rows[:_ROWS_CAP]


def _cpe_segment(name: str) -> str:
    """A CNA's vendor or product name in CPE spelling: lowercase, words
    joined by underscores ("Palo Alto Networks" → "palo_alto_networks")."""
    return re.sub(r"[\s/]+", "_", name.strip().lower())


def affected_pairs(parsed: dict) -> list[dict]:
    """The CNA's affected rows as cve_affected pairs (vendor, product, first
    affected version, the version that fixes it)."""
    pairs = []
    for row in parsed.get("affected") or []:
        vendor, product = row.get("vendor"), row.get("product")
        if not (vendor and product):
            continue
        fixed = row.get("fixed")
        pairs.append(
            {
                "vendor": _cpe_segment(vendor),
                "product": _cpe_segment(product),
                "version_start": row.get("version") if row.get("version") not in ("0", "*") else None,
                "version_end": fixed.removeprefix("≤ ") if isinstance(fixed, str) else None,
            }
        )
    return pairs


def cpe_pairs(cpes) -> list[dict]:
    """CPE 2.3 strings (``cpe:2.3:o:paloaltonetworks:pan-os:10.2.0:…``) as
    cve_affected pairs. CISA lists one CPE per affected version, which says
    nothing about a range, so the pair carries no versions."""
    pairs = []
    for cpe in cpes or []:
        parts = cpe.split(":") if isinstance(cpe, str) else []
        if len(parts) >= 5 and parts[0] == "cpe":
            pairs.append({"vendor": parts[3], "product": parts[4], "version_start": None, "version_end": None})
    return pairs


def parse_record(record: dict) -> dict:
    """A CVE JSON 5 record as parsed_data. A rejected record carries only its
    state and reason, so nothing of it lands on the CVE's columns."""
    meta = record.get("cveMetadata") or {}
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    parsed = {
        "found": True,
        "cve_id": meta.get("cveId"),
        "state": meta.get("state"),
        "assigner": meta.get("assignerShortName"),
        "published": meta.get("datePublished"),
        "updated": meta.get("dateUpdated"),
    }
    if meta.get("state") == "REJECTED":
        parsed["rejected_reason"] = _english(cna.get("rejectedReasons"))
        return parsed

    adp = next(
        (a for a in containers.get("adp") or [] if (a.get("providerMetadata") or {}).get("shortName") == "CISA-ADP"),
        {},
    )
    cna_cvss, adp_cvss = _cvss(cna.get("metrics")), _cvss(adp.get("metrics"))
    # The applier takes the CNA's score (rank 2) before CISA's (rank 3), and
    # the severity follows whichever it wrote: this is the same choice.
    chosen = cna_cvss or adp_cvss
    scorer = parsed["assigner"] if cna_cvss else "CISA-ADP"
    cna_v4 = next((m["cvssV4_0"] for m in cna.get("metrics") or [] if isinstance(m.get("cvssV4_0"), dict)), None)
    references = [r for r in cna.get("references") or [] if isinstance(r, dict) and r.get("url")]
    parsed.update(
        {
            "description": _english(cna.get("descriptions")),
            "cna_cvss": cna_cvss,
            "adp_cvss": adp_cvss,
            "cvss_severity": chosen["severity"] if chosen else None,
            "cvss_vector": chosen["vector"] if chosen else None,
            "cvss_scored_by": f"{scorer} · CVSS {chosen['version']}" if chosen else None,
            "cvss_v4": (
                f"{cna_v4.get('baseScore')} · {cna_v4.get('vectorString')}"
                if cna_v4 and chosen and chosen["version"] != "4.0"
                else None
            ),
            **_ssvc(adp.get("metrics")),
            "adp_kev_date_added": _kev_date(adp.get("metrics")),
            "weaknesses": [
                d["cweId"]
                for p in cna.get("problemTypes") or []
                for d in p.get("descriptions") or []
                if isinstance(d.get("cweId"), str)
            ],
            "capec": [i["capecId"] for i in cna.get("impacts") or [] if isinstance(i.get("capecId"), str)],
            "affected": _affected(cna.get("affected")),
            "solutions": _english(cna.get("solutions"), _TEXT_CAP),
            "workarounds": _english(cna.get("workarounds"), _TEXT_CAP),
            "exploits": _english(cna.get("exploits"), _TEXT_CAP),
            "references": [{"url": r["url"], "tags": r.get("tags") or []} for r in references[:20]],
            "adp_cpes": [c for a in adp.get("affected") or [] for c in a.get("cpes") or []][:_ROWS_CAP],
        }
    )
    return parsed


def record_result(record: dict) -> EnrichmentData:
    """A fetched record as a lookup result. The raw response keeps only the
    record's metadata: parsed_data has what is used, and a whole record (up to
    50 KB) per CVE would make enrichment_results the largest table."""
    return EnrichmentData(
        raw_response={"cveMetadata": record.get("cveMetadata") or {}},
        parsed_data=parse_record(record),
        ttl_hours=RECORD_TTL_HOURS,
    )


class CVEListAdapter(EnrichmentAdapter):
    source_type = "cvelist"
    display_name = "CVE List (cvelistV5)"
    about = "The CVE Program's own records: what each CNA and CISA published about a CVE."
    applies_to = {"cve": None}
    # Two GitHub hosts behind one bucket. raw.githubusercontent.com publishes
    # no number but rate-limits unauthenticated downloads
    # (github.blog/changelog/2025-05-08-updated-rate-limits-for-unauthenticated-requests);
    # the REST API allows 60 requests an hour unauthenticated
    # (docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api),
    # of which each sync uses one or two. A lookup fetches one record; the
    # jobs read zips, a handful of requests a run.
    quota = Quota(30, 60, daily_budget=12000)
    egress = Egress.NONE
    # "You may search, download, and use the content hosted in this
    # repository, per the CVE Program Terms of Use" (the repository's README);
    # the terms (www.cve.org/Legal/TermsOfUse) grant a perpetual, royalty-free
    # license to reproduce and redistribute CVE content with MITRE's notice.
    license = License("CVE Program terms of use", attribution="CVE® records © The MITRE Corporation, via cvelistV5")
    # GitHub answers rate limits with 403 or 429.
    throttle_statuses = (403, 429, 503)
    #: Claims name which container a score came from, for "CVSS by source".
    claim_refs = {"cna_cvss.score": "cvelist:cna", "adp_cvss.score": "cvelist:adp"}
    jobs = (
        Job(
            "cvelist-backfill",
            "app.workers.enrichment_tasks.run_cvelist_backfill",
            {"type": "crontab", "minute": "20"},
            "Apply CVE records (CNA and CISA-ADP) from cvelistV5's baseline zip to CVEs unchecked for 90 days",
        ),
        Job(
            "cvelist-delta-sync",
            "app.workers.enrichment_tasks.run_cvelist_delta_sync",
            {"type": "crontab", "minute": "40"},
            "Apply the CVE records changed since the last run, from cvelistV5's hourly delta zips",
        ),
    )
    outputs = (
        # NVD's score (rank 1) wins a blank column; the CNA's comes next and
        # CISA's last, for the CVEs neither NVD nor the CNA has scored. The
        # severity is written with the score, replacing extraction's UNKNOWN.
        Column("cna_cvss.score", "cve.cvss_score", Policy.RANK, rank=2),
        Column("adp_cvss.score", "cve.cvss_score", Policy.RANK, rank=3),
        Column("cvss_severity", "cve.severity", follows="cve.cvss_score"),
        # NVD republishes the CNA's text, so the two rank alike, ahead of Wikipedia.
        Column("description", "cve.description", Policy.RANK, rank=1),
        # The KEV sync sets the catalog's date; CISA's ADP container carries
        # the same date, which fills it for a CVE the sync hasn't reached.
        Column("adp_kev_date_added", "cve.kev_date_added", filter="date"),
        # CISA re-scores SSVC as exploitation changes: the newest record wins.
        Column("ssvc_exploitation", "cve.ssvc_exploitation", Policy.NEWER_WINS),
        Column("ssvc_automatable", "cve.ssvc_automatable", Policy.NEWER_WINS),
        Column("ssvc_technical_impact", "cve.ssvc_technical_impact", Policy.NEWER_WINS),
        Context(
            "ssvc_exploitation",
            "SSVC exploitation",
            Display.BADGE,
            tones={"active": "critical", "poc": "medium", "none": "neutral"},
        ),
        Context("state", "CVE record", Display.BADGE, tones={"REJECTED": "warning"}),
        Context("rejected_reason", "Rejected because", Display.FACT),
        Context("assigner", "CNA", Display.FACT),
        Context("cvss_scored_by", "CVSS from", Display.FACT),
        Context("cvss_vector", "CVSS vector", Display.FACT),
        Context("cvss_v4", "CVSS 4.0", Display.FACT),
        Context("ssvc_automatable", "SSVC automatable", Display.FACT),
        Context("ssvc_technical_impact", "SSVC technical impact", Display.FACT),
        Context("ssvc_timestamp", "SSVC assessed", Display.FACT),
        Context(
            "affected",
            "Affected versions",
            Display.TABLE,
            item={"Vendor": "vendor", "Product": "product", "From": "version", "Fixed in": "fixed"},
        ),
        Context("solutions", "Solution", Display.FACT),
        Context("workarounds", "Workarounds", Display.FACT),
        Context("exploits", "Exploitation (CNA)", Display.FACT),
        Context("weaknesses", "Weaknesses", Display.CHIPS),
        Context("capec", "CAPEC", Display.CHIPS),
        Context("adp_cpes", "CPEs (CISA-ADP)", Display.CHIPS),
        Context("published", "Published", Display.FACT),
        Context("updated", "Record updated", Display.FACT),
        Context("references", "References", Display.TABLE, item={"Link": "url", "Tags": "tags"}),
    )

    @staticmethod
    async def apply_record(db, entity_type: str, entity_id, data: EnrichmentData, cache: dict) -> None:
        """A record's links beyond its columns: its CWE ids as cve_weaknesses
        rows, and the CNA's affected products and CISA-ADP's CPEs as
        cve_affected rows."""
        from app.intelligence.cpe_resolver import build_cpe_index
        from app.intelligence.cve import build_cwe_index, sync_cve_affected, sync_cve_weaknesses

        parsed = data.parsed_data or {}
        if entity_type != "cve" or not parsed.get("found"):
            return
        weaknesses = [
            {"cwe_ref": ref, "is_primary": False, "assigner": parsed.get("assigner")}
            for ref in dict.fromkeys(parsed.get("weaknesses") or [])
        ]
        if weaknesses:
            if "cwe_index" not in cache:
                cache["cwe_index"] = await build_cwe_index(db)
            await sync_cve_weaknesses(db, entity_id, weaknesses, cache["cwe_index"], source="cvelist")
        for source, pairs in (("cna", affected_pairs(parsed)), ("cisa_adp", cpe_pairs(parsed.get("adp_cpes")))):
            if pairs:
                if "cpe_index" not in cache:
                    cache["cpe_index"] = await build_cpe_index(db)
                await sync_cve_affected(db, entity_id, pairs, cache["cpe_index"], source=source)

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        url = record_url(entity_value)
        if url is None:
            return EnrichmentData(
                raw_response={"status": "malformed_id"}, parsed_data={"found": False}, ttl_hours=NOT_FOUND_TTL_HOURS
            )
        async with self.http(timeout=15) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                return EnrichmentData(
                    raw_response={"status": "not_found"}, parsed_data={"found": False}, ttl_hours=NOT_FOUND_TTL_HOURS
                )
            resp.raise_for_status()
            return record_result(resp.json())

    async def check_health(self) -> bool:
        try:
            async with self.http(timeout=5) as client:
                resp = await client.get(record_url("CVE-2024-3400"))
                return resp.status_code == 200
        except httpx.HTTPError:
            return False
