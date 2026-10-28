"""cvelistV5 adapter — the CVE Program's own records, free, no API key.

A CVE record (CVE JSON 5) carries the assigning CNA's container — description,
CVSS, CWE and CAPEC ids, affected version ranges, solutions, references — and,
for most CVEs published since 2024 and every KEV entry, a CISA-ADP container
with CISA's SSVC decision points and a CVSS score for CVEs the CNA left
unscored. A lookup fetches one record from the cvelistV5 repository on
raw.githubusercontent.com; a 404 means the id has no published record.

The scheduled jobs (``app/workers/enrichment_tasks.py``) keep the records
current: ``cvelist-backfill`` looks up the CVEs never checked (or not checked
in ``RECORD_TTL_HOURS``), and ``cvelist-delta-sync`` reads the repository's
hourly delta zips for the records that changed.
"""

import re

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
    applies_to = {"cve": None}
    # Two GitHub hosts behind one bucket. raw.githubusercontent.com publishes
    # no number but rate-limits unauthenticated downloads
    # (github.blog/changelog/2025-05-08-updated-rate-limits-for-unauthenticated-requests);
    # the REST API allows 60 requests an hour unauthenticated
    # (docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api),
    # of which the delta sync uses one. 30 a minute keeps a backfill run at
    # about 400 record fetches.
    quota = Quota(30, 60, daily_budget=12000)
    egress = Egress.NONE
    # "You may search, download, and use the content hosted in this
    # repository, per the CVE Program Terms of Use" (the repository's README);
    # the terms (www.cve.org/Legal/TermsOfUse) grant a perpetual, royalty-free
    # license to reproduce and redistribute CVE content with MITRE's notice.
    license = License("CVE Program terms of use", attribution="CVE® records © The MITRE Corporation, via cvelistV5")
    # GitHub answers rate limits with 403 or 429.
    throttle_statuses = (403, 429, 503)
    jobs = (
        Job(
            "cvelist-backfill",
            "app.workers.enrichment_tasks.run_cvelist_backfill",
            {"type": "crontab", "minute": "20"},
            "Fetch the CVE record (CNA and CISA-ADP) for CVEs never checked or not checked in 90 days",
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
