"""OSV (Open Source Vulnerabilities) adapter — free, no API key.

Looks a CVE up by id (``GET /v1/vulns/{id}``) for its aliases, affected
packages and repos, fix ranges and severity vectors. A 404 means OSV has no
record for the CVE. A new CVE is looked up once; after that the hourly
``osv-delta-sync`` job reads OSV's change list (``modified_id.csv``, newest
first) back to its last run and fetches only the CVE records that changed, so
a stored answer stands until OSV changes it.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Column, Context, Display, Egress, Job, License, Policy, Quota

#: How long a stored answer stands: the delta job applies every change in
#: between, so refresh lookups are rare.
TTL_HOURS = 24 * 30


class OSVAdapter(EnrichmentAdapter):
    source_type = "osv"
    display_name = "OSV"
    about = "Open Source Vulnerabilities: the packages a CVE affects and the versions that fix it."
    applies_to = {"cve": None}
    # api.osv.dev publishes no request limit.
    quota = Quota(100, 60, daily_budget=2000)
    egress = Egress.LOW
    # On and auto from the start, so a new CVE is looked up when it arrives
    # instead of waiting for the source's scheduled job.
    default_enabled = True
    default_trigger_mode = "auto"
    license = License("CC BY 4.0", attribution="OSV.dev")
    jobs = (
        Job(
            "osv-delta-sync",
            "app.workers.enrichment_tasks.run_osv_delta_sync",
            {"type": "crontab", "minute": "40", "hour": "*"},
            "Apply the OSV records of tracked CVEs that changed since the last run",
        ),
    )
    outputs = (
        # The GHSA and distro ids people search by, kept with the CVE.
        Column("aliases", "cve.aliases", Policy.UNION, filter="ids"),
        Context("aliases", "Also known as", Display.CHIPS),
        Context("summary", "Summary", Display.FACT),
        Context("severity", "Severity vectors", Display.CHIPS),
        Context(
            "affected",
            "Affected packages",
            Display.TABLE,
            item={"Ecosystem": "ecosystem", "Package": "package_name", "Ranges": "ranges"},
        ),
        Context("references", "References", Display.TABLE, item={"Type": "type", "Link": "url"}),
    )

    _vulns_url = "https://api.osv.dev/v1/vulns/"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        async with self.http(timeout=10) as client:
            resp = await client.get(f"{self._vulns_url}{entity_value}")
            if resp.status_code == 404:
                return EnrichmentData(
                    raw_response={"status": "not_found"},
                    parsed_data={"found": False},
                    # A record OSV adds later arrives through the delta job.
                    ttl_hours=TTL_HOURS,
                )
            resp.raise_for_status()
            vuln = resp.json()
        return EnrichmentData(raw_response=vuln, parsed_data=parse_vuln(vuln), ttl_hours=TTL_HOURS)

    async def check_health(self) -> bool:
        try:
            async with self.http(timeout=5) as client:
                resp = await client.get(f"{self._vulns_url}CVE-2021-44228")
                return resp.status_code == 200
        except httpx.HTTPError:
            return False


def parse_vuln(vuln: dict) -> dict:
    """The parsed_data for one OSV record."""
    return {
        "found": True,
        "osv_id": vuln.get("id"),
        "aliases": vuln.get("aliases", []),
        "summary": vuln.get("summary"),
        "details": (vuln.get("details") or "")[:1000],
        "severity": [s.get("score") for s in vuln.get("severity", []) if s.get("score")],
        "affected": [_affected(a) for a in vuln.get("affected", [])[:10]],
        "references": [{"type": r.get("type"), "url": r.get("url")} for r in vuln.get("references", [])[:10]],
        "published": vuln.get("published"),
        "modified": vuln.get("modified"),
    }


def _affected(entry: dict) -> dict:
    """One ``affected`` block: the package (ecosystem + name) when OSV knows
    it, and each range's introduced/fixed events. Records imported from NVD
    carry only GIT ranges, so the repo is kept too."""
    package = entry.get("package") or {}
    ranges = []
    for r in entry.get("ranges", [])[:5]:
        events = r.get("events", [])
        ranges.append(
            {
                "type": r.get("type"),
                "repo": r.get("repo"),
                "introduced": [e["introduced"] for e in events if "introduced" in e],
                "fixed": [e["fixed"] for e in events if "fixed" in e],
            }
        )
    return {
        "ecosystem": package.get("ecosystem"),
        "package_name": package.get("name"),
        "ranges": ranges,
    }
