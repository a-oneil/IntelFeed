"""OSV (Open Source Vulnerabilities) adapter — free, no API key.

Looks a CVE up by id (``GET /v1/vulns/{id}``) for its aliases, affected
packages and repos, fix ranges and severity vectors. A 404 means OSV has no
record for the CVE.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Context, Display, Egress, License, Quota


class OSVAdapter(EnrichmentAdapter):
    source_type = "osv"
    display_name = "OSV"
    applies_to = {"cve": None}
    # api.osv.dev publishes no request limit.
    quota = Quota(100, 60, daily_budget=2000)
    egress = Egress.LOW
    license = License("CC BY 4.0", attribution="OSV.dev")
    default_trigger_mode = "auto"
    outputs = (
        Context("aliases", "Also known as", Display.CHIPS),
        Context("summary", "Summary", Display.FACT),
        Context("severity", "Severity vectors", Display.CHIPS),
        Context(
            "affected",
            "Affected packages",
            Display.TABLE,
            item={"Ecosystem": "ecosystem", "Package": "package_name", "Ranges": "ranges"},
        ),
        Context("references", "References", Display.LINK),
    )

    _vulns_url = "https://api.osv.dev/v1/vulns/"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        async with self.http(timeout=10) as client:
            resp = await client.get(f"{self._vulns_url}{entity_value}")
            if resp.status_code == 404:
                return EnrichmentData(
                    raw_response={"status": "not_found"},
                    parsed_data={"found": False},
                    ttl_hours=24,
                )
            resp.raise_for_status()
            vuln = resp.json()

        return EnrichmentData(
            raw_response=vuln,
            parsed_data={
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
            },
            ttl_hours=24,
        )

    async def check_health(self) -> bool:
        try:
            async with self.http(timeout=5) as client:
                resp = await client.get(f"{self._vulns_url}CVE-2021-44228")
                return resp.status_code == 200
        except httpx.HTTPError:
            return False


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
