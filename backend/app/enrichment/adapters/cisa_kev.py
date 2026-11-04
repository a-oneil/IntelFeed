"""CISA Known Exploited Vulnerabilities (KEV) adapter — free, no API key.

Checks if a CVE is in the CISA KEV catalog.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Context, Display, Egress, Job, License, Quota


class CISAKEVAdapter(EnrichmentAdapter):
    source_type = "cisa_kev"
    display_name = "CISA KEV"
    about = "CISA's catalog of vulnerabilities known to be exploited, with the date each was added."
    applies_to = {"cve": None}
    # One JSON file; a lookup downloads the whole catalog.
    quota = Quota(100, 60, daily_budget=500)
    egress = Egress.NONE
    # On and auto from the start, so a new CVE is looked up when it arrives
    # instead of waiting for the source's scheduled job.
    default_enabled = True
    default_trigger_mode = "auto"
    license = License("CISA KEV (public domain)", attribution="CISA Known Exploited Vulnerabilities Catalog")
    jobs = (
        Job(
            "sync-kev-feed",
            "app.workers.intel_feed_tasks.sync_kev_feed",
            {"type": "crontab", "minute": "15", "hour": "*/6"},
            "Sync CISA Known Exploited Vulnerabilities catalog",
        ),
    )
    outputs = (
        # A fact, not a badge: the header already shows cve.is_kev, which the
        # sync job sets from the same catalog.
        Context("in_kev", "In KEV", Display.FACT),
        Context("date_added", "Added to KEV", Display.FACT),
        Context("due_date", "Remediation due", Display.FACT),
        Context("required_action", "Required action", Display.FACT),
        Context("known_ransomware_use", "Known ransomware use", Display.FACT),
    )

    _kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        async with self.http(timeout=15) as client:
            resp = await client.get(self._kev_url)
            resp.raise_for_status()
            data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        match = next((v for v in vulnerabilities if v.get("cveID") == entity_value), None)

        if not match:
            return EnrichmentData(
                raw_response={"total": len(vulnerabilities), "found": False},
                parsed_data={"in_kev": False},
                ttl_hours=24,
            )

        return kev_result(match)

    async def check_health(self) -> bool:
        try:
            async with self.http(timeout=5) as client:
                resp = await client.head(self._kev_url)
                return resp.status_code == 200
        except httpx.HTTPError:
            return False


def kev_result(entry: dict, via: str | None = None) -> EnrichmentData:
    """A catalog entry as the source's answer for its CVE. The KEV sync names
    itself in the raw response instead of repeating the entry."""
    return EnrichmentData(
        raw_response={"via": via, "cveID": entry.get("cveID")} if via else entry,
        parsed_data={
            "in_kev": True,
            "vendor": entry.get("vendorProject"),
            "product": entry.get("product"),
            "vulnerability_name": entry.get("vulnerabilityName"),
            "date_added": entry.get("dateAdded"),
            "short_description": entry.get("shortDescription"),
            "required_action": entry.get("requiredAction"),
            "due_date": entry.get("dueDate"),
            "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
        },
        # The sync re-checks the catalog every six hours.
        ttl_hours=24,
    )
