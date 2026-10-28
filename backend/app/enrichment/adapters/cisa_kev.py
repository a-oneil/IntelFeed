"""CISA Known Exploited Vulnerabilities (KEV) adapter — free, no API key.

Checks if a CVE is in the CISA KEV catalog.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Context, Display, Egress, Job, License, Quota


class CISAKEVAdapter(EnrichmentAdapter):
    source_type = "cisa_kev"
    display_name = "CISA KEV"
    applies_to = {"cve": None}
    # One JSON file; a lookup downloads the whole catalog.
    quota = Quota(100, 60, daily_budget=500)
    egress = Egress.NONE
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

        return EnrichmentData(
            raw_response=match,
            parsed_data={
                "in_kev": True,
                "vendor": match.get("vendorProject"),
                "product": match.get("product"),
                "vulnerability_name": match.get("vulnerabilityName"),
                "date_added": match.get("dateAdded"),
                "short_description": match.get("shortDescription"),
                "required_action": match.get("requiredAction"),
                "due_date": match.get("dueDate"),
                "known_ransomware_use": match.get("knownRansomwareCampaignUse"),
            },
            ttl_hours=24,
        )

    async def check_health(self) -> bool:
        try:
            async with self.http(timeout=5) as client:
                resp = await client.head(self._kev_url)
                return resp.status_code == 200
        except httpx.HTTPError:
            return False
