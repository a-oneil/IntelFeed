"""CVEDetails.com API adapter — requires API key (paid subscription).

Provides enriched CVE data including CVSS scores from multiple sources,
affected products (including CVEs NVD hasn't processed), exploit references,
vendor advisories, remediation info, and EPSS history.

API docs: https://www.cvedetails.com/documentation/apis
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Context, Display, Egress, License, Quota

API_BASE = "https://www.cvedetails.com/api/v1"


class CVEDetailsAdapter(EnrichmentAdapter):
    source_type = "cvedetails"
    display_name = "CVEDetails"
    applies_to = {"cve": None}
    requires = ("api_key",)
    quota = Quota(60, 60, daily_budget=1000)
    egress = Egress.LOW
    # The site's terms bar using it or its information "for any commercial
    # purposes": https://www.cvedetails.com/terms-and-conditions.php
    license = License("CVEDetails API subscription", attribution="CVEdetails.com", commercial_ok=False)
    default_trigger_mode = "auto"
    outputs = (
        Context(
            "exploits",
            "Exploits",
            Display.TABLE,
            item={"Source": "source", "Link": "url", "Description": "description"},
        ),
        Context("advisories", "Advisories", Display.TABLE, item={"Source": "source", "Title": "title", "Link": "url"}),
        Context("cvedetails_url", "CVEdetails", Display.LINK),
    )

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

        async with self.http(timeout=15, headers=headers) as client:
            resp = await client.get(
                f"{API_BASE}/vulnerability/search",
                params={"cveId": entity_value},
            )

            if resp.status_code == 404:
                return EnrichmentData(
                    raw_response={"status": "not_found"},
                    parsed_data={"found": False},
                    ttl_hours=168,
                )

            resp.raise_for_status()
            data = resp.json()

        # CVEDetails returns a list of results
        results = data if isinstance(data, list) else data.get("results", [])
        if not results:
            return EnrichmentData(
                raw_response=data,
                parsed_data={"found": False},
                ttl_hours=168,
            )

        cve = results[0] if isinstance(results, list) else results

        # Extract affected products
        affected_products = []
        for product in cve.get("affectedProducts", cve.get("affected_products", []))[:20]:
            affected_products.append(
                {
                    "vendor": product.get("vendor", {}).get("name")
                    if isinstance(product.get("vendor"), dict)
                    else product.get("vendor"),
                    "product": product.get("product", {}).get("name")
                    if isinstance(product.get("product"), dict)
                    else product.get("product"),
                    "version": product.get("version"),
                }
            )

        # Extract exploit references
        exploits = []
        for exploit in cve.get("exploits", [])[:10]:
            exploits.append(
                {
                    "source": exploit.get("source"),
                    "url": exploit.get("url"),
                    "description": exploit.get("description"),
                }
            )

        # Extract advisories
        advisories = []
        for adv in cve.get("advisories", [])[:10]:
            advisories.append(
                {
                    "source": adv.get("source"),
                    "url": adv.get("url"),
                    "title": adv.get("title"),
                }
            )

        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "found": True,
                "cve_id": cve.get("cveId", cve.get("cve_id", entity_value)),
                "description": cve.get("description"),
                "cvss_score": cve.get("cvssScore", cve.get("cvss_score")),
                "cvss_severity": cve.get("cvssSeverity", cve.get("cvss_severity")),
                "cvss_vector": cve.get("cvssVector", cve.get("cvss_vector")),
                "epss_score": cve.get("epssScore", cve.get("epss_score")),
                "published": cve.get("publishedDate", cve.get("published")),
                "last_modified": cve.get("lastModifiedDate", cve.get("last_modified")),
                "affected_products": affected_products,
                "exploits": exploits,
                "advisories": advisories,
                "references": [
                    {"url": r.get("url"), "source": r.get("source")} for r in cve.get("references", [])[:20]
                ],
                "cwe": cve.get("cwe", []),
                "is_in_cisa_kev": cve.get("isInCISAKEV", cve.get("is_in_cisa_kev", False)),
                "cvedetails_url": f"https://www.cvedetails.com/cve/{entity_value}/",
            },
            ttl_hours=168,
        )

    async def check_health(self) -> bool:
        if not self.api_key:
            return False
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
            }
            async with self.http(timeout=5, headers=headers) as client:
                resp = await client.get(
                    f"{API_BASE}/vulnerability/search",
                    params={"cveId": "CVE-2021-44228"},
                )
                return resp.status_code == 200
        except httpx.HTTPError:
            return False
