"""GitHub PoC adapter — free (optional Bearer PAT for higher rate limits).

Searches GitHub for proof-of-concept exploit repositories for CVEs.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Context, Display, Egress, Job, License, Quota


class GitHubPoCAdapter(EnrichmentAdapter):
    source_type = "github_poc"
    display_name = "GitHub PoC"
    applies_to = {"cve": None}
    # GitHub's search API allows 10 requests a minute unauthenticated and 30
    # with a token (docs.github.com, "Rate limits for the REST API").
    quota = Quota(10, 60, daily_budget=1000, ceiling_per_period=10, keyed=Quota(30, 60, 1000, ceiling_per_period=30))
    egress = Egress.LOW
    # Shared GitHub PAT: lifts search from 10 to 30 requests/min.
    key_setting = "github_token"
    license = License("GitHub terms of service", attribution="GitHub")
    # GitHub answers its primary and secondary rate limits with 403 or 429.
    throttle_statuses = (403, 429, 503)
    jobs = (
        Job(
            "github-poc-scan",
            "app.workers.enrichment_tasks.run_github_poc_scan",
            {"type": "crontab", "minute": "0", "hour": "5"},
            "Scan GitHub for proof-of-concept exploits related to CVEs",
            settings_keys=("github_poc_batch_limit", "github_poc_rescan_days"),
        ),
    )
    outputs = (
        Context("exploit_maturity", "PoC", Display.BADGE, tones={"weaponized": "high", "poc": "medium"}),
        Context("poc_count", "Public PoCs", Display.FACT),
        Context(
            "poc_repos",
            "PoC repositories",
            Display.TABLE,
            item={"Repository": "name", "Link": "url", "Stars": "stars", "Language": "language"},
        ),
    )

    _api_url = "https://api.github.com/search/repositories"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        headers = {"Accept": "application/vnd.github+json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        query = f"{entity_value} poc exploit"

        async with self.http(timeout=15) as client:
            resp = await client.get(
                self._api_url,
                headers=headers,
                params={
                    "q": query,
                    "sort": "stars",
                    "order": "desc",
                    "per_page": 5,
                },
            )

            resp.raise_for_status()
            data = resp.json()

        items = data.get("items", [])
        total_count = data.get("total_count", 0)

        if not items:
            return EnrichmentData(
                raw_response=data,
                parsed_data={
                    "found": True,
                    "cve_id": entity_value,
                    "has_public_poc": False,
                    "poc_count": 0,
                    "poc_repos": [],
                    "exploit_maturity": "none",
                },
                ttl_hours=24,
            )

        # Determine exploit maturity based on star count and repo quality
        max_stars = max(item.get("stargazers_count", 0) for item in items)
        if max_stars >= 100:
            maturity = "weaponized"
        elif max_stars >= 10:
            maturity = "poc"
        else:
            maturity = "poc"

        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "found": True,
                "cve_id": entity_value,
                "has_public_poc": True,
                "poc_count": min(total_count, 100),
                "poc_repos": [
                    {
                        "name": item.get("name"),
                        "url": item.get("html_url"),
                        "stars": item.get("stargazers_count", 0),
                        "language": item.get("language"),
                        "created_at": item.get("created_at"),
                        "updated_at": item.get("updated_at"),
                        "description": (item.get("description") or "")[:200],
                    }
                    for item in items
                ],
                "exploit_maturity": maturity,
            },
            ttl_hours=24,
        )

    async def check_health(self) -> bool:
        try:
            headers = {"Accept": "application/vnd.github+json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            async with self.http(timeout=5) as client:
                resp = await client.get(
                    self._api_url,
                    headers=headers,
                    params={"q": "CVE-2021-44228 poc exploit", "per_page": 1},
                )
                return resp.status_code == 200
        except httpx.HTTPError:
            return False
