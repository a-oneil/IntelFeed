"""NVD API 2.0 adapter — free (optional API key for higher rate limits).

Provides CVE details, CVSS scores, references, and affected products.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Column, Context, Display, Egress, Job, License, Policy, Quota


class NVDAdapter(EnrichmentAdapter):
    source_type = "nvd"
    display_name = "NVD API 2.0"
    about = "The US National Vulnerability Database: NIST's CVSS score, weaknesses and affected products for a CVE."
    applies_to = {"cve": None}
    # NVD allows 50 requests per rolling 30 s with an API key and 5 without
    # (nvd.nist.gov/developers/start-here). The gateway keeps every caller,
    # jobs included, inside the window.
    quota = Quota(
        5, 30, daily_budget=5000, ceiling_per_period=5, concurrency=1, keyed=Quota(50, 30, 5000, ceiling_per_period=50)
    )
    egress = Egress.LOW
    key_setting = "nvd_api_key"
    license = License(
        "NVD terms of use", attribution="This product uses the NVD API but is not endorsed or certified by the NVD."
    )
    default_trigger_mode = "auto"
    # NVD answers 403 as well as 429 when a client exceeds its rolling window.
    throttle_statuses = (403, 429, 503)
    jobs = (
        Job(
            "cve-nvd-refresh",
            "app.workers.enrichment_tasks.run_cve_nvd_refresh",
            {"type": "crontab", "minute": "0", "hour": "*"},
            "Apply every NVD record changed since the last run (CVSS score changes) to existing CVEs",
        ),
        Job(
            "cve-nvd-backfill",
            "app.workers.enrichment_tasks.run_cve_nvd_backfill",
            {"type": "crontab", "minute": "30", "hour": "1"},
            "Backfill NVD data (CVSS, description, affected products, references) for CVEs missing it",
        ),
        Job(
            "reenrich-cve-nvd",
            "app.workers.maintenance.reenrich_cve_nvd",
            {"type": "crontab", "minute": "5", "hour": "3"},
            "Re-fetch NVD data for CVEs missing it (bulk-imported or awaiting NVD analysis)",
            settings_keys=("cve_reenrich_batch_size",),
        ),
    )
    outputs = (
        # NVD's score ranks first (NVD > CNA > CISA-ADP): it replaces a
        # CNA's or CISA's, and the severity goes with it. The description
        # ranks with the CNA's (NVD republishes it), ahead of Wikipedia's.
        Column("cvss_score", "cve.cvss_score", Policy.RANK, rank=1),
        Column("cvss_severity", "cve.severity", follows="cve.cvss_score"),
        Column("description", "cve.description", Policy.RANK, rank=1),
        Context("cvss_vector", "CVSS vector", Display.FACT),
        Context("published", "Published", Display.FACT),
        Context("last_modified", "Last modified", Display.FACT),
        Context("weaknesses", "Weaknesses", Display.CHIPS),
        Context("references", "References", Display.TABLE, item={"Source": "source", "Link": "url"}),
    )

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        async with self.http(timeout=15) as client:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": entity_value},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return EnrichmentData(
                raw_response=data,
                parsed_data={"found": False},
                ttl_hours=168,  # 1 week for NVD data
            )
        from app.intelligence.cve import parse_nvd_record

        record = parse_nvd_record(vulnerabilities[0].get("cve", {}))
        return EnrichmentData(raw_response=data, parsed_data=parsed(record), ttl_hours=168)

    @staticmethod
    async def apply_record(db, entity_type: str, entity_id, data: EnrichmentData, cache: dict) -> None:
        """A lookup's extra writes: the record, affected products, references
        and their cve_affected / cve_weaknesses links (``apply_nvd_record``).
        A sweep's answer (``nvd_result``) carries no record here; the sweep
        writes it itself."""
        from app.intelligence.cve import adopt_nvd_values, apply_nvd_record, parse_nvd_record
        from app.models.cve import CVE

        vulnerabilities = (data.raw_response or {}).get("vulnerabilities") or []
        record = vulnerabilities[0].get("cve") if vulnerabilities else None
        if entity_type != "cve" or not record:
            return
        cve = await db.get(CVE, entity_id)
        if cve is not None:
            # Claim the values NVD wrote before claims existed, read from the
            # stored nvd_data, so the field map may update them.
            await adopt_nvd_values(db, cve)
            await apply_nvd_record(db, cve, parse_nvd_record(record), cache)

    async def check_health(self) -> bool:
        """One lookup with the key in use, so a key test tests the key: NVD
        answers 404 to a key it doesn't know, which is a rejection."""
        from app.enrichment.gateway import AuthFailed

        try:
            async with self.http(timeout=5) as client:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": "CVE-2021-44228"},
                    headers={"apiKey": self.api_key} if self.api_key else {},
                )
        except httpx.HTTPError:
            return False
        if resp.status_code == 404 and self.api_key:
            raise AuthFailed("NVD doesn't know this key")
        return resp.status_code == 200


def parsed(nvd: dict) -> dict:
    """An NVD answer (``parse_nvd_record``'s values) as the source's parsed_data."""
    record = nvd.get("nvd_data") or {}
    score = nvd.get("cvss_score")
    return {
        "cve_id": record.get("id"),
        "description": nvd.get("description"),
        "cvss_score": score,
        "cvss_severity": nvd.get("severity") if score is not None else None,
        "cvss_vector": nvd.get("cvss_vector"),
        "published": record.get("published"),
        "last_modified": record.get("lastModified"),
        "references": [
            {"url": r.get("url"), "source": r.get("source"), "tags": r.get("tags") or []}
            for r in (nvd.get("references") or [])[:20]
        ],
        "weaknesses": [
            w.get("description", [{}])[0].get("value") for w in record.get("weaknesses", []) if w.get("description")
        ],
    }


def nvd_result(nvd: dict, via: str = "job") -> EnrichmentData:
    """A sweep's NVD answer (``enrich_from_nvd``) as the source's result. The
    raw response names the sweep instead of repeating the record, which
    ``cves.nvd_data`` holds."""
    record = nvd.get("nvd_data") or {}
    return EnrichmentData(raw_response={"via": via, "id": record.get("id")}, parsed_data=parsed(nvd), ttl_hours=168)
