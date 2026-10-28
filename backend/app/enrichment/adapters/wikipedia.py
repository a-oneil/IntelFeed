"""Wikipedia enrichment adapter — auto-populates entity Wikipedia content on discovery."""

from __future__ import annotations

import logging

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.gateway import GatewayError
from app.enrichment.wikipedia_helper import extract_first_paragraph, fetch_wikipedia

logger = logging.getLogger(__name__)


class WikipediaAdapter(EnrichmentAdapter):
    source_type = "wikipedia"
    display_name = "Wikipedia"
    supported_entity_types = [
        "threat_actor",
        "malware",
        "tool",
        "country",
        "vendor",
        "product",
        "ttp",
        "mitigation",
        "cve",
        "cwe",
    ]
    requires_api_key = False
    default_trigger_mode = "auto"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        """Fetch Wikipedia content for an entity."""
        try:
            result = await fetch_wikipedia(entity_value, entity_type, transport=self.http_transport())
        except GatewayError:
            raise
        except Exception as e:
            logger.warning("Wikipedia fetch failed for %s/%s: %s", entity_type, entity_value, e)
            return EnrichmentData(
                raw_response={"error": str(e)},
                parsed_data={"found": False, "error": str(e)},
                ttl_hours=1,
            )

        if not result:
            return EnrichmentData(
                raw_response={"status": "not_found"},
                parsed_data={"found": False},
                ttl_hours=168,  # 7 days before retrying
            )

        # Topical guard (F11): don't hand back wrong-subject content (calendar
        # year, disambiguation, geography, unrelated bio) — a wrong description
        # anchors later AI resolution to the wrong identity.
        from app.intelligence.entity_resolution import enrichment_content_ok

        ok, reject_reason = enrichment_content_ok(entity_value, result["content"])
        if not ok:
            logger.warning(
                "Wikipedia content for %s/%s rejected by topical guard: %s", entity_type, entity_value, reject_reason
            )
            return EnrichmentData(
                raw_response={"status": "rejected", "reason": reject_reason, "url": result.get("url")},
                parsed_data={"found": False, "rejected": reject_reason},
                ttl_hours=720,  # don't refetch the same wrong article for a month
            )

        first_para = extract_first_paragraph(result["content"])

        return EnrichmentData(
            raw_response={
                "title": result["title"],
                "url": result["url"],
                "content": result["content"],
                "image_url": result.get("image_url"),
            },
            parsed_data={
                "found": True,
                "wikipedia_url": result["url"],
                "wikipedia_content": result["content"],
                "wikipedia_image_url": result.get("image_url"),
                "title": result["title"],
                "first_paragraph": first_para,
            },
            ttl_hours=720,  # 30 days — Wikipedia content is slow-changing
        )

    async def check_health(self) -> bool:
        """Verify Wikipedia API is reachable."""
        # fetch_wikipedia answers None for anything but a gateway refusal.
        return await fetch_wikipedia("Computer security", "ttp", transport=self.http_transport()) is not None
