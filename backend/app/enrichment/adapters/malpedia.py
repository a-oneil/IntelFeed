"""Malpedia adapter — free (optional API key for higher access).

Provides malware family and threat actor intelligence from Fraunhofer FKIE's Malpedia database.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData


class MalpediaAdapter(EnrichmentAdapter):
    source_type = "malpedia"
    display_name = "Malpedia"
    supported_entity_types = ["malware", "tool", "threat_actor"]
    requires_api_key = False
    default_trigger_mode = "scheduled"

    _api_base = "https://malpedia.caad.fkie.fraunhofer.de/api/"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"apitoken {self.api_key}"

        # Malpedia files offensive tooling (Cobalt Strike, Mimikatz) under the
        # same "family" namespace as malware, so tools use the same lookup.
        if entity_type in ("malware", "tool"):
            return await self._enrich_malware(entity_value, headers)
        elif entity_type == "threat_actor":
            return await self._enrich_actor(entity_value, headers)

        return EnrichmentData(
            raw_response={},
            parsed_data={"found": False},
            ttl_hours=168,
        )

    async def _enrich_malware(self, family_name: str, headers: dict) -> EnrichmentData:
        # Normalize name for Malpedia URL format (lowercase, underscores)
        normalized = family_name.lower().replace(" ", "_").replace("-", "_")

        async with httpx.AsyncClient(timeout=15) as client:
            # Try to get family info
            resp = await client.get(
                f"{self._api_base}get/family/{normalized}",
                headers=headers,
            )

            if resp.status_code == 404:
                # Try listing all families and searching
                list_resp = await client.get(
                    f"{self._api_base}list/families",
                    headers=headers,
                )
                if list_resp.status_code == 200:
                    families = list_resp.json()
                    name_lower = family_name.lower()
                    for fam_key in families:
                        if name_lower in fam_key.lower():
                            resp = await client.get(
                                f"{self._api_base}get/family/{fam_key}",
                                headers=headers,
                            )
                            break
                    else:
                        return EnrichmentData(
                            raw_response={"status": "not_found"},
                            parsed_data={"found": False},
                            ttl_hours=168,
                        )

            if resp.status_code != 200:
                return EnrichmentData(
                    raw_response={"status": resp.status_code},
                    parsed_data={"found": False},
                    ttl_hours=168,
                )

            data = resp.json()

        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "found": True,
                "family_name": data.get("common_name", family_name),
                "description": (data.get("description") or "")[:2000],
                "alt_names": data.get("alt_names", []),
                "attribution": data.get("attribution", []),
                "urls": (data.get("urls") or [])[:10],  # plain URL strings
                "malpedia_url": data.get("malpedia_url"),
            },
            ttl_hours=168,
        )

    async def _enrich_actor(self, actor_name: str, headers: dict) -> EnrichmentData:
        normalized = actor_name.lower().replace(" ", "_").replace("-", "_")

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{self._api_base}get/actor/{normalized}",
                headers=headers,
            )

            if resp.status_code == 404:
                # Try listing actors and searching
                list_resp = await client.get(
                    f"{self._api_base}list/actors",
                    headers=headers,
                )
                if list_resp.status_code == 200:
                    actors = list_resp.json()
                    name_lower = actor_name.lower()
                    for actor_key in actors:
                        if name_lower in actor_key.lower():
                            resp = await client.get(
                                f"{self._api_base}get/actor/{actor_key}",
                                headers=headers,
                            )
                            break
                    else:
                        return EnrichmentData(
                            raw_response={"status": "not_found"},
                            parsed_data={"found": False},
                            ttl_hours=168,
                        )

            if resp.status_code != 200:
                return EnrichmentData(
                    raw_response={"status": resp.status_code},
                    parsed_data={"found": False},
                    ttl_hours=168,
                )

            data = resp.json()

        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "found": True,
                "actor_name": data.get("value", actor_name),
                "description": (data.get("description") or "")[:2000],
                "alt_names": data.get("meta", {}).get("synonyms", []),
                "country": data.get("meta", {}).get("country"),
                "refs": data.get("meta", {}).get("refs", [])[:10],
                # Malpedia keys an actor's families by family id ("win.wannacryptor").
                "families": list(data.get("families") or {})[:20],
            },
            ttl_hours=168,
        )

    async def check_health(self) -> bool:
        try:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"apitoken {self.api_key}"
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(
                    f"{self._api_base}list/families",
                    headers=headers,
                )
                return resp.status_code == 200
        except Exception:
            return False
