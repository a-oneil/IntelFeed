"""MITRE ATT&CK adapter — free, no API key.

Provides technique details, group mappings, software information, and mitigation details.
Uses the MITRE ATT&CK STIX data from GitHub.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/refs/heads/master/enterprise-attack/enterprise-attack.json"
)


class MITREAttackAdapter(EnrichmentAdapter):
    source_type = "mitre_attack"
    display_name = "MITRE ATT&CK"
    supported_entity_types = ["ttp", "threat_actor", "malware", "tool", "mitigation"]
    requires_api_key = False
    default_trigger_mode = "scheduled"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        async with self.http(timeout=60) as client:
            resp = await client.get(ATTACK_URL)
            resp.raise_for_status()
            bundle = resp.json()

        objects = bundle.get("objects", [])

        if entity_type == "ttp":
            return self._enrich_technique(entity_value, objects)
        elif entity_type == "threat_actor":
            return self._enrich_group(entity_value, objects)
        elif entity_type in ("malware", "tool"):
            # _enrich_software scans both STIX `malware` and `tool` objects
            return self._enrich_software(entity_value, objects)
        elif entity_type == "mitigation":
            return self._enrich_mitigation(entity_value, objects)

        return EnrichmentData(
            raw_response={},
            parsed_data={"found": False},
            ttl_hours=168,
        )

    def _enrich_technique(self, technique_id: str, objects: list) -> EnrichmentData:
        # Find attack-pattern with matching external_id
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id") == technique_id:
                    return EnrichmentData(
                        raw_response=obj,
                        parsed_data={
                            "technique_id": technique_id,
                            "name": obj.get("name"),
                            "description": (obj.get("description") or "")[:2000],
                            "kill_chain_phases": [p.get("phase_name") for p in obj.get("kill_chain_phases", [])],
                            "platforms": obj.get("x_mitre_platforms", []),
                            "data_sources": obj.get("x_mitre_data_sources", []),
                            "detection": (obj.get("x_mitre_detection") or "")[:1000],
                            "url": next(
                                (r["url"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                                None,
                            ),
                            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                        },
                        ttl_hours=168,
                    )

        return EnrichmentData(
            raw_response={},
            parsed_data={"found": False},
            ttl_hours=168,
        )

    def _enrich_group(self, group_name: str, objects: list) -> EnrichmentData:
        name_lower = group_name.lower()
        for obj in objects:
            if obj.get("type") != "intrusion-set":
                continue
            if obj.get("name", "").lower() == name_lower:
                aliases = obj.get("aliases", [])
                ext_refs = obj.get("external_references", [])
                mitre_id = next(
                    (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                    None,
                )
                return EnrichmentData(
                    raw_response=obj,
                    parsed_data={
                        "name": obj.get("name"),
                        "mitre_id": mitre_id,
                        "aliases": aliases,
                        "description": (obj.get("description") or "")[:2000],
                        "url": next(
                            (r["url"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                            None,
                        ),
                    },
                    ttl_hours=168,
                )
            # Check aliases
            for alias in obj.get("aliases", []):
                if alias.lower() == name_lower:
                    ext_refs = obj.get("external_references", [])
                    mitre_id = next(
                        (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                        None,
                    )
                    return EnrichmentData(
                        raw_response=obj,
                        parsed_data={
                            "name": obj.get("name"),
                            "mitre_id": mitre_id,
                            "aliases": obj.get("aliases", []),
                            "description": (obj.get("description") or "")[:2000],
                            "matched_alias": alias,
                        },
                        ttl_hours=168,
                    )

        return EnrichmentData(
            raw_response={},
            parsed_data={"found": False},
            ttl_hours=168,
        )

    def _enrich_software(self, software_name: str, objects: list) -> EnrichmentData:
        name_lower = software_name.lower()
        for obj in objects:
            if obj.get("type") not in ("malware", "tool"):
                continue
            if obj.get("name", "").lower() == name_lower:
                ext_refs = obj.get("external_references", [])
                return EnrichmentData(
                    raw_response=obj,
                    parsed_data={
                        "name": obj.get("name"),
                        "type": obj.get("type"),
                        "description": (obj.get("description") or "")[:2000],
                        "platforms": obj.get("x_mitre_platforms", []),
                        "aliases": obj.get("x_mitre_aliases", []),
                        "url": next(
                            (r["url"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                            None,
                        ),
                    },
                    ttl_hours=168,
                )

        return EnrichmentData(
            raw_response={},
            parsed_data={"found": False},
            ttl_hours=168,
        )

    def _enrich_mitigation(self, mitigation_value: str, objects: list) -> EnrichmentData:
        """Find a course-of-action by M-ID or name, and resolve mitigated TTPs."""
        value_lower = mitigation_value.lower()
        is_mid = value_lower.startswith("m") and value_lower[1:].isdigit()

        # Build STIX ID index for relationship resolution
        id_to_obj: dict[str, dict] = {}
        relationships: list[dict] = []
        for obj in objects:
            obj_type = obj.get("type", "")
            if obj.get("id"):
                id_to_obj[obj["id"]] = obj
            if obj_type == "relationship":
                relationships.append(obj)

        # Find the course-of-action
        coa_obj = None
        for obj in objects:
            if obj.get("type") != "course-of-action" or obj.get("revoked", False):
                continue
            ext_refs = obj.get("external_references", [])

            if is_mid:
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").lower() == value_lower:
                        coa_obj = obj
                        break
            else:
                if obj.get("name", "").lower() == value_lower:
                    coa_obj = obj

            if coa_obj:
                break

        if not coa_obj:
            return EnrichmentData(
                raw_response={},
                parsed_data={"found": False},
                ttl_hours=168,
            )

        ext_refs = coa_obj.get("external_references", [])
        mitre_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            None,
        )
        mitre_url = next(
            (r["url"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            None,
        )

        # Resolve TTPs this mitigation addresses via relationship objects
        coa_stix_id = coa_obj["id"]
        mitigated_ttps = []
        for rel in relationships:
            if rel.get("relationship_type") != "mitigates":
                continue
            if rel.get("source_ref") != coa_stix_id:
                continue
            target = id_to_obj.get(rel.get("target_ref", ""))
            if not target or target.get("type") != "attack-pattern":
                continue
            target_refs = target.get("external_references", [])
            tid = next(
                (r["external_id"] for r in target_refs if r.get("source_name") == "mitre-attack"),
                None,
            )
            if tid:
                mitigated_ttps.append(
                    {
                        "technique_id": tid,
                        "technique_name": target.get("name", tid),
                    }
                )

        return EnrichmentData(
            raw_response=coa_obj,
            parsed_data={
                "mitre_id": mitre_id,
                "name": coa_obj.get("name"),
                "description": (coa_obj.get("description") or "")[:2000],
                "url": mitre_url,
                "mitigated_ttps": mitigated_ttps,
            },
            ttl_hours=168,
        )

    async def check_health(self) -> bool:
        try:
            async with self.http(timeout=10) as client:
                resp = await client.head(ATTACK_URL)
                return resp.status_code == 200
        except httpx.HTTPError:
            return False
