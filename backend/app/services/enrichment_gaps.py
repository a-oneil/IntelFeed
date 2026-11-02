"""The entity fields AI gap research can fill.

``POST /admin/hygiene/enrichment-gaps/enrich`` takes an (entity_type, field)
pair from here, finds the entities missing the field and sends them to the
AI researcher (``app.workers.entity_maintenance_tasks``, which holds the
matching ``_GAP_FIELD_GUIDANCE`` entry for every pair). The Enrichment
console's coverage view offers AI research for a column only when its pair
is listed here.

Each spec names the model, the condition that means the field is missing, the
order the entities are offered in (most-cited first) and the column whose
value is the entity's name for the researcher.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, or_

from app import entity_types
from app.models.cve import CVE
from app.models.malware_family import MalwareFamily
from app.models.product import Product
from app.models.threat_actor import ThreatActor

ENRICH_GAP_SPECS: dict[tuple[str, str], dict[str, Any]] = {
    (entity_types.THREAT_ACTOR, "mitre_id"): {
        "model": ThreatActor,
        "condition": lambda: ThreatActor.mitre_id.is_(None),
        "order": lambda: ThreatActor.article_count.desc(),
        "name_attr": "name",
    },
    (entity_types.THREAT_ACTOR, "country"): {
        "model": ThreatActor,
        "condition": lambda: ThreatActor.origin_country_id.is_(None),
        "order": lambda: ThreatActor.article_count.desc(),
        "name_attr": "name",
    },
    (entity_types.THREAT_ACTOR, "motivation"): {
        "model": ThreatActor,
        "condition": lambda: ThreatActor.motivation.is_(None),
        "order": lambda: ThreatActor.article_count.desc(),
        "name_attr": "name",
    },
    (entity_types.THREAT_ACTOR, "description"): {
        "model": ThreatActor,
        "condition": lambda: or_(ThreatActor.description.is_(None), func.length(ThreatActor.description) < 80),
        "order": lambda: ThreatActor.article_count.desc(),
        "name_attr": "name",
    },
    (entity_types.MALWARE, "malware_type"): {
        "model": MalwareFamily,
        "condition": lambda: MalwareFamily.malware_type.is_(None),
        "order": lambda: MalwareFamily.article_count.desc(),
        "name_attr": "name",
    },
    (entity_types.MALWARE, "description"): {
        "model": MalwareFamily,
        "condition": lambda: or_(MalwareFamily.description.is_(None), func.length(MalwareFamily.description) < 80),
        "order": lambda: MalwareFamily.article_count.desc(),
        "name_attr": "name",
    },
    (entity_types.PRODUCT, "vendor_id"): {
        "model": Product,
        "condition": lambda: Product.vendor_id.is_(None),
        "order": lambda: Product.article_count.desc(),
        "name_attr": "name",
    },
    (entity_types.CVE, "cvss"): {
        "model": CVE,
        "condition": lambda: CVE.cvss_score.is_(None),
        "order": lambda: CVE.id.desc(),
        "name_attr": "cve_id",
    },
}
