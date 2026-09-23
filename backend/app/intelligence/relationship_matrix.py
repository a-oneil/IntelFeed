"""Semantic allowlist for EntityRelationship (source_type, verb, target_type) triples.

Every path that writes EntityRelationship rows (co-occurrence, AI extraction,
copilot tools, the REST API) must validate against this matrix. Types absent
as a source (country, ttp, vendor/product except catalog edges) are
target-only: countries are targeted or attribution anchors, TTPs are used,
vendors/products are targeted. CVE↔vendor/product affects-links live in
cve_affected, not here.

Symmetric ``related_to`` pairs store one canonical direction (the one listed
here) so the same association can't exist as two mirrored rows.
"""

ALLOWED_RELATIONSHIPS: frozenset[tuple[str, str, str]] = frozenset(
    {
        # threat_actor as source
        ("threat_actor", "uses", "malware"),
        ("threat_actor", "delivers", "malware"),
        ("threat_actor", "related_to", "malware"),
        ("threat_actor", "uses", "tool"),
        ("threat_actor", "uses", "ttp"),
        ("threat_actor", "exploits", "cve"),
        ("threat_actor", "targets", "country"),
        ("threat_actor", "attributed_to", "country"),
        ("threat_actor", "targets", "vendor"),
        ("threat_actor", "targets", "product"),
        ("threat_actor", "related_to", "threat_actor"),
        ("threat_actor", "communicates_with", "threat_actor"),
        ("threat_actor", "successor_of", "threat_actor"),
        ("threat_actor", "subgroup_of", "threat_actor"),
        ("threat_actor", "overlaps_with", "threat_actor"),
        # malware as source
        ("malware", "attributed_to", "threat_actor"),
        ("malware", "related_to", "threat_actor"),
        ("malware", "variant_of", "malware"),
        ("malware", "delivers", "malware"),
        ("malware", "drops", "malware"),
        ("malware", "communicates_with", "malware"),
        ("malware", "related_to", "malware"),
        ("malware", "successor_of", "malware"),
        ("malware", "overlaps_with", "malware"),
        ("malware", "uses", "tool"),
        ("malware", "related_to", "tool"),
        ("malware", "uses", "ttp"),
        ("malware", "exploits", "cve"),
        ("malware", "targets", "country"),
        ("malware", "targets", "vendor"),
        ("malware", "targets", "product"),
        # tool as source
        ("tool", "delivers", "malware"),
        ("tool", "related_to", "ttp"),
        ("tool", "exploits", "cve"),
        # cve as source (canonical direction for the symmetric cve↔ttp pair)
        ("cve", "related_to", "ttp"),
        # campaign as source (actor-like subject; used by copilot link tool)
        ("campaign", "attributed_to", "threat_actor"),
        ("campaign", "uses", "malware"),
        ("campaign", "uses", "tool"),
        ("campaign", "uses", "ttp"),
        ("campaign", "exploits", "cve"),
        ("campaign", "targets", "country"),
        ("campaign", "targets", "vendor"),
        ("campaign", "targets", "product"),
        # vendor/product catalog edges
        ("vendor", "related_to", "vendor"),
        ("vendor", "related_to", "product"),
        ("product", "related_to", "product"),
        # observable as target only — attribution claims onto the IOC ledger.
        # Deliberately NOT reachable from co-occurrence (observables are absent
        # from COOCCURRENCE_RELATIONSHIP_MAP): these edges enter only through
        # evidence-bearing paths (AI extraction with a sentence, the REST API,
        # copilot tools), which is the graph-bloat guard the ledger design
        # requires. Sightings themselves stay facts on entry_observables.
        ("threat_actor", "uses", "observable"),
        ("threat_actor", "communicates_with", "observable"),
        ("threat_actor", "controls", "observable"),
        ("malware", "uses", "observable"),
        ("malware", "communicates_with", "observable"),
        ("tool", "communicates_with", "observable"),
        ("campaign", "uses", "observable"),
    }
)


def is_allowed_relationship(source_type: str, relationship_type: str, target_type: str) -> bool:
    return (source_type, relationship_type, target_type) in ALLOWED_RELATIONSHIPS


def orient_relationship(source_type: str, relationship_type: str, target_type: str) -> tuple[str, str, str] | None:
    """Return the triple in its allowed orientation, or None if no orientation is valid.

    A reversed assertion (e.g. "cve exploits tool", "country attributed_to
    threat_actor") is flipped to the allowed direction rather than dropped.
    """
    if (source_type, relationship_type, target_type) in ALLOWED_RELATIONSHIPS:
        return source_type, relationship_type, target_type
    if (target_type, relationship_type, source_type) in ALLOWED_RELATIONSHIPS:
        return target_type, relationship_type, source_type
    return None


def allowed_verbs_for_pair(source_type: str, target_type: str) -> list[str]:
    """Verbs valid for source→target as stored, for error messages."""
    return sorted(rt for st, rt, tt in ALLOWED_RELATIONSHIPS if st == source_type and tt == target_type)


_CONFIDENCE_ORDER = ("possible", "probable", "confirmed")


def hidden_relationship_confidences() -> frozenset[str]:
    """Confidence levels hidden from display surfaces (profiles, graphs,
    timelines) per the ``relationship_min_confidence`` setting.

    Empty set = show everything (the default). Engine management views ignore
    this — they must show every stored edge.
    """
    from app.config import settings

    min_conf = str(settings.get("relationship_min_confidence") or "possible").lower()
    if min_conf not in _CONFIDENCE_ORDER:
        return frozenset()
    return frozenset(_CONFIDENCE_ORDER[: _CONFIDENCE_ORDER.index(min_conf)])
