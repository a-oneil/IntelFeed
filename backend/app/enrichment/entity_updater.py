"""Propagate enrichment results to entity model fields."""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.claim_provenance import record_claim

logger = logging.getLogger(__name__)

# Lazy model imports to avoid circular dependencies
_MODEL_MAP: dict | None = None


def _get_model_map() -> dict:
    global _MODEL_MAP
    if _MODEL_MAP is None:
        from app.models.country import Country
        from app.models.cve import CVE
        from app.models.cwe import CWE
        from app.models.malware_family import MalwareFamily
        from app.models.mitigation import Mitigation
        from app.models.observable import Observable
        from app.models.product import Product
        from app.models.threat_actor import ThreatActor
        from app.models.tool import Tool
        from app.models.ttp import TTP
        from app.models.vendor import Vendor

        _MODEL_MAP = {
            "observable": Observable,
            "threat_actor": ThreatActor,
            "malware": MalwareFamily,
            "cve": CVE,
            "ttp": TTP,
            "country": Country,
            "tool": Tool,
            "vendor": Vendor,
            "product": Product,
            "mitigation": Mitigation,
            "cwe": CWE,
        }
    return _MODEL_MAP


async def apply_wikipedia_to_entity(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    parsed_data: dict,
) -> bool:
    """Copy Wikipedia enrichment data to entity model fields.

    Sets wikipedia_url, wikipedia_content, and optionally description (if empty).
    Returns True if the entity was updated, False if not found or unsupported type.
    """
    model_map = _get_model_map()
    model_cls = model_map.get(entity_type)
    if not model_cls:
        return False

    result = await db.execute(select(model_cls).where(model_cls.id == entity_id))
    entity = result.scalar_one_or_none()
    if not entity:
        return False

    entity.wikipedia_url = parsed_data.get("wikipedia_url")
    entity.wikipedia_content = parsed_data.get("wikipedia_content")
    entity.wikipedia_image_url = parsed_data.get("wikipedia_image_url")

    # Auto-populate description from first paragraph if empty
    if hasattr(entity, "description") and not entity.description:
        first_para = parsed_data.get("first_paragraph")
        if first_para:
            entity.description = first_para
            await record_claim(
                db,
                entity_type=entity_type,
                entity_id=entity_id,
                field="description",
                value=first_para,
                source_kind="enrichment",
                source_ref="wikipedia",
            )

    db.add(entity)
    return True


# Sources we trust to fill the free-form `description` column, in priority
# order. Wikipedia first because its first paragraph is human-curated prose;
# MITRE ATT&CK and Malpedia are written by security researchers and are
# reliable but more technical.
_DESCRIPTION_SOURCE_ORDER = ("wikipedia", "mitre_attack", "malpedia")
# Aliases and platforms come from the reference catalogs, not Wikipedia — MITRE
# first because its alias lists are curated per software/group.
_ALIAS_SOURCES = (("mitre_attack", "aliases"), ("malpedia", "alt_names"))
_PLATFORM_SOURCES = ("mitre_attack",)


#: Shodan tags that name dual-use infrastructure → the ledger's infra_tag.
_SHODAN_TAG_TO_INFRA = {"vpn": "vpn", "proxy": "proxy", "tor": "tor"}


def _apply_observable_reputation(obs, by_source: dict[str, dict]) -> bool:
    """Fold VirusTotal / GreyNoise / Shodan results into ``Observable.reputation``
    and fill ``infra_tag`` when the reputation says the host is dual-use:
    Shodan ``vpn`` / ``proxy`` / ``tor`` tags, or GreyNoise RIOT (a known
    benign business service → ``benign_service``). Tags are fill-only, like
    every other door's."""
    from datetime import UTC, datetime

    summary: dict = dict(obs.reputation or {})
    vt = by_source.get("virustotal") or {}
    gn = by_source.get("greynoise") or {}
    sh = by_source.get("shodan") or {}
    if vt:
        summary.update(
            {
                k: v
                for k, v in {
                    "vt_ratio": vt.get("detection_ratio"),
                    "vt_malicious": vt.get("malicious_votes"),
                    "vt_threat_label": vt.get("threat_label"),
                    "vt_tags": vt.get("tags"),
                    "asn": vt.get("asn") or summary.get("asn"),
                    "as_owner": vt.get("as_owner") or summary.get("as_owner"),
                    "country": vt.get("country") or summary.get("country"),
                }.items()
                if v not in (None, "", [])
            }
        )
    if gn:
        summary.update(
            {
                k: v
                for k, v in {
                    "gn_classification": gn.get("classification"),
                    "gn_noise": gn.get("noise"),
                    "gn_riot": gn.get("riot"),
                    "gn_name": gn.get("name"),
                }.items()
                if v not in (None, "")
            }
        )
    if sh:
        summary.update(
            {
                k: v
                for k, v in {
                    "ports": sh.get("ports"),
                    "hostnames": sh.get("hostnames"),
                    "shodan_tags": sh.get("tags"),
                    "vulns": sh.get("vulns"),
                }.items()
                if v not in (None, "", [])
            }
        )
    if not (vt or gn or sh):
        return False
    summary["enriched_at"] = datetime.now(UTC).isoformat()
    obs.reputation = summary

    if not obs.infra_tag:
        shodan_tags = str(sh.get("tags") or "").lower()
        for tag, infra in _SHODAN_TAG_TO_INFRA.items():
            if tag in [t.strip() for t in shodan_tags.split(",")]:
                obs.infra_tag = infra
                break
        if not obs.infra_tag and gn.get("riot") is True:
            obs.infra_tag = "benign_service"
    return True


async def apply_enrichment_results_to_entity(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    results: list[dict],
) -> bool:
    """Propagate the best available enrichment data into entity columns.

    Today this covers:
      - Wikipedia: wikipedia_url / wikipedia_content / wikipedia_image_url
        and the `description` column from `first_paragraph` (if empty)
      - MITRE ATT&CK: `description` (if empty), `mitre_id` for
        threat_actor / malware / tool, `platforms`, and `aliases`
      - Malpedia: `description` (if empty), `malpedia_url`, `github_url`
        (first github.com reference), `aliases`, and actor `country`

    Everything except aliases is fill-blanks-only; aliases are unioned in so a
    curated list is never replaced.

    Each enrichment-result entry should look like:
      {"source_type": "...", "status": "success"|"cached", "parsed_data": {...}}

    Returns True if any field on the entity was actually changed.
    """
    model_map = _get_model_map()
    model_cls = model_map.get(entity_type)
    if not model_cls:
        return False

    entity = (await db.execute(select(model_cls).where(model_cls.id == entity_id))).scalar_one_or_none()
    if not entity:
        return False

    # Index results by source for prioritized lookup. Cached results carry
    # parsed_data too, so they're equivalent to fresh successes for write-back.
    by_source: dict[str, dict] = {}
    for r in results:
        if r.get("status") not in ("success", "cached"):
            continue
        src = r.get("source_type")
        data = r.get("parsed_data") or {}
        if not src or not isinstance(data, dict):
            continue
        # First write wins — pipeline returns sources in DB order; if the same
        # source somehow appears twice, the first entry is the freshest.
        by_source.setdefault(src, data)

    changed = False
    # (field, value, source_ref) for every column this pass actually filled, so
    # the profile can name which adapter asserted each one. Collected as we go
    # and written once at the end — a failed audit write must not cost the fill.
    claimed: list[tuple[str, object, str]] = []

    if entity_type == "observable":
        return _apply_observable_reputation(entity, by_source)

    # Wikipedia has its own dedicated columns
    wiki = by_source.get("wikipedia")
    if wiki:
        if wiki.get("wikipedia_url") and entity.wikipedia_url != wiki.get("wikipedia_url"):
            entity.wikipedia_url = wiki.get("wikipedia_url")
            entity.wikipedia_content = wiki.get("wikipedia_content")
            entity.wikipedia_image_url = wiki.get("wikipedia_image_url")
            changed = True

    # Description: only fill when the entity doesn't already have a real one.
    # Honors the source priority above so we don't clobber a Wikipedia paragraph
    # with a MITRE technical blurb just because both arrived in the same batch.
    if hasattr(entity, "description") and not (entity.description or "").strip():
        for src in _DESCRIPTION_SOURCE_ORDER:
            data = by_source.get(src)
            if not data:
                continue
            # Wikipedia uses `first_paragraph`; the others use `description`.
            candidate = (data.get("first_paragraph") if src == "wikipedia" else data.get("description")) or ""
            candidate = candidate.strip()
            if candidate:
                entity.description = candidate
                changed = True
                claimed.append(("description", candidate, src))
                break

    # MITRE ID — only on entities that have the column (threat_actor, malware,
    # tool). Adapters spell it either `mitre_id` or, for software, `url`-adjacent
    # `external_id`; accept both.
    if hasattr(entity, "mitre_id") and not (entity.mitre_id or "").strip():
        mitre_data = by_source.get("mitre_attack")
        if mitre_data:
            mid = (mitre_data.get("mitre_id") or mitre_data.get("external_id") or "").strip()
            if mid:
                entity.mitre_id = mid
                changed = True
                claimed.append(("mitre_id", mid, "mitre_attack"))

    # Malpedia URL — the adapter has always returned it; nothing used to store
    # it, which is why every malware and tool profile's References panel (gated
    # on this field) silently failed to render.
    malpedia = by_source.get("malpedia")
    if hasattr(entity, "malpedia_url") and not (entity.malpedia_url or "").strip() and malpedia:
        url = (malpedia.get("malpedia_url") or "").strip()
        if url:
            entity.malpedia_url = url
            changed = True

    # GitHub URL — Malpedia's reference list is the only place we already see
    # one for tooling. Take the first github.com link it reports.
    if hasattr(entity, "github_url") and not (entity.github_url or "").strip() and malpedia:
        for ref in malpedia.get("urls") or []:
            url = (ref.get("url") if isinstance(ref, dict) else ref) or ""
            if "github.com/" in url:
                entity.github_url = url
                changed = True
                break

    # Aliases — union in, never replace, so analyst-curated lists survive.
    # Everything goes through filter_aliases first: these lists feed the
    # autolinker vocabulary, and an unfiltered dictionary-word alias is how the
    # false-positive link epidemic started.
    if hasattr(entity, "aliases"):
        from app.intelligence.autolinker import filter_aliases

        name = getattr(entity, "name", "") or ""
        existing = list(entity.aliases or [])
        seen = {a.casefold() for a in existing} | {name.casefold()}
        incoming: list[str] = []
        for src, key in _ALIAS_SOURCES:
            incoming.extend(a for a in (by_source.get(src) or {}).get(key) or [] if isinstance(a, str))
        added = [a for a in filter_aliases(incoming, name) if a.casefold() not in seen and not seen.add(a.casefold())]
        if added:
            entity.aliases = existing + added
            changed = True
            claimed.append(("aliases", added, "mitre_attack/malpedia"))

    # Platforms — catalog truth, fill only when blank.
    if hasattr(entity, "platforms") and not (entity.platforms or []):
        for src in _PLATFORM_SOURCES:
            platforms = [p for p in (by_source.get(src) or {}).get("platforms") or [] if isinstance(p, str)]
            if platforms:
                entity.platforms = platforms
                changed = True
                break

    # Origin country for actors — Malpedia records attribution.
    if hasattr(entity, "country") and not (entity.country or "").strip() and malpedia:
        country = (malpedia.get("country") or "").strip()
        if country:
            entity.country = country
            changed = True
            claimed.append(("country", country, "malpedia"))

    if changed:
        db.add(entity)
    for field, value, source_ref in claimed:
        await record_claim(
            db,
            entity_type=entity_type,
            entity_id=entity_id,
            field=field,
            value=value,
            source_kind="enrichment",
            source_ref=source_ref,
        )
    return changed
