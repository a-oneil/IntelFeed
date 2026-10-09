"""Markdown export for entity profiles.

Renders a "rich" markdown document for any intelligence entity — its own
fields plus related entities (via the correlation pivot) and the articles that
mention it. Reused by the single-profile and bulk (ZIP) export endpoints.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.correlation import VALID_ENTITY_TYPES, pivot_from_entity

# Human-readable label for the subject entity's own type.
ENTITY_TYPE_LABELS: dict[str, str] = {
    "threat_actor": "Threat Actor",
    "malware": "Malware Family",
    "cve": "CVE",
    "cwe": "Weakness",
    "ttp": "ATT&CK Technique",
    "country": "Country",
    "sector": "Sector",
    "tool": "Offensive Tool",
    "mitigation": "Mitigation",
    "vendor": "Vendor",
    "product": "Product",
}

# The pivot groups related entities under `<related_type>s` keys.
RELATED_SECTION_LABELS: dict[str, str] = {
    "threat_actors": "Threat Actors",
    "malwares": "Malware",
    "cves": "CVEs",
    "cwes": "Weaknesses",
    "ttps": "ATT&CK Techniques",
    "countrys": "Countries",
    "sectors": "Sectors",
    "mitigations": "Mitigations",
    "tools": "Offensive Tools",
    "vendors": "Vendors",
    "products": "Products",
    "detection_rules": "Detection Rules",
}


def _entity_name(entity: dict) -> str:
    """Display name from a serialized entity dict."""
    et = entity.get("type")
    if et == "cve":
        return entity.get("cve_id") or "CVE"
    if et == "ttp":
        tid = entity.get("technique_id") or ""
        tname = entity.get("technique_name")
        if tname and tname != tid:
            return f"{tid} {tname}".strip()
        return tid or "Technique"
    return entity.get("name") or "Unknown"


def safe_filename(name: str) -> str:
    """Filesystem-safe base for a markdown filename (no extension)."""
    cleaned = "".join(c if c.isalnum() or c in " -_." else "-" for c in name)
    cleaned = cleaned.strip().strip(".")[:80]
    return cleaned or "entity"


def _fmt_date(iso: str | None) -> str:
    """Date portion of an ISO timestamp, or an em-dash."""
    if not iso:
        return "—"
    return iso[:10]


def _identity_meta(entity: dict) -> list[tuple[str, str]]:
    """Type-specific (label, value) header fields."""
    et = entity.get("type")
    meta: list[tuple[str, str]] = []

    def add(label: str, value) -> None:
        if value is None or value == "" or value == []:
            return
        meta.append((label, str(value)))

    if et == "threat_actor":
        add("MITRE ID", entity.get("mitre_id"))
        add("Country", entity.get("country"))
        add("Motivation", entity.get("motivation"))
    elif et == "malware":
        add("Malware Type", entity.get("malware_type"))
    elif et == "cve":
        add("Severity", (entity.get("severity") or "").upper() or None)
        add("CVSS", entity.get("cvss_score"))
        epss = entity.get("epss_score")
        if epss is not None:
            add("EPSS", f"{epss * 100:.1f}%")
        add("Risk Tier", (entity.get("risk_tier") or "").upper() or None)
        if entity.get("is_kev"):
            kev = "Yes"
            if entity.get("kev_date_added"):
                kev += f" (added {_fmt_date(entity['kev_date_added'])})"
            add("CISA KEV", kev)
        add("Exploit Availability", entity.get("exploit_availability"))
        if entity.get("metasploit_module"):
            add("Metasploit", entity.get("metasploit_module"))
        if entity.get("github_poc_count"):
            add("Public PoCs", entity.get("github_poc_count"))
    elif et == "ttp":
        tactics = entity.get("tactics") or ([entity["tactic"]] if entity.get("tactic") else [])
        add("Tactic", ", ".join(tactics) if tactics else None)
        add("Platforms", ", ".join(entity.get("platforms") or []) or None)
        add("Data Sources", ", ".join(entity.get("data_sources") or []) or None)
        if entity.get("is_subtechnique"):
            add("Sub-technique", "Yes")
        if entity.get("is_deprecated"):
            add("Deprecated", "Yes")
        add("MITRE", entity.get("mitre_url"))
    elif et == "country":
        add("ISO Code", entity.get("iso_code"))
        add("Region", entity.get("region"))
    elif et == "sector":
        add("Slug", entity.get("slug"))
    elif et == "tool":
        add("Tool Type", (entity.get("tool_type") or "").replace("_", " ") or None)
        add("Platforms", ", ".join(entity.get("platforms") or []) or None)
        add("Malpedia", entity.get("malpedia_url"))
        add("GitHub", entity.get("github_url"))
    elif et == "mitigation":
        add("MITRE ID", entity.get("mitre_id"))
    elif et == "cwe":
        add("Abstraction", entity.get("abstraction"))
        add("Parent", entity.get("parent_cwe_id"))
        add("MITRE mapping", entity.get("mapping_usage"))
    elif et == "vendor":
        add("Vendor Type", (entity.get("vendor_type") or "").replace("_", " ") or None)
        add("Website", entity.get("website"))
    elif et == "product":
        add("Vendor", entity.get("vendor_name"))
        add("Product Type", (entity.get("product_type") or "").replace("_", " ") or None)
        add("Website", entity.get("website"))

    return meta


def _related_label(item: dict) -> str:
    """Label for a related entity or detection rule row."""
    if "type" not in item:
        # Detection rule rows carry `title` / `rule_type` but no entity `type`.
        title = item.get("title") or "Untitled rule"
        parts = [title]
        extra = [p for p in (item.get("rule_type"), item.get("severity")) if p]
        if extra:
            parts.append(f"({', '.join(str(e) for e in extra)})")
        return " ".join(parts)
    return _entity_name(item)


def render_entity_profile_markdown(pivot: dict, *, related_limit: int = 50) -> str:
    """Render a pivot result (entity + related + entries) to markdown."""
    entity = pivot["entity"]
    et = entity["type"]
    related: dict[str, list] = pivot.get("related") or {}
    related_counts: dict[str, int] = pivot.get("related_counts") or {}
    entries: list[dict] = pivot.get("entries") or []

    lines = [f"# {_entity_name(entity)}", ""]
    lines.append(f"**Type:** {ENTITY_TYPE_LABELS.get(et, et)}")

    aliases = entity.get("aliases")
    if aliases:
        lines.append(f"**Aliases:** {', '.join(aliases)}")

    for label, value in _identity_meta(entity):
        lines.append(f"**{label}:** {value}")

    lines.append(f"**Articles:** {entity.get('article_count', 0)}")
    if entity.get("first_seen_at"):
        lines.append(f"**First Seen:** {_fmt_date(entity['first_seen_at'])}")
    if entity.get("last_seen_at"):
        lines.append(f"**Last Seen:** {_fmt_date(entity['last_seen_at'])}")
    if entity.get("mitre_url") and et != "ttp":
        lines.append(f"**MITRE:** {entity['mitre_url']}")
    if entity.get("wikipedia_url"):
        lines.append(f"**Wikipedia:** {entity['wikipedia_url']}")

    # Affected products table for CVEs.
    if et == "cve" and entity.get("affected_products"):
        lines += ["", "## Affected Products", ""]
        for ap in entity["affected_products"][:50]:
            vendor = ap.get("vendor") or ""
            product = ap.get("product") or ""
            versions = ap.get("versions") or ap.get("version") or ""
            label = " / ".join(p for p in (vendor, product) if p) or "—"
            if versions:
                label += f" ({versions})"
            lines.append(f"- {label}")

    description = entity.get("description")
    if description:
        lines += ["", "## Description", "", description.strip()]

    detection = entity.get("detection")
    if detection:
        lines += ["", "## Detection Guidance", "", detection.strip()]

    wiki = entity.get("wikipedia_content")
    if wiki and wiki.strip() and wiki.strip() != (description or "").strip():
        lines += ["", "## Background", "", wiki.strip()]

    # Related entities, grouped by type.
    has_related = any(related.get(k) for k in RELATED_SECTION_LABELS)
    if has_related:
        lines += ["", "## Related Entities"]
        for key, section_label in RELATED_SECTION_LABELS.items():
            items = related.get(key) or []
            if not items:
                continue
            total = related_counts.get(key, len(items))
            heading = f"### {section_label} ({total})"
            if total > len(items):
                heading = f"### {section_label} (top {len(items)} of {total})"
            lines += ["", heading, ""]
            for item in items[:related_limit]:
                label = _related_label(item)
                suffix = ""
                strength = item.get("strength") or {}
                arts = item.get("co_occurrence_count") or strength.get("articles")
                bits = []
                verb = item.get("relationship_type")
                if verb:
                    direction = " (inbound)" if item.get("relationship_direction") == "inbound" else ""
                    bits.append(verb.replace("_", " ") + direction)
                # Trust ladder, matching the profile UI: corroborated / reported /
                # signal for typed claims; plain co-mention otherwise.
                conf = item.get("relationship_confidence")
                if conf == "confirmed":
                    src = item.get("relationship_source")
                    if src == "external_feed":
                        bits.append("corroborated by MITRE ATT&CK")
                    elif src in ("analyst_confirmed", "analyst_created"):
                        bits.append("analyst-corroborated")
                    else:
                        bits.append("AI-corroborated")
                elif conf == "probable":
                    bits.append("reported")
                elif conf == "possible":
                    bits.append("signal")
                else:
                    bits.append("co-mentioned")
                if arts:
                    bits.append(f"{arts} article{'s' if arts != 1 else ''}")
                if bits:
                    suffix = f" — {', '.join(bits)}"
                lines.append(f"- {label}{suffix}")

    # Linked articles, newest first (the pivot already dedupes by content).
    if entries:
        shown = entries[:200]
        lines += ["", f"## Linked Articles ({len(entries)})", ""]
        for e in shown:
            title = e.get("title") or "Untitled"
            url = e.get("url")
            date = _fmt_date(e.get("published_at"))
            if url:
                lines.append(f"- {date} — [{title}]({url})")
            else:
                lines.append(f"- {date} — {title}")
        if len(entries) > len(shown):
            lines.append(f"- …and {len(entries) - len(shown)} more")

    now = datetime.now(UTC).strftime("%Y-%m-%d")
    lines += ["", "---", "", f"*Exported from IntelFeed on {now}*"]

    return "\n".join(lines)


async def build_entity_profile_markdown(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    *,
    related_limit: int = 50,
) -> tuple[str, str] | None:
    """Build (filename_base, markdown) for one entity, or None if not found."""
    if entity_type not in VALID_ENTITY_TYPES:
        return None
    pivot = await pivot_from_entity(db, entity_type, entity_id, limit_per_type=related_limit)
    if not pivot or not pivot.get("entity"):
        return None
    md = render_entity_profile_markdown(pivot, related_limit=related_limit)
    name = _entity_name(pivot["entity"])
    return safe_filename(name), md
