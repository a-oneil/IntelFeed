"""Fetch, parse and hydrate the MITRE CWE catalog.

MITRE ships the whole catalog as one zipped XML (~2 MB, a few thousand entries).
Unlike ATT&CK there is no per-domain split and no STIX — it is a single document
with ``<Weakness>`` and ``<Category>`` children, so parsing is a straight walk.

Both kinds are hydrated. Weaknesses are the real entries and carry the
abstraction ladder; categories are an orthogonal grouping whose ``mapping_usage``
is always ``Prohibited``. Categories are seeded anyway because NVD spent years
tagging CVEs with them, and resolving such a tag to a row that says "MITRE says
this was never a valid mapping target" is the whole point — a dangling string
can't say that.

``parse_cwe_catalog`` is pure and takes bytes, so tests exercise it without a
network call; ``hydrate_cwe_catalog`` is idempotent and keyed on ``cwe_id``.
"""

import io
import logging
import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.gateway import JOB_TOKEN_WAIT, SOURCE_REFUSALS, SourceGateway
from app.models.cwe import CWE, KIND_CATEGORY, KIND_WEAKNESS, CVEWeakness

logger = logging.getLogger(__name__)

CWE_CATALOG_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
# One file a week, with no enrichment_sources row to configure it.
CWE_GATEWAY = SourceGateway(
    "cwe_catalog", rate_limit_config={"requests_per_period": 10, "period_seconds": 3600}, max_wait=JOB_TOKEN_WAIT
)

#: The catalog's own XML namespace. Bumped by MITRE only on major schema
#: revisions; the parser tolerates a different one by reading it off the root.
_DEFAULT_NS = "http://cwe.mitre.org/cwe-7"

#: MITRE's research view. ``ChildOf`` edges exist in several views at once
#: (1000 research, 1003 simplified mapping, 1305/1340 hardware); only view 1000
#: is a complete single-parent tree, which is what the rollup needs.
_RESEARCH_VIEW = "1000"

#: "DEPRECATED: Use of Uninitialized Resource" → the replacement, when MITRE
#: names one in the description rather than in a structured field.
_SUPERSEDED_RE = re.compile(r"\b(?:see|use|replaced by|consult)\b[^.]*?\bCWE-(\d+)\b", re.I)


@dataclass
class ParsedCWE:
    cwe_id: str
    name: str
    kind: str
    abstraction: str | None = None
    status: str | None = None
    mapping_usage: str | None = None
    description: str | None = None
    extended_description: str | None = None
    parent_cwe_id: str | None = None
    likelihood_of_exploit: str | None = None
    alternate_terms: list[str] = field(default_factory=list)
    capec_ids: list[str] = field(default_factory=list)
    consequences: list[dict] = field(default_factory=list)
    mitigations: list[dict] = field(default_factory=list)
    detection_methods: list[dict] = field(default_factory=list)
    cwe_url: str | None = None
    is_deprecated: bool = False
    superseded_by: str | None = None


async def fetch_cwe_catalog(url: str = CWE_CATALOG_URL) -> bytes:
    """Download the zipped catalog and return the raw XML bytes."""
    async with CWE_GATEWAY.client(timeout=180.0, follow_redirects=True) as client:
        resp = await client.get(url)
        resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        # One .xml member, named for the version (cwec_v4.20.xml).
        name = next(n for n in zf.namelist() if n.endswith(".xml"))
        return zf.read(name)


def _text(el: ET.Element | None) -> str | None:
    """Flatten an element's text, including the XHTML markup MITRE embeds."""
    if el is None:
        return None
    parts = [t.strip() for t in el.itertext() if t and t.strip()]
    joined = " ".join(parts)
    return re.sub(r"\s+", " ", joined).strip() or None


def parse_cwe_catalog(xml_bytes: bytes) -> list[ParsedCWE]:
    """Parse the catalog XML into ParsedCWE records. Pure — no I/O, no DB."""
    root = ET.fromstring(xml_bytes)
    ns = root.tag.split("}")[0].strip("{") if root.tag.startswith("{") else _DEFAULT_NS
    n = f"{{{ns}}}"

    out: list[ParsedCWE] = []

    weaknesses = root.find(f"{n}Weaknesses")
    for w in list(weaknesses) if weaknesses is not None else []:
        out.append(_parse_weakness(w, n))

    categories = root.find(f"{n}Categories")
    for c in list(categories) if categories is not None else []:
        out.append(_parse_category(c, n))

    return out


def _mapping_usage(el: ET.Element, n: str) -> str | None:
    notes = el.find(f"{n}Mapping_Notes")
    return notes.findtext(f"{n}Usage") if notes is not None else None


def _deprecation(name: str, status: str | None, description: str | None) -> tuple[bool, str | None]:
    """Whether an entry is retired, and what replaced it if the catalog says.

    Both ``Deprecated`` (weaknesses) and ``Obsolete`` (categories) mean "do not
    use". MITRE has no structured replacement field for either, so the
    replacement is read out of the prose, which reliably reads "... see CWE-284".
    """
    deprecated = status in ("Deprecated", "Obsolete") or name.upper().startswith("DEPRECATED")
    if not deprecated:
        return False, None
    match = _SUPERSEDED_RE.search(description or "")
    return True, f"CWE-{match.group(1)}" if match else None


def _parse_weakness(w: ET.Element, n: str) -> ParsedCWE:
    cid = w.get("ID") or ""
    name = w.get("Name") or cid
    status = w.get("Status")
    description = _text(w.find(f"{n}Description"))
    deprecated, superseded = _deprecation(name, status, description)

    parent = None
    related = w.find(f"{n}Related_Weaknesses")
    for rel in list(related) if related is not None else []:
        if rel.get("Nature") == "ChildOf" and rel.get("View_ID") == _RESEARCH_VIEW:
            parent = f"CWE-{rel.get('CWE_ID')}"
            break

    alt_terms = [t for t in ((_text(term.find(f"{n}Term"))) for term in (w.find(f"{n}Alternate_Terms") or [])) if t]

    capec = [f"CAPEC-{p.get('CAPEC_ID')}" for p in (w.find(f"{n}Related_Attack_Patterns") or []) if p.get("CAPEC_ID")]

    consequences = []
    for c in w.find(f"{n}Common_Consequences") or []:
        scope = _text(c.find(f"{n}Scope"))
        impacts = [i for i in ((_text(x)) for x in c.findall(f"{n}Impact")) if i]
        if scope or impacts:
            consequences.append({"scope": scope, "impacts": impacts, "note": _text(c.find(f"{n}Note"))})

    mitigations = []
    for m in w.find(f"{n}Potential_Mitigations") or []:
        mitigations.append(
            {
                "phase": _text(m.find(f"{n}Phase")),
                "strategy": _text(m.find(f"{n}Strategy")),
                "description": _text(m.find(f"{n}Description")),
            }
        )

    detections = []
    for d in w.find(f"{n}Detection_Methods") or []:
        detections.append(
            {
                "method": _text(d.find(f"{n}Method")),
                "description": _text(d.find(f"{n}Description")),
                "effectiveness": _text(d.find(f"{n}Effectiveness")),
            }
        )

    return ParsedCWE(
        cwe_id=f"CWE-{cid}",
        name=name,
        kind=KIND_WEAKNESS,
        abstraction=w.get("Abstraction"),
        status=status,
        mapping_usage=_mapping_usage(w, n),
        description=description,
        extended_description=_text(w.find(f"{n}Extended_Description")),
        parent_cwe_id=parent,
        likelihood_of_exploit=w.findtext(f"{n}Likelihood_Of_Exploit"),
        alternate_terms=alt_terms,
        capec_ids=capec,
        consequences=consequences,
        mitigations=mitigations,
        detection_methods=detections,
        cwe_url=f"https://cwe.mitre.org/data/definitions/{cid}.html",
        is_deprecated=deprecated,
        superseded_by=superseded,
    )


def _parse_category(c: ET.Element, n: str) -> ParsedCWE:
    cid = c.get("ID") or ""
    name = c.get("Name") or cid
    status = c.get("Status")
    summary = _text(c.find(f"{n}Summary"))
    deprecated, superseded = _deprecation(name, status, summary)
    return ParsedCWE(
        cwe_id=f"CWE-{cid}",
        name=name,
        kind=KIND_CATEGORY,
        # Categories have no abstraction and no ChildOf parent — they group
        # weaknesses sideways rather than sitting on the ladder.
        status=status,
        mapping_usage=_mapping_usage(c, n),
        description=summary,
        cwe_url=f"https://cwe.mitre.org/data/definitions/{cid}.html",
        is_deprecated=deprecated,
        superseded_by=superseded,
    )


#: Columns refreshed on every run. article_count, first/last_seen_at and the
#: wikipedia_* fields are owned by the app, not the catalog, so they are excluded
#: — re-seeding must never reset an entity's observed activity.
_CATALOG_COLUMNS = (
    "name",
    "kind",
    "abstraction",
    "status",
    "mapping_usage",
    "description",
    "extended_description",
    "parent_cwe_id",
    "likelihood_of_exploit",
    "alternate_terms",
    "capec_ids",
    "consequences",
    "mitigations",
    "detection_methods",
    "cwe_url",
    "is_deprecated",
    "superseded_by",
)


async def hydrate_cwe_catalog(db: AsyncSession, parsed: list[ParsedCWE]) -> dict:
    """Upsert parsed catalog entries into ``cwes``. Idempotent, keyed on cwe_id."""
    if not parsed:
        return {"parsed": 0, "inserted": 0, "updated": 0}

    existing = {row[0] for row in (await db.execute(select(CWE.cwe_id))).all()}

    rows = [
        {
            "cwe_id": p.cwe_id,
            "name": p.name,
            "kind": p.kind,
            "abstraction": p.abstraction,
            "status": p.status,
            "mapping_usage": p.mapping_usage,
            "description": p.description,
            "extended_description": p.extended_description,
            "parent_cwe_id": p.parent_cwe_id,
            "likelihood_of_exploit": p.likelihood_of_exploit,
            "alternate_terms": p.alternate_terms,
            "capec_ids": p.capec_ids,
            "consequences": p.consequences,
            "mitigations": p.mitigations,
            "detection_methods": p.detection_methods,
            "cwe_url": p.cwe_url,
            "is_deprecated": p.is_deprecated,
            "superseded_by": p.superseded_by,
            "created_via": "catalog",
        }
        for p in parsed
    ]

    # One statement per chunk rather than per row — 1,400 entries otherwise costs
    # 1,400 round trips on every re-seed.
    chunk = 200
    for start in range(0, len(rows), chunk):
        stmt = pg_insert(CWE).values(rows[start : start + chunk])
        await db.execute(
            stmt.on_conflict_do_update(
                index_elements=["cwe_id"],
                set_={col: getattr(stmt.excluded, col) for col in _CATALOG_COLUMNS},
            )
        )

    inserted = sum(1 for p in parsed if p.cwe_id not in existing)
    return {"parsed": len(parsed), "inserted": inserted, "updated": len(parsed) - inserted}


async def resolve_cve_weakness_refs(db: AsyncSession) -> int:
    """Point unresolved ``cve_weaknesses`` rows at catalog entries.

    Runs after a catalog seed so refs that arrived before their weakness existed
    (or before a MITRE release added it) resolve retroactively — the same
    retroactive-resolution contract ``cve_affected`` has for CPE strings.
    """
    catalog = {row[0]: row[1] for row in (await db.execute(select(CWE.cwe_id, CWE.id))).all()}
    if not catalog:
        return 0

    unresolved = (
        await db.execute(select(CVEWeakness.id, CVEWeakness.cwe_ref).where(CVEWeakness.cwe_id_fk.is_(None)))
    ).all()

    now = datetime.now(UTC)
    resolved = 0
    for row_id, ref in unresolved:
        cwe_uuid = catalog.get(ref)
        if cwe_uuid is None:
            continue  # NVD-CWE-noinfo / NVD-CWE-Other, or an id MITRE has not published
        await db.execute(
            CVEWeakness.__table__.update().where(CVEWeakness.id == row_id).values(cwe_id=cwe_uuid, resolved_at=now)
        )
        resolved += 1
    return resolved


async def refresh_cwe_catalog(db: AsyncSession, url: str = CWE_CATALOG_URL) -> dict:
    """Download, parse, hydrate and re-resolve. Commits."""
    try:
        xml_bytes = await fetch_cwe_catalog(url)
    except SOURCE_REFUSALS as e:
        logger.warning("CWE catalog refresh skipped: %s", e)
        return {"stopped": e.status}
    parsed = parse_cwe_catalog(xml_bytes)
    stats = await hydrate_cwe_catalog(db, parsed)
    await db.flush()
    stats["refs_resolved"] = await resolve_cve_weakness_refs(db)
    await db.commit()
    return stats
