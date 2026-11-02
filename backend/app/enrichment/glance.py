"""The highlight popover's glance: a few words from enrichment that change how
a reader takes a highlighted name.

Each entity type the reader highlights has a list of rules. A rule reads one
source's stored answer (an entity column it writes, or its profile context)
or, for a few types, a count the enrichment jobs made possible (a CWE's CVEs
from the NVD and CVE-record weakness links). It returns a verdict **chip**
(something you'd act on: exploited, no patch, benign scanner, EOL) or a short
neutral **fact**, or nothing. ``glance()`` keeps the first two chips and the
first three facts, in rule order, from sources that are on and that the
viewer may see (visitors never see a source that sends indicators off the box
or bars commercial use). Nothing stored means nothing shown: the popover
looks as it would without enrichment.

The rules sit here rather than on each source's outputs because most need a
phrase built from several values ("AS10439 CariNet · US") or a threshold
("registered 3 days ago" only while it is new).
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.enrichment.manifest import Egress
from app.models.enrichment import EnrichmentResult, EnrichmentSource, EntityContext

#: Most chips and facts a glance shows.
MAX_CHIPS = 2
MAX_FACTS = 3
#: A domain registered more recently than this reads as new.
NEW_DOMAIN_DAYS = 30
#: Tranco ranks this high or better read as a popular site.
POPULAR_RANK = 10_000


@dataclass
class Item:
    text: str
    tone: str | None = None  # "bad" | "warn" | None (neutral)
    chip: bool = False
    source: str | None = None  # source_type, None for a derived count
    observed_at: datetime | None = None


@dataclass
class Facts:
    """What the rules read for one entity."""

    db: AsyncSession
    entity_type: str
    entity: object
    context: dict[str, dict[str, object]] = field(default_factory=dict)
    observed: dict[str, datetime] = field(default_factory=dict)

    def ctx(self, source: str, key: str):
        return self.context.get(source, {}).get(key)

    def col(self, name: str):
        return getattr(self.entity, name, None)


Rule = Callable[[Facts], Awaitable[Item | None]]


@dataclass(frozen=True)
class Spec:
    source: str | None  # the source whose answer it reads; None: derived
    rule: Rule


# ── Phrases ──────────────────────────────────────────────────────────


def _n(n: int) -> str:
    return f"{n:,}"


def _count(n: int, word: str, plural: str | None = None) -> str:
    """``1 CVE``, ``3 CVEs``."""
    return f"{_n(n)} {word if n == 1 else plural or word + 's'}"


def _rows(table) -> list[list]:
    return table.get("rows") or [] if isinstance(table, dict) else []


def _days_since(value) -> int | None:
    if isinstance(value, datetime):
        then = value if value.tzinfo else value.replace(tzinfo=UTC)
        return (datetime.now(UTC) - then).days
    if isinstance(value, date):
        return (datetime.now(UTC).date() - value).days
    if isinstance(value, str):
        try:
            return _days_since(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def _ago(days: int) -> str:
    if days < 1:
        return "today"
    if days < 60:
        return f"{days} day{'s' if days != 1 else ''} ago"
    if days < 730:
        return f"{days // 30} months ago"
    return f"{days // 365} years ago"


def _year(value) -> str | None:
    text = str(value or "").strip()
    return text[:4] if len(text) >= 4 and text[:4].isdigit() else None


def _short(text, limit: int = 40) -> str | None:
    text = str(text or "").strip()
    if not text:
        return None
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _first(values) -> str | None:
    if isinstance(values, list):
        return next((str(v) for v in values if v), None)
    return str(values) if values else None


# ── CVE ──────────────────────────────────────────────────────────────


async def _cve_exploited(f: Facts):
    # KEV already says "exploited" in the popover's own chips.
    if f.col("ssvc_exploitation") == "active" and not f.col("is_kev"):
        return Item("Exploited", "bad", chip=True)


async def _cve_no_patch(f: Facts):
    """An affected product is past support (the product itself, or the
    releases the CVE's range covers): "No patch" when every affected product
    is, "No patch for 1 of 3 products" when only some are."""
    from app.enrichment.endoflife import EndOfLifeSource, eol_releases
    from app.models.cve_affected import CVEAffected
    from app.models.product import Product

    rows = (
        await f.db.execute(
            select(CVEAffected.product_id, CVEAffected.version_start, CVEAffected.version_end, Product.support_status)
            .join(Product, Product.id == CVEAffected.product_id)
            .where(CVEAffected.cve_id == f.entity.id)
        )
    ).all()
    products = {pid for pid, *_ in rows}
    unpatched = {pid for pid, _, _, status in rows if status == "eol"}
    pending = products - unpatched
    if pending:
        releases = dict(
            (
                await f.db.execute(
                    select(EntityContext.entity_id, EntityContext.value).where(
                        EntityContext.entity_type == entity_types.PRODUCT,
                        EntityContext.entity_id.in_(pending),
                        EntityContext.source_type == EndOfLifeSource.source_type,
                        EntityContext.key == "releases",
                    )
                )
            ).all()
        )
        unpatched |= {
            pid for pid, start, end, _ in rows if pid in pending and eol_releases(releases.get(pid), start, end)
        }
    if not unpatched:
        return None
    if unpatched == products:
        return Item("No patch", "bad", chip=True)
    return Item(f"No patch for {len(unpatched)} of {_count(len(products), 'product')}", "bad", chip=True)


async def _cve_ransomware(f: Facts):
    if str(f.ctx("cisa_kev", "known_ransomware_use") or "").casefold() == "known":
        return Item("Used by ransomware")


async def _cve_metasploit(f: Facts):
    if f.col("metasploit_module"):
        return Item("Metasploit module")


async def _cve_automatable(f: Facts):
    if f.col("ssvc_automatable") == "yes":
        return Item("Automatable")


async def _cve_pocs(f: Facts):
    count = f.ctx("github_poc", "poc_count")
    if isinstance(count, int) and count > 0:
        return Item(f"{_count(count, 'public PoC')}")


# ── CWE ──────────────────────────────────────────────────────────────


async def _cwe_cves(f: Facts):
    from app.models.cve import CVE
    from app.models.cwe import CVEWeakness

    total, kev = (
        await f.db.execute(
            select(func.count(func.distinct(CVE.id)), func.count(func.distinct(CVE.id)).filter(CVE.is_kev))
            .select_from(CVEWeakness)
            .join(CVE, CVE.id == CVEWeakness.cve_id)
            .where(CVEWeakness.cwe_id_fk == f.entity.id)
        )
    ).one()
    if total:
        return Item(f"Behind {_count(total, 'CVE')}" + (f", {_n(kev)} in KEV" if kev else ""))


# ── Technique ────────────────────────────────────────────────────────


async def _ttp_platforms(f: Facts):
    platforms = f.col("platforms") or []
    if platforms:
        return Item(", ".join(platforms[:3]) + (f" +{len(platforms) - 3}" if len(platforms) > 3 else ""))


async def _ttp_countermeasures(f: Facts):
    rows = _rows(f.ctx("d3fend", "countermeasures"))
    if rows:
        return Item(_count(len(rows), "D3FEND countermeasure"))


async def _ttp_controls(f: Facts):
    nist = f.col("nist_controls") or []
    if nist:
        return Item(_count(len(nist), "NIST control"))


# ── Threat actor ─────────────────────────────────────────────────────


async def _actor_leak_site(f: Facts):
    if any(len(r) > 1 and str(r[1]).casefold() == "up" for r in _rows(f.ctx("ransomware_live", "leak_sites"))):
        return Item("Leak site up", "warn", chip=True)


async def _actor_sponsor(f: Facts):
    sponsor = _short(f.ctx("etda", "sponsor"))
    if sponsor:
        return Item(sponsor)


async def _actor_since(f: Facts):
    year = _year(f.ctx("etda", "first_seen"))
    if year:
        return Item(f"Active since {year}")


async def _actor_families(f: Facts):
    families = f.ctx("malpedia", "families")
    if isinstance(families, list) and families:
        return Item(_count(len(families), "malware family", "malware families"))


# ── Malware and tools ────────────────────────────────────────────────


async def _attributed(f: Facts):
    actor = _first(f.ctx("malpedia", "attribution"))
    if actor:
        return Item(f"Attributed to {_short(actor, 30)}")


async def _attack_id(f: Facts):
    if f.col("mitre_id"):
        return Item(f"ATT&CK {f.col('mitre_id')}")


async def _tool_archived(f: Facts):
    if f.ctx("github_repo", "archived") is True:
        return Item("Archived", "warn", chip=True)


async def _tool_stars(f: Facts):
    stars = f.ctx("github_repo", "stars")
    if isinstance(stars, int):
        shown = f"{stars / 1000:.1f}k".replace(".0k", "k") if stars >= 1000 else str(stars)
        return Item(f"★ {shown} on GitHub")


async def _tool_pushed(f: Facts):
    days = _days_since(f.ctx("github_repo", "pushed_at"))
    if days is not None:
        return Item(f"Last commit {_ago(days)}")


# ── Country, vendor, product, mitigation ─────────────────────────────


async def _country_targeted(f: Facts):
    from app.models.entity_relationship import EntityRelationship

    n = (
        await f.db.execute(
            select(func.count(func.distinct(EntityRelationship.source_id))).where(
                EntityRelationship.target_type == entity_types.COUNTRY,
                EntityRelationship.target_id == f.entity.id,
                EntityRelationship.source_type == entity_types.THREAT_ACTOR,
                EntityRelationship.relationship_type == "targets",
            )
        )
    ).scalar_one()
    if n:
        return Item(f"Targeted by {_count(n, 'threat actor')}")


async def _iso(f: Facts):
    if f.col("iso_code"):
        return Item(f"ISO {f.col('iso_code')}")


async def _vendor_country(f: Facts):
    country = _short(f.ctx("wikidata", "country"), 30)
    if country:
        return Item(country)


async def _vendor_founded(f: Facts):
    year = _year(f.ctx("wikidata", "founded"))
    if year:
        return Item(f"Founded {year}")


async def _product_support(f: Facts):
    status = f.col("support_status")
    if status == "eol":
        return Item("EOL", "bad", chip=True)
    if status == "security_only":
        return Item("Security fixes only", "warn", chip=True)


async def _product_next_eol(f: Facts):
    end = f.col("next_eol")
    if end:
        return Item(f"Security fixes until {end.isoformat() if isinstance(end, date) else end}")


async def _product_cves(f: Facts):
    from app.models.cve import CVE
    from app.models.cve_affected import CVEAffected

    total, kev = (
        await f.db.execute(
            select(func.count(func.distinct(CVE.id)), func.count(func.distinct(CVE.id)).filter(CVE.is_kev))
            .select_from(CVEAffected)
            .join(CVE, CVE.id == CVEAffected.cve_id)
            .where(CVEAffected.product_id == f.entity.id)
        )
    ).one()
    if total:
        return Item(_count(total, "CVE") + (f", {_n(kev)} in KEV" if kev else ""))


async def _mitigation_counters(f: Facts):
    from app.models.mitigation import TTPMitigation

    n = (await f.db.execute(select(func.count()).where(TTPMitigation.mitigation_id == f.entity.id))).scalar_one()
    if n:
        return Item(f"Counters {_count(n, 'technique')}")


# ── Observable ───────────────────────────────────────────────────────


async def _obs_noise(f: Facts):
    status = f.col("noise_class")
    if status == "benign":
        return Item("Benign scanner", "warn", chip=True)
    if status == "malicious":
        return Item("Malicious scanner", "bad", chip=True)


async def _obs_online(f: Facts):
    if str(f.ctx("urlhaus", "url_status") or "").casefold() == "online":
        return Item("Serving malware", "bad", chip=True)


async def _obs_new_domain(f: Facts):
    days = _days_since(f.col("registered_at"))
    if days is not None and days < NEW_DOMAIN_DAYS:
        return Item("New domain", "warn", chip=True)


async def _obs_popular(f: Facts):
    rank = f.col("popularity_rank")
    if isinstance(rank, int) and rank <= POPULAR_RANK:
        return Item("Popular site", "warn", chip=True)


async def _obs_family(f: Facts):
    family = _first(f.ctx("threatfox", "malware")) or f.ctx("malwarebazaar", "signature")
    if family:
        return Item(_short(family, 30))


async def _obs_vt(f: Facts):
    ratio = f.ctx("virustotal", "detection_ratio")
    if ratio:
        return Item(f"VirusTotal {ratio}")


async def _obs_scanner_name(f: Facts):
    name = _short(f.ctx("greynoise", "name"), 30)
    if name and f.col("noise_class"):
        return Item(name)


async def _obs_asn(f: Facts):
    asn = f.col("asn")
    if asn is None:
        return None
    parts = [f"AS{asn}"]
    if f.col("asn_org"):
        parts.append(_short(str(f.col("asn_org")).split(",")[0].split(" - ")[-1], 24))
    text = " ".join(parts)
    return Item(f"{text} · {f.col('geo_country')}" if f.col("geo_country") else text)


async def _obs_infra(f: Facts):
    tag = f.col("infra_tag")
    labels = {"vpn": "VPN", "proxy": "Proxy", "tor": "Tor exit", "scanner": "Scanner", "benign_service": None}
    if tag in labels and labels[tag]:
        return Item(labels[tag])


async def _obs_registered(f: Facts):
    days = _days_since(f.col("registered_at"))
    if days is not None:
        registrar = _short(f.ctx("rdap", "registrar"), 20)
        return Item(f"Registered {_ago(days)}" + (f" · {registrar}" if registrar else ""))


async def _obs_rank(f: Facts):
    rank = f.col("popularity_rank")
    if isinstance(rank, int):
        return Item(f"Tranco #{_n(rank)}")


#: Rules per highlighted type, chips and facts mixed, in priority order.
RULES: dict[str, tuple[Spec, ...]] = {
    entity_types.CVE: (
        Spec("cvelist", _cve_exploited),
        Spec("endoflife", _cve_no_patch),
        Spec("cisa_kev", _cve_ransomware),
        Spec("metasploit", _cve_metasploit),
        Spec("cvelist", _cve_automatable),
        Spec("github_poc", _cve_pocs),
    ),
    entity_types.CWE: (Spec(None, _cwe_cves),),
    entity_types.TTP: (
        Spec("mitre_attack", _ttp_platforms),
        Spec("d3fend", _ttp_countermeasures),
        Spec("ctid", _ttp_controls),
    ),
    entity_types.THREAT_ACTOR: (
        Spec("ransomware_live", _actor_leak_site),
        Spec("etda", _actor_sponsor),
        Spec("etda", _actor_since),
        Spec("malpedia", _actor_families),
    ),
    entity_types.MALWARE: (Spec("malpedia", _attributed), Spec("mitre_attack", _attack_id)),
    entity_types.TOOL: (
        Spec("github_repo", _tool_archived),
        Spec("malpedia", _attributed),
        Spec("github_repo", _tool_stars),
        Spec("github_repo", _tool_pushed),
        Spec("mitre_attack", _attack_id),
    ),
    entity_types.COUNTRY: (Spec(None, _country_targeted), Spec("wikidata", _iso)),
    entity_types.VENDOR: (Spec("wikidata", _vendor_country), Spec("wikidata", _vendor_founded)),
    entity_types.PRODUCT: (
        Spec("endoflife", _product_support),
        Spec("endoflife", _product_next_eol),
        Spec(None, _product_cves),
    ),
    entity_types.MITIGATION: (Spec(None, _mitigation_counters),),
    entity_types.OBSERVABLE: (
        Spec("urlhaus", _obs_online),
        Spec("greynoise", _obs_noise),
        Spec("rdap", _obs_new_domain),
        Spec("tranco", _obs_popular),
        Spec("threatfox", _obs_family),
        Spec("malwarebazaar", _obs_family),
        Spec("virustotal", _obs_vt),
        Spec("greynoise", _obs_scanner_name),
        Spec("cymru", _obs_asn),
        Spec("shodan", _obs_infra),
        Spec("rdap", _obs_registered),
        Spec("tranco", _obs_rank),
    ),
}


# ── The glance ───────────────────────────────────────────────────────


async def _lookup_sources(db: AsyncSession, entity_type: str, kind: str | None, rows, user) -> tuple[list, list]:
    """The lookup sources a person can run on this entity now (on, apply to
    its kind, key in hand), and, for admins, those that need a key first."""
    from app.enrichment.keys import credential_for
    from app.enrichment.pipeline import resolve_api_key
    from app.enrichment.registry import ADAPTER_REGISTRY

    if user.is_anonymous:
        return [], []
    runnable, needs_key = [], []
    for source_type, cls in ADAPTER_REGISTRY.items():
        row = rows.get(source_type)
        kinds = cls.applies_to.get(entity_type, ...)
        if row is None or not row.is_enabled or kinds is ...:
            continue
        if kinds and kind not in kinds:
            continue
        if cls.requires_api_key and not await resolve_api_key(row, user.id, db):
            if user.role == "admin":
                label = row.display_name or cls.display_name
                needs_key.append({"source_type": source_type, "label": label, "key": credential_for(source_type)})
            continue
        runnable.append({"source_type": source_type, "label": row.display_name or cls.display_name})
    return runnable, needs_key


async def glance(db: AsyncSession, entity_type: str, entity, user) -> dict:
    """The popover's chips and facts for ``entity`` as ``user`` may see them,
    plus the lookup sources its Look up button runs."""
    from app.enrichment.registry import SOURCE_REGISTRY

    rows = {r.source_type: r for r in (await db.execute(select(EnrichmentSource))).scalars()}
    visitor = user.is_anonymous

    def visible(source_type: str | None) -> bool:
        if source_type is None:
            return True
        cls, row = SOURCE_REGISTRY.get(source_type), rows.get(source_type)
        if cls is None or row is None or not row.is_enabled:
            return False
        return not (visitor and (cls.egress == Egress.SHARES_IOC or not cls.license.commercial_ok))

    facts = Facts(db, entity_type, entity)
    for row in (
        await db.execute(
            select(EntityContext).where(EntityContext.entity_type == entity_type, EntityContext.entity_id == entity.id)
        )
    ).scalars():
        facts.context.setdefault(row.source_type, {})[row.key] = row.value
        if row.source_type not in facts.observed or row.observed_at > facts.observed[row.source_type]:
            facts.observed[row.source_type] = row.observed_at

    chips: list[Item] = []
    lines: list[Item] = []
    for spec in RULES.get(entity_type, ()):
        if not visible(spec.source):
            continue
        item = await spec.rule(facts)
        # Two sources can say the same thing (ThreatFox and MalwareBazaar's
        # family): it shows once.
        if item is None or item.text in {i.text for i in chips + lines}:
            continue
        item.source = spec.source
        item.observed_at = facts.observed.get(spec.source) if spec.source else None
        target = chips if item.chip else lines
        if len(target) < (MAX_CHIPS if item.chip else MAX_FACTS):
            target.append(item)

    kind = getattr(entity, "kind", None) if entity_type == entity_types.OBSERVABLE else None
    runnable, needs_key = await _lookup_sources(db, entity_type, kind, rows, user)
    # "Refresh" once any source answered for this entity, "Look up" before.
    looked_up = (
        bool(facts.context)
        or (
            await db.execute(
                select(EnrichmentResult.id)
                .where(EnrichmentResult.entity_type == entity_type, EnrichmentResult.entity_id == entity.id)
                .limit(1)
            )
        ).first()
        is not None
    )

    def out(i: Item) -> dict:
        cls = SOURCE_REGISTRY.get(i.source) if i.source else None
        return {
            "text": i.text,
            "tone": i.tone,
            "source": (rows[i.source].display_name or cls.display_name) if cls and i.source in rows else None,
            "observed_at": i.observed_at.isoformat() if i.observed_at else None,
        }

    return {
        "chips": [out(i) for i in chips],
        "facts": [out(i) for i in lines],
        "lookup_sources": runnable,
        "needs_key": needs_key,
        "looked_up": looked_up,
    }


async def entity_for(db: AsyncSession, entity_type: str, entity_id: uuid.UUID):
    """The entity row, through the visitor filter; None when hidden or gone."""
    from app.enrichment.entity_updater import _get_model_map

    model = _get_model_map().get(entity_type)
    if model is None:
        return None
    return (await db.execute(select(model).where(model.id == entity_id))).scalar_one_or_none()
