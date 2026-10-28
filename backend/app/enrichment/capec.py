"""MITRE CAPEC: the attack-pattern catalog behind the CAPEC ids weaknesses carry.

The weekly job downloads CAPEC's research view (``1000.csv.zip``, every attack
pattern, ~380 KB zipped), replaces ``capec_patterns`` with it and writes each
technique's patterns (from CAPEC's ATT&CK taxonomy mappings) as profile
context. A CWE's ``capec_ids`` come from the CWE catalog; the CWE endpoints
resolve them to names against this table (``capec_names``).
"""

from __future__ import annotations

import csv
import io
import logging
import re
import zipfile

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.base import EnrichmentData, Source
from app.enrichment.gateway import SOURCE_REFUSALS, SourceGateway
from app.enrichment.manifest import Context, Display, Egress, Job, License, Quota

logger = logging.getLogger(__name__)

CAPEC_CSV_URL = "https://capec.mitre.org/data/csv/1000.csv.zip"
#: The weekly job plus a missed run.
TTL_HOURS = 24 * 14

#: ``TAXONOMY NAME:ATTACK:ENTRY ID:1574.010:`` in the Taxonomy Mappings field.
_ATTACK_ENTRY = re.compile(r"TAXONOMY NAME:ATTACK:ENTRY ID:(\d{4}(?:\.\d{3})?)")
_CWE_ID = re.compile(r"\d+")


class CAPECSource(Source):
    source_type = "capec"
    display_name = "MITRE CAPEC"
    applies_to = {"ttp": None, "cwe": None}
    # CAPEC publishes no rate limit; a run makes one request.
    quota = Quota(10, 3600, daily_budget=50)
    egress = Egress.NONE
    # Free for research, development and commercial use, reproducing MITRE's
    # copyright designation: https://capec.mitre.org/about/termsofuse.html
    license = License("CAPEC terms of use", attribution="CAPEC™ is a trademark of The MITRE Corporation")
    jobs = (
        Job(
            "capec-sync",
            "app.workers.enrichment_tasks.run_capec_sync",
            {"type": "crontab", "minute": "0", "hour": "4", "day_of_week": "1"},
            "Refresh the MITRE CAPEC attack-pattern catalog and the patterns mapped to each technique",
        ),
    )
    outputs = (
        Context(
            "attack_patterns",
            "Attack patterns",
            Display.TABLE,
            item={"CAPEC": "capec_id", "Pattern": "name", "Abstraction": "abstraction"},
            entity_types=("ttp",),
        ),
    )


def parse_capec_csv(text: str) -> list[dict]:
    """``capec_patterns`` rows from the CSV. Its first header is ``'ID`` (a
    stray quote CAPEC ships), so headers are read with quotes stripped."""
    reader = csv.reader(io.StringIO(text))
    header = [h.strip().strip("'") for h in next(reader, [])]
    patterns = []
    for values in reader:
        row = dict(zip(header, values, strict=False))
        number, name = (row.get("ID") or "").strip(), (row.get("Name") or "").strip()
        if not number.isdigit() or not name:
            continue
        patterns.append(
            {
                "capec_id": f"CAPEC-{number}",
                "name": name,
                "abstraction": row.get("Abstraction") or None,
                "status": row.get("Status") or None,
                "description": (row.get("Description") or "").strip() or None,
                "cwe_ids": [f"CWE-{n}" for n in _CWE_ID.findall(row.get("Related Weaknesses") or "")],
                "technique_ids": list(
                    dict.fromkeys(f"T{t}" for t in _ATTACK_ENTRY.findall(row.get("Taxonomy Mappings") or ""))
                ),
            }
        )
    return patterns


def technique_patterns(patterns: list[dict]) -> dict[str, list[dict]]:
    """Technique id → the patterns CAPEC maps to it, in CAPEC id order."""
    by_technique: dict[str, list[dict]] = {}
    for p in sorted(patterns, key=lambda p: int(p["capec_id"].split("-")[1])):
        for technique_id in p["technique_ids"]:
            by_technique.setdefault(technique_id, []).append(
                {"capec_id": p["capec_id"], "name": p["name"], "abstraction": p["abstraction"]}
            )
    return by_technique


async def capec_names(db: AsyncSession, capec_ids: list[str]) -> list[dict]:
    """``capec_ids`` as ``{"capec_id", "name"}``, in their order; an id the
    catalog lacks keeps a null name."""
    from app.models.capec import CAPECPattern

    if not capec_ids:
        return []
    rows = await db.execute(
        select(CAPECPattern.capec_id, CAPECPattern.name).where(CAPECPattern.capec_id.in_(capec_ids))
    )
    names = dict(rows.all())
    return [{"capec_id": c, "name": names.get(c)} for c in capec_ids]


async def sync_capec(db: AsyncSession, gateway: SourceGateway) -> dict:
    """Download the catalog, replace ``capec_patterns`` with it, then write each
    technique's patterns. A refusal stops the run before anything changes."""
    from app.enrichment.pipeline import apply_catalog_result
    from app.models.capec import CAPECPattern
    from app.models.enrichment import EntityContext
    from app.models.ttp import TTP

    stats = {"patterns": 0, "techniques": 0, "stopped": None}
    async with gateway.client(timeout=60.0, follow_redirects=True) as client:
        try:
            resp = await client.get(CAPEC_CSV_URL)
            resp.raise_for_status()
        except SOURCE_REFUSALS as e:
            logger.warning("CAPEC sync skipped: %s", e)
            return {**stats, "stopped": e.status}
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".csv"))
        patterns = parse_capec_csv(zf.read(name).decode("utf-8"))
    if not patterns:
        # An empty file would read as "every pattern was withdrawn".
        raise RuntimeError(f"{CAPEC_CSV_URL} held no attack patterns")

    insert = pg_insert(CAPECPattern).values(patterns)
    await db.execute(
        insert.on_conflict_do_update(
            index_elements=["capec_id"],
            set_={
                **{
                    col: getattr(insert.excluded, col)
                    for col in ("name", "abstraction", "status", "description", "cwe_ids", "technique_ids")
                },
                "updated_at": func.now(),
            },
        )
    )
    await db.execute(delete(CAPECPattern).where(CAPECPattern.capec_id.not_in([p["capec_id"] for p in patterns])))
    stats["patterns"] = len(patterns)

    by_technique = technique_patterns(patterns)
    # Techniques that showed patterns before, so one CAPEC no longer maps loses them.
    shown = set(
        (
            await db.execute(
                select(EntityContext.entity_id).where(
                    EntityContext.entity_type == "ttp", EntityContext.source_type == CAPECSource.source_type
                )
            )
        ).scalars()
    )
    for ttp_id, technique_id in (await db.execute(select(TTP.id, TTP.technique_id))).all():
        mapped = by_technique.get(technique_id)
        if not mapped and ttp_id not in shown:
            continue
        parsed = {"attack_patterns": mapped or []}
        data = EnrichmentData(raw_response=parsed, parsed_data=parsed, ttl_hours=TTL_HOURS)
        await apply_catalog_result(db, "ttp", ttp_id, CAPECSource.source_type, data)
        stats["techniques"] += bool(mapped)
    await db.commit()
    return stats
