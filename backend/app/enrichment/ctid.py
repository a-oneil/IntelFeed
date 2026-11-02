"""CTID control mappings: the NIST 800-53 and CIS controls that mitigate each
ATT&CK technique.

The Center for Threat-Informed Defense's Mappings Explorer publishes one JSON
file per framework, each a list of ``mapping_objects`` (``capability_id`` →
``attack_object_id``, ``mapping_type`` ``mitigates``). The weekly job reads both
files and writes each technique's controls into ``ttps.nist_controls`` and
``ttps.cis_controls`` (the mapping is authoritative: newer wins, and a
technique the mappings drop is cleared), with the controls and their names as
profile context.

The files map controls to techniques only; they don't name ATT&CK mitigations
(M-ids), so nothing is written onto mitigations.

A new framework or ATT&CK version is a new path in Mappings Explorer:
``MAPPING_URLS`` names the ones read.
"""

from __future__ import annotations

import logging
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.base import EnrichmentData, Source
from app.enrichment.gateway import SOURCE_REFUSALS, SourceGateway
from app.enrichment.manifest import Column, Context, Display, Egress, Job, License, Policy, Quota

logger = logging.getLogger(__name__)

_BASE = "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings"
#: Framework → its mapping file, the newest ATT&CK version CTID has mapped it to.
MAPPING_URLS = {
    "nist": f"{_BASE}/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-16.1-enterprise.json",
    "cis": f"{_BASE}/cis/attack-19.1/cis-8.1.2/enterprise/cis-8.1.2_attack-19.1-enterprise.json",
}
#: The weekly job plus a missed run.
TTL_HOURS = 24 * 14


class CTIDSource(Source):
    source_type = "ctid"
    display_name = "CTID control mappings"
    about = "Which security controls (NIST 800-53, CIS) address each ATT&CK technique."
    applies_to = {"ttp": None}
    # raw.githubusercontent.com publishes no rate limit; a run makes two requests.
    quota = Quota(10, 3600, daily_budget=50)
    egress = Egress.NONE
    # Apache 2.0: https://github.com/center-for-threat-informed-defense/mappings-explorer/blob/main/LICENSE.txt
    license = License("Apache 2.0", attribution="MITRE Center for Threat-Informed Defense, Mappings Explorer")
    jobs = (
        Job(
            "ctid-mappings-sync",
            "app.workers.enrichment_tasks.run_ctid_sync",
            {"type": "crontab", "minute": "15", "hour": "4", "day_of_week": "0"},
            "Map NIST 800-53 and CIS controls onto techniques from CTID's Mappings Explorer",
            counts=False,
        ),
    )
    outputs = (
        Column("nist_controls", "ttp.nist_controls", Policy.NEWER_WINS, clears=True),
        Column("cis_controls", "ttp.cis_controls", Policy.NEWER_WINS, clears=True),
        Context("nist", "NIST 800-53 rev5", Display.CHIPS),
        Context("cis", "CIS Controls v8.1", Display.CHIPS),
    )


def _natural(control_id: str) -> list:
    """ "CIS-2.1" sorts before "CIS-10.7"."""
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", control_id)]


def parse_mappings(document: dict) -> dict[str, dict[str, str]]:
    """Technique id → {control id: control name} for the file's ``mitigates``
    mappings. Non-mappable rows and rows without a control are skipped."""
    by_technique: dict[str, dict[str, str]] = {}
    for m in document.get("mapping_objects") or []:
        if not isinstance(m, dict) or m.get("mapping_type") != "mitigates" or m.get("status") != "complete":
            continue
        technique, control = m.get("attack_object_id"), m.get("capability_id")
        if isinstance(technique, str) and isinstance(control, str) and technique and control:
            by_technique.setdefault(technique, {})[control] = (m.get("capability_description") or "").strip()
    return by_technique


def technique_controls(controls: dict[str, str] | None) -> tuple[list[str], list[str]]:
    """(control ids, chips "id name") in control order."""
    ids = sorted(controls or {}, key=_natural)
    return ids, [f"{c} {controls[c]}".strip() for c in ids]


async def sync_ctid(db: AsyncSession, gateway: SourceGateway) -> dict:
    """Read both mapping files, then write every technique either maps or that
    holds controls from before. A refusal or a failed file stops the run before
    anything is written: half the frameworks would read as controls removed."""
    from app.enrichment.pipeline import apply_catalog_result
    from app.models.ttp import TTP

    stats = {"nist_techniques": 0, "cis_techniques": 0, "updated": 0, "stopped": None}
    frameworks: dict[str, dict[str, dict[str, str]]] = {}
    async with gateway.client(timeout=60.0) as client:
        for framework, url in MAPPING_URLS.items():
            try:
                resp = await client.get(url)
                resp.raise_for_status()
            except SOURCE_REFUSALS as e:
                logger.warning("CTID sync skipped: %s", e)
                return {**stats, "stopped": e.status}
            frameworks[framework] = parse_mappings(resp.json())
            if not frameworks[framework]:
                raise RuntimeError(f"{url} held no mappings")
            stats[f"{framework}_techniques"] = len(frameworks[framework])

    ttps = (await db.execute(select(TTP.id, TTP.technique_id, TTP.nist_controls, TTP.cis_controls))).all()
    for ttp_id, technique_id, nist_held, cis_held in ttps:
        nist = frameworks["nist"].get(technique_id)
        cis = frameworks["cis"].get(technique_id)
        if not (nist or cis or nist_held or cis_held):
            continue
        nist_ids, nist_chips = technique_controls(nist)
        cis_ids, cis_chips = technique_controls(cis)
        parsed = {"nist_controls": nist_ids, "cis_controls": cis_ids, "nist": nist_chips, "cis": cis_chips}
        data = EnrichmentData(raw_response=parsed, parsed_data=parsed, ttl_hours=TTL_HOURS)
        if await apply_catalog_result(db, "ttp", ttp_id, CTIDSource.source_type, data):
            stats["updated"] += 1
    await db.commit()
    return stats
