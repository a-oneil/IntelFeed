"""Rule-independent detectability via ATT&CK data sources (heuristic).

Answers "could you detect this CVE's exploitation even if no rule references it?"
by walking CVE -> co-occurring ATT&CK techniques (shared entries) -> those
techniques' MITRE data sources (``TTP.data_sources``) -> your telemetry inventory,
reusing the same ``split_data_sources`` matcher as rule-backed coverage.

This is a LOWER-CONFIDENCE signal than rule coverage: the CVE->technique link is
co-occurrence on shared entries, not a curated mapping. Surface it as a hint
("you have the telemetry to write a detection"), never as authoritative coverage.
Gated by ``exposure_attack_visibility_enabled``. See docs/intelligence-engine.md.
This module only READS from detection_coverage — it never edits it, to
stay clear of concurrently-edited detection code.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import EntryCVE
from app.models.ttp import TTP, EntryTTP
from app.services.detection_coverage import get_available_telemetry, split_data_sources


def _component(data_source: str) -> str:
    """ATT&CK data-source strings look like ``"Process: Process Creation"``; the
    component after the colon (``Process Creation``) matches telemetry log types
    like ``process_creation`` once ``split_data_sources`` normalizes it."""
    return data_source.split(":", 1)[1].strip() if ":" in data_source else data_source.strip()


async def cve_attack_visibility(
    db: AsyncSession,
    cve_pk_to_id: dict[uuid.UUID, str],
    available: set[str] | None = None,
) -> dict[str, dict]:
    """ATT&CK data-source visibility per CVE, from its co-occurring techniques.

    Returns ``{cve_id_str: {detectable, data_sources[], available[], missing[]}}``.
    Only CVEs whose co-occurring techniques carry data sources appear.
    """
    if not cve_pk_to_id:
        return {}
    if available is None:
        available = await get_available_telemetry(db)

    rows = (
        await db.execute(
            select(EntryCVE.cve_id, TTP.data_sources)
            .join(EntryTTP, EntryTTP.entry_id == EntryCVE.entry_id)
            .join(TTP, TTP.id == EntryTTP.ttp_id)
            .where(EntryCVE.cve_id.in_(list(cve_pk_to_id.keys())))
        )
    ).all()

    ds_by_cve: dict[uuid.UUID, set[str]] = {}
    for cve_pk, data_sources in rows:
        for ds in data_sources or []:
            if ds:
                ds_by_cve.setdefault(cve_pk, set()).add(_component(ds))

    out: dict[str, dict] = {}
    for cve_pk, components in ds_by_cve.items():
        sources = sorted(components)
        avail, missing = split_data_sources(sources, available)
        out[cve_pk_to_id[cve_pk]] = {
            "detectable": bool(avail),
            "data_sources": sources,
            "available": avail,
            "missing": missing,
        }
    return out
