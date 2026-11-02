"""MITRE D3FEND: the defensive techniques that counter each ATT&CK technique.

The weekly job asks D3FEND for its current release, then streams that
release's ``d3fend-full-mappings.csv`` (~15 MB): one row per inferred path
from a defensive technique, through the digital artifacts both act on, to an
offensive technique. It keeps each offensive technique's defensive techniques
(``def_tech``, with their label and tactic) and writes them as profile
context, with a link to the technique's D3FEND page.

The file lists only a technique's own mappings. D3FEND's page for a technique
(and its API) adds those inherited through ATT&CK's hierarchy, and so does
``countermeasures``: a sub-technique takes its parent's, a parent its
sub-techniques'.
"""

from __future__ import annotations

import csv
import logging
import re
import tempfile

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.base import EnrichmentData, Source
from app.enrichment.gateway import SOURCE_REFUSALS, SourceGateway
from app.enrichment.manifest import Context, Display, Egress, Job, License, Quota

logger = logging.getLogger(__name__)

VERSION_URL = "https://d3fend.mitre.org/api/version.json"
MAPPINGS_URL = "https://d3fend.mitre.org/ontologies/d3fend/{version}/d3fend-full-mappings.csv"
PAGE_URL = "https://d3fend.mitre.org/offensive-technique/attack/{technique_id}/"
#: The weekly job plus a missed run.
TTL_HOURS = 24 * 14

#: D3FEND's tactics in the order it lists them.
TACTICS = ("Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore")
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


class D3FENDSource(Source):
    source_type = "d3fend"
    display_name = "MITRE D3FEND"
    about = "MITRE's catalog of defensive techniques, mapped to the attacks they counter."
    applies_to = {"ttp": None}
    # D3FEND publishes no rate limit; a run makes two requests.
    quota = Quota(10, 3600, daily_budget=50)
    egress = Egress.NONE
    # Free for research, development and commercial use, reproducing MITRE's
    # copyright designation: https://d3fend.mitre.org/tou/
    license = License("MITRE D3FEND terms of use", attribution="MITRE D3FEND™ is a trademark of The MITRE Corporation")
    jobs = (
        Job(
            "d3fend-sync",
            "app.workers.enrichment_tasks.run_d3fend_sync",
            {"type": "crontab", "minute": "30", "hour": "4", "day_of_week": "0"},
            "Map D3FEND defensive techniques onto the ATT&CK techniques they counter",
            counts=False,
        ),
    )
    outputs = (
        Context(
            "countermeasures",
            "Countermeasures",
            Display.TABLE,
            item={"Defensive technique": "technique", "Tactic": "tactic"},
        ),
        Context("link", "D3FEND", Display.LINK),
    )


def read_mappings(fh) -> dict[str, dict[str, tuple[str, str]]]:
    """Offensive technique id → {defensive technique IRI name: (label, tactic)}
    from the CSV (an open file or its lines)."""
    rows = csv.reader(fh)
    header = next(rows, None)
    if not header:
        return {}
    col = {name: i for i, name in enumerate(header)}
    off_id, def_iri, def_label, tactic = (
        col["off_tech_id"],
        col["def_tech"],
        col["def_tech_label"],
        col["def_tactic_label"],
    )
    own: dict[str, dict[str, tuple[str, str]]] = {}
    for row in rows:
        if len(row) < len(header) or not _TECHNIQUE_ID.match(row[off_id]):
            continue
        name = row[def_iri].rsplit("#", 1)[-1]
        if name and row[def_label]:
            own.setdefault(row[off_id], {})[name] = (row[def_label], row[tactic])
    return own


def countermeasures(technique_id: str, own: dict[str, dict[str, tuple[str, str]]]) -> list[dict]:
    """The technique's defensive techniques, its own with those inherited
    through ATT&CK's hierarchy, ordered by tactic then name."""
    found = dict(own.get(technique_id, {}))
    if "." in technique_id:
        found.update(own.get(technique_id.split(".")[0], {}))
    else:
        for other, defenses in own.items():
            if other.startswith(technique_id + "."):
                found.update(defenses)
    order = {t: i for i, t in enumerate(TACTICS)}
    return [
        {"technique": label, "tactic": tactic}
        for label, tactic in sorted(found.values(), key=lambda d: (order.get(d[1], len(TACTICS)), d[0]))
    ]


async def sync_d3fend(db: AsyncSession, gateway: SourceGateway) -> dict:
    """Read the current release's mappings, then write every technique D3FEND
    counters or that showed countermeasures before. A refusal stops the run
    before anything is written."""
    from app.enrichment.pipeline import apply_catalog_result
    from app.models.enrichment import EntityContext
    from app.models.ttp import TTP

    stats = {"version": None, "mapped": 0, "techniques": 0, "stopped": None}
    async with gateway.client(timeout=120.0) as client:
        try:
            resp = await client.get(VERSION_URL)
            resp.raise_for_status()
            version = resp.json().get("version")
            if not (isinstance(version, str) and _VERSION.match(version)):
                raise RuntimeError(f"D3FEND reported version {version!r}")
            stats["version"] = version
            # Spooled to disk, not held: the file is ~15 MB.
            with tempfile.TemporaryFile("w+", encoding="utf-8", newline="") as fh:
                async with client.stream("GET", MAPPINGS_URL.format(version=version)) as resp:
                    resp.raise_for_status()
                    async for chunk in resp.aiter_text():
                        fh.write(chunk)
                fh.seek(0)
                own = read_mappings(fh)
        except SOURCE_REFUSALS as e:
            logger.warning("D3FEND sync skipped: %s", e)
            return {**stats, "stopped": e.status}
    if not own:
        raise RuntimeError(f"D3FEND {version} mappings held no techniques")
    stats["mapped"] = len(own)

    shown = set(
        (
            await db.execute(
                select(EntityContext.entity_id).where(
                    EntityContext.entity_type == "ttp", EntityContext.source_type == D3FENDSource.source_type
                )
            )
        ).scalars()
    )
    for ttp_id, technique_id in (await db.execute(select(TTP.id, TTP.technique_id))).all():
        found = countermeasures(technique_id, own)
        if not found and ttp_id not in shown:
            continue
        parsed = {"countermeasures": found}
        if found:
            parsed["link"] = {
                "url": PAGE_URL.format(technique_id=technique_id),
                "label": f"D3FEND · {technique_id}",
            }
        data = EnrichmentData(raw_response=parsed, parsed_data=parsed, ttl_hours=TTL_HOURS)
        await apply_catalog_result(db, "ttp", ttp_id, D3FENDSource.source_type, data)
        stats["techniques"] += bool(found)
    await db.commit()
    return stats
