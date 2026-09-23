"""Tests for the MITRE ATT&CK catalog: STIX parsing, hydration, and validation."""

import pytest
from sqlalchemy import select

from app.intelligence.attack_catalog import (
    hydrate_attack_catalog,
    is_ics_context,
    parse_attack_bundle,
    resolve_technique_ids,
)
from app.intelligence.ttp import store_ttps
from app.models.ttp import TTP, EntryTTP


def _enterprise_bundle() -> dict:
    """Minimal Enterprise STIX 2.1 bundle: technique, sub-technique, revoked
    technique with a revoked-by replacement, mitigation + mitigates link."""
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1059",
                "name": "Command and Scripting Interpreter",
                "description": (
                    "Adversaries may abuse command and script interpreters.\n\nSecond paragraph with citations."
                ),
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059",
                        "url": "https://attack.mitre.org/techniques/T1059",
                    },
                ],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "x_mitre_platforms": ["Windows", "Linux", "macOS"],
                "x_mitre_data_sources": ["Command: Command Execution", "Process: Process Creation"],
                "x_mitre_is_subtechnique": False,
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1059-001",
                "name": "PowerShell",
                "description": "Adversaries may abuse PowerShell.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059.001",
                        "url": "https://attack.mitre.org/techniques/T1059/001",
                    },
                ],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "x_mitre_platforms": ["Windows"],
                "x_mitre_is_subtechnique": True,
            },
            {
                # Revoked legacy technique, replaced by T1059.001
                "type": "attack-pattern",
                "id": "attack-pattern--t1086",
                "name": "PowerShell",
                "revoked": True,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1086",
                        "url": "https://attack.mitre.org/techniques/T1086",
                    },
                ],
            },
            {
                # Multi-tactic technique
                "type": "attack-pattern",
                "id": "attack-pattern--t1078",
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1078",
                        "url": "https://attack.mitre.org/techniques/T1078",
                    },
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                ],
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--m1038",
                "name": "Execution Prevention",
                "description": "Block execution of code.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "M1038",
                        "url": "https://attack.mitre.org/mitigations/M1038",
                    },
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--rev",
                "relationship_type": "revoked-by",
                "source_ref": "attack-pattern--t1086",
                "target_ref": "attack-pattern--t1059-001",
            },
            {
                "type": "relationship",
                "id": "relationship--mit",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--m1038",
                "target_ref": "attack-pattern--t1059",
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--g0016",
                "name": "APT29",
                "aliases": ["APT29", "Cozy Bear"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "G0016"},
                ],
            },
        ],
    }


def _ics_bundle() -> dict:
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t0853",
                "name": "Scripting",
                "description": "Adversaries may use scripting languages in ICS environments.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T0853",
                        "url": "https://attack.mitre.org/techniques/T0853",
                    },
                ],
                "kill_chain_phases": [{"kill_chain_name": "mitre-ics-attack", "phase_name": "execution"}],
                "x_mitre_platforms": ["Engineering Workstation"],
            },
        ],
    }


async def _hydrate(db_session) -> dict:
    parsed = [
        parse_attack_bundle(_enterprise_bundle(), "enterprise"),
        parse_attack_bundle(_ics_bundle(), "ics"),
    ]
    return await hydrate_attack_catalog(db_session, parsed)


# --- Parsing ---------------------------------------------------------------


def test_parse_bundle_technique_fields():
    parsed = parse_attack_bundle(_enterprise_bundle(), "enterprise")
    by_id = {t["technique_id"]: t for t in parsed.techniques}

    t1059 = by_id["T1059"]
    assert t1059["technique_name"] == "Command and Scripting Interpreter"
    assert t1059["tactics"] == ["execution"]
    # First paragraph only
    assert t1059["description"] == "Adversaries may abuse command and script interpreters."
    assert t1059["platforms"] == ["Windows", "Linux", "macOS"]
    assert t1059["data_sources"] == ["Command: Command Execution", "Process: Process Creation"]
    assert t1059["mitre_url"] == "https://attack.mitre.org/techniques/T1059"
    assert t1059["is_subtechnique"] is False
    assert t1059["parent_technique_id"] is None
    assert t1059["is_deprecated"] is False
    assert t1059["matrix_domain"] == "enterprise"


def test_parse_bundle_subtechnique_parent_linkage():
    parsed = parse_attack_bundle(_enterprise_bundle(), "enterprise")
    by_id = {t["technique_id"]: t for t in parsed.techniques}
    sub = by_id["T1059.001"]
    assert sub["is_subtechnique"] is True
    assert sub["parent_technique_id"] == "T1059"


def test_parse_bundle_revoked_with_replacement():
    parsed = parse_attack_bundle(_enterprise_bundle(), "enterprise")
    by_id = {t["technique_id"]: t for t in parsed.techniques}
    revoked = by_id["T1086"]
    assert revoked["is_deprecated"] is True
    assert revoked["superseded_by"] == "T1059.001"


def test_parse_bundle_multi_tactic():
    parsed = parse_attack_bundle(_enterprise_bundle(), "enterprise")
    by_id = {t["technique_id"]: t for t in parsed.techniques}
    assert by_id["T1078"]["tactics"] == ["defense-evasion", "persistence"]


def test_parse_bundle_mitigations_and_links():
    parsed = parse_attack_bundle(_enterprise_bundle(), "enterprise")
    assert [m["mitre_id"] for m in parsed.mitigations] == ["M1038"]
    assert parsed.mitigates == [("M1038", "T1059")]
    assert [g["name"] for g in parsed.intrusion_sets] == ["APT29"]


def test_parse_ics_bundle_domain():
    parsed = parse_attack_bundle(_ics_bundle(), "ics")
    assert parsed.techniques[0]["technique_id"] == "T0853"
    assert parsed.techniques[0]["matrix_domain"] == "ics"


# --- Hydration ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_hydrate_creates_and_backfills(db_session):
    # Pre-create a broken stub row (the prod failure mode: name == id, no tactic)
    stub = TTP(technique_id="T1059", technique_name="T1059", article_count=7)
    db_session.add(stub)
    await db_session.flush()

    stats = await _hydrate(db_session)
    assert stats["enterprise"]["techniques_updated"] == 1
    assert stats["enterprise"]["techniques_created"] == 3
    assert stats["enterprise"]["mitigations_created"] == 1
    assert stats["enterprise"]["ttp_mitigation_links"] == 1
    assert stats["ics"]["techniques_created"] == 1

    refreshed = (await db_session.execute(select(TTP).where(TTP.technique_id == "T1059"))).scalar_one()
    assert refreshed.id == stub.id  # updated in place
    assert refreshed.technique_name == "Command and Scripting Interpreter"
    assert refreshed.tactic == "execution"
    assert refreshed.tactics == ["execution"]
    assert refreshed.platforms == ["Windows", "Linux", "macOS"]
    assert refreshed.matrix_domain == "enterprise"
    assert refreshed.article_count == 7  # usage stats preserved


@pytest.mark.asyncio
async def test_hydrate_is_idempotent(db_session):
    await _hydrate(db_session)
    stats = await _hydrate(db_session)
    assert stats["enterprise"]["techniques_created"] == 0
    assert stats["enterprise"]["techniques_updated"] == 4
    # No duplicate mitigation links on re-run
    assert stats["enterprise"]["ttp_mitigation_links"] == 0


@pytest.mark.asyncio
async def test_hydrate_preserves_analyst_description(db_session):
    stub = TTP(
        technique_id="T1078",
        technique_name="T1078",
        description="Analyst-written context notes.",
    )
    db_session.add(stub)
    await db_session.flush()

    await _hydrate(db_session)
    refreshed = (await db_session.execute(select(TTP).where(TTP.technique_id == "T1078"))).scalar_one()
    assert refreshed.description == "Analyst-written context notes."
    assert refreshed.technique_name == "Valid Accounts"


# --- Validation ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_passthrough_before_hydration(db_session):
    resolved = await resolve_technique_ids(db_session, ["T1059", "T9999"], "any text")
    assert resolved == {"T1059": "T1059", "T9999": "T9999"}


@pytest.mark.asyncio
async def test_resolve_drops_unknown_ids(db_session):
    await _hydrate(db_session)
    resolved = await resolve_technique_ids(db_session, ["T1059", "T9999"], "any text")
    assert resolved["T1059"] == "T1059"
    assert resolved["T9999"] is None


@pytest.mark.asyncio
async def test_resolve_maps_revoked_to_replacement(db_session):
    await _hydrate(db_session)
    resolved = await resolve_technique_ids(db_session, ["T1086"], "any text")
    assert resolved["T1086"] == "T1059.001"


@pytest.mark.asyncio
async def test_resolve_gates_ics_without_context(db_session):
    await _hydrate(db_session)
    resolved = await resolve_technique_ids(
        db_session, ["T0853"], "A blog post about web application firewalls and XSS."
    )
    assert resolved["T0853"] is None


@pytest.mark.asyncio
async def test_resolve_accepts_ics_with_context(db_session):
    await _hydrate(db_session)
    resolved = await resolve_technique_ids(
        db_session, ["T0853"], "Attackers targeted SCADA systems at a water treatment plant."
    )
    assert resolved["T0853"] == "T0853"


def test_is_ics_context_word_boundaries():
    # "ot" must not fire inside ordinary words
    assert is_ics_context("This is another boring article about bots.") is False
    assert is_ics_context("The OT network was segmented from IT.") is True
    assert is_ics_context("Malware hit the PLC controlling the pipeline.") is True
    assert is_ics_context(None) is False
    assert is_ics_context("") is False


# --- store_ttps integration ---------------------------------------------------


@pytest.mark.asyncio
async def test_store_ttps_drops_unknown_and_never_creates_stub_rows(db_session, test_entry):
    await _hydrate(db_session)
    stored = await store_ttps(
        db_session,
        test_entry.id,
        [
            {"technique_id": "T1059", "technique_name": "T1059", "confidence": "medium", "source": "regex"},
            {"technique_id": "T9999", "technique_name": "T9999", "confidence": "medium", "source": "regex"},
        ],
    )
    ids = {t.technique_id for t, _ in stored}
    assert ids == {"T1059"}
    # No stub row was created for the unknown id
    unknown = (await db_session.execute(select(TTP).where(TTP.technique_id == "T9999"))).scalar_one_or_none()
    assert unknown is None
    # And nothing in the DB carries name == id anymore
    for ttp, is_new in stored:
        assert not is_new
        assert ttp.technique_name != ttp.technique_id


@pytest.mark.asyncio
async def test_store_ttps_gates_ics_by_entry_context(db_session, test_entry):
    # test_entry content is about APT29/CVEs — not ICS
    await _hydrate(db_session)
    stored = await store_ttps(
        db_session,
        test_entry.id,
        [{"technique_id": "T0853", "technique_name": "T0853"}],
    )
    assert stored == []
    links = (await db_session.execute(select(EntryTTP).where(EntryTTP.entry_id == test_entry.id))).scalars().all()
    assert links == []


@pytest.mark.asyncio
async def test_store_ttps_remaps_revoked_and_dedupes(db_session, test_entry):
    await _hydrate(db_session)
    stored = await store_ttps(
        db_session,
        test_entry.id,
        [
            {"technique_id": "T1086", "technique_name": "PowerShell"},
            {"technique_id": "T1059.001", "technique_name": "PowerShell"},
        ],
        context_text="Attackers used PowerShell.",
    )
    ids = [t.technique_id for t, _ in stored]
    assert ids == ["T1059.001"]


@pytest.mark.asyncio
async def test_store_ttps_downgrades_confidence_when_name_contradicts_id(db_session, test_entry):
    """A syntactically valid but mispaired ID keeps its link and loses its confidence.

    Local models reliably emit real technique IDs attached to the wrong
    technique name; the ID passes validation, so the bad mapping would
    otherwise land silently at full confidence.
    """
    await _hydrate(db_session)
    stored = await store_ttps(
        db_session,
        test_entry.id,
        [
            # T1059.001 is "PowerShell" in the bundle — naming a different
            # technique means the extractor was confused about which it meant.
            {"technique_id": "T1059.001", "technique_name": "Clear Windows Event Logs", "confidence": "high"},
        ],
        context_text="Attackers used PowerShell.",
    )
    assert [t.technique_id for t, _ in stored] == ["T1059.001"]
    link = (await db_session.execute(select(EntryTTP).where(EntryTTP.entry_id == test_entry.id))).scalar_one()
    assert link.confidence == "low"


@pytest.mark.asyncio
async def test_store_ttps_keeps_confidence_when_name_agrees(db_session, test_entry):
    await _hydrate(db_session)
    await store_ttps(
        db_session,
        test_entry.id,
        [
            # Parent-prefixed form of the catalog's "PowerShell" still agrees.
            {
                "technique_id": "T1059.001",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "confidence": "high",
            }
        ],
        context_text="Attackers used PowerShell.",
    )
    link = (await db_session.execute(select(EntryTTP).where(EntryTTP.entry_id == test_entry.id))).scalar_one()
    assert link.confidence == "high"
