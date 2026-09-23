"""Rule → entity resolution.

The false-positive guards are the point of these tests, not an afterthought:
rule bodies carry more English prose than an article does (``description:``,
``falsepositives:``, comments), so the text writer is one loosened check away
from re-creating the alias epidemic the autolinker already lived through.
"""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from sqlalchemy import select, update

from app import entity_types
from app.intelligence.autolinker import EntityVocabulary
from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.rule_coverage import RuleCoverage
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.services.rule_coverage import (
    VIA_META,
    VIA_TAG,
    VIA_TEXT,
    RuleFacts,
    resolve_all,
    resolve_facts,
    resolve_rule,
)


def _facts(**overrides) -> RuleFacts:
    base = {
        "id": uuid.uuid4(),
        "title": "",
        "tags": [],
        "rule_type": "sigma",
        "rule_content": "",
        "source_cves": [],
        "source_ttps": [],
        "source_actors": [],
        "metadata_": {},
    }
    return RuleFacts(**{**base, **overrides})


def _vocab_entity(name, aliases=None):
    entity = MagicMock()
    entity.id = uuid.uuid4()
    entity.name = name
    entity.aliases = aliases or []
    return entity


@pytest.fixture
def vocabulary(monkeypatch):
    """Install a two-entity autolinker vocabulary for the duration of a test."""
    import app.intelligence.autolinker as autolinker
    import app.services.rule_coverage as resolver

    async def _noop(db):
        return None

    def _build(actors=None, malware=None):
        vocab = EntityVocabulary()
        vocab.build_from_entities(actors=actors or [], malware_families=malware or [])
        monkeypatch.setattr(autolinker, "_vocabulary", vocab)
        monkeypatch.setattr(autolinker, "_vocab_version", vocab.version)
        # The resolver would otherwise rebuild the vocabulary from the database
        # and overwrite the one this fixture just installed.
        monkeypatch.setattr(resolver, "_ensure_vocabulary", _noop)
        return vocab

    return _build


# ── tag + meta writers ──────────────────────────────────────────────


def test_tag_writer_reads_all_three_source_columns():
    actor_id = uuid.uuid4()
    rows = resolve_facts(_facts(source_cves=["CVE-2026-1731"], source_ttps=["T1059.001"], source_actors=[actor_id]))
    assert {(r.entity_type, r.entity_key, r.via, r.confidence) for r in rows} == {
        (entity_types.CVE, "CVE-2026-1731", VIA_TAG, "high"),
        (entity_types.TTP, "T1059.001", VIA_TAG, "high"),
        (entity_types.THREAT_ACTOR, str(actor_id), VIA_TAG, "high"),
    }


def test_tag_writer_normalizes_case_and_rejects_malformed_ids():
    rows = resolve_facts(_facts(source_cves=["cve-2026-1731", "CVE-26-1"], source_ttps=["t1059", "TA0001"]))
    assert {(r.entity_type, r.entity_key) for r in rows} == {
        (entity_types.CVE, "CVE-2026-1731"),
        (entity_types.TTP, "T1059"),
    }


def test_meta_writer_uses_stored_extraction():
    rows = resolve_facts(_facts(metadata_={"mitre_attack_ids": ["T1566"], "cve_ids": ["CVE-2023-2868"]}))
    assert {(r.entity_type, r.entity_key, r.via) for r in rows} == {
        (entity_types.TTP, "T1566", VIA_META),
        (entity_types.CVE, "CVE-2023-2868", VIA_META),
    }


def test_meta_writer_parses_content_when_no_metadata_stored():
    content = "title: Test\ntags:\n  - attack.t1003.001\nlogsource:\n  product: windows\ndetection:\n  condition: x\n"
    rows = resolve_facts(_facts(rule_type="sigma", rule_content=content, metadata_=None))
    ttp = [r for r in rows if r.entity_type == entity_types.TTP]
    assert ("T1003.001", VIA_META) in {(r.entity_key, r.via) for r in ttp}


# ── text writer: regex identifiers ──────────────────────────────────


def test_text_confidence_tracks_the_region_that_matched():
    title = resolve_facts(_facts(title="Exploit for CVE-2026-1731"))[0]
    tags = resolve_facts(_facts(tags=["cve-2026-1731"]))[0]
    # Not a "reference:" line — that is a citation and is filtered out entirely
    # (see test_cve_named_only_in_a_citation_is_not_coverage).
    body = resolve_facts(_facts(rule_content="description: exploitation of CVE-2026-1731"))[0]
    assert (title.confidence, tags.confidence, body.confidence) == ("high", "medium", "low")
    assert title.matched_on == "CVE-2026-1731"


def test_cve_named_only_in_a_citation_is_not_coverage():
    """A rule linking to a write-up about a CVE does not detect that CVE.

    Measured at 46 of 318 CVE text rows before this filter: nuclei templates and
    sigma rules routinely cite an advisory URL containing an unrelated CVE id.
    """
    assert resolve_facts(_facts(rule_content="references:\n  - https://x.test/CVE-2017-5638")) == []
    assert resolve_facts(_facts(rule_content="  - https://nvd.nist.gov/vuln/detail/CVE-2017-5638")) == []


def test_cve_named_in_a_detecting_line_still_resolves():
    """The filter is per-occurrence, so a citing rule that also detects still counts."""
    rows = resolve_facts(
        _facts(rule_content="references:\n  - https://x.test/CVE-2017-5638\ndetection: exploit of CVE-2017-5638")
    )
    assert [r.entity_key for r in rows] == ["CVE-2017-5638"]


def test_attack_tag_is_the_only_technique_pattern_read_from_text():
    """A bare ``T1059`` in a rule body is as likely to be a port or an error code."""
    rows = resolve_facts(
        _facts(
            rule_content="tags:\n  - attack.t1059.003\ndetection: EventID 1059 T1059",
            metadata_={"rule_title": "already extracted"},
        )
    )
    assert [(r.entity_key, r.via) for r in rows] == [("T1059.003", VIA_TEXT)]


def test_invalid_subtechnique_falls_back_to_the_parent():
    rows = resolve_facts(_facts(tags=["attack.t1078.000"]))
    assert [r.entity_key for r in rows] == ["T1078"]


# ── text writer: entity names + the false-positive guards ───────────


def test_canonical_name_in_title_resolves_the_entity(vocabulary):
    actor = _vocab_entity("Gamaredon Group")
    vocabulary(actors=[actor])
    rows = resolve_facts(_facts(title="Detects suspicious SFX as used by Gamaredon Group"))
    assert [(r.entity_type, r.entity_key, r.via, r.confidence, r.matched_on) for r in rows] == [
        (entity_types.THREAT_ACTOR, str(actor.id), VIA_TEXT, "high", "Gamaredon Group")
    ]


def test_alias_only_match_is_not_coverage(vocabulary):
    """Aliases are where the dictionary-word false positives live: "BackUp" is an
    alias of a real actor, and every third rule body says it."""
    actor = _vocab_entity("313 Team", aliases=["BackUp"])
    vocabulary(actors=[actor])
    assert resolve_facts(_facts(title="Suspicious BackUp Utility Execution")) == []


def test_common_english_word_canonical_name_is_rejected(vocabulary):
    """ "Registry Hive Dumping" is not a Hive ransomware rule."""
    malware = _vocab_entity("Hive")
    vocabulary(malware=[malware])
    assert resolve_facts(_facts(title="Credential Acquisition via Registry Hive Dumping")) == []


def test_false_positive_name_list_is_applied(vocabulary):
    malware = _vocab_entity("Storm")
    vocabulary(malware=[malware])
    assert resolve_facts(_facts(title="Storm Cloud Backdoor Activity")) == []


def test_binary_filename_entity_never_becomes_coverage(vocabulary):
    """Rules mention system binaries constantly; a malware row named after one
    would match half the library."""
    malware = _vocab_entity("svchost.exe")
    vocabulary(malware=[malware])
    assert resolve_facts(_facts(rule_content="Image|endswith: '\\svchost.exe'")) == []


def test_vendor_and_product_names_are_out_of_scope(vocabulary):
    """Only actors and malware. "Covered by 400 rules because it says Windows"
    is not an answer anyone can act on."""
    actor = _vocab_entity("APT29")
    vocabulary(actors=[actor])
    rows = resolve_facts(_facts(title="Microsoft Windows Defender Tampering by APT29"))
    assert {r.entity_type for r in rows} == {entity_types.THREAT_ACTOR}


# ── precedence ──────────────────────────────────────────────────────


def test_tag_beats_text_for_the_same_entity():
    rows = resolve_facts(_facts(title="Exploit for CVE-2026-1731", source_cves=["CVE-2026-1731"]))
    assert [(r.via, r.confidence, r.matched_on) for r in rows] == [(VIA_TAG, "high", "CVE-2026-1731")]


def test_strongest_region_wins_within_the_text_writer():
    rows = resolve_facts(_facts(tags=["cve-2026-1731"], rule_content="see CVE-2026-1731"))
    assert [(r.via, r.confidence) for r in rows] == [(VIA_TEXT, "medium")]


# ── persistence ─────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def rule(db_session) -> DetectionRule:
    row = DetectionRule(
        title="Detects APT29 Cobalt Strike loader",
        rule_type="sigma",
        rule_content="detection:\n  condition: selection\n",
        source_cves=["CVE-2026-1731"],
        source_ttps=["T1059.001"],
        upstream_updated_at=datetime.now(UTC),
    )
    db_session.add(row)
    await db_session.flush()
    return row


async def _coverage(db, rule_id) -> dict:
    rows = (await db.execute(select(RuleCoverage).where(RuleCoverage.rule_id == rule_id))).scalars().all()
    return {(r.entity_type, r.entity_key): r for r in rows}


async def test_resolve_rule_writes_every_writer(db_session, rule, vocabulary):
    actor = _vocab_entity("APT29")
    vocabulary(actors=[actor])
    await resolve_rule(db_session, rule)

    coverage = await _coverage(db_session, rule.id)
    assert coverage[(entity_types.CVE, "CVE-2026-1731")].via == VIA_TAG
    assert coverage[(entity_types.TTP, "T1059.001")].via == VIA_TAG
    assert coverage[(entity_types.THREAT_ACTOR, str(actor.id))].via == VIA_TEXT


async def test_re_resolving_drops_rows_the_rule_no_longer_earns(db_session, rule, vocabulary):
    actor = _vocab_entity("APT29")
    vocabulary(actors=[actor])
    await resolve_rule(db_session, rule)
    assert (entity_types.THREAT_ACTOR, str(actor.id)) in await _coverage(db_session, rule.id)

    rule.title = "Detects a generic loader"
    rule.source_cves = []
    await db_session.flush()
    await resolve_rule(db_session, rule)

    coverage = await _coverage(db_session, rule.id)
    assert set(coverage) == {(entity_types.TTP, "T1059.001")}


async def test_resolve_all_since_reaches_locally_authored_rules(db_session, vocabulary):
    """upstream_updated_at is NULL for every in-app rule (~540 of them).

    Filtering the incremental pass on the repo-sync watermark alone left an
    authored or edited rule invisible to the board until the next full pass.
    """
    vocabulary()
    local = DetectionRule(title="Authored here", rule_type="sigma", rule_content="x", source_cves=["CVE-2026-4242"])
    db_session.add(local)
    await db_session.flush()
    assert local.upstream_updated_at is None

    await resolve_all(db_session, since=datetime.now(UTC) - timedelta(hours=1))
    assert await _coverage(db_session, local.id)


async def test_resolve_all_since_only_touches_moved_rules(db_session, rule, vocabulary):
    vocabulary()
    old_ts = datetime.now(UTC) - timedelta(days=30)
    stale = DetectionRule(
        title="Untouched",
        rule_type="sigma",
        rule_content="x",
        source_cves=["CVE-2020-0001"],
        upstream_updated_at=old_ts,
    )
    db_session.add(stale)
    await db_session.flush()
    # updated_at defaults to now() on insert, and the incremental pass now reads
    # it too so locally authored rules are not skipped — a genuinely untouched
    # row therefore has to be backdated on both columns.
    await db_session.execute(update(DetectionRule).where(DetectionRule.id == stale.id).values(updated_at=old_ts))

    stats = await resolve_all(db_session, since=datetime.now(UTC) - timedelta(hours=1))

    assert stats["rules"] == 1
    assert await _coverage(db_session, rule.id)
    assert not await _coverage(db_session, stale.id)


# ── the board reads the materialised table ──────────────────────────


async def test_coverage_board_counts_actor_rules(db_session, client, auth_headers, test_feed, vocabulary):
    """The actor branch counted zero forever: `source_actors` is written by
    nothing, so the board could only ever read what the resolver now provides.
    """
    vocabulary()
    actor = ThreatActor(name="APT29")
    entry = Entry(feed_id=test_feed.id, title="APT29 campaign", url="https://x.test/1", guid="g1")
    entry.published_at = datetime.now(UTC)
    db_session.add_all([actor, entry])
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))

    for i in range(3):
        rule_row = DetectionRule(title=f"APT29 rule {i}", rule_type="sigma", rule_content="x")
        db_session.add(rule_row)
        await db_session.flush()
        db_session.add(
            RuleCoverage(
                rule_id=rule_row.id,
                entity_type=entity_types.THREAT_ACTOR,
                entity_key=str(actor.id),
                via=VIA_TEXT,
                confidence="high",
                matched_on="APT29",
            )
        )
    await db_session.flush()

    resp = await client.get("/api/detection-rules/coverage-board?type=actor", headers=auth_headers)
    assert resp.status_code == 200
    item = next(i for i in resp.json()["items"] if i["label"] == "APT29")
    assert item["rule_count"] == 3
    assert item["is_gap"] is False
    assert item["type"] == "threat_actor"
    assert item["id"] == str(actor.id) == item["entity_id"]


async def test_coverage_board_reports_a_gap_when_nothing_resolves(
    db_session, client, auth_headers, test_feed, vocabulary
):
    vocabulary()
    cve = CVE(cve_id="CVE-2026-9999")
    entry = Entry(feed_id=test_feed.id, title="New bug", url="https://x.test/2", guid="g2")
    entry.published_at = datetime.now(UTC)
    db_session.add_all([cve, entry])
    await db_session.flush()
    db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve.id))
    await db_session.flush()

    resp = await client.get("/api/detection-rules/coverage-board?type=cve", headers=auth_headers)
    item = next(i for i in resp.json()["items"] if i["label"] == "CVE-2026-9999")
    assert (item["rule_count"], item["is_gap"], item["sublabel"]) == (0, True, None)
