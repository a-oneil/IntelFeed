"""Autolink CVE stubs and the retroactive backlink follow the same rules as ingest.

- A CVE id autolink sees becomes a stub only when it isn't on the analyst
  do-not-recreate list; the stub is marked created_via="auto_link" and queued
  for enrichment.
- The nightly NVD backfill spends a bounded retry budget on ids NVD has no
  record of, instead of looking every junk id up again every night.
- The backlink run when an entity or alias is added skips manual/none feeds,
  honours the FP list and the capital-letter check, and scales confidence by
  the feed's reliability.
"""

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

import app.intelligence.autolinker as autolinker_mod
from app.intelligence.autolinker import (
    EntityVocabulary,
    _link_entity_to_existing_entries_inner,
    autolink_entry,
    store_autolink_matches,
)
from app.intelligence.entity_resolution import DO_NOT_RECREATE_SOURCE, normalize_entity_name
from app.models.cve import CVE, EntryCVE
from app.models.entity_index import EntityNameDenylist
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily


async def _mk_entry(db, text: str, *, mode: str = "full", rating: str | None = "A", title: str = "Report") -> Entry:
    feed = Feed(
        title=f"Feed {uuid.uuid4().hex[:6]}",
        url=f"https://feed.example/{uuid.uuid4()}",
        feed_type="rss",
        intel_extraction_mode=mode,
        reliability_rating=rating,
    )
    db.add(feed)
    await db.flush()
    entry = Entry(
        feed_id=feed.id,
        title=title,
        guid=f"guid-{uuid.uuid4()}",
        url=f"https://example.com/{uuid.uuid4()}",
        content_text=text,
    )
    db.add(entry)
    await db.flush()
    return entry


def _cve_match(cve_id: str) -> dict:
    return {
        "entity_type": "cve",
        "entity_id": None,
        "canonical_name": cve_id,
        "surface_form": cve_id,
        "confidence": "high",
        "source": "auto_link",
        "lookup_key": cve_id,
        "paragraph_indices": [0],
    }


# ── CVE stubs from autolink ─────────────────────────────────────────


async def test_new_cve_stub_is_marked_auto_link(db_session):
    entry = await _mk_entry(db_session, "Patch CVE-2026-31337 now.")
    stored = await store_autolink_matches(db_session, entry.id, [_cve_match("CVE-2026-31337")])

    assert len(stored) == 1 and stored[0]["is_new_stub"] is True
    cve = (await db_session.execute(select(CVE).where(CVE.cve_id == "CVE-2026-31337"))).scalar_one()
    assert cve.created_via == "auto_link"
    assert cve.created_from_entry_id == entry.id


async def test_existing_cve_is_linked_not_restamped(db_session):
    db_session.add(CVE(cve_id="CVE-2024-3400", created_via="ai_extraction"))
    await db_session.flush()
    entry = await _mk_entry(db_session, "CVE-2024-3400 again.")
    stored = await store_autolink_matches(db_session, entry.id, [_cve_match("CVE-2024-3400")])

    assert stored[0]["is_new_stub"] is False
    cve = (await db_session.execute(select(CVE).where(CVE.cve_id == "CVE-2024-3400"))).scalar_one()
    assert cve.created_via == "ai_extraction"
    link = await db_session.execute(select(EntryCVE).where(EntryCVE.entry_id == entry.id))
    assert link.scalar_one_or_none() is not None


async def test_denied_cve_is_not_recreated(db_session):
    db_session.add(
        EntityNameDenylist(
            entity_type="cve",
            normalized_name=normalize_entity_name("CVE-2026-00001", "cve").norm_exact,
            display_name="CVE-2026-00001",
            source=DO_NOT_RECREATE_SOURCE,
        )
    )
    await db_session.flush()
    entry = await _mk_entry(db_session, "Junk id CVE-2026-00001 in a footer.")
    stored = await store_autolink_matches(db_session, entry.id, [_cve_match("CVE-2026-00001")])

    assert stored == []
    assert (await db_session.execute(select(CVE).where(CVE.cve_id == "CVE-2026-00001"))).scalar_one_or_none() is None


async def test_autolink_entry_queues_enrichment_for_new_cve_stub(db_session, monkeypatch):
    from app.workers.enrichment_tasks import auto_enrich_entity

    async def _noop(_db):
        return None

    monkeypatch.setattr(autolinker_mod, "_ensure_vocabulary", _noop)
    vocab = EntityVocabulary()
    vocab.build_from_entities([], [])
    monkeypatch.setattr(autolinker_mod, "_vocabulary", vocab)
    queued: list[dict] = []
    monkeypatch.setattr(auto_enrich_entity, "delay", lambda **kw: queued.append(kw))

    entry = await _mk_entry(db_session, "Exploitation of CVE-2026-40404 began Monday.")
    await autolink_entry(db_session, entry.id, entry.content_text, entry.title, "")

    assert [(q["entity_type"], q["entity_value"]) for q in queued] == [("cve", "CVE-2026-40404")]

    # A second article mentioning the same id links the existing row: no new stub, no new job.
    other = await _mk_entry(db_session, "More on CVE-2026-40404.")
    await autolink_entry(db_session, other.id, other.content_text, other.title, "")
    assert len(queued) == 1


# ── NVD backfill retry budget ───────────────────────────────────────


@pytest.fixture
def backfill(db_session, monkeypatch):
    import app.services.system_settings as ss
    import app.workers.enrichment_tasks as tasks
    from app.intelligence import cve as cve_mod

    @asynccontextmanager
    async def fake_session():
        yield db_session

    async def fake_setting(key, db=None):
        return "test-key"  # keyed pacing: 0.7s between calls

    looked_up: list[str] = []

    async def fake_enrich(cve_id, gateway, api_key=None):
        looked_up.append(cve_id)
        return None  # NVD has nothing for any of these

    monkeypatch.setattr(tasks, "_get_worker_session", fake_session)
    monkeypatch.setattr(ss, "get_setting", fake_setting)
    monkeypatch.setattr(cve_mod, "enrich_from_nvd", fake_enrich)
    return tasks._run_cve_nvd_backfill, looked_up


async def test_backfill_stamps_misses_and_respects_the_budget(db_session, backfill):
    run, looked_up = backfill
    recent = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    old = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    fresh = CVE(cve_id="CVE-2026-11111", created_via="auto_link", nvd_data={})
    spent = CVE(cve_id="CVE-2026-22222", nvd_data={"_enrich_attempts": 3, "_enrich_last_attempt": old})
    cooling = CVE(cve_id="CVE-2026-33333", nvd_data={"_enrich_attempts": 1, "_enrich_last_attempt": recent})
    due = CVE(cve_id="CVE-2026-44444", nvd_data={"_enrich_attempts": 2, "_enrich_last_attempt": old})
    db_session.add_all([fresh, spent, cooling, due])
    await db_session.flush()

    stats = await run()

    assert sorted(looked_up) == ["CVE-2026-11111", "CVE-2026-44444"]
    assert stats["failed"] == 2
    await db_session.refresh(fresh)
    await db_session.refresh(due)
    assert fresh.nvd_data["_enrich_attempts"] == 1
    assert due.nvd_data["_enrich_attempts"] == 3

    # The next night nothing above is due: one is spent, the others cooling off.
    looked_up.clear()
    await run()
    assert looked_up == []


async def test_backfill_rate_limit_does_not_spend_a_retry(db_session, backfill, monkeypatch):
    from app.enrichment.gateway import RateLimited
    from app.intelligence import cve as cve_mod

    run, _ = backfill

    async def throttled(cve_id, gateway, api_key=None):
        raise RateLimited("nvd", 60)

    monkeypatch.setattr(cve_mod, "enrich_from_nvd", throttled)
    row = CVE(cve_id="CVE-2026-55555", nvd_data={})
    db_session.add(row)
    await db_session.flush()

    stats = await run()

    assert stats["stopped"] == "rate_limited"
    await db_session.refresh(row)
    assert "_enrich_attempts" not in row.nvd_data


# ── Retroactive backlink ────────────────────────────────────────────


async def _mk_malware(db, name: str, aliases: list[str] | None = None) -> MalwareFamily:
    row = MalwareFamily(name=name, aliases=aliases or [])
    db.add(row)
    await db.flush()
    return row


async def _backlink(db, entity_type: str, entity_id: uuid.UUID) -> dict:
    return await _link_entity_to_existing_entries_inner(
        db, entity_type, entity_id, 500, {"scanned": 0, "linked": 0, "entity_type": entity_type}
    )


async def _links(db, malware_id: uuid.UUID) -> dict[uuid.UUID, str]:
    rows = await db.execute(
        select(EntryMalware.entry_id, EntryMalware.confidence).where(EntryMalware.malware_family_id == malware_id)
    )
    return dict(rows.all())


async def test_backlink_skips_manual_and_none_feeds(db_session):
    malware = await _mk_malware(db_session, "Zloader")
    full = await _mk_entry(db_session, "Zloader returns.", mode="full")
    selective = await _mk_entry(db_session, "Zloader returns.", mode="selective")
    manual = await _mk_entry(db_session, "Zloader returns.", mode="manual")
    none = await _mk_entry(db_session, "Zloader returns.", mode="none")

    await _backlink(db_session, "malware", malware.id)

    linked = await _links(db_session, malware.id)
    assert full.id in linked and selective.id in linked
    assert manual.id not in linked and none.id not in linked


async def test_backlink_applies_the_false_positive_list(db_session, monkeypatch):
    monkeypatch.setattr(autolinker_mod, "_get_fp_names", lambda: frozenset({"agent"}))
    malware = await _mk_malware(db_session, "Agent Tesla", aliases=["Agent"])
    only_fp = await _mk_entry(db_session, "The Agent was arrested in Madrid.")
    real = await _mk_entry(db_session, "Agent Tesla spreads through invoices.")

    await _backlink(db_session, "malware", malware.id)

    linked = await _links(db_session, malware.id)
    assert real.id in linked
    assert only_fp.id not in linked


async def test_backlink_requires_capital_letter_for_ambiguous_names(db_session, monkeypatch):
    monkeypatch.setattr(autolinker_mod, "_get_fp_names", lambda: frozenset())
    malware = await _mk_malware(db_session, "Hive")
    prose = await _mk_entry(db_session, "Bees returned to the hive after the storm.")
    named = await _mk_entry(db_session, "Hive affiliates hit a hospital.")

    await _backlink(db_session, "malware", malware.id)

    linked = await _links(db_session, malware.id)
    assert named.id in linked
    assert prose.id not in linked


async def test_backlink_confidence_scales_with_feed_reliability(db_session, monkeypatch):
    monkeypatch.setattr(autolinker_mod, "_get_fp_names", lambda: frozenset())
    malware = await _mk_malware(db_session, "Zloader", aliases=["Terdot Loader"])
    a_canonical = await _mk_entry(db_session, "Zloader returns.", rating="A")
    unrated_canonical = await _mk_entry(db_session, "Zloader returns.", rating=None)
    a_alias = await _mk_entry(db_session, "Terdot Loader returns.", rating="A")
    d_alias = await _mk_entry(db_session, "Terdot Loader returns.", rating="D")

    await _backlink(db_session, "malware", malware.id)

    linked = await _links(db_session, malware.id)
    assert linked[a_canonical.id] == "high"
    assert linked[unrated_canonical.id] == "medium"
    assert linked[a_alias.id] == "medium"
    assert linked[d_alias.id] == "low"


def test_reliability_weight_is_shared_with_ingest():
    from app.workers.intel_feed_tasks import _reliability_to_weight

    assert _reliability_to_weight("A") == autolinker_mod.reliability_to_weight("A") == 1.0
    assert _reliability_to_weight(None) == autolinker_mod.reliability_to_weight(None) == 0.5
