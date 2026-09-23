"""Threat-board story lines, and the vulnerability half that never got one.

CVE rows have been ranked and rendered on the board since it shipped, but they
were briefed by nothing: the nightly fan-out only walked ``build_threat_board``
(actors and malware), and even when reached, ``_BRIEF_ENTRIES_SQL`` had no CVE
branch, so ``collect_brief_entries`` returned an empty list and every
vulnerability row fell back to its lead headline. On prod that was 0 briefs
across 60 CVE rows against ~45% of the actor/malware rows.

These cover both halves of that: the collector now resolves CVE rows, and the
task routing sends them to their own prompt.
"""

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest

from app import entity_types
from app.models.cve import CVE, EntryCVE
from app.models.cve_affected import CVEAffected
from app.models.entry import Entry
from app.models.product import Product
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP
from app.models.vendor import Vendor
from app.services.threat_brief import (
    CVE_TASK_NAME,
    TASK_NAME,
    brief_target_id,
    collect_brief_entries,
    collect_cve_facts,
    task_name_for,
)


class TestTaskRouting:
    def test_cve_rows_use_the_vulnerability_prompt(self):
        assert task_name_for(entity_types.CVE) == CVE_TASK_NAME

    @pytest.mark.parametrize("etype", [entity_types.THREAT_ACTOR, entity_types.MALWARE])
    def test_threat_rows_keep_the_actor_prompt(self, etype):
        assert task_name_for(etype) == TASK_NAME

    def test_the_two_prompts_are_distinct(self):
        assert CVE_TASK_NAME != TASK_NAME

    def test_cache_ids_cannot_collide_across_types(self):
        """Both tasks write one target_type, so the id must carry the type."""
        assert brief_target_id(entity_types.CVE, "shared-key") != brief_target_id(
            entity_types.THREAT_ACTOR, "shared-key"
        )


@pytest.mark.asyncio
class TestCollectBriefEntries:
    async def _seed_cve(self, db_session, test_feed, *, cve_id: str, titles: list[str], **cve_kw):
        now = datetime.now(UTC)
        cve = CVE(cve_id=cve_id, **cve_kw)
        db_session.add(cve)
        await db_session.flush()
        for i, title in enumerate(titles):
            entry = Entry(
                feed_id=test_feed.id,
                guid=f"{cve_id}-{i}-{uuid.uuid4()}",
                title=title,
                url=f"https://outlet{i}.example.com/{cve_id}-{i}",
                summary=f"Body for {title}",
                published_at=now - timedelta(days=1),
            )
            db_session.add(entry)
            await db_session.flush()
            db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve.id))
        await db_session.flush()
        return cve

    async def test_cve_row_resolves_its_window_entries(self, db_session, test_feed):
        """The regression itself: this returned [] for every CVE row."""
        await self._seed_cve(
            db_session,
            test_feed,
            cve_id="CVE-2026-11111",
            titles=["CVE-2026-11111 exploited in the wild", "Weekly roundup"],
        )
        await db_session.commit()

        entries = await collect_brief_entries(db_session, entity_types.CVE, "CVE-2026-11111", 336)

        assert len(entries) == 2
        assert {e["title"] for e in entries} == {
            "CVE-2026-11111 exploited in the wild",
            "Weekly roundup",
        }

    async def test_cve_rows_key_on_cve_id_not_the_row_uuid(self, db_session, test_feed):
        """CVE board rows are keyed by the string id everywhere else."""
        cve = await self._seed_cve(db_session, test_feed, cve_id="CVE-2026-22222", titles=["A write-up"])
        await db_session.commit()

        assert await collect_brief_entries(db_session, entity_types.CVE, "CVE-2026-22222", 336)
        assert await collect_brief_entries(db_session, entity_types.CVE, str(cve.id), 336) == []

    async def test_does_not_bleed_entries_from_another_cve(self, db_session, test_feed):
        await self._seed_cve(db_session, test_feed, cve_id="CVE-2026-33333", titles=["Mine"])
        await self._seed_cve(db_session, test_feed, cve_id="CVE-2026-44444", titles=["Theirs", "Also theirs"])
        await db_session.commit()

        entries = await collect_brief_entries(db_session, entity_types.CVE, "CVE-2026-33333", 336)
        assert [e["title"] for e in entries] == ["Mine"]

    async def test_window_excludes_older_articles(self, db_session, test_feed):
        cve = CVE(cve_id="CVE-2026-55555")
        db_session.add(cve)
        await db_session.flush()
        for label, age in (("fresh", 1), ("stale", 40)):
            entry = Entry(
                feed_id=test_feed.id,
                guid=f"win-{label}",
                title=f"{label} report",
                url=f"https://x.example.com/{label}",
                published_at=datetime.now(UTC) - timedelta(days=age),
            )
            db_session.add(entry)
            await db_session.flush()
            db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve.id))
        await db_session.commit()

        entries = await collect_brief_entries(db_session, entity_types.CVE, "CVE-2026-55555", 336)
        assert [e["title"] for e in entries] == ["fresh report"]

    async def test_carries_extracted_techniques_through(self, db_session, test_feed):
        cve = CVE(cve_id="CVE-2026-66666")
        db_session.add(cve)
        await db_session.flush()
        entry = Entry(
            feed_id=test_feed.id,
            guid="ttp-carrier",
            title="CVE-2026-66666 chained for access",
            url="https://x.example.com/ttp",
            published_at=datetime.now(UTC) - timedelta(days=1),
        )
        db_session.add(entry)
        await db_session.flush()
        db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve.id))
        ttp = TTP(technique_id="T1190", technique_name="Exploit Public-Facing Application")
        db_session.add(ttp)
        await db_session.flush()
        db_session.add(EntryTTP(entry_id=entry.id, ttp_id=ttp.id, source_text="reached via the /upload endpoint"))
        await db_session.commit()

        entries = await collect_brief_entries(db_session, entity_types.CVE, "CVE-2026-66666", 336)

        assert entries[0]["techniques"] == ["T1190 Exploit Public-Facing Application"]
        assert entries[0]["quotes"] == ["reached via the /upload endpoint"]

    async def test_actor_path_is_unchanged(self, db_session, test_feed):
        """The CVE branch must not disturb the collector it was added beside."""
        actor = ThreatActor(name="Briefable")
        db_session.add(actor)
        await db_session.flush()
        entry = Entry(
            feed_id=test_feed.id,
            guid="actor-entry",
            title="Briefable hits a bank",
            url="https://x.example.com/actor",
            published_at=datetime.now(UTC) - timedelta(days=1),
        )
        db_session.add(entry)
        await db_session.flush()
        db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
        await db_session.commit()

        entries = await collect_brief_entries(db_session, entity_types.THREAT_ACTOR, str(actor.id), 336)
        assert [e["title"] for e in entries] == ["Briefable hits a bank"]


@pytest.mark.asyncio
class TestCollectCveFacts:
    async def test_returns_the_exploitation_state_the_prompt_grounds_on(self, db_session):
        cve = CVE(
            cve_id="CVE-2026-77777",
            description="Pre-auth RCE in the widget parser.",
            severity="CRITICAL",
            cvss_score=9.8,
            epss_score=0.71,
            is_kev=True,
            kev_date_added=date(2026, 9, 1),
            exploit_status="weaponized",
        )
        db_session.add(cve)
        await db_session.commit()

        facts = await collect_cve_facts(db_session, "CVE-2026-77777")

        assert facts["description"] == "Pre-auth RCE in the widget parser."
        assert facts["severity"] == "CRITICAL"
        assert facts["cvss_score"] == 9.8
        assert facts["epss_score"] == pytest.approx(0.71)
        assert facts["is_kev"] is True
        assert facts["kev_date_added"] == "2026-09-01"
        assert facts["exploit_status"] == "weaponized"

    async def test_scores_are_json_plain_not_decimal(self, db_session):
        """cvss_score is Numeric; a Decimal leaking into the variables is a trap."""
        db_session.add(CVE(cve_id="CVE-2026-88888", cvss_score=7.5))
        await db_session.commit()

        facts = await collect_cve_facts(db_session, "CVE-2026-88888")
        assert type(facts["cvss_score"]) is float

    async def test_includes_affected_products(self, db_session):
        vendor = Vendor(name="Acme")
        product = Product(name="Acme Gateway")
        cve = CVE(cve_id="CVE-2026-99999")
        db_session.add_all([vendor, product, cve])
        await db_session.flush()
        db_session.add(
            CVEAffected(
                cve_id=cve.id,
                cpe_vendor="acme",
                cpe_product="gateway",
                vendor_id=vendor.id,
                product_id=product.id,
            )
        )
        await db_session.commit()

        facts = await collect_cve_facts(db_session, "CVE-2026-99999")
        assert facts["affected"] == ["Acme Gateway"]

    async def test_unknown_cve_is_empty_not_an_error(self, db_session):
        assert await collect_cve_facts(db_session, "CVE-1999-00001") == {}


@pytest.mark.asyncio
class TestFoldingByStory:
    """The prompt sees one article per story, not the pile it arrived in."""

    async def _actor_with_entries(self, db_session, test_feed, *, name: str, count: int):
        from sqlalchemy import text

        actor = ThreatActor(name=name)
        db_session.add(actor)
        await db_session.flush()
        now = datetime.now(UTC)
        entries = []
        for i in range(count):
            entry = Entry(
                feed_id=test_feed.id,
                guid=f"{name}-brief-{i}",
                title=f"{name} coverage {i}",
                url=f"https://outlet{i}.example.com/{name}-{i}",
                summary="Body of the report.",
                published_at=now - timedelta(hours=i + 1),
            )
            db_session.add(entry)
            await db_session.flush()
            db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
            entries.append(entry)
        await db_session.flush()
        return actor, entries, text

    async def test_one_story_is_one_article_in_the_prompt(self, db_session, test_feed):
        actor, entries, text = await self._actor_with_entries(db_session, test_feed, name="Folded", count=5)
        thread_id = str(uuid.uuid4())
        await db_session.execute(
            text(
                """
                INSERT INTO story_threads (id, slug, title, status, entry_count, source_count,
                                           first_seen, last_seen, key_entities)
                VALUES (:id, 'folded-wave', 'Folded wave', 'open', 4, 4,
                        now() - interval '2 days', now(), '[]'::jsonb)
                """
            ),
            {"id": thread_id},
        )
        # Four of the five are one story; the fifth is its own.
        for i, entry in enumerate(entries[:4]):
            await db_session.execute(
                text(
                    "INSERT INTO story_thread_entries (id, thread_id, entry_id, role, similarity) "
                    "VALUES (:id, :tid, :eid, :role, 0.9)"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tid": thread_id,
                    "eid": str(entry.id),
                    "role": "origin" if i == 0 else "beat",
                },
            )
        await db_session.commit()

        rows = await collect_brief_entries(db_session, entity_types.THREAT_ACTOR, str(actor.id), 336)
        assert len(rows) == 2, [r["title"] for r in rows]
        folded = next(r for r in rows if r.get("also_reported_by"))
        assert folded["also_reported_by"] == 3
        assert folded["outlet_count"] == 4
        # The unthreaded article is itself and says nothing about coverage.
        assert [r for r in rows if "also_reported_by" not in r]

    async def test_an_echo_never_represents_the_story_it_re_reports(self, db_session, test_feed):
        from sqlalchemy import text as sa_text

        actor, entries, _ = await self._actor_with_entries(db_session, test_feed, name="Echoed", count=3)
        thread_id = str(uuid.uuid4())
        await db_session.execute(
            sa_text(
                """
                INSERT INTO story_threads (id, slug, title, status, entry_count, source_count,
                                           first_seen, last_seen, key_entities)
                VALUES (:id, 'echoed-wave', 'Echoed wave', 'open', 3, 3,
                        now() - interval '2 days', now(), '[]'::jsonb)
                """
            ),
            {"id": thread_id},
        )
        # Newest first is how the collector orders, and the newest here is the
        # re-report — the one the fold must not hand the story to.
        roles = {entries[0].id: "echo", entries[1].id: "beat", entries[2].id: "origin"}
        for entry in entries:
            await db_session.execute(
                sa_text(
                    "INSERT INTO story_thread_entries (id, thread_id, entry_id, role, similarity) "
                    "VALUES (:id, :tid, :eid, :role, 0.9)"
                ),
                {"id": str(uuid.uuid4()), "tid": thread_id, "eid": str(entry.id), "role": roles[entry.id]},
            )
        await db_session.commit()

        rows = await collect_brief_entries(db_session, entity_types.THREAT_ACTOR, str(actor.id), 336)
        assert len(rows) == 1
        assert rows[0]["entry_id"] != str(entries[0].id)
        assert rows[0]["also_reported_by"] == 2

    async def test_one_loud_story_cannot_eat_the_prompt_budget(self, db_session, test_feed):
        """The cap is applied after folding, so 14 re-reports cost one slot."""
        from sqlalchemy import text as sa_text

        actor, entries, _ = await self._actor_with_entries(db_session, test_feed, name="Budget", count=20)
        thread_id = str(uuid.uuid4())
        await db_session.execute(
            sa_text(
                """
                INSERT INTO story_threads (id, slug, title, status, entry_count, source_count,
                                           first_seen, last_seen, key_entities)
                VALUES (:id, 'budget-wave', 'Budget wave', 'open', 14, 14,
                        now() - interval '2 days', now(), '[]'::jsonb)
                """
            ),
            {"id": thread_id},
        )
        for entry in entries[:14]:
            await db_session.execute(
                sa_text(
                    "INSERT INTO story_thread_entries (id, thread_id, entry_id, role, similarity) "
                    "VALUES (:id, :tid, :eid, 'beat', 0.9)"
                ),
                {"id": str(uuid.uuid4()), "tid": thread_id, "eid": str(entry.id)},
            )
        await db_session.commit()

        rows = await collect_brief_entries(db_session, entity_types.THREAT_ACTOR, str(actor.id), 336)
        wave = [r for r in rows if r.get("also_reported_by")]
        assert len(wave) == 1, "the wave is one article in the prompt"
        # Folding freed the rest of the budget for articles that say something
        # else — before, the wave alone would have filled it.
        assert len(rows) > 1

    async def test_unthreaded_entries_pass_through_untouched(self, db_session, test_feed):
        actor, _, _ = await self._actor_with_entries(db_session, test_feed, name="Unfolded", count=3)
        await db_session.commit()

        rows = await collect_brief_entries(db_session, entity_types.THREAT_ACTOR, str(actor.id), 336)
        assert len(rows) == 3
        assert all("also_reported_by" not in r for r in rows)
