"""Threat board ranking, facet folding and generic-entity holdout.

The two bugs these cover both showed up against real data, not in review:
"Medusa Group" and "MEDUSA" ranked as two threats splitting one threat's
evidence, and a CVE id sitting in malware_families ranked as a malware family.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app import entity_types
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP
from app.services.threat_board import (
    _GENERIC_NORMALIZED,
    _ID_SHAPED,
    STORY,
    ThreatRow,
    _normalize_name,
    build_story_rows,
    build_threat_board,
)


def _row(**kw) -> ThreatRow:
    base = dict(
        entity_type=entity_types.THREAT_ACTOR,
        entity_key="k",
        label="X",
        facets=[entity_types.THREAT_ACTOR],
        attention=1,
        new_techniques=0,
        on_record=0,
        prior_rules=0,
        prior_rules_strong=0,
        prior_rule_repos={},
        last_seen=None,
        state="open",
        is_generic=False,
        score=0.0,
    )
    return ThreatRow(**{**base, **kw})


class TestNameNormalisation:
    @pytest.mark.parametrize(
        "a,b",
        [
            ("Medusa Group", "MEDUSA"),
            ("Scattered Spider Group", "scattered spider"),
            ("Cl0p Gang", "Cl0p"),
            ("Shai-Hulud", "shai hulud"),
            # Both seen live, each holding a second row for the same threat.
            ("Shai-Hulud", "Mini Shai-Hulud worm"),
            ("The Gentlemen", "Gentlemen Ransomware"),
            ("Interlock Ransomware", "Interlock"),
        ],
    )
    def test_collective_suffix_folds_to_same_key(self, a, b):
        assert _normalize_name(a) == _normalize_name(b)

    def test_does_not_fold_distinct_threats(self):
        assert _normalize_name("Medusa") != _normalize_name("Medusa Locker")
        assert _normalize_name("APT29") != _normalize_name("APT28")
        assert _normalize_name("Lumma") != _normalize_name("Lumma Stealer C2")

    def test_stem_floor_stops_short_names_over_merging(self):
        """ "The Com" and "Com Loader" both strip to "com" — three characters is
        not distinctive enough to fold two threats on."""
        assert _normalize_name("The Com") != _normalize_name("Com Loader")

    def test_bare_collective_noun_survives(self):
        # "Ransomware" alone must not normalise to the empty string and collide
        # with every other single-word name.
        assert _normalize_name("Ransomware") == "ransomware"


class TestGenericHoldout:
    def test_detection_formats_are_not_malware(self):
        """ "Sigma" reached the board as a malware family with 26 techniques on
        record. It is the rule format."""
        for name in ("Sigma", "YARA", "Suricata"):
            assert _normalize_name(name) in _GENERIC_NORMALIZED, name

    def test_genre_words_are_generic(self):
        for name in ("Infostealer", "ransomware", "Web Shell", "Backdoor"):
            assert _normalize_name(name) in _GENERIC_NORMALIZED, name

    def test_real_threats_are_not_generic(self):
        for name in ("APT29", "Qilin", "MacSync", "Tycoon2FA"):
            assert _normalize_name(name) not in _GENERIC_NORMALIZED, name

    @pytest.mark.parametrize("ident", ["CVE-2026-65400", "T1059.001", "T1078", "S0039", "G0016"])
    def test_identifier_shaped_names_are_flagged(self, ident):
        assert _ID_SHAPED.match(ident)

    @pytest.mark.parametrize("name", ["APT29", "Cobalt Strike", "T-Rex Loader"])
    def test_real_names_are_not_identifier_shaped(self, name):
        assert not _ID_SHAPED.match(name)


class TestActionDerivation:
    def test_no_prior_rules_is_write(self):
        assert _row(prior_rules=0, prior_rules_strong=0, new_techniques=5).action == "write"

    def test_prior_rules_plus_new_tradecraft_is_extend(self):
        assert _row(prior_rules=36, prior_rules_strong=36, new_techniques=6).action == "extend"

    def test_quiet_window_with_history_is_audit(self):
        # The Shai-Hulud case: 15 outlets, nothing new, 65 techniques on record
        # that have never been checked against the library. Not a dead row.
        assert _row(prior_rules=18, prior_rules_strong=18, new_techniques=0, on_record=65).action == "audit"

    def test_weak_only_inventory_is_a_diff_not_an_extend(self):
        """A story:-tag hit is inventory worth opening, not a rule that names
        this threat — so it must not read as something to extend."""
        assert _row(prior_rules=54, prior_rules_strong=0, new_techniques=4).action == "diff"

    def test_generic_entity_goes_to_merge(self):
        assert _row(is_generic=True, prior_rules=0).action == "merge"


@pytest.mark.asyncio
class TestBuildThreatBoard:
    async def _seed(self, db_session, test_feed, *, name: str, kind: str, entries: int, techniques: int = 0):
        now = datetime.now(UTC)
        if kind == "actor":
            ent = ThreatActor(name=name)
            db_session.add(ent)
            await db_session.flush()
        else:
            ent = MalwareFamily(name=name)
            db_session.add(ent)
            await db_session.flush()
        for i in range(entries):
            e = Entry(
                feed_id=test_feed.id,
                guid=f"{name}-{kind}-{i}",
                title=f"{name} report {i}",
                url=f"https://outlet{i}.example.com/{name}-{i}",
                published_at=now - timedelta(days=1),
            )
            db_session.add(e)
            await db_session.flush()
            if kind == "actor":
                db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=ent.id))
            else:
                db_session.add(EntryMalware(entry_id=e.id, malware_family_id=ent.id))
            # Techniques ride the first entry so their min(published_at) — the
            # first-seen date the `new` count reads — lands inside the window.
            if i == 0:
                for t in range(techniques):
                    ttp = TTP(technique_id=f"T9{t:03d}", technique_name=f"Probe {t}")
                    db_session.add(ttp)
                    await db_session.flush()
                    db_session.add(EntryTTP(entry_id=e.id, ttp_id=ttp.id))
        await db_session.flush()
        return ent

    async def test_actor_and_malware_facets_fold_into_one_row(self, db_session, test_feed):
        await self._seed(db_session, test_feed, name="Medusa Group", kind="actor", entries=4)
        await self._seed(db_session, test_feed, name="MEDUSA", kind="malware", entries=4)
        await db_session.commit()

        rows = await build_threat_board(db_session, window="14d", min_attention=1, limit=20)
        medusa = [r for r in rows if _normalize_name(r.label) == "medusa"]
        assert len(medusa) == 1, f"expected one folded row, got {[r.label for r in medusa]}"
        assert set(medusa[0].facets) == {entity_types.THREAT_ACTOR, entity_types.MALWARE}

    async def test_attention_counts_outlets_not_entries(self, db_session, test_feed):
        # Four entries from four distinct hosts is attention 4, not 4 "entries".
        await self._seed(db_session, test_feed, name="Testcrew", kind="actor", entries=4)
        await db_session.commit()

        rows = await build_threat_board(db_session, window="14d", min_attention=1, limit=20)
        row = next(r for r in rows if r.label == "Testcrew")
        assert row.attention == 4

    async def test_generic_entity_sorts_last_and_scores_zero(self, db_session, test_feed):
        await self._seed(db_session, test_feed, name="Infostealer", kind="malware", entries=9)
        await self._seed(db_session, test_feed, name="Realthreat", kind="actor", entries=3)
        await db_session.commit()

        rows = await build_threat_board(db_session, window="14d", min_attention=1, limit=20)
        labels = [r.label for r in rows]
        assert labels.index("Realthreat") < labels.index("Infostealer"), (
            "a genre word with 3x the outlets must not outrank a real threat"
        )
        assert next(r for r in rows if r.label == "Infostealer").score == 0.0

    async def _mark_handled(self, db_session, actor, new_count_at_decision: int):
        await db_session.execute(
            text(
                "INSERT INTO threat_board_state (entity_type, entity_key, state, new_count_at_decision) "
                "VALUES (:et, :ek, 'handled', :n) "
                "ON CONFLICT (entity_type, entity_key) DO UPDATE SET new_count_at_decision = :n"
            ),
            {"et": entity_types.THREAT_ACTOR, "ek": str(actor.id), "n": new_count_at_decision},
        )
        await db_session.commit()

    async def test_handled_threat_stays_hidden_while_nothing_new_arrives(self, db_session, test_feed):
        actor = await self._seed(db_session, test_feed, name="Quiet", kind="actor", entries=3, techniques=2)
        # Decided when both techniques were already known.
        await self._mark_handled(db_session, actor, new_count_at_decision=2)

        rows = await build_threat_board(db_session, window="14d", min_attention=1, limit=20)
        assert "Quiet" not in [r.label for r in rows]

        rows = await build_threat_board(db_session, window="14d", min_attention=1, limit=20, include_handled=True)
        assert next(r for r in rows if r.label == "Quiet").state == "handled"

    async def test_handled_threat_reopens_when_new_tradecraft_arrives(self, db_session, test_feed):
        """The reason no snooze date is needed: new tradecraft reopens the row.

        Decided at zero, then two techniques land in the window, so the live
        `new` count exceeds the count recorded at the decision.
        """
        actor = await self._seed(db_session, test_feed, name="Reopener", kind="actor", entries=3, techniques=2)
        await self._mark_handled(db_session, actor, new_count_at_decision=0)

        rows = await build_threat_board(db_session, window="14d", min_attention=1, limit=20)
        row = next((r for r in rows if r.label == "Reopener"), None)
        assert row is not None, "a handled threat with new tradecraft must come back on its own"
        assert row.new_techniques == 2
        assert row.state == "open"


@pytest.mark.asyncio
class TestTracked:
    """The pull path: a threat you name enters the board regardless of the
    attention floor, pinned above the ranking."""

    async def test_tracked_quiet_threat_pins_above_the_ranking(self, db_session, test_feed):
        from app.models.threat_actor import ThreatActor

        quiet = ThreatActor(name="Warp Panda")
        db_session.add(quiet)
        await db_session.flush()
        await db_session.execute(
            text(
                "INSERT INTO threat_board_state (entity_type, entity_key, state, new_count_at_decision) "
                "VALUES (:et, :ek, 'tracked', 0)"
            ),
            {"et": entity_types.THREAT_ACTOR, "ek": str(quiet.id)},
        )
        await db_session.commit()

        # Zero window activity, min_attention 3 — the ranking alone would
        # never show this row. Tracking is exactly for that case.
        rows = await build_threat_board(db_session, window="14d", min_attention=3, limit=5)
        row = next((r for r in rows if r.label == "Warp Panda"), None)
        assert row is not None
        assert row.state == "tracked"
        assert row.attention == 0
        # Pinned above everything the score ranked.
        assert rows[0].label == "Warp Panda"

    async def test_track_endpoint_pins_an_off_board_entity(self, db_session, client, auth_headers, test_feed):
        from app.models.threat_actor import ThreatActor

        quiet = ThreatActor(name="Quietcrew")
        db_session.add(quiet)
        await db_session.commit()

        resp = await client.put(
            f"/api/threat-board/threat_actor/{quiet.id}/state",
            headers=auth_headers,
            json={"state": "tracked"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["state"] == "tracked"

        board = await client.get("/api/threat-board?min_attention=3", headers=auth_headers)
        assert "Quietcrew" in [r["label"] for r in board.json()["items"]]


@pytest.mark.asyncio
class TestVulnFacet:
    """CVE rows as board citizens: exploitation-ranked, posture-derived
    actions, and the surface split — a KEV affecting nothing you run and
    nothing you can observe is landscape context, not your write-queue."""

    async def _seed_cve(self, db_session, test_feed, cve_id, *, is_kev=True, entries=3, title_prefix="Exploit"):
        from app.models.cve import CVE, EntryCVE

        cve = CVE(cve_id=cve_id, severity="CRITICAL", cvss_score=9.8, is_kev=is_kev)
        db_session.add(cve)
        await db_session.flush()
        now = datetime.now(UTC)
        for i in range(entries):
            entry = Entry(
                feed_id=test_feed.id,
                guid=f"{cve_id}-{i}",
                title=f"{title_prefix} {cve_id} wave {i}",
                url=f"https://outlet{i}.example.com/{cve_id}",
                published_at=now - timedelta(days=1),
            )
            db_session.add(entry)
            await db_session.flush()
            db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve.id))
        return cve

    async def test_stack_match_sorts_above_the_surface_divider(self, db_session, test_feed, test_user):
        from app.models.cve_affected import CVEAffected
        from app.models.user_entity_watch import UserEntityWatch
        from app.models.vendor import Vendor
        from app.services.threat_board import build_cve_board

        mine = await self._seed_cve(db_session, test_feed, "CVE-2026-11111", entries=2)
        await self._seed_cve(db_session, test_feed, "CVE-2026-22222", entries=5)

        vendor = Vendor(name="RunsHere Corp")
        db_session.add(vendor)
        await db_session.flush()
        db_session.add(CVEAffected(cve_id=mine.id, vendor_id=vendor.id, cpe_vendor="runshere", cpe_product="widget"))
        db_session.add(
            UserEntityWatch(created_by=test_user.id, entity_type="vendor", entity_id=vendor.id, mode="stack")
        )
        await db_session.commit()

        rows = await build_cve_board(db_session, min_attention=1, user_id=test_user.id)
        by_key = {r.entity_key: r for r in rows}

        assert by_key["CVE-2026-11111"].in_stack is True
        assert by_key["CVE-2026-11111"].on_surface is True
        assert by_key["CVE-2026-22222"].on_surface is False
        # The stack CVE outranks the louder landscape KEV: on_surface sorts
        # first, and only stack matches earn the exposure base multiplier.
        keys = [r.entity_key for r in rows]
        assert keys.index("CVE-2026-11111") < keys.index("CVE-2026-22222")
        assert by_key["CVE-2026-11111"].action == "write"
        assert by_key["CVE-2026-11111"].is_kev is True

    async def test_vulns_facet_and_all_interleave_through_the_api(self, db_session, client, auth_headers, test_feed):
        await self._seed_cve(db_session, test_feed, "CVE-2026-33333", entries=4)
        await db_session.commit()

        vulns = await client.get("/api/threat-board?facet=vulns&min_attention=1", headers=auth_headers)
        assert vulns.status_code == 200
        row = next(r for r in vulns.json()["items"] if r["label"] == "CVE-2026-33333")
        assert row["entity_type"] == "cve"
        assert row["is_kev"] is True
        assert row["action"] in ("write", "adopt", "collect")
        assert row["headline"]["title"].startswith("Exploit CVE-2026-33333")

        merged = await client.get("/api/threat-board?facet=all&min_attention=1", headers=auth_headers)
        assert any(r["entity_type"] == "cve" for r in merged.json()["items"])


@pytest.mark.asyncio
class TestWatchIsTrack:
    """One verb: watching a threat pins it to the board; unwatching clears the
    pin. Handled/muted are human decisions and survive both directions."""

    async def test_watch_pins_and_unwatch_unpins(self, db_session, client, auth_headers, test_feed):
        from app.models.threat_actor import ThreatActor

        actor = ThreatActor(name="Watched Crew")
        db_session.add(actor)
        await db_session.commit()

        resp = await client.put(
            "/api/intelligence/watchlist",
            headers=auth_headers,
            json={"entity_type": "threat_actor", "entity_id": str(actor.id), "mode": "watch"},
        )
        assert resp.status_code == 200, resp.text
        state = (
            await db_session.execute(
                text("SELECT state FROM threat_board_state WHERE entity_key = :k"), {"k": str(actor.id)}
            )
        ).scalar_one_or_none()
        assert state == "tracked"

        resp = await client.delete(f"/api/intelligence/watchlist/threat_actor/{actor.id}", headers=auth_headers)
        assert resp.status_code == 200, resp.text
        state = (
            await db_session.execute(
                text("SELECT state FROM threat_board_state WHERE entity_key = :k"), {"k": str(actor.id)}
            )
        ).scalar_one_or_none()
        assert state is None

    async def test_watch_never_outranks_a_handled_decision(self, db_session, client, auth_headers, test_feed):
        from app.models.threat_actor import ThreatActor

        actor = ThreatActor(name="Decided Crew")
        db_session.add(actor)
        await db_session.flush()
        await db_session.execute(
            text(
                "INSERT INTO threat_board_state (entity_type, entity_key, state, new_count_at_decision) "
                "VALUES ('threat_actor', :k, 'handled', 0)"
            ),
            {"k": str(actor.id)},
        )
        await db_session.commit()

        await client.put(
            "/api/intelligence/watchlist",
            headers=auth_headers,
            json={"entity_type": "threat_actor", "entity_id": str(actor.id), "mode": "watch"},
        )
        await client.delete(f"/api/intelligence/watchlist/threat_actor/{actor.id}", headers=auth_headers)
        state = (
            await db_session.execute(
                text("SELECT state FROM threat_board_state WHERE entity_key = :k"), {"k": str(actor.id)}
            )
        ).scalar_one_or_none()
        assert state == "handled"


async def _thread(db_session, *, slug: str, title: str, entries: list, origin=None) -> str:
    """A story thread over the given entries, with no embeddings involved.

    The board never reads a centroid — it reads membership — so these tests
    build threads the way the sweeper leaves them rather than the way it
    arrives at them.
    """
    thread_id = str(uuid.uuid4())
    await db_session.execute(
        text(
            """
            INSERT INTO story_threads (id, slug, title, status, entry_count, source_count,
                                       first_seen, last_seen, key_entities)
            VALUES (:id, :slug, :title, 'open', :n, :n, now() - interval '2 days', now(), '[]'::jsonb)
            """
        ),
        {"id": thread_id, "slug": slug, "title": title, "n": len(entries)},
    )
    for entry in entries:
        await db_session.execute(
            text(
                "INSERT INTO story_thread_entries (id, thread_id, entry_id, role, similarity) "
                "VALUES (:id, :tid, :eid, :role, 0.9)"
            ),
            {
                "id": str(uuid.uuid4()),
                "tid": thread_id,
                "eid": str(entry.id),
                "role": "origin" if origin is not None and entry.id == origin.id else "beat",
            },
        )
    await db_session.commit()
    return thread_id


async def _technique(db_session, entry, *, technique_id: str, observable: str | None = None) -> None:
    """One extracted technique on an entry — what makes a story worth a row."""
    ttp = TTP(technique_id=technique_id, technique_name=f"Probe {technique_id}")
    db_session.add(ttp)
    await db_session.flush()
    db_session.add(EntryTTP(entry_id=entry.id, ttp_id=ttp.id, source_text=observable))
    await db_session.flush()


async def _entries(db_session, feed, *, prefix: str, count: int, days_ago: int = 1) -> list[Entry]:
    now = datetime.now(UTC)
    made = []
    for i in range(count):
        entry = Entry(
            feed_id=feed.id,
            guid=f"{prefix}-{i}",
            title=f"{prefix} {i}",
            url=f"https://outlet-{prefix}-{i}.example.com/story",
            published_at=now - timedelta(days=days_ago),
        )
        db_session.add(entry)
        await db_session.flush()
        made.append(entry)
    return made


@pytest.mark.asyncio
class TestStoryAwareRanking:
    """Stories, not outlets. One wave carried by eleven outlets is one thing."""

    async def _link(self, db_session, entity, entries, kind="actor"):
        for entry in entries:
            if kind == "actor":
                db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=entity.id))
            else:
                db_session.add(EntryMalware(entry_id=entry.id, malware_family_id=entity.id))
        await db_session.flush()

    async def test_one_wave_ranks_below_several_separate_stories(self, db_session, test_feed):
        loud = ThreatActor(name="Loudwave")
        recurring = ThreatActor(name="Recurring")
        db_session.add_all([loud, recurring])
        await db_session.flush()

        wave = await _entries(db_session, test_feed, prefix="wave", count=8)
        await self._link(db_session, loud, wave)
        await _thread(db_session, slug="one-wave", title="One wave", entries=wave, origin=wave[0])

        # Three separate stories, five outlets between them — fewer outlets,
        # more things that actually happened.
        spread = await _entries(db_session, test_feed, prefix="spread", count=5)
        await self._link(db_session, recurring, spread)
        for i, group in enumerate([spread[0:2], spread[2:4], spread[4:5]]):
            await _thread(db_session, slug=f"spread-{i}", title=f"Incident {i}", entries=group, origin=group[0])
        await db_session.commit()

        rows = await build_threat_board(db_session, window="14d", min_attention=1, limit=20)
        labels = [r.label for r in rows]
        assert labels.index("Recurring") < labels.index("Loudwave"), (
            "three incidents must outrank one incident re-reported by eight outlets"
        )
        loud_row = next(r for r in rows if r.label == "Loudwave")
        assert (loud_row.stories, loud_row.attention) == (1, 8)
        assert next(r for r in rows if r.label == "Recurring").stories == 3

    async def test_story_count_falls_back_to_outlets_with_no_threads(self, db_session, test_feed):
        actor = ThreatActor(name="Unthreaded")
        db_session.add(actor)
        await db_session.flush()
        await self._link(db_session, actor, await _entries(db_session, test_feed, prefix="plain", count=4))
        await db_session.commit()

        row = next(
            r
            for r in await build_threat_board(db_session, window="14d", min_attention=1, limit=20)
            if r.label == "Unthreaded"
        )
        # The whole safety property: an un-embedded corpus ranks as it always did.
        assert row.stories == row.attention == 4
        assert row.echoes_folded == 0

    async def test_echoes_folded_counts_what_the_story_absorbed(self, db_session, test_feed):
        actor = ThreatActor(name="Echoey")
        db_session.add(actor)
        await db_session.flush()
        entries = await _entries(db_session, test_feed, prefix="echo", count=6)
        await self._link(db_session, actor, entries)
        await _thread(db_session, slug="echo-wave", title="Echo wave", entries=entries, origin=entries[0])
        await db_session.commit()

        row = next(
            r
            for r in await build_threat_board(db_session, window="14d", min_attention=1, limit=20)
            if r.label == "Echoey"
        )
        assert (row.articles, row.stories, row.echoes_folded) == (6, 1, 5)
        assert row.thread_slug == "echo-wave"

    async def test_headline_is_the_first_report_not_the_densest_writeup(self, db_session, test_feed):
        actor = ThreatActor(name="Originator")
        db_session.add(actor)
        await db_session.flush()
        entries = await _entries(db_session, test_feed, prefix="origin", count=3, days_ago=3)
        entries[0].title = "Originator hits regional banks"
        # The last article is the technique-dense one the old heuristic picks,
        # and it names the threat in its title as well.
        entries[2].title = "Originator technique roundup"
        entries[2].published_at = datetime.now(UTC) - timedelta(hours=2)
        await self._link(db_session, actor, entries)
        for t in range(3):
            ttp = TTP(technique_id=f"T81{t:02d}", technique_name=f"Dense {t}")
            db_session.add(ttp)
            await db_session.flush()
            db_session.add(EntryTTP(entry_id=entries[2].id, ttp_id=ttp.id))
        await _thread(db_session, slug="origin-story", title="Origin story", entries=entries, origin=entries[0])
        await db_session.commit()

        row = next(
            r
            for r in await build_threat_board(db_session, window="14d", min_attention=1, limit=20)
            if r.label == "Originator"
        )
        assert row.headline["entry_id"] == str(entries[0].id)
        assert row.headline["is_origin"] is True

    async def test_each_row_leads_with_its_own_first_article_in_the_story(self, db_session, test_feed):
        """Three rows in one story must not all print the same quote."""
        early = ThreatActor(name="Earlybird")
        latecomer = MalwareFamily(name="Latecomer")
        db_session.add_all([early, latecomer])
        await db_session.flush()
        entries = await _entries(db_session, test_feed, prefix="samestory", count=4, days_ago=4)
        for i, entry in enumerate(entries):
            entry.published_at = datetime.now(UTC) - timedelta(days=4 - i)
        # The actor is in the story from its first article; the malware is only
        # named once the third article lands. The malware also has coverage of
        # its own, so the thread holds two thirds of it — enough to speak for
        # its headline, not enough to fold it into the actor's row.
        await self._link(db_session, early, entries)
        await self._link(db_session, latecomer, entries[2:], kind="malware")
        await self._link(
            db_session,
            latecomer,
            await _entries(db_session, test_feed, prefix="latecomer-own", count=1),
            kind="malware",
        )
        await _thread(db_session, slug="shared-arc", title="Shared arc", entries=entries, origin=entries[0])
        await db_session.commit()

        rows = {r.label: r for r in await build_threat_board(db_session, window="14d", min_attention=1, limit=20)}
        assert rows["Earlybird"].headline["entry_id"] == str(entries[0].id)
        assert rows["Earlybird"].headline["is_origin"] is True
        assert rows["Latecomer"].headline["entry_id"] == str(entries[2].id)
        # It is the row's first article in the story, not the story's origin.
        assert rows["Latecomer"].headline["is_origin"] is False

    async def test_a_row_no_headline_names_still_leads_with_the_earliest(self, db_session, test_feed):
        """Density never decides it — inside the story, first is first."""
        malware = MalwareFamily(name="Unnamedware")
        db_session.add(malware)
        await db_session.flush()
        entries = await _entries(db_session, test_feed, prefix="anon", count=3, days_ago=3)
        for i, entry in enumerate(entries):
            entry.title = f"Campaign coverage part {i}"
            entry.published_at = datetime.now(UTC) - timedelta(days=3 - i)
        await self._link(db_session, malware, entries, kind="malware")
        for t in range(4):
            await _technique(db_session, entries[2], technique_id=f"T82{t:02d}")
        await _thread(db_session, slug="anon-arc", title="Anon arc", entries=entries, origin=entries[0])
        await db_session.commit()

        row = next(
            r
            for r in await build_threat_board(db_session, window="14d", min_attention=1, limit=20)
            if r.label == "Unnamedware"
        )
        assert row.headline["entry_id"] == str(entries[0].id)

    async def test_two_rows_on_one_story_fold_into_one(self, db_session, test_feed):
        operator = ThreatActor(name="Operator-9")
        payload = MalwareFamily(name="Payloadware")
        db_session.add_all([operator, payload])
        await db_session.flush()
        entries = await _entries(db_session, test_feed, prefix="shared", count=4)
        await self._link(db_session, operator, entries)
        await self._link(db_session, payload, entries, kind="malware")
        await _thread(db_session, slug="one-job", title="One job", entries=entries, origin=entries[0])
        await db_session.commit()

        rows = await build_threat_board(db_session, window="14d", min_attention=1, limit=20)
        labels = [r.label for r in rows]
        assert "Operator-9" in labels or "Payloadware" in labels
        assert not ("Operator-9" in labels and "Payloadware" in labels), (
            "an operator and its payload on one story are one row"
        )
        row = next(r for r in rows if r.label in ("Operator-9", "Payloadware"))
        assert set(row.facets) == {entity_types.THREAT_ACTOR, entity_types.MALWARE}
        assert [m["label"] for m in row.merged_from] == ["Payloadware" if row.label == "Operator-9" else "Operator-9"]

    async def test_a_walk_on_part_in_someone_elses_story_does_not_fold(self, db_session, test_feed):
        star = ThreatActor(name="Mainplot")
        cameo = MalwareFamily(name="Cameoware")
        db_session.add_all([star, cameo])
        await db_session.flush()
        entries = await _entries(db_session, test_feed, prefix="cameo", count=4)
        await self._link(db_session, star, entries)
        # The malware appears in one of the four articles, and in three of its
        # own elsewhere — the thread holds a quarter of its coverage, not three
        # quarters, so it keeps its row.
        await self._link(db_session, cameo, entries[:1], kind="malware")
        own = await _entries(db_session, test_feed, prefix="cameo-own", count=3)
        await self._link(db_session, cameo, own, kind="malware")
        await _thread(db_session, slug="main-plot", title="Main plot", entries=entries, origin=entries[0])
        await db_session.commit()

        labels = [r.label for r in await build_threat_board(db_session, window="14d", min_attention=1, limit=20)]
        assert "Mainplot" in labels and "Cameoware" in labels


@pytest.mark.asyncio
class TestNoThreadsAtAll:
    """The dormant case: embeddings off, or the backfill hasn't reached here."""

    async def test_board_is_unchanged_and_asks_the_thread_tables_once(self, db_session, test_feed):
        actor = ThreatActor(name="Threadless")
        db_session.add(actor)
        await db_session.flush()
        entries = await _entries(db_session, test_feed, prefix="none", count=5)
        for entry in entries:
            db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
        await db_session.commit()

        rows = await build_threat_board(db_session, window="14d", min_attention=1, limit=20)
        row = next(r for r in rows if r.label == "Threadless")
        assert (row.stories, row.attention, row.echoes_folded) == (5, 5, 0)
        assert row.thread_slug is None and row.beats == 0
        # The old ranking, exactly: outlets + 2.5 x new tradecraft, and the
        # corroboration bump that is the only new term.
        assert row.score == pytest.approx(5 + min(0.25 * 5, 2.0))
        assert await build_story_rows(db_session, window="14d", min_attention=1, limit=20) == []


@pytest.mark.asyncio
class TestStoryRows:
    """The row the board could never show: a story nothing has named yet."""

    async def test_thread_with_no_entity_becomes_a_row(self, db_session, test_feed):
        entries = await _entries(db_session, test_feed, prefix="unnamed", count=4)
        await _technique(db_session, entries[0], technique_id="T1190", observable="POST /api/fabric")
        await _thread(
            db_session,
            slug="fortiweb-preauth-rce",
            title="FortiWeb pre-auth RCE exploited pre-patch",
            entries=entries,
            origin=entries[0],
        )
        await db_session.commit()

        rows = await build_story_rows(db_session, window="14d", min_attention=1, limit=20)
        assert [r.entity_key for r in rows] == ["fortiweb-preauth-rce"]
        row = rows[0]
        assert row.entity_type == STORY and row.is_story
        assert row.label == "FortiWeb pre-auth RCE exploited pre-patch"
        assert row.action == "collect"
        assert row.attention == 4 and row.stories == 1
        assert row.headline["entry_id"] == str(entries[0].id)

    async def test_a_story_with_nothing_to_extract_is_not_a_row(self, db_session, test_feed):
        """A funding round and a policy statement also resolve to no entity."""
        entries = await _entries(db_session, test_feed, prefix="newsy", count=5)
        await _thread(
            db_session,
            slug="vendor-raises-a-round",
            title="Vendor raises $1B to fight AI threats",
            entries=entries,
            origin=entries[0],
        )
        await db_session.commit()

        assert await build_story_rows(db_session, window="14d", min_attention=1, limit=20) == []

    async def test_thread_that_resolved_an_entity_is_not_a_story_row(self, db_session, test_feed):
        actor = ThreatActor(name="Named")
        db_session.add(actor)
        await db_session.flush()
        entries = await _entries(db_session, test_feed, prefix="named", count=4)
        for entry in entries:
            db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
        await db_session.flush()
        await _thread(db_session, slug="named-story", title="Named story", entries=entries, origin=entries[0])
        await db_session.commit()

        # The actor row already carries it; a second row for the same coverage
        # is the duplication threads exist to remove.
        assert await build_story_rows(db_session, window="14d", min_attention=1, limit=20) == []

    async def test_story_rows_reach_the_board_through_the_api(self, db_session, client, auth_headers, test_feed):
        entries = await _entries(db_session, test_feed, prefix="apistory", count=3)
        await _technique(db_session, entries[0], technique_id="T1566")
        await _thread(db_session, slug="api-story", title="Something unnamed", entries=entries, origin=entries[0])
        await db_session.commit()

        resp = await client.get("/api/threat-board", params={"min_attention": 1}, headers=auth_headers)
        assert resp.status_code == 200
        story = next(i for i in resp.json()["items"] if i["entity_key"] == "api-story")
        assert story["is_story"] is True
        assert story["entity_type"] == STORY
        assert story["thread_slug"] == "api-story"

    async def test_story_rows_do_not_push_the_board_over_its_limit(self, db_session, client, auth_headers, test_feed):
        for n in range(3):
            actor = ThreatActor(name=f"Limitactor {n}")
            db_session.add(actor)
            await db_session.flush()
            for entry in await _entries(db_session, test_feed, prefix=f"limit{n}", count=2):
                db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
        await db_session.flush()
        for n in range(3):
            entries = await _entries(db_session, test_feed, prefix=f"limitstory{n}", count=2)
            await _technique(db_session, entries[0], technique_id=f"T90{n:02d}")
            await _thread(db_session, slug=f"limit-story-{n}", title=f"Unnamed {n}", entries=entries, origin=entries[0])
        await db_session.commit()

        resp = await client.get("/api/threat-board", params={"min_attention": 1, "limit": 4}, headers=auth_headers)
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 4

    async def test_story_row_can_be_marked_handled(self, db_session, client, auth_headers, test_feed):
        entries = await _entries(db_session, test_feed, prefix="handlestory", count=3)
        await _technique(db_session, entries[0], technique_id="T1059")
        await _thread(db_session, slug="handle-story", title="Handle me", entries=entries, origin=entries[0])
        await db_session.commit()

        resp = await client.put(
            f"/api/threat-board/{STORY}/handle-story/state",
            json={"state": "handled"},
            headers=auth_headers,
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["state"] == "handled"

        board = await client.get("/api/threat-board", params={"min_attention": 1}, headers=auth_headers)
        assert not [i for i in board.json()["items"] if i["entity_key"] == "handle-story"]


@pytest.mark.asyncio
class TestMergedRowDecisions:
    """One row on the board is one decision, whatever it folded."""

    async def test_handling_a_merged_row_handles_what_it_absorbed(self, db_session, client, auth_headers, test_feed):
        operator = ThreatActor(name="Foldop")
        payload = MalwareFamily(name="Foldware")
        db_session.add_all([operator, payload])
        await db_session.flush()
        entries = await _entries(db_session, test_feed, prefix="folddec", count=4)
        for entry in entries:
            db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=operator.id))
            db_session.add(EntryMalware(entry_id=entry.id, malware_family_id=payload.id))
        await db_session.flush()
        await _thread(db_session, slug="fold-decision", title="Fold decision", entries=entries, origin=entries[0])
        await db_session.commit()

        board = await client.get("/api/threat-board", params={"min_attention": 1}, headers=auth_headers)
        row = next(i for i in board.json()["items"] if i["label"] in ("Foldop", "Foldware"))
        assert row["merged_from"], "the two rows should have folded into one"

        resp = await client.put(
            f"/api/threat-board/{row['entity_type']}/{row['entity_key']}/state",
            json={"state": "handled"},
            headers=auth_headers,
        )
        assert resp.status_code == 200, resp.text

        # Both entities carry the decision, so neither can reappear alone.
        states = dict(
            (r.entity_key, r.state)
            for r in (
                await db_session.execute(
                    text("SELECT entity_key, state FROM threat_board_state WHERE entity_key = ANY(:keys)"),
                    {"keys": [str(operator.id), str(payload.id)]},
                )
            ).all()
        )
        assert states == {str(operator.id): "handled", str(payload.id): "handled"}


@pytest.mark.asyncio
class TestPrecedent:
    """Have we seen this shape before — answered from the thread centroids."""

    async def _thread_with_centroid(self, db_session, *, slug: str, title: str, vec: list[float]):
        from app.models.vector_types import to_literal

        await db_session.execute(
            text(
                """
                INSERT INTO story_threads (id, slug, title, status, entry_count, source_count,
                                           first_seen, last_seen, key_entities, centroid)
                VALUES (:id, :slug, :title, 'open', 3, 3, now() - interval '9 days', now(),
                        '[]'::jsonb, CAST(:vec AS halfvec(768)))
                """
            ),
            {"id": str(uuid.uuid4()), "slug": slug, "title": title, "vec": to_literal(vec)},
        )
        await db_session.commit()

    async def test_nearest_story_is_returned_and_the_far_one_is_not(self, db_session, client, auth_headers):
        near = [0.0] * 768
        near[0] = 1.0
        alike = [0.0] * 768
        alike[0] = 0.95
        alike[1] = 0.3122498999199199  # unit vector at cosine 0.95 to `near`
        elsewhere = [0.0] * 768
        elsewhere[5] = 1.0

        await self._thread_with_centroid(db_session, slug="this-week", title="Edge VPN, no MFA", vec=near)
        await self._thread_with_centroid(db_session, slug="last-year", title="Same shape, other vendor", vec=alike)
        await self._thread_with_centroid(db_session, slug="unrelated", title="Nothing like it", vec=elsewhere)

        resp = await client.get("/api/threat-board/precedent", params={"thread": "this-week"}, headers=auth_headers)
        assert resp.status_code == 200, resp.text
        slugs = [i["slug"] for i in resp.json()["items"]]
        assert slugs == ["last-year"], "only a story above the precedent floor counts as one"

    async def test_unknown_thread_is_a_404(self, client, auth_headers):
        resp = await client.get("/api/threat-board/precedent", params={"thread": "nope"}, headers=auth_headers)
        assert resp.status_code == 404
