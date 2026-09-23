"""Coverage Workspace — articles, behaviours, prior rules and the assembled set.

The two things worth failing a build over live here:

* a behaviour whose ATT&CK channels match nothing in the inventory is a
  *sourcing* item, not a detection gap — it sorts below the divider and carries
  the category that is missing;
* a `low` rule_coverage row matched body text or a Splunk story tag. It is real
  inventory, but it never outranks a rule that names the behaviour, and the
  payload says how many of the candidates are weak.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text

from app import entity_types
from app.models.detection_rule import DetectionRule
from app.models.detection_summary import DetectionSummary
from app.models.entry import Entry
from app.models.telemetry_source import TelemetrySource
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP
from app.services.coverage_workspace import (
    build_workspace,
    get_prior_rules,
    list_sets,
    save_set,
)

CLOUD_CHANNELS = ["m365:unified", "azure:signinlogs"]
WINDOWS_CHANNELS = ["WinEventLog:Sysmon", "WinEventLog:Security"]


@pytest.fixture
async def cloud_inventory(db_session):
    """A cloud-only inventory: nothing answers a Windows event channel."""
    source = TelemetrySource(
        name="Microsoft 365 Unified Audit",
        category="cloud",
        product="Microsoft 365",
        log_types=["unified_audit", "signin_log"],
        log_types_canonical=["saas.activity", "auth.login"],
        enabled=True,
    )
    db_session.add(source)
    await db_session.flush()
    return source


async def _seed_threat(
    db_session,
    test_feed,
    *,
    name="Testcrew",
    techniques=(),
    entries=1,
    quote="the loader wrote to the user's vault directory",
    published_days_ago=1,
):
    """One actor, `entries` articles, techniques riding the first article."""
    actor = ThreatActor(name=name)
    db_session.add(actor)
    await db_session.flush()

    now = datetime.now(UTC)
    made = []
    for i in range(entries):
        entry = Entry(
            feed_id=test_feed.id,
            guid=f"{name}-{i}",
            title=f"{name} report {i}",
            url=f"https://outlet{i}.example.com/{name}-{i}",
            published_at=now - timedelta(days=published_days_ago),
            word_count=1200,
        )
        db_session.add(entry)
        await db_session.flush()
        db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
        made.append(entry)

    for technique_id, technique_name, data_sources in techniques:
        ttp = TTP(technique_id=technique_id, technique_name=technique_name, data_sources=list(data_sources))
        db_session.add(ttp)
        await db_session.flush()
        db_session.add(EntryTTP(entry_id=made[0].id, ttp_id=ttp.id, source_text=quote, paragraph_indices=[4]))
    await db_session.flush()
    return actor, made


@pytest.mark.asyncio
class TestBehaviours:
    async def test_unsourced_behaviour_sorts_below_the_line_with_its_category(
        self, db_session, test_feed, cloud_inventory
    ):
        actor, _ = await _seed_threat(
            db_session,
            test_feed,
            techniques=[
                ("T1078.004", "Cloud Accounts", CLOUD_CHANNELS),
                ("T1574.002", "DLL Side-Loading", WINDOWS_CHANNELS),
            ],
        )
        await db_session.commit()

        ws = await build_workspace(db_session, entity_types.THREAT_ACTOR, str(actor.id))
        by_id = {b.technique_id: b for b in ws.behaviours}

        assert by_id["T1078.004"].tier == "source"
        assert by_id["T1078.004"].below_line is False
        # A Windows event channel against a cloud-only inventory: a rule for it
        # could not fire, so it is a sourcing item, not a gap to write against.
        assert by_id["T1574.002"].tier is None
        assert by_id["T1574.002"].below_line is True
        assert "windows_events" in by_id["T1574.002"].missing_categories
        assert ws.missing_categories == ["windows_events"]
        # Ordering is the contract the divider renders against.
        assert [b.technique_id for b in ws.behaviours] == ["T1078.004", "T1574.002"]

    async def test_technique_without_channels_is_unassessed_not_unsourced(self, db_session, test_feed, cloud_inventory):
        """342 of 1,198 techniques carry no ATT&CK data_sources at all. Absent
        channel metadata is not evidence that the telemetry is missing."""
        actor, _ = await _seed_threat(db_session, test_feed, techniques=[("T1583.006", "Web Services", [])])
        await db_session.commit()

        ws = await build_workspace(db_session, entity_types.THREAT_ACTOR, str(actor.id))
        behaviour = ws.behaviours[0]
        assert behaviour.tier is None
        assert behaviour.below_line is False
        assert behaviour.missing_categories == []

    async def test_quote_and_paragraph_reach_the_payload(self, db_session, test_feed, cloud_inventory):
        actor, _ = await _seed_threat(
            db_session,
            test_feed,
            techniques=[("T1555.003", "Credentials from Web Browsers", CLOUD_CHANNELS)],
            quote="credential vault read from the user context",
        )
        await db_session.commit()

        ws = await build_workspace(db_session, entity_types.THREAT_ACTOR, str(actor.id))
        quote = ws.behaviours[0].quotes[0]
        assert quote.text == "credential vault read from the user context"
        assert quote.paragraph_indices == [4]
        assert quote.entry_title.startswith("Testcrew report")

    async def test_autolinker_marker_is_not_a_quote(self, db_session, test_feed, cloud_inventory):
        """8,785 of the 20,097 populated source_text rows are "auto_link:T1059"
        provenance markers. Rendering one as a quote shows a machine token where
        the analyst expects the article's words."""
        actor, _ = await _seed_threat(
            db_session,
            test_feed,
            techniques=[("T1059.001", "PowerShell", CLOUD_CHANNELS)],
            quote="auto_link:T1059.001",
        )
        await db_session.commit()

        ws = await build_workspace(db_session, entity_types.THREAT_ACTOR, str(actor.id))
        assert ws.behaviours[0].quotes == []

    async def test_technique_reported_again_is_on_record_not_new(self, db_session, test_feed, cloud_inventory):
        """`is_new` is first-*ever* sighting for this threat, not "mentioned in
        the window" — the board made the same correction (18 → 6 for APT29)."""
        actor, entries = await _seed_threat(
            db_session,
            test_feed,
            techniques=[("T1071.004", "DNS", CLOUD_CHANNELS)],
            published_days_ago=40,
        )
        recent = Entry(
            feed_id=test_feed.id,
            guid="recap",
            title="Testcrew recap",
            url="https://recap.example.com/1",
            published_at=datetime.now(UTC) - timedelta(days=1),
        )
        db_session.add(recent)
        await db_session.flush()
        db_session.add(EntryThreatActor(entry_id=recent.id, threat_actor_id=actor.id))
        ttp = (await db_session.execute(select(TTP).where(TTP.technique_id == "T1071.004"))).scalar_one()
        db_session.add(EntryTTP(entry_id=recent.id, ttp_id=ttp.id, source_text="dns tunnelled c2"))
        await db_session.commit()

        ws = await build_workspace(db_session, entity_types.THREAT_ACTOR, str(actor.id), window="7d")
        behaviour = ws.behaviours[0]
        assert behaviour.technique_id == "T1071.004"
        assert behaviour.is_new is False
        # The window's article is the one that reported it; the 40-day-old first
        # sighting is what makes it old tradecraft.
        assert behaviour.entry_count == 1


@pytest.mark.asyncio
class TestArticles:
    async def test_articles_split_by_contribution_newest_first(self, db_session, test_feed, cloud_inventory):
        actor, entries = await _seed_threat(
            db_session,
            test_feed,
            entries=3,
            techniques=[("T1566", "Phishing", CLOUD_CHANNELS)],
        )
        # The technique rides entries[0]; the other two are recaps.
        entries[1].published_at = datetime.now(UTC) - timedelta(days=2)
        entries[2].published_at = datetime.now(UTC) - timedelta(days=3)
        await db_session.commit()

        ws = await build_workspace(db_session, entity_types.THREAT_ACTOR, str(actor.id))
        assert [a.contributed for a in ws.articles] == [True, False, False]
        assert ws.articles[0].technique_count == 1
        assert ws.articles[0].new_technique_count == 1
        assert ws.articles[0].source == "outlet0.example.com"
        published = [a.published_at for a in ws.articles]
        assert published == sorted(published, reverse=True)


@pytest.mark.asyncio
class TestPriorRules:
    async def _rule(self, db_session, title, rule_type="sigma", data_sources=None, repo="sigma", lic="DRL-1.1"):
        rule = DetectionRule(
            title=title,
            rule_type=rule_type,
            rule_content="detection:\n  condition: selection",
            is_draft=False,
            data_sources=list(data_sources or []),
            license=lic,
            metadata_={"repo": repo},
        )
        db_session.add(rule)
        await db_session.flush()
        return rule

    async def _coverage(self, db_session, rule, entity_type, entity_key, via, confidence, matched_on):
        await db_session.execute(
            text(
                "INSERT INTO rule_coverage (rule_id, entity_type, entity_key, via, confidence, matched_on) "
                "VALUES (:rid, :et, :ek, :via, :conf, :m)"
            ),
            {
                "rid": rule.id,
                "et": entity_type,
                "ek": entity_key,
                "via": via,
                "conf": confidence,
                "m": matched_on,
            },
        )

    async def test_firing_rules_rank_above_blocked_and_weak_ones(self, db_session, test_feed, cloud_inventory):
        actor, _ = await _seed_threat(
            db_session, test_feed, techniques=[("T1078.004", "Cloud Accounts", CLOUD_CHANNELS)]
        )
        fires = await self._rule(db_session, "Device Code Authentication Flow", data_sources=["m365:unified"])
        blocked = await self._rule(db_session, "Vault Access via Sysmon", data_sources=["WinEventLog:Sysmon"])
        weak = await self._rule(db_session, "Generic Analytic", data_sources=["m365:unified"])
        await self._coverage(db_session, fires, entity_types.TTP, "T1078.004", "tag", "high", "T1078.004")
        await self._coverage(db_session, blocked, entity_types.TTP, "T1078.004", "tag", "high", "T1078.004")
        await self._coverage(db_session, weak, entity_types.THREAT_ACTOR, str(actor.id), "text", "low", "Testcrew")
        await db_session.commit()

        found = await get_prior_rules(db_session, entity_types.THREAT_ACTOR, str(actor.id), "T1078.004")
        titles = [r.title for r in found.items]
        # Telemetry first: a rule that cannot fire here is not the one to adopt,
        # however cleanly it matched.
        assert titles.index("Device Code Authentication Flow") < titles.index("Generic Analytic")
        assert titles.index("Generic Analytic") < titles.index("Vault Access via Sysmon")
        assert found.total_candidates == 3
        assert (found.strong, found.weak) == (2, 1)
        assert (found.technique_scope, found.threat_scope) == (2, 1)

    async def test_row_carries_why_it_matched_and_its_provenance(self, db_session, test_feed, cloud_inventory):
        actor, _ = await _seed_threat(
            db_session, test_feed, techniques=[("T1078.004", "Cloud Accounts", CLOUD_CHANNELS)]
        )
        rule = await self._rule(db_session, "Testcrew Loader", rule_type="yara", repo="signature-base", lic="CC-BY-4.0")
        await self._coverage(db_session, rule, entity_types.THREAT_ACTOR, str(actor.id), "text", "low", "Testcrew")
        await db_session.commit()

        found = await get_prior_rules(db_session, entity_types.THREAT_ACTOR, str(actor.id), "T1078.004")
        row = found.items[0]
        assert (row.via, row.confidence, row.matched_on) == ("text", "low", "Testcrew")
        assert row.scope == "threat"
        assert (row.repo, row.license) == ("signature-base", "CC-BY-4.0")

    async def test_rule_matching_twice_is_one_row_at_its_strongest_claim(self, db_session, test_feed, cloud_inventory):
        actor, _ = await _seed_threat(
            db_session, test_feed, techniques=[("T1078.004", "Cloud Accounts", CLOUD_CHANNELS)]
        )
        rule = await self._rule(db_session, "Both Ways", data_sources=["m365:unified"])
        await self._coverage(db_session, rule, entity_types.TTP, "T1078.004", "tag", "high", "T1078.004")
        await self._coverage(db_session, rule, entity_types.THREAT_ACTOR, str(actor.id), "text", "low", "Testcrew")
        await db_session.commit()

        found = await get_prior_rules(db_session, entity_types.THREAT_ACTOR, str(actor.id), "T1078.004")
        assert found.total_candidates == 1
        assert found.items[0].confidence == "high"
        assert found.items[0].scope == "technique"


@pytest.mark.asyncio
class TestSavedSets:
    async def test_saving_a_set_writes_a_detection_summary_with_provenance(
        self, db_session, test_feed, test_user, cloud_inventory
    ):
        actor, entries = await _seed_threat(
            db_session, test_feed, techniques=[("T1078.004", "Cloud Accounts", CLOUD_CHANNELS)]
        )
        rule = DetectionRule(
            title="Device Code Authentication Flow",
            rule_type="kql",
            rule_content="SigninLogs | where 1 == 1",
            is_draft=False,
            license="MIT",
            metadata_={"repo": "Azure-Sentinel"},
        )
        db_session.add(rule)
        await db_session.flush()
        await db_session.commit()

        before = (await db_session.execute(select(DetectionSummary))).scalars().all()
        assert before == []

        summary = await save_set(
            db_session,
            user_id=test_user.id,
            entity_type=entity_types.THREAT_ACTOR,
            entity_key=str(actor.id),
            label="Testcrew",
            window="14d",
            title="Testcrew — device code",
            items=[
                {"op": "adopt", "rule_id": str(rule.id), "technique_id": "T1078.004"},
                {"op": "new", "technique_id": "T1078.004", "title": "New draft", "rule_type": "sigma"},
            ],
            entry_ids=[entries[0].id],
        )

        stored = (await db_session.execute(select(DetectionSummary))).scalars().all()
        assert len(stored) == 1
        adopted = summary.summary_content["items"][0]
        # Provenance is read from the library at save time, not trusted from the
        # client, so the set keeps its attribution wherever it is exported.
        assert adopted["repo"] == "Azure-Sentinel"
        assert adopted["license"] == "MIT"
        assert adopted["rule_type"] == "kql"
        assert adopted["title"] == "Device Code Authentication Flow"
        assert summary.summary_content["items"][1]["op"] == "new"

    async def test_saving_with_summary_id_rewrites_instead_of_accumulating(
        self, db_session, test_feed, test_user, cloud_inventory
    ):
        actor, _ = await _seed_threat(db_session, test_feed)
        await db_session.commit()

        first = await save_set(
            db_session,
            user_id=test_user.id,
            entity_type=entity_types.THREAT_ACTOR,
            entity_key=str(actor.id),
            label="Testcrew",
            window="14d",
            title="Working set",
            items=[{"op": "new", "title": "One"}],
            entry_ids=[],
        )
        second = await save_set(
            db_session,
            user_id=test_user.id,
            entity_type=entity_types.THREAT_ACTOR,
            entity_key=str(actor.id),
            label="Testcrew",
            window="14d",
            title="Working set",
            items=[{"op": "new", "title": "One"}, {"op": "new", "title": "Two"}],
            entry_ids=[],
            summary_id=first.id,
        )

        assert second.id == first.id
        rows = await list_sets(db_session, test_user.id, entity_types.THREAT_ACTOR, str(actor.id))
        assert len(rows) == 1
        assert len(rows[0].summary_content["items"]) == 2


@pytest.mark.asyncio
class TestFaces:
    """One Detection tab, four faces: the CVE and technique workspaces."""

    async def test_cve_face_carries_exploitation_context_and_accepts_both_keys(
        self, db_session, test_feed, cloud_inventory
    ):
        from app.models.cve import CVE, EntryCVE

        cve = CVE(cve_id="CVE-2026-99999", severity="CRITICAL", is_kev=True, github_poc_count=3)
        db_session.add(cve)
        await db_session.flush()

        entry = Entry(
            feed_id=test_feed.id,
            guid="cve-entry",
            title="Exploitation of CVE-2026-99999 escalates",
            url="https://outlet.example.com/cve",
            published_at=datetime.now(UTC) - timedelta(days=1),
        )
        db_session.add(entry)
        await db_session.flush()
        db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve.id))
        ttp = TTP(technique_id="T1190", technique_name="Exploit Public-Facing Application", data_sources=CLOUD_CHANNELS)
        db_session.add(ttp)
        await db_session.flush()
        db_session.add(EntryTTP(entry_id=entry.id, ttp_id=ttp.id))
        await db_session.commit()

        # By canonical id (the board's key) and by uuid (the profile's key):
        # both must land on the same workspace under the canonical key.
        for key in ("CVE-2026-99999", str(cve.id)):
            ws = await build_workspace(db_session, entity_types.CVE, key)
            assert ws is not None, key
            assert ws.entity_key == "CVE-2026-99999"
            assert ws.cve is not None
            assert ws.cve["is_kev"] is True
            assert ws.cve["github_poc_count"] == 3
            assert [a.title for a in ws.articles] == ["Exploitation of CVE-2026-99999 escalates"]
            assert [b.technique_id for b in ws.behaviours] == ["T1190"]

    async def test_technique_face_is_a_bench_for_one_technique_only(self, db_session, test_feed, cloud_inventory):
        # Two techniques ride the same article; the T1078.004 face must not
        # show its neighbour's row.
        actor, _ = await _seed_threat(
            db_session,
            test_feed,
            techniques=[
                ("T1078.004", "Cloud Accounts", CLOUD_CHANNELS),
                ("T1574.002", "DLL Side-Loading", WINDOWS_CHANNELS),
            ],
        )
        await db_session.commit()

        ws = await build_workspace(db_session, entity_types.TTP, "T1078.004")
        assert ws is not None
        assert ws.entity_key == "T1078.004"
        assert [b.technique_id for b in ws.behaviours] == ["T1078.004"]
        assert ws.cve is None
        # The article that mentioned the technique is the bench's intel column.
        assert len(ws.articles) == 1


@pytest.mark.asyncio
class TestApi:
    async def test_workspace_endpoint_returns_the_four_regions(
        self, client, auth_headers, db_session, test_feed, cloud_inventory
    ):
        actor, _ = await _seed_threat(
            db_session,
            test_feed,
            techniques=[
                ("T1078.004", "Cloud Accounts", CLOUD_CHANNELS),
                ("T1574.002", "DLL Side-Loading", WINDOWS_CHANNELS),
            ],
        )
        await db_session.commit()

        resp = await client.get(f"/api/coverage-workspace/threat_actor/{actor.id}?window=14d", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["label"] == "Testcrew"
        assert len(body["articles"]) == 1
        assert body["below_line_count"] == 1
        assert body["missing_categories"] == ["windows_events"]
        assert body["behaviours"][-1]["technique_id"] == "T1574.002"

    async def test_unsupported_entity_type_is_a_400_not_an_empty_workspace(self, client, auth_headers):
        # CVEs and techniques gained faces of their own; vendors did not — a
        # tab that could only render an empty ladder shouldn't exist.
        resp = await client.get("/api/coverage-workspace/vendor/Microsoft", headers=auth_headers)
        assert resp.status_code == 400

    async def test_unknown_cve_is_a_404(self, client, auth_headers):
        resp = await client.get("/api/coverage-workspace/cve/CVE-2026-1731", headers=auth_headers)
        assert resp.status_code == 404

    async def test_unknown_entity_is_404(self, client, auth_headers):
        resp = await client.get(
            "/api/coverage-workspace/threat_actor/00000000-0000-0000-0000-000000000000",
            headers=auth_headers,
        )
        assert resp.status_code == 404

    async def test_set_round_trip_through_the_api(self, client, auth_headers, db_session, test_feed, cloud_inventory):
        actor, _ = await _seed_threat(
            db_session, test_feed, techniques=[("T1078.004", "Cloud Accounts", CLOUD_CHANNELS)]
        )
        await db_session.commit()

        created = await client.post(
            f"/api/coverage-workspace/threat_actor/{actor.id}/sets",
            headers=auth_headers,
            json={
                "title": "Testcrew — device code",
                "window": "14d",
                "items": [{"op": "new", "technique_id": "T1078.004", "title": "Draft"}],
            },
        )
        assert created.status_code == 201
        summary_id = created.json()["id"]

        listed = await client.get(f"/api/coverage-workspace/threat_actor/{actor.id}/sets", headers=auth_headers)
        assert listed.json()["total"] == 1

        # bundle: file list with the research report as MANIFEST.md on top.
        exported = await client.post(
            f"/api/coverage-workspace/sets/{summary_id}/export?format=bundle", headers=auth_headers
        )
        assert exported.status_code == 200
        assert exported.json()["item_count"] == 1
        files = exported.json()["payload"]["files"]
        assert files[0]["path"] == "MANIFEST.md"
        assert "Testcrew" in files[0]["content"]

        # markdown: the research report itself, skips rendered as known gaps.
        md = await client.post(
            f"/api/coverage-workspace/sets/{summary_id}/export?format=markdown", headers=auth_headers
        )
        assert md.status_code == 200
        assert "## Behaviours" in md.json()["payload"]["markdown"]

        # zip: a real archive a browser can download.
        z = await client.get(f"/api/coverage-workspace/sets/{summary_id}/export.zip", headers=auth_headers)
        assert z.status_code == 200
        assert z.headers["content-type"] == "application/zip"
        import io
        import zipfile

        with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
            assert "MANIFEST.md" in zf.namelist()

    async def test_skip_persists_with_its_reason(self, client, auth_headers, db_session, test_feed, cloud_inventory):
        """A skip is a judgement worth keeping — it survives the round trip and
        explains the gap to the next person who opens this threat."""
        actor, _ = await _seed_threat(
            db_session, test_feed, techniques=[("T1078.004", "Cloud Accounts", CLOUD_CHANNELS)]
        )
        user_id = (await db_session.execute(text("SELECT id FROM users LIMIT 1"))).scalar_one()
        rule = DetectionRule(
            created_by=user_id,
            rule_type="yara",
            title="Old file signature",
            rule_content="rule x { condition: true }",
        )
        db_session.add(rule)
        await db_session.flush()
        await db_session.commit()

        created = await client.post(
            f"/api/coverage-workspace/threat_actor/{actor.id}/sets",
            headers=auth_headers,
            json={
                "title": "Testcrew — with a known gap",
                "window": "14d",
                "items": [
                    {
                        "op": "adopt",
                        "rule_id": str(rule.id),
                        "technique_id": "T1078.004",
                        "title": "Old file signature",
                    },
                    {
                        "op": "skip",
                        "rule_id": str(rule.id),
                        "technique_id": "T1078.004",
                        "title": "Old file signature",
                        "reason": "cannot fire here",
                    },
                ],
            },
        )
        assert created.status_code == 201, created.text
        content = created.json()["content"]
        skip = next(i for i in content["items"] if i["op"] == "skip")
        assert skip["reason"] == "cannot fire here"

    async def test_unknown_export_format_is_rejected(
        self, client, auth_headers, db_session, test_feed, cloud_inventory
    ):
        actor, _ = await _seed_threat(db_session, test_feed)
        await db_session.commit()
        created = await client.post(
            f"/api/coverage-workspace/threat_actor/{actor.id}/sets",
            headers=auth_headers,
            json={"title": "Set", "window": "14d", "items": []},
        )
        resp = await client.post(
            f"/api/coverage-workspace/sets/{created.json()['id']}/export?format=stix",
            headers=auth_headers,
        )
        assert resp.status_code == 400
