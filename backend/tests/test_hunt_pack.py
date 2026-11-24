"""Hunt packs: hypotheses and queries drafted from a board row's window or a
profile's whole record, the ATHF hunt files they export to, and the hunt
package zip.

The pack is a starting point, so the tests hold it to that: it is drafted only
from its scope's evidence, cached per entity/scope/language, checked against
the telemetry inventory at read time, and exported one ATHF file per
hypothesis in the shape ATHF's template defines with Keep left empty. Nothing
about the hunt is stored.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.entry import Entry
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP
from app.services import hunt_pack as hp

CANNED = {
    "hypotheses": [
        {
            "title": "Help-desk reset followed by MFA enrollment",
            "hypothesis": (
                "Adversaries use help-desk password resets to register their own MFA method on employee accounts."
            ),
            "tactic": "credential-access",
            "techniques": ["T1621", "T1556.006"],
            "platform": "Identity Provider",
            "data_sources": ["auth.account", "auth.mfa", "not-a-real-id"],
            "query": "AuditLogs\n| where TimeGenerated > ago(7d)\n| take 100",
            "query_notes": "Join resets to registrations within one hour.",
            "false_positives": "New-hire onboarding.",
        },
        {"hypothesis": "no query here", "data_sources": []},
        {
            "hypothesis": "Adversaries use RMM installs to keep access on workstations.",
            "query": "DeviceProcessEvents | where FileName =~ 'AnyDesk.exe' | summarize count() by DeviceName",
            "data_sources": ["process.creation"],
            "techniques": ["T1219"],
        },
    ]
}


class TestNormalize:
    def test_drops_items_without_a_query_and_numbers_the_rest(self):
        hyps = hp.normalize_pack(CANNED)
        assert [h["id"] for h in hyps] == ["H1", "H2"]
        assert hyps[1]["title"].startswith("Adversaries use RMM installs")

    def test_keeps_only_canonical_data_sources(self):
        hyps = hp.normalize_pack(CANNED)
        assert hyps[0]["data_sources"] == ["auth.account", "auth.mfa"]

    def test_caps_at_three_for_a_window_and_five_for_a_profile(self):
        many = {"hypotheses": [CANNED["hypotheses"][0]] * 8}
        assert len(hp.normalize_pack(many)) == hp.MAX_HYPOTHESES
        assert len(hp.normalize_pack(many, hp.max_hypotheses("all"))) == hp.MAX_PROFILE_HYPOTHESES == 5
        assert hp.max_hypotheses("14d") == 3

    def test_reads_hunting_query_the_schema_field_and_query_from_older_packs(self):
        item = {k: v for k, v in CANNED["hypotheses"][0].items() if k != "query"}
        new = hp.normalize_pack({"hypotheses": [{**item, "hunting_query": "SigninLogs | take 100"}]})
        assert new[0]["query"] == "SigninLogs | take 100"
        empty = hp.normalize_pack({"hypotheses": [{**item, "hunting_query": ""}]})
        assert empty == [], "an empty query is no hunt"

    def test_one_line_pipe_queries_get_one_stage_per_line_outside_strings(self):
        q = 'let lookback = 7d; DeviceProcessEvents | where Cmd has "a | b; c" | take 100'
        assert hp.format_query(q, "kql") == (
            'let lookback = 7d;\nDeviceProcessEvents\n| where Cmd has "a | b; c"\n| take 100'
        )
        assert hp.format_query("index=x | stats count", "spl") == "index=x\n| stats count"
        assert hp.format_query("T\n| take 1", "kql") == "T\n| take 1", "already multi-line: untouched"
        assert hp.format_query("title: x | y", "sigma") == "title: x | y"

    def test_bookkeeping_quotes_are_not_evidence(self):
        assert hp.is_junk_quote("reclassified from clickfix")
        assert hp.is_junk_quote("ATT&CK mapping from detection rule: T1486")
        assert hp.is_junk_quote("auto_link:akira")
        assert hp.is_junk_quote(None)
        assert not hp.is_junk_quote("procdump.exe was run from the C:\\PerfLogs folder")

    def test_garbage_in_nothing_out(self):
        assert hp.normalize_pack(None) == []
        assert hp.normalize_pack({"hypotheses": "nope"}) == []
        assert hp.normalize_pack({"hypotheses": [1, "x", None]}) == []


class TestLanguageAndKeys:
    def test_cache_key_separates_window_and_language(self):
        a = hp.pack_target_id("threat_actor", "k", "14d", "kql")
        assert a != hp.pack_target_id("threat_actor", "k", "7d", "kql")
        assert a != hp.pack_target_id("threat_actor", "k", "14d", "spl")
        assert a == hp.pack_target_id("threat_actor", "k", "14d", "kql")


def _pack(**over) -> dict:
    hyps = hp.normalize_pack(CANNED)
    for h in hyps:
        h["telemetry"] = [{"source": d, "have": d == "auth.mfa"} for d in h["data_sources"]]
        h["runnable"] = all(t["have"] for t in h["telemetry"])
    base = {
        "entity_type": "threat_actor",
        "entity_key": "abc",
        "label": "Scattered Spider",
        "window": "14d",
        "language": "kql",
        "language_name": "KQL (Microsoft Sentinel / Defender XDR)",
        "generated_at": "2026-11-17T00:00:00+00:00",
        "model": "test",
        "entry_ids": [],
        "hypotheses": hyps,
    }
    return {**base, **over}


class TestOneHuntPerFile:
    def test_single_hypothesis_narrows_the_pack_and_names_the_file_after_it(self):
        one = hp.single_hypothesis(_pack(), "H2")
        assert [h["id"] for h in one["hypotheses"]] == ["H2"]
        assert hp.hunt_filename(one) == "H-XXXX-scattered-spider-adversaries-use-rmm-installs-to-keep-access-on.md"
        assert hp.single_hypothesis(_pack(), "H9") is None

    def test_profile_scope_says_where_it_came_from(self):
        md = hp.render_athf_markdown(_pack(window="all"), hunter="a", articles=[])
        assert "IntelFeed profile, all reporting" in md
        md = hp.render_athf_markdown(_pack(), hunter="a", articles=[])
        assert "IntelFeed Threats board, 14d window" in md


class TestHuntFile:
    def test_frontmatter_follows_the_athf_template(self):
        md = hp.render_athf_markdown(
            _pack(),
            hunter="aoneil",
            articles=[
                {
                    "title": "Insurer confirms intrusion",
                    "url": "https://x.example/a",
                    "source": "x.example",
                    "published_at": "2026-11-14",
                }
            ],
            today=datetime(2026, 11, 17, tzinfo=UTC),
        )
        head = md.split("---")[1]
        for key in (
            "hunt_id: H-XXXX",
            "status: planning",
            "date: 2026-11-17",
            "hunter: aoneil",
            "hunt_type: hypothesis",
            "platform: [Identity Provider]",
            "tactics: [credential-access]",
            "techniques: [T1219, T1556.006, T1621]",
            "data_sources: [Sentinel]",
            "findings_count: 0",
            "findings: []",
            "ruled_out: []",
            "tags: [intelfeed, threat-actor, scattered-spider]",
        ):
            assert key in head, key

    def test_lock_sections_filled_except_keep(self):
        md = hp.render_athf_markdown(_pack(), hunter="a", articles=[], today=datetime(2026, 11, 17, tzinfo=UTC))
        for heading in ("## LEARN", "## OBSERVE", "## CHECK", "## KEEP"):
            assert heading in md
        # Learn carries the hypotheses and ABLE table; Check the queries.
        assert "H1. **Help-desk reset followed by MFA enrollment**" in md
        assert "| H1 | Scattered Spider |" in md
        assert "```kql\nAuditLogs\n| where TimeGenerated > ago(7d)\n| take 100\n```" in md
        assert "**Telemetry not collected when exported:** auth.account, process.creation" in md
        # Keep is the hunter's: counts at zero, tables empty.
        keep = md.split("## KEEP")[1]
        assert "`confirmed` 0 · `suspected` 0" in keep
        assert "_Fill in after the hunt._" in keep
        assert "INC-" not in keep

    def test_cve_rows_scope_actor_as_any_and_carry_facts(self):
        md = hp.render_athf_markdown(
            _pack(entity_type="cve", entity_key="CVE-2026-1", label="CVE-2026-1"),
            hunter="a",
            articles=[],
            facts={"affected": ["FortiOS"], "is_kev": True, "kev_date_added": "2026-11-12", "cvss_score": 9.8},
        )
        assert "| H1 | (any) |" in md
        assert "affected: FortiOS · on CISA KEV since 2026-11-12 · CVSS 9.8" in md

    def test_filename_is_a_slug_under_the_placeholder_id(self):
        assert hp.hunt_filename(_pack()) == "H-XXXX-scattered-spider.md"
        assert hp.hunt_filename(_pack(label="CVE-2026-1 / FortiOS")) == "H-XXXX-cve-2026-1-fortios.md"
        assert hp.hunt_filename(_pack(), "H-0042") == "H-0042-scattered-spider.md"

    def test_title_with_a_colon_is_quoted_for_yaml(self):
        import yaml

        md = hp.render_athf_markdown(_pack(), hunter="a", articles=[], hunt_id="H-0001")
        head = yaml.safe_load(md.split("---")[1])
        assert head["hunt_id"] == "H-0001"
        assert head["title"] == "Scattered Spider: 2 hunt hypotheses"
        assert head["techniques"] == ["T1219", "T1556.006", "T1621"]
        for heading in ("### Threat Context", "### Visualization & Analytics", "### Follow-up Hunts"):
            assert heading in md


async def _seed_actor(db_session, test_feed, *, name="Hunt Crew", entries=2, technique=True):
    actor = ThreatActor(name=name)
    db_session.add(actor)
    await db_session.flush()
    ttp = None
    if technique:
        ttp = TTP(
            technique_id="T1621",
            technique_name="Multi-Factor Authentication Request Generation",
            tactic="credential-access",
        )
        db_session.add(ttp)
        await db_session.flush()
    now = datetime.now(UTC)
    for i in range(entries):
        entry = Entry(
            feed_id=test_feed.id,
            guid=f"{name}-{i}",
            title=f"{name} resets passwords via the help desk, wave {i}",
            url=f"https://outlet{i}.example.com/{name}/{i}",
            summary="Callers impersonate staff to reset passwords, then enroll an authenticator.",
            published_at=now - timedelta(days=1),
        )
        db_session.add(entry)
        await db_session.flush()
        db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
        if ttp is not None:
            db_session.add(EntryTTP(entry_id=entry.id, ttp_id=ttp.id, source_text="registered a new MFA method"))
    await db_session.commit()
    return actor


def _stub_run_task(monkeypatch, db_session, parsed, *, store=True):
    """Stand in for the AI engine: record what it was asked, store a result row
    the way run_task does, return the parsed JSON."""
    import app.ai.engine as engine

    calls: list[dict] = []

    async def fake_run_task(db, user_id, task_name, variables, **kw):
        calls.append({"task_name": task_name, "variables": variables, **kw})
        if parsed is None:
            return None
        if store:
            task_id = (await db.execute(select(AITask.id).where(AITask.name == task_name))).scalar_one()
            db.add(
                AIResult(
                    task_id=task_id,
                    target_type=kw["target_type"],
                    target_id=kw["target_id"],
                    parsed_result=dict(parsed),
                    model_name="stub",
                    is_current=True,
                )
            )
            await db.flush()
        return parsed

    monkeypatch.setattr(engine, "run_task", fake_run_task)
    return calls


async def _ensure_task(db_session):
    if (await db_session.execute(select(AITask).where(AITask.name == hp.TASK_NAME))).scalar_one_or_none() is None:
        db_session.add(
            AITask(
                name=hp.TASK_NAME, display_name="Hunt pack", default_prompt_template="{{ threat_name }}", is_system=True
            )
        )
        await db_session.commit()


@pytest.mark.asyncio
class TestGenerate:
    async def test_prompt_sees_only_the_window(self, db_session, test_feed, test_user, monkeypatch):
        actor = await _seed_actor(db_session, test_feed)
        await _ensure_task(db_session)
        calls = _stub_run_task(monkeypatch, db_session, CANNED)

        pack = await hp.generate_hunt_pack(db_session, test_user.id, "threat_actor", str(actor.id), "14d", "spl")

        assert pack is not None and [h["id"] for h in pack["hypotheses"]] == ["H1", "H2"]
        assert pack["language"] == "spl" and pack["label"] == "Hunt Crew"
        call = calls[0]
        assert call["task_name"] == hp.TASK_NAME
        v = call["variables"]
        assert v["query_language"] == "spl" and v["query_language_name"] == "SPL (Splunk)"
        assert v["entry_count"] == 2 and len(v["entries"]) == 2
        assert [b["technique_id"] for b in v["behaviours"]] == ["T1621"]
        assert v["behaviours"][0]["quotes"][0]["text"] == "registered a new MFA method"
        assert "auth.mfa" in v["log_types"] and "process.creation" in v["log_types"]
        assert call["caller"].is_user

    async def test_cached_pack_reads_back_and_keeps_the_audit_trail(
        self, db_session, test_feed, test_user, monkeypatch
    ):
        actor = await _seed_actor(db_session, test_feed, name="Cache Crew")
        await _ensure_task(db_session)
        _stub_run_task(monkeypatch, db_session, CANNED)
        await hp.generate_hunt_pack(db_session, test_user.id, "threat_actor", str(actor.id), "14d", "kql")

        cached = await hp.get_cached_pack(db_session, "threat_actor", str(actor.id), "14d", "kql")
        assert cached is not None
        assert len(cached["entry_ids"]) == 2
        assert cached["hypotheses"][0]["data_sources"] == ["auth.account", "auth.mfa"]
        # Another language is another pack.
        assert await hp.get_cached_pack(db_session, "threat_actor", str(actor.id), "14d", "spl") is None

    async def test_an_unusable_redraft_keeps_the_last_good_pack(self, db_session, test_feed, test_user, monkeypatch):
        actor = await _seed_actor(db_session, test_feed, name="Redraft Crew")
        await _ensure_task(db_session)
        _stub_run_task(monkeypatch, db_session, CANNED)
        await hp.generate_hunt_pack(db_session, test_user.id, "threat_actor", str(actor.id), "all", "kql")

        import app.ai.engine as engine

        good = await hp._current_result(db_session, hp.pack_target_id("threat_actor", str(actor.id), "all", "kql"))

        async def empty_queries(db, user_id, task_name, variables, **kw):
            await engine.demote_current_results(
                db, target_type=kw["target_type"], target_id=kw["target_id"], task_id=good.task_id
            )
            db.add(
                AIResult(
                    task_id=good.task_id,
                    target_type=kw["target_type"],
                    target_id=kw["target_id"],
                    parsed_result={"hypotheses": [{"hypothesis": "x", "hunting_query": ""}]},
                    model_name="stub",
                    is_current=True,
                )
            )
            await db.flush()
            return {"hypotheses": [{"hypothesis": "x", "hunting_query": ""}]}

        monkeypatch.setattr(engine, "run_task", empty_queries)
        assert (
            await hp.generate_hunt_pack(db_session, test_user.id, "threat_actor", str(actor.id), "all", "kql") is None
        )
        cached = await hp.get_cached_pack(db_session, "threat_actor", str(actor.id), "all", "kql")
        assert cached is not None and [h["id"] for h in cached["hypotheses"]] == ["H1", "H2"]

    async def test_draft_more_keeps_the_pack_and_numbers_new_hunts_on(
        self, db_session, test_feed, test_user, monkeypatch
    ):
        actor = await _seed_actor(db_session, test_feed, name="More Crew")
        await _ensure_task(db_session)
        _stub_run_task(monkeypatch, db_session, CANNED)
        await hp.generate_hunt_pack(db_session, test_user.id, "threat_actor", str(actor.id), "all", "kql")

        more = {
            "hypotheses": [
                {**CANNED["hypotheses"][0]},  # a repeat by title: dropped
                {
                    "title": "Rclone to cloud storage",
                    "hypothesis": "Adversaries use Rclone to exfiltrate data on file servers.",
                    "hunting_query": "DeviceProcessEvents | where FileName =~ 'rclone.exe' | take 100",
                    "data_sources": ["process.creation"],
                    "techniques": ["T1567.002"],
                },
            ]
        }
        calls = _stub_run_task(monkeypatch, db_session, more)
        pack = await hp.generate_hunt_pack(
            db_session, test_user.id, "threat_actor", str(actor.id), "all", "kql", append=True
        )
        assert [h["id"] for h in pack["hypotheses"]] == ["H1", "H2", "H3"]
        assert pack["hypotheses"][2]["title"] == "Rclone to cloud storage"
        assert [h["title"] for h in calls[0]["variables"]["existing_hunts"]] == [
            "Help-desk reset followed by MFA enrollment",
            "Adversaries use RMM installs to keep access on workstations.",
        ]

        # Only repeats back: nothing new, and the pack stays as it was.
        _stub_run_task(monkeypatch, db_session, {"hypotheses": [CANNED["hypotheses"][0]]})
        assert (
            await hp.generate_hunt_pack(
                db_session, test_user.id, "threat_actor", str(actor.id), "all", "kql", append=True
            )
            is None
        )
        cached = await hp.get_cached_pack(db_session, "threat_actor", str(actor.id), "all", "kql")
        assert [h["id"] for h in cached["hypotheses"]] == ["H1", "H2", "H3"]

    async def test_the_log_a_hunt_reads_is_checked_against_the_inventory(
        self, db_session, test_feed, test_user, monkeypatch
    ):
        from app.models.telemetry_source import TelemetrySource

        actor = await _seed_actor(db_session, test_feed, name="Source Crew")
        await _ensure_task(db_session)
        db_session.add(
            TelemetrySource(
                name="Okta Identity Cloud",
                category="identity",
                enabled=True,
                ingested_into="LogScale",
                log_types=["auth.mfa", "auth.account"],
                log_types_canonical=["auth.mfa", "auth.account"],
                created_by=test_user.id,
            )
        )
        await db_session.commit()
        item = {**CANNED["hypotheses"][0], "data_sources": ["auth.mfa"]}
        drafted = {
            "hypotheses": [
                {
                    **item,
                    "log_source": "Okta system log in LogScale",
                    "source_name": "Okta Identity Cloud (into LogScale)",
                },
                {
                    **item,
                    "title": "vCenter archive staging",
                    "log_source": "vCenter VCSA syslog",
                    "source_name": "none",
                },
            ]
        }
        calls = _stub_run_task(monkeypatch, db_session, drafted)
        pack = await hp.generate_hunt_pack(db_session, test_user.id, "threat_actor", str(actor.id), "all", "kql")

        inventory = calls[0]["variables"]["telemetry_inventory"]
        identity = next(c for c in inventory if c["category"] == "identity")
        assert "Okta Identity Cloud (into LogScale)" in identity["sources"]
        assert "auth.mfa" in identity["log_types"]

        annotated = await hp.annotate_telemetry(db_session, dict(pack))
        okta, vcenter = annotated["hypotheses"]
        assert okta["source_have"] is True and okta["runnable"] is True
        assert vcenter["source_name"] == "" and vcenter["source_have"] is False
        assert vcenter["runnable"] is False, "a log nobody collects is not runnable, whatever its log type says"
        md = hp.render_athf_markdown(hp.single_hypothesis(annotated, "H2"), hunter="a", articles=[])
        assert "**Log source (H2):** vCenter VCSA syslog — not in the telemetry inventory" in md

    async def test_window_without_evidence_is_nothing_to_hunt(self, db_session, test_feed, test_user, monkeypatch):
        actor = await _seed_actor(db_session, test_feed, name="Quiet Crew", entries=0, technique=False)
        await _ensure_task(db_session)
        calls = _stub_run_task(monkeypatch, db_session, CANNED)
        with pytest.raises(hp.NothingToHunt):
            await hp.generate_hunt_pack(db_session, test_user.id, "threat_actor", str(actor.id), "14d", "kql")
        assert calls == [], "no model call without evidence"

    async def test_unknown_row_is_a_lookup_error(self, db_session, test_user, monkeypatch):
        _stub_run_task(monkeypatch, db_session, CANNED)
        with pytest.raises(LookupError):
            await hp.generate_hunt_pack(db_session, test_user.id, "threat_actor", str(uuid.uuid4()), "14d", "kql")

    async def test_telemetry_is_checked_at_read_time(self, db_session, test_feed, test_user, monkeypatch):
        from app.models.telemetry_source import TelemetrySource

        actor = await _seed_actor(db_session, test_feed, name="Tel Crew")
        await _ensure_task(db_session)
        _stub_run_task(monkeypatch, db_session, CANNED)
        pack = await hp.generate_hunt_pack(db_session, test_user.id, "threat_actor", str(actor.id), "14d", "kql")

        annotated = await hp.annotate_telemetry(db_session, dict(pack))
        h1 = annotated["hypotheses"][0]
        assert all(t["have"] is False for t in h1["telemetry"]) and h1["runnable"] is False

        db_session.add(
            TelemetrySource(
                name="Entra ID",
                category="identity",
                enabled=True,
                log_types=["auth.account", "auth.mfa"],
                log_types_canonical=["auth.account", "auth.mfa"],
                created_by=test_user.id,
            )
        )
        await db_session.commit()
        annotated = await hp.annotate_telemetry(db_session, dict(pack))
        h1 = annotated["hypotheses"][0]
        assert all(t["have"] for t in h1["telemetry"]) and h1["runnable"] is True


def _stub_queue(monkeypatch):
    """No AI worker in tests: record what would be queued, and say a provider answers."""
    from app.workers.celery_app import celery_app

    sent: list[dict] = []
    monkeypatch.setattr(
        celery_app,
        "send_task",
        lambda name, kwargs=None, queue=None: sent.append({"name": name, "kwargs": kwargs, "queue": queue}),
    )

    async def provider(*_a, **_kw):
        return object()

    monkeypatch.setattr(hp.ai_engine, "resolve_assignment", provider)
    return sent


async def _run_worker(db_session, user_id, job: dict):
    """What app.workers.hunt_pack_tasks does, on the test session."""
    kw = job["kwargs"]
    await hp.generate_hunt_pack(db_session, user_id, kw["entity_type"], kw["entity_key"], kw["scope"], kw["lang"])
    await hp.clear_draft_state(hp.pack_target_id(kw["entity_type"], kw["entity_key"], kw["scope"], kw["lang"]))


@pytest.mark.asyncio
class TestApi:
    async def test_none_then_drafting_then_ready_then_one_file_per_hunt(
        self, db_session, client, auth_headers, test_feed, test_user, monkeypatch
    ):
        actor = await _seed_actor(db_session, test_feed, name="Api Crew")
        await _ensure_task(db_session)
        _stub_run_task(monkeypatch, db_session, CANNED)
        sent = _stub_queue(monkeypatch)
        base = f"/api/hunt-packs/threat_actor/{actor.id}"

        resp = await client.get(f"{base}?scope=14d", headers=auth_headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "none"
        assert resp.json()["language"] == "kql"
        assert (await client.get(f"{base}/hunts/H1.md?scope=14d", headers=auth_headers)).status_code == 404

        resp = await client.post(f"{base}?scope=14d", headers=auth_headers)
        assert resp.status_code == 202, resp.text
        assert resp.json()["status"] == "drafting" and resp.json()["started_at"]
        assert sent == [
            {
                "name": hp.DRAFT_TASK,
                "kwargs": {
                    "user_id": str(test_user.id),
                    "entity_type": "threat_actor",
                    "entity_key": str(actor.id),
                    "scope": "14d",
                    "lang": "kql",
                    "append": False,
                },
                "queue": "ai",
            }
        ]
        # A second click while drafting queues nothing more.
        await client.post(f"{base}?scope=14d", headers=auth_headers)
        assert len(sent) == 1

        await _run_worker(db_session, test_user.id, sent[0])
        body = (await client.get(f"{base}?scope=14d", headers=auth_headers)).json()
        assert body["status"] == "ready"
        assert [h["id"] for h in body["pack"]["hypotheses"]] == ["H1", "H2"]
        assert body["pack"]["hypotheses"][0]["telemetry"][0] == {"source": "auth.account", "have": False}
        refs = body["pack"]["hypotheses"][0]["technique_refs"]
        assert refs[0]["technique_id"] == "T1621" and refs[0]["name"].startswith("Multi-Factor") and refs[0]["id"]
        assert refs[1] == {"technique_id": "T1556.006", "name": None, "id": None}, "not in the catalog: no link"
        # The profile's scope is another pack.
        assert (await client.get(base, headers=auth_headers)).json()["status"] == "none"

        resp = await client.get(f"{base}/hunts/H1.md?scope=14d", headers=auth_headers)
        assert resp.status_code == 200, resp.text
        assert resp.headers["content-type"].startswith("text/markdown")
        assert "H-XXXX-api-crew-help-desk-reset-followed-by-mfa-enrollment.md" in resp.headers["content-disposition"]
        assert resp.text.startswith("---\nhunt_id: H-XXXX\n")
        assert "Help-desk reset followed by MFA enrollment" in resp.text
        assert "Adversaries use RMM installs" not in resp.text, "one hypothesis per file"
        assert f"hunter: {test_user.username}" in resp.text
        assert "Api Crew resets passwords via the help desk, wave 0" in resp.text

        resp = await client.get(f"{base}/hunts/H2.md?scope=14d&hunt_id=H-0007", headers=auth_headers)
        assert resp.status_code == 200, resp.text
        assert resp.text.startswith("---\nhunt_id: H-0007\n")
        assert (await client.get(f"{base}/hunts/H1.md?scope=14d&hunt_id=42", headers=auth_headers)).status_code == 400

    async def test_failed_draft_reads_back_with_its_reason(
        self, db_session, client, auth_headers, test_feed, monkeypatch
    ):
        actor = await _seed_actor(db_session, test_feed, name="Fail Crew")
        await _ensure_task(db_session)
        _stub_queue(monkeypatch)
        target = hp.pack_target_id("threat_actor", str(actor.id), "all", "kql")
        await hp.set_draft_state(target, "failed", error="The model took more than ten minutes.")
        body = (await client.get(f"/api/hunt-packs/threat_actor/{actor.id}", headers=auth_headers)).json()
        assert body["status"] == "failed" and body["error"] == "The model took more than ten minutes."
        await hp.clear_draft_state(target)

    async def test_language_comes_from_the_user_setting(
        self, db_session, client, auth_headers, test_feed, test_user, monkeypatch
    ):
        actor = await _seed_actor(db_session, test_feed, name="Spl Crew")
        await _ensure_task(db_session)
        sent = _stub_queue(monkeypatch)
        test_user.settings = {**(test_user.settings or {}), "query_language": "spl"}
        await db_session.commit()

        resp = await client.post(f"/api/hunt-packs/threat_actor/{actor.id}", headers=auth_headers)
        assert resp.status_code == 202, resp.text
        assert resp.json()["language"] == "spl"
        assert sent[0]["kwargs"]["lang"] == "spl"
        await hp.clear_draft_state(hp.pack_target_id("threat_actor", str(actor.id), "all", "spl"))

        resp = await client.get(f"/api/hunt-packs/threat_actor/{actor.id}?language=cobol", headers=auth_headers)
        assert resp.status_code == 400

    async def test_unsupported_types_and_scopes_are_refused(self, client, auth_headers):
        assert (await client.get("/api/hunt-packs/story/some-slug", headers=auth_headers)).status_code == 400
        assert (
            await client.get("/api/hunt-packs/vendor/" + str(uuid.uuid4()), headers=auth_headers)
        ).status_code == 400
        resp = await client.get(f"/api/hunt-packs/threat_actor/{uuid.uuid4()}?scope=90d", headers=auth_headers)
        assert resp.status_code == 400
        resp = await client.get(f"/api/hunt-packs/threat_actor/{uuid.uuid4()}", headers=auth_headers)
        assert resp.status_code == 404

    async def test_a_stopped_engine_refuses_the_draft_instead_of_queueing_it(
        self, db_session, client, auth_headers, test_feed, monkeypatch
    ):
        from app.services import engine_switch

        actor = await _seed_actor(db_session, test_feed, name="Stopped Crew")
        await _ensure_task(db_session)
        sent = _stub_queue(monkeypatch)

        async def stopped(**_kw):
            return True

        monkeypatch.setattr(engine_switch, "is_stopped_async", stopped)
        resp = await client.post(f"/api/hunt-packs/threat_actor/{actor.id}", headers=auth_headers)
        assert resp.status_code == 409, resp.text
        assert resp.json()["error"]["code"] == "engine_stopped"
        assert sent == []
        assert (await client.get(f"/api/hunt-packs/threat_actor/{actor.id}", headers=auth_headers)).json()[
            "status"
        ] == "none"

    async def test_no_provider_is_422_and_no_evidence_is_409(
        self, db_session, client, auth_headers, test_feed, monkeypatch
    ):
        actor = await _seed_actor(db_session, test_feed, name="Unassigned Crew")
        await _ensure_task(db_session)

        async def nobody(*_a, **_kw):
            return None

        monkeypatch.setattr(hp.ai_engine, "resolve_assignment", nobody)
        resp = await client.post(f"/api/hunt-packs/threat_actor/{actor.id}", headers=auth_headers)
        assert resp.status_code == 422, resp.text

        _stub_queue(monkeypatch)
        quiet = await _seed_actor(db_session, test_feed, name="Silent Crew", entries=0, technique=False)
        resp = await client.post(f"/api/hunt-packs/threat_actor/{quiet.id}", headers=auth_headers)
        assert resp.status_code == 409, resp.text


@pytest.mark.asyncio
class TestProfilePack:
    async def test_profile_inputs_rank_claimed_techniques_and_drop_bookkeeping_quotes(
        self, db_session, test_feed, test_user, monkeypatch
    ):
        from app.models.entity_relationship import EntityRelationship

        actor = await _seed_actor(db_session, test_feed, name="Profile Crew")
        other = TTP(technique_id="T1486", technique_name="Data Encrypted for Impact", tactic="impact")
        db_session.add(other)
        await db_session.flush()
        entries = (
            (
                await db_session.execute(
                    select(EntryThreatActor.entry_id).where(EntryThreatActor.threat_actor_id == actor.id)
                )
            )
            .scalars()
            .all()
        )
        db_session.add(EntryTTP(entry_id=entries[0], ttp_id=other.id, source_text="reclassified from clickfix"))
        db_session.add(
            EntityRelationship(
                source_type="threat_actor",
                source_id=actor.id,
                target_type="ttp",
                target_id=other.id,
                relationship_type="uses",
                confidence="confirmed",
            )
        )
        await db_session.commit()
        await _ensure_task(db_session)
        calls = _stub_run_task(monkeypatch, db_session, CANNED)

        pack = await hp.generate_hunt_pack(db_session, test_user.id, "threat_actor", str(actor.id), "all", "kql")
        assert pack is not None and pack["window"] == "all"
        v = calls[0]["variables"]
        assert v["scope"] == "profile" and v["max_hypotheses"] == 5
        ids = [b["technique_id"] for b in v["behaviours"]]
        assert ids[0] == "T1486", "a claimed technique outranks one only mentioned"
        claimed = v["behaviours"][0]
        assert claimed["claimed"] is True and claimed["rule_status"] == "no_rule"
        assert claimed["quotes"] == [], "bookkeeping notes never reach the prompt as evidence"
        assert all("reclassified" not in q for e in v["entries"] for q in e["quotes"])

    async def test_hunt_package_zip(self, db_session, client, auth_headers, test_feed, test_user, monkeypatch):
        import io
        import zipfile

        actor = await _seed_actor(db_session, test_feed, name="Zip Crew")
        await _ensure_task(db_session)
        _stub_run_task(monkeypatch, db_session, CANNED)
        await hp.generate_hunt_pack(db_session, test_user.id, "threat_actor", str(actor.id), "all", "kql")

        resp = await client.get(f"/api/hunt-packs/threat_actor/{actor.id}/package.zip", headers=auth_headers)
        assert resp.status_code == 200, resp.text
        assert "zip-crew-hunt-package.zip" in resp.headers["content-disposition"]
        names = zipfile.ZipFile(io.BytesIO(resp.content)).namelist()
        root = "zip-crew-hunt-package/"
        assert root + "README.md" in names
        assert root + "entities.md" in names and root + "timeline.csv" in names
        hunts = sorted(n for n in names if n.startswith(root + "hunts/"))
        assert len(hunts) == 2
        assert any(h.endswith("H-XXXX-zip-crew-help-desk-reset-followed-by-mfa-enrollment.md") for h in hunts)
        assert sorted(n for n in names if n.startswith(root + "queries/"))[0].endswith(".kql")
        assert root + "telemetry.md" in names
        readme = zipfile.ZipFile(io.BytesIO(resp.content)).read(root + "README.md").decode()
        assert "2 ATHF hunt files" in readme
