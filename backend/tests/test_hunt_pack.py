"""Hunt packs: hypotheses and queries drafted from a board row's window, and the
ATHF hunt file they export to.

The pack is a starting point, so the tests hold it to that: it is drafted only
from the window, cached per row/window/language, checked against the telemetry
inventory at read time, and exported in the shape ATHF's template defines with
Keep left empty. Nothing about the hunt is stored.
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

    def test_caps_at_three(self):
        many = {"hypotheses": [CANNED["hypotheses"][0]] * 6}
        assert len(hp.normalize_pack(many)) == hp.MAX_HYPOTHESES

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


@pytest.mark.asyncio
class TestApi:
    async def test_none_until_drafted_then_ready_then_exported(
        self, db_session, client, auth_headers, test_feed, test_user, monkeypatch
    ):
        actor = await _seed_actor(db_session, test_feed, name="Api Crew")
        await _ensure_task(db_session)
        _stub_run_task(monkeypatch, db_session, CANNED)
        base = f"/api/threat-board/threat_actor/{actor.id}/hunt-pack"

        resp = await client.get(base, headers=auth_headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "none"
        assert resp.json()["language"] == "kql"

        resp = await client.get(f"{base}.md", headers=auth_headers)
        assert resp.status_code == 404

        resp = await client.post(base, headers=auth_headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "ready"
        assert [h["id"] for h in body["pack"]["hypotheses"]] == ["H1", "H2"]
        assert body["pack"]["hypotheses"][0]["telemetry"][0] == {"source": "auth.account", "have": False}

        resp = await client.get(base, headers=auth_headers)
        assert resp.json()["status"] == "ready"

        resp = await client.get(f"{base}.md", headers=auth_headers)
        assert resp.status_code == 200, resp.text
        assert resp.headers["content-type"].startswith("text/markdown")
        assert resp.headers["content-disposition"] == 'attachment; filename="H-XXXX-api-crew.md"'
        assert resp.text.startswith("---\nhunt_id: H-XXXX\n")

        resp = await client.get(f"{base}.md?hunt_id=H-0007", headers=auth_headers)
        assert resp.status_code == 200, resp.text
        assert resp.headers["content-disposition"] == 'attachment; filename="H-0007-api-crew.md"'
        assert resp.text.startswith("---\nhunt_id: H-0007\n")
        assert (await client.get(f"{base}.md?hunt_id=42", headers=auth_headers)).status_code == 400
        assert f"hunter: {test_user.username}" in resp.text
        assert "Api Crew resets passwords via the help desk, wave 0" in resp.text

    async def test_language_comes_from_the_user_setting(
        self, db_session, client, auth_headers, test_feed, test_user, monkeypatch
    ):
        actor = await _seed_actor(db_session, test_feed, name="Spl Crew")
        await _ensure_task(db_session)
        calls = _stub_run_task(monkeypatch, db_session, CANNED)
        test_user.settings = {**(test_user.settings or {}), "query_language": "spl"}
        await db_session.commit()

        resp = await client.post(f"/api/threat-board/threat_actor/{actor.id}/hunt-pack", headers=auth_headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["language"] == "spl"
        assert calls[0]["variables"]["query_language"] == "spl"

        resp = await client.get(
            f"/api/threat-board/threat_actor/{actor.id}/hunt-pack?language=cobol", headers=auth_headers
        )
        assert resp.status_code == 400

    async def test_story_rows_have_no_pack(self, client, auth_headers):
        resp = await client.get("/api/threat-board/story/some-slug/hunt-pack", headers=auth_headers)
        assert resp.status_code == 400

    async def test_no_provider_is_422_and_no_evidence_is_409(
        self, db_session, client, auth_headers, test_feed, monkeypatch
    ):
        actor = await _seed_actor(db_session, test_feed, name="Unassigned Crew")
        await _ensure_task(db_session)
        _stub_run_task(monkeypatch, db_session, None)
        resp = await client.post(f"/api/threat-board/threat_actor/{actor.id}/hunt-pack", headers=auth_headers)
        assert resp.status_code == 422, resp.text

        quiet = await _seed_actor(db_session, test_feed, name="Silent Crew", entries=0, technique=False)
        resp = await client.post(f"/api/threat-board/threat_actor/{quiet.id}/hunt-pack", headers=auth_headers)
        assert resp.status_code == 409, resp.text
        assert resp.json()["error"]["code"] == "nothing_to_hunt" if "error" in resp.json() else True
