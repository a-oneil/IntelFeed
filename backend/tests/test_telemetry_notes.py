"""Notes and saved links per telemetry source (/api/telemetry-sources/notes)."""

import json

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.telemetry_notes import name_matches
from app.models.telemetry_source import TelemetrySource
from app.models.user import User

GUARDDUTY_URL = "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html"


async def _post(client: AsyncClient, headers: dict, **body) -> dict:
    resp = await client.post("/api/telemetry-sources/notes", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_link_on_a_catalog_source_nobody_enabled(client: AsyncClient, auth_headers: dict):
    note = await _post(
        client,
        auth_headers,
        source_name="aws guardduty",
        url=GUARDDUTY_URL,
        page_title="GuardDuty active finding types",
        quote="  Runtime Monitoring needs the agent.  ",
        content="EKS has the agent; EC2 does not.",
    )
    # Stored under the catalog's own spelling, trimmed.
    assert note["source_name"] == "AWS GuardDuty"
    assert note["quote"] == "Runtime Monitoring needs the agent."
    assert note["username"]

    listed = await client.get("/api/telemetry-sources/notes", params={"source": "AWS GuardDuty"}, headers=auth_headers)
    assert listed.status_code == 200
    assert [n["id"] for n in listed.json()["items"]] == [note["id"]]

    counts = await client.get("/api/telemetry-sources/notes/counts", headers=auth_headers)
    assert counts.json() == {"AWS GuardDuty": 1}


@pytest.mark.asyncio
async def test_rejects_unknown_source_empty_note_and_odd_scheme(client: AsyncClient, auth_headers: dict):
    url = "/api/telemetry-sources/notes"
    resp = await client.post(url, json={"source_name": "Nope Sensor", "content": "x"}, headers=auth_headers)
    assert resp.status_code == 422
    resp = await client.post(url, json={"source_name": "AWS GuardDuty", "content": "   "}, headers=auth_headers)
    assert resp.status_code == 422
    resp = await client.post(
        url, json={"source_name": "AWS GuardDuty", "url": "javascript:alert(1)"}, headers=auth_headers
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_custom_inventory_source_and_rename_carries_notes(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_user: User
):
    source = TelemetrySource(created_by=test_user.id, name="Homegrown Proxy", category="web_proxy")
    db_session.add(source)
    await db_session.flush()
    await _post(client, auth_headers, source_name="Homegrown Proxy", content="Logs land in the lake hourly.")

    resp = await client.put(f"/api/telemetry-sources/{source.id}", json={"name": "Squid Proxy"}, headers=auth_headers)
    assert resp.status_code == 200
    moved = await client.get("/api/telemetry-sources/notes", params={"source": "Squid Proxy"}, headers=auth_headers)
    assert moved.json()["total"] == 1
    old = await client.get("/api/telemetry-sources/notes", params={"source": "Homegrown Proxy"}, headers=auth_headers)
    assert old.json()["total"] == 0


@pytest.mark.asyncio
async def test_only_author_or_admin_edits(
    client: AsyncClient, auth_headers: dict, admin_headers: dict, db_session: AsyncSession
):
    from app.core.security import create_access_token, hash_password

    other = User(username="other", password_hash=hash_password("pw-123456"), role="user")
    db_session.add(other)
    await db_session.flush()
    other_headers = {"Authorization": f"Bearer {create_access_token(other.id, other.role)}"}

    note = await _post(client, auth_headers, source_name="AWS GuardDuty", content="first")
    path = f"/api/telemetry-sources/notes/{note['id']}"

    assert (await client.put(path, json={"content": "hijack"}, headers=other_headers)).status_code == 403
    assert (await client.delete(path, headers=other_headers)).status_code == 403

    edited = await client.put(path, json={"content": "second", "url": GUARDDUTY_URL}, headers=auth_headers)
    assert edited.status_code == 200
    assert edited.json()["content"] == "second"
    # Clearing the text is fine while the link stays.
    assert (await client.put(path, json={"content": ""}, headers=auth_headers)).json()["content"] is None
    # Clearing both is not.
    assert (await client.put(path, json={"url": ""}, headers=auth_headers)).status_code == 422

    assert (await client.delete(path, headers=admin_headers)).status_code == 204


def test_name_matches_finds_the_product_in_the_address():
    names = [item["name"] for _, item in name_matches(GUARDDUTY_URL, "Active finding types - Amazon GuardDuty")]
    assert names[0] == "AWS GuardDuty"


def test_name_matches_ignores_short_generic_products():
    # A three-letter word like "dns" never matches a product on its own.
    for _, item in name_matches("https://example.com/blog/dns", ""):
        assert "dns" != "".join(c for c in (item.get("product") or "").lower() if c.isalnum())


@pytest.mark.asyncio
async def test_suggest_prefers_sources_saved_from_the_same_docs_section(client: AsyncClient, auth_headers: dict):
    # A page under /guardduty/ whose title names nothing: learned from the earlier save.
    await _post(client, auth_headers, source_name="AWS GuardDuty", url=GUARDDUTY_URL)
    resp = await client.get(
        "/api/telemetry-sources/notes/suggest",
        params={"url": "https://docs.aws.amazon.com/guardduty/latest/ug/what-is.html", "title": "What is it?"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    first = resp.json()[0]
    assert first["name"] == "AWS GuardDuty"
    assert first["reason"] == "saved_before"


@pytest.mark.asyncio
async def test_rule_detail_names_the_sources_answering_its_telemetry(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_user: User
):
    from app.models.detection_rule import DetectionRule

    db_session.add(
        TelemetrySource(
            created_by=test_user.id,
            name="AWS GuardDuty",
            category="cloud",
            vendor="Amazon",
            product="GuardDuty",
            log_types=["malware_finding"],
        )
    )
    rule = DetectionRule(
        rule_type="splunk_spl",
        title="GuardDuty malware findings",
        rule_content="index=aws sourcetype=guardduty",
        data_sources=["GuardDuty", "process_creation"],
    )
    db_session.add(rule)
    await db_session.flush()
    await _post(client, auth_headers, source_name="AWS GuardDuty", content="Findings arrive within 5 minutes.")

    resp = await client.get(f"/api/detection-rules/{rule.id}", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    telemetry = resp.json()["telemetry"]
    assert telemetry["collected"] == ["GuardDuty"]
    assert telemetry["sources"] == [{"name": "AWS GuardDuty", "provides": ["GuardDuty"], "note_count": 1}]


@pytest.mark.asyncio
async def test_prompt_notes_cover_enabled_sources_with_text_only(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_user: User
):
    from app.ai.engine import render_prompt
    from app.ai.prompts.defaults import SYSTEM_TASKS
    from app.intelligence.telemetry_context import NOTE_CHARS_PER_SOURCE, get_telemetry_notes_for_prompt

    db_session.add(TelemetrySource(created_by=test_user.id, name="AWS GuardDuty", category="cloud"))
    await db_session.flush()
    await _post(client, auth_headers, source_name="AWS GuardDuty", url=GUARDDUTY_URL)  # bare link: left out
    await _post(
        client, auth_headers, source_name="AWS GuardDuty", content="EC2 fleet has no agent.", quote="Needs agent"
    )
    await _post(client, auth_headers, source_name="AWS GuardDuty", content="x" * 2000)
    # Not enabled anywhere: left out.
    await _post(client, auth_headers, source_name="AWS CloudTrail", content="We keep 90 days.")

    notes = await get_telemetry_notes_for_prompt(db_session)
    assert [n["source"] for n in notes] == ["AWS GuardDuty"]
    texts = notes[0]["notes"]
    assert sum(len(t) for t in texts) <= NOTE_CHARS_PER_SOURCE
    assert any('EC2 fleet has no agent. (quoting the docs: "Needs agent")' == t for t in texts)

    task = next(t for t in SYSTEM_TASKS if t["name"] == "threat_assessment")
    rendered = render_prompt(
        task["default_prompt_template"],
        {"entry": {"title": "t", "content_text": "c", "feed_title": "f"}, "telemetry_notes": notes},
    )
    assert "Analysts' notes on these telemetry sources" in rendered
    assert "- AWS GuardDuty: " in rendered


@pytest.mark.asyncio
async def test_sources_answering_names_products_not_whole_categories(db_session: AsyncSession, test_user: User):
    from app.services.detection_coverage import sources_answering

    for name, category, product, log_types in [
        ("AWS CloudTrail", "cloud", "CloudTrail", ["management_events", "s3_data_events"]),
        ("AWS Config", "cloud", "Config", ["configuration_change"]),
        ("CrowdStrike Falcon", "endpoint_edr", "Falcon", ["process_creation", "network_connection", "file_write"]),
        ("Cisco Umbrella", "dns_security", "Umbrella", ["dns_query"]),
    ]:
        db_session.add(
            TelemetrySource(created_by=test_user.id, name=name, category=category, product=product, log_types=log_types)
        )
    await db_session.flush()

    async def names(*tokens):
        return [s["name"] for s in await sources_answering(db_session, list(tokens))]

    # Named by its product, not every cloud source.
    assert await names("logs-aws.cloudtrail-*") == ["AWS CloudTrail"]
    # Named by behaviour: the EDR gives process creation, the DNS product does not.
    assert await names("process_creation") == ["CrowdStrike Falcon"]
    # A catch-all channel names nothing in particular.
    assert await names("SecurityEvents") == []


@pytest.mark.asyncio
async def test_list_every_source_with_search(client: AsyncClient, auth_headers: dict):
    await _post(client, auth_headers, source_name="AWS GuardDuty", content="EC2 fleet has no agent")
    await _post(client, auth_headers, source_name="AWS CloudTrail", content="Data events are off")
    url = "/api/telemetry-sources/notes"
    everything = (await client.get(url, headers=auth_headers)).json()
    assert everything["total"] == 2
    found = (await client.get(url, params={"q": "cloudtrail"}, headers=auth_headers)).json()
    assert [n["source_name"] for n in found["items"]] == ["AWS CloudTrail"]
    found = (await client.get(url, params={"q": "agent"}, headers=auth_headers)).json()
    assert [n["source_name"] for n in found["items"]] == ["AWS GuardDuty"]


@pytest.mark.asyncio
async def test_rename_keeps_catalog_notes_and_notes_another_row_uses(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_user: User
):
    from_catalog = TelemetrySource(created_by=test_user.id, name="AWS GuardDuty", category="cloud")
    first = TelemetrySource(created_by=test_user.id, name="Homegrown Proxy", category="web_proxy")
    second = TelemetrySource(created_by=test_user.id, name="Homegrown Proxy", category="web_proxy")
    db_session.add_all([from_catalog, first, second])
    await db_session.flush()
    await _post(client, auth_headers, source_name="AWS GuardDuty", content="EC2 fleet has no agent.")
    await _post(client, auth_headers, source_name="Homegrown Proxy", content="Logs land in the lake hourly.")

    url = "/api/telemetry-sources"
    assert (
        await client.put(f"{url}/{from_catalog.id}", json={"name": "GuardDuty (prod)"}, headers=auth_headers)
    ).status_code == 200
    assert (
        await client.put(f"{url}/{first.id}", json={"name": "Squid Proxy"}, headers=auth_headers)
    ).status_code == 200

    counts = (await client.get(f"{url}/notes/counts", headers=auth_headers)).json()
    assert counts == {"AWS GuardDuty": 1, "Homegrown Proxy": 1}


@pytest.mark.asyncio
async def test_put_rejects_a_link_that_is_not_http(client: AsyncClient, auth_headers: dict):
    note = await _post(client, auth_headers, source_name="AWS GuardDuty", content="first")
    path = f"/api/telemetry-sources/notes/{note['id']}"
    resp = await client.put(path, json={"url": "ftp://example.com/doc"}, headers=auth_headers)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_url"


@pytest.mark.asyncio
async def test_prompt_notes_match_source_names_ignoring_case(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_user: User
):
    from app.intelligence.telemetry_context import get_telemetry_notes_for_prompt

    # The inventory row is spelled differently from the catalog name the note is saved under.
    db_session.add(TelemetrySource(created_by=test_user.id, name="aws guardduty", category="cloud"))
    await db_session.flush()
    await _post(client, auth_headers, source_name="AWS GuardDuty", content="EC2 fleet has no agent.")

    notes = await get_telemetry_notes_for_prompt(db_session)
    assert notes == [{"source": "AWS GuardDuty", "notes": ["EC2 fleet has no agent."]}]


@pytest.mark.asyncio
async def test_note_tools(db_session: AsyncSession, test_user: User):
    from app.tools import execute_tool

    async def run(name, **args):
        return json.loads(await execute_tool(name, args, db_session, test_user.id))

    saved = await run("add_telemetry_source_note", source_name="aws guardduty", content="EC2 fleet has no agent.")
    assert saved["saved"] is True
    assert saved["source_name"] == "AWS GuardDuty"

    assert (
        "No telemetry source named"
        in (await run("add_telemetry_source_note", source_name="Nope", content="x"))["error"]
    )
    assert (await run("add_telemetry_source_note", source_name="AWS GuardDuty", content="  "))["error"] == (
        "Add a link, a note, or both."
    )
    too_long = await run(
        "add_telemetry_source_note", source_name="AWS GuardDuty", url=GUARDDUTY_URL, page_title="t" * 501
    )
    assert too_long["error"] == "page_title is longer than 500 characters"

    read = await run("get_telemetry_source_notes", source_name="AWS GUARDDUTY")
    assert read["count"] == 1
    assert read["notes"][0]["content"] == "EC2 fleet has no agent."
