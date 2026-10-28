"""send_email automation action: recipients, rendering, batch digest, SMTP config."""

from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.automation import _mask_secrets_in_actions
from app.automation.actions import execute_action, execute_actions_batch
from app.core.security import create_access_token, hash_password
from app.models.automation_rule import AutomationRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.system_setting import SystemSettings
from app.models.user import User
from app.models.webhook_preset import WebhookPreset
from app.services.mailer import MAX_RECIPIENTS, NOT_CONFIGURED, parse_recipients
from app.services.system_settings import invalidate_cache, update_settings

SMTP = {
    "smtp_host": "mail.example.com",
    "smtp_port": 587,
    "smtp_username": "intelfeed",
    "smtp_password": "hunter2",
    "smtp_from_address": "IntelFeed <alerts@example.com>",
}


class _FakeRedis:
    """Just the counter calls the hourly limit makes. The real Redis is the
    dev stack's, and its per-hour key would count these sends against dev."""

    def __init__(self, fail: bool = False):
        self.counts: dict[str, int] = {}
        self.fail = fail

    async def incr(self, key):
        if self.fail:
            raise ConnectionError("redis down")
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def decr(self, key):
        self.counts[key] -= 1
        return self.counts[key]

    async def expire(self, key, seconds):
        return True


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    fake = _FakeRedis()

    async def get_fake():
        return fake

    monkeypatch.setattr("app.services.mailer._counter_redis", get_fake)
    return fake


@pytest_asyncio.fixture(autouse=True)
async def _settings_row(db_session: AsyncSession):
    # create_all skips the data migration that seeds the singleton row
    db_session.add(SystemSettings(id=1, settings={}, secrets={}))
    await db_session.flush()
    invalidate_cache()
    yield
    invalidate_cache()


@pytest_asyncio.fixture
async def smtp_configured(db_session: AsyncSession):
    await update_settings(db_session, SMTP)


@pytest_asyncio.fixture
async def feed(db_session: AsyncSession) -> Feed:
    f = Feed(title="Security News", url="https://example.com/email-feed", feed_type="rss")
    db_session.add(f)
    await db_session.flush()
    return f


async def _entry(db: AsyncSession, feed: Feed, n: int, title: str | None = None) -> Entry:
    e = Entry(
        feed_id=feed.id,
        title=title or f"Advisory {n}",
        guid=f"email-entry-{n}",
        summary=f"Summary of advisory {n}",
        url=f"https://example.com/advisory/{n}",
    )
    db.add(e)
    await db.flush()
    return e


def _sent(mock: AsyncMock):
    """The EmailMessage each aiosmtplib.send call carried."""
    return [c.args[0] for c in mock.await_args_list]


def test_parse_recipients_splits_validates_and_dedupes():
    valid, invalid = parse_recipients("a@example.com; Jane <jane@example.com>, A@example.com, not-an-address")
    assert valid == ["a@example.com", "Jane <jane@example.com>"]
    assert invalid == ["not-an-address"]
    assert parse_recipients(["x@example.com", "y@example.com"]) == (["x@example.com", "y@example.com"], [])
    assert parse_recipients(None) == ([], [])


@pytest.mark.asyncio
async def test_send_email_per_entry(db_session: AsyncSession, smtp_configured, feed: Feed, test_user: User):
    entry = await _entry(db_session, feed, 1)
    action = {"type": "send_email", "config": {"to": "soc@example.com", "cc": "lead@example.com"}}
    with patch("app.services.mailer.aiosmtplib.send", new_callable=AsyncMock) as send:
        result = await execute_action(db_session, entry, action, test_user.id)

    assert result["status"] == "success", result
    assert result["recipients"] == 2
    (msg,) = _sent(send)
    assert msg["To"] == "soc@example.com"
    assert msg["Cc"] == "lead@example.com"
    assert msg["From"] == "IntelFeed <alerts@example.com>"
    assert msg["Subject"] == "[IntelFeed] Advisory 1"
    # markdown (the default) sends a plain-text part plus rendered HTML
    assert msg.get_body(("plain",)).get_content().startswith("## Advisory 1")
    assert "<h2" in msg.get_body(("html",)).get_content()
    kwargs = send.await_args.kwargs
    assert kwargs["hostname"] == "mail.example.com"
    assert kwargs["password"] == "hunter2"
    assert kwargs["start_tls"] is True


@pytest.mark.asyncio
async def test_html_body_escapes_entry_values_and_subject_is_one_line(
    db_session: AsyncSession, smtp_configured, feed: Feed, test_user: User
):
    entry = await _entry(db_session, feed, 2, title="Bad <script>x</script>\nBcc: evil@example.com")
    action = {
        "type": "send_email",
        "config": {"to": "soc@example.com", "body_format": "html", "body_template": "<p>{title}</p>"},
    }
    with patch("app.services.mailer.aiosmtplib.send", new_callable=AsyncMock) as send:
        result = await execute_action(db_session, entry, action, test_user.id)

    assert result["status"] == "success", result
    (msg,) = _sent(send)
    html_part = msg.get_body(("html",)).get_content()
    assert "<script>" not in html_part
    assert "&lt;script&gt;" in html_part
    assert "\n" not in msg["Subject"]
    assert msg["Bcc"] is None


@pytest.mark.asyncio
async def test_not_configured_errors_and_the_rule_keeps_going(db_session: AsyncSession, feed: Feed, test_user: User):
    from app.automation.engine import execute_automation

    entry = await _entry(db_session, feed, 3)
    rule = AutomationRule(
        created_by=test_user.id,
        name="Email then tag",
        trigger_type="on_new_entry",
        conditions={},
        actions=[
            {"type": "send_email", "config": {"to": "soc@example.com"}},
            {"type": "add_tags", "config": {"tags": ["emailed"]}},
        ],
    )
    db_session.add(rule)
    await db_session.flush()

    with patch("app.services.mailer.aiosmtplib.send", new_callable=AsyncMock) as send:
        log = await execute_automation(db_session, entry, rule)

    send.assert_not_awaited()
    email, tag = log.actions_executed
    assert email == {"type": "send_email", "status": "error", "message": NOT_CONFIGURED}
    assert tag["type"] == "add_tags" and tag["status"] == "success"


@pytest.mark.asyncio
async def test_recipient_problems_are_refused_before_sending(
    db_session: AsyncSession, smtp_configured, feed: Feed, test_user: User
):
    entry = await _entry(db_session, feed, 4)
    too_many = ", ".join(f"r{i}@example.com" for i in range(MAX_RECIPIENTS + 1))
    cases = [
        ({}, "No recipients"),
        ({"to": "soc@example.com, nope"}, "Not a valid email address: nope"),
        ({"to": too_many}, "Too many recipients"),
        ({"to": "soc@example.com", "body_format": "pdf"}, "Unknown body_format"),
    ]
    with patch("app.services.mailer.aiosmtplib.send", new_callable=AsyncMock) as send:
        for config, expected in cases:
            result = await execute_action(db_session, entry, {"type": "send_email", "config": config}, test_user.id)
            assert result["status"] == "error"
            assert expected in result["message"]
    send.assert_not_awaited()


@pytest.mark.asyncio
async def test_batch_sends_one_digest(db_session: AsyncSession, smtp_configured, feed: Feed, test_user: User):
    entries = [await _entry(db_session, feed, n) for n in range(10, 13)]
    actions = [{"type": "send_email", "config": {"to": "soc@example.com", "body_format": "text"}}]
    with patch("app.services.mailer.aiosmtplib.send", new_callable=AsyncMock) as send:
        (result,) = await execute_actions_batch(db_session, entries, actions, test_user.id)

    assert result["status"] == "success", result
    assert result["entries_included"] == 3
    (msg,) = _sent(send)
    assert msg["Subject"] == "IntelFeed digest: 3 entries"
    body = msg.get_body(("plain",)).get_content()
    for n in range(10, 13):
        assert f"Advisory {n}" in body
    assert msg.get_body(("html",)) is None


@pytest.mark.asyncio
async def test_batch_uses_ai_summary(db_session: AsyncSession, smtp_configured, feed: Feed, test_user: User):
    entries = [await _entry(db_session, feed, n) for n in range(20, 22)]
    from app.automation import actions as actions_mod

    async def fake_ai(db, entries, config, user_id, batch_context):
        batch_context["ai_summary"] = "# Morning briefing\n\nTwo things happened."
        return {"status": "success"}

    rule_actions = [
        {"type": "run_ai_task", "config": {"task_id": "briefing"}},
        {"type": "send_email", "config": {"to": "soc@example.com"}},
    ]
    with (
        patch.object(actions_mod, "_action_run_ai_task_batch", fake_ai),
        patch("app.services.mailer.aiosmtplib.send", new_callable=AsyncMock) as send,
    ):
        results = await execute_actions_batch(db_session, entries, rule_actions, test_user.id)

    assert results[1]["status"] == "success", results
    assert results[1]["has_ai_summary"] is True
    (msg,) = _sent(send)
    assert msg.get_body(("plain",)).get_content().startswith("# Morning briefing")
    assert "<h1" in msg.get_body(("html",)).get_content()


def test_recipients_are_masked_for_non_owners():
    masked = _mask_secrets_in_actions(
        [
            {"type": "send_email", "config": {"to": "soc@example.com", "cc": "", "subject_template": "{title}"}},
            {
                "type": "branch",
                "config": {"then_actions": [{"type": "send_email", "config": {"to": "x@example.com"}}]},
            },
        ]
    )
    assert masked[0]["config"] == {"to": "<REDACTED>", "cc": "", "subject_template": "{title}"}
    assert masked[1]["config"]["then_actions"][0]["config"]["to"] == "<REDACTED>"


@pytest.mark.asyncio
async def test_test_email_endpoint(client: AsyncClient, admin_headers: dict, auth_headers: dict, db_session):
    r = await client.post("/api/system-settings/email/test", json={"to": "me@example.com"}, headers=admin_headers)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "email_not_configured"

    await update_settings(db_session, SMTP)
    with patch("app.services.mailer.aiosmtplib.send", new_callable=AsyncMock) as send:
        r = await client.post("/api/system-settings/email/test", json={"to": "me@example.com"}, headers=admin_headers)
        assert r.status_code == 200, r.text
        send.assert_awaited_once()

        r = await client.post("/api/system-settings/email/test", json={"to": "me@example.com"}, headers=auth_headers)
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_html_body_renders_the_ai_summary_instead_of_escaping_it(
    db_session: AsyncSession, smtp_configured, feed: Feed, test_user: User
):
    entry = await _entry(db_session, feed, 30)
    action = {
        "type": "send_email",
        "config": {"to": "soc@example.com", "body_format": "html", "body_template": "<div>{ai_summary}</div>"},
    }
    ctx = {"ai_summary": "Two **critical** bugs <script>x</script>"}
    with patch("app.services.mailer.aiosmtplib.send", new_callable=AsyncMock) as send:
        result = await execute_action(db_session, entry, action, test_user.id, context=ctx)

    assert result["status"] == "success", result
    html_part = _sent(send)[0].get_body(("html",)).get_content()
    assert "<strong>critical</strong>" in html_part
    assert "**" not in html_part
    assert "<script>" not in html_part  # rendered through the sanitizer


@pytest.mark.asyncio
async def test_entry_count_variable(db_session: AsyncSession, smtp_configured, feed: Feed, test_user: User):
    entries = [await _entry(db_session, feed, n) for n in range(40, 44)]
    batch = [{"type": "send_email", "config": {"to": "soc@example.com", "subject_template": "{entry_count} new"}}]
    with patch("app.services.mailer.aiosmtplib.send", new_callable=AsyncMock) as send:
        await execute_actions_batch(db_session, entries, batch, test_user.id)
        await execute_action(db_session, entries[0], batch[0], test_user.id)
    assert [m["Subject"] for m in _sent(send)] == ["4 new", "1 new"]


@pytest.mark.asyncio
async def test_hourly_limit_stops_sending(db_session: AsyncSession, feed: Feed, test_user: User, fake_redis):
    await update_settings(db_session, {**SMTP, "smtp_max_per_hour": 2})
    entry = await _entry(db_session, feed, 50)
    action = {"type": "send_email", "config": {"to": "soc@example.com"}}
    with patch("app.services.mailer.aiosmtplib.send", new_callable=AsyncMock) as send:
        results = [await execute_action(db_session, entry, action, test_user.id) for _ in range(3)]

    assert [r["status"] for r in results] == ["success", "success", "error"]
    assert "Hourly email limit reached (2 per hour" in results[2]["message"]
    assert send.await_count == 2
    # A refused send doesn't use up the budget
    assert list(fake_redis.counts.values()) == [2]


@pytest.mark.asyncio
async def test_hourly_limit_sends_when_redis_is_down(db_session: AsyncSession, feed: Feed, test_user: User, fake_redis):
    fake_redis.fail = True
    await update_settings(db_session, {**SMTP, "smtp_max_per_hour": 1})
    entry = await _entry(db_session, feed, 51)
    action = {"type": "send_email", "config": {"to": "soc@example.com"}}
    with patch("app.services.mailer.aiosmtplib.send", new_callable=AsyncMock) as send:
        for _ in range(2):
            assert (await execute_action(db_session, entry, action, test_user.id))["status"] == "success"
    assert send.await_count == 2


@pytest.mark.asyncio
async def test_test_email_failure_is_a_400_with_the_reason(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    import aiosmtplib

    await update_settings(db_session, SMTP)
    with patch(
        "app.services.mailer.aiosmtplib.send",
        new_callable=AsyncMock,
        side_effect=aiosmtplib.SMTPAuthenticationError(535, "bad credentials"),
    ):
        r = await client.post("/api/system-settings/email/test", json={"to": "me@example.com"}, headers=admin_headers)
    assert r.status_code == 400
    assert r.json()["error"]["message"] == "SMTP login failed: bad credentials"


@pytest.mark.asyncio
async def test_presets_hide_destinations_from_other_users(
    client: AsyncClient, db_session: AsyncSession, test_user: User, auth_headers: dict, admin_headers: dict
):
    db_session.add_all(
        [
            WebhookPreset(
                created_by=test_user.id,
                name="SOC mail",
                preset_type="email",
                config={"to": "soc@example.com", "cc": "", "subject_template": "{title}"},
            ),
            WebhookPreset(
                created_by=test_user.id,
                name="SOC Slack",
                preset_type="notification",
                url="https://hooks.slack.com/services/T0/B0/secret",
                headers={"Authorization": "Bearer x"},
            ),
        ]
    )
    other = User(username="otheruser", password_hash=hash_password("otherpassword"), role="user")
    db_session.add(other)
    await db_session.flush()
    other_headers = {"Authorization": f"Bearer {create_access_token(other.id, other.role)}"}

    def by_name(resp):
        assert resp.status_code == 200, resp.text
        return {p["name"]: p for p in resp.json()["items"]}

    mine = by_name(await client.get("/api/webhook-presets", headers=auth_headers))
    assert mine["SOC mail"]["config"]["to"] == "soc@example.com"
    assert mine["SOC Slack"]["url"].endswith("/secret")

    admin = by_name(await client.get("/api/webhook-presets", headers=admin_headers))
    assert admin["SOC mail"]["config"]["to"] == "soc@example.com"

    theirs = by_name(await client.get("/api/webhook-presets", headers=other_headers))
    assert theirs["SOC mail"]["config"] == {"to": "<REDACTED>", "cc": "", "subject_template": "{title}"}
    assert theirs["SOC Slack"]["url"] == "<REDACTED>"
    assert theirs["SOC Slack"]["headers"] == {"Authorization": "<REDACTED>"}

    one = await client.get(f"/api/webhook-presets/{theirs['SOC mail']['id']}", headers=other_headers)
    assert one.json()["config"]["to"] == "<REDACTED>"


@pytest.mark.asyncio
async def test_import_warns_about_redacted_fields(client: AsyncClient, auth_headers: dict):
    payload = {
        "intelfeed_rule_export": {"version": 1, "exported_at": "2026-10-27T00:00:00Z"},
        "rules": [
            {
                "name": "Mail the SOC",
                "trigger_type": "on_new_entry",
                "actions": [
                    {"type": "send_email", "config": {"to": "<REDACTED>", "subject_template": "{title}"}},
                    {"type": "run_webhook", "config": {"url": "https://example.com", "headers": {"X": "<REDACTED>"}}},
                ],
            }
        ],
    }
    r = await client.post("/api/automation/rules/import", json=payload, headers=auth_headers)
    assert r.status_code == 200, r.text
    warnings = r.json()["warnings"]
    assert any("'send_email' was exported without secrets (to redacted)" in w for w in warnings), warnings
    assert any("'run_webhook' was exported without secrets (headers redacted)" in w for w in warnings), warnings


@pytest.mark.asyncio
async def test_unencrypted_connection_is_refused(db_session: AsyncSession, feed: Feed, test_user: User, fake_redis):
    # The settings UI only offers starttls/tls, but an old row or SMTP_SECURITY=none can still say "none"
    await update_settings(db_session, {**SMTP, "smtp_security": "none"})
    entry = await _entry(db_session, feed, 60)
    action = {"type": "send_email", "config": {"to": "soc@example.com"}}
    with patch("app.services.mailer.aiosmtplib.send", new_callable=AsyncMock) as send:
        result = await execute_action(db_session, entry, action, test_user.id)

    assert result["status"] == "error"
    assert "Connection Security 'none' isn't supported" in result["message"]
    send.assert_not_awaited()
    # Refused before the hourly budget is touched
    assert fake_redis.counts == {}
