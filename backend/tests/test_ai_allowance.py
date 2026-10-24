"""Who may spend the instance's AI, and how much.

Three gates: a per-person daily allowance on the instance's own providers,
a per-link daily limit on the share page's AI routes, and the outbound URL
check that refuses to point the server at the LAN.
"""

import ipaddress
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import AsyncClient

from app.ai.caller import Caller
from app.config import settings as env_settings
from app.core.exceptions import AppError
from app.models.ai_provider import AIProvider
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment
from app.models.shared_entry import SharedEntry
from app.models.user import User

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def provider(db_session) -> AIProvider:
    row = AIProvider(name="Lab Ollama", provider_type="ollama", base_url="http://ollama.test:11434")
    db_session.add(row)
    await db_session.flush()
    return row


async def _assigned_task(db_session, provider: AIProvider, name: str, template: str = "{{ text }}") -> AITask:
    task = AITask(name=name, display_name=name, default_prompt_template=template)
    db_session.add(task)
    await db_session.flush()
    db_session.add(AITaskAssignment(task_id=task.id, provider_id=provider.id, model_name="qwen"))
    await db_session.flush()
    return task


def _stub_provider(monkeypatch, content='{"answer": "ok"}'):
    import app.ai.engine as engine

    response = MagicMock(content=content, model="qwen", tokens_input=12, tokens_output=4, latency_ms=7, cost_usd=None)
    stub = MagicMock()
    stub.complete = AsyncMock(return_value=response)
    monkeypatch.setattr(engine, "_get_provider_instance", lambda pm, **kw: stub)
    return stub


# ------------------------------------------------------ per-user allowance


async def test_allowance_refuses_a_person_after_the_cap(db_session, test_user: User, provider, monkeypatch):
    from app.ai.engine import SiteAllowanceExceeded, run_task

    task = await _assigned_task(db_session, provider, "allow_cap")
    _stub_provider(monkeypatch)
    monkeypatch.setattr(env_settings, "site_ai_user_daily_requests", 2)

    for i in range(2):
        await run_task(db_session, test_user.id, task.name, variables={"text": str(i)}, force=True)
    with pytest.raises(SiteAllowanceExceeded) as exc:
        await run_task(db_session, test_user.id, task.name, variables={"text": "3"}, force=True)

    assert exc.value.status_code == 429
    assert exc.value.code == "ai_allowance_exceeded"
    assert exc.value.used == 2 and exc.value.cap == 2


async def test_allowance_counts_failed_calls(db_session, test_user: User, provider, monkeypatch):
    import app.ai.engine as engine
    from app.ai.engine import SiteAllowanceExceeded, run_task

    task = await _assigned_task(db_session, provider, "allow_failed")
    broken = MagicMock()
    broken.complete = AsyncMock(side_effect=RuntimeError("down"))
    monkeypatch.setattr(engine, "_get_provider_instance", lambda pm, **kw: broken)
    monkeypatch.setattr(env_settings, "site_ai_user_daily_requests", 1)

    first = await run_task(db_session, test_user.id, task.name, variables={"text": "a"}, force=True)
    assert first["_extraction_status"] == "provider_error"
    # A broken provider is not a free retry loop.
    with pytest.raises(SiteAllowanceExceeded):
        await run_task(db_session, test_user.id, task.name, variables={"text": "b"}, force=True)


async def test_allowance_ignores_background_and_automation(db_session, test_user: User, provider, monkeypatch):
    from app.ai.engine import run_task

    task = await _assigned_task(db_session, provider, "allow_exempt")
    _stub_provider(monkeypatch)
    monkeypatch.setattr(env_settings, "site_ai_user_daily_requests", 1)

    # The pipeline and a rule running as this user are the operator's spend.
    for caller in (Caller.system(), Caller.automation(test_user.id), Caller.share(test_user.id)):
        await run_task(db_session, test_user.id, task.name, variables={"text": caller.kind}, force=True, caller=caller)
    # None of that touched the person's allowance.
    await run_task(db_session, test_user.id, task.name, variables={"text": "mine"}, force=True)


async def test_allowance_zero_means_unlimited(db_session, test_user: User, provider, monkeypatch):
    from app.ai.engine import run_task

    task = await _assigned_task(db_session, provider, "allow_zero")
    _stub_provider(monkeypatch)
    monkeypatch.setattr(env_settings, "site_ai_user_daily_requests", 0)
    for i in range(3):
        await run_task(db_session, test_user.id, task.name, variables={"text": str(i)}, force=True)


async def test_allowance_does_not_charge_a_cached_answer(db_session, test_user: User, provider, monkeypatch):
    from app.ai.engine import run_task

    task = await _assigned_task(db_session, provider, "allow_cached")
    _stub_provider(monkeypatch)
    monkeypatch.setattr(env_settings, "site_ai_user_daily_requests", 1)
    target = uuid.uuid4()

    first = await run_task(
        db_session, test_user.id, task.name, variables={"text": "a"}, target_type="entry", target_id=target
    )
    # Same target, no force: the dedup guard answers before the allowance is checked.
    again = await run_task(
        db_session, test_user.id, task.name, variables={"text": "a"}, target_type="entry", target_id=target
    )
    assert again == first


async def test_allowance_gates_rule_conversion_and_copilot(
    client: AsyncClient, db_session, auth_headers: dict, test_user: User, provider, monkeypatch
):
    from app.models.ai_result import AIResult

    await _assigned_task(db_session, provider, "detection_rules")
    await _assigned_task(db_session, provider, "copilot")
    monkeypatch.setattr(env_settings, "site_ai_user_daily_requests", 1)
    db_session.add(
        AIResult(
            target_type="rule_chat",
            is_current=False,
            task_id=(await _assigned_task(db_session, provider, "x")).id,
            provider_id=provider.id,
            caller_kind="user",
            user_id=test_user.id,
        )
    )
    await db_session.flush()

    chat = await client.post(
        "/api/detection-rules/chat",
        json={"message": "help", "rule_type": "sigma", "history": []},
        headers=auth_headers,
    )
    assert chat.status_code == 429, chat.text
    assert chat.json()["error"]["code"] == "ai_allowance_exceeded"

    copilot = await client.post("/api/ai/copilot/stream", json={"question": "hi"}, headers=auth_headers)
    assert copilot.status_code == 429, copilot.text


# ------------------------------------------------------ share link limit


async def test_share_link_has_its_own_daily_limit(
    client: AsyncClient, db_session, test_user: User, test_entry, provider, monkeypatch
):
    await _assigned_task(db_session, provider, "entry_qa", template="{{ question }}")
    share = SharedEntry(entry_id=test_entry.id, created_by=test_user.id, is_active=True)
    db_session.add(share)
    await db_session.flush()
    _stub_provider(monkeypatch, content="Gen 7 only.")
    monkeypatch.setattr(env_settings, "share_ai_daily_requests", 2)

    first = await client.post(f"/api/shared/{share.token}/ask-agent", json={"question": "one"})
    assert first.status_code == 200, first.text
    assert first.json()["remaining_today"] == 1
    second = await client.post(f"/api/shared/{share.token}/ask-agent", json={"question": "two"})
    assert second.json()["remaining_today"] == 0
    third = await client.post(f"/api/shared/{share.token}/ask-agent", json={"question": "three"})
    assert third.status_code == 429
    assert third.json()["error"]["code"] == "share_limit_exceeded"


async def test_share_tasks_and_questions_share_one_budget(
    client: AsyncClient, db_session, test_user: User, test_entry, provider, monkeypatch
):
    await _assigned_task(db_session, provider, "entry_qa", template="{{ question }}")
    task = await _assigned_task(db_session, provider, "threat_assessment", template="{{ entry.title }}")
    task.category = "analysis"
    share = SharedEntry(entry_id=test_entry.id, created_by=test_user.id, is_active=True)
    db_session.add(share)
    await db_session.flush()
    _stub_provider(monkeypatch, content='{"what": "x"}')
    monkeypatch.setattr(env_settings, "share_ai_daily_requests", 1)

    ran = await client.post(f"/api/shared/{share.token}/run-ai-task", json={"task_name": "threat_assessment"})
    assert ran.status_code == 200, ran.text
    assert ran.json()["remaining_today"] == 0
    asked = await client.post(f"/api/shared/{share.token}/ask-agent", json={"question": "one"})
    assert asked.status_code == 429


async def test_share_limit_does_not_touch_the_sharer_allowance(
    client: AsyncClient, db_session, test_user: User, test_entry, provider, monkeypatch
):
    from app.ai.engine import site_requests_today

    await _assigned_task(db_session, provider, "entry_qa", template="{{ question }}")
    share = SharedEntry(entry_id=test_entry.id, created_by=test_user.id, is_active=True)
    db_session.add(share)
    await db_session.flush()
    _stub_provider(monkeypatch)

    await client.post(f"/api/shared/{share.token}/ask-agent", json={"question": "one"})
    assert await site_requests_today(db_session, test_user.id) == 0


async def test_rate_limiter_covers_the_share_ai_routes():
    from app.core.rate_limit import AI_LIMIT, _get_limit

    assert _get_limit("/api/shared/abc123/ask-agent", "POST") == (*AI_LIMIT, "ai")
    assert _get_limit("/api/shared/abc123/run-ai-task", "POST") == (*AI_LIMIT, "ai")
    assert _get_limit("/api/shared/abc123", "GET") is None


# ------------------------------------------------------ outbound URL check


async def test_outbound_check_refuses_private_literals_and_localhost():
    from app.core.outbound import check_outbound_url

    assert await check_outbound_url("http://10.20.0.2:11434/v1") == "URL points to a private address (10.20.0.2)"
    assert await check_outbound_url("http://169.254.169.254/latest/meta-data") is not None
    assert await check_outbound_url("http://[::1]:8080/") is not None
    assert await check_outbound_url("http://[::ffff:127.0.0.1]/") is not None
    assert await check_outbound_url("http://localhost:11434/") == "URL points to localhost"
    assert await check_outbound_url("ftp://example.com/x") == "Unsupported URL scheme: ftp"
    assert await check_outbound_url("not a url") is not None


async def test_outbound_check_resolves_the_name(monkeypatch):
    import app.core.outbound as outbound

    async def fake_resolve(hostname):
        return {
            "evil.example": [ipaddress.ip_address("93.184.216.34"), ipaddress.ip_address("10.0.0.5")],
            "api.example": [ipaddress.ip_address("93.184.216.34")],
            "gone.example": [],
        }[hostname]

    monkeypatch.setattr(outbound, "resolve_host", fake_resolve)

    assert await outbound.check_outbound_url("https://evil.example/hook") == (
        "evil.example resolves to a private address (10.0.0.5)"
    )
    assert await outbound.check_outbound_url("https://api.example/v1") is None
    assert await outbound.check_outbound_url("https://gone.example/") == "Could not resolve host gone.example"
    # The operator's override skips the address check, never the scheme check.
    assert await outbound.check_outbound_url("https://evil.example/hook", allow_private=True) is None
    assert await outbound.check_outbound_url("gopher://evil.example/", allow_private=True) is not None


async def test_webhook_validator_resolves(monkeypatch):
    import app.core.outbound as outbound
    from app.automation.actions import _validate_webhook_url

    async def fake_resolve(hostname):
        return [ipaddress.ip_address("192.168.1.20")]

    monkeypatch.setattr(outbound, "resolve_host", fake_resolve)
    monkeypatch.setattr(env_settings, "webhook_allow_private_networks", False)
    assert (
        await _validate_webhook_url("https://hooks.example/x")
        == "hooks.example resolves to a private address (192.168.1.20)"
    )
    monkeypatch.setattr(env_settings, "webhook_allow_private_networks", True)
    assert await _validate_webhook_url("https://hooks.example/x") is None


async def test_allowance_error_is_an_app_error():
    from app.ai.engine import SiteAllowanceExceeded

    assert isinstance(SiteAllowanceExceeded(5, 5), AppError)


# ------------------------------------------------- allowance at enqueue


async def test_report_generation_is_refused_before_enqueue(
    client: AsyncClient, db_session, auth_headers: dict, test_user: User, test_entry, provider, monkeypatch
):
    from unittest.mock import patch

    from app.models.ai_result import AIResult

    task = await _assigned_task(db_session, provider, "report_section")
    db_session.add(
        AIResult(
            target_type="intel_report",
            is_current=False,
            task_id=task.id,
            provider_id=provider.id,
            caller_kind="user",
            user_id=test_user.id,
        )
    )
    await db_session.flush()
    monkeypatch.setattr(env_settings, "site_ai_user_daily_requests", 1)

    with patch("app.workers.report_tasks.generate_full_report") as mock_task:
        resp = await client.post(
            "/api/intel-reports/generate-full",
            json={
                "source_type": "entry",
                "entry_id": str(test_entry.id),
                "template_type": "flash_alert",
                "title": "Refused",
                "tlp_marking": "TLP:AMBER",
            },
            headers=auth_headers,
        )
    assert resp.status_code == 429, resp.text
    assert resp.json()["error"]["code"] == "ai_allowance_exceeded"
    mock_task.delay.assert_not_called()


# ------------------------------------------------- limiter identity


def _request(host, headers=None):
    return MagicMock(client=MagicMock(host=host), headers=headers or {})


async def test_client_ip_trusts_forwarded_header_only_behind_our_proxy(monkeypatch):
    from app.core.rate_limit import client_ip

    # Caddy on the Docker network forwards the real client.
    assert client_ip(_request("172.18.0.5", {"x-forwarded-for": "203.0.113.9, 172.18.0.1"})) == "203.0.113.9"
    # A public direct peer claiming a forwarded header is just itself.
    assert client_ip(_request("8.8.4.4", {"x-forwarded-for": "203.0.113.9"})) == "8.8.4.4"
    assert client_ip(_request("172.18.0.5")) == "172.18.0.5"
    assert client_ip(MagicMock(client=None, headers={})) == "unknown"
    # Behind Cloudflare the forwarded hop is the edge node and CF-Connecting-IP is the
    # visitor — but only the operator knows the origin accepts the edge alone, so the
    # header is read only once they name it; on an open origin anyone could send it.
    spoofed = _request("172.18.0.5", {"cf-connecting-ip": "198.51.100.7", "x-forwarded-for": "104.16.1.1"})
    assert client_ip(spoofed) == "104.16.1.1"
    monkeypatch.setattr(env_settings, "trusted_client_ip_header", "CF-Connecting-IP")
    assert client_ip(spoofed) == "198.51.100.7"
    assert client_ip(_request("172.18.0.5", {"x-forwarded-for": "104.16.1.1"})) == "104.16.1.1"
    assert client_ip(_request("8.8.4.4", {"cf-connecting-ip": "198.51.100.7"})) == "8.8.4.4"


async def test_limiter_identity_is_a_verified_token_or_the_ip(test_user):
    """The share routes take no login, so a bearer only names a bucket when its signature checks."""
    import base64
    import json

    from app.core.rate_limit import _get_identity
    from app.core.security import create_access_token

    real = create_access_token(test_user.id, test_user.role)
    assert _get_identity(_request("203.0.113.9", {"authorization": f"Bearer {real}"})) == f"user:{test_user.id}"
    forged_payload = base64.urlsafe_b64encode(json.dumps({"sub": str(uuid.uuid4())}).encode()).decode().rstrip("=")
    forged = f"eyJhbGciOiJIUzI1NiJ9.{forged_payload}.bad"
    assert _get_identity(_request("203.0.113.9", {"authorization": f"Bearer {forged}"})) == "ip:203.0.113.9"
    assert _get_identity(_request("203.0.113.9", {"authorization": "Bearer not-a-jwt"})) == "ip:203.0.113.9"


# ------------------------------------------------- address ranges + cache


async def test_is_public_uses_the_iana_registry():
    from app.core.outbound import is_public

    assert is_public(ipaddress.ip_address("8.8.8.8"))
    assert is_public(ipaddress.ip_address("2606:4700::1111"))
    for bad in ("100.64.0.1", "224.0.0.1", "240.0.0.1", "0.0.0.0", "::ffff:10.0.0.1", "fe80::1", "fc00::1"):
        assert not is_public(ipaddress.ip_address(bad)), bad


async def test_resolve_host_caches_for_a_batch(monkeypatch):
    import app.core.outbound as outbound

    calls = []

    async def fake_getaddrinfo(host, port, **kw):
        calls.append(host)
        return [(None, None, None, None, ("93.184.216.34", 0))]

    monkeypatch.setattr(outbound.asyncio, "get_running_loop", lambda: MagicMock(getaddrinfo=fake_getaddrinfo))
    monkeypatch.setattr(outbound, "_resolved", {})

    for _ in range(50):
        assert await outbound.resolve_host("hooks.example") == [ipaddress.ip_address("93.184.216.34")]
    assert calls == ["hooks.example"]


async def test_resolver_cache_is_bounded_and_remembers_misses(monkeypatch):
    """Hostnames come from users, so the cache can't grow without bound; a name that resolves
    to nothing is remembered for the same minute as one that resolves."""
    import socket

    import app.core.outbound as outbound

    calls: list[str] = []

    async def fake_getaddrinfo(host, *args, **kwargs):
        calls.append(host)
        if host == "gone.example":
            raise socket.gaierror
        return [(2, 1, 6, "", ("8.8.4.4", 0))]

    loop = MagicMock()
    loop.getaddrinfo = fake_getaddrinfo
    monkeypatch.setattr(outbound.asyncio, "get_running_loop", lambda: loop)
    monkeypatch.setattr(outbound, "_resolved", {})
    monkeypatch.setattr(outbound, "RESOLVE_CACHE_MAX", 3)

    assert await outbound.resolve_host("gone.example") == []
    assert await outbound.resolve_host("gone.example") == []
    assert calls == ["gone.example"]
    for n in range(5):
        await outbound.resolve_host(f"h{n}.example")
    assert len(outbound._resolved) <= 3
    assert "h4.example" in outbound._resolved

    monkeypatch.setattr(outbound, "RESOLVE_CACHE_SECONDS", 0.0)
    await outbound.resolve_host("fresh.example")
    assert set(outbound._resolved) == {"fresh.example"}
