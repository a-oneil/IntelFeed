"""Resource and SSRF limits on two user-reachable inputs: the SIGMA archive
import and scheduled-rule webhooks."""

import io
import zipfile
from types import SimpleNamespace

import pytest
from httpx import AsyncClient

_RULE = b"""title: Test Rule
id: 5f1e6a2b-1c3d-4e5f-8a9b-0c1d2e3f4a5b
status: experimental
description: Import limit test
logsource:
  product: windows
detection:
  sel:
    EventID: 1
  condition: sel
level: low
"""


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.mark.asyncio
async def test_sigma_zip_import_still_imports(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/detection-rules/import",
        files={"file": ("rules.zip", _zip({"a.yml": _RULE, "README.md": b"x"}), "application/zip")},
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["imported"] == 1, body
    assert body["skipped"] == 1


@pytest.mark.asyncio
async def test_sigma_zip_bomb_refused_before_inflating(client: AsyncClient, auth_headers: dict):
    # 8 MB of zeros deflates to a few KB: small upload, large inflate.
    bomb = _zip({"bomb.yml": b"\0" * (8 * 1024 * 1024)})
    assert len(bomb) < 64 * 1024
    resp = await client.post(
        "/api/detection-rules/import",
        files={"file": ("bomb.zip", bomb, "application/zip")},
        headers=auth_headers,
    )
    assert resp.status_code == 413


@pytest.mark.asyncio
async def test_scheduled_webhook_goes_through_the_ssrf_gate():
    """The scheduled-rule path POSTs to the URL and headers its author typed, so
    it gets the gate every other webhook path applies. Even with private
    networks allowed (the default, for LAN webhooks), loopback and the cloud
    metadata service stay refused."""
    from app.workers.automation_tasks import _execute_scheduled_notification

    rule = SimpleNamespace(id="r1", name="nightly")
    for url in (
        "http://127.0.0.1:8000/metrics",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/",
        "http://[fd00:ec2::254]/",
        "http://localhost:5000/",
        "file:///etc/passwd",
    ):
        result = await _execute_scheduled_notification({"type": "webhook", "config": {"url": url}}, rule, None)
        assert result["status"] == "error"
        assert "http_status" not in result


@pytest.mark.asyncio
async def test_private_network_switch_opens_the_lan_only():
    from app.core.outbound import check_outbound_url

    assert await check_outbound_url("http://192.168.1.20:5678/hook", allow_private=True) is None
    assert await check_outbound_url("http://10.0.0.5/hook", allow_private=True) is None
    assert await check_outbound_url("http://169.254.169.254/", allow_private=True) is not None
    assert await check_outbound_url("http://127.0.0.1/", allow_private=True) is not None
    assert await check_outbound_url("http://0.0.0.0/", allow_private=True) is not None
    assert await check_outbound_url("http://192.168.1.20/", allow_private=False) is not None
