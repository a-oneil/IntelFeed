"""Tests for the tools API endpoints (/api/tools)."""

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_tools_requires_auth(client: AsyncClient):
    resp = await client.get("/api/tools/tools")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_execute_requires_auth(client: AsyncClient):
    resp = await client.post(
        "/api/tools/execute",
        json={"tool_name": "search_entries", "args": {"query": "test"}},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_tools(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/tools/tools", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    # Every tool definition should have name, description, and input_schema
    for tool in data:
        assert "name" in tool
        assert "description" in tool
        assert "input_schema" in tool
        assert tool["input_schema"]["type"] == "object"


@pytest.mark.asyncio
async def test_execute_unknown_tool(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/tools/execute",
        json={"tool_name": "nonexistent_tool_xyz", "args": {}},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    # execute_tool returns a JSON string with an error key for unknown tools
    import json

    result = json.loads(data["result"])
    assert "error" in result
    assert "nonexistent_tool_xyz" in result["error"]


@pytest.mark.asyncio
async def test_execute_tool_success(client: AsyncClient, auth_headers: dict):
    """Test executing a tool with a mocked handler to avoid DB side effects."""
    mock_result = {"entries": [], "total": 0}

    # The endpoint runs tools through gate.execute_isolated (a savepoint per call).
    with patch("app.tools.gate.execute_tool", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = '{"entries": [], "total": 0}'
        resp = await client.post(
            "/api/tools/execute",
            json={"tool_name": "search_entries", "args": {"query": "test"}},
            headers=auth_headers,
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "result" in data
    import json

    result = json.loads(data["result"])
    assert result == mock_result


@pytest.mark.asyncio
async def test_execute_tool_default_args(client: AsyncClient, auth_headers: dict):
    """Verify that omitting args defaults to empty dict."""
    with patch("app.tools.gate.execute_tool", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = '{"ok": true}'
        resp = await client.post(
            "/api/tools/execute",
            json={"tool_name": "some_tool"},
            headers=auth_headers,
        )
    assert resp.status_code == 200
    # Confirm execute_tool was called with empty args
    call_args = mock_exec.call_args
    assert call_args[0][1] == {}  # second positional arg is args dict


@pytest.mark.asyncio
async def test_execute_tool_invalid_body(client: AsyncClient, auth_headers: dict):
    """Missing required field tool_name should return 400 (app's validation_error_handler)."""
    resp = await client.post(
        "/api/tools/execute",
        json={"args": {"query": "test"}},
        headers=auth_headers,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_get_cve_includes_article_count(client: AsyncClient, auth_headers: dict, db_session, test_entry):
    """Regression: the CVE model has no article_count column — get_cve must compute it."""
    import json

    from app.models.cve import CVE, EntryCVE

    cve = CVE(cve_id="CVE-2024-99999", severity="critical", description="Test CVE")
    db_session.add(cve)
    await db_session.flush()
    db_session.add(EntryCVE(entry_id=test_entry.id, cve_id=cve.id))
    await db_session.flush()

    resp = await client.post(
        "/api/tools/execute",
        json={"tool_name": "get_cve", "args": {"cve_id": "CVE-2024-99999"}},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    result = json.loads(resp.json()["result"])
    assert "error" not in result
    assert result["cve_id"] == "CVE-2024-99999"
    assert result["article_count"] == 1


async def _get_entry(client: AsyncClient, auth_headers: dict, **args) -> dict:
    import json

    resp = await client.post("/api/tools/execute", json={"tool_name": "get_entry", "args": args}, headers=auth_headers)
    assert resp.status_code == 200
    return json.loads(resp.json()["result"])


@pytest.mark.asyncio
async def test_get_entry_short_body_is_whole(client: AsyncClient, auth_headers: dict, test_entry):
    result = await _get_entry(client, auth_headers, entry_id=str(test_entry.id))
    assert result["content"] == test_entry.content_text
    assert result["content_length"] == len(test_entry.content_text)
    assert result["truncated"] is False
    assert result["next_offset"] is None


@pytest.mark.asyncio
async def test_get_entry_pages_a_long_body(client: AsyncClient, auth_headers: dict, db_session, test_entry):
    """Regression: a long newsletter's body was cut at 8,000 characters with no way to read on,
    while its entity links pointed at paragraphs past the cut."""
    body = "a" * 8000 + "Qilin dox counter-claims" + "b" * 5000
    test_entry.content_text = body
    await db_session.flush()

    first = await _get_entry(client, auth_headers, entry_id=str(test_entry.id))
    assert first["content_length"] == len(body)
    assert first["truncated"] is True
    assert first["next_offset"] == 8000
    assert "Qilin" not in first["content"]
    assert "continue with offset=8000" in first["content"]

    rest = await _get_entry(client, auth_headers, entry_id=str(test_entry.id), offset=first["next_offset"])
    assert rest["content_offset"] == 8000
    assert rest["content"].startswith("Qilin dox counter-claims")
    assert rest["truncated"] is False
    assert rest["next_offset"] is None


@pytest.mark.asyncio
async def test_get_entry_clamps_window(client: AsyncClient, auth_headers: dict, db_session, test_entry):
    test_entry.content_text = "x" * 30000
    await db_session.flush()

    capped = await _get_entry(client, auth_headers, entry_id=str(test_entry.id), max_chars=10**6)
    assert capped["next_offset"] == 20000

    tiny = await _get_entry(client, auth_headers, entry_id=str(test_entry.id), max_chars=0, offset=-5)
    assert tiny["content_offset"] == 0
    assert tiny["next_offset"] == 1

    past_end = await _get_entry(client, auth_headers, entry_id=str(test_entry.id), offset=99999)
    assert past_end["content"] == ""
    assert past_end["truncated"] is False
