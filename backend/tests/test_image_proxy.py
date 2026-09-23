from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import quote

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_proxy_missing_url_param(client: AsyncClient, auth_headers: dict):
    """Requesting the proxy endpoint without a url param should return an error."""
    response = await client.get("/api/proxy/image", headers=auth_headers)
    # The app's validation_error_handler maps missing required query params to 400
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_proxy_success(client: AsyncClient, auth_headers: dict):
    """Proxy should return the image content when the upstream returns an image."""
    fake_image_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200  # PNG-ish bytes, >100 to avoid tracking pixel check

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "image/png"}
    mock_response.content = fake_image_bytes
    mock_response.raise_for_status = MagicMock()

    async def mock_get(url, **kwargs):
        return mock_response

    mock_client_instance = AsyncMock()
    mock_client_instance.get = mock_get
    mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
    mock_client_instance.__aexit__ = AsyncMock(return_value=False)

    target_url = "https://example.com/image.png"

    with patch("app.api.proxy.httpx.AsyncClient", return_value=mock_client_instance):
        response = await client.get(
            f"/api/proxy/image?url={quote(target_url, safe='')}",
            headers=auth_headers,
        )

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.content == fake_image_bytes
    assert "cache-control" in response.headers


@pytest.mark.asyncio
async def test_proxy_blocks_non_image_content_type(client: AsyncClient, auth_headers: dict):
    """Proxy should return 415 when upstream returns a non-image content type."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "text/html; charset=utf-8"}
    mock_response.content = b"<html>Not an image</html>"
    mock_response.raise_for_status = MagicMock()

    async def mock_get(url, **kwargs):
        return mock_response

    mock_client_instance = AsyncMock()
    mock_client_instance.get = mock_get
    mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
    mock_client_instance.__aexit__ = AsyncMock(return_value=False)

    target_url = "https://example.com/page.html"

    with patch("app.api.proxy.httpx.AsyncClient", return_value=mock_client_instance):
        response = await client.get(
            f"/api/proxy/image?url={quote(target_url, safe='')}",
            headers=auth_headers,
        )

    assert response.status_code == 415
