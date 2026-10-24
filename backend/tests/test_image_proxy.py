from unittest.mock import AsyncMock, patch
from urllib.parse import quote

import pytest
from httpx import AsyncClient

from app.api.proxy import _FetchFailed


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

    target_url = "https://example.com/image.png"

    with patch("app.api.proxy._fetch_image", AsyncMock(return_value=(fake_image_bytes, "image/png"))):
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
    target_url = "https://example.com/page.html"

    with patch("app.api.proxy._fetch_image", AsyncMock(side_effect=_FetchFailed(415))):
        response = await client.get(
            f"/api/proxy/image?url={quote(target_url, safe='')}",
            headers=auth_headers,
        )

    assert response.status_code == 415
