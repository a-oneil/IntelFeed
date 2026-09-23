from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.config import settings


@pytest.mark.asyncio
async def test_proxy_rejects_file_url(client, auth_headers):
    """file:// URLs must be rejected to prevent SSRF local file read."""
    response = await client.get("/api/proxy/image", params={"url": "file:///etc/passwd"}, headers=auth_headers)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_proxy_rejects_non_http_schemes(client, auth_headers):
    """Only http and https schemes are allowed."""
    for scheme in ("ftp://example.com/img.png", "data:image/png;base64,abc", "gopher://evil"):
        response = await client.get("/api/proxy/image", params={"url": scheme}, headers=auth_headers)
        assert response.status_code == 400, f"Expected 400 for scheme in: {scheme}"


@pytest.mark.asyncio
async def test_proxy_rejects_private_ip_ranges(client, auth_headers):
    """Private/internal IPs should be blocked to prevent SSRF."""
    private_urls = [
        "http://127.0.0.1/image.png",
        "http://10.0.0.1/image.png",
        "http://192.168.1.1/image.png",
        "http://172.16.0.1/image.png",
        "http://[::1]/image.png",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    ]
    for url in private_urls:
        response = await client.get("/api/proxy/image", params={"url": url}, headers=auth_headers)
        assert response.status_code == 400, f"Expected 400 for private IP URL: {url}"


@pytest.mark.asyncio
async def test_proxy_requires_authentication(client):
    """Proxy endpoint must require a valid auth token."""
    response = await client.get("/api/proxy/image", params={"url": "https://example.com/image.png"})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_proxy_valid_url_returns_image(client, auth_headers):
    """A valid image URL should be proxied and returned."""
    fake_image = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200  # minimal PNG-like bytes
    mock_response = httpx.Response(
        200,
        content=fake_image,
        headers={"content-type": "image/png"},
        request=httpx.Request("GET", "https://example.com/image.png"),
    )

    with patch("app.api.proxy.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        original_enabled = settings.image_proxy_enabled
        settings.image_proxy_enabled = True
        try:
            response = await client.get(
                "/api/proxy/image",
                params={"url": "https://example.com/image.png"},
                headers=auth_headers,
            )
        finally:
            settings.image_proxy_enabled = original_enabled

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_proxy_returns_404_when_disabled(client, auth_headers):
    """Proxy returns 404 when image_proxy_enabled is False."""
    original_enabled = settings.image_proxy_enabled
    settings.image_proxy_enabled = False
    try:
        response = await client.get(
            "/api/proxy/image",
            params={"url": "https://example.com/image.png"},
            headers=auth_headers,
        )
    finally:
        settings.image_proxy_enabled = original_enabled

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_proxy_rejects_non_image_content_type(client, auth_headers):
    """Non-image content types must be rejected (415)."""
    mock_response = httpx.Response(
        200,
        content=b"<html>not an image</html>",
        headers={"content-type": "text/html"},
        request=httpx.Request("GET", "https://example.com/page.html"),
    )

    with patch("app.api.proxy.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        original_enabled = settings.image_proxy_enabled
        settings.image_proxy_enabled = True
        try:
            response = await client.get(
                "/api/proxy/image",
                params={"url": "https://example.com/page.html"},
                headers=auth_headers,
            )
        finally:
            settings.image_proxy_enabled = original_enabled

    assert response.status_code == 415
