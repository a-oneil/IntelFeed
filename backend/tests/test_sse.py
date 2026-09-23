import json
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient

from app.api.events import publish_event
from app.models.user import User


@pytest.mark.asyncio
async def test_sse_requires_auth(client: AsyncClient):
    """SSE endpoint without a ticket query param fails validation (mapped to 400)."""
    response = await client.get("/api/events")
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_publish_event_function(test_user: User):
    """Test that publish_event publishes to Redis with correct channel and payload."""
    user_id = str(test_user.id)

    mock_redis = MagicMock()
    with patch("app.api.events.sync_redis") as mock_module:
        mock_module.from_url.return_value = mock_redis

        publish_event(user_id, "feed_fetched", {"feed_id": "abc", "new_entries": 5})

        mock_redis.publish.assert_called_once()

        call_args = mock_redis.publish.call_args
        channel = call_args[0][0]
        payload = json.loads(call_args[0][1])

        assert channel == f"sse:{user_id}"
        assert payload["event"] == "feed_fetched"
        assert payload["data"]["feed_id"] == "abc"
        assert payload["data"]["new_entries"] == 5

        mock_redis.close.assert_called_once()


@pytest.mark.asyncio
async def test_publish_event_no_subscriber():
    """Publishing to a user with no SSE subscriber should not raise."""
    mock_redis = MagicMock()
    with patch("app.api.events.sync_redis") as mock_module:
        mock_module.from_url.return_value = mock_redis
        publish_event("nonexistent-user-id", "test_event", {"key": "value"})
        mock_redis.publish.assert_called_once()


@pytest.mark.asyncio
async def test_publish_event_redis_error():
    """publish_event should swallow Redis connection errors gracefully."""
    with patch("app.api.events.sync_redis") as mock_module:
        mock_module.from_url.side_effect = ConnectionError("Redis down")
        # Should not raise
        publish_event("some-user", "test_event", {"key": "value"})
