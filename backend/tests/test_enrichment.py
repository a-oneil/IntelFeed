"""Tests for threat actor and malware extraction (AI-dependent, mocked)."""

import uuid
from unittest.mock import AsyncMock, patch

from app.intelligence.enrichment import _ai_status, extract_malware, extract_threat_actors

# --- _ai_status helper tests ---


def test_ai_status_helper_not_configured():
    status, error = _ai_status(None)
    assert status == "ai_not_configured"
    assert error is None


def test_ai_status_helper_provider_error():
    result = {"_extraction_status": "provider_error", "_error": "API key invalid"}
    status, error = _ai_status(result)
    assert status == "provider_error"
    assert error == "API key invalid"


def test_ai_status_helper_parse_error():
    result = {"_extraction_status": "parse_error"}
    status, error = _ai_status(result)
    assert status == "parse_error"
    assert error is None


def test_ai_status_helper_success():
    result = {"threat_actors": [{"name": "APT28"}]}
    status, error = _ai_status(result)
    assert status == "success"
    assert error is None


# --- extract_threat_actors tests ---


async def test_extract_threat_actors_no_ai():
    """When run_task returns None (no AI configured), returns empty list with correct status."""
    mock_db = AsyncMock()
    user_id = uuid.uuid4()
    entry_id = uuid.uuid4()
    entry_data = {"title": "Test", "content_text": "APT28 targeted organization."}

    with patch("app.intelligence.enrichment.run_task", new_callable=AsyncMock, return_value=None):
        items, status, error_msg = await extract_threat_actors(
            db=mock_db,
            user_id=user_id,
            entry_id=entry_id,
            entry_data=entry_data,
        )

    assert items == []
    assert status == "ai_not_configured"
    assert error_msg is None


# --- extract_malware tests ---


async def test_extract_malware_no_ai():
    """When run_task returns None (no AI configured), returns empty list with correct status."""
    mock_db = AsyncMock()
    user_id = uuid.uuid4()
    entry_id = uuid.uuid4()
    entry_data = {"title": "Test", "content_text": "Cobalt Strike was deployed."}

    with patch("app.intelligence.enrichment.run_task", new_callable=AsyncMock, return_value=None):
        items, status, error_msg = await extract_malware(
            db=mock_db,
            user_id=user_id,
            entry_id=entry_id,
            entry_data=entry_data,
        )

    assert items == []
    assert status == "ai_not_configured"
    assert error_msg is None
