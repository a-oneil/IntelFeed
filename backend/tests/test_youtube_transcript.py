"""Tests for YouTube transcript fetching service.

``youtube_transcript`` holds a module-level ``YouTubeTranscriptApi`` instance
and calls ``.fetch()`` on it, so these patch ``_ytt`` rather than the class —
patching the class would leave the already-constructed instance in place and
let the tests hit the network.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.services.youtube_transcript import _fetch_transcript_sync


def _transcript(*texts: str) -> MagicMock:
    """Build a stand-in for the library's FetchedTranscript."""
    transcript = MagicMock()
    transcript.snippets = [MagicMock(text=t) for t in texts]
    return transcript


def test_fetch_transcript_success():
    """Snippets are joined into a single plain-text string."""
    mock_ytt = MagicMock()
    mock_ytt.fetch.return_value = _transcript(
        "Hello everyone",
        "welcome to the show",
        "today we discuss threats",
    )

    with patch("app.services.youtube_transcript._ytt", mock_ytt):
        result = _fetch_transcript_sync("test_video_id")

    assert result == "Hello everyone welcome to the show today we discuss threats"
    mock_ytt.fetch.assert_called_once_with("test_video_id", languages=["en", "en-US", "en-GB"])


def test_fetch_transcript_disabled():
    """Test graceful handling when transcripts are disabled."""
    from youtube_transcript_api import TranscriptsDisabled

    mock_ytt = MagicMock()
    mock_ytt.fetch.side_effect = TranscriptsDisabled("test_video_id")

    with patch("app.services.youtube_transcript._ytt", mock_ytt):
        result = _fetch_transcript_sync("test_video_id")

    assert result is None


def test_fetch_transcript_not_found():
    """Test graceful handling when no transcript exists."""
    from youtube_transcript_api import NoTranscriptFound

    mock_ytt = MagicMock()
    mock_ytt.fetch.side_effect = NoTranscriptFound("test_video_id", ["en"], MagicMock())

    with patch("app.services.youtube_transcript._ytt", mock_ytt):
        result = _fetch_transcript_sync("test_video_id")

    assert result is None


@pytest.mark.parametrize("snippets", [(), ("",), ("   ",)])
def test_fetch_transcript_empty(snippets):
    """A transcript with no usable text yields None rather than an empty string."""
    mock_ytt = MagicMock()
    mock_ytt.fetch.return_value = _transcript(*snippets)

    with patch("app.services.youtube_transcript._ytt", mock_ytt):
        result = _fetch_transcript_sync("test_video_id")

    assert result is None


def test_fetch_transcript_generic_error():
    """Test handling of unexpected errors."""
    mock_ytt = MagicMock()
    mock_ytt.fetch.side_effect = Exception("Network error")

    with patch("app.services.youtube_transcript._ytt", mock_ytt):
        result = _fetch_transcript_sync("test_video_id")

    assert result is None
