"""Tests for Podcast feed adapter."""

import pytest

from app.adapters.podcast import PodcastAdapter, parse_duration

SAMPLE_PODCAST_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
     xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd"
     xmlns:podcast="https://podcastindex.org/namespace/1.0">
  <channel>
    <title>Test Security Podcast</title>
    <link>https://example.com</link>
    <description>A podcast about cybersecurity</description>
    <language>en-us</language>
    <itunes:author>Security Team</itunes:author>
    <itunes:image href="https://example.com/artwork.jpg"/>
    <itunes:category text="Technology"/>
    <itunes:explicit>false</itunes:explicit>
    <itunes:type>episodic</itunes:type>

    <item>
      <title>Episode 42: Zero Days</title>
      <link>https://example.com/ep42</link>
      <guid>ep42-unique-id</guid>
      <description>Discussing zero-day vulnerabilities.</description>
      <enclosure url="https://cdn.example.com/ep42.mp3" length="52345678" type="audio/mpeg"/>
      <itunes:duration>01:23:45</itunes:duration>
      <itunes:episode>42</itunes:episode>
      <itunes:season>2</itunes:season>
      <itunes:episodeType>full</itunes:episodeType>
      <itunes:author>Security Team</itunes:author>
      <pubDate>Mon, 01 Mar 2026 12:00:00 GMT</pubDate>
    </item>

    <item>
      <title>Episode 41: Ransomware Update</title>
      <link>https://example.com/ep41</link>
      <guid>ep41-unique-id</guid>
      <description>Latest ransomware trends.</description>
      <enclosure url="https://cdn.example.com/ep41.mp3" length="38765432" type="audio/mpeg"/>
      <itunes:duration>58:30</itunes:duration>
      <itunes:episode>41</itunes:episode>
      <itunes:season>2</itunes:season>
      <pubDate>Mon, 22 Feb 2026 12:00:00 GMT</pubDate>
    </item>

    <item>
      <title>Trailer</title>
      <link>https://example.com/trailer</link>
      <guid>trailer-id</guid>
      <description>Show trailer.</description>
      <enclosure url="https://cdn.example.com/trailer.mp3" length="5000000" type="audio/mpeg"/>
      <itunes:duration>120</itunes:duration>
      <itunes:episodeType>trailer</itunes:episodeType>
      <pubDate>Mon, 01 Jan 2026 12:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>"""


@pytest.fixture
def adapter():
    return PodcastAdapter()


def test_parse_show_metadata(adapter):
    meta, _ = adapter.parse_entries("https://example.com/feed.xml", SAMPLE_PODCAST_FEED)
    assert meta.title == "Test Security Podcast"
    assert meta.podcast_author == "Security Team"
    assert meta.podcast_type == "episodic"
    assert meta.podcast_explicit is False


def test_parse_entries_count(adapter):
    _, entries = adapter.parse_entries("https://example.com/feed.xml", SAMPLE_PODCAST_FEED)
    assert len(entries) == 3


def test_parse_episode_audio(adapter):
    _, entries = adapter.parse_entries("https://example.com/feed.xml", SAMPLE_PODCAST_FEED)
    ep42 = entries[0]
    assert ep42.media is not None
    assert ep42.media.media_type == "audio"
    assert ep42.media.url == "https://cdn.example.com/ep42.mp3"
    assert ep42.media.mime_type == "audio/mpeg"
    assert ep42.media.file_size == 52345678


def test_parse_episode_duration(adapter):
    _, entries = adapter.parse_entries("https://example.com/feed.xml", SAMPLE_PODCAST_FEED)
    ep42 = entries[0]
    # 01:23:45 = 5025 seconds
    assert ep42.media.duration_seconds == 5025


def test_parse_episode_metadata(adapter):
    _, entries = adapter.parse_entries("https://example.com/feed.xml", SAMPLE_PODCAST_FEED)
    ep42 = entries[0]
    assert ep42.metadata.get("episode_number") == 42
    assert ep42.metadata.get("season_number") == 2
    assert ep42.metadata.get("episode_type") == "full"


def test_parse_episode_author(adapter):
    _, entries = adapter.parse_entries("https://example.com/feed.xml", SAMPLE_PODCAST_FEED)
    assert entries[0].author == "Security Team"


def test_parse_trailer_type(adapter):
    _, entries = adapter.parse_entries("https://example.com/feed.xml", SAMPLE_PODCAST_FEED)
    trailer = entries[2]
    assert trailer.metadata.get("episode_type") == "trailer"


# parse_duration unit tests
def test_duration_hms():
    assert parse_duration("01:23:45") == 5025


def test_duration_ms():
    assert parse_duration("58:30") == 3510


def test_duration_seconds():
    assert parse_duration("120") == 120


def test_duration_none():
    assert parse_duration("") is None
    assert parse_duration(None) is None


def test_duration_invalid():
    assert parse_duration("abc") is None
