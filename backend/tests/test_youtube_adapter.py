"""Tests for YouTube feed adapter."""

import pytest

from app.adapters.youtube import YouTubeAdapter

SAMPLE_YOUTUBE_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns:yt="http://www.youtube.com/xml/schemas/2015"
      xmlns:media="http://search.yahoo.com/mrss/"
      xmlns="http://www.w3.org/2005/Atom">
 <link rel="self" href="https://www.youtube.com/feeds/videos.xml?channel_id=UC123"/>
 <title>Test Channel</title>
 <link rel="alternate" href="https://www.youtube.com/channel/UC123"/>
 <author>
  <name>Test Channel</name>
 </author>
 <entry>
  <id>yt:video:dQw4w9WgXcQ</id>
  <yt:videoId>dQw4w9WgXcQ</yt:videoId>
  <yt:channelId>UC123</yt:channelId>
  <title>Test Video Title</title>
  <link rel="alternate" href="https://www.youtube.com/watch?v=dQw4w9WgXcQ"/>
  <author>
   <name>Test Channel</name>
  </author>
  <published>2026-03-01T12:00:00+00:00</published>
  <updated>2026-03-01T14:00:00+00:00</updated>
  <media:group>
   <media:title>Test Video Title</media:title>
   <media:content url="https://www.youtube.com/v/dQw4w9WgXcQ" type="application/x-shockwave-flash"/>
   <media:thumbnail url="https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg" width="480" height="360"/>
   <media:description>A test video description.</media:description>
   <media:community>
    <media:starRating count="100" average="4.5"/>
    <media:statistics views="1000000"/>
   </media:community>
  </media:group>
 </entry>
 <entry>
  <id>yt:video:abc123def</id>
  <yt:videoId>abc123def</yt:videoId>
  <yt:channelId>UC123</yt:channelId>
  <title>Second Video</title>
  <link rel="alternate" href="https://www.youtube.com/watch?v=abc123def"/>
  <author>
   <name>Test Channel</name>
  </author>
  <published>2026-02-28T10:00:00+00:00</published>
 </entry>
</feed>"""


@pytest.fixture
def adapter():
    return YouTubeAdapter()


def test_parse_entries_basic(adapter):
    meta, entries = adapter.parse_entries(
        "https://www.youtube.com/feeds/videos.xml?channel_id=UC123",
        SAMPLE_YOUTUBE_FEED,
    )
    assert meta.title == "Test Channel"
    assert len(entries) == 2


def test_parse_entry_video_id(adapter):
    _, entries = adapter.parse_entries(
        "https://www.youtube.com/feeds/videos.xml?channel_id=UC123",
        SAMPLE_YOUTUBE_FEED,
    )
    entry = entries[0]
    assert entry.metadata["video_id"] == "dQw4w9WgXcQ"
    assert entry.metadata["channel_id"] == "UC123"


def test_parse_entry_media(adapter):
    _, entries = adapter.parse_entries(
        "https://www.youtube.com/feeds/videos.xml?channel_id=UC123",
        SAMPLE_YOUTUBE_FEED,
    )
    entry = entries[0]
    assert entry.media is not None
    assert entry.media.media_type == "video"
    assert "dQw4w9WgXcQ" in entry.media.url
    assert entry.media.thumbnail_url is not None


def test_parse_entry_url(adapter):
    _, entries = adapter.parse_entries(
        "https://www.youtube.com/feeds/videos.xml?channel_id=UC123",
        SAMPLE_YOUTUBE_FEED,
    )
    assert entries[0].url == "https://www.youtube.com/watch?v=dQw4w9WgXcQ"


def test_parse_entry_embed_url(adapter):
    _, entries = adapter.parse_entries(
        "https://www.youtube.com/feeds/videos.xml?channel_id=UC123",
        SAMPLE_YOUTUBE_FEED,
    )
    assert entries[0].metadata["embed_url"] == "https://www.youtube.com/embed/dQw4w9WgXcQ"


def test_parse_entry_published_date(adapter):
    _, entries = adapter.parse_entries(
        "https://www.youtube.com/feeds/videos.xml?channel_id=UC123",
        SAMPLE_YOUTUBE_FEED,
    )
    assert entries[0].published_at is not None


def test_parse_entry_author(adapter):
    _, entries = adapter.parse_entries(
        "https://www.youtube.com/feeds/videos.xml?channel_id=UC123",
        SAMPLE_YOUTUBE_FEED,
    )
    assert entries[0].author == "Test Channel"


def test_parse_guid_truncation(adapter):
    _, entries = adapter.parse_entries(
        "https://www.youtube.com/feeds/videos.xml?channel_id=UC123",
        SAMPLE_YOUTUBE_FEED,
    )
    assert len(entries[0].guid) <= 2000
