"""Tests for feed type auto-detection."""

from app.adapters.base import BaseAdapter

RSS_CONTENT = """<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Test RSS</title>
    <item><title>Article</title></item>
  </channel>
</rss>"""

ATOM_CONTENT = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Test Atom</title>
  <entry><title>Article</title></entry>
</feed>"""

PODCAST_CONTENT = """<?xml version="1.0"?>
<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd">
  <channel>
    <title>Test Podcast</title>
    <itunes:author>Author</itunes:author>
    <item>
      <title>Episode 1</title>
      <enclosure url="https://example.com/ep1.mp3" length="1234" type="audio/mpeg"/>
    </item>
  </channel>
</rss>"""


def test_detect_rss():
    assert BaseAdapter.detect_feed_type("https://example.com/feed.xml", RSS_CONTENT) == "rss"


def test_detect_atom():
    assert BaseAdapter.detect_feed_type("https://example.com/feed.xml", ATOM_CONTENT) == "atom"


def test_detect_youtube():
    assert (
        BaseAdapter.detect_feed_type(
            "https://www.youtube.com/feeds/videos.xml?channel_id=UC123",
            ATOM_CONTENT,
        )
        == "youtube"
    )


def test_detect_podcast_by_enclosure():
    assert BaseAdapter.detect_feed_type("https://example.com/feed.xml", PODCAST_CONTENT) == "podcast"


def test_detect_podcast_by_itunes_namespace():
    content = """<?xml version="1.0"?>
    <rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd">
      <channel>
        <title>Show</title>
        <itunes:type>episodic</itunes:type>
        <itunes:author>Author</itunes:author>
        <item><title>Ep 1</title></item>
      </channel>
    </rss>"""
    assert BaseAdapter.detect_feed_type("https://example.com/feed.xml", content) == "podcast"
