"""Feeds fill a missing date with year 1 (Hugo) or the Unix epoch. Stored, year 1
becomes -infinity and breaks the search index rebuild, so neither is kept."""

from datetime import UTC, datetime

import pytest

from app.adapters.base import ParsedEntry
from app.adapters.rss import RSSAdapter


@pytest.mark.parametrize(
    "value",
    [
        datetime(1, 1, 1, tzinfo=UTC),
        datetime.min,
        datetime(1970, 1, 1, tzinfo=UTC),
        datetime(1900, 6, 1, tzinfo=UTC),
    ],
)
def test_placeholder_dates_are_dropped(value):
    assert ParsedEntry(guid="g", published_at=value).published_at is None


@pytest.mark.parametrize("value", [datetime(2009, 10, 20, tzinfo=UTC), datetime(1970, 1, 2, tzinfo=UTC), None])
def test_real_dates_are_kept(value):
    assert ParsedEntry(guid="g", published_at=value).published_at == value


def test_hugo_zero_pubdate_is_not_stored():
    feed = """<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
    <item><title>About</title><guid>1</guid><link>https://x.example/about/</link>
    <pubDate>Mon, 01 Jan 0001 00:00:00 +0000</pubDate></item>
    <item><title>Post</title><guid>2</guid><link>https://x.example/post/</link>
    <pubDate>Tue, 04 Nov 2026 00:00:00 +0000</pubDate></item>
    </channel></rss>"""
    _, entries = RSSAdapter().parse_entries("https://x.example/index.xml", feed)
    dates = {e.title: e.published_at for e in entries}
    assert dates == {"About": None, "Post": datetime(2026, 11, 4, tzinfo=UTC)}
