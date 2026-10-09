from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.feed import Feed
from app.models.user import User

MINIMAL_OPML = """<?xml version="1.0" encoding="UTF-8"?>
<opml version="1.0">
  <head><title>Test Subs</title></head>
  <body>
    <outline text="Security" title="Security">
      <outline text="Krebs on Security" title="Krebs on Security"
               type="rss" xmlUrl="https://krebsonsecurity.com/feed/"
               htmlUrl="https://krebsonsecurity.com/" />
      <outline text="Schneier on Security" title="Schneier on Security"
               type="rss" xmlUrl="https://schneier.com/feed/atom/"
               htmlUrl="https://schneier.com/" />
    </outline>
    <outline text="Standalone Feed" title="Standalone Feed"
             type="rss" xmlUrl="https://standalone.com/rss"
             htmlUrl="https://standalone.com/" />
  </body>
</opml>
"""

INVALID_XML = """This is not valid XML at all <<<<>>>"""


@pytest.mark.asyncio
async def test_import_opml(client: AsyncClient, admin_headers: dict):
    with patch("app.workers.feed_tasks.fetch_feed.delay") as mock_fetch:
        response = await client.post(
            "/api/opml/import",
            headers=admin_headers,
            files={"file": ("subs.opml", MINIMAL_OPML.encode(), "text/xml")},
        )

    assert response.status_code == 200
    data = response.json()

    # Should have created 1 category ("Security") and 3 feeds total
    assert data["categories_created"] == 1
    assert data["feeds_added"] == 3
    assert data["feeds_skipped"] == 0
    assert data["errors"] == []

    # fetch_feed.delay should have been called for each new feed
    assert mock_fetch.call_count == 3


@pytest.mark.asyncio
async def test_import_opml_invalid_xml(client: AsyncClient, admin_headers: dict):
    response = await client.post(
        "/api/opml/import",
        headers=admin_headers,
        files={"file": ("bad.opml", INVALID_XML.encode(), "text/xml")},
    )

    assert response.status_code == 200
    data = response.json()
    assert "error" in data
    assert "Invalid" in data["error"]


@pytest.mark.asyncio
async def test_import_opml_requires_admin(client: AsyncClient, auth_headers: dict):
    """OPML import is admin-only; export stays open to any authenticated user."""
    response = await client.post(
        "/api/opml/import",
        headers=auth_headers,
        files={"file": ("subs.opml", MINIMAL_OPML.encode(), "text/xml")},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_export_opml(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    db_session: AsyncSession,
):
    # Create feeds to export
    from app.models.category import Category

    category = Category(
        created_by=test_user.id,
        name="Export Category",
        position=0,
    )
    db_session.add(category)
    await db_session.flush()

    feed1 = Feed(
        title="Export Feed 1",
        url="https://export1.com/feed.xml",
        feed_type="rss",
        site_url="https://export1.com",
        category_id=category.id,
    )
    feed2 = Feed(
        title="Export Feed 2",
        url="https://export2.com/feed.xml",
        feed_type="rss",
        site_url="https://export2.com",
        category_id=None,  # uncategorized
    )
    db_session.add_all([feed1, feed2])
    await db_session.flush()

    response = await client.get("/api/opml/export", headers=auth_headers)
    assert response.status_code == 200
    assert "text/xml" in response.headers["content-type"]

    # Parse the XML response and verify structure
    import xml.etree.ElementTree as ET

    root = ET.fromstring(response.text)
    assert root.tag == "opml"
    assert root.get("version") == "1.0"

    head = root.find("head")
    assert head is not None
    title = head.find("title")
    assert title is not None
    assert title.text == "IntelFeed Subscriptions"

    body = root.find("body")
    assert body is not None

    # Should have a category outline and an uncategorized feed outline
    outlines = list(body)
    assert len(outlines) >= 2

    # Find the category outline
    category_outlines = [o for o in outlines if list(o)]  # outlines with children
    uncategorized_outlines = [o for o in outlines if not list(o) and o.get("xmlUrl")]

    assert len(category_outlines) == 1
    assert category_outlines[0].get("text") == "Export Category"

    # The category should contain one feed
    cat_feeds = list(category_outlines[0])
    assert len(cat_feeds) == 1
    assert cat_feeds[0].get("xmlUrl") == "https://export1.com/feed.xml"
    assert cat_feeds[0].get("htmlUrl") == "https://export1.com"

    # The uncategorized feed
    assert len(uncategorized_outlines) == 1
    assert uncategorized_outlines[0].get("xmlUrl") == "https://export2.com/feed.xml"


EXTENDED_OPML = """<?xml version="1.0" encoding="UTF-8"?>
<opml version="1.0" xmlns:intelfeed="https://intelfeed.app/ns/opml/1">
  <head><title>Extended</title></head>
  <body>
    <outline text="Rules" title="Rules">
      <outline text="SigmaHQ/sigma" title="SigmaHQ/sigma" type="rss"
               xmlUrl="https://github.com/SigmaHQ/sigma"
               intelfeed:feedType="github_repo"
               intelfeed:config='{"owner":"SigmaHQ","repo":"sigma","branch":"master"}'
               intelfeed:interval="1440"
               intelfeed:extractionMode="full"
               intelfeed:extractRules="true"
               intelfeed:extractTools="false" />
      <outline text="Junk settings" title="Junk settings" type="rss"
               xmlUrl="https://junk.example.com/feed"
               intelfeed:feedType="not_a_real_adapter"
               intelfeed:config="{not json at all"
               intelfeed:interval="banana"
               intelfeed:extractionMode="sideways"
               intelfeed:extractRules="perhaps" />
    </outline>
  </body>
</opml>
"""


@pytest.mark.asyncio
async def test_import_opml_reads_intelfeed_extension_attrs(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """The extension namespace carries what plain OPML cannot: the real feed
    type, its adapter_config, and the per-feed extraction tuning."""
    with patch("app.workers.feed_tasks.fetch_feed.delay"):
        response = await client.post(
            "/api/opml/import",
            headers=admin_headers,
            files={"file": ("ext.opml", EXTENDED_OPML.encode(), "text/xml")},
        )
    assert response.status_code == 200
    assert response.json()["feeds_added"] == 2

    from sqlalchemy import select

    sigma = (await db_session.execute(select(Feed).where(Feed.url == "https://github.com/SigmaHQ/sigma"))).scalar_one()
    assert sigma.feed_type == "github_repo"
    assert sigma.adapter_config == {"owner": "SigmaHQ", "repo": "sigma", "branch": "master"}
    assert sigma.fetch_interval_minutes == 1440
    assert sigma.intel_extraction_mode == "full"
    assert sigma.extract_detection_rules is True
    assert sigma.extract_tools is False


@pytest.mark.asyncio
async def test_import_opml_ignores_malformed_extension_attrs(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """One unparseable attribute costs that setting, not the whole import."""
    with patch("app.workers.feed_tasks.fetch_feed.delay"):
        await client.post(
            "/api/opml/import",
            headers=admin_headers,
            files={"file": ("ext.opml", EXTENDED_OPML.encode(), "text/xml")},
        )

    from sqlalchemy import select

    junk = (await db_session.execute(select(Feed).where(Feed.url == "https://junk.example.com/feed"))).scalar_one()
    # An unknown feed type, bad JSON, a non-numeric interval, an invalid mode
    # and an unparseable boolean all fall back to the column defaults.
    assert junk.feed_type == "rss"
    assert junk.adapter_config == {}
    assert junk.fetch_interval_minutes == 30
    assert junk.intel_extraction_mode == "selective"
    assert junk.extract_detection_rules is False


@pytest.mark.asyncio
async def test_plain_opml_cannot_declare_an_extended_feed_type(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """A third-party export saying type="reddit" would create a feed that can
    never fetch, because the subreddit only travels in adapter_config."""
    opml = (
        '<?xml version="1.0"?><opml version="1.0"><body>'
        '<outline text="r/netsec" type="reddit" xmlUrl="https://reddit.com/r/netsec" />'
        "</body></opml>"
    )
    with patch("app.workers.feed_tasks.fetch_feed.delay"):
        await client.post(
            "/api/opml/import",
            headers=admin_headers,
            files={"file": ("x.opml", opml.encode(), "text/xml")},
        )

    from sqlalchemy import select

    feed = (await db_session.execute(select(Feed).where(Feed.url == "https://reddit.com/r/netsec"))).scalar_one()
    assert feed.feed_type == "rss"
