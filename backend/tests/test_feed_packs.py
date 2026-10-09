"""Guards on the curated starter feed packs that ship in the image.

These are data tests, not logic tests: the files are hand-curated, so what can
go wrong is a bad edit — a pack listed in the manifest with no file behind it, a
``github_repo`` outline whose ``adapter_config`` lost its owner, a Telegram feed
sneaking back in, or someone's export cursor committed along with the list.
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.adapters import known_feed_types
from app.api.opml import PORTABLE_FEED_TYPES, parse_extension_attrs
from app.feed_packs import INTELFEED_NS, MANIFEST, PACK_DIR, load_packs
from app.models.feed import Feed

# Settings that describe where an import left off, not what to fetch. Committing
# one would hand every install the exporting instance's cursor.
RUNTIME_CONFIG_KEYS = {
    "last_commit_sha",
    "last_seen_id",
    "channel_id",
    "url_autodiscovery_history",
}


def outlines(path: Path) -> list[ET.Element]:
    return [o for o in ET.parse(path).getroot().iter("outline") if o.get("xmlUrl")]


def all_outlines() -> list[tuple[str, ET.Element]]:
    return [(p.id, o) for p in load_packs() for o in outlines(p.path())]


def test_packs_load():
    packs = load_packs()
    assert packs, "no starter packs loaded — did the data directory move?"
    assert all(p.feed_count > 0 for p in packs), "a pack shipped with no feeds in it"


def test_exactly_one_recommended_pack():
    """The wizard pre-selects the recommended packs; more than one core set
    would quietly make the default first run much bigger than it reads."""
    assert [p.id for p in load_packs() if p.recommended] == ["core"]


def test_every_manifest_pack_has_a_file():
    listed = {entry["file"] for entry in json.loads(MANIFEST.read_text())["packs"]}
    on_disk = {p.name for p in PACK_DIR.glob("*.opml")}
    assert listed == on_disk, f"manifest/files mismatch: {listed ^ on_disk}"


def test_pack_files_are_wellformed_opml():
    for pack in load_packs():
        root = ET.parse(pack.path()).getroot()
        assert root.tag == "opml"
        assert root.find("body") is not None
        # Every feed sits inside a category group, so importing a pack produces
        # a browsable sidebar rather than a flat list of 40 feeds.
        for outline in outlines(pack.path()):
            assert outline.get("text"), f"{pack.id}: outline with no title"


def test_no_duplicate_urls_across_packs():
    """Packs are additive — the same URL in two of them is a wasted slot, and
    which pack 'owns' a feed stops being answerable."""
    seen: dict[str, str] = {}
    duplicates = []
    for pack_id, outline in all_outlines():
        url = outline.get("xmlUrl")
        if url in seen:
            duplicates.append(f"{url} in both {seen[url]} and {pack_id}")
        seen[url] = pack_id
    assert not duplicates, duplicates


def test_urls_are_fetchable():
    """A feed whose adapter fetches the URL needs a real one — the importer
    drops anything else. Extended adapters are driven by adapter_config and
    never fetch this value, so NVD may identify itself as `nvd://cves`."""
    from app.adapters import is_extended_feed_type

    for pack_id, outline in all_outlines():
        url = outline.get("xmlUrl")
        feed_type = outline.get(f"{{{INTELFEED_NS}}}feedType") or outline.get("type", "rss")
        if is_extended_feed_type(feed_type):
            continue
        assert url.startswith(("http://", "https://")), f"{pack_id}: {url}"


def test_feed_types_are_real_adapters():
    known = known_feed_types()
    for pack_id, outline in all_outlines():
        portable = outline.get("type", "rss")
        assert portable in PORTABLE_FEED_TYPES, f"{pack_id}: unportable type={portable}"
        declared = outline.get(f"{{{INTELFEED_NS}}}feedType")
        if declared:
            assert declared in known, f"{pack_id}: {declared} has no adapter"


def test_no_telegram_feeds_ship():
    """Telegram needs TELEGRAM_API_ID/HASH plus an interactive login, so these
    would import as permanently failing feeds on a fresh install."""
    shipped = {outline.get(f"{{{INTELFEED_NS}}}feedType") for _, outline in all_outlines()}
    assert "telegram" not in shipped
    assert "bluesky" not in shipped, "bluesky feeds carry an app password"


def test_extended_feeds_carry_the_config_their_adapter_needs():
    """An extended feed without its adapter_config is inert: the reddit adapter
    reads the subreddit from config, not from the URL."""
    required = {
        "github_repo": ("owner", "repo"),
        "reddit": ("subreddit",),
        "web_scraper": ("blog_url",),
    }
    for pack_id, outline in all_outlines():
        feed_type = outline.get(f"{{{INTELFEED_NS}}}feedType")
        if feed_type not in required:
            continue
        config = json.loads(outline.get(f"{{{INTELFEED_NS}}}config") or "{}")
        for key in required[feed_type]:
            assert config.get(key), f"{pack_id}: {outline.get('text')} missing config.{key}"


def test_no_runtime_state_in_shipped_configs():
    for pack_id, outline in all_outlines():
        raw = outline.get(f"{{{INTELFEED_NS}}}config")
        if not raw:
            continue
        leaked = RUNTIME_CONFIG_KEYS & set(json.loads(raw))
        assert not leaked, f"{pack_id}: {outline.get('text')} ships runtime state {leaked}"


def test_extension_attrs_parse_into_real_feed_columns():
    """Every intelfeed:* attribute in the shipped files has to be one the
    importer understands, or the tuning is silently dropped on import."""
    feed_columns = set(Feed.__table__.columns.keys())
    for pack_id, outline in all_outlines():
        parsed = parse_extension_attrs(outline)
        unknown = set(parsed) - feed_columns - {"feed_type"}
        assert not unknown, f"{pack_id}: parsed non-column keys {unknown}"
        declared = {
            k.removeprefix(f"{{{INTELFEED_NS}}}") for k in outline.attrib if k.startswith(f"{{{INTELFEED_NS}}}")
        }
        # One parsed value per declared attribute: a typo'd attribute name
        # parses to nothing and would otherwise go unnoticed.
        assert len(parsed) == len(declared), (
            f"{pack_id}: {outline.get('text')} declared {declared} but parsed {set(parsed)}"
        )


def test_polling_intervals_are_polite():
    """Every install polls these on the same defaults, so the shipped intervals
    are deliberately slower than a tuned instance's."""
    for pack_id, outline in all_outlines():
        interval = int(outline.get(f"{{{INTELFEED_NS}}}interval") or 30)
        assert interval >= 60, f"{pack_id}: {outline.get('text')} polls every {interval}m"


@pytest.mark.asyncio
async def test_list_starter_packs_endpoint(client: AsyncClient, auth_headers: dict):
    response = await client.get("/api/opml/starter-packs", headers=auth_headers)
    assert response.status_code == 200
    packs = response.json()["packs"]
    assert {p["id"] for p in packs} == {p.id for p in load_packs()}
    core = next(p for p in packs if p["id"] == "core")
    assert core["recommended"] is True
    assert core["feed_count"] > 0


@pytest.mark.asyncio
async def test_import_starter_pack_creates_feeds(client: AsyncClient, admin_headers: dict, db_session):
    from unittest.mock import patch

    with patch("app.workers.feed_tasks.fetch_feed.delay") as mock_fetch:
        response = await client.post("/api/opml/starter-packs/import", headers=admin_headers, json=["core"])
    assert response.status_code == 200
    data = response.json()

    core = next(p for p in load_packs() if p.id == "core")
    assert data["feeds_added"] == core.feed_count
    assert data["categories_created"] > 0
    assert data["packs"] == [{"id": "core", "title": "Core", "feeds_added": core.feed_count}]
    assert mock_fetch.call_count == core.feed_count

    feeds = (await db_session.execute(select(Feed))).scalars().all()
    assert len(feeds) == core.feed_count
    assert all(f.category_id is not None for f in feeds)
    # Core carries the NVD source, whose URL is `nvd://cves` — the importer
    # skips non-HTTP URLs for everything that actually fetches one.
    assert any(f.feed_type == "nvd" for f in feeds)


@pytest.mark.asyncio
async def test_every_pack_imports_with_its_settings_intact(client: AsyncClient, admin_headers: dict, db_session):
    """The whole point of the extension namespace: a fresh install inherits the
    tuning, not just a list of URLs."""
    from unittest.mock import patch

    with patch("app.workers.feed_tasks.fetch_feed.delay"):
        response = await client.post(
            "/api/opml/starter-packs/import",
            headers=admin_headers,
            json=[p.id for p in load_packs()],
        )
    assert response.status_code == 200
    assert response.json()["feeds_added"] == sum(p.feed_count for p in load_packs())

    feeds = {f.url: f for f in (await db_session.execute(select(Feed))).scalars().all()}

    sigma = feeds["https://github.com/SigmaHQ/sigma"]
    assert sigma.feed_type == "github_repo"
    assert sigma.adapter_config["owner"] == "SigmaHQ"
    assert sigma.adapter_config["paths"] == ["rules/**/*.yml"]
    assert sigma.extract_detection_rules is True
    assert sigma.fetch_interval_minutes == 1440

    # Reddit's subreddit only travels in adapter_config.
    netsec = next(f for f in feeds.values() if f.adapter_config.get("subreddit") == "netsec")
    assert netsec.feed_type == "reddit"

    # Advisory and rule feeds name affected software, not wielded tooling, so
    # they ship with tool extraction off.
    assert any(f.extract_tools is False for f in feeds.values())


@pytest.mark.asyncio
async def test_importing_a_pack_twice_adds_nothing(client: AsyncClient, admin_headers: dict):
    from unittest.mock import patch

    with patch("app.workers.feed_tasks.fetch_feed.delay"):
        first = await client.post("/api/opml/starter-packs/import", headers=admin_headers, json=["podcasts"])
        second = await client.post("/api/opml/starter-packs/import", headers=admin_headers, json=["podcasts"])
    assert first.json()["feeds_added"] > 0
    assert second.json()["feeds_added"] == 0
    assert second.json()["feeds_skipped"] == first.json()["feeds_added"]


@pytest.mark.asyncio
async def test_import_starter_pack_rejects_unknown_id(client: AsyncClient, admin_headers: dict):
    response = await client.post("/api/opml/starter-packs/import", headers=admin_headers, json=["not-a-pack"])
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "unknown_feed_pack"


@pytest.mark.asyncio
async def test_import_starter_pack_is_admin_only(client: AsyncClient, auth_headers: dict):
    response = await client.post("/api/opml/starter-packs/import", headers=auth_headers, json=["core"])
    assert response.status_code == 403
