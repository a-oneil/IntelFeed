"""Curated starter feed packs — the sources a fresh install begins with.

A brand new instance has zero feeds, so nothing ingests, nothing extracts, and
every entity page, the priority queue, the threats board and the whole engine
sit empty until the user goes and sources URLs themselves. These packs are the
cure: an audited list of real security sources, grouped so the user picks a
firehose size rather than inheriting one.

The packs are the **OPML files** beside this module, so they stay reviewable in
git and readable by any other feed reader. Plain OPML can only describe
rss/atom/youtube/podcast feeds, though, and it carries no IntelFeed settings at
all — which would silently drop every ``github_repo``, ``reddit``,
``web_scraper`` and ``nvd`` source (they are inert without their
``adapter_config``) along with the per-feed extraction tuning. So the files
carry an ``xmlns:intelfeed`` extension namespace alongside the standard
attributes; other readers ignore what they don't recognize, and
:func:`app.api.opml.parse_extension_attrs` reads it back losslessly.

They live inside the ``app`` package rather than under ``scripts/`` on purpose:
``scripts/`` is a bind mount, so an endpoint reading from there would 404 on any
image run without the repo beside it. Here they ship in the image, and
``scripts/seed/seed_feeds.py`` reads this same directory — one source of truth.

Note the directory is ``app/feed_packs/`` and not ``app/data/feed_packs/``:
``.gitignore`` excludes ``data/`` anywhere in the tree for runtime caches, which
would have silently kept every pack file out of the repository.
"""

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# IntelFeed's OPML extension namespace. OPML ignores attributes it doesn't
# recognize, so a file using this stays a valid subscription list for any other
# reader while round-tripping the settings that make an IntelFeed feed useful.
# It lives here rather than in the API module because it is a property of the
# file format, and tooling that only reads the files shouldn't have to import
# the app's configuration to learn the prefix.
INTELFEED_NS = "https://intelfeed.app/ns/opml/1"

PACK_DIR = Path(__file__).resolve().parent
MANIFEST = PACK_DIR / "packs.json"


@dataclass(frozen=True)
class FeedPack:
    """One selectable group of sources, backed by a single OPML file."""

    id: str
    title: str
    description: str
    file: str
    # Core is what the onboarding wizard pre-selects: enough to make the
    # platform demonstrate itself on day one without being a firehose.
    recommended: bool = False
    # Human-readable prerequisite, surfaced in the UI so a pack that cannot
    # work on this instance yet says so before it creates failing feeds.
    requires: str | None = None
    feed_count: int = 0

    def path(self) -> Path:
        return PACK_DIR / self.file


@lru_cache(maxsize=1)
def load_packs() -> tuple[FeedPack, ...]:
    """Read the manifest, counting each pack's feeds from its OPML file.

    The count is derived rather than stored: a hand-maintained number in the
    manifest is a number that goes stale the first time someone prunes a dead
    source out of an OPML file.
    """
    if not MANIFEST.exists():
        return ()

    raw = json.loads(MANIFEST.read_text())
    packs = []
    for entry in raw.get("packs", []):
        pack = FeedPack(**entry)
        if not pack.path().exists():
            continue
        packs.append(
            FeedPack(
                **{**entry, "feed_count": _count_feeds(pack.path())},
            )
        )
    return tuple(packs)


def get_pack(pack_id: str) -> FeedPack | None:
    return next((p for p in load_packs() if p.id == pack_id), None)


def _count_feeds(path: Path) -> int:
    """Count outlines carrying an ``xmlUrl`` — i.e. feeds, not category groups."""
    try:
        root = ET.fromstring(path.read_text())
    except ET.ParseError:
        return 0
    return sum(1 for outline in root.iter("outline") if outline.get("xmlUrl"))
