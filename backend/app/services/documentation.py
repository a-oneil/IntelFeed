"""Reads the repo's ``docs/`` markdown tree.

The files are read from disk rather than the database: they are versioned with
the code, and a doc edit should ship with the change it describes. ``docs/`` is
mounted read-only into the API container (see ``docker-compose.*.yml``); when it
is absent every function here degrades to an empty result rather than erroring,
so a deployment that forgets the mount loses the docs and nothing else.

Nothing about a page is configured. Its title is its own H1, its section is the
directory it sits in, and it is discovered by walking the tree — so dropping a
new ``.md`` file into ``docs/`` is the whole publishing step.

This module is the single reader: the ``/api/documentation`` router serves it to
the docs UI, and ``app.tools.docs`` exposes the same tree to the copilot so it
can answer "how does IntelFeed do X" from the shipped documentation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Section for pages sitting directly in docs/. Subdirectories name their own.
ROOT_SECTION = "Documentation"

# Filenames that act as their directory's landing page, pinned above their
# siblings. A structural convention, not a per-page list.
_INDEX_STEMS = {"readme", "index"}

# Slugs are filesystem paths, so constrain them before touching disk. One
# optional subdirectory level is allowed, which covers docs/diagrams/.
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)?$")

_H1_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class DocPage:
    """One markdown file, summarised for an index listing."""

    slug: str
    title: str
    section: str
    summary: str | None


def docs_dir() -> Path | None:
    """Locate docs/ in the container (/app/docs) or a source checkout (repo/docs)."""
    here = Path(__file__).resolve()
    for candidate in (here.parents[2] / "docs", here.parents[3] / "docs"):
        if candidate.is_dir():
            return candidate
    return None


def title_of(markdown: str, slug: str) -> str:
    match = _H1_RE.search(markdown)
    if match:
        return match.group(1).strip()
    return slug.rsplit("/", 1)[-1].replace("-", " ").replace("_", " ").title()


def summary_of(markdown: str) -> str | None:
    """First real paragraph after the H1, flattened to a single line."""
    body = _H1_RE.split(markdown, maxsplit=1)
    text = body[-1] if len(body) > 1 else markdown
    for block in text.split("\n\n"):
        candidate = block.strip()
        if not candidate or candidate.startswith(("#", "```", "|", ">", "---")):
            continue
        flat = " ".join(candidate.split())
        # Strip markdown link syntax so the sidebar tooltip reads as prose.
        flat = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", flat)
        flat = flat.replace("**", "").replace("`", "")
        return flat[:280]
    return None


def section_for(slug: str) -> str:
    """The page's directory, humanised. Root-level pages share one section."""
    if "/" not in slug:
        return ROOT_SECTION
    folder = slug.rsplit("/", 1)[0].rsplit("/", 1)[-1]
    return folder.replace("-", " ").replace("_", " ").strip().title()


# Sections pinned ahead of the alphabet. The user guide leads because most
# readers arriving at the docs want to use IntelFeed, not build it; everything
# unpinned keeps sorting A–Z after these, so a new directory needs no change
# here to appear sensibly.
_SECTION_ORDER: tuple[str, ...] = ("Guide", ROOT_SECTION)


def _section_rank(section: str) -> int:
    try:
        return _SECTION_ORDER.index(section)
    except ValueError:
        return len(_SECTION_ORDER)


def _sort_key(page: DocPage) -> tuple[int, str, int, str]:
    """Pinned sections first, then directories A–Z; index pages lead each section."""
    rank = _section_rank(page.section)
    is_index = 0 if page.slug.rsplit("/", 1)[-1].lower() in _INDEX_STEMS else 1
    return (rank, page.section.lower(), is_index, page.title.lower())


def _dir_signature(root: Path) -> tuple:
    """Cheap fingerprint of docs/ — path, size and mtime of every markdown file.

    Cached index results are keyed on this instead of process lifetime, so a doc
    added or edited under the read-only mount shows up without an API restart.
    """
    entries = []
    for path in sorted(root.rglob("*.md")):
        try:
            stat = path.stat()
        except OSError:
            continue
        entries.append((path.as_posix(), stat.st_size, stat.st_mtime_ns))
    return tuple(entries)


_index_cache: tuple[tuple, list[DocPage]] | None = None


def index() -> list[DocPage]:
    """Every markdown file under docs/, rescanned whenever the tree changes."""
    global _index_cache
    root = docs_dir()
    if root is None:
        return []

    signature = _dir_signature(root)
    if _index_cache is not None and _index_cache[0] == signature:
        return _index_cache[1]

    pages: list[DocPage] = []
    for path in sorted(root.rglob("*.md")):
        slug = path.relative_to(root).with_suffix("").as_posix()
        try:
            markdown = path.read_text(encoding="utf-8")
        except OSError:
            continue
        pages.append(
            DocPage(
                slug=slug,
                title=title_of(markdown, slug),
                section=section_for(slug),
                summary=summary_of(markdown),
            )
        )
    pages.sort(key=_sort_key)
    _index_cache = (signature, pages)
    return pages


def reset_index_cache() -> None:
    """Drop the memoised index. Used by tests that swap the docs root."""
    global _index_cache
    _index_cache = None


def resolve(slug: str) -> Path | None:
    """Map a slug to a file inside docs/, or None if it doesn't exist or escapes."""
    root = docs_dir()
    if root is None or not SLUG_RE.match(slug):
        return None
    target = (root / f"{slug}.md").resolve()
    if not target.is_file() or root.resolve() not in target.parents:
        return None
    return target


def read_page(slug: str) -> tuple[str, str] | None:
    """``(title, markdown)`` for a slug, or None when it doesn't resolve."""
    path = resolve(slug)
    if path is None:
        return None
    markdown = path.read_text(encoding="utf-8")
    return title_of(markdown, slug), markdown
