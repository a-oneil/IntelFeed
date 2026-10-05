"""Check the relative links, `#anchors` and images in the Markdown docs.

Companion to check_doc_refs.py (which checks `file.py:line` references into the
code). This checks the links between the docs themselves: that the file a link
points at exists, that a `#fragment` names a heading in it, and that an image
path resolves. External URLs and root-relative app routes (`/documentation`,
`/workbench/threats`), which only mean something inside the running app, are
skipped.

    python3 scripts/dev/check_doc_links.py

Exit 1 if anything is broken. Anchors follow GitHub's slugging (lowercase, drop
punctuation, one hyphen per space, `-1` on a repeat), which is also what the
in-app docs reader produces for headings without inline code.

Runs on the host from the repo root; it needs git and nothing else.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GITHUB_RELATIVE = re.compile(r"^\.\./\.\./(issues|pulls|security|discussions|actions|releases|wiki)\b")
LINK = re.compile(r"(!?)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")

# Tracked and untracked-but-not-ignored: a doc or source file you have not committed yet still counts.
tracked = subprocess.run(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
    cwd=ROOT,
    capture_output=True,
    text=True,
    check=True,
).stdout.splitlines()
tracked_set = set(tracked)


def slugs(path: Path) -> set[str]:
    found, seen, fenced = set(), {}, False
    for line in path.read_text(errors="replace").splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        m = None if fenced else re.match(r"^#{1,6} +(.+?)\s*#*\s*$", line)
        if not m:
            continue
        text = re.sub(r"[^\w\s-]", "", m.group(1).strip().lower())
        text = re.sub(r"\s", "-", text)
        n = seen.get(text, 0)
        seen[text] = n + 1
        found.add(text if n == 0 else f"{text}-{n}")
    return found


def docs() -> list[str]:
    in_scope = ("docs/", "scripts/", "intelfeed-")
    return [t for t in tracked if t.endswith(".md") and (t.startswith(in_scope) or "/" not in t)]


def main() -> int:
    problems, checked = [], 0
    anchor_cache: dict[Path, set[str]] = {}
    for doc in docs():
        src = ROOT / doc
        fenced = False
        for n, line in enumerate(src.read_text(errors="replace").splitlines(), 1):
            if line.lstrip().startswith("```"):
                fenced = not fenced
            if fenced:
                continue
            for m in LINK.finditer(line):
                target = m.group(2)
                if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I) or target.startswith(("/", "//")):
                    continue
                if GITHUB_RELATIVE.match(target):
                    continue  # `../../issues` from a root file: GitHub resolves it to the repo's Issues tab
                checked += 1
                path_part, _, frag = target.partition("#")
                dest = src if not path_part else (src.parent / path_part).resolve()
                try:
                    rel = dest.relative_to(ROOT).as_posix()
                except ValueError:
                    problems.append(f"{doc}:{n}  {target}  (escapes the repo)")
                    continue
                is_dir_link = dest.is_dir() and any(t.startswith(rel + "/") for t in tracked)
                if path_part and rel not in tracked_set and not is_dir_link:
                    problems.append(f"{doc}:{n}  {target}  (no such file)")
                    continue
                if frag and dest.suffix == ".md" and dest.is_file():
                    if dest not in anchor_cache:
                        anchor_cache[dest] = slugs(dest)
                    if frag.lower() not in anchor_cache[dest]:
                        problems.append(f"{doc}:{n}  {target}  (no heading '#{frag}')")

    print(f"{checked} links checked, {len(problems)} broken")
    for p in problems:
        print("  BROKEN", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
