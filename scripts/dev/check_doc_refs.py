"""Check the `path/to/file.py:line` references in the docs against the code.

docs/README.md promises `path/to/file.py:line` references, and line numbers rot:
every refactor above a cited line moves it. This finds the refs that have moved
and, with --fix, repairs the ones it can repair without guessing.

A ref is judged by the backticked identifier next to it on the same line, e.g.
``sight_known_values()`` (``observables.py:677``). If the cited file defines that
identifier and it is not within a few lines of the cited line, the ref has
drifted. A ref whose line is past the end of the file has drifted too. A ref with
no identifier beside it can't be judged and is only counted.

    python3 scripts/dev/check_doc_refs.py            # report; exit 1 on drift
    python3 scripts/dev/check_doc_refs.py --fix      # repair unambiguous drift
    python3 scripts/dev/check_doc_refs.py --unverified   # also list unjudgeable refs

--fix only rewrites a ref into a Python file, and only when the identifier has
exactly one definition there (a def, a class, or a module- or class-level
assignment, found by parsing rather than pattern-matching). Refs into TypeScript,
YAML, shell and the rest are still checked, against declarations only, but never
rewritten: without a parser a regex cannot tell a definition from an object key
or a local variable, and "the nearest match" is a guess. A wrong line number is
worse than a stale one, so everything uncertain is left for a human.

A repaired ref is written with its full repo path, which is the convention, so a
bare `observables.py:677` becomes `backend/app/intelligence/observables.py:1001`.

Runs on the host from the repo root; it needs git and nothing else.
"""

import argparse
import ast
import re
import subprocess
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WINDOW = 6
EXTS = r"(?:py|tsx|ts|yml|yaml|sh|kt|css|toml|json)"
REF = re.compile(rf"([A-Za-z0-9_./\-]+\.{EXTS}):(\d+)(?:[-–](\d+))?")
IDENT = re.compile(r"`([A-Za-z_][A-Za-z0-9_.]*)(?:\(\))?`")
# An identifier that *follows* a ref only counts if it hugs it: ``x.py:9` (`func()`)`.
AFTER = re.compile(r"`?[\s)(,:;—-]{0,8}(?:`[A-Za-z_][A-Za-z0-9_.]*(?:\(\))?`)?")

# Tracked and untracked-but-not-ignored: a doc or source file you have not committed yet still counts.
tracked = subprocess.run(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
    cwd=ROOT,
    capture_output=True,
    text=True,
    check=True,
).stdout.splitlines()
_sources: dict[str, list[str]] = {}


def source(path: str) -> list[str]:
    if path not in _sources:
        _sources[path] = (ROOT / path).read_text(errors="replace").splitlines()
    return _sources[path]


def candidates(path: str) -> list[str]:
    return [t for t in tracked if t == path or t.endswith("/" + path)]


def extent(src: list[str], at: int) -> int:
    """Last line of the block that starts at 1-indexed line `at`, by indentation.

    Non-Python fallback. A ref that lands inside a function body ("the signal
    fires at signals.py:769, in `_severity_signals`") is as valid as one that
    lands on the `def` line, so a definition owns its whole body.
    """
    indent = len(src[at - 1]) - len(src[at - 1].lstrip())
    end = at
    for i in range(at, len(src)):
        line = src[i]
        if not line.strip():
            continue
        if len(line) - len(line.lstrip()) <= indent and not line.lstrip().startswith((")", "]", "}")):
            break
        end = i + 1
    return end


_py_index: dict[str, dict[str, list[tuple[int, int]]]] = {}


def python_index(path: str) -> dict[str, list[tuple[int, int]]]:
    """name -> [(first, last)] for every def/class, plus module- and class-level assignments.

    Parsed rather than pattern-matched so a local variable that happens to share a
    name (`run_extraction = bool(...)` inside a function) is not mistaken for the
    definition, and a function's extent is exact rather than guessed.
    """
    if path not in _py_index:
        index: dict[str, list[tuple[int, int]]] = {}
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # old files with a bad escape sequence still parse
                tree = ast.parse((ROOT / path).read_text(errors="replace"))
        except SyntaxError:
            tree = ast.Module(body=[], type_ignores=[])
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                index.setdefault(node.name, []).append((node.lineno, node.end_lineno or node.lineno))
        scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        for scope in scopes:
            for node in scope.body:
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif isinstance(node, ast.AnnAssign):
                    targets = [node.target]
                else:
                    targets = []
                for t in targets:
                    if isinstance(t, ast.Name):
                        index.setdefault(t.id, []).append((node.lineno, node.end_lineno or node.lineno))
        _py_index[path] = index
    return _py_index[path]


def definitions(path: str, ident: str) -> list[tuple[int, int]]:
    """(first_line, last_line) of every place `ident` is defined in `path`.

    A string key ("name": ...), an object property, or a `case "name":` mentions an
    identifier without being where it lives, so those never count: pointing a ref
    there would be a confident wrong answer.
    """
    if path.endswith(".py"):
        return python_index(path).get(ident, [])
    src = source(path)
    name = re.escape(ident)
    if path.endswith((".yml", ".yaml")):
        # A YAML key is how a service or volume is declared.
        pattern = re.compile(rf"^\s*{name}\s*:")
    else:
        # Declarations only. A bare `name:` or `name =` also matches object
        # properties, parameters and locals, none of which is the thing a doc means.
        pattern = re.compile(
            rf"\b(?:def|class|function|fun|interface|enum|type|const|let|var|val)\s+{name}\b|^\s*{name}\s*\(\)\s*\{{"
        )
    found = []
    for i, line in enumerate(src, 1):
        if pattern.search(line):
            found.append((i, extent(src, i)))
    return found


def looks_like_symbol(ident: str) -> bool:
    return len(ident) >= 6 and ("_" in ident or any(c.isupper() for c in ident))


def idents_in(text: str) -> list[str]:
    return [i for i in IDENT.findall(text) if not re.search(rf"\.{EXTS}$", i)]


def judge(line: str, m: re.Match, prev_end: int, next_start: int):
    """Return (verdict, new_ref_or_None). verdict: ok | drift | unverified | nofile.

    The identifier is taken from the text between this ref and its neighbours on
    the line: before it if there is one, else after it. A line carrying several
    refs must not lend one ref another's identifier, or --fix would "repair" a
    ref to point at the wrong symbol.
    """
    path, start, end = m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))
    cands = candidates(path)
    if not cands:
        return "nofile", None

    idents = idents_in(line[prev_end : m.start()]) or idents_in(AFTER.match(line[m.end() : next_start]).group(0))[:1]

    if all(end > len(source(c)) for c in cands):
        return "drift", None

    for ident in reversed(idents):
        name = ident.split(".")[-1]
        if not looks_like_symbol(name):
            continue  # a bare word (`health`, `done`) says nothing about where a ref should land
        found = [(c, d) for c in cands if end <= len(source(c)) for d in definitions(c, name)]
        if not found:
            continue  # only ever a table key or a `case`: mentioned there, not defined there
        if any(start <= last + WINDOW and first - WINDOW <= end for _, (first, last) in found):
            return "ok", None
        # A name that is data rather than code ("epss_jump" fires at this line) is
        # right wherever the cited line says it, however far from its table entry.
        if any(name in source(c)[n - 1] for c in cands for n in range(start, min(end, len(source(c))) + 1)):
            return "ok", None
        fixable = len(found) == 1 and found[0][0].endswith(".py")
        return "drift", (f"{found[0][0]}:{found[0][1][0]}" if fixable else None)
    return "unverified", None


def docs() -> list[str]:
    return [t for t in tracked if t.endswith(".md") and (t.startswith(("docs/", "scripts/")) or "/" not in t)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--fix", action="store_true", help="rewrite unambiguous drifted refs in place")
    ap.add_argument("--unverified", action="store_true", help="also list refs with no identifier to judge by")
    args = ap.parse_args()

    total, drift, unverified, fixed = 0, [], [], 0
    for doc in docs():
        lines = (ROOT / doc).read_text().splitlines(keepends=True)
        dirty = False
        for n, line in enumerate(lines, 1):
            matches = list(REF.finditer(line))
            for k in range(len(matches) - 1, -1, -1):  # right to left: an edit never shifts a span still to come
                m = matches[k]
                prev_end = matches[k - 1].end() if k else 0
                next_start = matches[k + 1].start() if k + 1 < len(matches) else len(line)
                total += 1
                verdict, repair = judge(line, m, prev_end, next_start)
                if verdict == "unverified":
                    unverified.append(f"{doc}:{n}  {m.group(0)}")
                elif verdict in ("drift", "nofile"):
                    if repair and args.fix:
                        line = line[: m.start()] + repair + line[m.end() :]
                        dirty, fixed = True, fixed + 1
                    else:
                        drift.append(f"{doc}:{n}  {m.group(0)}" + (f"  -> {repair}" if repair else ""))
            lines[n - 1] = line
        if dirty:
            (ROOT / doc).write_text("".join(lines))

    summary = f"{total} refs: {len(drift)} drifted, {len(unverified)} unverifiable"
    print(summary + (f", {fixed} fixed" if args.fix else ""))
    for d in drift:
        print("  DRIFT", d)
    if args.unverified:
        for u in unverified:
            print("  UNVERIFIED", u)
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
